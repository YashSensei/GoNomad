//! Session registries: terminals, AI agents, editor tabs, run chips, and
//! notifications.
//!
//! These tables hold *metadata only*. Scrollback, agent transcripts, and file
//! content are capped on-disk files referenced by path (`ARCHITECTURE.md`
//! §16.1) — storing megabytes of terminal output as rows bloats the database
//! and slows every query while buying no query anyone wants to run.
//!
//! Sessions are daemon-owned and outlive connections (§2, §7.4), which is why
//! they are persisted at all: a phone that reconnects after an app kill must
//! find its terminals where it left them.

use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::clock;
use crate::error::{Result, StoreError};
use crate::row;

const AGENT_TABLE: &str = "agent_sessions";
const NOTIFICATION_TABLE: &str = "notifications";
const SNIPPET_TABLE: &str = "snippets";

/// A terminal session (`ARCHITECTURE.md` §8.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtySession {
    /// Daemon-assigned identifier.
    pub id: String,
    /// A user-visible name, so "the test terminal" is findable across days.
    pub name: String,
    /// The shell that was spawned.
    pub shell: String,
    /// The working directory it started in.
    pub cwd: String,
    /// When it was spawned, Unix milliseconds UTC.
    pub created_at_ms: i64,
    /// When the process exited, or `None` while it is still running.
    pub exited_at_ms: Option<i64>,
    /// Path to the capped on-disk scrollback ring, if one was allocated.
    pub scrollback_path: Option<String>,
}

/// The lifecycle state of an AI agent session (`ARCHITECTURE.md` §7.3).
///
/// Vendor-neutral by design: the phone renders these states for every adapter,
/// and no protocol type ever names a vendor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AgentState {
    /// The adapter is launching.
    Starting,
    /// Running and waiting for the user.
    Idle,
    /// Working on a turn.
    Thinking,
    /// Blocked on an approval decision (§7.5).
    AwaitingApproval,
    /// Blocked on user input.
    AwaitingInput,
    /// Failed; the transcript holds the detail.
    Error,
    /// The process has exited.
    Exited,
}

impl AgentState {
    /// Every variant, in declaration order.
    pub const ALL: [Self; 7] = [
        Self::Starting,
        Self::Idle,
        Self::Thinking,
        Self::AwaitingApproval,
        Self::AwaitingInput,
        Self::Error,
        Self::Exited,
    ];

    /// The stable string stored in the database.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Idle => "idle",
            Self::Thinking => "thinking",
            Self::AwaitingApproval => "awaiting_approval",
            Self::AwaitingInput => "awaiting_input",
            Self::Error => "error",
            Self::Exited => "exited",
        }
    }

    /// `true` when the session no longer needs a running process.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Exited)
    }
}

impl core::fmt::Display for AgentState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned when a stored agent state string is not recognised.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown agent state: {0:?}")]
pub struct UnknownAgentState(pub String);

impl core::str::FromStr for AgentState {
    type Err = UnknownAgentState;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|state| state.as_str() == s)
            .ok_or_else(|| UnknownAgentState(s.to_owned()))
    }
}

/// An AI agent session (`ARCHITECTURE.md` §7.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSession {
    /// Daemon-assigned identifier.
    pub id: String,
    /// The adapter name. **Display only** — nothing branches on it.
    pub adapter: String,
    /// The workspace the agent is operating in.
    pub workspace: String,
    /// Current lifecycle state.
    pub state: AgentState,
    /// When the session was created, Unix milliseconds UTC.
    pub created_at_ms: i64,
    /// When anything last happened, Unix milliseconds UTC.
    pub last_activity_ms: i64,
    /// Path to the append-only transcript file, if one exists.
    pub transcript_path: Option<String>,
    /// The agent's own session identifier, needed to `resume` it (§7.4).
    pub agent_native_session_id: Option<String>,
}

/// An open editor tab, so a reconnecting phone restores its workspace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EditorTab {
    /// The file path.
    pub path: String,
    /// Cursor line, zero-based.
    pub cursor_line: u32,
    /// Cursor column, zero-based.
    pub cursor_col: u32,
    /// First visible line.
    pub scroll_top: u32,
    /// Whether the tab has unsaved edits.
    pub dirty: bool,
}

/// A saved command, surfaced as a "run chip" (`ARCHITECTURE.md` §16.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snippet {
    /// Row identifier.
    pub id: i64,
    /// The workspace it belongs to.
    pub workspace: String,
    /// The label shown on the chip.
    pub label: String,
    /// The command that runs.
    pub command: String,
    /// How often it has been used; drives ordering.
    pub use_count: u64,
}

/// A queued or delivered notification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notification {
    /// Row identifier.
    pub id: i64,
    /// When it was raised, Unix milliseconds UTC.
    pub ts_ms: i64,
    /// A short kind discriminator, e.g. `agent.approval`.
    pub kind: String,
    /// An opaque payload, rendered by the client.
    pub payload: String,
    /// Whether delivery to a transport has been attempted successfully.
    pub delivered: bool,
    /// Whether the user has read it.
    pub read: bool,
}

/// The session registries repository. Obtained from
/// [`crate::Store::sessions`].
pub struct Sessions<'a> {
    conn: &'a Connection,
}

impl<'a> Sessions<'a> {
    pub(crate) fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    // --- PTY sessions -----------------------------------------------------

    /// Registers a newly spawned terminal.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`], including when `id` is already in use.
    pub fn create_pty(
        &self,
        id: &str,
        name: &str,
        shell: &str,
        cwd: &str,
        scrollback_path: Option<&str>,
    ) -> Result<PtySession> {
        let now = clock::now_unix_ms();
        self.conn.execute(
            "INSERT INTO pty_sessions (id, name, shell, cwd, created_at, exited_at, scrollback_path)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6)",
            rusqlite::params![id, name, shell, cwd, now, scrollback_path],
        )?;
        Ok(PtySession {
            id: id.to_owned(),
            name: name.to_owned(),
            shell: shell.to_owned(),
            cwd: cwd.to_owned(),
            created_at_ms: now,
            exited_at_ms: None,
            scrollback_path: scrollback_path.map(ToOwned::to_owned),
        })
    }

    /// Fetches one terminal by id.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`].
    pub fn pty(&self, id: &str) -> Result<Option<PtySession>> {
        Ok(self
            .conn
            .query_row(
                "SELECT id, name, shell, cwd, created_at, exited_at, scrollback_path
                 FROM pty_sessions WHERE id = ?1",
                [id],
                pty_from_row,
            )
            .optional()?)
    }

    /// Every terminal, newest first, including exited ones.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`].
    pub fn list_ptys(&self) -> Result<Vec<PtySession>> {
        self.query_ptys(
            "SELECT id, name, shell, cwd, created_at, exited_at, scrollback_path
             FROM pty_sessions ORDER BY created_at DESC",
        )
    }

    /// Terminals whose process is still running, newest first.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`].
    pub fn list_live_ptys(&self) -> Result<Vec<PtySession>> {
        self.query_ptys(
            "SELECT id, name, shell, cwd, created_at, exited_at, scrollback_path
             FROM pty_sessions WHERE exited_at IS NULL ORDER BY created_at DESC",
        )
    }

    fn query_ptys(&self, sql: &str) -> Result<Vec<PtySession>> {
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map([], pty_from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Records that a terminal's process exited.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] when no such session exists.
    pub fn mark_pty_exited(&self, id: &str) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE pty_sessions SET exited_at = ?2 WHERE id = ?1 AND exited_at IS NULL",
            rusqlite::params![id, clock::now_unix_ms()],
        )?;
        if changed == 0 && self.pty(id)?.is_none() {
            return Err(StoreError::not_found("pty session", id));
        }
        Ok(())
    }

    /// Forgets a terminal entirely.
    ///
    /// Safe to delete, unlike a device row: nothing references a PTY id after
    /// the fact, and the audit log records what happened independently.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`].
    pub fn remove_pty(&self, id: &str) -> Result<bool> {
        Ok(self
            .conn
            .execute("DELETE FROM pty_sessions WHERE id = ?1", [id])?
            > 0)
    }

    // --- Agent sessions ---------------------------------------------------

    /// Registers a new agent session.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`], including when `id` is already in use.
    pub fn create_agent(
        &self,
        id: &str,
        adapter: &str,
        workspace: &str,
        state: AgentState,
    ) -> Result<AgentSession> {
        let now = clock::now_unix_ms();
        self.conn.execute(
            "INSERT INTO agent_sessions
                 (id, adapter, workspace, state, created_at, last_activity,
                  transcript_path, agent_native_session_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5, NULL, NULL)",
            rusqlite::params![id, adapter, workspace, state.as_str(), now],
        )?;
        Ok(AgentSession {
            id: id.to_owned(),
            adapter: adapter.to_owned(),
            workspace: workspace.to_owned(),
            state,
            created_at_ms: now,
            last_activity_ms: now,
            transcript_path: None,
            agent_native_session_id: None,
        })
    }

    /// Fetches one agent session by id.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::CorruptRow`] when the stored state is unknown, or
    /// [`StoreError::Database`].
    pub fn agent(&self, id: &str) -> Result<Option<AgentSession>> {
        let raw = self
            .conn
            .query_row(
                "SELECT id, adapter, workspace, state, created_at, last_activity,
                        transcript_path, agent_native_session_id
                 FROM agent_sessions WHERE id = ?1",
                [id],
                RawAgent::from_row,
            )
            .optional()?;
        raw.map(RawAgent::decode).transpose()
    }

    /// Every agent session, newest activity first.
    ///
    /// # Errors
    ///
    /// As [`Sessions::agent`].
    pub fn list_agents(&self) -> Result<Vec<AgentSession>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, adapter, workspace, state, created_at, last_activity,
                    transcript_path, agent_native_session_id
             FROM agent_sessions ORDER BY last_activity DESC",
        )?;
        let rows = stmt.query_map([], RawAgent::from_row)?;
        let mut out = Vec::new();
        for raw in rows {
            out.push(raw?.decode()?);
        }
        Ok(out)
    }

    /// Updates an agent's state and bumps its activity timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] when no such session exists.
    pub fn set_agent_state(&self, id: &str, state: AgentState) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE agent_sessions SET state = ?2, last_activity = ?3 WHERE id = ?1",
            rusqlite::params![id, state.as_str(), clock::now_unix_ms()],
        )?;
        if changed == 0 {
            return Err(StoreError::not_found("agent session", id));
        }
        Ok(())
    }

    /// Records where the transcript file lives and the agent's own session id,
    /// which together are what make `resume` (§7.4) possible after a restart.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] when no such session exists.
    pub fn set_agent_resume_info(
        &self,
        id: &str,
        transcript_path: Option<&str>,
        agent_native_session_id: Option<&str>,
    ) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE agent_sessions
                SET transcript_path = ?2, agent_native_session_id = ?3, last_activity = ?4
              WHERE id = ?1",
            rusqlite::params![
                id,
                transcript_path,
                agent_native_session_id,
                clock::now_unix_ms()
            ],
        )?;
        if changed == 0 {
            return Err(StoreError::not_found("agent session", id));
        }
        Ok(())
    }

    /// Forgets an agent session.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`].
    pub fn remove_agent(&self, id: &str) -> Result<bool> {
        Ok(self
            .conn
            .execute("DELETE FROM agent_sessions WHERE id = ?1", [id])?
            > 0)
    }

    // --- Editor tabs ------------------------------------------------------

    /// Creates or updates a device's tab for `path`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`], including a foreign key violation when
    /// the device is not paired.
    pub fn upsert_editor_tab(
        &self,
        device_id: &gonomad_proto::DeviceId,
        tab: &EditorTab,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO editor_tabs (device_id, path, cursor_line, cursor_col, scroll_top, dirty)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(device_id, path) DO UPDATE SET
                 cursor_line = excluded.cursor_line,
                 cursor_col  = excluded.cursor_col,
                 scroll_top  = excluded.scroll_top,
                 dirty       = excluded.dirty",
            rusqlite::params![
                device_id.to_hex(),
                tab.path,
                tab.cursor_line,
                tab.cursor_col,
                tab.scroll_top,
                i64::from(tab.dirty),
            ],
        )?;
        Ok(())
    }

    /// A device's open tabs, sorted by path.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`].
    pub fn editor_tabs(&self, device_id: &gonomad_proto::DeviceId) -> Result<Vec<EditorTab>> {
        let mut stmt = self.conn.prepare(
            "SELECT path, cursor_line, cursor_col, scroll_top, dirty
             FROM editor_tabs WHERE device_id = ?1 ORDER BY path ASC",
        )?;
        let rows = stmt.query_map([device_id.to_hex()], |row| {
            Ok(EditorTab {
                path: row.get(0)?,
                cursor_line: row.get(1)?,
                cursor_col: row.get(2)?,
                scroll_top: row.get(3)?,
                dirty: row.get::<_, i64>(4)? != 0,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Closes one tab.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`].
    pub fn close_editor_tab(
        &self,
        device_id: &gonomad_proto::DeviceId,
        path: &str,
    ) -> Result<bool> {
        Ok(self.conn.execute(
            "DELETE FROM editor_tabs WHERE device_id = ?1 AND path = ?2",
            rusqlite::params![device_id.to_hex(), path],
        )? > 0)
    }

    // --- Snippets ---------------------------------------------------------

    /// Saves a run chip, or updates the command behind an existing label.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`].
    pub fn upsert_snippet(&self, workspace: &str, label: &str, command: &str) -> Result<Snippet> {
        self.conn.execute(
            "INSERT INTO snippets (workspace, label, command, use_count)
             VALUES (?1, ?2, ?3, 0)
             ON CONFLICT(workspace, label) DO UPDATE SET command = excluded.command",
            rusqlite::params![workspace, label, command],
        )?;
        self.snippet(workspace, label)?
            .ok_or_else(|| StoreError::not_found("snippet", label))
    }

    /// Fetches one snippet by workspace and label.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::CorruptRow`] or [`StoreError::Database`].
    pub fn snippet(&self, workspace: &str, label: &str) -> Result<Option<Snippet>> {
        let raw = self
            .conn
            .query_row(
                "SELECT id, workspace, label, command, use_count
                 FROM snippets WHERE workspace = ?1 AND label = ?2",
                rusqlite::params![workspace, label],
                RawSnippet::from_row,
            )
            .optional()?;
        raw.map(RawSnippet::decode).transpose()
    }

    /// A workspace's snippets, most-used first.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::CorruptRow`] or [`StoreError::Database`].
    pub fn snippets(&self, workspace: &str) -> Result<Vec<Snippet>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, workspace, label, command, use_count
             FROM snippets WHERE workspace = ?1 ORDER BY use_count DESC, label ASC",
        )?;
        let rows = stmt.query_map([workspace], RawSnippet::from_row)?;
        let mut out = Vec::new();
        for raw in rows {
            out.push(raw?.decode()?);
        }
        Ok(out)
    }

    /// Increments a snippet's use count, which is what orders the chips.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] when no such snippet exists.
    pub fn record_snippet_use(&self, id: i64) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE snippets SET use_count = use_count + 1 WHERE id = ?1",
            [id],
        )?;
        if changed == 0 {
            return Err(StoreError::not_found("snippet", id));
        }
        Ok(())
    }

    /// Deletes a snippet.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`].
    pub fn remove_snippet(&self, id: i64) -> Result<bool> {
        Ok(self
            .conn
            .execute("DELETE FROM snippets WHERE id = ?1", [id])?
            > 0)
    }

    // --- Notifications ----------------------------------------------------

    /// Queues a notification.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`].
    pub fn push_notification(&self, kind: &str, payload: &str) -> Result<Notification> {
        let now = clock::now_unix_ms();
        self.conn.execute(
            "INSERT INTO notifications (ts, kind, payload, delivered, read)
             VALUES (?1, ?2, ?3, 0, 0)",
            rusqlite::params![now, kind, payload],
        )?;
        Ok(Notification {
            id: self.conn.last_insert_rowid(),
            ts_ms: now,
            kind: kind.to_owned(),
            payload: payload.to_owned(),
            delivered: false,
            read: false,
        })
    }

    /// Notifications that have not yet been delivered, oldest first.
    ///
    /// Oldest first because this is a queue: delivering out of order would show
    /// a user yesterday's approval prompt after today's.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::CorruptRow`] or [`StoreError::Database`].
    pub fn undelivered_notifications(&self, limit: u32) -> Result<Vec<Notification>> {
        self.query_notifications(
            "SELECT id, ts, kind, payload, delivered, read
             FROM notifications WHERE delivered = 0 ORDER BY ts ASC, id ASC LIMIT ?1",
            limit,
        )
    }

    /// The most recent notifications, newest first.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::CorruptRow`] or [`StoreError::Database`].
    pub fn recent_notifications(&self, limit: u32) -> Result<Vec<Notification>> {
        self.query_notifications(
            "SELECT id, ts, kind, payload, delivered, read
             FROM notifications ORDER BY ts DESC, id DESC LIMIT ?1",
            limit,
        )
    }

    fn query_notifications(&self, sql: &str, limit: u32) -> Result<Vec<Notification>> {
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map([limit], |row| {
            Ok(Notification {
                id: row.get(0)?,
                ts_ms: row.get(1)?,
                kind: row.get(2)?,
                payload: row.get(3)?,
                delivered: row.get::<_, i64>(4)? != 0,
                read: row.get::<_, i64>(5)? != 0,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Marks a notification delivered.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] when no such notification exists.
    pub fn mark_notification_delivered(&self, id: i64) -> Result<()> {
        self.flag_notification(id, "delivered")
    }

    /// Marks a notification read.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] when no such notification exists.
    pub fn mark_notification_read(&self, id: i64) -> Result<()> {
        self.flag_notification(id, "read")
    }

    /// Sets one boolean flag. The column name is chosen from a closed set here,
    /// never taken from a caller, so this cannot become an injection point.
    fn flag_notification(&self, id: i64, column: &'static str) -> Result<()> {
        let sql = match column {
            "delivered" => "UPDATE notifications SET delivered = 1 WHERE id = ?1",
            "read" => "UPDATE notifications SET read = 1 WHERE id = ?1",
            other => {
                return Err(StoreError::corrupt(
                    NOTIFICATION_TABLE,
                    format!("unknown flag {other}"),
                ))
            }
        };
        if self.conn.execute(sql, [id])? == 0 {
            return Err(StoreError::not_found("notification", id));
        }
        Ok(())
    }

    /// Discards delivered-and-read notifications older than `before_ms`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`].
    pub fn prune_notifications(&self, before_ms: i64) -> Result<u64> {
        let removed = self.conn.execute(
            "DELETE FROM notifications WHERE delivered = 1 AND read = 1 AND ts < ?1",
            [before_ms],
        )?;
        Ok(removed as u64)
    }
}

fn pty_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PtySession> {
    Ok(PtySession {
        id: row.get(0)?,
        name: row.get(1)?,
        shell: row.get(2)?,
        cwd: row.get(3)?,
        created_at_ms: row.get(4)?,
        exited_at_ms: row.get(5)?,
        scrollback_path: row.get(6)?,
    })
}

struct RawAgent {
    id: String,
    adapter: String,
    workspace: String,
    state: String,
    created_at: i64,
    last_activity: i64,
    transcript_path: Option<String>,
    agent_native_session_id: Option<String>,
}

impl RawAgent {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            adapter: row.get(1)?,
            workspace: row.get(2)?,
            state: row.get(3)?,
            created_at: row.get(4)?,
            last_activity: row.get(5)?,
            transcript_path: row.get(6)?,
            agent_native_session_id: row.get(7)?,
        })
    }

    fn decode(self) -> Result<AgentSession> {
        Ok(AgentSession {
            id: self.id,
            adapter: self.adapter,
            workspace: self.workspace,
            state: self
                .state
                .parse()
                .map_err(|e| StoreError::corrupt(AGENT_TABLE, e))?,
            created_at_ms: self.created_at,
            last_activity_ms: self.last_activity,
            transcript_path: self.transcript_path,
            agent_native_session_id: self.agent_native_session_id,
        })
    }
}

struct RawSnippet {
    id: i64,
    workspace: String,
    label: String,
    command: String,
    use_count: i64,
}

impl RawSnippet {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            workspace: row.get(1)?,
            label: row.get(2)?,
            command: row.get(3)?,
            use_count: row.get(4)?,
        })
    }

    fn decode(self) -> Result<Snippet> {
        Ok(Snippet {
            id: self.id,
            workspace: self.workspace,
            label: self.label,
            command: self.command,
            use_count: row::u64_from_i64(SNIPPET_TABLE, "use_count", self.use_count)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use gonomad_proto::{CapabilitySet, PublicKey};

    use super::*;
    use crate::Store;

    fn on_disk() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("gonomad.db")).unwrap();
        (dir, store)
    }

    #[test]
    fn pty_sessions_survive_a_reopen() {
        // Sessions are daemon-owned and outlive connections (§2), so this must
        // hold across a restart, not just within one process.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gonomad.db");
        {
            let store = Store::open(&path).unwrap();
            store
                .sessions()
                .create_pty(
                    "pty-1",
                    "test terminal",
                    "pwsh",
                    "C:/code",
                    Some("C:/sb/1.log"),
                )
                .unwrap();
        }
        let store = Store::open(&path).unwrap();
        let session = store.sessions().pty("pty-1").unwrap().unwrap();
        assert_eq!(session.name, "test terminal");
        assert_eq!(session.scrollback_path.as_deref(), Some("C:/sb/1.log"));
        assert_eq!(session.exited_at_ms, None);
    }

    #[test]
    fn exited_ptys_drop_out_of_the_live_list() {
        let (_dir, store) = on_disk();
        let sessions = store.sessions();
        sessions.create_pty("a", "a", "pwsh", "/", None).unwrap();
        sessions.create_pty("b", "b", "bash", "/", None).unwrap();
        assert_eq!(sessions.list_live_ptys().unwrap().len(), 2);

        sessions.mark_pty_exited("a").unwrap();
        assert_eq!(sessions.list_live_ptys().unwrap().len(), 1);
        assert_eq!(sessions.list_ptys().unwrap().len(), 2);
        assert!(sessions.pty("a").unwrap().unwrap().exited_at_ms.is_some());

        // Marking an already-exited session is not an error.
        sessions.mark_pty_exited("a").unwrap();
        assert!(matches!(
            sessions.mark_pty_exited("nope"),
            Err(StoreError::NotFound { .. })
        ));

        assert!(sessions.remove_pty("a").unwrap());
        assert!(!sessions.remove_pty("a").unwrap());
    }

    #[test]
    fn only_metadata_is_stored_for_a_pty() {
        // §16.1: scrollback is a capped file, referenced by path. If a future
        // change adds a content column, this test should be the thing that
        // forces the conversation.
        let (_dir, store) = on_disk();
        let columns: Vec<String> = {
            let conn = store.raw_for_test();
            let mut stmt = conn
                .prepare("SELECT name FROM pragma_table_info('pty_sessions')")
                .unwrap();
            let names = stmt
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            names
        };
        assert!(columns.contains(&"scrollback_path".to_owned()));
        assert!(!columns.iter().any(|c| c.contains("content")));
    }

    #[test]
    fn agent_sessions_track_state_and_resume_information() {
        let (_dir, store) = on_disk();
        let sessions = store.sessions();
        let created = sessions
            .create_agent("agent-1", "claude-code", "C:/code", AgentState::Starting)
            .unwrap();
        assert_eq!(created.state, AgentState::Starting);
        assert_eq!(created.created_at_ms, created.last_activity_ms);

        sessions
            .set_agent_state("agent-1", AgentState::AwaitingApproval)
            .unwrap();
        let fetched = sessions.agent("agent-1").unwrap().unwrap();
        assert_eq!(fetched.state, AgentState::AwaitingApproval);
        assert!(!fetched.state.is_terminal());

        sessions
            .set_agent_resume_info("agent-1", Some("C:/t/1.jsonl"), Some("native-abc"))
            .unwrap();
        let fetched = sessions.agent("agent-1").unwrap().unwrap();
        assert_eq!(fetched.transcript_path.as_deref(), Some("C:/t/1.jsonl"));
        assert_eq!(
            fetched.agent_native_session_id.as_deref(),
            Some("native-abc")
        );

        sessions
            .set_agent_state("agent-1", AgentState::Exited)
            .unwrap();
        assert!(sessions
            .agent("agent-1")
            .unwrap()
            .unwrap()
            .state
            .is_terminal());

        assert_eq!(sessions.list_agents().unwrap().len(), 1);
        assert!(sessions.remove_agent("agent-1").unwrap());
        assert_eq!(sessions.agent("agent-1").unwrap(), None);
    }

    #[test]
    fn agent_state_strings_round_trip_and_reject_unknowns() {
        for state in AgentState::ALL {
            assert_eq!(state.as_str().parse::<AgentState>().unwrap(), state);
        }
        assert!("dreaming".parse::<AgentState>().is_err());
    }

    #[test]
    fn an_unknown_stored_agent_state_is_a_corrupt_row() {
        let (_dir, store) = on_disk();
        store
            .sessions()
            .create_agent("a", "generic", "/", AgentState::Idle)
            .unwrap();
        store
            .raw_for_test()
            .execute("UPDATE agent_sessions SET state = 'dreaming'", [])
            .unwrap();
        assert!(matches!(
            store.sessions().agent("a"),
            Err(StoreError::CorruptRow { .. })
        ));
    }

    #[test]
    fn editor_tabs_upsert_per_device() {
        let (_dir, store) = on_disk();
        let device = store
            .devices()
            .pair(
                &PublicKey::from_bytes([1; 32]),
                "Phone",
                None,
                CapabilitySet::default_grant(),
            )
            .unwrap();

        let tab = EditorTab {
            path: "src/main.rs".to_owned(),
            cursor_line: 10,
            cursor_col: 4,
            scroll_top: 3,
            dirty: false,
        };
        store
            .sessions()
            .upsert_editor_tab(&device.id, &tab)
            .unwrap();
        assert_eq!(
            store.sessions().editor_tabs(&device.id).unwrap(),
            vec![tab.clone()]
        );

        let moved = EditorTab {
            cursor_line: 99,
            dirty: true,
            ..tab
        };
        store
            .sessions()
            .upsert_editor_tab(&device.id, &moved)
            .unwrap();
        let tabs = store.sessions().editor_tabs(&device.id).unwrap();
        assert_eq!(tabs.len(), 1, "upsert must not duplicate");
        assert_eq!(tabs[0], moved);

        assert!(store
            .sessions()
            .close_editor_tab(&device.id, "src/main.rs")
            .unwrap());
        assert!(store.sessions().editor_tabs(&device.id).unwrap().is_empty());
    }

    #[test]
    fn editor_tabs_are_removed_when_their_device_row_is() {
        // The ON DELETE CASCADE only fires because `PRAGMA foreign_keys = ON`
        // is set per connection; this test is really asserting that pragma.
        let (_dir, store) = on_disk();
        let device = store
            .devices()
            .pair(
                &PublicKey::from_bytes([2; 32]),
                "Phone",
                None,
                CapabilitySet::EMPTY,
            )
            .unwrap();
        store
            .sessions()
            .upsert_editor_tab(
                &device.id,
                &EditorTab {
                    path: "a.rs".to_owned(),
                    cursor_line: 0,
                    cursor_col: 0,
                    scroll_top: 0,
                    dirty: false,
                },
            )
            .unwrap();

        store
            .raw_for_test()
            .execute("DELETE FROM devices WHERE id = ?1", [device.id.to_hex()])
            .unwrap();
        assert!(store.sessions().editor_tabs(&device.id).unwrap().is_empty());
    }

    #[test]
    fn a_tab_for_an_unpaired_device_is_rejected() {
        let (_dir, store) = on_disk();
        let result = store.sessions().upsert_editor_tab(
            &gonomad_proto::DeviceId::from_bytes([7; 32]),
            &EditorTab {
                path: "a.rs".to_owned(),
                cursor_line: 0,
                cursor_col: 0,
                scroll_top: 0,
                dirty: false,
            },
        );
        assert!(result.is_err(), "foreign key should have rejected this");
    }

    #[test]
    fn snippets_order_by_use_count() {
        let (_dir, store) = on_disk();
        let sessions = store.sessions();
        let test = sessions.upsert_snippet("/w", "test", "cargo test").unwrap();
        let build = sessions
            .upsert_snippet("/w", "build", "cargo build")
            .unwrap();
        sessions
            .upsert_snippet("/other", "test", "npm test")
            .unwrap();

        for _ in 0..3 {
            sessions.record_snippet_use(build.id).unwrap();
        }
        sessions.record_snippet_use(test.id).unwrap();

        let ordered = sessions.snippets("/w").unwrap();
        assert_eq!(ordered.len(), 2, "snippets are scoped to a workspace");
        assert_eq!(ordered[0].label, "build");
        assert_eq!(ordered[0].use_count, 3);
        assert_eq!(ordered[1].use_count, 1);

        // Re-saving the same label updates the command in place.
        let updated = sessions
            .upsert_snippet("/w", "build", "cargo build --release")
            .unwrap();
        assert_eq!(updated.id, build.id);
        assert_eq!(updated.command, "cargo build --release");
        assert_eq!(updated.use_count, 3, "use count must survive an edit");

        assert!(sessions.remove_snippet(build.id).unwrap());
        assert!(matches!(
            sessions.record_snippet_use(build.id),
            Err(StoreError::NotFound { .. })
        ));
    }

    #[test]
    fn notifications_are_a_fifo_queue() {
        let (_dir, store) = on_disk();
        let sessions = store.sessions();
        let first = sessions.push_notification("agent.approval", "{}").unwrap();
        let second = sessions.push_notification("build.done", "{}").unwrap();

        let pending = sessions.undelivered_notifications(10).unwrap();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].id, first.id, "oldest first");

        sessions.mark_notification_delivered(first.id).unwrap();
        let pending = sessions.undelivered_notifications(10).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, second.id);

        assert_eq!(sessions.recent_notifications(1).unwrap()[0].id, second.id);

        sessions.mark_notification_read(first.id).unwrap();
        assert!(matches!(
            sessions.mark_notification_read(9999),
            Err(StoreError::NotFound { .. })
        ));
    }

    #[test]
    fn pruning_spares_anything_undelivered_or_unread() {
        let (_dir, store) = on_disk();
        let sessions = store.sessions();
        let done = sessions.push_notification("a", "{}").unwrap();
        let unread = sessions.push_notification("b", "{}").unwrap();
        sessions.push_notification("c", "{}").unwrap();

        sessions.mark_notification_delivered(done.id).unwrap();
        sessions.mark_notification_read(done.id).unwrap();
        sessions.mark_notification_delivered(unread.id).unwrap();

        let removed = sessions.prune_notifications(i64::MAX).unwrap();
        assert_eq!(removed, 1);
        assert_eq!(sessions.recent_notifications(10).unwrap().len(), 2);
    }
}
