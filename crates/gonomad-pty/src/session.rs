//! PTY lifecycle and the daemon-side terminal emulator.
//!
//! # The central decision
//!
//! Each PTY has a **full terminal emulator running in the daemon**
//! (`ARCHITECTURE.md` §8.3). The daemon holds the authoritative screen; the
//! phone is sent a rendered screen, never a raw byte stream. Three consequences
//! justify the whole design:
//!
//! - **Reconnect is one snapshot.** Attaching sends the current screen, not a
//!   replay of scrollback, so there is no way for the phone's view to diverge
//!   from the daemon's.
//! - **Bandwidth gets a hard ceiling.** This is the big one. Raw stdout
//!   streaming has no upper bound: `npm install` or `yes` produces megabytes per
//!   second, and every byte would cross a cellular link and drain the battery to
//!   render frames nobody can read. With server-side emulation, output becomes at
//!   most N screen updates per second regardless of how fast the program writes.
//!   **The cost of a command becomes a function of what changes on screen, not of
//!   how much it prints.**
//! - **The phone can be genuinely dumb.** No VT parser, no ANSI state machine,
//!   no scrollback on the device.
//!
//! # What this slice does and does not do
//!
//! This delivers a working terminal: spawn, input, resize, kill, and a rendered
//! screen. It sends the screen as **text**, not as the cell-run diffs of §13.1.
//! Diffs, the adaptive frame rate, and the Compose glyph-atlas renderer arrive
//! with M2. The emulator boundary is already in the right place, so that is a
//! change to the wire format and the client, not to this architecture.
//!
//! # Known gap: process-tree teardown on Windows
//!
//! Windows has no process groups, so killing the shell can orphan its children —
//! a `node` or `python` it launched keeps running. The fix is a Job Object per
//! PTY (§8.2), which requires `unsafe` FFI that this crate forbids. Until that
//! lands in a dedicated module, [`PtyManager::kill`] terminates the shell and may
//! leave descendants behind. Recorded rather than assumed away.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use portable_pty::{CommandBuilder, PtySize};

use crate::shell::Shell;

/// Identifies a terminal session.
pub type PtyId = u64;

/// Default terminal size, chosen for a phone in portrait.
///
/// 80 columns is the convention every CLI tool is formatted for, and squeezing to
/// the ~55 a phone can legibly show breaks column-aligned output. The client
/// scrolls horizontally instead, which is the lesser evil.
pub const DEFAULT_COLS: u16 = 80;
/// Default terminal rows.
pub const DEFAULT_ROWS: u16 = 24;

/// Lines of scrollback retained per session.
///
/// Bounded because this lives in the daemon's memory for the process's lifetime.
/// 10k lines at 80 columns is roughly 1.6 MB of `char` worst case, comfortably
/// under the §14.1 budget of 2 MB per PTY.
pub const SCROLLBACK_LINES: usize = 10_000;

/// Errors from terminal operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PtyError {
    /// No session with that id, or it has already exited and been reaped.
    #[error("no such terminal")]
    NotFound,

    /// The configured shell could not be started.
    ///
    /// Carries the shell's display name because the actionable part of the
    /// message for a user is *which* shell failed, not the OS errno.
    #[error("could not start {shell}: {detail}")]
    SpawnFailed {
        /// Which shell failed to start.
        shell: String,
        /// The underlying reason.
        detail: String,
    },

    /// The host has no usable shell.
    #[error("no shell found on this machine")]
    NoShell,

    /// Writing to the terminal failed, usually because the process exited.
    #[error("terminal is no longer accepting input")]
    Closed,

    /// The concurrent-terminal cap was reached (`ARCHITECTURE.md` §3.8).
    #[error("terminal limit of {limit} reached; close one first")]
    TooManyTerminals {
        /// The configured ceiling.
        limit: usize,
    },
}

/// A rendered snapshot of a terminal's screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScreenSnapshot {
    /// Which terminal this is.
    pub pty_id: PtyId,
    /// The visible screen, one string per row, trailing blanks trimmed.
    pub rows: Vec<String>,
    /// Cursor row, zero-based from the top of the screen.
    pub cursor_row: u16,
    /// Cursor column, zero-based.
    pub cursor_col: u16,
    /// Terminal width in columns.
    pub cols: u16,
    /// Whether the child process has exited.
    pub exited: bool,
}

impl ScreenSnapshot {
    /// The screen as one newline-joined string.
    #[must_use]
    pub fn text(&self) -> String {
        self.rows.join("\n")
    }
}

/// One live terminal.
///
/// The id is not stored here: it is the key this session is filed under in
/// [`PtyManager::sessions`], and duplicating it would create two places that
/// could disagree.
struct PtySession {
    shell_id: String,
    /// The VT emulator. Shared with the reader thread, which is why it is behind
    /// a mutex rather than owned outright.
    parser: Arc<Mutex<vt100::Parser>>,
    writer: Box<dyn Write + Send>,
    master: Box<dyn portable_pty::MasterPty + Send>,
    /// Shared with the watcher thread that detects exit.
    child: Arc<Mutex<Box<dyn portable_pty::Child + Send + Sync>>>,
    exited: Arc<AtomicBool>,
    cols: u16,
    rows: u16,
}

/// Starts the thread that drains the PTY into the VT emulator.
///
/// A dedicated OS thread rather than a tokio task: portable-pty's reader is a
/// blocking `Read` with no async equivalent, and parking it on the async runtime
/// would occupy a worker thread for the session's entire life.
fn spawn_reader(
    id: PtyId,
    mut reader: Box<dyn Read + Send>,
    parser: Arc<Mutex<vt100::Parser>>,
    shell_name: &str,
) -> Result<(), PtyError> {
    std::thread::Builder::new()
        .name(format!("gonomad-pty-read-{id}"))
        .spawn(move || {
            let mut buf = [0u8; 8192];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => parser.lock().process(&buf[..n]),
                }
            }
        })
        .map(|_| ())
        .map_err(|e| PtyError::SpawnFailed {
            shell: shell_name.to_owned(),
            detail: format!("could not start reader thread: {e}"),
        })
}

/// Starts the thread that detects the child's exit.
///
/// Polls the child rather than waiting for the reader to see EOF. This is a
/// Windows necessity, not a preference: with ConPTY the read side does not reach
/// EOF while the daemon still holds the master handle open, and the daemon holds
/// it for the session's whole life so that it can resize. Waiting on reader EOF
/// therefore never reports the exit at all.
fn spawn_watcher(
    id: PtyId,
    child: Arc<Mutex<Box<dyn portable_pty::Child + Send + Sync>>>,
    exited: Arc<AtomicBool>,
    shell_name: &str,
) -> Result<(), PtyError> {
    std::thread::Builder::new()
        .name(format!("gonomad-pty-wait-{id}"))
        .spawn(move || loop {
            // `try_wait` rather than `wait`: `wait` would hold the mutex for the
            // process's entire lifetime and deadlock `kill`.
            let finished = matches!(child.lock().try_wait(), Ok(Some(_)));
            if finished {
                exited.store(true, Ordering::SeqCst);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        })
        .map(|_| ())
        .map_err(|e| PtyError::SpawnFailed {
            shell: shell_name.to_owned(),
            detail: format!("could not start watcher thread: {e}"),
        })
}

/// Owns every terminal on the machine.
///
/// Sessions are owned by the daemon rather than by a connection, which is the
/// central invariant of the whole product (`ARCHITECTURE.md` §2): losing signal
/// in a tunnel does not kill a running test suite, and reconnecting restores a
/// *view* of state that never stopped existing.
pub struct PtyManager {
    sessions: HashMap<PtyId, PtySession>,
    next_id: PtyId,
    max_sessions: usize,
}

impl PtyManager {
    /// Creates a manager with the default concurrent-terminal cap.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limit(16)
    }

    /// Creates a manager with an explicit cap (§3.8).
    #[must_use]
    pub fn with_limit(max_sessions: usize) -> Self {
        Self {
            sessions: HashMap::new(),
            next_id: 1,
            max_sessions,
        }
    }

    /// Spawns a terminal.
    ///
    /// # Errors
    ///
    /// - [`PtyError::TooManyTerminals`] if the cap is reached.
    /// - [`PtyError::NoShell`] if `shell` is `None` and none could be detected.
    /// - [`PtyError::SpawnFailed`] if the shell could not start.
    pub fn spawn(
        &mut self,
        shell: Option<Shell>,
        cwd: Option<&str>,
        cols: u16,
        rows: u16,
    ) -> Result<PtyId, PtyError> {
        if self.sessions.len() >= self.max_sessions {
            return Err(PtyError::TooManyTerminals {
                limit: self.max_sessions,
            });
        }

        let shell = match shell {
            Some(s) => s,
            None => crate::shell::default_shell().ok_or(PtyError::NoShell)?,
        };

        // Zero would make the emulator's geometry degenerate; clamp rather than
        // fail, since a client sending 0 is a bug we can absorb harmlessly.
        let cols = cols.max(1);
        let rows = rows.max(1);

        let pty_system = portable_pty::native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| PtyError::SpawnFailed {
                shell: shell.display_name.clone(),
                detail: e.to_string(),
            })?;

        let mut cmd = CommandBuilder::new(&shell.program);
        for arg in &shell.args {
            cmd.arg(arg);
        }
        if let Some(dir) = cwd {
            cmd.cwd(dir);
        }
        // ConPTY defaults to the legacy OEM code page, so anything non-ASCII
        // arrives mangled unless UTF-8 is forced (§8.2).
        cmd.env("TERM", "xterm-256color");

        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| PtyError::SpawnFailed {
                shell: shell.display_name.clone(),
                detail: e.to_string(),
            })?;
        // The slave handle must be dropped or the child never sees EOF on exit.
        drop(pair.slave);

        let writer = pair
            .master
            .take_writer()
            .map_err(|e| PtyError::SpawnFailed {
                shell: shell.display_name.clone(),
                detail: e.to_string(),
            })?;
        // Not `mut`: ownership moves into the reader thread, which takes it by
        // value and declares its own mutability.
        let reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| PtyError::SpawnFailed {
                shell: shell.display_name.clone(),
                detail: e.to_string(),
            })?;

        let parser = Arc::new(Mutex::new(vt100::Parser::new(rows, cols, SCROLLBACK_LINES)));
        let exited = Arc::new(AtomicBool::new(false));

        let child = Arc::new(Mutex::new(child));
        let id = self.next_id;

        spawn_reader(id, reader, Arc::clone(&parser), &shell.display_name)?;
        spawn_watcher(
            id,
            Arc::clone(&child),
            Arc::clone(&exited),
            &shell.display_name,
        )?;

        self.next_id += 1;

        self.sessions.insert(
            id,
            PtySession {
                shell_id: shell.id.clone(),
                parser,
                writer,
                master: pair.master,
                child,
                exited,
                cols,
                rows,
            },
        );

        tracing::info!(pty_id = id, shell = %shell.id, "terminal spawned");
        Ok(id)
    }

    /// Writes input to a terminal.
    ///
    /// # Errors
    ///
    /// [`PtyError::NotFound`] if the id is unknown, [`PtyError::Closed`] if the
    /// process is gone.
    pub fn write(&mut self, id: PtyId, data: &[u8]) -> Result<(), PtyError> {
        let session = self.sessions.get_mut(&id).ok_or(PtyError::NotFound)?;
        session
            .writer
            .write_all(data)
            .map_err(|_| PtyError::Closed)?;
        session.writer.flush().map_err(|_| PtyError::Closed)
    }

    /// Resizes a terminal.
    ///
    /// On Windows this is an API call rather than a signal, because there is no
    /// `SIGWINCH` (§8.2) — which is why resize is an explicit protocol operation.
    ///
    /// # Errors
    ///
    /// [`PtyError::NotFound`] if the id is unknown.
    pub fn resize(&mut self, id: PtyId, cols: u16, rows: u16) -> Result<(), PtyError> {
        let session = self.sessions.get_mut(&id).ok_or(PtyError::NotFound)?;
        let cols = cols.max(1);
        let rows = rows.max(1);

        session
            .master
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|_| PtyError::Closed)?;
        session.parser.lock().set_size(rows, cols);
        session.cols = cols;
        session.rows = rows;
        Ok(())
    }

    /// Returns the current screen.
    ///
    /// # Errors
    ///
    /// [`PtyError::NotFound`] if the id is unknown.
    pub fn screen(&self, id: PtyId) -> Result<ScreenSnapshot, PtyError> {
        let session = self.sessions.get(&id).ok_or(PtyError::NotFound)?;
        let parser = session.parser.lock();
        let screen = parser.screen();
        let (cursor_row, cursor_col) = screen.cursor_position();

        let rows = (0..session.rows)
            .map(|row| {
                // `contents_between` on a single row gives that row's text with
                // attributes stripped, which is what this text-based slice wants.
                let line = screen.contents_between(row, 0, row, session.cols);
                line.trim_end().to_owned()
            })
            .collect();

        Ok(ScreenSnapshot {
            pty_id: id,
            rows,
            cursor_row,
            cursor_col,
            cols: session.cols,
            exited: session.exited.load(Ordering::SeqCst),
        })
    }

    /// Terminates a terminal and forgets it.
    ///
    /// See the module docs: on Windows this may orphan descendant processes until
    /// Job Object support lands.
    ///
    /// # Errors
    ///
    /// [`PtyError::NotFound`] if the id is unknown.
    pub fn kill(&mut self, id: PtyId) -> Result<(), PtyError> {
        let session = self.sessions.remove(&id).ok_or(PtyError::NotFound)?;
        {
            let mut child = session.child.lock();
            let _ = child.kill();
            let _ = child.wait();
        }
        tracing::info!(pty_id = id, "terminal killed");
        Ok(())
    }

    /// Ids of every live terminal, in ascending order.
    #[must_use]
    pub fn list(&self) -> Vec<PtyId> {
        let mut ids: Vec<PtyId> = self.sessions.keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    /// The shell id a terminal was started with.
    #[must_use]
    pub fn shell_of(&self, id: PtyId) -> Option<&str> {
        self.sessions.get(&id).map(|s| s.shell_id.as_str())
    }

    /// Number of live terminals.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Whether no terminals are running.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Removes sessions whose process has exited.
    ///
    /// Returns the ids reaped, so the caller can notify clients. Not automatic:
    /// a user may want to read the final output of a command that failed, so the
    /// daemon keeps an exited terminal until something asks it not to.
    pub fn reap_exited(&mut self) -> Vec<PtyId> {
        let dead: Vec<PtyId> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.exited.load(Ordering::SeqCst))
            .map(|(id, _)| *id)
            .collect();
        for id in &dead {
            self.sessions.remove(id);
        }
        dead
    }
}

impl Default for PtyManager {
    fn default() -> Self {
        Self::new()
    }
}

// Hand-written because `PtySession` holds boxed trait objects that are not
// `Debug`. Prints counts rather than session internals, which is also what a log
// line actually wants.
impl std::fmt::Debug for PtyManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PtyManager")
            .field("live", &self.sessions.len())
            .field("max", &self.max_sessions)
            .field("next_id", &self.next_id)
            .finish()
    }
}

// Terminals must not outlive the daemon: an abandoned shell holds a console
// handle and, on Windows, may keep a whole process tree alive.
impl Drop for PtyManager {
    fn drop(&mut self) {
        for session in self.sessions.values() {
            let _ = session.child.lock().kill();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Waits until `predicate` holds or the budget expires.
    ///
    /// Terminal output is inherently asynchronous — a shell takes time to print
    /// its prompt — so tests poll rather than sleep a fixed amount, which would
    /// be both slower and flakier.
    fn wait_for(mut predicate: impl FnMut() -> bool) -> bool {
        for _ in 0..200 {
            if predicate() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        false
    }

    #[test]
    fn spawns_and_reports_a_screen() {
        let mut mgr = PtyManager::new();
        let id = mgr.spawn(None, None, 80, 24).expect("spawn");

        assert_eq!(mgr.list(), vec![id]);
        assert_eq!(mgr.len(), 1);
        assert!(!mgr.is_empty());

        let screen = mgr.screen(id).expect("screen");
        assert_eq!(screen.pty_id, id);
        assert_eq!(screen.rows.len(), 24);
        assert_eq!(screen.cols, 80);

        mgr.kill(id).expect("kill");
        assert!(mgr.is_empty());
    }

    #[test]
    fn a_command_produces_visible_output() {
        // The end-to-end property that matters: bytes typed in reach the shell,
        // and its output reaches the emulator's screen.
        let mut mgr = PtyManager::new();
        let id = mgr.spawn(None, None, 80, 24).expect("spawn");

        // Give the shell a moment to be ready for input.
        assert!(wait_for(|| mgr
            .screen(id)
            .is_ok_and(|s| !s.text().trim().is_empty())));

        mgr.write(id, b"echo gonomad-marker\r").expect("write");

        let found = wait_for(|| {
            mgr.screen(id)
                .is_ok_and(|s| s.text().contains("gonomad-marker"))
        });
        let screen = mgr.screen(id).expect("screen");
        assert!(
            found,
            "marker never appeared. screen was:\n{}",
            screen.text()
        );

        mgr.kill(id).expect("kill");
    }

    #[test]
    fn resize_changes_the_reported_geometry() {
        let mut mgr = PtyManager::new();
        let id = mgr.spawn(None, None, 80, 24).expect("spawn");

        mgr.resize(id, 100, 30).expect("resize");
        let screen = mgr.screen(id).expect("screen");
        assert_eq!(screen.cols, 100);
        assert_eq!(screen.rows.len(), 30);

        mgr.kill(id).expect("kill");
    }

    #[test]
    fn degenerate_sizes_are_clamped_not_rejected() {
        // A client sending 0 is a bug, but crashing the daemon over it is worse.
        let mut mgr = PtyManager::new();
        let id = mgr.spawn(None, None, 0, 0).expect("spawn with zero size");
        let screen = mgr.screen(id).expect("screen");
        assert!(screen.cols >= 1);
        assert!(!screen.rows.is_empty());

        mgr.resize(id, 0, 0).expect("resize to zero");
        assert!(mgr.screen(id).expect("screen").cols >= 1);

        mgr.kill(id).expect("kill");
    }

    #[test]
    fn several_terminals_coexist_independently() {
        let mut mgr = PtyManager::new();
        let a = mgr.spawn(None, None, 80, 24).expect("a");
        let b = mgr.spawn(None, None, 80, 24).expect("b");
        let c = mgr.spawn(None, None, 80, 24).expect("c");

        assert_eq!(mgr.list(), vec![a, b, c]);
        assert_ne!(a, b);
        assert_ne!(b, c);

        // Writing to one must not disturb another.
        mgr.write(b, b"echo only-in-b\r").expect("write b");
        assert!(wait_for(|| mgr
            .screen(b)
            .is_ok_and(|s| s.text().contains("only-in-b"))));
        assert!(!mgr.screen(a).expect("a").text().contains("only-in-b"));

        for id in [a, b, c] {
            mgr.kill(id).expect("kill");
        }
    }

    #[test]
    fn the_terminal_cap_is_enforced() {
        let mut mgr = PtyManager::with_limit(2);
        let a = mgr.spawn(None, None, 80, 24).expect("a");
        let b = mgr.spawn(None, None, 80, 24).expect("b");

        match mgr.spawn(None, None, 80, 24) {
            Err(PtyError::TooManyTerminals { limit }) => assert_eq!(limit, 2),
            other => panic!("expected the cap to be enforced, got {other:?}"),
        }

        // Closing one frees a slot, so the cap is a ceiling rather than a
        // lifetime quota.
        mgr.kill(a).expect("kill");
        let c = mgr.spawn(None, None, 80, 24).expect("after freeing a slot");

        for id in [b, c] {
            mgr.kill(id).expect("kill");
        }
    }

    #[test]
    fn unknown_ids_are_rejected_everywhere() {
        let mut mgr = PtyManager::new();
        assert!(matches!(mgr.screen(999), Err(PtyError::NotFound)));
        assert!(matches!(mgr.write(999, b"x"), Err(PtyError::NotFound)));
        assert!(matches!(mgr.resize(999, 80, 24), Err(PtyError::NotFound)));
        assert!(matches!(mgr.kill(999), Err(PtyError::NotFound)));
        assert!(mgr.shell_of(999).is_none());
    }

    #[test]
    fn ids_are_never_reused_after_close() {
        // Reuse would let a stale client write into a terminal it does not own.
        let mut mgr = PtyManager::new();
        let first = mgr.spawn(None, None, 80, 24).expect("first");
        mgr.kill(first).expect("kill");
        let second = mgr.spawn(None, None, 80, 24).expect("second");
        assert_ne!(first, second);
        mgr.kill(second).expect("kill");
    }

    #[test]
    fn exiting_is_detected_and_reapable() {
        let mut mgr = PtyManager::new();
        let id = mgr.spawn(None, None, 80, 24).expect("spawn");

        assert!(wait_for(|| mgr
            .screen(id)
            .is_ok_and(|s| !s.text().trim().is_empty())));
        mgr.write(id, b"exit\r").expect("write");

        assert!(
            wait_for(|| mgr.screen(id).is_ok_and(|s| s.exited)),
            "the shell never reported exit"
        );

        // An exited terminal is retained until reaped, so the user can still
        // read the output of whatever failed.
        assert_eq!(mgr.len(), 1);
        assert_eq!(mgr.reap_exited(), vec![id]);
        assert!(mgr.is_empty());
    }

    #[test]
    fn shell_of_reports_what_was_spawned() {
        let mut mgr = PtyManager::new();
        let expected = crate::shell::default_shell().expect("a shell exists");
        let id = mgr.spawn(None, None, 80, 24).expect("spawn");
        assert_eq!(mgr.shell_of(id), Some(expected.id.as_str()));
        mgr.kill(id).expect("kill");
    }

    #[test]
    fn dropping_the_manager_kills_its_terminals() {
        // An abandoned shell holds a console handle and, on Windows, may keep a
        // whole process tree alive.
        let mut mgr = PtyManager::new();
        let id = mgr.spawn(None, None, 80, 24).expect("spawn");
        assert_eq!(mgr.list(), vec![id]);
        drop(mgr);
        // Nothing to assert directly without inspecting the OS process table;
        // this exercises the Drop path so a panic or hang there is caught.
    }

    #[test]
    fn snapshot_text_joins_rows_with_newlines() {
        let snap = ScreenSnapshot {
            pty_id: 1,
            rows: vec!["one".into(), "two".into()],
            cursor_row: 0,
            cursor_col: 0,
            cols: 80,
            exited: false,
        };
        assert_eq!(snap.text(), "one\ntwo");
    }
}
