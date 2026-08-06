//! The UniFFI surface, transcribed from `docs/ffi-contract.md`.
//!
//! Proc-macro mode, not a `.udl` file: the types below *are* the definition, so
//! there is no second description of the same API to drift out of sync with the
//! first. `uniffi-bindgen --library` reads the metadata the macros embed in the
//! compiled artifact.
//!
//! # This module holds no logic
//!
//! Every method here does three things: convert arguments, call
//! [`crate::client`], convert the result. Anything resembling a decision about
//! protocol state belongs on the other side of that call
//! (`ARCHITECTURE.md` §6.2). The one thing this layer owns is **the error
//! vocabulary**: [`ClientError`] is fine-grained for the log, and
//! [`GonomadError`] is the closed set Compose renders an action for (§11.2).
//!
//! # Two types named `GonomadClient`
//!
//! [`crate::client::GonomadClient`] is the real client; the object below is the
//! handle Kotlin holds, and it must carry that name because the generated class
//! name is the Kotlin-visible API the app already codes against. They live in
//! different modules for exactly that reason.
//!
//! # Messages a user sees never name a Rust type
//!
//! `Debug` output, error enum variants, and crate names are all absent from the
//! `detail` strings produced here. A user reading "TransportError::WrongPeer" has
//! been handed a bug report to write rather than an action to take.

use std::sync::Arc;

use gonomad_proto::methods::{self as proto_methods, ScreenFrame};
use gonomad_transport::TransportError;

use crate::client::{
    self, ClientError, ConnPhase, ConnectionStatus, ScreenObserver, StateObserver,
};
use crate::storage::PairedDaemon;

/// Where the connection stands, as rendered by the connection chip (§23).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ConnState {
    /// Paired, but nothing is connected.
    Disconnected,
    /// A dial or hello exchange is in progress.
    Connecting,
    /// A control stream is live.
    Connected,
    /// No pairing on record, or the machine does not recognise this device.
    Unpaired,
    /// The machine revoked this device.
    Revoked,
}

impl From<ConnPhase> for ConnState {
    fn from(phase: ConnPhase) -> Self {
        match phase {
            ConnPhase::Disconnected => Self::Disconnected,
            ConnPhase::Connecting => Self::Connecting,
            ConnPhase::Connected => Self::Connected,
            ConnPhase::Unpaired => Self::Unpaired,
            ConnPhase::Revoked => Self::Revoked,
        }
    }
}

/// The paired machine, for the pairing card.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DeviceInfo {
    /// The machine's identifier as hex, to be shortened for display.
    ///
    /// The daemon's Noise static key. See
    /// [`crate::storage::PairedDaemon::device_id`] for why it cannot be a
    /// `DeviceId`: the pairing QR does not carry the daemon's signing key, so this
    /// device has no way to derive one that would agree with the laptop's.
    pub device_id: String,
    /// The machine's host name.
    pub name: String,
    /// When pairing completed, unix milliseconds.
    pub paired_at: i64,
    /// When the machine was last reached, unix milliseconds.
    pub last_seen: Option<i64>,
}

impl From<PairedDaemon> for DeviceInfo {
    fn from(daemon: PairedDaemon) -> Self {
        Self {
            device_id: daemon.device_id,
            name: daemon.name,
            paired_at: daemon.paired_at_ms,
            last_seen: daemon.last_seen_ms,
        }
    }
}

/// The connection status.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Status {
    /// Where the connection stands.
    pub state: ConnState,
    /// The machine's name, once known.
    pub daemon_name: Option<String>,
    /// Last measured round-trip time in milliseconds.
    pub rtt_ms: Option<u32>,
    /// Which rung of the transport ladder is carrying the session — `"LAN"` for
    /// this slice. Surfaced because a silently relayed session that feels slow
    /// is worse than a visibly relayed one (§4.2).
    pub transport: Option<String>,
}

impl From<ConnectionStatus> for Status {
    fn from(status: ConnectionStatus) -> Self {
        Self {
            state: status.phase.into(),
            daemon_name: status.daemon_name,
            rtt_ms: status.rtt_ms,
            transport: status.transport.map(|tier| tier.label().to_owned()),
        }
    }
}

/// What a directory entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum EntryKind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
    /// A symlink or reparse point, deliberately not followed.
    Symlink,
}

/// One entry in a directory listing.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DirEntry {
    /// File name only, never a path: a full path would disclose host layout.
    pub name: String,
    /// What it is.
    pub kind: EntryKind,
    /// Size in bytes, for files.
    pub size_bytes: Option<u64>,
    /// Last-modified time, unix milliseconds.
    pub modified_ms: Option<i64>,
    /// Whether the name marks it hidden by convention.
    pub is_hidden: bool,
    /// Whether git ignores it.
    ///
    /// Always `false` in this slice. `fs.list` does not carry the flag yet —
    /// ignore-awareness arrives with the file service at M3 — and reporting a
    /// guess would have the UI dim files that git is tracking.
    pub is_git_ignored: bool,
}

impl From<proto_methods::DirEntry> for DirEntry {
    fn from(entry: proto_methods::DirEntry) -> Self {
        Self {
            name: entry.name,
            kind: match entry.kind {
                proto_methods::EntryKind::Directory => EntryKind::Directory,
                proto_methods::EntryKind::Symlink => EntryKind::Symlink,
                // Includes any kind a newer daemon adds: showing an unknown
                // entry as a file is wrong in a way the user can see and
                // recover from, whereas hiding it is not.
                _ => EntryKind::File,
            },
            size_bytes: entry.size_bytes,
            modified_ms: entry.modified_ms,
            is_hidden: entry.is_hidden,
            is_git_ignored: false,
        }
    }
}

/// A file's contents.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FileContent {
    /// The path that was read.
    pub path: String,
    /// Contents as UTF-8. Binary files are refused by the daemon.
    pub text: String,
    /// BLAKE3 of the bytes sent — the compare-and-swap baseline for a future
    /// write (§12.2). Hex, because the contract's type is a string and the
    /// client only ever echoes it back.
    pub content_hash: String,
    /// Whether the file exceeded the read cap, so the UI can say "showing the
    /// first N bytes" rather than presenting a truncated file as complete.
    pub truncated: bool,
}

impl From<proto_methods::FsReadResult> for FileContent {
    fn from(result: proto_methods::FsReadResult) -> Self {
        Self {
            path: result.path,
            text: result.text,
            content_hash: result.content_hash.to_hex(),
            truncated: result.truncated,
        }
    }
}

/// A terminal's rendered screen.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TerminalFrame {
    /// Which terminal.
    pub pty_id: u64,
    /// The visible screen as text, rows separated by newlines. The cell-diff
    /// renderer (§13) arrives with M2 and changes this field, not the API.
    pub screen: String,
    /// Cursor row, zero-based.
    pub cursor_row: u16,
    /// Cursor column, zero-based.
    pub cursor_col: u16,
}

impl From<ScreenFrame> for TerminalFrame {
    fn from(frame: ScreenFrame) -> Self {
        Self {
            pty_id: frame.pty_id,
            screen: frame.rows.join("\n"),
            cursor_row: frame.cursor_row,
            cursor_col: frame.cursor_col,
        }
    }
}

/// A newly spawned terminal and its first screen.
///
/// Carries the frame as well as the id so the UI can tell "spawned, no output
/// yet" from "spawned, first frame lost". With an id alone those are
/// indistinguishable and the screen stays blank forever.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TerminalHandle {
    /// The new terminal's id.
    pub pty_id: u64,
    /// Its screen immediately after spawning.
    pub initial: TerminalFrame,
}

/// Every failure the app can receive.
///
/// A closed set, so Compose can render a correct action for each rather than
/// showing the machine's prose to the user (§11.2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
#[non_exhaustive]
pub enum GonomadError {
    /// This device does not hold the capability the operation needs.
    #[error("not allowed: {capability}")]
    Denied {
        /// The capability that would have permitted it.
        capability: String,
    },

    /// The path, terminal, or record does not exist.
    #[error("not found")]
    NotFound,

    /// The machine is rate-limiting this device.
    #[error("rate limited")]
    RateLimited {
        /// How long to wait before retrying.
        retry_after_ms: u32,
    },

    /// The machine's GoNomad does not implement this.
    #[error("unsupported: {feature}")]
    Unsupported {
        /// The feature or method that is unavailable.
        feature: String,
    },

    /// The connection failed.
    #[error("{detail}")]
    Transport {
        /// A sentence to show the user.
        detail: String,
    },

    /// The exchange itself went wrong.
    #[error("{detail}")]
    Protocol {
        /// A sentence to show the user.
        detail: String,
    },

    /// No machine is paired.
    #[error("not paired")]
    NotPaired,
}

impl From<ClientError> for GonomadError {
    fn from(error: ClientError) -> Self {
        match error {
            ClientError::NotPaired | ClientError::Unpaired => Self::NotPaired,
            ClientError::RateLimited { retry_after_ms } => Self::RateLimited { retry_after_ms },
            ClientError::Remote(remote) => from_remote(remote),
            ClientError::Transport(transport) => Self::Transport {
                detail: transport_detail(&transport),
            },
            ClientError::Timeout => Self::Transport {
                detail: "Your machine did not answer in time.".to_owned(),
            },
            ClientError::ConnectionLost => Self::Transport {
                detail: "The connection to your machine was lost.".to_owned(),
            },
            ClientError::NotConnected => Self::Transport {
                detail: "Not connected to your machine yet.".to_owned(),
            },
            ClientError::Revoked => Self::Protocol {
                detail: "This device's access was revoked. Pair again to restore it.".to_owned(),
            },
            ClientError::DaemonTooOld { .. } => Self::Unsupported {
                feature: "this version of the app".to_owned(),
            },
            ClientError::AppTooOld { .. } => Self::Unsupported {
                feature: "this version of the app; update it".to_owned(),
            },
            ClientError::TooLarge { max, .. } => Self::Protocol {
                detail: format!("That is too large to send in one piece (limit {max} bytes)."),
            },
            ClientError::Pairing(pairing) => Self::Protocol {
                // `PairingError`'s messages are already written for a person
                // holding a phone that just scanned something ("not a GoNomad
                // pairing ticket"), so they pass through.
                detail: pairing.to_string(),
            },
            ClientError::Storage(storage) => {
                // The path in a `StorageError` is an app-private Android
                // directory the user cannot act on, so it is logged and not
                // shown.
                tracing::error!(error = %storage, "local state failure");
                Self::Protocol {
                    detail: "This device could not save its pairing.".to_owned(),
                }
            }
            ClientError::NoPairingInProgress => Self::Protocol {
                detail: "That pairing is no longer in progress. Scan the code again.".to_owned(),
            },
            ClientError::Malformed { detail } => {
                tracing::warn!(detail, "malformed message from the daemon");
                Self::Protocol {
                    detail: "Your machine sent something this app could not read.".to_owned(),
                }
            }
            ClientError::Framing(framing) => {
                tracing::warn!(error = %framing, "framing failure");
                Self::Protocol {
                    detail: "Your machine sent something this app could not read.".to_owned(),
                }
            }
            ClientError::Internal(detail) => {
                tracing::error!(detail, "internal client failure");
                Self::Protocol {
                    detail: "Something went wrong in the app.".to_owned(),
                }
            } // Deliberately no catch-all. `ClientError` lives in this crate, so a
              // new variant is a compile error here rather than a silent fall
              // through to a message nobody wrote for a user to read.
        }
    }
}

/// Maps the daemon's own error onto the closed client set.
fn from_remote(remote: gonomad_proto::ProtoError) -> GonomadError {
    use gonomad_proto::ErrorKind;
    match remote.kind {
        ErrorKind::Denied { capability } => GonomadError::Denied {
            capability: capability.as_str().to_owned(),
        },
        ErrorKind::NotFound => GonomadError::NotFound,
        ErrorKind::RateLimited { retry_after_ms } => GonomadError::RateLimited { retry_after_ms },
        ErrorKind::Unsupported { feature, .. } => GonomadError::Unsupported { feature },
        // The remaining kinds have no variant in this slice's contract —
        // `Conflict` needs the write path, `PresenceRequired` needs the presence
        // key. Their `user_message` is written for the person holding the phone,
        // so it is the right thing to surface rather than a placeholder.
        ref other => GonomadError::Protocol {
            detail: other.user_message(),
        },
    }
}

/// Turns a transport failure into a sentence with an action in it.
///
/// Deliberately not `TransportError`'s own `Display`: some variants render an
/// `io::ErrorKind` (`AddrInUse`) or a mux violation, and a user shown those has
/// been given a bug report instead of a next step.
fn transport_detail(error: &TransportError) -> String {
    match error {
        TransportError::NoReachableAddress
        | TransportError::Connect { .. }
        | TransportError::Bind { .. } => {
            "Could not reach your machine. Check it is awake and on the same Wi-Fi."
        }
        TransportError::HandshakeFailed => {
            "Could not agree a secure connection. If you are pairing, the code may be wrong."
        }
        TransportError::PeerNotAuthorized | TransportError::WrongPeer => {
            "That is not the machine this device is paired with."
        }
        TransportError::Crypto | TransportError::NonceExhausted => {
            "The secure connection failed. Try connecting again."
        }
        TransportError::Timeout => "Your machine did not answer in time.",
        TransportError::Closed | TransportError::ConnectionLost | TransportError::StreamClosed => {
            "The connection to your machine was lost."
        }
        TransportError::NotListening | TransportError::Config(_) => {
            "This app is misconfigured. Please report this."
        }
        _ => "The connection to your machine failed.",
    }
    .to_owned()
}

/// Receives every connection-state change.
///
/// **Single registration.** The Rust side holds exactly one listener, so
/// registering twice replaces the first — register once in a process-wide
/// repository and fan out with a `SharedFlow`.
#[uniffi::export(callback_interface)]
pub trait StatusListener: Send + Sync + 'static {
    /// Called after the connection status changed.
    fn on_status(&self, status: Status);
}

/// Receives terminal screens. Single registration, exactly as [`StatusListener`].
#[uniffi::export(callback_interface)]
pub trait TerminalListener: Send + Sync + 'static {
    /// Called with a newly fetched screen.
    fn on_frame(&self, frame: TerminalFrame);
}

/// Adapts a Kotlin [`StatusListener`] to the client's observer.
struct StatusBridge(Box<dyn StatusListener>);

impl StateObserver for StatusBridge {
    fn on_state(&self, status: ConnectionStatus) {
        self.0.on_status(status.into());
    }
}

/// Adapts a Kotlin [`TerminalListener`] to the client's observer.
struct TerminalBridge(Box<dyn TerminalListener>);

impl ScreenObserver for TerminalBridge {
    fn on_screen(&self, frame: ScreenFrame) {
        self.0.on_frame(frame.into());
    }
}

/// The handle Kotlin holds. All protocol logic is behind it, in Rust.
#[derive(Debug, uniffi::Object)]
pub struct GonomadClient {
    core: client::GonomadClient,
}

#[uniffi::export]
impl GonomadClient {
    /// Loads a persisted identity and pairing, or creates an identity on first
    /// run.
    ///
    /// `state_dir` is app-private storage, which on Android is excluded from
    /// backup and device transfer.
    ///
    /// # Errors
    ///
    /// [`GonomadError::Protocol`] when the directory is unusable or the stored
    /// identity is corrupt. Corrupt state is reported rather than replaced:
    /// regenerating the key would silently orphan the pairing.
    #[uniffi::constructor]
    pub fn create(state_dir: String) -> Result<Arc<Self>, GonomadError> {
        // The `String` is consumed rather than borrowed: UniFFI lifts a foreign
        // string into an owned one, so borrowing it here would only copy it again.
        let core = client::GonomadClient::create(state_dir)?;
        Ok(Arc::new(Self { core }))
    }

    /// True once this device has completed pairing with some machine.
    ///
    /// Synchronous, and answered from memory — loaded once at construction, as
    /// the contract requires.
    pub fn is_paired(&self) -> bool {
        self.core.is_paired()
    }

    /// The paired machine, if any. Synchronous, as [`GonomadClient::is_paired`].
    pub fn paired_daemon(&self) -> Option<DeviceInfo> {
        self.core.paired_daemon().map(Into::into)
    }

    /// Runs the pairing handshake for a scanned QR payload and returns the SAS.
    ///
    /// The UI **must** show the digits and require the user to confirm they match
    /// the laptop before calling [`GonomadClient::confirm_pairing`]. That
    /// comparison is the defence against a photographed QR (§9.2). Nothing is
    /// registered or stored by this call.
    ///
    /// # Errors
    ///
    /// [`GonomadError::Protocol`] when the payload is not a GoNomad code, or
    /// [`GonomadError::Transport`] when the handshake fails — which is what a
    /// wrong pairing code looks like from the phone (§19 R24).
    pub async fn begin_pairing(&self, qr_payload: String) -> Result<String, GonomadError> {
        Ok(self.core.begin_pairing(qr_payload).await?)
    }

    /// Commits the pairing after the user confirmed the SAS matched.
    ///
    /// `device_name` is **this phone's** name, as it will appear in the machine's
    /// device list and audit log.
    ///
    /// Performs an authenticated `sys.register` over the established session and
    /// stores nothing unless it round-trips (§19 R24). Treating handshake
    /// completion as success would register a device that guessed nothing.
    ///
    /// # Errors
    ///
    /// [`GonomadError::Protocol`] when no pairing is in progress or the machine
    /// refuses to register this device, and [`GonomadError::Transport`] when the
    /// session died. Nothing is persisted in any of those cases.
    pub async fn confirm_pairing(&self, device_name: String) -> Result<(), GonomadError> {
        Ok(self.core.confirm_pairing(device_name).await?)
    }

    /// Abandons an in-progress pairing (SAS mismatch, or the user cancelled).
    pub fn cancel_pairing(&self) {
        self.core.cancel_pairing();
    }

    /// Connects to the paired machine.
    ///
    /// # Errors
    ///
    /// [`GonomadError::NotPaired`] with no pairing on record, or
    /// [`GonomadError::Transport`] when the machine cannot be reached.
    pub async fn connect(&self) -> Result<(), GonomadError> {
        Ok(self.core.connect().await?)
    }

    /// Drops the connection, keeping the pairing.
    pub fn disconnect(&self) {
        self.core.disconnect();
    }

    /// The current connection status, from memory.
    pub fn status(&self) -> Status {
        self.core.status().into()
    }

    /// Registers the connection-state listener, replacing any previous one.
    ///
    /// See [`StatusListener`] for why there is exactly one.
    pub fn observe_status(&self, listener: Box<dyn StatusListener>) {
        self.core.observe_state(Arc::new(StatusBridge(listener)));
    }

    /// Lists one directory level.
    ///
    /// # Errors
    ///
    /// [`GonomadError::NotFound`] for a path that does not exist *or* is outside
    /// the workspace roots — the daemon does not distinguish the two, so that a
    /// caller cannot map the filesystem one probe at a time (§3.6).
    pub async fn list_dir(&self, path: String) -> Result<Vec<DirEntry>, GonomadError> {
        let entries = self.core.list_dir(path).await?;
        Ok(entries.into_iter().map(Into::into).collect())
    }

    /// Reads a file as text.
    ///
    /// # Errors
    ///
    /// As [`GonomadClient::list_dir`].
    pub async fn read_file(&self, path: String) -> Result<FileContent, GonomadError> {
        Ok(self.core.read_file(path).await?.into())
    }

    /// The workspace roots this device may reach.
    ///
    /// # Errors
    ///
    /// [`GonomadError::Transport`] when there is no live connection: the roots
    /// come from the session's `HelloOk`, so they cannot be answered without one.
    pub async fn workspace_roots(&self) -> Result<Vec<String>, GonomadError> {
        Ok(self.core.workspace_roots().await?)
    }

    /// Spawns a terminal and returns its id together with its first frame.
    ///
    /// Starts a poller that pushes later frames to the registered
    /// [`TerminalListener`].
    ///
    /// # Errors
    ///
    /// [`GonomadError::Denied`] without the terminal capability, or
    /// [`GonomadError::NotFound`] when `cwd` is outside the workspace roots.
    pub async fn spawn_terminal(
        &self,
        cwd: Option<String>,
    ) -> Result<TerminalHandle, GonomadError> {
        let spawned = self.core.spawn_terminal(cwd).await?;
        Ok(TerminalHandle {
            pty_id: spawned.pty_id,
            initial: spawned.initial.into(),
        })
    }

    /// Lists the terminals still running on the machine.
    ///
    /// Call this after connecting. The machine owns the terminals, so they are
    /// still running after a disconnect, an app restart, or a phone reboot — this
    /// is how the app finds them again.
    ///
    /// # Errors
    ///
    /// [`GonomadError::Transport`] when there is no live connection.
    pub async fn list_terminals(&self) -> Result<Vec<u64>, GonomadError> {
        Ok(self.core.list_terminals().await?)
    }

    /// Reattaches to a terminal already running on the machine.
    ///
    /// The counterpart to [`Self::spawn_terminal`], and what makes background
    /// terminals *usable* rather than merely alive: without it, the machine keeps
    /// a build running exactly as designed while the phone has no route back to
    /// it, which from the user's chair is indistinguishable from losing the work.
    ///
    /// Returns the terminal's current screen, so a restored tab renders
    /// immediately instead of sitting blank for a poll interval.
    ///
    /// # Errors
    ///
    /// [`GonomadError::NotFound`] if the terminal has since exited and been
    /// reaped — the normal outcome for a stale id from a previous session, and
    /// the signal to drop that tab.
    pub async fn attach_terminal(&self, pty_id: u64) -> Result<TerminalFrame, GonomadError> {
        Ok(self.core.attach_terminal(pty_id).await?.into())
    }

    /// Sends input to a terminal. Control characters are how `Ctrl-C` is sent.
    ///
    /// # Errors
    ///
    /// [`GonomadError::NotFound`] for a terminal that has gone.
    pub async fn send_input(&self, pty_id: u64, data: String) -> Result<(), GonomadError> {
        Ok(self.core.send_input(pty_id, data).await?)
    }

    /// Resizes a terminal.
    ///
    /// # Errors
    ///
    /// [`GonomadError::NotFound`] for a terminal that has gone.
    pub async fn resize_terminal(
        &self,
        pty_id: u64,
        cols: u16,
        rows: u16,
    ) -> Result<(), GonomadError> {
        Ok(self.core.resize_terminal(pty_id, cols, rows).await?)
    }

    /// Terminates a terminal and stops its poller.
    ///
    /// # Errors
    ///
    /// [`GonomadError::NotFound`] for a terminal that has already gone. The
    /// poller stops either way.
    pub async fn close_terminal(&self, pty_id: u64) -> Result<(), GonomadError> {
        Ok(self.core.close_terminal(pty_id).await?)
    }

    /// Registers the terminal listener, replacing any previous one.
    ///
    /// Single registration, exactly as [`GonomadClient::observe_status`].
    pub fn observe_terminal(&self, listener: Box<dyn TerminalListener>) {
        self.core
            .observe_screens(Arc::new(TerminalBridge(listener)));
    }

    /// Forgets the machine and wipes local keys.
    ///
    /// # Errors
    ///
    /// [`GonomadError::Protocol`] when a file could not be removed. The
    /// in-memory state is cleared regardless, so the app is unpaired either way.
    pub fn unpair(&self) -> Result<(), GonomadError> {
        Ok(self.core.unpair()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gonomad_proto::{Capability, Digest, ErrorKind, ProtoError};

    #[test]
    fn every_daemon_error_kind_maps_onto_the_closed_set() {
        // The contract's promise: Compose can render an action for anything the
        // app can receive. A kind with no mapping would reach the UI as nothing.
        let cases = [
            ErrorKind::Denied {
                capability: Capability::FsWrite,
            },
            ErrorKind::NotFound,
            ErrorKind::Conflict {
                current_hash: Digest::of(b"x"),
            },
            ErrorKind::RateLimited { retry_after_ms: 50 },
            ErrorKind::ResourceExhausted {
                resource: "ptys".into(),
                limit: 4,
            },
            ErrorKind::Unsupported {
                feature: "fs.write".into(),
                since_version: None,
            },
            ErrorKind::PresenceRequired {
                challenge: Digest::of(b"y"),
            },
            ErrorKind::Cancelled,
            ErrorKind::BadRequest {
                detail: "bad".into(),
            },
            ErrorKind::Internal {
                trace_id: "t-1".into(),
            },
        ];
        for kind in cases {
            let mapped = from_remote(ProtoError::new(kind.clone()));
            let rendered = format!("{mapped}");
            assert!(!rendered.is_empty(), "{kind:?} produced an empty message");
        }
    }

    #[test]
    fn the_variants_the_ui_branches_on_are_preserved_exactly() {
        assert_eq!(
            from_remote(ProtoError::denied(Capability::PtySpawn)),
            GonomadError::Denied {
                capability: Capability::PtySpawn.as_str().to_owned()
            }
        );
        assert_eq!(from_remote(ProtoError::not_found()), GonomadError::NotFound);
        assert_eq!(
            from_remote(ProtoError::rate_limited(1500)),
            GonomadError::RateLimited {
                retry_after_ms: 1500
            }
        );
        assert_eq!(
            from_remote(ProtoError::new(ErrorKind::Unsupported {
                feature: "git.status".into(),
                since_version: Some(4),
            })),
            GonomadError::Unsupported {
                feature: "git.status".into()
            }
        );
    }

    #[test]
    fn no_user_facing_message_names_a_rust_type() {
        // A user shown "TransportError::WrongPeer" has been handed a bug report
        // rather than an action.
        let errors = [
            GonomadError::from(ClientError::Transport(TransportError::WrongPeer)),
            GonomadError::from(ClientError::Transport(TransportError::Bind {
                addr: "127.0.0.1:1".parse().expect("literal"),
                kind: std::io::ErrorKind::AddrInUse,
            })),
            GonomadError::from(ClientError::Transport(TransportError::Protocol(
                gonomad_transport::ProtocolViolation::UnknownChannel { channel: 9 },
            ))),
            GonomadError::from(ClientError::Timeout),
            GonomadError::from(ClientError::ConnectionLost),
            GonomadError::from(ClientError::Malformed { detail: "internal" }),
            GonomadError::from(ClientError::Internal("internal")),
            GonomadError::from(ClientError::TooLarge { len: 9, max: 8 }),
            GonomadError::from(ClientError::Revoked),
            GonomadError::from(ClientError::NoPairingInProgress),
        ];
        for error in errors {
            let rendered = format!("{error}");
            for forbidden in [
                "Error",
                "::",
                "AddrInUse",
                "TransportError",
                "ClientError",
                "gonomad_",
                "Err(",
                "detail:",
            ] {
                assert!(
                    !rendered.contains(forbidden),
                    "{rendered:?} leaks {forbidden:?}"
                );
            }
            assert!(rendered.len() > 4, "{rendered:?} says nothing useful");
        }
    }

    #[test]
    fn a_wrong_pairing_code_reads_as_a_pairing_problem() {
        // The most likely real failure, so the wording has to point at the code.
        let mapped = GonomadError::from(ClientError::Transport(TransportError::HandshakeFailed));
        match mapped {
            GonomadError::Transport { detail } => {
                assert!(detail.contains("code"), "got {detail:?}");
            }
            other => panic!("expected Transport, got {other:?}"),
        }
    }

    #[test]
    fn an_unpaired_machine_and_no_pairing_both_read_as_not_paired() {
        // Both mean "you need to pair", which is one screen, not two.
        assert_eq!(
            GonomadError::from(ClientError::NotPaired),
            GonomadError::NotPaired
        );
        assert_eq!(
            GonomadError::from(ClientError::Unpaired),
            GonomadError::NotPaired
        );
    }

    #[test]
    fn every_phase_has_a_ui_state() {
        for phase in [
            ConnPhase::Disconnected,
            ConnPhase::Connecting,
            ConnPhase::Connected,
            ConnPhase::Unpaired,
            ConnPhase::Revoked,
        ] {
            let state: ConnState = phase.into();
            assert!(!format!("{state:?}").is_empty());
        }
        assert_eq!(ConnState::from(ConnPhase::Revoked), ConnState::Revoked);
    }

    #[test]
    fn a_screen_frame_becomes_newline_separated_text() {
        let frame = ScreenFrame {
            pty_id: 3,
            rows: vec!["one".into(), "two".into()],
            cursor_row: 1,
            cursor_col: 3,
            cols: 80,
            exited: false,
        };
        let converted: TerminalFrame = frame.into();
        assert_eq!(converted.screen, "one\ntwo");
        assert_eq!(converted.pty_id, 3);
        assert_eq!(converted.cursor_col, 3);
    }

    #[test]
    fn a_directory_entry_keeps_every_field_the_ui_shows() {
        let entry = proto_methods::DirEntry {
            name: ".env".into(),
            kind: proto_methods::EntryKind::Symlink,
            size_bytes: Some(12),
            modified_ms: Some(7),
            is_hidden: true,
        };
        let converted: DirEntry = entry.into();
        assert_eq!(converted.kind, EntryKind::Symlink);
        assert_eq!(converted.size_bytes, Some(12));
        assert_eq!(converted.modified_ms, Some(7));
        assert!(converted.is_hidden);
        assert!(
            !converted.is_git_ignored,
            "fs.list carries no ignore flag in this slice"
        );
    }

    #[test]
    fn a_file_read_carries_the_hash_as_hex_for_a_later_write() {
        let result = proto_methods::FsReadResult {
            path: "a.rs".into(),
            text: "fn main() {}".into(),
            content_hash: Digest::of(b"fn main() {}"),
            truncated: true,
        };
        let converted: FileContent = result.into();
        assert_eq!(converted.content_hash, Digest::of(b"fn main() {}").to_hex());
        assert_eq!(converted.content_hash.len(), 64);
        assert!(converted.truncated);
    }

    #[test]
    fn the_transport_tier_reaches_the_ui_as_a_label() {
        let status = ConnectionStatus {
            phase: ConnPhase::Connected,
            daemon_name: Some("DESKTOP-ABC".into()),
            rtt_ms: Some(4),
            transport: Some(gonomad_transport::Tier::Lan),
        };
        let converted: Status = status.into();
        assert_eq!(converted.transport.as_deref(), Some("LAN"));
        assert_eq!(converted.state, ConnState::Connected);
        assert_eq!(converted.rtt_ms, Some(4));
    }
}
