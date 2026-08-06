//! Typed parameters and results for every RPC method.
//!
//! [`Request::params`](crate::Request::params) and
//! [`ResponseBody::Ok::result`](crate::ResponseBody) carry opaque CBOR so that
//! the envelope does not change every time a method is added
//! (`ARCHITECTURE.md` §11). This module is what goes *inside* those bytes.
//!
//! Both ends depend on it, which is the point: the daemon and the mobile client
//! decode the same structs from the same crate, so a field cannot be added on one
//! side and forgotten on the other. Method names live in [`method`] as constants
//! rather than string literals scattered across call sites, so a typo is a
//! compile error rather than an `Unsupported` at runtime.

use serde::{Deserialize, Serialize};

use crate::{CapabilitySet, Digest};

/// Method name constants.
///
/// Namespaced and dotted, matching §11.1. Referenced by both the client's
/// request builders and the daemon's router, so the two cannot disagree.
pub mod method {
    /// Negotiate capabilities and learn the workspace roots.
    pub const SYS_INFO: &str = "sys.info";
    /// Complete pairing with an authenticated application exchange.
    pub const SYS_REGISTER: &str = "sys.register";
    /// List one directory level.
    pub const FS_LIST: &str = "fs.list";
    /// Read a file as text.
    pub const FS_READ: &str = "fs.read";
    /// Spawn a terminal.
    pub const PTY_SPAWN: &str = "pty.spawn";
    /// Send input to a terminal.
    pub const PTY_INPUT: &str = "pty.input";
    /// Resize a terminal.
    pub const PTY_RESIZE: &str = "pty.resize";
    /// Fetch a terminal's current screen.
    pub const PTY_SCREEN: &str = "pty.screen";
    /// Terminate a terminal.
    pub const PTY_KILL: &str = "pty.kill";
    /// List live terminals.
    pub const PTY_LIST: &str = "pty.list";

    /// Every method this build implements.
    ///
    /// The router rejects anything absent from this list with
    /// [`crate::ErrorKind::Unsupported`], which the client renders as the
    /// version-skew screen rather than a generic failure (§24.7).
    pub const ALL: &[&str] = &[
        SYS_INFO,
        SYS_REGISTER,
        FS_LIST,
        FS_READ,
        PTY_SPAWN,
        PTY_INPUT,
        PTY_RESIZE,
        PTY_SCREEN,
        PTY_KILL,
        PTY_LIST,
    ];
}

/// `sys.info` — no parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SysInfoParams {}

/// `sys.info` result: what this daemon is and what the caller may do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysInfoResult {
    /// Human-readable host name, for the phone's "paired machine" card.
    pub host_name: String,
    /// The daemon's build version.
    pub daemon_version: String,
    /// The operating system, e.g. `"windows"`.
    pub os: String,
    /// Capabilities actually granted to the calling device.
    pub capabilities: CapabilitySet,
    /// Workspace roots this device may reach, as absolute paths.
    pub workspace_roots: Vec<String>,
    /// Shell identifiers available for `pty.spawn`.
    pub shells: Vec<String>,
}

/// `sys.register` — the authenticated exchange that completes pairing.
///
/// **This request is why pairing is safe** (`ARCHITECTURE.md` §19 R24). With
/// `IKpsk2` the daemon completes its side of the handshake even when the phone's
/// pairing code was wrong, so handshake completion proves nothing. Only a
/// successfully *decrypted* request — which requires the session keys to actually
/// match, which requires the correct pre-shared key — proves the peer saw the QR.
/// The daemon must register a device on receiving this and never earlier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysRegisterParams {
    /// The name this device should appear under in the daemon's device list.
    pub device_name: String,
    /// Model string, for display only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_model: Option<String>,
    /// The six-digit SAS the phone displayed, as digits.
    ///
    /// Sent so the daemon can confirm both sides derived the same value before
    /// committing. A mismatch means something sat in the middle, and the daemon
    /// refuses rather than relying solely on the human comparison.
    pub sas: String,
}

/// `sys.register` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysRegisterResult {
    /// The registered device's id, as hex.
    pub device_id: String,
    /// Capabilities granted at pairing.
    pub capabilities: CapabilitySet,
}

/// `fs.list` parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsListParams {
    /// Absolute path of the directory to list.
    pub path: String,
}

/// What a directory entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EntryKind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
    /// A symlink or reparse point, deliberately not followed.
    Symlink,
}

/// One entry in a directory listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirEntry {
    /// File name only. Never a full path, which would disclose host layout.
    pub name: String,
    /// What it is.
    pub kind: EntryKind,
    /// Size in bytes, for files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    /// Last-modified time as unix milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified_ms: Option<i64>,
    /// Whether the name marks it hidden by convention.
    pub is_hidden: bool,
}

/// `fs.list` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsListResult {
    /// The directory that was listed.
    pub path: String,
    /// Its entries, directories first then case-insensitive by name.
    pub entries: Vec<DirEntry>,
}

/// `fs.read` parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsReadParams {
    /// Absolute path of the file to read.
    pub path: String,
}

/// `fs.read` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsReadResult {
    /// The path that was read.
    pub path: String,
    /// Contents as UTF-8 text.
    pub text: String,
    /// BLAKE3 of the bytes sent — the compare-and-swap baseline (§12.2).
    pub content_hash: Digest,
    /// Whether the file was longer than the read cap.
    ///
    /// Surfaced so the client can say "showing the first N bytes" rather than
    /// presenting a truncated file as complete.
    pub truncated: bool,
}

/// `pty.spawn` parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtySpawnParams {
    /// Working directory. Must be inside an allowed workspace root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Shell identifier from [`SysInfoResult::shells`], or the default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
    /// Terminal width in columns.
    pub cols: u16,
    /// Terminal height in rows.
    pub rows: u16,
}

/// A terminal's rendered screen.
///
/// Text rather than the cell-run diffs of §13.1, which arrive with M2. The
/// emulator already lives in the daemon, so that is a change to this struct and
/// the renderer, not to the architecture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScreenFrame {
    /// Which terminal.
    pub pty_id: u64,
    /// Visible rows, trailing blanks trimmed.
    pub rows: Vec<String>,
    /// Cursor row, zero-based.
    pub cursor_row: u16,
    /// Cursor column, zero-based.
    pub cursor_col: u16,
    /// Width in columns.
    pub cols: u16,
    /// Whether the child process has exited.
    pub exited: bool,
}

/// `pty.spawn` result.
///
/// Carries the first frame as well as the id, so the client can distinguish
/// "spawned, no output yet" from "spawned, first frame lost". With an id alone
/// those are indistinguishable and the screen stays blank forever.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtySpawnResult {
    /// The new terminal's id.
    pub pty_id: u64,
    /// Its screen immediately after spawning.
    pub initial: ScreenFrame,
    /// The shell that was actually started.
    pub shell: String,
}

/// `pty.input` parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtyInputParams {
    /// Which terminal.
    pub pty_id: u64,
    /// Bytes to write, as UTF-8 text. Control characters are permitted and are
    /// how the accessory bar sends `Ctrl-C`.
    pub data: String,
}

/// `pty.resize` parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtyResizeParams {
    /// Which terminal.
    pub pty_id: u64,
    /// New width.
    pub cols: u16,
    /// New height.
    pub rows: u16,
}

/// `pty.screen` and `pty.kill` parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtyIdParams {
    /// Which terminal.
    pub pty_id: u64,
}

/// `pty.list` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtyListResult {
    /// Live terminal ids, ascending.
    pub pty_ids: Vec<u64>,
}

/// An empty result, for methods whose success carries no data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Empty {}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip<T>(value: &T) -> T
    where
        T: Serialize + serde::de::DeserializeOwned,
    {
        let mut buf = Vec::new();
        ciborium::into_writer(value, &mut buf).expect("serialize");
        ciborium::from_reader(buf.as_slice()).expect("deserialize")
    }

    #[test]
    fn method_names_are_unique() {
        // A duplicate would make the router's dispatch ambiguous.
        let mut names = method::ALL.to_vec();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before, "duplicate method name in ALL");
    }

    #[test]
    fn method_names_are_namespaced_and_lowercase() {
        for name in method::ALL {
            assert!(name.contains('.'), "{name} is not namespaced");
            assert_eq!(*name, name.to_lowercase(), "{name} is not lowercase");
            assert!(!name.starts_with('.'), "{name} has an empty namespace");
            assert!(!name.ends_with('.'), "{name} has an empty member");
        }
    }

    #[test]
    fn sys_info_round_trips() {
        let value = SysInfoResult {
            host_name: "DESKTOP-ABC".into(),
            daemon_version: "0.0.1".into(),
            os: "windows".into(),
            capabilities: CapabilitySet::default_grant(),
            workspace_roots: vec!["C:/code/gonomad".into()],
            shells: vec!["pwsh".into(), "wsl".into()],
        };
        assert_eq!(round_trip(&value), value);
    }

    #[test]
    fn register_round_trips_and_carries_the_sas() {
        let value = SysRegisterParams {
            device_name: "Pixel 9".into(),
            device_model: Some("Google Pixel 9".into()),
            sas: "418273".into(),
        };
        let back = round_trip(&value);
        assert_eq!(back, value);
        assert_eq!(back.sas, "418273");
    }

    #[test]
    fn fs_list_round_trips_with_every_entry_kind() {
        let value = FsListResult {
            path: "C:/code".into(),
            entries: vec![
                DirEntry {
                    name: "src".into(),
                    kind: EntryKind::Directory,
                    size_bytes: None,
                    modified_ms: Some(1_700_000_000_000),
                    is_hidden: false,
                },
                DirEntry {
                    name: "main.rs".into(),
                    kind: EntryKind::File,
                    size_bytes: Some(1234),
                    modified_ms: None,
                    is_hidden: false,
                },
                DirEntry {
                    name: ".config".into(),
                    kind: EntryKind::Symlink,
                    size_bytes: None,
                    modified_ms: None,
                    is_hidden: true,
                },
            ],
        };
        assert_eq!(round_trip(&value), value);
    }

    #[test]
    fn fs_read_round_trips_including_the_cas_baseline() {
        let value = FsReadResult {
            path: "a.rs".into(),
            text: "fn main() {}".into(),
            content_hash: Digest::of(b"fn main() {}"),
            truncated: false,
        };
        let back = round_trip(&value);
        assert_eq!(back, value);
        // The hash must survive exactly, or a later write would be rejected as a
        // false conflict.
        assert_eq!(back.content_hash, Digest::of(b"fn main() {}"));
    }

    #[test]
    fn pty_spawn_result_carries_a_first_frame() {
        // Without it the client cannot tell "no output yet" from "frame lost".
        let value = PtySpawnResult {
            pty_id: 1,
            shell: "pwsh".into(),
            initial: ScreenFrame {
                pty_id: 1,
                rows: vec!["PS C:\\code>".into()],
                cursor_row: 0,
                cursor_col: 11,
                cols: 80,
                exited: false,
            },
        };
        let back = round_trip(&value);
        assert_eq!(back, value);
        assert_eq!(back.initial.pty_id, back.pty_id);
    }

    #[test]
    fn control_characters_survive_pty_input() {
        // The accessory bar sends Ctrl-C as 0x03; mangling it would break the
        // single most important key in a terminal.
        let value = PtyInputParams {
            pty_id: 1,
            data: "\u{3}".into(),
        };
        assert_eq!(round_trip(&value).data, "\u{3}");

        let esc = PtyInputParams {
            pty_id: 1,
            data: "\u{1b}[A".into(),
        };
        assert_eq!(round_trip(&esc).data, "\u{1b}[A");
    }

    #[test]
    fn absent_optional_fields_are_omitted_from_the_wire() {
        let params = PtySpawnParams {
            cwd: None,
            shell: None,
            cols: 80,
            rows: 24,
        };
        let json = serde_json::to_string(&params).unwrap();
        assert!(!json.contains("cwd"), "got {json}");
        assert!(!json.contains("shell"), "got {json}");
    }

    #[test]
    fn empty_params_encode_compactly() {
        // An empty map, not null: `serde` would otherwise refuse to decode a
        // unit struct from a map and vice versa across versions.
        let mut buf = Vec::new();
        ciborium::into_writer(&SysInfoParams {}, &mut buf).unwrap();
        assert!(buf.len() <= 2, "empty params took {} bytes", buf.len());
        let _: SysInfoParams = ciborium::from_reader(buf.as_slice()).unwrap();
    }

    #[test]
    fn a_screen_frame_with_many_rows_round_trips() {
        let value = ScreenFrame {
            pty_id: 7,
            rows: (0..50).map(|i| format!("line {i}")).collect(),
            cursor_row: 49,
            cursor_col: 0,
            cols: 120,
            exited: true,
        };
        assert_eq!(round_trip(&value), value);
    }

    proptest::proptest! {
        /// Decoding arbitrary bytes as any params type must never panic: these
        /// arrive from a peer that may be hostile.
        #[test]
        fn decoding_arbitrary_bytes_never_panics(bytes: Vec<u8>) {
            let _ = ciborium::from_reader::<FsListParams, _>(bytes.as_slice());
            let _ = ciborium::from_reader::<FsReadParams, _>(bytes.as_slice());
            let _ = ciborium::from_reader::<PtySpawnParams, _>(bytes.as_slice());
            let _ = ciborium::from_reader::<PtyInputParams, _>(bytes.as_slice());
            let _ = ciborium::from_reader::<SysRegisterParams, _>(bytes.as_slice());
        }

        #[test]
        fn any_path_round_trips(path: String) {
            let value = FsListParams { path: path.clone() };
            proptest::prop_assert_eq!(round_trip(&value).path, path);
        }

        #[test]
        fn any_terminal_input_round_trips(data: String) {
            let value = PtyInputParams { pty_id: 3, data: data.clone() };
            proptest::prop_assert_eq!(round_trip(&value).data, data);
        }
    }
}
