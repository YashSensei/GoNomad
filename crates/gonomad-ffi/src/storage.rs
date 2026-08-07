//! Local persistence: the device seed and the one paired daemon.
//!
//! # Known gap: this is not the production storage layer
//!
//! `ARCHITECTURE.md` §3.3 requires the phone's identity key to live in the
//! Android Keystore — a software key wrapped by Keystore encryption and gated on
//! the lockscreen, with a separate hardware-backed P-256 presence key for
//! destructive operations. This module instead writes the seed as hex into a
//! file under the `state_dir` Kotlin passes in, exactly as
//! `crates/gonomad-server/src/state.rs` does for the daemon.
//!
//! That is honesty about scope, not a judgement that it is safe. Keystore
//! integration is Android's half of the work (it needs JNI and a `KeyStore`
//! provider, neither of which belongs in a portable Rust crate) and this module
//! is the seam it will replace. **Do not treat the current state as
//! production-ready storage.** What it does buy today: app-private storage on
//! Android is unreadable by other apps and is excluded from backup and device
//! transfer, so the exposure is a rooted or physically compromised device rather
//! than any installed app.
//!
//! # Why the paired daemon is stored at all
//!
//! Everything needed to reconnect — the daemon's Noise static key and its
//! address hints — comes from the pairing QR, which is single-use and gone
//! afterwards. Losing this record means re-pairing, so it is written once,
//! atomically as far as a rename allows, and only after the daemon has answered
//! an authenticated `sys.register` (`ARCHITECTURE.md` §19 R24).

use std::path::{Path, PathBuf};

use gonomad_core::{DeviceIdentity, SEED_LEN};
use gonomad_proto::PublicKey;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// File holding the hex-encoded device seed.
pub const IDENTITY_FILE: &str = "identity.key";

/// File holding the CBOR-encoded [`PairedDaemon`] record.
pub const DAEMON_FILE: &str = "daemon.cbor";

/// Errors from reading or writing local state.
///
/// Every variant names the path, because the only useful action on a corrupt
/// state directory is to look at it — and on Android that path is not something
/// the user can guess.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StorageError {
    /// The state directory could not be created or is not usable.
    #[error("could not prepare the state directory {path}: {detail}")]
    Directory {
        /// The path that failed.
        path: String,
        /// Why.
        detail: String,
    },

    /// The identity file exists but could not be read or parsed.
    #[error("the device identity at {path} is unreadable or corrupt: {detail}")]
    Identity {
        /// The path that failed.
        path: String,
        /// Why.
        detail: String,
    },

    /// The paired-daemon record exists but could not be read or parsed.
    #[error("the paired-machine record at {path} is unreadable or corrupt: {detail}")]
    Daemon {
        /// The path that failed.
        path: String,
        /// Why.
        detail: String,
    },
}

/// The daemon this phone is paired with.
///
/// Serialized as CBOR rather than JSON to match the wire encoding, so there is
/// one serialization format in the product rather than two.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairedDaemon {
    /// The daemon's X25519 Noise static key — what the reconnect handshake
    /// authenticates against.
    ///
    /// **Not** its Ed25519 signing key: the two are different values derived
    /// from one seed, and handing the wrong one to a handshake fails in a way
    /// that is tedious to diagnose from the wire (`gonomad_core::identity`).
    pub noise_key: PublicKey,

    /// The daemon's iroh `NodeId`.
    ///
    /// A *transport address*, not a credential — iroh dials by public key rather
    /// than by IP, which is what lets this phone reach the machine from any
    /// network without a port forward (`ARCHITECTURE.md` §4.3). Stored because
    /// without it a reconnect has nothing to dial: address hints go stale the
    /// moment either side changes network, whereas the `NodeId` never does.
    ///
    /// Deliberately separate from [`PairedDaemon::noise_key`]. The Noise key is
    /// the credential the session authenticates against; conflating the two would
    /// tie the security model to one transport, which §3.4 declines to do.
    #[serde(default)]
    pub node_id: Option<PublicKey>,

    /// How the *daemon* is identified in the UI, as hex.
    ///
    /// The hex of [`PairedDaemon::noise_key`], not a `DeviceId`. A `DeviceId` is
    /// `BLAKE3(Ed25519 public key)` and the pairing QR carries only the daemon's
    /// X25519 key, so this device genuinely cannot compute the daemon's id. The
    /// Noise key identifies the machine just as stably, which is what the pairing
    /// card needs, and inventing an id would produce one that disagrees with the
    /// laptop's own.
    pub device_id: String,

    /// The id the daemon assigned this *phone* at registration, as hex.
    ///
    /// Kept so a support conversation can match this install to a row in the
    /// laptop's device list and audit log. `#[serde(default)]` for the same
    /// reason as [`PairedDaemon::last_seen_ms`].
    #[serde(default)]
    pub registered_device_id: String,

    /// The daemon's human-readable host name, e.g. `"DESKTOP-ABC"`.
    pub name: String,

    /// Where the daemon was reachable, in the order to try them.
    ///
    /// Copied from the pairing ticket. Hints go stale when the laptop changes
    /// network, which is a recovery path (mDNS, §4.6) rather than a failure of
    /// this record.
    pub addr_hints: Vec<String>,

    /// When pairing completed, in unix milliseconds.
    pub paired_at_ms: i64,

    /// When a connection last succeeded, in unix milliseconds.
    ///
    /// `#[serde(default)]` so a record written before this field existed still
    /// loads: a missing timestamp must not cost the user a re-pair.
    #[serde(default)]
    pub last_seen_ms: Option<i64>,
}

/// The state directory and the files inside it.
#[derive(Debug, Clone)]
pub struct Storage {
    root: PathBuf,
}

impl Storage {
    /// Points at a state directory. Nothing is touched until a call needs it.
    pub fn new(state_dir: impl Into<PathBuf>) -> Self {
        Self {
            root: state_dir.into(),
        }
    }

    /// The state root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Where the device seed lives.
    #[must_use]
    pub fn identity_path(&self) -> PathBuf {
        self.root.join(IDENTITY_FILE)
    }

    /// Where the paired-daemon record lives.
    #[must_use]
    pub fn daemon_path(&self) -> PathBuf {
        self.root.join(DAEMON_FILE)
    }

    /// Loads the device identity, generating and persisting one on first run.
    ///
    /// A missing identity is the first-run case, not an error. A *present but
    /// unreadable* identity is an error rather than a silent regeneration:
    /// replacing the key would orphan the pairing with no explanation, and the
    /// user's only recovery would be to re-pair without knowing why.
    ///
    /// # Errors
    ///
    /// [`StorageError::Directory`] when the state directory cannot be created,
    /// or [`StorageError::Identity`] when an existing file is corrupt or a new
    /// one cannot be written.
    pub fn load_or_create_identity(&self) -> Result<DeviceIdentity, StorageError> {
        self.ensure_dir()?;
        let path = self.identity_path();

        if path.is_file() {
            return self.load_identity();
        }

        let identity = DeviceIdentity::generate();
        // The hex string is itself secret material, so it lives in a wiping
        // buffer for the few microseconds before it reaches the filesystem.
        let encoded = Zeroizing::new(hex::encode(*identity.expose_seed()));
        std::fs::write(&path, encoded.as_bytes()).map_err(|e| StorageError::Identity {
            path: path.display().to_string(),
            detail: e.to_string(),
        })?;
        restrict_permissions(&path);
        Ok(identity)
    }

    /// Reads an existing identity.
    fn load_identity(&self) -> Result<DeviceIdentity, StorageError> {
        let path = self.identity_path();
        let fail = |detail: String| StorageError::Identity {
            path: path.display().to_string(),
            detail,
        };

        let text = std::fs::read_to_string(&path).map_err(|e| fail(e.to_string()))?;
        let raw =
            Zeroizing::new(hex::decode(text.trim()).map_err(|_| fail("not valid hex".to_owned()))?);
        let seed: [u8; SEED_LEN] = raw
            .as_slice()
            .try_into()
            .map_err(|_| fail(format!("expected {SEED_LEN} bytes, found {}", raw.len())))?;
        Ok(DeviceIdentity::from_seed(seed))
    }

    /// Loads the paired daemon, or `Ok(None)` when this device is unpaired.
    ///
    /// # Errors
    ///
    /// [`StorageError::Daemon`] when the record exists but cannot be decoded.
    /// Reported rather than treated as "unpaired", because silently forgetting a
    /// pairing is indistinguishable to the user from the app losing their setup.
    pub fn load_daemon(&self) -> Result<Option<PairedDaemon>, StorageError> {
        let path = self.daemon_path();
        if !path.is_file() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path).map_err(|e| StorageError::Daemon {
            path: path.display().to_string(),
            detail: e.to_string(),
        })?;
        ciborium::from_reader(bytes.as_slice())
            .map(Some)
            .map_err(|_| StorageError::Daemon {
                path: path.display().to_string(),
                detail: "the record is not valid CBOR for this app version".to_owned(),
            })
    }

    /// Writes the paired daemon, replacing any previous record.
    ///
    /// Written to a sibling temporary file and renamed, so a crash mid-write
    /// leaves the old record intact instead of a half-written one that would
    /// read as corrupt and force a re-pair.
    ///
    /// # Errors
    ///
    /// [`StorageError::Directory`] when the state directory cannot be created,
    /// or [`StorageError::Daemon`] when the write or rename fails.
    pub fn save_daemon(&self, daemon: &PairedDaemon) -> Result<(), StorageError> {
        self.ensure_dir()?;
        let path = self.daemon_path();
        let fail = |detail: String| StorageError::Daemon {
            path: path.display().to_string(),
            detail,
        };

        let mut bytes = Vec::new();
        ciborium::into_writer(daemon, &mut bytes)
            .map_err(|_| fail("the record could not be encoded".to_owned()))?;

        let temp = path.with_extension("cbor.tmp");
        std::fs::write(&temp, &bytes).map_err(|e| fail(e.to_string()))?;
        restrict_permissions(&temp);
        std::fs::rename(&temp, &path).map_err(|e| fail(e.to_string()))?;
        restrict_permissions(&path);
        Ok(())
    }

    /// Removes the paired-daemon record, leaving the identity in place.
    ///
    /// # Errors
    ///
    /// [`StorageError::Daemon`] when the file exists and cannot be removed. A
    /// file that was already absent is success: the caller asked for a state,
    /// not for an event.
    pub fn forget_daemon(&self) -> Result<(), StorageError> {
        remove_if_present(&self.daemon_path()).map_err(|detail| StorageError::Daemon {
            path: self.daemon_path().display().to_string(),
            detail,
        })
    }

    /// Removes the paired daemon *and* the device seed.
    ///
    /// What `unpair` means: the next launch generates a fresh identity, so even
    /// a daemon that still holds the old registration cannot be reached with it.
    /// Both files are attempted even if the first fails, because leaving the key
    /// behind after telling the user their keys were wiped is the worst possible
    /// outcome.
    ///
    /// # Errors
    ///
    /// [`StorageError::Identity`] or [`StorageError::Daemon`] naming the first
    /// file that could not be removed.
    pub fn wipe(&self) -> Result<(), StorageError> {
        let daemon = self.forget_daemon();
        let identity =
            remove_if_present(&self.identity_path()).map_err(|detail| StorageError::Identity {
                path: self.identity_path().display().to_string(),
                detail,
            });
        daemon.and(identity)
    }

    /// Creates the state directory if it is missing.
    fn ensure_dir(&self) -> Result<(), StorageError> {
        std::fs::create_dir_all(&self.root).map_err(|e| StorageError::Directory {
            path: self.root.display().to_string(),
            detail: e.to_string(),
        })?;
        restrict_permissions(&self.root);
        Ok(())
    }
}

/// Deletes a path, treating "already gone" as success.
fn remove_if_present(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

/// Narrows a path to the current user as far as the platform allows.
///
/// A real `0600`/`0700` on Unix, which covers Android. A no-op on Windows,
/// where the desktop tests run: tightening an ACL needs the `windows` crate or
/// `icacls`, and the file this protects only exists on a phone. Stated rather
/// than silently skipped, matching `gonomad-server`'s note.
fn restrict_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = if meta.is_dir() { 0o700 } else { 0o600 };
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// The current wall-clock time in unix milliseconds.
///
/// Wall clock, not monotonic, because these timestamps are *displayed* — "paired
/// 3 days ago" — and are never used to enforce a window. Expiry decisions use a
/// monotonic clock (`gonomad_core::PairingWindow`) precisely because a wall clock
/// can be moved.
#[must_use]
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn storage() -> (TempDir, Storage) {
        let dir = TempDir::new().expect("temp dir");
        let storage = Storage::new(dir.path().join("gonomad"));
        (dir, storage)
    }

    fn daemon() -> PairedDaemon {
        PairedDaemon {
            noise_key: PublicKey::from_bytes([0xAB; 32]),
            // A distinct value from the Noise key, so a test that accidentally
            // swapped the two would fail rather than pass by coincidence.
            node_id: Some(PublicKey::from_bytes([0xCD; 32])),
            device_id: "a".repeat(64),
            registered_device_id: "b".repeat(64),
            name: "DESKTOP-ABC".into(),
            addr_hints: vec!["192.168.1.4:41234".into()],
            paired_at_ms: 1_700_000_000_000,
            last_seen_ms: None,
        }
    }

    #[test]
    fn a_fresh_directory_creates_an_identity_and_reloads_it_unchanged() {
        // The property the pairing depends on: relaunching the app must not
        // change this device's key, or the daemon would stop recognising it.
        let (_dir, storage) = storage();
        let created = storage.load_or_create_identity().expect("create");
        let reloaded = storage.load_or_create_identity().expect("reload");
        assert_eq!(created.public_key(), reloaded.public_key());
        assert_eq!(created.noise_public_key(), reloaded.noise_public_key());
    }

    #[test]
    fn a_corrupt_identity_is_reported_rather_than_silently_replaced() {
        // Regenerating would orphan the pairing with no explanation.
        let (_dir, storage) = storage();
        storage.load_or_create_identity().expect("create");
        std::fs::write(storage.identity_path(), b"not hex").expect("overwrite");
        assert!(matches!(
            storage.load_or_create_identity(),
            Err(StorageError::Identity { .. })
        ));
    }

    #[test]
    fn an_unpaired_device_has_no_daemon_record() {
        let (_dir, storage) = storage();
        assert_eq!(storage.load_daemon().expect("load"), None);
    }

    #[test]
    fn the_daemon_record_round_trips() {
        let (_dir, storage) = storage();
        let expected = daemon();
        storage.save_daemon(&expected).expect("save");
        assert_eq!(storage.load_daemon().expect("load"), Some(expected));
    }

    #[test]
    fn saving_twice_replaces_rather_than_appends() {
        let (_dir, storage) = storage();
        storage.save_daemon(&daemon()).expect("first");
        let mut second = daemon();
        second.name = "LAPTOP-2".into();
        storage.save_daemon(&second).expect("second");
        assert_eq!(storage.load_daemon().expect("load"), Some(second));
    }

    #[test]
    fn a_corrupt_daemon_record_is_reported_not_read_as_unpaired() {
        let (_dir, storage) = storage();
        storage.save_daemon(&daemon()).expect("save");
        std::fs::write(storage.daemon_path(), b"\xff\xff\xff").expect("corrupt");
        assert!(matches!(
            storage.load_daemon(),
            Err(StorageError::Daemon { .. })
        ));
    }

    #[test]
    fn forgetting_the_daemon_keeps_the_identity() {
        let (_dir, storage) = storage();
        let identity = storage.load_or_create_identity().expect("create");
        storage.save_daemon(&daemon()).expect("save");
        storage.forget_daemon().expect("forget");
        assert_eq!(storage.load_daemon().expect("load"), None);
        assert_eq!(
            storage
                .load_or_create_identity()
                .expect("reload")
                .public_key(),
            identity.public_key()
        );
    }

    #[test]
    fn wiping_removes_the_key_so_the_old_registration_is_unusable() {
        let (_dir, storage) = storage();
        let before = storage.load_or_create_identity().expect("create");
        storage.save_daemon(&daemon()).expect("save");
        storage.wipe().expect("wipe");
        assert_eq!(storage.load_daemon().expect("load"), None);
        assert_ne!(
            storage
                .load_or_create_identity()
                .expect("regenerate")
                .public_key(),
            before.public_key(),
            "unpair must leave the old key unusable"
        );
    }

    #[test]
    fn removing_something_already_absent_is_success() {
        // `unpair` may be called twice; the second call is not an error.
        let (_dir, storage) = storage();
        storage.forget_daemon().expect("first");
        storage.forget_daemon().expect("second");
        storage.wipe().expect("wipe with nothing to wipe");
    }

    /// A record as it was written before `last_seen_ms` existed.
    #[derive(Serialize)]
    struct Old {
        noise_key: PublicKey,
        device_id: String,
        name: String,
        addr_hints: Vec<String>,
        paired_at_ms: i64,
    }

    #[test]
    fn a_record_without_last_seen_still_loads() {
        // Forward compatibility: a field added later must not cost a re-pair.
        let (_dir, storage) = storage();
        let old = Old {
            noise_key: PublicKey::from_bytes([1; 32]),
            device_id: "b".repeat(64),
            name: "OLD".into(),
            addr_hints: vec![],
            paired_at_ms: 1,
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&old, &mut bytes).expect("encode");
        std::fs::create_dir_all(storage.root()).expect("mkdir");
        std::fs::write(storage.daemon_path(), bytes).expect("write");

        let loaded = storage.load_daemon().expect("load").expect("present");
        assert_eq!(loaded.last_seen_ms, None);
        assert!(loaded.registered_device_id.is_empty());
        assert_eq!(loaded.name, "OLD");
    }

    #[test]
    fn the_seed_is_never_written_in_the_clear_as_bytes() {
        // Hex, matching the daemon's format, so the two can be inspected the
        // same way. This is a format assertion, not a security claim: see the
        // module docs for why the file is not the endpoint.
        let (_dir, storage) = storage();
        let identity = storage.load_or_create_identity().expect("create");
        let text = std::fs::read_to_string(storage.identity_path()).expect("read");
        assert_eq!(text.trim().len(), SEED_LEN * 2);
        assert_eq!(text.trim(), hex::encode(*identity.expose_seed()));
    }

    #[test]
    fn timestamps_are_plausible_unix_milliseconds() {
        // Guards against a seconds/millis mix-up, which would render every
        // "paired at" date in 1970.
        assert!(now_ms() > 1_700_000_000_000, "got {}", now_ms());
    }
}
