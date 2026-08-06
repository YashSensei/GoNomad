//! Daemon state directory: identity, database, and configuration.
//!
//! Everything lives under `~/.gonomad/` so that uninstalling is deleting one
//! directory (`ARCHITECTURE.md` §24.8), and so a user can see exactly what the
//! daemon keeps.
//!
//! # Known gap: the identity key is stored in a file
//!
//! `ARCHITECTURE.md` §3.3 requires the daemon's identity key to live in the OS
//! keyring — Windows Credential Manager via DPAPI, macOS Keychain, Secret
//! Service — precisely because a plain file is readable by every process running
//! as that user.
//!
//! This slice writes it to `~/.gonomad/identity.key` instead, and warns loudly at
//! startup. The reason is honesty about scope rather than a judgement that it is
//! safe: the keyring integration is a small, well-understood change, and shipping
//! it half-done would be worse than shipping it late. **Do not treat the current
//! state as production-ready storage.** Tracked for M1 completion.
//!
//! Note also that the threat this protects against is a *different* OS user or a
//! stolen disk. A process running as the same user can read the keyring too
//! (§3.1, T10), so the keyring is an improvement rather than a boundary.

use std::path::{Path, PathBuf};

use gonomad_core::DeviceIdentity;
use zeroize::Zeroizing;

/// Errors from loading or creating daemon state.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StateError {
    /// The state directory could not be determined or created.
    #[error("could not prepare the state directory {path}: {detail}")]
    Directory {
        /// The path that failed.
        path: String,
        /// Why.
        detail: String,
    },

    /// The identity file exists but could not be read or parsed.
    #[error("identity at {path} is unreadable or corrupt: {detail}")]
    Identity {
        /// The path that failed.
        path: String,
        /// Why.
        detail: String,
    },

    /// The daemon has not been initialised yet.
    #[error("this machine is not set up yet — run `gonomad init` first")]
    NotInitialised,
}

/// Locations the daemon uses.
#[derive(Debug, Clone)]
pub struct Paths {
    /// The state root, `~/.gonomad`.
    pub root: PathBuf,
    /// The Ed25519/X25519 master seed. See the module docs for the caveat.
    pub identity: PathBuf,
    /// The SQLite database.
    ///
    /// Declared now and unused until the daemon serves connections: the device
    /// registry and audit log live here, and having the path resolved in one
    /// place means `gonomad uninstall` and the doctor already know about it.
    pub database: PathBuf,
    /// The human-editable configuration file (`ARCHITECTURE.md` §5.4).
    pub config: PathBuf,
}

impl Paths {
    /// Resolves the default locations under the user's home directory.
    ///
    /// # Errors
    ///
    /// [`StateError::Directory`] if no home directory can be determined.
    pub fn discover() -> Result<Self, StateError> {
        let home = dirs::home_dir().ok_or_else(|| StateError::Directory {
            path: "<home>".into(),
            detail: "no home directory could be determined".into(),
        })?;
        Ok(Self::under(home.join(".gonomad")))
    }

    /// Uses an explicit root, which is what the tests do.
    #[must_use]
    pub fn under(root: PathBuf) -> Self {
        Self {
            identity: root.join("identity.key"),
            database: root.join("gonomad.db"),
            config: root.join("config.toml"),
            root,
        }
    }

    /// Creates the state directory if it does not exist.
    ///
    /// # Errors
    ///
    /// [`StateError::Directory`] if the directory cannot be created.
    pub fn ensure(&self) -> Result<(), StateError> {
        std::fs::create_dir_all(&self.root).map_err(|e| StateError::Directory {
            path: self.root.display().to_string(),
            detail: e.to_string(),
        })?;
        restrict_permissions(&self.root);
        Ok(())
    }

    /// Whether `gonomad init` has been run.
    #[must_use]
    pub fn is_initialised(&self) -> bool {
        self.identity.is_file()
    }
}

/// Generates a new identity and writes it, failing if one already exists.
///
/// Refusing to overwrite is deliberate: silently replacing an identity would
/// orphan every paired device with no explanation, and the recovery path is a
/// re-pair on each of them.
///
/// # Errors
///
/// [`StateError::Identity`] if an identity is already present or the write fails.
pub fn create_identity(paths: &Paths) -> Result<DeviceIdentity, StateError> {
    paths.ensure()?;

    if paths.identity.exists() {
        return Err(StateError::Identity {
            path: paths.identity.display().to_string(),
            detail: "an identity already exists; delete it only if you intend to \
                     invalidate every paired device"
                .into(),
        });
    }

    let identity = DeviceIdentity::generate();
    let seed = identity.expose_seed();
    write_identity(&paths.identity, &seed)?;
    Ok(identity)
}

/// Loads the daemon's identity.
///
/// # Errors
///
/// [`StateError::NotInitialised`] if no identity exists, or
/// [`StateError::Identity`] if it is unreadable or the wrong length.
pub fn load_identity(paths: &Paths) -> Result<DeviceIdentity, StateError> {
    if !paths.identity.is_file() {
        return Err(StateError::NotInitialised);
    }

    let text = std::fs::read_to_string(&paths.identity).map_err(|e| StateError::Identity {
        path: paths.identity.display().to_string(),
        detail: e.to_string(),
    })?;

    let raw = Zeroizing::new(hex::decode(text.trim()).map_err(|_| StateError::Identity {
        path: paths.identity.display().to_string(),
        detail: "not valid hex".into(),
    })?);

    let seed: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| StateError::Identity {
            path: paths.identity.display().to_string(),
            detail: format!("expected 32 bytes, found {}", raw.len()),
        })?;

    Ok(DeviceIdentity::from_seed(seed))
}

fn write_identity(path: &Path, seed: &[u8; 32]) -> Result<(), StateError> {
    let encoded = Zeroizing::new(hex::encode(seed));
    std::fs::write(path, encoded.as_bytes()).map_err(|e| StateError::Identity {
        path: path.display().to_string(),
        detail: e.to_string(),
    })?;
    restrict_permissions(path);
    Ok(())
}

/// Narrows a path's permissions to the current user as far as the platform
/// allows without extra dependencies.
///
/// On Unix this is a real `0600`/`0700`. On Windows it is currently a no-op:
/// tightening an ACL needs either the `windows` crate or shelling out to
/// `icacls`, and neither is worth adding while the key is going to move into the
/// Credential Manager anyway. Stated rather than silently skipped.
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

/// The warning printed at startup while the key is file-backed.
pub const KEY_STORAGE_WARNING: &str = "\
warning: this build stores the daemon identity in a plain file, not the OS
         keyring. Any process running as your user can read it. Keyring
         storage is required before this is production-ready (ARCHITECTURE.md 3.3).";

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn paths() -> (TempDir, Paths) {
        let dir = TempDir::new().unwrap();
        let paths = Paths::under(dir.path().join(".gonomad"));
        (dir, paths)
    }

    #[test]
    fn a_fresh_directory_is_not_initialised() {
        let (_dir, paths) = paths();
        assert!(!paths.is_initialised());
        assert!(matches!(
            load_identity(&paths),
            Err(StateError::NotInitialised)
        ));
    }

    #[test]
    fn init_creates_an_identity_that_reloads_identically() {
        // The property the whole product depends on: restarting the daemon must
        // not change its identity, or every paired phone would be orphaned.
        let (_dir, paths) = paths();
        let created = create_identity(&paths).expect("create");
        assert!(paths.is_initialised());

        let loaded = load_identity(&paths).expect("load");
        assert_eq!(loaded.public_key(), created.public_key());
        assert_eq!(loaded.noise_public_key(), created.noise_public_key());
        assert_eq!(loaded.device_id(), created.device_id());
    }

    #[test]
    fn init_refuses_to_overwrite_an_existing_identity() {
        // Overwriting would silently invalidate every paired device.
        let (_dir, paths) = paths();
        create_identity(&paths).expect("first");
        assert!(matches!(
            create_identity(&paths),
            Err(StateError::Identity { .. })
        ));
    }

    #[test]
    fn a_corrupt_identity_is_reported_rather_than_silently_replaced() {
        let (_dir, paths) = paths();
        paths.ensure().unwrap();
        std::fs::write(&paths.identity, b"not hex at all").unwrap();
        match load_identity(&paths) {
            Err(StateError::Identity { detail, .. }) => assert!(detail.contains("hex")),
            other => panic!("expected an Identity error, got {other:?}"),
        }
    }

    #[test]
    fn a_wrong_length_identity_reports_the_actual_length() {
        let (_dir, paths) = paths();
        paths.ensure().unwrap();
        std::fs::write(&paths.identity, hex::encode([0u8; 16])).unwrap();
        match load_identity(&paths) {
            Err(StateError::Identity { detail, .. }) => assert!(detail.contains("16")),
            other => panic!("expected an Identity error, got {other:?}"),
        }
    }

    #[test]
    fn whitespace_around_the_key_is_tolerated() {
        // A user who opens the file in an editor may add a trailing newline.
        let (_dir, paths) = paths();
        let created = create_identity(&paths).expect("create");
        let seed = created.expose_seed();
        std::fs::write(&paths.identity, format!("  {}\n", hex::encode(*seed))).unwrap();
        assert_eq!(
            load_identity(&paths).unwrap().public_key(),
            created.public_key()
        );
    }

    #[test]
    fn every_path_lives_under_the_single_state_root() {
        // Uninstalling must be deleting one directory (§24.8).
        let (_dir, paths) = paths();
        for p in [&paths.identity, &paths.database, &paths.config] {
            assert!(
                p.starts_with(&paths.root),
                "{} escapes the state root",
                p.display()
            );
        }
    }

    #[test]
    fn ensure_is_idempotent() {
        let (_dir, paths) = paths();
        paths.ensure().expect("first");
        paths.ensure().expect("second");
        assert!(paths.root.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn the_identity_file_is_not_world_readable_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, paths) = paths();
        create_identity(&paths).expect("create");
        let mode = std::fs::metadata(&paths.identity)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "identity is readable by others: {mode:o}");
    }
}
