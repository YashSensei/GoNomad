//! GoNomad persistence.
//!
//! SQLite via `rusqlite` with the `bundled` feature, so there is no system
//! dependency and the one-binary deployment promise holds
//! (`ARCHITECTURE.md` §16.1).
//!
//! What lives here: paired devices, capability grants, workspace roots, the
//! hash-chained audit log, session registries, and settings.
//!
//! What deliberately does **not**: file content, terminal scrollback, and agent
//! transcripts. Those are capped on-disk files, because storing megabytes of
//! terminal output as rows bloats the database and slows every query while
//! buying no query we actually want to run.
//!
//! # Getting started
//!
//! ```
//! use gonomad_proto::{CapabilitySet, PublicKey};
//! use gonomad_store::Store;
//!
//! # fn main() -> Result<(), gonomad_store::StoreError> {
//! # let dir = tempfile::tempdir().unwrap();
//! // Opening applies every pending migration, in one transaction.
//! let store = Store::open(dir.path().join("gonomad.db"))?;
//!
//! let device = store.devices().pair(
//!     &PublicKey::from_bytes([7; 32]),
//!     "Pixel 8",
//!     Some("Google Pixel 8"),
//!     CapabilitySet::default_grant(),
//! )?;
//!
//! // Every mutating operation, denial, and policy change is logged (§3.9).
//! use gonomad_proto::Digest;
//! use gonomad_store::audit::{AuditRecord, AuditResult};
//! store.audit().append(
//!     &AuditRecord::new("device.pair", Digest::of(b"Pixel 8"), AuditResult::Ok)
//!         .by(device.id),
//! )?;
//!
//! assert!(store.audit().verify()?.is_intact());
//! # Ok(())
//! # }
//! ```
//!
//! # Module map
//!
//! | Module | Contents |
//! |---|---|
//! | [`audit`] | The hash-chained, append-only audit log and its verifier |
//! | [`devices`] | Pairing, revocation, capability grants, workspace roots |
//! | [`sessions`] | Terminals, agents, editor tabs, snippets, notifications |
//! | [`settings`] | The daemon's key/value table |
//! | [`migrations`] | Numbered forward-only migrations and the schema itself |
//!
//! # Design rules for this crate
//!
//! 1. **Hand-written SQL, no ORM.** §16.1 rejects `sqlx`/Diesel for a schema
//!    this small: they add compile-time cost and indirection where a
//!    repository module is simply clearer.
//! 2. **`rusqlite` never appears in a public signature.** See [`StoreError`].
//! 3. **The audit log is append-only.** There is no update or delete API for
//!    it; the only removal path is a signed retention rotation.
//! 4. **Fail closed.** A grant that cannot be read is the empty grant, not a
//!    full one; a rotation that cannot be signed does not happen.

// Lints are configured in this crate's `[lints]` table in Cargo.toml.
// Do not duplicate them here: source-level attributes silently override it.

mod canonical;
mod clock;
mod db;
mod error;
mod row;

pub mod audit;
pub mod devices;
pub mod migrations;
pub mod sessions;
pub mod settings;

pub use audit::{
    AuditEntry, AuditLog, AuditRecord, AuditResult, ChainBreak, ChainStatus, Checkpoint,
    CheckpointSigner, CheckpointVerifier, GENESIS_PREV_HASH,
};
pub use db::{migrate, Store};
pub use devices::{Device, Devices};
pub use error::{DatabaseError, Result, StoreError};
pub use migrations::{Migration, MigrationReport, LATEST_VERSION};
pub use sessions::{AgentSession, AgentState, EditorTab, Notification, PtySession, Sessions};
pub use settings::Settings;

#[cfg(test)]
mod tests {
    use gonomad_proto::{Capability, CapabilitySet, Digest, PublicKey};

    use super::*;

    /// One pass through the surface a daemon start-up actually touches,
    /// against a real file, to catch anything that only breaks when the
    /// modules are used together.
    #[test]
    fn a_realistic_session_works_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gonomad.db");

        let device_id = {
            let store = Store::open(&path).unwrap();
            assert_eq!(store.schema_version().unwrap(), LATEST_VERSION);

            let pubkey = PublicKey::from_bytes([42; 32]);
            let device = store
                .devices()
                .pair(
                    &pubkey,
                    "Pixel 8",
                    Some("Pixel 8"),
                    CapabilitySet::default_grant(),
                )
                .unwrap();
            store
                .devices()
                .add_workspace_root(&device.id, "C:/code/gonomad")
                .unwrap();

            store
                .audit()
                .append(
                    &AuditRecord::new("device.pair", Digest::of(b"Pixel 8"), AuditResult::Ok)
                        .by(device.id),
                )
                .unwrap();
            store
                .audit()
                .append(
                    &AuditRecord::new("fs.read", Digest::of(b"C:/code/.env"), AuditResult::Denied)
                        .by(device.id),
                )
                .unwrap();

            store
                .sessions()
                .create_pty("pty-1", "main", "pwsh", "C:/code/gonomad", None)
                .unwrap();
            store
                .settings()
                .set("workspace", "C:/code/gonomad")
                .unwrap();
            device.id
        };

        // Restart the daemon.
        let store = Store::open(&path).unwrap();
        assert!(migrate(&store).unwrap().is_noop());
        assert!(store.audit().verify().unwrap().is_intact());
        assert_eq!(store.audit().count().unwrap(), 2);
        assert_eq!(store.devices().list_active().unwrap().len(), 1);
        assert!(store
            .devices()
            .grants(&device_id)
            .unwrap()
            .contains(Capability::FsRead));
        assert_eq!(store.sessions().list_live_ptys().unwrap().len(), 1);
        assert_eq!(
            store.settings().get("workspace").unwrap().as_deref(),
            Some("C:/code/gonomad")
        );

        // Revoking cuts the device off but leaves its history intact.
        store.devices().revoke(&device_id).unwrap();
        assert!(store.devices().list_active().unwrap().is_empty());
        assert!(store.devices().grants(&device_id).unwrap().is_empty());
        assert_eq!(store.audit().for_device(&device_id, 10).unwrap().len(), 2);
        assert!(store.audit().verify().unwrap().is_intact());
    }
}
