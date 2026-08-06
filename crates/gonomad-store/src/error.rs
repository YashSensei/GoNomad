//! The crate's error type.
//!
//! Deliberately opaque about the storage engine. `ARCHITECTURE.md` §16.1 picks
//! SQLite via `rusqlite`, but that is an implementation choice, and leaking
//! `rusqlite::Error` through public signatures would make every driver upgrade
//! a breaking change for every caller and would tie the daemon's error
//! rendering to a third-party enum it does not control.

use core::fmt;

use gonomad_proto::DeviceId;

/// Result alias used by every fallible operation in this crate.
pub type Result<T, E = StoreError> = core::result::Result<T, E>;

/// An error raised by the underlying database engine.
///
/// Opaque by construction: the concrete driver error is boxed behind
/// `dyn Error`, so it is available through [`std::error::Error::source`] for
/// diagnostics while remaining unnameable in this crate's public API.
#[derive(Debug)]
pub struct DatabaseError(Box<dyn std::error::Error + Send + Sync + 'static>);

impl DatabaseError {
    /// Wraps a driver error.
    pub(crate) fn new(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self(Box::new(source))
    }
}

impl fmt::Display for DatabaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl std::error::Error for DatabaseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

/// Everything that can go wrong in the store.
///
/// `#[non_exhaustive]` because the daemon renders these to a user and new
/// failure modes must not silently become an unhandled `_` arm downstream.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// The database engine rejected an operation.
    #[error("database error: {0}")]
    Database(#[from] DatabaseError),

    /// The database file could not be opened, created, or backed up.
    #[error("cannot use the database at {path}: {source}")]
    Io {
        /// The path that failed.
        path: String,
        /// The underlying filesystem error.
        #[source]
        source: std::io::Error,
    },

    /// A migration failed. The transaction was rolled back, so the database is
    /// still at `rolled_back_to` and is safe to retry against.
    #[error(
        "migration {version} ({name}) failed and was rolled back; \
         database remains at schema version {rolled_back_to}: {source}"
    )]
    Migration {
        /// The migration that failed.
        version: u32,
        /// Its human-readable name.
        name: String,
        /// The schema version the database is left at.
        rolled_back_to: u32,
        /// The underlying database error.
        #[source]
        source: DatabaseError,
    },

    /// The database was written by a newer build.
    ///
    /// Migrations are forward-only (§16.1), so there is no safe way to run
    /// against a schema this build does not know. Refusing is the only correct
    /// answer; silently proceeding would corrupt data written by the newer
    /// build.
    #[error("database schema is version {found}, but this build supports at most {supported}")]
    SchemaTooNew {
        /// The version found in the database.
        found: u32,
        /// The newest version this build knows how to produce.
        supported: u32,
    },

    /// The migration table itself is inconsistent (duplicate or unordered
    /// versions), which is a programming error in this crate.
    #[error("migration set is invalid: {detail}")]
    InvalidMigrationSet {
        /// What is wrong with it.
        detail: String,
    },

    /// A row that was expected to exist does not.
    #[error("{entity} not found: {key}")]
    NotFound {
        /// The logical entity, e.g. `"device"`.
        entity: &'static str,
        /// The key that was looked up.
        key: String,
    },

    /// A device with this public key is already paired.
    ///
    /// Surfaced rather than silently updated: re-pairing an existing key must
    /// be an explicit act, because it would otherwise be a way to quietly reset
    /// a device's name and grants.
    #[error("a device with this public key is already paired as {device_id}")]
    AlreadyPaired {
        /// The existing device's identifier.
        device_id: DeviceId,
    },

    /// A stored row could not be decoded into its Rust type.
    ///
    /// Distinguished from [`StoreError::Database`] because it means the data is
    /// wrong, not that the engine failed — for the audit log in particular,
    /// this is a tamper signal rather than an operational fault.
    #[error("corrupt row in `{table}`: {detail}")]
    CorruptRow {
        /// The table the row came from.
        table: &'static str,
        /// What could not be decoded.
        detail: String,
    },

    /// The audit chain is broken, so appending to it would produce a log that
    /// silently rests on unverifiable history.
    #[error("audit chain is broken at seq {seq}; refusing to append")]
    AuditChainBroken {
        /// Where verification failed.
        seq: u64,
    },

    /// A truncation checkpoint could not be signed (§3.9).
    ///
    /// Rotation is refused rather than performed unsigned: an unsigned
    /// truncation point is indistinguishable from an attacker's truncation.
    #[error("cannot sign the audit truncation checkpoint: {0}")]
    CheckpointSigning(String),
}

impl StoreError {
    /// Builds a [`StoreError::NotFound`].
    pub(crate) fn not_found(entity: &'static str, key: impl fmt::Display) -> Self {
        Self::NotFound {
            entity,
            key: key.to_string(),
        }
    }

    /// Builds a [`StoreError::CorruptRow`].
    pub(crate) fn corrupt(table: &'static str, detail: impl fmt::Display) -> Self {
        Self::CorruptRow {
            table,
            detail: detail.to_string(),
        }
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Database(DatabaseError::new(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The daemon moves errors across task boundaries, so this must hold.
    #[test]
    fn store_error_is_send_and_sync_and_static() {
        const fn assert_bounds<T: Send + Sync + 'static>() {}
        assert_bounds::<StoreError>();
    }

    #[test]
    fn database_errors_keep_a_readable_message() {
        let err = StoreError::from(rusqlite::Error::QueryReturnedNoRows);
        let rendered = err.to_string();
        assert!(rendered.starts_with("database error: "), "{rendered}");
        assert!(rendered.len() > "database error: ".len());
    }

    #[test]
    fn not_found_names_both_the_entity_and_the_key() {
        let err = StoreError::not_found("device", "abc123");
        assert_eq!(err.to_string(), "device not found: abc123");
    }

    #[test]
    fn corrupt_row_names_the_table() {
        let err = StoreError::corrupt("audit", "hash is 31 bytes");
        assert_eq!(err.to_string(), "corrupt row in `audit`: hash is 31 bytes");
    }
}
