//! Numbered, forward-only migrations applied in a single transaction at
//! startup (`ARCHITECTURE.md` §16.1).
//!
//! Four properties, each of which is tested:
//!
//! - **Forward-only.** There are no `down` scripts. Down-migrations are written
//!   once, run never, and are wrong when they finally matter; a restore from
//!   the pre-migration backup is the honest recovery path.
//! - **All-or-nothing.** Every pending migration runs inside one transaction.
//!   SQLite makes DDL transactional, so a failure anywhere leaves the database
//!   byte-identical to how it started, still readable by the previous build.
//! - **Idempotent.** Applying an up-to-date database is a no-op; applying a
//!   half-migrated one resumes at the first unapplied version.
//! - **Refuses the future.** A database written by a newer build is rejected
//!   rather than opened, because a forward-only scheme has no way to reason
//!   about a schema it has never seen.

use rusqlite::{Connection, Transaction, TransactionBehavior};

use crate::clock;
use crate::error::{DatabaseError, Result, StoreError};

/// One numbered schema change.
#[derive(Debug, Clone, Copy)]
pub struct Migration {
    /// Monotonic version number. Never reused, never reordered.
    pub version: u32,
    /// A short identifier recorded in `schema_version`, for humans reading
    /// `gonomad doctor` output.
    pub name: &'static str,
    /// The SQL to execute. May contain multiple statements.
    pub sql: &'static str,
}

/// The complete migration set, in ascending version order.
pub const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "initial_schema",
    sql: V1_INITIAL_SCHEMA,
}];

/// The schema version this build produces.
pub const LATEST_VERSION: u32 = {
    let mut i = 0;
    let mut max = 0;
    while i < MIGRATIONS.len() {
        if MIGRATIONS[i].version > max {
            max = MIGRATIONS[i].version;
        }
        i += 1;
    }
    max
};

/// What [`apply`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationReport {
    /// The schema version before this run.
    pub from_version: u32,
    /// The schema version after this run.
    pub to_version: u32,
    /// The versions applied, ascending. Empty when nothing was pending.
    pub applied: Vec<u32>,
}

impl MigrationReport {
    /// `true` when the database was already up to date.
    pub fn is_noop(&self) -> bool {
        self.applied.is_empty()
    }
}

/// Creates the bookkeeping table if it is absent.
///
/// Deliberately outside the migration transaction and outside the migration
/// list: the table that records which migrations ran cannot itself be created
/// by a migration.
fn ensure_version_table(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (
             version    INTEGER PRIMARY KEY,
             name       TEXT    NOT NULL,
             applied_at INTEGER NOT NULL
         ) STRICT;",
    )?;
    Ok(())
}

/// Returns the highest applied schema version, or `0` for a fresh database.
///
/// # Errors
///
/// Returns [`StoreError::Database`] when the bookkeeping table cannot be read
/// or created.
pub fn current_version(conn: &Connection) -> Result<u32> {
    ensure_version_table(conn)?;
    // One row per applied migration rather than a single mutable row: the
    // history is worth keeping, and MAX() over it is the current version.
    let version: i64 = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |row| row.get(0),
    )?;
    u32::try_from(version)
        .map_err(|_| StoreError::corrupt("schema_version", format!("version {version} is invalid")))
}

/// Applies every pending migration in one transaction.
///
/// # Errors
///
/// Returns [`StoreError::SchemaTooNew`] when the database was written by a
/// newer build, [`StoreError::Migration`] when a migration script fails (the
/// database is left untouched), or [`StoreError::Database`] for engine
/// failures.
pub fn apply(conn: &Connection) -> Result<MigrationReport> {
    apply_set(conn, MIGRATIONS)
}

/// The body of [`apply`], parameterised by the migration set so that the
/// failure path can be tested with a deliberately broken script.
fn apply_set(conn: &Connection, migrations: &[Migration]) -> Result<MigrationReport> {
    validate(migrations)?;

    let from_version = current_version(conn)?;
    let newest = migrations.iter().map(|m| m.version).max().unwrap_or(0);
    if from_version > newest {
        return Err(StoreError::SchemaTooNew {
            found: from_version,
            supported: newest,
        });
    }

    let pending: Vec<&Migration> = migrations
        .iter()
        .filter(|m| m.version > from_version)
        .collect();
    if pending.is_empty() {
        return Ok(MigrationReport {
            from_version,
            to_version: from_version,
            applied: Vec::new(),
        });
    }

    // `new_unchecked` because the repositories borrow the connection
    // immutably; IMMEDIATE so the write lock is taken up front rather than
    // discovered part-way through a DDL batch.
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
    let applied_at = clock::now_unix_ms();
    let mut applied = Vec::with_capacity(pending.len());

    for migration in &pending {
        if let Err(source) = run_one(&tx, migration, applied_at) {
            // Dropping the transaction rolls it back, so the database is still
            // at `from_version` and the previous build can still open it.
            drop(tx);
            return Err(StoreError::Migration {
                version: migration.version,
                name: migration.name.to_owned(),
                rolled_back_to: from_version,
                source,
            });
        }
        applied.push(migration.version);
    }

    tx.commit()?;

    let to_version = applied.iter().copied().max().unwrap_or(from_version);
    tracing::info!(
        from_version,
        to_version,
        applied = applied.len(),
        "applied schema migrations"
    );
    Ok(MigrationReport {
        from_version,
        to_version,
        applied,
    })
}

fn run_one(
    tx: &Transaction<'_>,
    migration: &Migration,
    applied_at: i64,
) -> core::result::Result<(), DatabaseError> {
    tx.execute_batch(migration.sql).map_err(DatabaseError::new)?;
    tx.execute(
        "INSERT INTO schema_version (version, name, applied_at) VALUES (?1, ?2, ?3)",
        rusqlite::params![migration.version, migration.name, applied_at],
    )
    .map_err(DatabaseError::new)?;
    Ok(())
}

/// Rejects a migration set that is unordered, duplicated, or starts below 1.
///
/// This is a bug in this crate rather than a user-facing condition, but a
/// duplicate version silently skipping a schema change is bad enough to be
/// worth a runtime check as well as review.
fn validate(migrations: &[Migration]) -> Result<()> {
    let mut previous = 0u32;
    for migration in migrations {
        if migration.version == 0 {
            return Err(StoreError::InvalidMigrationSet {
                detail: "version 0 is reserved for an unmigrated database".to_owned(),
            });
        }
        if migration.version <= previous {
            return Err(StoreError::InvalidMigrationSet {
                detail: format!(
                    "version {} follows {previous}; migrations must ascend and be unique",
                    migration.version
                ),
            });
        }
        previous = migration.version;
    }
    Ok(())
}

/// The initial schema (`ARCHITECTURE.md` §16.1).
///
/// Notes that are not obvious from the DDL:
///
/// - Every table is `STRICT`. SQLite's default type affinity would happily
///   store the text `"one"` in the audit log's `seq` column; for a table whose
///   entire purpose is to be trustworthy after an intrusion, "the engine
///   accepts anything" is not an acceptable default.
/// - Identifiers are stored as lowercase hex `TEXT` so `sqlite3` and `gonomad
///   audit` output is readable without a decoder, matching the wire encoding
///   chosen in `gonomad-proto`. Hashes and digests are `BLOB`, because they are
///   never read by a human and the audit table is the one that grows.
/// - Timestamps are `INTEGER` Unix milliseconds UTC. Text timestamps have
///   multiple valid spellings of the same instant, which would make the audit
///   log's canonical hash input ambiguous.
/// - `audit.device_id` has **no** foreign key: a failed pairing attempt or a
///   request from an unknown key must still be logged, and a constraint that
///   makes some events unloggable is a constraint an attacker can exploit.
const V1_INITIAL_SCHEMA: &str = r"
--------------------------------------------------------------------------
-- Identity and authorization (§3.2, §3.6)
--------------------------------------------------------------------------

CREATE TABLE devices (
    id         TEXT    PRIMARY KEY,          -- hex DeviceId = BLAKE3(pubkey)
    pubkey     TEXT    NOT NULL UNIQUE,      -- hex Ed25519 public key: the credential
    name       TEXT    NOT NULL,
    model      TEXT,
    paired_at  INTEGER NOT NULL,
    last_seen  INTEGER,
    revoked_at INTEGER                       -- NULL = active; rows are never deleted
) STRICT;

-- Revocation is a tombstone, never a DELETE: the audit trail references these
-- rows, and a revoked device whose row vanished would render its own history
-- unattributable (§3.9).
CREATE INDEX devices_active ON devices(revoked_at);

CREATE TABLE grants (
    device_id  TEXT    NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    capability TEXT    NOT NULL,             -- Capability::as_str(), e.g. 'fs:read'
    granted_at INTEGER NOT NULL,
    granted_by TEXT,                         -- hex DeviceId, or NULL for the operator
    PRIMARY KEY (device_id, capability)
) STRICT;

CREATE TABLE workspace_roots (
    device_id TEXT    NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    path      TEXT    NOT NULL,
    added_at  INTEGER NOT NULL,
    PRIMARY KEY (device_id, path)
) STRICT;

--------------------------------------------------------------------------
-- Hash-chained audit log (§3.9)
--------------------------------------------------------------------------

CREATE TABLE audit (
    seq          INTEGER PRIMARY KEY,        -- gap-free, assigned by this crate
    ts_utc       INTEGER NOT NULL,           -- Unix ms UTC (movable wall clock)
    monotonic_ns INTEGER NOT NULL,           -- never decreases, even across restarts
    device_id    TEXT,                       -- NULL for daemon-originated events
    operation    TEXT    NOT NULL,
    args_digest  BLOB    NOT NULL,           -- BLAKE3 of the arguments, never the arguments
    result       TEXT    NOT NULL,           -- 'ok' | 'denied' | 'failed'
    prev_hash    BLOB    NOT NULL,           -- hash of entry seq-1, or the genesis constant
    hash         BLOB    NOT NULL            -- BLAKE3(canonical_cbor(entry))
) STRICT;

CREATE INDEX audit_ts ON audit(ts_utc);
CREATE INDEX audit_device ON audit(device_id, seq);

-- Retention rotation records where it cut, and signs it, so the chain still
-- verifies after old entries are gone (§3.9).
CREATE TABLE audit_checkpoints (
    truncated_through_seq INTEGER PRIMARY KEY,  -- last seq removed
    chain_hash            BLOB    NOT NULL,     -- hash of that entry: the splice point
    entries_removed       INTEGER NOT NULL,
    ts_utc                INTEGER NOT NULL,
    signer                TEXT    NOT NULL,     -- hex public key of the daemon identity
    signature             BLOB    NOT NULL      -- 64-byte detached signature
) STRICT;

--------------------------------------------------------------------------
-- Session registries (§7.3, §8.4)
--------------------------------------------------------------------------

CREATE TABLE pty_sessions (
    id              TEXT    PRIMARY KEY,
    name            TEXT    NOT NULL,        -- named so 'the test terminal' is findable
    shell           TEXT    NOT NULL,
    cwd             TEXT    NOT NULL,
    created_at      INTEGER NOT NULL,
    exited_at       INTEGER,
    scrollback_path TEXT                     -- capped on-disk ring, not a BLOB here
) STRICT;

CREATE TABLE agent_sessions (
    id                      TEXT    PRIMARY KEY,
    adapter                 TEXT    NOT NULL,   -- display string only, never branched on
    workspace               TEXT    NOT NULL,
    state                   TEXT    NOT NULL,
    created_at              INTEGER NOT NULL,
    last_activity           INTEGER NOT NULL,
    transcript_path         TEXT,               -- append-only file with rotation
    agent_native_session_id TEXT                -- for `resume_args`
) STRICT;

CREATE TABLE editor_tabs (
    device_id   TEXT    NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    path        TEXT    NOT NULL,
    cursor_line INTEGER NOT NULL DEFAULT 0,
    cursor_col  INTEGER NOT NULL DEFAULT 0,
    scroll_top  INTEGER NOT NULL DEFAULT 0,
    dirty       INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (device_id, path)
) STRICT;

CREATE TABLE snippets (
    id        INTEGER PRIMARY KEY,
    workspace TEXT    NOT NULL,
    label     TEXT    NOT NULL,
    command   TEXT    NOT NULL,
    use_count INTEGER NOT NULL DEFAULT 0,
    UNIQUE (workspace, label)
) STRICT;

CREATE TABLE notifications (
    id        INTEGER PRIMARY KEY,
    ts        INTEGER NOT NULL,
    kind      TEXT    NOT NULL,
    payload   TEXT    NOT NULL,
    delivered INTEGER NOT NULL DEFAULT 0,
    read      INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE INDEX notifications_undelivered ON notifications(delivered, ts);

--------------------------------------------------------------------------
-- Key/value settings
--------------------------------------------------------------------------

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;
";

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        conn
    }

    fn table_names(conn: &Connection) -> Vec<String> {
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .unwrap();
        let names = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        names
    }

    #[test]
    fn the_shipped_migration_set_is_well_formed() {
        validate(MIGRATIONS).unwrap();
        assert!(LATEST_VERSION >= 1);
        assert_eq!(
            LATEST_VERSION,
            MIGRATIONS.iter().map(|m| m.version).max().unwrap()
        );
    }

    #[test]
    fn fresh_database_migrates_to_latest() {
        let conn = fresh();
        let report = apply(&conn).unwrap();
        assert_eq!(report.from_version, 0);
        assert_eq!(report.to_version, LATEST_VERSION);
        assert!(!report.is_noop());
        assert_eq!(current_version(&conn).unwrap(), LATEST_VERSION);
    }

    #[test]
    fn every_table_from_architecture_16_1_exists() {
        let conn = fresh();
        apply(&conn).unwrap();
        let tables = table_names(&conn);
        for expected in [
            "devices",
            "grants",
            "workspace_roots",
            "audit",
            "pty_sessions",
            "agent_sessions",
            "editor_tabs",
            "snippets",
            "notifications",
            "settings",
            "schema_version",
        ] {
            assert!(
                tables.iter().any(|t| t == expected),
                "missing table `{expected}`; have {tables:?}"
            );
        }
    }

    #[test]
    fn re_migration_is_a_no_op() {
        let conn = fresh();
        apply(&conn).unwrap();
        let before = table_names(&conn);

        let second = apply(&conn).unwrap();
        assert!(second.is_noop());
        assert_eq!(second.from_version, LATEST_VERSION);
        assert_eq!(second.to_version, LATEST_VERSION);
        assert_eq!(table_names(&conn), before);

        // And a third time, because "idempotent" means any number of times.
        assert!(apply(&conn).unwrap().is_noop());
        assert_eq!(current_version(&conn).unwrap(), LATEST_VERSION);
    }

    #[test]
    fn a_partially_migrated_database_resumes_where_it_stopped() {
        let conn = fresh();
        let set = [
            Migration {
                version: 1,
                name: "one",
                sql: "CREATE TABLE one (x INTEGER) STRICT;",
            },
            Migration {
                version: 2,
                name: "two",
                sql: "CREATE TABLE two (x INTEGER) STRICT;",
            },
            Migration {
                version: 3,
                name: "three",
                sql: "CREATE TABLE three (x INTEGER) STRICT;",
            },
        ];

        // Stop after version 1.
        let first = apply_set(&conn, &set[..1]).unwrap();
        assert_eq!(first.applied, vec![1]);

        // Resuming applies only 2 and 3, and does not re-run 1 (which would
        // fail with "table one already exists").
        let rest = apply_set(&conn, &set).unwrap();
        assert_eq!(rest.from_version, 1);
        assert_eq!(rest.applied, vec![2, 3]);
        assert_eq!(current_version(&conn).unwrap(), 3);
    }

    #[test]
    fn a_failing_migration_rolls_back_everything_including_earlier_ones() {
        let conn = fresh();
        let set = [
            Migration {
                version: 1,
                name: "good",
                sql: "CREATE TABLE good (x INTEGER) STRICT;",
            },
            Migration {
                version: 2,
                name: "broken",
                sql: "CREATE TABLE ok_so_far (x INTEGER) STRICT; THIS IS NOT SQL;",
            },
        ];

        let err = apply_set(&conn, &set).unwrap_err();
        match err {
            StoreError::Migration {
                version,
                ref name,
                rolled_back_to,
                ..
            } => {
                assert_eq!(version, 2);
                assert_eq!(name, "broken");
                assert_eq!(rolled_back_to, 0);
            }
            other => panic!("expected a Migration error, got {other:?}"),
        }

        // The whole batch is gone, not just the failing statement: version 1's
        // table and version 2's first statement both rolled back.
        assert_eq!(current_version(&conn).unwrap(), 0);
        let tables = table_names(&conn);
        assert!(!tables.iter().any(|t| t == "good"), "{tables:?}");
        assert!(!tables.iter().any(|t| t == "ok_so_far"), "{tables:?}");
    }

    #[test]
    fn a_failed_migration_can_be_retried_after_the_script_is_fixed() {
        let conn = fresh();
        let broken = [Migration {
            version: 1,
            name: "v1",
            sql: "CREATE TABLE thing (x INTEGER) STRICT; NOT SQL;",
        }];
        assert!(apply_set(&conn, &broken).is_err());

        let fixed = [Migration {
            version: 1,
            name: "v1",
            sql: "CREATE TABLE thing (x INTEGER) STRICT;",
        }];
        assert_eq!(apply_set(&conn, &fixed).unwrap().applied, vec![1]);
        assert_eq!(current_version(&conn).unwrap(), 1);
    }

    #[test]
    fn a_database_from_a_newer_build_is_refused() {
        let conn = fresh();
        apply(&conn).unwrap();
        conn.execute(
            "INSERT INTO schema_version (version, name, applied_at) VALUES (?1, 'from_the_future', 0)",
            [LATEST_VERSION + 5],
        )
        .unwrap();

        match apply(&conn).unwrap_err() {
            StoreError::SchemaTooNew { found, supported } => {
                assert_eq!(found, LATEST_VERSION + 5);
                assert_eq!(supported, LATEST_VERSION);
            }
            other => panic!("expected SchemaTooNew, got {other:?}"),
        }
    }

    #[test]
    fn unordered_or_duplicated_migration_sets_are_rejected() {
        let duplicate = [
            Migration {
                version: 1,
                name: "a",
                sql: "",
            },
            Migration {
                version: 1,
                name: "b",
                sql: "",
            },
        ];
        assert!(validate(&duplicate).is_err());

        let descending = [
            Migration {
                version: 2,
                name: "a",
                sql: "",
            },
            Migration {
                version: 1,
                name: "b",
                sql: "",
            },
        ];
        assert!(validate(&descending).is_err());

        let zero = [Migration {
            version: 0,
            name: "a",
            sql: "",
        }];
        assert!(validate(&zero).is_err());
    }

    #[test]
    fn applied_migrations_are_recorded_with_their_names() {
        let conn = fresh();
        apply(&conn).unwrap();
        let name: String = conn
            .query_row(
                "SELECT name FROM schema_version WHERE version = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(name, "initial_schema");
    }

    #[test]
    fn tables_are_strict_so_a_tampered_type_is_rejected() {
        // The reason every table is STRICT: without it, this INSERT succeeds
        // and the audit log grows a row whose `seq` is the text "one".
        let conn = fresh();
        apply(&conn).unwrap();
        let err = conn.execute(
            "INSERT INTO audit (seq, ts_utc, monotonic_ns, operation, args_digest, result, prev_hash, hash)
             VALUES ('one', 0, 0, 'x', x'00', 'ok', x'00', x'00')",
            [],
        );
        assert!(err.is_err(), "STRICT should have rejected a text seq");
    }
}
