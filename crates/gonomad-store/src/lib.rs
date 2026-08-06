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

// Lints are configured in this crate's `[lints]` table in Cargo.toml.
// Do not duplicate them here: source-level attributes silently override it.

/// Placeholder while the crate is built out under milestone M1.
///
/// Replaced by the real schema, migration runner, and audit chain.
#[must_use]
pub const fn placeholder() -> bool {
    true
}
