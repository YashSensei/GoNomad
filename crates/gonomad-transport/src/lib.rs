//! GoNomad transport.
//!
//! Implements Tier 0 of the transport ladder (`ARCHITECTURE.md` §4.2): LAN
//! direct. Everything sits behind the `Transport` trait shape from §4.5, so
//! iroh — which provides Tiers 1 and 2, hole-punched direct and relayed QUIC —
//! can be substituted without the layers above noticing.

// Lints are configured in this crate's `[lints]` table in Cargo.toml.
// Do not duplicate them here: source-level attributes silently override it.

/// Placeholder while the crate is built out.
#[must_use]
pub const fn placeholder() -> bool {
    true
}
