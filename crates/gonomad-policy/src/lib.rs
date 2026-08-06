//! GoNomad authorization.
//!
//! Authentication (`ARCHITECTURE.md` §3.2) answers *who is connecting*; this
//! crate answers *what they may do*, and it is where most of the real security
//! lives.
//!
//! Structurally, this crate sits on the **only** path from the protocol router
//! to any service (`ARCHITECTURE.md` §2). A service call cannot skip it,
//! rather than merely conventionally not skipping it.
//!
//! Three concerns:
//!
//! - **Capability checks** — does this device hold the required permission?
//! - **Path guards** — does this path resolve inside a permitted workspace
//!   root, after canonicalisation and symlink resolution, and is it off the
//!   secret denylist? This is the highest-consequence code in the project and
//!   is verified with generative tests.
//! - **Rate limits** — protecting the developer's machine from a buggy or
//!   compromised phone.

// Lints are configured in this crate's `[lints]` table in Cargo.toml.
// Do not duplicate them here: source-level attributes silently override it.

/// Placeholder while the crate is built out under milestone M1.
///
/// Replaced by the capability engine, path guard, and rate limiter.
#[must_use]
pub const fn placeholder() -> bool {
    true
}
