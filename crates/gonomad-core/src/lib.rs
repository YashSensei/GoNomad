//! # GoNomad session core
//!
//! The crate compiled into **both** the daemon and the Android application, via
//! UniFFI (`ARCHITECTURE.md` §6.2). That sharing is the point: the protocol,
//! the cryptography, and the session state machines exist exactly once, so
//! client and server cannot drift — the most common and most painful failure
//! mode in client/server projects.
//!
//! It also bounds the cost of the Android-only decision. Because all logic lives
//! here rather than in Kotlin, a future iOS or desktop client reimplements
//! *views only*. The rule for reviewers follows directly: **if logic can live in
//! Rust, it must.** A conditional in Kotlin about protocol state belongs here.
//!
//! ## What lives here
//!
//! | Module | Contents |
//! |---|---|
//! | [`identity`] | The Ed25519 device keypair that *is* the credential |
//! | [`sas`] | The six-digit Short Authentication String shown during pairing |
//!
//! Landing in later M1 work: the Noise IK session, request correlation, the
//! reconnect policy, the client-side cache, and the offline write queue.
//!
//! ## Design rules
//!
//! 1. **No I/O.** No filesystem, no sockets, no clock. Callers inject those, so
//!    that every state machine in here is deterministically testable.
//! 2. **No `unsafe`.** Enforced by the `[lints]` table.
//! 3. **Key material is wiped on drop** and never reachable through `Debug`,
//!    `Clone`, or `Serialize`. Exporting a secret must be a conspicuous call.
//! 4. **Everything hashed is domain-separated.** A transcript hash must not be
//!    usable as a signature input, and a signature for one purpose must not
//!    verify for another.

// Lints are configured in this crate's `[lints]` table in Cargo.toml.
// Do not duplicate them here: source-level attributes silently override it.

pub mod identity;
pub mod sas;

pub use identity::{DeviceIdentity, IdentityError, SEED_LEN, SIGNATURE_LEN};
pub use sas::{Sas, SAS_DIGITS};
