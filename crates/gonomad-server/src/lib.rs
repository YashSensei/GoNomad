//! The GoNomad daemon, as a library.
//!
//! The `gonomad` binary is a thin CLI over these modules. They are public so
//! integration tests can stand up a real listener and drive it over a real
//! socket — which is the only way to verify the pairing property in
//! `ARCHITECTURE.md` §19 R24, since that property is about what happens *after*
//! a handshake completes and cannot be observed from a unit test.

// Lints are configured in this crate's `[lints]` table in Cargo.toml.
// Do not duplicate them here: source-level attributes silently override it.

pub mod fs_service;
pub mod router;
pub mod serve;
pub mod state;

pub use router::{Daemon, Effect, PairingState, Router};
pub use serve::{bind_pairing, run_pairing, serve, serve_pairing, PairedDevice};
