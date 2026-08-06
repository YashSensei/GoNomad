//! # GoNomad FFI
//!
//! The client half of the protocol, plus the UniFFI surface the Android app
//! consumes. This crate is the "fat core" of `ARCHITECTURE.md` §6.2: the dial
//! sequence, the hello exchange, request correlation, timeouts, the pairing state
//! machine, and local persistence all live here, so Kotlin renders state and
//! forwards intents and contains no conditional about protocol state.
//!
//! ## Layout
//!
//! | Module | Contents |
//! |---|---|
//! | [`client`] | The real client: connection, correlation, pairing, typed method wrappers |
//! | [`storage`] | The device seed and the paired daemon on disk — **not** the Keystore |
//! | [`ffi`] | The UniFFI types and object, mirroring `docs/ffi-contract.md` |
//!
//! ## Design rules
//!
//! 1. **Kotlin holds no protocol logic.** Anything resembling a state machine
//!    belongs in [`client`].
//! 2. **The boundary is coarse.** Few methods, rich types: each FFI crossing has
//!    overhead and a chatty interface would put it on the hot path.
//! 3. **Errors are a closed enum** ([`ffi::GonomadError`]) so Compose can render
//!    a correct action for each (§11.2), and no message a user sees names a Rust
//!    type.
//! 4. **Nothing blocks the caller's thread.** Every method that can touch the
//!    network is `async`, dispatched onto the runtime [`client::GonomadClient`]
//!    owns, because Kotlin cannot drive a Rust executor.
//!
//! ## Three constraints worth knowing before changing anything here
//!
//! - **Registration is gated on a decrypted round trip, never on handshake
//!   completion** (§19 R24). With `IKpsk2` the daemon finishes its side of the
//!   handshake even when the pairing code was wrong, so only a `sys.register`
//!   that the daemon could decrypt proves the phone saw the QR.
//!   [`client::GonomadClient::confirm_pairing`] is the only writer of the paired
//!   daemon record.
//! - **A single frame is capped at 256 KiB on this transport** (§19 R25), well
//!   below the protocol's 32 MiB. A larger frame can never be reassembled, so
//!   over-sized requests are refused with [`client::ClientError::TooLarge`]
//!   rather than sent and parked on credit that cannot come back.
//! - **Terminal output is polled, not pushed.** A stopgap until `pty.output`
//!   arrives with M2; see [`client::SCREEN_POLL_INTERVAL`].
//!
//! ## Generating the Kotlin bindings
//!
//! ```text
//! cargo build -p gonomad-ffi
//! cargo run -p gonomad-ffi --bin uniffi-bindgen -- \
//!     generate --library target/debug/gonomad_ffi.dll --language kotlin --out-dir <dir>
//! ```
//!
//! The package name comes from `uniffi.toml`, so the generated class is
//! `dev.gonomad.ffi.GonomadClient` — the name the app already codes against.

// Lints are configured in this crate's `[lints]` table in Cargo.toml.
// Do not duplicate them here: source-level attributes silently override it.

pub mod client;
pub mod ffi;
pub mod storage;

// Registers this crate's UniFFI scaffolding. The namespace defaults to the crate
// name, which is what `--library` mode looks for; the Kotlin package is set in
// `uniffi.toml` instead, so the two can differ without a build script.
uniffi::setup_scaffolding!();
