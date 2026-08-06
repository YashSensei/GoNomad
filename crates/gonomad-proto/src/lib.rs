//! # GoNomad wire protocol
//!
//! The shared contract between the daemon (running on the developer's machine)
//! and the mobile client. This crate is deliberately **pure**: it has no
//! knowledge of the filesystem, of process spawning, or of any transport. That
//! purity is what makes it safe to compile into an Android application via
//! UniFFI alongside the daemon (see `ARCHITECTURE.md` §6.2).
//!
//! ## What lives here
//!
//! | Module | Contents |
//! |---|---|
//! | [`ids`] | Cryptographic identifiers: [`PublicKey`], [`DeviceId`], [`Digest`] |
//! | [`capability`] | The authorization vocabulary: [`Capability`], [`CapabilitySet`] |
//! | [`error`] | The closed protocol error enum: [`ProtoError`] |
//! | [`frame`] | Wire framing and the length-prefixed codec: [`Frame`], [`FrameFlags`] |
//! | [`control`] | Handshake and request/response envelope: [`ControlMessage`] |
//! | [`events`] | Server-pushed events: [`Event`], [`EventPayload`] |
//!
//! ## Design rules for this crate
//!
//! 1. **No I/O.** Nothing here may touch the filesystem, the network, or the
//!    clock. Callers pass values in.
//! 2. **No `unsafe`.** Enforced by `#![forbid(unsafe_code)]`.
//! 3. **Closed enums for anything crossing the wire.** A client must be able to
//!    render a correct, actionable message for every failure it can receive, and
//!    stringly-typed errors make that impossible (`ARCHITECTURE.md` §11.2).
//! 4. **Constant-time comparison for secrets.** Identifier equality is
//!    constant-time so that comparing a presented key against a stored one
//!    cannot leak via timing.

// Lints are configured once, in this crate's `[lints]` table in Cargo.toml.
// Declaring them here as well would silently override that table (source-level
// attributes win), which is how `clippy::doc_markdown` kept firing after being
// allowed in the manifest.

pub mod capability;
pub mod control;
pub mod error;
pub mod events;
pub mod frame;
pub mod ids;
pub mod methods;

pub use capability::{Capability, CapabilitySet};
pub use control::{
    ControlMessage, CorrelationId, Heartbeat, Hello, HelloOk, HelloReject, RejectReason, Request,
    Response, ResponseBody, SessionId,
};
pub use error::{ErrorKind, ProtoError};
pub use events::{
    AgentState, ApprovalRequest, Destructiveness, Event, EventPayload, FileChange, FileChangeKind,
    TaskOutcome,
};
pub use frame::{Frame, FrameError, FrameFlags};
pub use ids::{DeviceId, Digest, PublicKey};
pub use methods::method;

/// The wire protocol version this build speaks.
///
/// Bumped for any change to frame layout or message semantics. The handshake
/// negotiates a common version and fails loudly when none exists, because
/// silent partial breakage from version skew is among the hardest classes of
/// bug for a user to report usefully (`ARCHITECTURE.md` §24.7).
pub const PROTOCOL_VERSION: u32 = 1;

/// The oldest protocol version this build can still talk to.
///
/// A peer advertising a version below this is rejected with a clear,
/// actionable message rather than being allowed to connect and misbehave.
pub const MIN_PROTOCOL_VERSION: u32 = 1;

/// The ALPN identifier used for QUIC connections.
///
/// A connection that does not offer this exact protocol is dropped during the
/// QUIC handshake, before a single byte of application data is read. This is
/// part of why the daemon presents nothing to a scanner (`ARCHITECTURE.md`
/// §3.7).
pub const ALPN: &[u8] = b"gonomad/1";

/// Returns `true` when this build can interoperate with a peer speaking
/// `peer_version`.
#[must_use]
pub fn is_version_compatible(peer_version: u32) -> bool {
    peer_version >= MIN_PROTOCOL_VERSION && peer_version <= PROTOCOL_VERSION
}

// Compile-time invariant: the compatibility window must be non-empty. Checked
// here rather than in a test so that an inverted bump cannot even build.
const _: () = assert!(
    MIN_PROTOCOL_VERSION <= PROTOCOL_VERSION,
    "MIN_PROTOCOL_VERSION must not exceed PROTOCOL_VERSION"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_version_is_compatible_with_itself() {
        assert!(is_version_compatible(PROTOCOL_VERSION));
    }

    #[test]
    fn versions_outside_the_window_are_rejected() {
        assert!(!is_version_compatible(MIN_PROTOCOL_VERSION - 1));
        assert!(!is_version_compatible(PROTOCOL_VERSION + 1));
    }

    #[test]
    fn alpn_is_versioned() {
        // The ALPN must change when the protocol version does, so that
        // incompatible peers cannot complete a QUIC handshake at all.
        let alpn = std::str::from_utf8(ALPN).expect("ALPN is valid UTF-8");
        assert!(alpn.ends_with(&PROTOCOL_VERSION.to_string()));
    }
}
