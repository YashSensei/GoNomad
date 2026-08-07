//! Transport errors.
//!
//! # Why `std::io::Error` and `snow::Error` do not appear here
//!
//! Both are deliberately absent from the public API:
//!
//! - `std::io::Error` is not `Clone`, not `PartialEq`, and carries an
//!   open-ended boxed payload. Leaking it would force every caller — including
//!   the Kotlin side, across UniFFI — to deal with a type that cannot cross a
//!   language boundary and cannot be matched on exhaustively. Only the
//!   [`std::io::ErrorKind`] is retained, as a plain `Copy` enum, and only for
//!   diagnostics.
//! - Noise failures are collapsed into [`TransportError::HandshakeFailed`] and
//!   [`TransportError::Crypto`], mirroring the deliberate coarseness of
//!   `gonomad_core::SessionError`. A peer must not learn *why* its handshake
//!   failed — whether its key was unknown, its PSK wrong, or its message
//!   malformed — because that distinction is exactly what an attacker probes
//!   for (`ARCHITECTURE.md` §3.7). The daemon logs the precise cause locally.

use std::io;
use std::net::SocketAddr;

use gonomad_proto::FrameError;

/// Result alias for every fallible operation in this crate.
pub type Result<T> = core::result::Result<T, TransportError>;

/// A specific way a peer broke the multiplexer's rules.
///
/// Every variant is fatal to the connection. Once framing sync is lost there is
/// no correlation id to attach a reply to, and continuing to parse a stream we
/// have desynchronised from is how a parser bug becomes a vulnerability — the
/// same reasoning `gonomad_proto::FrameError` documents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProtocolViolation {
    /// A Noise record was shorter than the AEAD tag it must contain.
    #[error("record of {len} bytes is too short to contain an AEAD tag")]
    ShortRecord {
        /// The declared record length.
        len: usize,
    },

    /// A decrypted record was too short to hold a segment header.
    #[error("segment of {len} bytes is shorter than the {header} byte header")]
    MalformedSegment {
        /// Bytes actually present.
        len: usize,
        /// Bytes the header requires.
        header: usize,
    },

    /// The segment kind byte is not one this build understands.
    ///
    /// Rejected rather than skipped, for the same reason `FrameFlags` rejects
    /// unknown bits: proceeding while ignoring a segment's meaning is how a
    /// peer ends up believing data was delivered when it was dropped.
    #[error("unknown segment kind {kind}")]
    UnknownSegmentKind {
        /// The kind byte as received.
        kind: u8,
    },

    /// Data arrived for a channel that was never opened.
    #[error("data for channel {channel}, which was never opened")]
    UnknownChannel {
        /// The channel id the peer used.
        channel: u32,
    },

    /// The peer opened a channel id that is already live.
    #[error("channel {channel} was opened twice")]
    DuplicateChannel {
        /// The channel id the peer reused.
        channel: u32,
    },

    /// The peer opened a channel id belonging to the other side's number space.
    ///
    /// Initiator-opened channels are even and responder-opened channels are
    /// odd, borrowed from QUIC's stream-id parity, so the two sides can allocate
    /// concurrently without a negotiation round trip. A peer that ignores the
    /// parity is either buggy or trying to hijack a channel we allocated.
    #[error("channel {channel} is not in the peer's number space")]
    WrongChannelParity {
        /// The channel id the peer used.
        channel: u32,
    },

    /// The peer exceeded the configured channel limit.
    #[error("peer opened more than {max} concurrent channels")]
    TooManyChannels {
        /// The configured limit.
        max: usize,
    },

    /// The peer sent more bytes on a channel than its credit window allowed.
    ///
    /// Enforced rather than trusted: a peer that ignores flow control would
    /// otherwise force us to buffer without bound, which is a trivial
    /// memory-exhaustion attack (`ARCHITECTURE.md` §3.8).
    #[error("peer exceeded the flow-control window on channel {channel}")]
    FlowControlExceeded {
        /// The offending channel.
        channel: u32,
    },

    /// The peer tried to grant us more credit than the window permits.
    #[error("peer inflated the flow-control window on channel {channel}")]
    FlowControlInflated {
        /// The offending channel.
        channel: u32,
    },

    /// A `WINDOW` segment did not carry exactly a `u32`.
    #[error("malformed window update on channel {channel}")]
    MalformedWindowUpdate {
        /// The offending channel.
        channel: u32,
    },

    /// The peer announced a frame larger than this binding will reassemble.
    ///
    /// See [`crate::MuxConfig::max_frame_len`] for why the TCP binding needs a
    /// cap that QUIC does not.
    #[error("peer announced a {len} byte frame, above the {max} byte limit")]
    OversizedFrame {
        /// The length the peer declared.
        len: usize,
        /// The configured maximum.
        max: usize,
    },
}

/// Everything that can go wrong in the transport.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    /// A listener could not be bound.
    #[error("could not bind a listener on {addr} ({kind:?})")]
    Bind {
        /// The address that was attempted.
        addr: SocketAddr,
        /// The underlying OS error class, for diagnostics only.
        kind: io::ErrorKind,
    },

    /// A TCP connection to a specific address could not be established.
    #[error("could not connect to {addr} ({kind:?})")]
    Connect {
        /// The address that was attempted.
        addr: SocketAddr,
        /// The underlying OS error class, for diagnostics only.
        kind: io::ErrorKind,
    },

    /// No address hint could be reached.
    ///
    /// Tier 0 only knows how to dial a `SocketAddr`. When every hint fails, the
    /// caller's next move is to try the next rung of the ladder (§4.2), which is
    /// why this is distinct from a single [`TransportError::Connect`] failure.
    #[error("no address hint could be reached")]
    NoReachableAddress,

    /// The hints carried no usable iroh `NodeId`.
    ///
    /// Distinct from [`TransportError::NoReachableAddress`] because the two send a
    /// user in opposite directions: that one means "the network would not carry
    /// us", this one means "the pairing code did not say who to call" — a stale QR,
    /// a ticket from a daemon predating [`crate::AddrHint::Node`], or 32 bytes that
    /// are not a valid Ed25519 point. Re-pairing fixes it; hunting for a firewall
    /// does not.
    #[error("no iroh node id was supplied, so there is no peer to dial")]
    NoNodeId,

    /// The Noise handshake did not complete.
    ///
    /// Deliberately does not say why. See the module documentation.
    #[error("handshake failed")]
    HandshakeFailed,

    /// The peer authenticated, but its key is not paired with this daemon.
    ///
    /// Distinct from [`TransportError::HandshakeFailed`] because this one is
    /// only ever surfaced *locally*, to the daemon's log and devices screen. The
    /// peer is dropped without being told (§3.7).
    #[error("peer is not an authorized device")]
    PeerNotAuthorized,

    /// The peer's static key was not the one we dialled.
    ///
    /// Cannot normally happen — Noise IK authenticates the responder by
    /// construction — so reaching this means something is very wrong and the
    /// connection must not be used.
    #[error("peer presented an unexpected static key")]
    WrongPeer,

    /// A record failed to decrypt or authenticate after the handshake.
    #[error("a record failed to decrypt or authenticate")]
    Crypto,

    /// The Noise nonce space is exhausted and the session must be re-established.
    #[error("nonce space exhausted; reconnect to rekey")]
    NonceExhausted,

    /// The peer violated the multiplexer's framing rules.
    #[error("protocol violation: {0}")]
    Protocol(#[from] ProtocolViolation),

    /// A frame could not be encoded or decoded.
    #[error("framing error: {0}")]
    Framing(#[from] FrameError),

    /// A frame was larger than this binding's per-frame cap.
    #[error("frame payload of {len} bytes exceeds the {max} byte channel limit")]
    FrameTooLarge {
        /// The payload length attempted.
        len: usize,
        /// The configured maximum.
        max: usize,
    },

    /// The connection ended abruptly: the socket died with bytes still in flight.
    #[error("the connection was lost")]
    ConnectionLost,

    /// The connection was closed cleanly, by us or by the peer.
    #[error("the connection is closed")]
    Closed,

    /// The individual channel is closed, though the connection may be alive.
    #[error("the stream is closed")]
    StreamClosed,

    /// More channels are open than the configuration permits.
    #[error("cannot open another channel: the limit of {max} is reached")]
    TooManyChannels {
        /// The configured limit.
        max: usize,
    },

    /// An operation did not finish inside its deadline.
    #[error("the operation timed out")]
    Timeout,

    /// `accept` was called on a transport that is not listening.
    ///
    /// The phone dials and never listens, so its transport has no listener at
    /// all. Returning an error is better than silently hanging forever.
    #[error("this transport is not listening for inbound connections")]
    NotListening,

    /// The configuration is internally inconsistent.
    #[error("invalid transport configuration: {0}")]
    Config(&'static str),
}

impl TransportError {
    /// Wraps an I/O failure from `connect`, discarding everything but the kind.
    pub(crate) fn connect(addr: SocketAddr, err: &io::Error) -> Self {
        Self::Connect {
            addr,
            kind: err.kind(),
        }
    }

    /// Wraps an I/O failure from `bind`, discarding everything but the kind.
    pub(crate) fn bind(addr: SocketAddr, err: &io::Error) -> Self {
        Self::Bind {
            addr,
            kind: err.kind(),
        }
    }
}

/// Collapses a session-layer failure into a transport error.
///
/// Every Noise failure except nonce exhaustion becomes an opaque
/// [`TransportError::Crypto`]: the session layer already refuses to distinguish
/// a wrong key from a tampered ciphertext from a replay, and re-introducing that
/// distinction here would undo the property on purpose.
pub(crate) fn from_session(err: gonomad_core::SessionError) -> TransportError {
    match err {
        gonomad_core::SessionError::NonceExhausted => TransportError::NonceExhausted,
        _ => TransportError::Crypto,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_errors_are_reduced_to_a_kind_and_never_stored_whole() {
        // The public API must stay Clone + PartialEq so it can cross UniFFI and
        // be asserted on in tests. A stored io::Error would break both.
        let err = TransportError::connect(
            "127.0.0.1:1".parse().expect("literal address"),
            &io::Error::new(io::ErrorKind::ConnectionRefused, "boom"),
        );
        assert_eq!(err.clone(), err);
        match err {
            TransportError::Connect { kind, .. } => {
                assert_eq!(kind, io::ErrorKind::ConnectionRefused);
            }
            other => panic!("expected Connect, got {other:?}"),
        }
    }

    #[test]
    fn the_message_never_reveals_the_underlying_os_string() {
        // "boom" is a stand-in for an OS message that can name paths or users.
        let err = TransportError::bind(
            "0.0.0.0:9".parse().expect("literal address"),
            &io::Error::new(io::ErrorKind::PermissionDenied, "boom"),
        );
        assert!(!err.to_string().contains("boom"), "got {err}");
    }

    #[test]
    fn every_noise_failure_except_nonce_exhaustion_is_opaque() {
        use gonomad_core::SessionError;
        assert_eq!(
            from_session(SessionError::HandshakeFailed),
            TransportError::Crypto
        );
        assert_eq!(
            from_session(SessionError::DecryptFailed),
            TransportError::Crypto
        );
        assert_eq!(
            from_session(SessionError::NonceExhausted),
            TransportError::NonceExhausted
        );
    }

    #[test]
    fn protocol_violations_render_with_their_offending_value() {
        // These strings end up in the daemon's log, which is the only place the
        // cause of a dropped connection is visible.
        let err = TransportError::from(ProtocolViolation::FlowControlExceeded { channel: 7 });
        assert!(err.to_string().contains('7'), "got {err}");
    }
}
