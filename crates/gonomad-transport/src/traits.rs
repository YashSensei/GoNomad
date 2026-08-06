//! The transport abstraction from `ARCHITECTURE.md` §4.5.
//!
//! One interface, several bindings. Today there is exactly one implementation —
//! [`crate::TcpTransport`], Tier 0 of the ladder (§4.2) — and the whole point of
//! the indirection is that **iroh will implement these same traits** for Tiers 1
//! and 2 (hole-punched direct QUIC, and relayed QUIC) without anything above
//! this crate changing.
//!
//! # Deviations from the sketch in §4.5, and why
//!
//! The architecture document writes the traits with `async fn` and
//! `-> impl Stream<Item = PathInfo>`. Both are written differently here:
//!
//! - **`async fn` in a trait is not object-safe.** The daemon needs
//!   `Box<dyn Transport>` so the active tier can be chosen at runtime and
//!   swapped mid-session, which is the entire premise of a ladder. So the async
//!   methods return [`BoxFuture`] explicitly. This is what `#[async_trait]`
//!   generates, written out by hand rather than adding a dependency for it.
//! - **`impl Stream` is replaced by a [`tokio::sync::watch::Receiver`].** Also
//!   an object-safety problem, but the watch channel is a better fit regardless:
//!   path info is *current state*, not a log of events, and a subscriber that
//!   was slow should see the latest path — not replay every intermediate one.
//!   `tokio_stream::wrappers::WatchStream` converts it to a `Stream` for any
//!   caller that wants one.

use std::future::Future;
use std::pin::Pin;

use gonomad_proto::PublicKey;
use tokio::sync::watch;

use crate::error::Result;
use crate::mux::{RecvStream, SendStream};

/// A boxed, `Send` future — the object-safe stand-in for `async fn` in a trait.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Which rung of the transport ladder (§4.2) is carrying a connection.
///
/// Surfaced all the way to the UI on purpose: "a silently relayed session that
/// feels slow is worse than a visibly relayed one" (§4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Tier {
    /// Tier 0 — same physical network, no NAT traversal, no relay.
    Lan,
    /// Tier 1 — hole-punched direct peer-to-peer. Landing with iroh.
    Direct,
    /// Tier 2 — carried by a relay that sees only ciphertext. Landing with iroh.
    Relay,
}

impl Tier {
    /// A short label for the connection-status chip in the UI (§23).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Lan => "LAN",
            Self::Direct => "Direct",
            Self::Relay => "Relay",
        }
    }
}

/// What is known about the network path underneath a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathInfo {
    /// Which rung of the ladder is active.
    pub tier: Tier,
    /// Last measured round-trip time, when one has been measured.
    ///
    /// `None` rather than a fabricated zero: the responder side of a handshake
    /// has no RTT sample until application traffic flows, and a progress
    /// indicator that reports a number it invented is worse than one that
    /// reports nothing.
    pub rtt_ms: Option<u32>,
    /// Whether traffic is passing through a relay.
    ///
    /// Always `false` for Tier 0. Kept in the struct rather than derived from
    /// [`PathInfo::tier`] because iroh can upgrade a relayed path to a direct
    /// one mid-session, and the two facts are updated by different events.
    pub relayed: bool,
}

impl PathInfo {
    /// The path info for a LAN-direct connection with no RTT sample yet.
    #[must_use]
    pub const fn lan() -> Self {
        Self {
            tier: Tier::Lan,
            rtt_ms: None,
            relayed: false,
        }
    }

    /// Returns a copy with the round-trip time recorded.
    #[must_use]
    pub const fn with_rtt_ms(mut self, rtt_ms: u32) -> Self {
        self.rtt_ms = Some(rtt_ms);
        self
    }
}

/// Identifies the peer to dial.
///
/// Wraps the peer's **X25519 Noise static key** — the value the pairing QR
/// carries (§9.1), and the value the Noise IK initiator must know in advance.
/// It is a newtype rather than a bare `PublicKey` because `gonomad-core` also
/// has an Ed25519 `PublicKey` for signatures, the two are *not* interchangeable,
/// and handing the wrong one to a handshake fails in a way that is tedious to
/// diagnose from the wire.
///
/// When iroh lands this becomes the `NodeId` — same idea, same "a peer is a
/// public key, not an address" property (§4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerId(PublicKey);

impl PeerId {
    /// Wraps a peer's Noise static key.
    #[must_use]
    pub const fn from_noise_key(key: PublicKey) -> Self {
        Self(key)
    }

    /// The peer's Noise static key.
    #[must_use]
    pub const fn noise_key(&self) -> &PublicKey {
        &self.0
    }

    /// The first eight hex characters, for logs and compact UI.
    #[must_use]
    pub fn short(&self) -> String {
        self.0.short()
    }
}

/// A place a peer might be reachable.
///
/// Sourced from the pairing QR's `addr_hints` and `relay_hint` (§4.6), so the
/// first connection after pairing needs no discovery at all. Hints are advisory:
/// a stale one costs a fallback, never a failure.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AddrHint {
    /// A direct socket address, e.g. `192.168.1.4:41234`.
    Direct(std::net::SocketAddr),
    /// A relay URL. Ignored by Tier 0; consumed by iroh at Tier 2.
    Relay(String),
}

impl AddrHint {
    /// Parses one `addr_hints` entry from a pairing ticket.
    ///
    /// Anything that is not a socket address is treated as a relay URL, which
    /// matches how [`gonomad_core::PairingTicket`] tags its hints and keeps a
    /// newer daemon's hint format from breaking an older client.
    #[must_use]
    pub fn parse(hint: &str) -> Self {
        hint.parse()
            .map_or_else(|_| Self::Relay(hint.to_owned()), Self::Direct)
    }

    /// Every hint carried by a pairing ticket, in the order it should be tried.
    #[must_use]
    pub fn from_ticket(ticket: &gonomad_core::PairingTicket) -> Vec<Self> {
        let mut hints: Vec<Self> = ticket.addr_hints.iter().map(|h| Self::parse(h)).collect();
        if let Some(relay) = &ticket.relay_hint {
            hints.push(Self::Relay(relay.clone()));
        }
        hints
    }

    /// The socket address, when this is a direct hint.
    #[must_use]
    pub const fn socket_addr(&self) -> Option<std::net::SocketAddr> {
        match self {
            Self::Direct(addr) => Some(*addr),
            Self::Relay(_) => None,
        }
    }
}

/// Decides whether an authenticated peer may proceed.
///
/// Called after the Noise handshake has proved possession of a static key and
/// **before** any application data is read, which is what lets the daemon reject
/// an unpaired device without ever running a request handler (§3.7). The daemon
/// implements this over its SQLite device table; the pairing window implements
/// it as [`AllowAny`].
///
/// Synchronous on purpose: a database lookup on the accept path must be fast,
/// and making it awaitable would invite someone to put a network call here.
pub trait PeerPolicy: Send + Sync + 'static {
    /// Returns `true` when this Noise static key belongs to a paired,
    /// non-revoked device.
    fn authorize(&self, peer: &PublicKey) -> bool;
}

/// Accepts any peer.
///
/// Correct **only** inside an open pairing window, where the pre-shared key from
/// the QR is what authenticates the peer and the window is time-boxed,
/// single-use, and attempt-capped (§9.1). Using it for `Purpose::Reconnect`
/// would make the paired-device list decorative.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowAny;

impl PeerPolicy for AllowAny {
    fn authorize(&self, _peer: &PublicKey) -> bool {
        true
    }
}

/// Accepts a fixed set of keys.
///
/// A convenience for tests and for a daemon that keeps its device list in
/// memory. Comparison goes through `PublicKey`'s constant-time equality, so a
/// linear scan does not leak a matching prefix by timing.
#[derive(Debug, Clone, Default)]
pub struct Allowlist(Vec<PublicKey>);

impl Allowlist {
    /// Builds an allowlist from paired devices' Noise static keys.
    #[must_use]
    pub fn new(keys: Vec<PublicKey>) -> Self {
        Self(keys)
    }
}

impl PeerPolicy for Allowlist {
    fn authorize(&self, peer: &PublicKey) -> bool {
        // `filter().count()` rather than `any()`, so the scan visits every entry
        // instead of short-circuiting on the first match and revealing the
        // matching position through timing. Each individual comparison is
        // already constant-time — `PublicKey`'s `PartialEq` uses `subtle` — so
        // this closes the remaining leak, which is *where* in the list the match
        // occurred.
        //
        // Written this way rather than folding with a bitwise `|` because that
        // trips `clippy::needless_bitwise_bool`, and suppressing a lint is worse
        // than expressing the same guarantee in a form the linter understands.
        self.0.iter().filter(|key| *key == peer).count() > 0
    }
}

/// One established, authenticated, encrypted connection to a peer.
///
/// Mirrors `Conn` in §4.5. Every method is object-safe so the ladder can hold
/// `Box<dyn Conn>` and swap the rung underneath the session.
pub trait Conn: Send + Sync + 'static {
    /// Opens a new bidirectional stream.
    ///
    /// By convention the **first** stream opened by the initiator is the control
    /// stream (§10.2). Nothing enforces that here, because the transport does
    /// not parse what flows over it.
    ///
    /// # Errors
    ///
    /// Fails once the connection is closed, or when the concurrent-channel limit
    /// is reached.
    fn open_bi(&self) -> BoxFuture<'_, Result<(SendStream, RecvStream)>>;

    /// Waits for the peer to open a bidirectional stream.
    ///
    /// # Errors
    ///
    /// Fails once the connection is closed.
    fn accept_bi(&self) -> BoxFuture<'_, Result<(SendStream, RecvStream)>>;

    /// What is currently known about the network path.
    fn path_info(&self) -> PathInfo;

    /// Watches the path for change.
    ///
    /// On Tier 0 this never fires after the connection is established, and that
    /// is the honest answer rather than a missing feature: a TCP connection is
    /// identified by its 4-tuple, so a network change does not migrate the
    /// path — it kills the socket. QUIC connection migration (§4.4) is precisely
    /// what makes this channel interesting, and it arrives with iroh.
    fn path_changes(&self) -> watch::Receiver<PathInfo>;

    /// The peer's authenticated Noise static key.
    fn peer_key(&self) -> PublicKey;

    /// Closes the connection and every stream on it.
    fn close(&self);
}

/// Establishes connections, in one or both directions.
///
/// Mirrors `Transport` in §4.5.
pub trait Transport: Send + Sync + 'static {
    /// Dials `peer`, trying `hints` in order.
    ///
    /// # Errors
    ///
    /// Returns [`crate::TransportError::NoReachableAddress`] when no hint could
    /// be reached, or a handshake error when a peer answered but did not
    /// authenticate.
    fn connect<'a>(
        &'a self,
        peer: PeerId,
        hints: &'a [AddrHint],
    ) -> BoxFuture<'a, Result<Box<dyn Conn>>>;

    /// Waits for the next inbound connection that completed its handshake.
    ///
    /// # Errors
    ///
    /// Returns [`crate::TransportError::NotListening`] on a dial-only transport,
    /// and [`crate::TransportError::Closed`] once the listener has shut down.
    fn accept(&self) -> BoxFuture<'_, Result<Box<dyn Conn>>>;

    /// The tier this transport provides.
    fn path_info(&self) -> PathInfo;
}

/// Resolves a [`PeerId`] to addresses when no hint is available.
///
/// The seam for mDNS (`_gonomad._udp.local`, §4.6), which is deliberately **not
/// implemented in this slice**: the pairing QR already carries `addr_hints`, so
/// the first connect and every reconnect to a remembered address need no
/// discovery at all. mDNS earns its keep only when the daemon's LAN address has
/// changed since pairing, which is a recovery path rather than the common one.
///
/// When it lands it implements this trait, and [`crate::TcpTransport`] gains an
/// optional `Arc<dyn Discovery>` consulted after the hints are exhausted.
pub trait Discovery: Send + Sync + 'static {
    /// Finds addresses for `peer`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::TransportError::NoReachableAddress`] when the peer
    /// cannot be located.
    fn resolve(&self, peer: PeerId) -> BoxFuture<'_, Result<Vec<AddrHint>>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> PublicKey {
        PublicKey::from_bytes([byte; 32])
    }

    #[test]
    fn a_direct_hint_parses_as_a_socket_address() {
        assert_eq!(
            AddrHint::parse("192.168.1.4:41234"),
            AddrHint::Direct("192.168.1.4:41234".parse().expect("literal"))
        );
        assert_eq!(
            AddrHint::parse("[2001:db8::1]:41234"),
            AddrHint::Direct("[2001:db8::1]:41234".parse().expect("literal"))
        );
    }

    #[test]
    fn anything_that_is_not_an_address_is_kept_as_a_relay_hint() {
        // Forward compatibility: a newer daemon's hint format must not make an
        // older client reject the whole ticket.
        assert_eq!(
            AddrHint::parse("https://relay.example.com"),
            AddrHint::Relay("https://relay.example.com".into())
        );
        assert_eq!(AddrHint::parse(""), AddrHint::Relay(String::new()));
    }

    #[test]
    fn ticket_hints_come_out_in_dial_order_with_the_relay_last() {
        let ticket = gonomad_core::PairingTicket {
            daemon_key: key(1),
            addr_hints: vec!["10.0.0.2:1234".into(), "not-an-address".into()],
            relay_hint: Some("https://relay.example.com".into()),
        };
        let hints = AddrHint::from_ticket(&ticket);
        assert_eq!(hints.len(), 3);
        assert!(matches!(hints[0], AddrHint::Direct(_)));
        assert_eq!(
            hints[2],
            AddrHint::Relay("https://relay.example.com".into())
        );
    }

    #[test]
    fn only_direct_hints_yield_a_socket_address() {
        assert!(AddrHint::parse("10.0.0.2:1").socket_addr().is_some());
        assert!(AddrHint::parse("https://r").socket_addr().is_none());
    }

    #[test]
    fn allow_any_is_exactly_that() {
        assert!(AllowAny.authorize(&key(9)));
    }

    #[test]
    fn an_allowlist_admits_only_listed_keys() {
        let list = Allowlist::new(vec![key(1), key(2)]);
        assert!(list.authorize(&key(1)));
        assert!(list.authorize(&key(2)));
        assert!(!list.authorize(&key(3)));
        assert!(!Allowlist::default().authorize(&key(1)));
    }

    #[test]
    fn lan_path_info_is_never_relayed() {
        let info = PathInfo::lan();
        assert_eq!(info.tier, Tier::Lan);
        assert!(!info.relayed);
        assert_eq!(info.rtt_ms, None);
        assert_eq!(info.with_rtt_ms(3).rtt_ms, Some(3));
    }

    #[test]
    fn every_tier_has_a_ui_label() {
        for tier in [Tier::Lan, Tier::Direct, Tier::Relay] {
            assert!(!tier.label().is_empty());
        }
    }

    #[test]
    fn the_traits_are_object_safe() {
        // The ladder's whole premise is swapping the rung at runtime, which is
        // impossible if these are not object-safe. A compile-time assertion.
        fn assert_object_safe(_: Option<&dyn Transport>, _: Option<&dyn Conn>) {}
        fn assert_policy_object_safe(_: Option<&dyn PeerPolicy>, _: Option<&dyn Discovery>) {}
        assert_object_safe(None, None);
        assert_policy_object_safe(None, None);
    }
}
