//! Tiers 1 and 2: hole-punched direct QUIC, and relayed QUIC, over iroh.
//!
//! This is the rung that makes GoNomad a product rather than a demo. Tier 0
//! ([`crate::tcp`]) requires the phone and the laptop to be on the same network.
//! This module removes that requirement: the phone on mobile data reaches a
//! laptop behind a home router, with no port forwarding, no dynamic DNS, no VPN
//! profile, and no account (`ARCHITECTURE.md` §4.2, §4.3).
//!
//! # What iroh provides, and what this module adds
//!
//! iroh gives a QUIC endpoint addressed by public key: hole punching over UDP,
//! a relay fallback when a NAT refuses to be punched, and transparent upgrade
//! from relayed to direct mid-session. On top of that this module adds exactly
//! the things GoNomad's security model requires:
//!
//! | Layer | Provided by |
//! |---|---|
//! | Reachability, NAT traversal, relay fallback | iroh |
//! | Transport encryption, peer authentication by `NodeId` | iroh's QUIC TLS 1.3 |
//! | ALPN gate (`gonomad/1`) | iroh, configured here (§3.7) |
//! | **Session encryption and device authentication** | Noise IK, run here (§3.4) |
//! | Paired-device authorisation | [`crate::PeerPolicy`], checked here |
//! | Frame codec, stream topology | [`crate::stream`], §10.2–10.3 |
//!
//! # Noise is still inside, and it has to be
//!
//! iroh's QUIC already authenticates both peers' `NodeId`s and encrypts
//! everything, so running Noise inside it is redundant on this rung. §3.4 keeps
//! it anyway, and the reason matters more here than anywhere:
//!
//! - **The relay is untrusted by construction.** A relayed connection carries
//!   ciphertext the relay cannot read even if it wanted to, because the payload is
//!   Noise-sealed before QUIC ever sees it. That is what makes defaulting to
//!   *public* relays a defensible choice rather than a compromise, and what lets
//!   the answer to "is relaying safe?" be yes without qualification (§4.3).
//! - **Security is a property of the session, not of the tier.** A relayed path, a
//!   hole-punched path, Tier 0's TCP socket and a future Tier 3 tunnel all present
//!   the same session layer to a reviewer. Cloudflare Tunnel terminates TLS and
//!   would otherwise see plaintext.
//! - **The device credential is the Noise static key**, not the `NodeId`. The
//!   daemon's paired-device table (§9.4) is keyed on it, revocation deletes it,
//!   and [`crate::PeerPolicy`] checks it — unchanged from Tier 0.
//!
//! # One Noise session per stream, not per connection
//!
//! The one genuinely non-obvious decision in this module. `snow`'s transport state
//! advances an implicit nonce counter per direction, so records must be decrypted
//! in the order they were encrypted. Sealing several QUIC streams with one session
//! would therefore force the receiver to wait for every stream's records in send
//! order — head-of-line blocking, rebuilt in userspace, on top of the transport
//! chosen specifically to avoid it (§4.4). So every bidirectional stream runs its
//! own Noise IK handshake and owns its own session.
//!
//! What that costs, stated honestly:
//!
//! | | Cost |
//! |---|---|
//! | Opening a stream after the first | One extra round trip, and one Noise handshake's worth of X25519 |
//! | Opening the *control* stream | Nothing: the connection handshake runs on it, and it is handed to the first `open_bi`/`accept_bi` |
//! | Bytes on the wire | One `u16` record prefix per 64 KiB, as on Tier 0 |
//!
//! Streams here are long-lived — one control stream, one per PTY, one per bulk
//! transfer (§10.2) — so a round trip at stream open is paid once per terminal
//! tab, not once per keystroke. The alternative was to give up either per-stream
//! independence or Noise-inside, and both are load-bearing.
//!
//! Two properties fall out of this that are worth noting because they are
//! improvements rather than compromises: each stream gets its own ephemeral keys,
//! so compromising one stream's session does not touch another's, and a stream's
//! Noise handshake re-verifies that the peer still holds the connection's
//! authenticated static key.
//!
//! # No userspace multiplexer, and no 256 KiB frame cap
//!
//! [`crate::mux`] exists only because TCP is one ordered byte stream. QUIC streams
//! are independent, with their own flow control and their own loss recovery, so
//! [`Conn::open_bi`] maps straight onto [`iroh::endpoint::Connection::open_bi`].
//! Routing through the mux would reintroduce exactly the blocking QUIC avoids.
//!
//! This also retires R25 in §19: the mux caps a single frame at 256 KiB because
//! its credit is returned only when a *whole frame* is consumed, so a frame larger
//! than the receive window could never be reassembled. QUIC flow-controls a byte
//! stream rather than whole messages, so this binding carries the protocol's full
//! [`gonomad_proto::frame::MAX_PAYLOAD_LEN`] — 32 MiB — and
//! [`IrohConfig::max_frame_len`] defaults to it.
//!
//! # Naming: `NodeId` versus `EndpointId`
//!
//! iroh 1.0 renamed `NodeId` to `EndpointId` and `NodeAddr` to `EndpointAddr`.
//! GoNomad's documentation and API keep saying **node id**, because that is what
//! §4.3 and §4.6 call it, and renaming a concept across the architecture document,
//! the pairing ticket, the UI and the FFI to track an upstream rename is churn a
//! reader absorbs for nothing. The conversion happens in this module and nowhere
//! else.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt as _;
use gonomad_core::{DeviceIdentity, PairingSecret, Purpose, Sas, Session};
use gonomad_proto::{PublicKey, ALPN};
use iroh::endpoint::{Connection, SendStream as QuicSendHalf};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl, SecretKey, TransportAddr};
use tokio::sync::{mpsc, watch};
use zeroize::Zeroizing;

use crate::error::{from_session, Result, TransportError};
use crate::handshake::{self, Authenticated};
use crate::mux::TaskGuard;
use crate::stream::{QuicRecv, QuicSend, RecvStream, SendStream, StreamCrypto, StreamId};
use crate::traits::{
    AddrHint, AllowAny, BoxFuture, Conn, PathInfo, PeerId, PeerPolicy, Tier, Transport,
};

/// How long a peer has to complete a Noise handshake before being dropped.
///
/// Bounds the pre-authentication resource commitment (§3.8), and — unlike on
/// Tier 0 — also bounds `open_bi`: a stream's handshake needs a reply from the
/// peer, so without a deadline a peer that accepts the QUIC stream and then says
/// nothing would park the caller forever.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait for a QUIC connection, hole punching included.
///
/// Longer than Tier 0's TCP connect timeout on purpose: this covers relay
/// discovery, address publication and a hole-punching attempt, not one `SYN`.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// Concurrent bidirectional streams a peer may hold open.
///
/// Sized above the §3.8 ceilings that consume streams — 16 PTYs, plus control,
/// plus bulk transfers and subscriptions — with room to spare. It is a cap rather
/// than a guess because the reassembly buffer a peer can pin is
/// `max_frame_len × max_concurrent_streams`, and the product needs to be a number
/// someone has looked at.
pub const DEFAULT_MAX_CONCURRENT_STREAMS: u32 = 64;

/// Completed connections buffered before the acceptor stops taking new ones.
const DEFAULT_ACCEPT_QUEUE: usize = 16;

/// Completed streams buffered per connection.
const DEFAULT_STREAM_QUEUE: usize = 16;

/// Where relayed traffic goes when a direct path cannot be established.
///
/// The default is iroh's public relays, and that is safe rather than merely
/// convenient: a relay forwards Noise-sealed ciphertext keyed by `NodeId` and can
/// read nothing (§4.3). What it *can* observe is that two node ids exchange
/// packets, and when — so [`RelayPolicy::SelfHosted`] exists for anyone who
/// objects to that timing metadata leaving their control.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RelayPolicy {
    /// iroh's public relay network. No account, no configuration.
    Default,
    /// A self-hosted `iroh-relay`, given as a URL.
    ///
    /// Several may be listed; iroh picks the lowest-latency one as its home relay.
    SelfHosted(Vec<String>),
    /// No relay at all.
    ///
    /// Only direct paths, so a peer behind a symmetric NAT or CGNAT becomes
    /// unreachable — which is the entire failure mode Tier 2 exists to cover. It
    /// is here for tests, for an air-gapped LAN, and for a user who would rather
    /// fail than be relayed.
    Disabled,
}

impl RelayPolicy {
    /// Converts to iroh's configuration.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Config`] when a self-hosted URL does not parse,
    /// or when the list is empty — which would silently mean "no relay" and is
    /// almost certainly a misconfiguration rather than an intent.
    fn to_relay_mode(&self) -> Result<RelayMode> {
        match self {
            Self::Default => Ok(RelayMode::Default),
            Self::Disabled => Ok(RelayMode::Disabled),
            Self::SelfHosted(urls) => {
                if urls.is_empty() {
                    return Err(TransportError::Config(
                        "RelayPolicy::SelfHosted needs at least one relay URL",
                    ));
                }
                let parsed = urls
                    .iter()
                    .map(|url| url.parse::<RelayUrl>())
                    .collect::<core::result::Result<Vec<_>, _>>()
                    .map_err(|_| TransportError::Config("relay URL could not be parsed"))?;
                Ok(RelayMode::custom(parsed))
            }
        }
    }
}

/// How this endpoint dials, accepts, and authenticates.
///
/// One configuration rather than Tier 0's separate client and server halves,
/// because an iroh endpoint is symmetric: the same UDP socket dials and accepts,
/// and the phone needs one in order to dial at all.
pub struct IrohConfig {
    /// This device's identity. Its iroh subkey is the endpoint's secret key and
    /// its X25519 subkey is the Noise static.
    pub identity: Arc<DeviceIdentity>,
    /// Which Noise pattern to run. [`Purpose::Pairing`] only while a pairing
    /// window is open.
    pub purpose: Purpose,
    /// The pairing pre-shared key, required when `purpose` is
    /// [`Purpose::Pairing`] and forbidden otherwise.
    pub psk: Option<Zeroizing<[u8; 32]>>,
    /// Decides whether an authenticated Noise static key may proceed.
    pub policy: Arc<dyn PeerPolicy>,
    /// Whether to answer inbound connections.
    ///
    /// `false` sets no ALPN on the endpoint, so the QUIC handshake of an inbound
    /// connection fails before this code sees it. The phone sets this: it dials
    /// and is never dialled, and an endpoint that cannot accept is one fewer
    /// surface to reason about (§3.7).
    pub accept_inbound: bool,
    /// Where relayed traffic goes.
    pub relay: RelayPolicy,
    /// Whether to publish and resolve node addresses through iroh's discovery
    /// service (DNS by default, §4.6).
    ///
    /// With this off, a peer is reachable only at the addresses and relay a
    /// pairing ticket already pinned. Worth turning off for a deployment that
    /// wants no dependency on named infrastructure — at the cost of the recovery
    /// path when every pinned address has gone stale.
    pub address_lookup: bool,
    /// Sockets to bind, or empty for iroh's defaults (`0.0.0.0` and `[::]`).
    pub bind_addrs: Vec<SocketAddr>,
    /// Largest single [`gonomad_proto::Frame`] payload this binding will carry.
    ///
    /// Defaults to the protocol's own maximum, because QUIC has no reason to cap
    /// it lower — see the module documentation on R25.
    pub max_frame_len: usize,
    /// Concurrent bidirectional streams a peer may hold open.
    pub max_concurrent_streams: u32,
    /// Deadline for one Noise handshake, connection- or stream-level.
    pub handshake_timeout: Duration,
    /// Deadline for establishing the QUIC connection.
    pub connect_timeout: Duration,
    /// Completed connections buffered for [`Transport::accept`].
    pub accept_queue: usize,
}

impl IrohConfig {
    /// Accepts and dials as an already-paired device.
    #[must_use]
    pub fn reconnect(identity: Arc<DeviceIdentity>, policy: Arc<dyn PeerPolicy>) -> Self {
        Self {
            identity,
            purpose: Purpose::Reconnect,
            psk: None,
            policy,
            accept_inbound: true,
            relay: RelayPolicy::Default,
            address_lookup: true,
            bind_addrs: Vec::new(),
            max_frame_len: gonomad_proto::frame::MAX_PAYLOAD_LEN,
            max_concurrent_streams: DEFAULT_MAX_CONCURRENT_STREAMS,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            accept_queue: DEFAULT_ACCEPT_QUEUE,
        }
    }

    /// Accepts a first-time pairing, authenticated by the QR's secret.
    ///
    /// The policy is [`AllowAny`] because the peer's key is *by definition* not
    /// yet known — proving it saw the screen is the pre-shared key's job (§9.2).
    /// The caller must tear this endpoint down when the 120-second window closes.
    #[must_use]
    pub fn pairing(identity: Arc<DeviceIdentity>, secret: &PairingSecret) -> Self {
        Self {
            purpose: Purpose::Pairing,
            psk: Some(Zeroizing::new(*secret.as_bytes())),
            policy: Arc::new(AllowAny),
            ..Self::reconnect(identity, Arc::new(AllowAny))
        }
    }

    /// Dials only: no ALPN is offered, so nothing can connect inbound.
    #[must_use]
    pub fn dialer(identity: Arc<DeviceIdentity>) -> Self {
        Self {
            accept_inbound: false,
            ..Self::reconnect(identity, Arc::new(AllowAny))
        }
    }

    /// Dials only, to complete a first-time pairing.
    #[must_use]
    pub fn pairing_dialer(identity: Arc<DeviceIdentity>, secret: &PairingSecret) -> Self {
        Self {
            accept_inbound: false,
            ..Self::pairing(identity, secret)
        }
    }

    /// Checks that the configuration is internally consistent.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Config`] when pairing has no secret or a
    /// reconnect carries one — both are silent security failures otherwise — when
    /// a limit is zero, or when the relay configuration cannot be built.
    pub fn validate(&self) -> Result<()> {
        match (self.purpose, self.psk.is_some()) {
            (Purpose::Pairing, false) => {
                return Err(TransportError::Config(
                    "Purpose::Pairing requires the pairing secret as a pre-shared key",
                ))
            }
            (Purpose::Reconnect, true) => {
                return Err(TransportError::Config(
                    "Purpose::Reconnect must not carry a pre-shared key",
                ))
            }
            _ => {}
        }
        if self.max_frame_len == 0 {
            return Err(TransportError::Config("max_frame_len must be at least 1"));
        }
        if self.max_frame_len > gonomad_proto::frame::MAX_PAYLOAD_LEN {
            return Err(TransportError::Config(
                "max_frame_len exceeds the protocol's maximum payload",
            ));
        }
        if self.max_concurrent_streams == 0 {
            return Err(TransportError::Config(
                "max_concurrent_streams must be at least 1",
            ));
        }
        self.relay.to_relay_mode().map(drop)
    }
}

// Never prints the pre-shared key. A PSK in a log is a pairing an attacker can
// complete, and the 120-second window is no comfort if the log is read later.
impl core::fmt::Debug for IrohConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IrohConfig")
            .field("device_id", &self.identity.device_id())
            .field("node_id", &self.identity.iroh_node_id().short())
            .field("purpose", &self.purpose)
            .field("psk", &self.psk.as_ref().map(|_| "<redacted>"))
            .field("accept_inbound", &self.accept_inbound)
            .field("relay", &self.relay)
            .finish_non_exhaustive()
    }
}

/// Tiers 1 and 2 of the transport ladder, over one iroh endpoint.
pub struct IrohTransport {
    endpoint: Endpoint,
    config: Arc<IrohConfig>,
    incoming: tokio::sync::Mutex<mpsc::Receiver<IrohConnection>>,
    _acceptor: TaskGuard,
}

impl IrohTransport {
    /// Binds an endpoint at this device's derived `NodeId` and starts accepting.
    ///
    /// The endpoint's secret key is `DeviceIdentity::expose_iroh_secret`, so the
    /// `NodeId` is a pure function of the master seed: a daemon restored from its
    /// recovery phrase is reachable at the address its old pairing QRs advertise.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Config`] when the configuration is inconsistent,
    /// or [`TransportError::Bind`] when the endpoint cannot be brought up.
    pub async fn bind(config: IrohConfig) -> Result<Self> {
        config.validate()?;

        let secret = SecretKey::from_bytes(&config.identity.expose_iroh_secret());
        // `N0` bundles iroh's DNS/pkarr address lookup with its default relays;
        // `Minimal` bundles nothing but the crypto provider. Either way the relay
        // mode is set explicitly afterwards, so the preset never decides it.
        let mut builder = if config.address_lookup {
            Endpoint::builder(iroh::endpoint::presets::N0)
        } else {
            Endpoint::builder(iroh::endpoint::presets::Minimal)
        };
        builder = builder
            .secret_key(secret)
            .relay_mode(config.relay.to_relay_mode()?);

        // The ALPN gate (§3.7). Offering none is how `accept_inbound: false` makes
        // an inbound QUIC handshake fail one layer below this code.
        if config.accept_inbound {
            builder = builder.alpns(vec![ALPN.to_vec()]);
        }

        if !config.bind_addrs.is_empty() {
            builder = builder.clear_ip_transports();
            for addr in &config.bind_addrs {
                builder = builder
                    .bind_addr(*addr)
                    .map_err(|_| TransportError::Config("bind address is not usable"))?;
            }
        }

        let endpoint = builder.bind().await.map_err(|err| {
            tracing::warn!(error = %err, "iroh endpoint could not be bound");
            TransportError::Bind {
                addr: config
                    .bind_addrs
                    .first()
                    .copied()
                    .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0))),
                kind: std::io::ErrorKind::AddrNotAvailable,
            }
        })?;

        let config = Arc::new(config);
        let (tx, rx) = mpsc::channel(config.accept_queue.max(1));
        let acceptor = if config.accept_inbound {
            vec![tokio::spawn(accept_loop(
                endpoint.clone(),
                Arc::clone(&config),
                tx,
            ))]
        } else {
            Vec::new()
        };

        Ok(Self {
            endpoint,
            config,
            incoming: tokio::sync::Mutex::new(rx),
            _acceptor: TaskGuard(acceptor),
        })
    }

    /// This endpoint's `NodeId`, which is what a pairing ticket must carry.
    #[must_use]
    pub fn node_id(&self) -> PublicKey {
        PublicKey::from_bytes(*self.endpoint.id().as_bytes())
    }

    /// The sockets this endpoint is actually listening on.
    ///
    /// Useful for the address hints a pairing QR pins (§4.6), and for a test that
    /// wants to dial a loopback address without any discovery at all.
    #[must_use]
    pub fn bound_sockets(&self) -> Vec<SocketAddr> {
        self.endpoint.bound_sockets()
    }

    /// Waits until the endpoint has reached a relay and is dialable from
    /// elsewhere.
    ///
    /// Only meaningful with a relay configured. A daemon should await this before
    /// rendering a pairing QR, or the ticket may pin a relay the endpoint has not
    /// settled on yet.
    pub async fn online(&self) {
        self.endpoint.online().await;
    }

    /// Everything a peer needs to dial this endpoint, as pairing-ticket hints.
    #[must_use]
    pub fn addr_hints(&self) -> Vec<AddrHint> {
        let addr = self.endpoint.addr();
        let mut hints = vec![AddrHint::Node(self.node_id())];
        for ip in addr.ip_addrs() {
            hints.push(AddrHint::Direct(*ip));
        }
        for relay in addr.relay_urls() {
            hints.push(AddrHint::Relay(relay.to_string()));
        }
        hints
    }

    /// Dials `peer`, whose `NodeId` must appear among `hints`.
    ///
    /// Direct address hints and a relay hint are passed to iroh as a starting
    /// point, which is what lets the first connection after pairing skip discovery
    /// entirely (§4.6). They are hints: iroh races them against whatever it
    /// discovers, and a stale one costs nothing.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NoNodeId`] when no [`AddrHint::Node`] is present,
    /// [`TransportError::NoReachableAddress`] when the peer cannot be reached,
    /// [`TransportError::Timeout`] on a deadline, or a handshake error when a peer
    /// answered but did not authenticate.
    pub async fn connect_iroh(&self, peer: PeerId, hints: &[AddrHint]) -> Result<IrohConnection> {
        let addr = node_addr_from_hints(hints)?;
        let dial = self.endpoint.connect(addr, ALPN);
        let conn = match tokio::time::timeout(self.config.connect_timeout, dial).await {
            Ok(Ok(conn)) => conn,
            Ok(Err(err)) => {
                // The failure could be an unreachable peer, a refused ALPN, or a
                // relay that would not take us. iroh distinguishes them; the
                // caller's next move — try the next rung — is the same either way.
                tracing::debug!(error = %err, peer = %peer.short(), "iroh dial failed");
                return Err(TransportError::NoReachableAddress);
            }
            Err(_) => return Err(TransportError::Timeout),
        };
        // The QUIC connection is up; the Noise handshake on top of it needs its own
        // deadline. Without one, a peer that completes the QUIC handshake and then
        // says nothing parks the caller forever — and on this rung "the peer" may be
        // anything on the internet that knows our node id.
        let establish = IrohConnection::establish(conn, Some(peer), Arc::clone(&self.config));
        match tokio::time::timeout(self.config.handshake_timeout, establish).await {
            Ok(result) => result,
            Err(_) => Err(TransportError::Timeout),
        }
    }

    /// Waits for the next inbound connection that completed its handshake.
    ///
    /// Connections that fail to authenticate never appear here: they are logged
    /// and dropped, because surfacing them would give a caller a way to learn that
    /// an unpaired device tried to connect, which is exactly the information §3.7
    /// declines to leak on the wire.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotListening`] when `accept_inbound` is false,
    /// and [`TransportError::Closed`] once the acceptor has stopped.
    pub async fn accept_iroh(&self) -> Result<IrohConnection> {
        if !self.config.accept_inbound {
            return Err(TransportError::NotListening);
        }
        let mut rx = self.incoming.lock().await;
        rx.recv().await.ok_or(TransportError::Closed)
    }

    /// Closes the endpoint and every connection on it.
    ///
    /// Awaited rather than dropped so that peers are told, instead of discovering
    /// it on an idle timeout.
    pub async fn close(&self) {
        self.endpoint.close().await;
    }
}

impl core::fmt::Debug for IrohTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IrohTransport")
            .field("node_id", &self.node_id().short())
            .field("accepting", &self.config.accept_inbound)
            .finish_non_exhaustive()
    }
}

impl Transport for IrohTransport {
    fn connect<'a>(
        &'a self,
        peer: PeerId,
        hints: &'a [AddrHint],
    ) -> BoxFuture<'a, Result<Box<dyn Conn>>> {
        Box::pin(async move {
            let conn = self.connect_iroh(peer, hints).await?;
            Ok(Box::new(conn) as Box<dyn Conn>)
        })
    }

    fn accept(&self) -> BoxFuture<'_, Result<Box<dyn Conn>>> {
        Box::pin(async move {
            let conn = self.accept_iroh().await?;
            Ok(Box::new(conn) as Box<dyn Conn>)
        })
    }

    /// The tier this transport *can* provide, before any path exists.
    ///
    /// Reports [`Tier::Relay`], the pessimistic answer, because until a connection
    /// is up there is no way to know whether hole punching will succeed — and
    /// over-claiming `Direct` is precisely the failure §4.2 warns about. A live
    /// connection reports the truth through [`Conn::path_info`].
    fn path_info(&self) -> PathInfo {
        PathInfo {
            tier: Tier::Relay,
            rtt_ms: None,
            relayed: true,
        }
    }
}

/// Builds an [`EndpointAddr`] from pairing-ticket hints.
///
/// The `NodeId` is mandatory and the rest is advisory, which mirrors what the
/// hints mean: iroh needs the key to dial at all, and addresses only make the
/// first attempt faster.
fn node_addr_from_hints(hints: &[AddrHint]) -> Result<EndpointAddr> {
    let node = hints
        .iter()
        .find_map(|hint| match hint {
            AddrHint::Node(key) => Some(*key),
            _ => None,
        })
        .ok_or(TransportError::NoNodeId)?;
    let id = EndpointId::from_bytes(node.as_bytes()).map_err(|_| TransportError::NoNodeId)?;

    let mut addr = EndpointAddr::new(id);
    for hint in hints {
        match hint {
            AddrHint::Direct(socket) => addr = addr.with_ip_addr(*socket),
            AddrHint::Relay(url) => {
                // A hint is advisory. A malformed relay URL from an old or
                // unfamiliar daemon must cost the relay path, not the connection.
                if let Ok(relay) = url.parse::<RelayUrl>() {
                    addr = addr.with_relay_url(relay);
                } else {
                    tracing::debug!(%url, "ignoring an unparsable relay hint");
                }
            }
            AddrHint::Node(_) => {}
        }
    }
    Ok(addr)
}

/// Accepts inbound QUIC connections and runs their Noise handshakes.
///
/// Handshakes run in their own tasks so one silent peer cannot stall every other
/// device's reconnect for the whole handshake timeout. iroh bounds inbound QUIC
/// handshake concurrency itself, one layer below.
async fn accept_loop(
    endpoint: Endpoint,
    config: Arc<IrohConfig>,
    tx: mpsc::Sender<IrohConnection>,
) {
    while let Some(incoming) = endpoint.accept().await {
        if tx.is_closed() {
            return;
        }
        let config = Arc::clone(&config);
        let tx = tx.clone();
        tokio::spawn(async move {
            // Anything that can send a UDP datagram can reach here, so a failure
            // is noise rather than an incident (§3.7).
            let Ok(accepting) = incoming.accept() else {
                tracing::trace!("inbound QUIC connection was not accepted");
                return;
            };
            let conn = match accepting.await {
                Ok(conn) => conn,
                Err(err) => {
                    tracing::debug!(error = %err, "inbound QUIC handshake failed");
                    return;
                }
            };
            // Belt and braces: iroh has already refused any connection not
            // offering the ALPN, since it is the only one the endpoint advertises.
            // Checked again because "presents nothing to a scanner" is a property
            // worth two lines of defence.
            if conn.alpn() != ALPN {
                tracing::debug!("inbound connection offered the wrong ALPN");
                conn.close(1u8.into(), b"alpn");
                return;
            }
            let timeout = config.handshake_timeout;
            match tokio::time::timeout(timeout, IrohConnection::establish(conn, None, config)).await
            {
                Ok(Ok(conn)) => {
                    // A full queue means the daemon is not accepting fast enough;
                    // dropping is better than unbounded buffering.
                    drop(tx.send(conn).await);
                }
                Ok(Err(err)) => tracing::debug!(error = %err, "inbound connection rejected"),
                Err(_) => tracing::debug!("inbound Noise handshake timed out"),
            }
        });
    }
}

/// One authenticated QUIC connection, direct or relayed.
pub struct IrohConnection {
    conn: Connection,
    config: Arc<IrohConfig>,
    peer: PublicKey,
    node_id: PublicKey,
    sas: Sas,
    channel_binding: [u8; 32],
    /// Whether this side dialled. Decides which of `open_bi`/`accept_bi` is
    /// handed the stream the connection handshake ran on.
    dialled: bool,
    /// The control stream (§10.2), already authenticated by the connection
    /// handshake and waiting for the first `open_bi`/`accept_bi`.
    control: Mutex<Option<(SendStream, RecvStream)>>,
    /// Streams the peer opened, with their own handshakes already completed.
    incoming: tokio::sync::Mutex<mpsc::Receiver<(SendStream, RecvStream)>>,
    /// Retained, not just subscribed from: dropping the sender would close every
    /// subscriber's watch.
    path_tx: watch::Sender<PathInfo>,
    _tasks: TaskGuard,
}

impl IrohConnection {
    /// Runs the connection-level Noise handshake and starts the background tasks.
    ///
    /// `expected` is `Some` when we dialled, and carries the Noise static key the
    /// pairing ticket promised. The stream this handshake runs on becomes the
    /// control stream rather than being discarded, so a fresh connection costs one
    /// QUIC handshake and one Noise handshake and no more.
    async fn establish(
        conn: Connection,
        expected: Option<PeerId>,
        config: Arc<IrohConfig>,
    ) -> Result<Self> {
        conn.set_max_concurrent_bi_streams(config.max_concurrent_streams.into());

        let node_id = PublicKey::from_bytes(*conn.remote_id().as_bytes());
        let psk = config.psk.clone();

        // Whoever dialled the connection also opens the stream the connection
        // handshake runs on, and is therefore the Noise initiator — the side that
        // must already know the peer's static key, which is exactly what the
        // pairing QR gave it.
        let (authenticated, id, send, recv) = if let Some(peer) = &expected {
            let (send, recv) = conn
                .open_bi()
                .await
                .map_err(|_| TransportError::ConnectionLost)?;
            let id = StreamId::from(send.id());
            let mut duplex = tokio::io::join(recv, send);
            let authenticated = handshake::initiate(
                &mut duplex,
                &config.identity,
                peer.noise_key(),
                config.purpose,
                psk.as_deref(),
            )
            .await?;
            let (recv, send) = duplex.into_inner();
            (authenticated, id, send, recv)
        } else {
            let (send, recv) = conn
                .accept_bi()
                .await
                .map_err(|_| TransportError::ConnectionLost)?;
            let id = StreamId::from(send.id());
            let mut duplex = tokio::io::join(recv, send);
            let authenticated = handshake::respond(
                &mut duplex,
                &config.identity,
                config.purpose,
                psk.as_deref(),
                config.policy.as_ref(),
            )
            .await?;
            let (recv, send) = duplex.into_inner();
            (authenticated, id, send, recv)
        };

        let Authenticated {
            handshake,
            peer,
            rtt,
        } = authenticated;
        let sas = handshake.sas().map_err(from_session)?;
        let session: Session = handshake.into_session().map_err(from_session)?;
        let channel_binding = *session.channel_binding();
        let control = split_stream(id, send, recv, session, config.max_frame_len);

        let mut info = path_info(&conn);
        if let Some(rtt) = rtt {
            info = info.with_rtt_ms(u32::try_from(rtt.as_millis()).unwrap_or(u32::MAX));
        }
        let (path_tx, _) = watch::channel(info);

        let (stream_tx, stream_rx) = mpsc::channel(DEFAULT_STREAM_QUEUE);
        let tasks = vec![
            tokio::spawn(watch_paths(conn.clone(), path_tx.clone())),
            tokio::spawn(accept_streams(
                conn.clone(),
                Arc::clone(&config),
                peer,
                stream_tx,
            )),
        ];

        Ok(Self {
            conn,
            config,
            peer,
            node_id,
            sas,
            channel_binding,
            dialled: expected.is_some(),
            control: Mutex::new(Some(control)),
            incoming: tokio::sync::Mutex::new(stream_rx),
            path_tx,
            _tasks: TaskGuard(tasks),
        })
    }

    /// The peer's authenticated X25519 Noise static key — its device credential.
    #[must_use]
    pub const fn peer_key(&self) -> PublicKey {
        self.peer
    }

    /// The peer's `NodeId`, authenticated by QUIC's TLS handshake.
    ///
    /// Distinct from [`IrohConnection::peer_key`]: this one is the transport
    /// address, that one is the credential the paired-device table is keyed on.
    #[must_use]
    pub const fn peer_node_id(&self) -> PublicKey {
        self.node_id
    }

    /// The six digits both ends display during pairing (§9.2).
    ///
    /// Derived from the full Noise transcript, so a man-in-the-middle proxying the
    /// connection produces different digits on each side and the human comparing
    /// them sees it.
    #[must_use]
    pub const fn sas(&self) -> &Sas {
        &self.sas
    }

    /// The handshake hash, usable as a channel binding.
    ///
    /// A presence signature bound to this value cannot be replayed into another
    /// connection (§3.10).
    #[must_use]
    pub const fn channel_binding(&self) -> &[u8; 32] {
        &self.channel_binding
    }

    /// Takes the control stream if this side is the one that should get it.
    fn take_control(&self, dialling_side: bool) -> Option<(SendStream, RecvStream)> {
        if self.dialled != dialling_side {
            return None;
        }
        self.control
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    /// Opens a bidirectional stream and runs a Noise handshake on it.
    ///
    /// The first call on the dialling side returns the control stream (§10.2),
    /// which the connection handshake already authenticated.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ConnectionLost`] when the connection is gone,
    /// [`TransportError::Timeout`] when the peer accepts the stream but does not
    /// complete its handshake, or a handshake error.
    pub async fn open_stream(&self) -> Result<(SendStream, RecvStream)> {
        if let Some(control) = self.take_control(true) {
            return Ok(control);
        }
        let (send, recv) = self
            .conn
            .open_bi()
            .await
            .map_err(|_| TransportError::ConnectionLost)?;
        let id = StreamId::from(send.id());
        let mut duplex = tokio::io::join(recv, send);
        let psk = self.config.psk.clone();
        let run = handshake::initiate(
            &mut duplex,
            &self.config.identity,
            &self.peer,
            self.config.purpose,
            psk.as_deref(),
        );
        let authenticated = match tokio::time::timeout(self.config.handshake_timeout, run).await {
            Ok(result) => result?,
            Err(_) => return Err(TransportError::Timeout),
        };
        let (recv, send) = duplex.into_inner();
        let session = authenticated
            .handshake
            .into_session()
            .map_err(from_session)?;
        Ok(split_stream(
            id,
            send,
            recv,
            session,
            self.config.max_frame_len,
        ))
    }

    /// Waits for the peer to open a bidirectional stream.
    ///
    /// The first call on the accepting side returns the control stream. Later
    /// calls take streams whose Noise handshake a background task already
    /// completed — which is what keeps the peer's `open_stream` from waiting on
    /// *this* application getting round to calling `accept_bi`.
    ///
    /// # Errors
    ///
    /// Returns the connection's close reason once the link is gone.
    pub async fn accept_stream(&self) -> Result<(SendStream, RecvStream)> {
        if let Some(control) = self.take_control(false) {
            return Ok(control);
        }
        let mut rx = self.incoming.lock().await;
        rx.recv().await.ok_or(TransportError::Closed)
    }

    /// What is currently known about the network path.
    #[must_use]
    pub fn path_info(&self) -> PathInfo {
        *self.path_tx.borrow()
    }

    /// Watches the path for change.
    ///
    /// Fires on QUIC connection migration and on a relay→direct upgrade, which is
    /// the §4.4 property Tier 0 structurally cannot offer. The receiver starts at
    /// the current path rather than empty, so a late subscriber still learns the
    /// tier without waiting for a change that may never come.
    #[must_use]
    pub fn path_changes(&self) -> watch::Receiver<PathInfo> {
        self.path_tx.subscribe()
    }

    /// Whether the connection has ended.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.conn.close_reason().is_some()
    }

    /// Closes the connection and every stream on it.
    pub fn close(&self) {
        self.conn.close(0u8.into(), b"");
    }
}

impl core::fmt::Debug for IrohConnection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IrohConnection")
            .field("peer", &self.peer.short())
            .field("node_id", &self.node_id.short())
            .field("path", &self.path_info())
            .field("closed", &self.is_closed())
            .finish_non_exhaustive()
    }
}

impl Conn for IrohConnection {
    fn open_bi(&self) -> BoxFuture<'_, Result<(SendStream, RecvStream)>> {
        Box::pin(self.open_stream())
    }

    fn accept_bi(&self) -> BoxFuture<'_, Result<(SendStream, RecvStream)>> {
        Box::pin(self.accept_stream())
    }

    fn path_info(&self) -> PathInfo {
        *self.path_tx.borrow()
    }

    fn path_changes(&self) -> watch::Receiver<PathInfo> {
        self.path_tx.subscribe()
    }

    fn peer_key(&self) -> PublicKey {
        self.peer
    }

    fn close(&self) {
        self.conn.close(0u8.into(), b"");
    }
}

/// Pairs a QUIC stream with the session that seals it.
fn split_stream(
    id: StreamId,
    send: QuicSendHalf,
    recv: iroh::endpoint::RecvStream,
    session: Session,
    max_frame_len: usize,
) -> (SendStream, RecvStream) {
    let crypto = Arc::new(StreamCrypto::new(session));
    (
        SendStream::from_quic(QuicSend::new(id, send, Arc::clone(&crypto), max_frame_len)),
        RecvStream::from_quic(QuicRecv::new(id, recv, crypto, max_frame_len)),
    )
}

/// Runs the responder half of each stream's Noise handshake, off the caller's
/// path.
///
/// Doing this in a background task rather than inside `accept_stream` is what
/// makes a peer's `open_stream` complete on its own schedule. If the handshake
/// only ran when the application asked for a stream, an application that is busy
/// would look — to the peer — exactly like one that had hung.
async fn accept_streams(
    conn: Connection,
    config: Arc<IrohConfig>,
    peer: PublicKey,
    tx: mpsc::Sender<(SendStream, RecvStream)>,
) {
    loop {
        let Ok((send, recv)) = conn.accept_bi().await else {
            return;
        };
        if tx.is_closed() {
            return;
        }
        let id = StreamId::from(send.id());
        let config = Arc::clone(&config);
        let tx = tx.clone();
        tokio::spawn(async move {
            let mut duplex = tokio::io::join(recv, send);
            let psk = config.psk.clone();
            // The stream is authorised against the *connection's* authenticated
            // key, not the paired-device list. Stricter, and the right question: a
            // second paired device must not be able to graft a stream onto this
            // connection.
            let policy = crate::traits::Allowlist::new(vec![peer]);
            let run = handshake::respond(
                &mut duplex,
                &config.identity,
                config.purpose,
                psk.as_deref(),
                &policy,
            );
            let authenticated = match tokio::time::timeout(config.handshake_timeout, run).await {
                Ok(Ok(authenticated)) => authenticated,
                Ok(Err(err)) => {
                    tracing::debug!(error = %err, stream = id, "stream handshake failed");
                    return;
                }
                Err(_) => {
                    tracing::debug!(stream = id, "stream handshake timed out");
                    return;
                }
            };
            let (recv, send) = duplex.into_inner();
            let Ok(session) = authenticated.handshake.into_session() else {
                return;
            };
            let pair = split_stream(id, send, recv, session, config.max_frame_len);
            drop(tx.send(pair).await);
        });
    }
}

/// Republishes [`PathInfo`] whenever iroh's set of paths changes.
///
/// This is the task that makes [`Conn::path_changes`] fire, and the one thing the
/// TCP binding structurally cannot do (§4.4): a relayed connection that later
/// hole-punches its way to a direct path emits [`PathEvent::Selected`] with an IP
/// address, and the UI's connection chip flips from "Relay" to "Direct" with no
/// reconnect, no session loss, and nothing for the application to do.
async fn watch_paths(conn: Connection, path_tx: watch::Sender<PathInfo>) {
    let mut events = conn.path_events();
    while let Some(event) = events.next().await {
        // Recomputed from the connection rather than from the event, for two
        // reasons: `Lagged` carries no address at all, and `Opened` for a relay
        // path while a direct path is already selected must not downgrade the
        // reported tier.
        let next = path_info(&conn);
        let updated = path_tx.send_if_modified(|current| {
            if *current == next {
                false
            } else {
                *current = next;
                true
            }
        });
        if updated {
            tracing::debug!(
                tier = next.tier.label(),
                relayed = next.relayed,
                rtt_ms = ?next.rtt_ms,
                ?event,
                "network path changed"
            );
        }
    }
    // The event stream ends when the connection closes. Subscribers keep their
    // last value, which is the honest final state.
}

/// Reads the live tier, relay status and RTT off a connection.
fn path_info(conn: &Connection) -> PathInfo {
    let paths = conn.paths();
    // The *selected* path is the one carrying application data, so it is the only
    // one that answers "am I being relayed right now?". A connection commonly
    // holds a relay path open alongside a direct one, and reporting on the
    // presence of a relay path rather than on its selection would leave the UI
    // permanently claiming Relay.
    let selected = paths
        .iter()
        .find(iroh::endpoint::Path::is_selected)
        .or_else(|| paths.iter().next());

    let Some(path) = selected else {
        // No path yet. Pessimistic rather than optimistic: over-claiming Direct is
        // the failure mode §4.2 warns about.
        return PathInfo {
            tier: Tier::Relay,
            rtt_ms: None,
            relayed: true,
        };
    };

    let (tier, relayed) = tier_for(path.remote_addr());
    let rtt_ms = u32::try_from(path.rtt().as_millis()).ok();
    PathInfo {
        tier,
        rtt_ms,
        relayed,
    }
}

/// Maps one of iroh's transport addresses onto a rung of the ladder.
///
/// The mapping is deliberately conservative in one direction only. An IP path is
/// [`Tier::Direct`] — packets are going peer to peer, which is what Tier 1 means.
/// Anything else, including a transport this build does not recognise, is reported
/// as [`Tier::Relay`], because the cost of wrongly claiming Direct is a user who
/// believes a slow session is unavoidable, while the cost of wrongly claiming
/// Relay is a pessimistic chip on a fast connection.
///
/// Note that a direct path to a machine on the same Wi-Fi is still reported as
/// `Direct`, not [`Tier::Lan`]: on this rung the path was established by hole
/// punching whether or not it happens to stay on the subnet, and `Tier::Lan` means
/// "Tier 0, no NAT traversal involved", which is [`crate::TcpTransport`]'s claim to
/// make.
fn tier_for(addr: &TransportAddr) -> (Tier, bool) {
    if addr.is_ip() {
        (Tier::Direct, false)
    } else {
        (Tier::Relay, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> Arc<DeviceIdentity> {
        Arc::new(DeviceIdentity::generate())
    }

    #[test]
    fn pairing_without_a_secret_is_refused() {
        // Otherwise the pairing pattern would run with nothing proving the peer
        // ever saw the QR, which is the whole point of the pre-shared key.
        let mut config = IrohConfig::pairing(identity(), &PairingSecret::generate());
        config.psk = None;
        assert!(matches!(config.validate(), Err(TransportError::Config(_))));
    }

    #[test]
    fn a_reconnect_carrying_a_secret_is_refused() {
        let mut config = IrohConfig::reconnect(identity(), Arc::new(AllowAny));
        config.psk = Some(Zeroizing::new([0u8; 32]));
        assert!(matches!(config.validate(), Err(TransportError::Config(_))));
    }

    #[test]
    fn the_default_configurations_are_valid() {
        let secret = PairingSecret::generate();
        IrohConfig::reconnect(identity(), Arc::new(AllowAny))
            .validate()
            .expect("reconnect");
        IrohConfig::pairing(identity(), &secret)
            .validate()
            .expect("pairing");
        IrohConfig::dialer(identity()).validate().expect("dialer");
        IrohConfig::pairing_dialer(identity(), &secret)
            .validate()
            .expect("pairing dialer");
    }

    #[test]
    fn the_default_frame_cap_is_the_protocols_own_maximum() {
        // R25: the mux's 256 KiB cap does not survive onto QUIC.
        let config = IrohConfig::reconnect(identity(), Arc::new(AllowAny));
        assert_eq!(config.max_frame_len, gonomad_proto::frame::MAX_PAYLOAD_LEN);
        assert!(config.max_frame_len > crate::MuxConfig::default().max_frame_len);
    }

    #[test]
    fn absurd_limits_are_refused() {
        let base = IrohConfig::reconnect(identity(), Arc::new(AllowAny));
        let too_big = IrohConfig {
            max_frame_len: gonomad_proto::frame::MAX_PAYLOAD_LEN + 1,
            ..IrohConfig::reconnect(identity(), Arc::new(AllowAny))
        };
        assert!(too_big.validate().is_err());
        assert!(IrohConfig {
            max_concurrent_streams: 0,
            ..base
        }
        .validate()
        .is_err());
    }

    #[test]
    fn debug_never_prints_the_pre_shared_key() {
        let secret = PairingSecret::generate();
        let hex = hex_of(secret.as_bytes());
        let config = IrohConfig::pairing(identity(), &secret);
        let rendered = format!("{config:?}");
        assert!(!rendered.contains(&hex));
        assert!(rendered.contains("redacted"));
    }

    fn hex_of(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
    }

    #[test]
    fn an_ip_path_is_direct_and_a_relay_path_is_relayed() {
        // The honest mapping, asserted without a network: this is the function the
        // UI's connection chip depends on (§23), and getting it backwards would
        // tell a user a relayed session was direct.
        let ip = TransportAddr::Ip("192.0.2.1:41234".parse().expect("literal"));
        assert_eq!(tier_for(&ip), (Tier::Direct, false));

        let relay = TransportAddr::Relay(
            "https://relay.example.com"
                .parse()
                .expect("literal relay url"),
        );
        assert_eq!(tier_for(&relay), (Tier::Relay, true));

        // Anything else — including a custom transport a future iroh adds — takes
        // the relay branch. `TransportAddr` is `#[non_exhaustive]`, so this is
        // asserted through the predicate rather than by naming a third variant.
        assert!(!relay.is_ip());
    }

    #[test]
    fn dialling_without_a_node_id_is_a_distinct_error() {
        // A ticket that predates the node id, or a caller that passed only address
        // hints. "No reachable address" would send someone hunting for a firewall.
        let hints = [
            AddrHint::Direct("192.0.2.1:41234".parse().expect("literal")),
            AddrHint::Relay("https://relay.example.com".into()),
        ];
        assert!(matches!(
            node_addr_from_hints(&hints),
            Err(TransportError::NoNodeId)
        ));
    }

    #[test]
    fn hints_become_a_node_address() {
        let node = identity().iroh_node_id();
        let hints = [
            AddrHint::Node(node),
            AddrHint::Direct("192.0.2.1:41234".parse().expect("literal")),
            AddrHint::Relay("https://relay.example.com".into()),
            // An unparsable relay hint must cost the relay path, not the dial.
            AddrHint::Relay("not a url".into()),
        ];
        let addr = node_addr_from_hints(&hints).expect("node address");
        assert_eq!(addr.id.as_bytes(), node.as_bytes());
        assert_eq!(addr.ip_addrs().count(), 1);
        assert_eq!(addr.relay_urls().count(), 1);
    }

    proptest::proptest! {
        /// A node id arrives from a scanned QR code, so it is 32 bytes chosen by
        /// whatever was on the screen. Building a dial target from it must either
        /// succeed or report [`TransportError::NoNodeId`] — never panic, and never
        /// silently produce something else.
        ///
        /// Note that not every rejection happens here: `ed25519-dalek` accepts some
        /// non-canonical encodings at parse time and fails later, which is why this
        /// asserts the shape of the outcome rather than a specific verdict.
        #[test]
        fn any_node_id_either_dials_or_is_refused(bytes: [u8; 32]) {
            let hints = [AddrHint::Node(PublicKey::from_bytes(bytes))];
            match node_addr_from_hints(&hints) {
                Ok(addr) => proptest::prop_assert_eq!(addr.id.as_bytes(), &bytes),
                Err(err) => proptest::prop_assert_eq!(err, TransportError::NoNodeId),
            }
        }
    }

    #[test]
    fn a_self_hosted_relay_needs_a_parsable_url() {
        assert!(RelayPolicy::SelfHosted(vec![]).to_relay_mode().is_err());
        assert!(RelayPolicy::SelfHosted(vec!["not a url".into()])
            .to_relay_mode()
            .is_err());
        assert!(
            RelayPolicy::SelfHosted(vec!["https://relay.internal".into()])
                .to_relay_mode()
                .is_ok()
        );
        assert_eq!(
            RelayPolicy::Disabled.to_relay_mode().expect("disabled"),
            RelayMode::Disabled
        );
    }

    #[tokio::test]
    async fn a_dial_only_endpoint_cannot_accept() {
        let transport = IrohTransport::bind(IrohConfig {
            relay: RelayPolicy::Disabled,
            address_lookup: false,
            bind_addrs: vec!["127.0.0.1:0".parse().expect("literal")],
            ..IrohConfig::dialer(identity())
        })
        .await
        .expect("bind");
        assert!(matches!(
            transport.accept_iroh().await,
            Err(TransportError::NotListening)
        ));
        transport.close().await;
    }

    #[tokio::test]
    async fn the_endpoint_binds_at_the_node_id_derived_from_the_seed() {
        // The property the recovery phrase depends on: a restored daemon must be
        // reachable at the address its old pairing QRs advertise.
        let identity = identity();
        let expected = identity.iroh_node_id();
        let transport = IrohTransport::bind(IrohConfig {
            relay: RelayPolicy::Disabled,
            address_lookup: false,
            bind_addrs: vec!["127.0.0.1:0".parse().expect("literal")],
            ..IrohConfig::dialer(Arc::clone(&identity))
        })
        .await
        .expect("bind");
        assert_eq!(transport.node_id(), expected);
        assert!(transport
            .bound_sockets()
            .iter()
            .any(|addr| addr.port() != 0));
        transport.close().await;
    }
}
