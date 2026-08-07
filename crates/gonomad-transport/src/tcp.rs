//! Tier 0: LAN direct, over TCP, carrying Noise IK.
//!
//! # Why TCP here, when the ladder says QUIC
//!
//! `ARCHITECTURE.md` §4.2 lists LAN direct as Tier 0 and iroh's QUIC as the
//! default for Tiers 1 and 2. This module is the first rung only: it gets a
//! phone and a daemon on the same Wi-Fi talking, authenticated and encrypted,
//! with no NAT traversal problem to solve. It is **kept** now that
//! [`crate::iroh`] has landed, because on a LAN it is genuinely faster — one
//! `connect`, no hole punching, no discovery, no relay to rule out — and because
//! a second, simpler binding is what keeps the §4.5 abstraction honest.
//!
//! The security properties do **not** differ between the two, and that is the
//! whole reason §3.4 puts Noise inside the transport rather than relying on the
//! transport's own encryption. Both bindings run the same
//! `Noise_IK_25519_ChaChaPoly_BLAKE2s` handshake, from the same code in
//! [`crate::handshake`], over the same `gonomad-core` session layer. A reviewer
//! auditing the handshake audits it once.
//!
//! # Where the interesting parts are documented
//!
//! - The handshake, its `u16` framing, why it is not a [`gonomad_proto::Frame`],
//!   and why a wrong pairing PSK surfaces on the phone rather than the daemon:
//!   [`crate::handshake`].
//! - The channel multiplexer this binding needs and QUIC does not, and the
//!   head-of-line blocking it cannot fix: [`crate::mux`].
//!
//! # After the handshake, nothing is plaintext
//!
//! Every subsequent byte is a Noise-sealed record (see [`crate::mux`]). The only
//! cleartext on the wire post-handshake is the 2-byte record length, which
//! carries no semantics.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use gonomad_core::{DeviceIdentity, PairingSecret, Purpose, Sas, Session};
use gonomad_proto::PublicKey;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, Semaphore};
use zeroize::Zeroizing;

use crate::error::{from_session, Result, TransportError};
use crate::handshake::{self, Authenticated};
use crate::mux::{Mux, MuxConfig, Role, TaskGuard};
use crate::stream::{RecvStream, SendStream};
use crate::traits::{AddrHint, AllowAny, BoxFuture, Conn, PathInfo, PeerId, PeerPolicy, Transport};

/// The daemon's default listening port.
///
/// In the ephemeral-adjacent range and not a port anything common squats on. It
/// is only a default: the port that matters is the one in the pairing QR's
/// address hints (§4.6).
pub const DEFAULT_PORT: u16 = 41234;

/// How long a peer has to complete its handshake before being dropped.
///
/// Bounds the pre-authentication resource commitment (§3.8): without it, a
/// connection that opens a socket and sends nothing costs a task and a buffer
/// forever, and a few thousand of them cost the daemon.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait for a TCP connection to one address hint.
///
/// Short, because hints are tried in order and a stale hint should cost a
/// perceptible pause rather than the OS's default multi-second SYN retry.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Concurrent in-progress handshakes the listener will run.
const DEFAULT_MAX_PENDING_HANDSHAKES: usize = 32;

/// Completed connections buffered before the acceptor stops taking new ones.
const DEFAULT_ACCEPT_QUEUE: usize = 16;

/// How long the acceptor pauses after an `accept` failure.
///
/// Errors here are usually resource exhaustion (EMFILE). Retrying in a tight
/// loop would spin a core while the daemon is already under pressure.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

/// How the daemon answers inbound connections.
pub struct ServerConfig {
    /// The daemon's identity. Its X25519 subkey is the Noise static.
    pub identity: Arc<DeviceIdentity>,
    /// Which Noise pattern to run. [`Purpose::Pairing`] only while a pairing
    /// window is open.
    pub purpose: Purpose,
    /// The pairing pre-shared key, required when `purpose` is
    /// [`Purpose::Pairing`] and forbidden otherwise.
    pub psk: Option<Zeroizing<[u8; 32]>>,
    /// Decides whether an authenticated key may proceed.
    pub policy: Arc<dyn PeerPolicy>,
    /// Multiplexer tuning.
    pub mux: MuxConfig,
    /// Per-connection handshake deadline.
    pub handshake_timeout: Duration,
    /// Concurrent in-progress handshakes.
    pub max_pending_handshakes: usize,
    /// Completed connections buffered for [`Transport::accept`].
    pub accept_queue: usize,
}

impl ServerConfig {
    /// Accepts reconnects from already-paired devices.
    #[must_use]
    pub fn reconnect(identity: Arc<DeviceIdentity>, policy: Arc<dyn PeerPolicy>) -> Self {
        Self {
            identity,
            purpose: Purpose::Reconnect,
            psk: None,
            policy,
            mux: MuxConfig::default(),
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            max_pending_handshakes: DEFAULT_MAX_PENDING_HANDSHAKES,
            accept_queue: DEFAULT_ACCEPT_QUEUE,
        }
    }

    /// Accepts a first-time pairing, authenticated by the QR's secret.
    ///
    /// The policy is [`AllowAny`] because the peer's key is *by definition* not
    /// yet known — proving it saw the screen is the pre-shared key's job (§9.2).
    /// The caller is responsible for tearing this listener down when the
    /// 120-second window closes.
    #[must_use]
    pub fn pairing(identity: Arc<DeviceIdentity>, secret: &PairingSecret) -> Self {
        Self {
            identity,
            purpose: Purpose::Pairing,
            psk: Some(Zeroizing::new(*secret.as_bytes())),
            policy: Arc::new(AllowAny),
            mux: MuxConfig::default(),
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            max_pending_handshakes: DEFAULT_MAX_PENDING_HANDSHAKES,
            accept_queue: DEFAULT_ACCEPT_QUEUE,
        }
    }

    /// Checks that the purpose and the pre-shared key agree.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Config`] when pairing has no secret, or when a
    /// reconnect carries one. Both are silent security failures otherwise: the
    /// first would run the pairing pattern with no proof of physical access, and
    /// the second signals that a caller has confused the two flows.
    pub fn validate(&self) -> Result<()> {
        match (self.purpose, self.psk.is_some()) {
            (Purpose::Pairing, false) => Err(TransportError::Config(
                "Purpose::Pairing requires the pairing secret as a pre-shared key",
            )),
            (Purpose::Reconnect, true) => Err(TransportError::Config(
                "Purpose::Reconnect must not carry a pre-shared key",
            )),
            _ => self.mux.validate(),
        }
    }

    /// The matching dialling configuration, for a daemon that also dials.
    fn to_client(&self) -> ClientConfig {
        ClientConfig {
            identity: Arc::clone(&self.identity),
            purpose: self.purpose,
            psk: self.psk.clone(),
            mux: self.mux,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            handshake_timeout: self.handshake_timeout,
        }
    }
}

// Never prints the pre-shared key. A PSK in a log is a pairing an attacker can
// complete, and the 120-second window is no comfort if the log is read later.
impl core::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("device_id", &self.identity.device_id())
            .field("purpose", &self.purpose)
            .field("psk", &self.psk.as_ref().map(|_| "<redacted>"))
            .field("mux", &self.mux)
            .finish_non_exhaustive()
    }
}

/// How a client dials.
#[derive(Clone)]
pub struct ClientConfig {
    /// This device's identity. Its X25519 subkey is the Noise static.
    pub identity: Arc<DeviceIdentity>,
    /// Which Noise pattern to run.
    pub purpose: Purpose,
    /// The pairing pre-shared key, scanned from the QR.
    pub psk: Option<Zeroizing<[u8; 32]>>,
    /// Multiplexer tuning. Must match the peer's window, or flow control
    /// disagrees and one side tears the connection down.
    pub mux: MuxConfig,
    /// Per-address TCP connect deadline.
    pub connect_timeout: Duration,
    /// Handshake deadline once a socket is open.
    pub handshake_timeout: Duration,
}

impl ClientConfig {
    /// Dials as an already-paired device.
    #[must_use]
    pub fn reconnect(identity: Arc<DeviceIdentity>) -> Self {
        Self {
            identity,
            purpose: Purpose::Reconnect,
            psk: None,
            mux: MuxConfig::default(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
        }
    }

    /// Dials to complete a first-time pairing.
    #[must_use]
    pub fn pairing(identity: Arc<DeviceIdentity>, secret: &PairingSecret) -> Self {
        Self {
            identity,
            purpose: Purpose::Pairing,
            psk: Some(Zeroizing::new(*secret.as_bytes())),
            mux: MuxConfig::default(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
        }
    }

    /// Checks that the purpose and the pre-shared key agree.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Config`] on the same mismatches as
    /// [`ServerConfig::validate`].
    pub fn validate(&self) -> Result<()> {
        match (self.purpose, self.psk.is_some()) {
            (Purpose::Pairing, false) => Err(TransportError::Config(
                "Purpose::Pairing requires the pairing secret as a pre-shared key",
            )),
            (Purpose::Reconnect, true) => Err(TransportError::Config(
                "Purpose::Reconnect must not carry a pre-shared key",
            )),
            _ => self.mux.validate(),
        }
    }
}

impl core::fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClientConfig")
            .field("device_id", &self.identity.device_id())
            .field("purpose", &self.purpose)
            .field("psk", &self.psk.as_ref().map(|_| "<redacted>"))
            .finish_non_exhaustive()
    }
}

/// One authenticated LAN connection.
pub struct TcpConnection {
    mux: Mux,
    peer: PublicKey,
    remote_addr: SocketAddr,
    sas: Sas,
    channel_binding: [u8; 32],
    // Retained, not just subscribed from: dropping the sender would close every
    // subscriber's watch. It is also where iroh's path-change events will be
    // published once a path can actually change.
    path_tx: watch::Sender<PathInfo>,
}

impl TcpConnection {
    /// The peer's authenticated X25519 Noise static key.
    #[must_use]
    pub const fn peer_key(&self) -> PublicKey {
        self.peer
    }

    /// The address the peer was reached at.
    #[must_use]
    pub const fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// The six digits both ends display during pairing (§9.2).
    ///
    /// Derived from the full handshake transcript, so a man-in-the-middle
    /// proxying the connection produces different digits on each side and the
    /// human comparing them sees it.
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

    /// Opens a bidirectional stream. The first one is the control stream (§10.2).
    ///
    /// # Errors
    ///
    /// Fails once the connection is closed or the channel limit is reached.
    pub fn open_bi(&self) -> Result<(SendStream, RecvStream)> {
        self.mux.open_bi()
    }

    /// Waits for the peer to open a bidirectional stream.
    ///
    /// # Errors
    ///
    /// Returns the connection's close reason once the link is gone.
    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream)> {
        self.mux.accept_bi().await
    }

    /// What is known about the path.
    #[must_use]
    pub fn path_info(&self) -> PathInfo {
        *self.path_tx.borrow()
    }

    /// Whether the connection has ended.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.mux.is_closed()
    }

    /// Closes the connection and every stream on it.
    pub fn close(&self) {
        self.mux.close();
    }
}

impl core::fmt::Debug for TcpConnection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TcpConnection")
            .field("peer", &self.peer.short())
            .field("remote_addr", &self.remote_addr)
            .field("closed", &self.is_closed())
            .finish_non_exhaustive()
    }
}

// Each method reaches into the fields directly rather than calling the
// identically named inherent method: `Self::open_bi(self)` inside a trait impl
// resolves by inherent-first lookup today, but that is a subtle rule to leave a
// future reader (or a future refactor) to rediscover.
impl Conn for TcpConnection {
    fn open_bi(&self) -> BoxFuture<'_, Result<(SendStream, RecvStream)>> {
        let mux = &self.mux;
        Box::pin(async move { mux.open_bi() })
    }

    fn accept_bi(&self) -> BoxFuture<'_, Result<(SendStream, RecvStream)>> {
        Box::pin(self.mux.accept_bi())
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
        self.mux.close();
    }
}

/// A bound listener plus the machinery that feeds it.
struct Listening {
    local_addr: SocketAddr,
    incoming: tokio::sync::Mutex<mpsc::Receiver<TcpConnection>>,
    _acceptor: TaskGuard,
}

/// Tier 0 of the transport ladder.
///
/// Can listen, dial, or both. The daemon binds; the phone dials.
pub struct TcpTransport {
    dialer: Arc<ClientConfig>,
    listening: Option<Listening>,
}

impl TcpTransport {
    /// Creates a dial-only transport, for a client that never listens.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Config`] when the configuration is inconsistent.
    pub fn client(config: ClientConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            dialer: Arc::new(config),
            listening: None,
        })
    }

    /// Binds a listener and starts accepting.
    ///
    /// Handshakes run concurrently in their own tasks, bounded by
    /// [`ServerConfig::max_pending_handshakes`]. Running them inline on the
    /// accept loop would let one silent peer stall every other device's
    /// reconnect for the whole handshake timeout.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Bind`] when the address is unavailable, or
    /// [`TransportError::Config`] when the configuration is inconsistent.
    pub async fn bind(addr: SocketAddr, config: ServerConfig) -> Result<Self> {
        config.validate()?;
        let dialer = Arc::new(config.to_client());
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|err| TransportError::bind(addr, &err))?;
        let local_addr = listener
            .local_addr()
            .map_err(|err| TransportError::bind(addr, &err))?;

        let (tx, rx) = mpsc::channel(config.accept_queue.max(1));
        let config = Arc::new(config);
        let acceptor = tokio::spawn(accept_loop(listener, config, tx));

        Ok(Self {
            dialer,
            listening: Some(Listening {
                local_addr,
                incoming: tokio::sync::Mutex::new(rx),
                _acceptor: TaskGuard(vec![acceptor]),
            }),
        })
    }

    /// The address actually bound, which resolves a `:0` request to a real port.
    #[must_use]
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.listening.as_ref().map(|l| l.local_addr)
    }

    /// Waits for the next inbound connection that completed its handshake.
    ///
    /// Connections that fail to authenticate never appear here: they are logged
    /// and dropped, because surfacing them would give a caller a way to learn
    /// that an unpaired device tried to connect, which is exactly the
    /// information §3.7 declines to leak on the wire.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotListening`] on a dial-only transport, and
    /// [`TransportError::Closed`] once the acceptor has stopped.
    pub async fn accept_lan(&self) -> Result<TcpConnection> {
        let listening = self
            .listening
            .as_ref()
            .ok_or(TransportError::NotListening)?;
        let mut rx = listening.incoming.lock().await;
        rx.recv().await.ok_or(TransportError::Closed)
    }

    /// Dials `peer`, trying each direct hint in turn.
    ///
    /// Hints are tried **sequentially**, not raced. §4.2 says tiers are attempted
    /// concurrently, and they will be — by the ladder above this crate, once
    /// there is more than one rung. Within Tier 0 the hint list is short (the
    /// daemon's own LAN addresses) and a failing hint on a LAN fails in
    /// milliseconds, so racing would add machinery for no measurable gain.
    ///
    /// Relay hints are skipped: Tier 0 has no relay. iroh consumes them at
    /// Tier 2.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NoReachableAddress`] when no direct hint could
    /// be reached, or the last handshake failure when one answered but did not
    /// authenticate.
    pub async fn connect_lan(&self, peer: PeerId, hints: &[AddrHint]) -> Result<TcpConnection> {
        let mut last: Option<TransportError> = None;
        for addr in hints.iter().filter_map(AddrHint::socket_addr) {
            match dial(addr, peer, &self.dialer).await {
                Ok(conn) => return Ok(conn),
                Err(err) => {
                    tracing::debug!(%addr, error = %err, "LAN dial failed");
                    last = Some(err);
                }
            }
        }
        Err(last.unwrap_or(TransportError::NoReachableAddress))
    }
}

impl core::fmt::Debug for TcpTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TcpTransport")
            .field("local_addr", &self.local_addr())
            .finish_non_exhaustive()
    }
}

impl Transport for TcpTransport {
    fn connect<'a>(
        &'a self,
        peer: PeerId,
        hints: &'a [AddrHint],
    ) -> BoxFuture<'a, Result<Box<dyn Conn>>> {
        Box::pin(async move {
            let conn = self.connect_lan(peer, hints).await?;
            Ok(Box::new(conn) as Box<dyn Conn>)
        })
    }

    fn accept(&self) -> BoxFuture<'_, Result<Box<dyn Conn>>> {
        Box::pin(async move {
            let conn = self.accept_lan().await?;
            Ok(Box::new(conn) as Box<dyn Conn>)
        })
    }

    fn path_info(&self) -> PathInfo {
        PathInfo::lan()
    }
}

/// Accepts sockets and spawns a bounded number of concurrent handshakes.
async fn accept_loop(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    tx: mpsc::Sender<TcpConnection>,
) {
    let slots = Arc::new(Semaphore::new(config.max_pending_handshakes.max(1)));
    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                tracing::warn!(error = ?err.kind(), "accept failed");
                tokio::time::sleep(ACCEPT_BACKOFF).await;
                continue;
            }
        };
        let Ok(slot) = Arc::clone(&slots).acquire_owned().await else {
            return;
        };
        if tx.is_closed() {
            return;
        }
        let config = Arc::clone(&config);
        let tx = tx.clone();
        tokio::spawn(async move {
            let _slot = slot;
            match tokio::time::timeout(config.handshake_timeout, greet(stream, addr, &config)).await
            {
                Ok(Ok(conn)) => {
                    // A full queue means the daemon is not accepting fast
                    // enough; dropping is better than unbounded buffering.
                    drop(tx.send(conn).await);
                }
                Ok(Err(err)) => {
                    tracing::debug!(%addr, error = %err, "inbound connection rejected");
                }
                Err(_) => {
                    tracing::debug!(%addr, "inbound handshake timed out");
                }
            }
        });
    }
}

/// Runs the responder side of the handshake and builds the connection.
async fn greet(
    mut stream: TcpStream,
    addr: SocketAddr,
    config: &ServerConfig,
) -> Result<TcpConnection> {
    disable_nagle(&stream);

    // Cloned rather than copied out, so the key stays inside a wiping buffer.
    let psk = config.psk.clone();
    let authenticated = handshake::respond(
        &mut stream,
        &config.identity,
        config.purpose,
        psk.as_deref(),
        config.policy.as_ref(),
    )
    .await?;

    finish(stream, addr, authenticated, Role::Responder, config.mux)
}

/// Runs the initiator side of the handshake against one address.
async fn dial(addr: SocketAddr, peer: PeerId, config: &ClientConfig) -> Result<TcpConnection> {
    let connect = tokio::time::timeout(config.connect_timeout, TcpStream::connect(addr));
    let mut stream = match connect.await {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => return Err(TransportError::connect(addr, &err)),
        Err(_) => return Err(TransportError::Timeout),
    };
    disable_nagle(&stream);

    let psk = config.psk.clone();
    let run = handshake::initiate(
        &mut stream,
        &config.identity,
        peer.noise_key(),
        config.purpose,
        psk.as_deref(),
    );
    let authenticated = match tokio::time::timeout(config.handshake_timeout, run).await {
        Ok(result) => result?,
        Err(_) => return Err(TransportError::Timeout),
    };

    finish(stream, addr, authenticated, Role::Initiator, config.mux)
}

/// Turns off Nagle's algorithm, tolerating a platform that refuses.
///
/// Nagle batches small writes, which is precisely wrong for a keystroke
/// protocol: it trades tens of milliseconds of latency for bytes we do not need
/// to save (§14.1). A platform that will not honour the request is a latency
/// problem, not a correctness one, so it is logged rather than fatal.
fn disable_nagle(stream: &TcpStream) {
    if let Err(err) = stream.set_nodelay(true) {
        tracing::debug!(error = ?err.kind(), "could not disable Nagle");
    }
}

/// Turns a completed handshake into a running connection.
fn finish(
    stream: TcpStream,
    addr: SocketAddr,
    authenticated: Authenticated,
    role: Role,
    mux_cfg: MuxConfig,
) -> Result<TcpConnection> {
    let Authenticated {
        handshake,
        peer,
        rtt,
    } = authenticated;
    let sas = handshake.sas().map_err(from_session)?;
    let session: Session = handshake.into_session().map_err(from_session)?;
    let channel_binding = *session.channel_binding();

    let (read, write) = stream.into_split();
    let mux = Mux::spawn(read, write, session, role, mux_cfg)?;

    let mut info = PathInfo::lan();
    if let Some(rtt) = rtt {
        info = info.with_rtt_ms(u32::try_from(rtt.as_millis()).unwrap_or(u32::MAX));
    }
    let (path_tx, _) = watch::channel(info);

    Ok(TcpConnection {
        mux,
        peer,
        remote_addr: addr,
        sas,
        channel_binding,
        path_tx,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::Allowlist;

    fn identity() -> Arc<DeviceIdentity> {
        Arc::new(DeviceIdentity::generate())
    }

    #[test]
    fn pairing_without_a_secret_is_refused() {
        // Otherwise the pairing pattern would run with nothing proving the peer
        // ever saw the QR, which is the whole point of the pre-shared key.
        let mut config = ClientConfig::pairing(identity(), &PairingSecret::generate());
        config.psk = None;
        assert!(matches!(config.validate(), Err(TransportError::Config(_))));
    }

    #[test]
    fn a_reconnect_carrying_a_secret_is_refused() {
        let mut config = ClientConfig::reconnect(identity());
        config.psk = Some(Zeroizing::new([0u8; 32]));
        assert!(matches!(config.validate(), Err(TransportError::Config(_))));
    }

    #[test]
    fn valid_configurations_pass() {
        ClientConfig::reconnect(identity())
            .validate()
            .expect("client");
        ClientConfig::pairing(identity(), &PairingSecret::generate())
            .validate()
            .expect("pairing client");
        ServerConfig::reconnect(identity(), Arc::new(Allowlist::default()))
            .validate()
            .expect("server");
        ServerConfig::pairing(identity(), &PairingSecret::generate())
            .validate()
            .expect("pairing server");
    }

    #[test]
    fn debug_never_prints_the_pre_shared_key() {
        let secret = PairingSecret::generate();
        let hex = hex_of(secret.as_bytes());
        let client = ClientConfig::pairing(identity(), &secret);
        let server = ServerConfig::pairing(identity(), &secret);
        assert!(!format!("{client:?}").contains(&hex));
        assert!(!format!("{server:?}").contains(&hex));
        assert!(format!("{client:?}").contains("redacted"));
    }

    fn hex_of(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
    }

    #[tokio::test]
    async fn a_dial_only_transport_cannot_accept() {
        let transport =
            TcpTransport::client(ClientConfig::reconnect(identity())).expect("client transport");
        assert_eq!(transport.local_addr(), None);
        assert!(matches!(
            transport.accept_lan().await,
            Err(TransportError::NotListening)
        ));
    }

    #[tokio::test]
    async fn connecting_with_no_direct_hints_reports_no_reachable_address() {
        let transport =
            TcpTransport::client(ClientConfig::reconnect(identity())).expect("client transport");
        let peer = PeerId::from_noise_key(identity().noise_public_key());
        let hints = [AddrHint::Relay("https://relay.example.com".into())];
        assert!(matches!(
            transport.connect_lan(peer, &hints).await,
            Err(TransportError::NoReachableAddress)
        ));
    }

    #[tokio::test]
    async fn binding_to_port_zero_resolves_to_a_real_port() {
        let server = ServerConfig::reconnect(identity(), Arc::new(Allowlist::default()));
        let transport = TcpTransport::bind("127.0.0.1:0".parse().expect("literal"), server)
            .await
            .expect("bind");
        let addr = transport.local_addr().expect("bound");
        assert_ne!(addr.port(), 0);
    }
}
