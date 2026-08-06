//! The client half of the protocol: connect, pair, correlate, and call.
//!
//! Everything Kotlin would otherwise have to implement lives here — the dial
//! sequence, the hello exchange, request/response correlation, timeouts, the
//! pairing state machine, and the terminal poller (`ARCHITECTURE.md` §6.2).
//! [`crate::ffi`] is a translation layer over this module and holds no logic of
//! its own.
//!
//! # Why this type owns a tokio runtime
//!
//! Kotlin cannot drive a Rust executor: there is no way to hand a `Waker` to a
//! coroutine dispatcher and have Rust futures make progress. So the client
//! carries a multi-threaded runtime and every async method dispatches its work
//! onto it with [`tokio::runtime::Runtime::spawn`], returning a `JoinHandle` that
//! the caller (UniFFI's generated poller, or a test) can await from any context.
//!
//! Spawning rather than `block_on` matters for a second reason: every socket and
//! every timer is then created *inside* this runtime, so the reader task, the
//! multiplexer's own tasks, and the terminal poller all share one reactor. A
//! future built on one runtime and polled on another is a class of bug that
//! surfaces as an unexplained hang.
//!
//! # Request correlation
//!
//! Requests carry a monotonic [`CorrelationId`]; a single reader task owns the
//! control stream's receive half and routes each [`Response`] to the oneshot
//! channel registered for its id. Nothing else reads the stream, so responses
//! cannot be consumed by the wrong caller — the failure mode of a design where
//! every request reads until it sees "its" reply.
//!
//! Every request has a deadline. A phone loses its network constantly, and a
//! future that waits forever for a response that will never arrive is
//! indistinguishable, from the UI, from the app being broken.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use gonomad_core::{DeviceIdentity, PairingError, PairingTicket, Sas};
use gonomad_proto::methods::{
    method, DirEntry, Empty, FsListParams, FsListResult, FsReadParams, FsReadResult, PtyIdParams,
    PtyInputParams, PtyListResult, PtyResizeParams, PtySpawnParams, PtySpawnResult, ScreenFrame,
    SysInfoParams, SysInfoResult, SysRegisterParams, SysRegisterResult,
};
use gonomad_proto::{
    ControlMessage, CorrelationId, Frame, FrameFlags, Hello, HelloOk, ProtoError, PublicKey,
    RejectReason, Request, Response, ResponseBody, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION,
};
use gonomad_transport::{
    AddrHint, ClientConfig, MuxConfig, PeerId, RecvStream, SendStream, TcpConnection, TcpTransport,
    Tier, TransportError,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::storage::{now_ms, PairedDaemon, Storage, StorageError};

/// The build string this client reports in [`Hello`].
///
/// Shown on the laptop's devices screen, so it names the app rather than the
/// crate a reader of the log would have to look up.
pub const CLIENT_VERSION: &str = concat!("gonomad-android/", env!("CARGO_PKG_VERSION"));

/// How long a request waits for its response before failing.
///
/// Generous enough for a cold `fs.list` on a spinning disk, short enough that a
/// dead connection surfaces as an error rather than a spinner the user stares at.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// How long the hello exchange may take once the socket is authenticated.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// How often an attached terminal's screen is fetched.
///
/// A stopgap. `pty.output` on the PTY stream (§10.2) is the real mechanism and
/// arrives with M2 alongside the cell-diff renderer; until the daemon can push,
/// polling is the only way for the phone to see output at all. 150 ms is chosen
/// to be under the ~200 ms at which typing stops feeling connected while costing
/// roughly seven small requests per second — which is why the poller runs only
/// while a terminal is actually attached and stops the moment it closes.
pub const SCREEN_POLL_INTERVAL: Duration = Duration::from_millis(150);

/// Columns a terminal is spawned with before the UI has measured itself.
///
/// The FFI contract's `spawnTerminal` takes no geometry, so a default is
/// unavoidable; the UI calls `resizeTerminal` as soon as it has laid out.
pub const DEFAULT_COLS: u16 = 80;

/// Rows a terminal is spawned with. See [`DEFAULT_COLS`].
pub const DEFAULT_ROWS: u16 = 24;

/// Everything that can go wrong in the client.
///
/// Internal, and mapped onto the FFI contract's closed error set by
/// [`crate::ffi`]. Deliberately finer-grained than that set: the mapping can
/// collapse variants, but it cannot invent a distinction it was never given.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    /// No daemon has been paired, so there is nothing to connect to.
    #[error("this device is not paired with a machine")]
    NotPaired,

    /// A call needing a live connection was made without one.
    #[error("there is no live connection")]
    NotConnected,

    /// The daemon refused the hello because this key is not registered.
    #[error("the machine does not recognise this device")]
    Unpaired,

    /// The daemon refused the hello because this device was revoked.
    #[error("this device's access was revoked")]
    Revoked,

    /// The daemon speaks an older protocol than this app.
    #[error("the machine's GoNomad is too old: it speaks at most v{server_max}")]
    DaemonTooOld {
        /// The newest version the daemon understands.
        server_max: u32,
    },

    /// The daemon requires a newer protocol than this app speaks.
    #[error("this app is too old: the machine requires at least v{server_min}")]
    AppTooOld {
        /// The oldest version the daemon accepts.
        server_min: u32,
    },

    /// The daemon is rate-limiting handshakes from this device.
    #[error("too many attempts; retry in {retry_after_ms}ms")]
    RateLimited {
        /// How long to wait before retrying.
        retry_after_ms: u32,
    },

    /// The transport failed.
    #[error(transparent)]
    Transport(#[from] TransportError),

    /// The scanned QR payload was not a usable pairing ticket.
    #[error(transparent)]
    Pairing(#[from] PairingError),

    /// Local state could not be read or written.
    #[error(transparent)]
    Storage(#[from] StorageError),

    /// The daemon answered the request with a protocol error.
    #[error(transparent)]
    Remote(#[from] ProtoError),

    /// A frame could not be encoded or decoded.
    ///
    /// Distinct from [`ClientError::Malformed`]: this is the *framing* layer, and
    /// a framing failure means the byte stream itself is unusable rather than one
    /// message being unreadable.
    #[error(transparent)]
    Framing(#[from] gonomad_proto::FrameError),

    /// The request did not get a response inside its deadline.
    #[error("the request timed out")]
    Timeout,

    /// The connection ended while a request was in flight.
    #[error("the connection was lost")]
    ConnectionLost,

    /// A message from the daemon could not be decoded, or arrived out of order.
    #[error("the machine sent something this app could not read: {detail}")]
    Malformed {
        /// What was wrong, for the log.
        detail: &'static str,
    },

    /// The request would not fit in one frame on this transport.
    ///
    /// See `ARCHITECTURE.md` §19 R25: the mux caps a frame below the protocol's
    /// 32 MiB, and a frame larger than the receive window can never be
    /// reassembled. Refused up front rather than sent and parked on credit the
    /// peer is unable to return.
    #[error("a {len} byte request exceeds this connection's {max} byte frame limit")]
    TooLarge {
        /// The encoded length attempted.
        len: usize,
        /// The per-frame limit.
        max: usize,
    },

    /// [`GonomadClient::confirm_pairing`] was called with no pairing in flight.
    #[error("no pairing is in progress")]
    NoPairingInProgress,

    /// A bug in this crate, not a condition the user can act on.
    #[error("internal error: {0}")]
    Internal(&'static str),
}

/// Where the connection stands.
///
/// Mirrors the FFI contract's `ConnState`; kept as its own type so `client.rs`
/// has no dependency on the UniFFI layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnPhase {
    /// Idle, with a pairing on record.
    Disconnected,
    /// A dial or hello exchange is in progress.
    Connecting,
    /// A control stream is live.
    Connected,
    /// No pairing, or the daemon does not recognise this device.
    Unpaired,
    /// The daemon revoked this device.
    Revoked,
}

/// A snapshot of the connection, cheap enough to hand out on every change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionStatus {
    /// Where the connection stands.
    pub phase: ConnPhase,
    /// The paired machine's name, once known.
    pub daemon_name: Option<String>,
    /// Last measured round-trip time.
    pub rtt_ms: Option<u32>,
    /// Which rung of the transport ladder is carrying the session.
    pub transport: Option<Tier>,
}

impl ConnectionStatus {
    /// The status of a client that has not connected yet.
    fn idle(daemon: Option<&PairedDaemon>) -> Self {
        Self {
            phase: match daemon {
                Some(_) => ConnPhase::Disconnected,
                None => ConnPhase::Unpaired,
            },
            daemon_name: daemon.map(|d| d.name.clone()),
            rtt_ms: None,
            transport: None,
        }
    }
}

/// Receives every connection-state change.
///
/// **One observer at a time**, as the FFI contract states: registering replaces
/// the previous one. A second registration silently starving the first is the
/// bug this constraint exists to make impossible to hide.
pub trait StateObserver: Send + Sync + 'static {
    /// Called after the status changed, never while a lock is held.
    fn on_state(&self, status: ConnectionStatus);
}

/// Receives terminal screens. Single registration, as [`StateObserver`].
pub trait ScreenObserver: Send + Sync + 'static {
    /// Called with a freshly fetched screen.
    fn on_screen(&self, frame: ScreenFrame);
}

/// A response body, as delivered to the request that was waiting for it.
type Reply = Result<Vec<u8>, ProtoError>;

/// Requests awaiting a response, keyed by correlation id.
#[derive(Default)]
struct PendingMap {
    slots: Mutex<HashMap<CorrelationId, oneshot::Sender<Reply>>>,
}

impl PendingMap {
    /// Registers a slot and returns the receiver the caller awaits.
    fn register(&self, id: CorrelationId) -> oneshot::Receiver<Reply> {
        let (tx, rx) = oneshot::channel();
        lock(&self.slots).insert(id, tx);
        rx
    }

    /// Removes a slot, whether it is being answered or abandoned.
    fn take(&self, id: CorrelationId) -> Option<oneshot::Sender<Reply>> {
        lock(&self.slots).remove(&id)
    }

    /// Routes one response to its waiting request.
    fn deliver(&self, response: Response) {
        let id = response.correlation_id;
        let reply = match response.body {
            ResponseBody::Ok { result } => Ok(result),
            ResponseBody::Error { error } => Err(error),
            // Progress is not terminal, so the slot must survive it. Handled by
            // the caller before this point; reaching here means a variant was
            // added and this match was not revisited.
            _ => {
                tracing::debug!(id, "ignoring a non-terminal response body");
                return;
            }
        };
        if let Some(slot) = self.take(id) {
            // A send failure means the caller gave up (timed out, or was
            // cancelled). Not an error: the reply is simply discarded.
            drop(slot.send(reply));
        } else {
            tracing::debug!(id, "response for an unknown correlation id");
        }
    }

    /// Wakes every waiting request, because no response can arrive any more.
    ///
    /// Dropping the senders closes each receiver, which every caller maps to
    /// [`ClientError::ConnectionLost`]. Called explicitly by the reader task
    /// rather than left to this map's destructor: the map is shared with the live
    /// connection, so the reader dropping *its* handle would free nothing and
    /// every in-flight request would sit until its own deadline expired.
    fn abandon_all(&self) {
        let abandoned = std::mem::take(&mut *lock(&self.slots));
        if !abandoned.is_empty() {
            tracing::debug!(
                count = abandoned.len(),
                "the connection ended with requests in flight"
            );
        }
        drop(abandoned);
    }
}

/// One live control stream and the machinery around it.
struct Live {
    /// Owns the multiplexer, so this must outlive every stream taken from it.
    conn: TcpConnection,
    /// The send half. A tokio mutex because `send` parks on flow-control credit,
    /// and holding a `std` guard across that await would block a worker thread.
    tx: Arc<tokio::sync::Mutex<SendStream>>,
    pending: Arc<PendingMap>,
    next_id: AtomicU64,
    /// What the daemon granted for this session.
    hello: HelloOk,
    /// Aborted on drop, so a dropped connection cannot leave a task reading a
    /// socket nobody owns.
    reader: JoinHandle<()>,
}

impl Live {
    /// Spawns the reader task and assembles the connection.
    fn start(conn: TcpConnection, tx: SendStream, rx: RecvStream, hello: HelloOk) -> Self {
        let tx = Arc::new(tokio::sync::Mutex::new(tx));
        let pending = Arc::new(PendingMap::default());
        let reader = tokio::spawn(route_control(rx, Arc::clone(&tx), Arc::clone(&pending)));
        Self {
            conn,
            tx,
            pending,
            next_id: AtomicU64::new(1),
            hello,
            reader,
        }
    }

    /// Sends a request and awaits its terminal response.
    async fn request<P, R>(
        &self,
        method: &str,
        params: &P,
        timeout: Duration,
    ) -> Result<R, ClientError>
    where
        P: Serialize,
        R: DeserializeOwned,
    {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let frame = encode_request(id, method, params)?;

        // Registered *before* the send, so a response that arrives while we are
        // still inside `send` has a slot to land in.
        let waiting = self.pending.register(id);
        if let Err(err) = self.tx.lock().await.send(&frame).await {
            self.pending.take(id);
            return Err(err.into());
        }

        match tokio::time::timeout(timeout, waiting).await {
            Ok(Ok(Ok(result))) => decode_result(&result),
            Ok(Ok(Err(remote))) => Err(ClientError::Remote(remote)),
            // The slot was dropped: the reader task ended, which means the
            // connection is gone.
            Ok(Err(_)) => Err(ClientError::ConnectionLost),
            Err(_) => {
                self.pending.take(id);
                self.cancel(id).await;
                Err(ClientError::Timeout)
            }
        }
    }

    /// Tells the daemon to abandon a request we stopped waiting for.
    ///
    /// Best-effort: the request has already failed locally, and a phone that
    /// navigated away must not be billed for work nobody will read (§11.2).
    async fn cancel(&self, id: CorrelationId) {
        if let Ok(frame) = Frame::cbor(
            FrameFlags::LAST,
            &ControlMessage::Cancel { correlation_id: id },
        ) {
            let sent = self.tx.lock().await.send(&frame).await;
            if let Err(err) = sent {
                tracing::debug!(id, error = %err, "could not cancel a timed-out request");
            }
        }
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        self.reader.abort();
        self.conn.close();
    }
}

/// A pairing that has handshaken but not yet registered.
///
/// Holding the live session here is what makes `ARCHITECTURE.md` §19 R24
/// implementable: `sys.register` must travel over *this* session, because that
/// is the only thing that proves the pairing code was right.
struct Pairing {
    live: Arc<Live>,
    sas: Sas,
    /// The daemon's Noise static key, as authenticated by the handshake rather
    /// than as claimed by the QR.
    peer: PublicKey,
    addr_hints: Vec<String>,
}

/// Shared client state. Held behind an `Arc` so spawned work can outlive a call.
struct Inner {
    identity: Arc<DeviceIdentity>,
    storage: Storage,
    /// Cached so `is_paired` and `paired_daemon` can answer from memory: the FFI
    /// contract makes them synchronous precisely to keep a disk round trip off
    /// whatever thread calls them.
    daemon: Mutex<Option<PairedDaemon>>,
    status: Mutex<ConnectionStatus>,
    live: Mutex<Option<Arc<Live>>>,
    pairing: Mutex<Option<Pairing>>,
    terminals: Mutex<HashMap<u64, JoinHandle<()>>>,
    on_state: Mutex<Option<Arc<dyn StateObserver>>>,
    on_screen: Mutex<Option<Arc<dyn ScreenObserver>>>,
    request_timeout: Mutex<Duration>,
}

impl Inner {
    /// The current status snapshot.
    fn status(&self) -> ConnectionStatus {
        lock(&self.status).clone()
    }

    /// Applies a change to the status and notifies the observer if it moved.
    ///
    /// The observer is called with **no lock held**. A Kotlin listener is free to
    /// call back into the client from `onStatus`, and doing that while holding
    /// the status mutex would deadlock on the first reentrant `status()`.
    fn update_status(&self, change: impl FnOnce(&mut ConnectionStatus)) {
        let updated = {
            let mut status = lock(&self.status);
            let before = status.clone();
            change(&mut status);
            if *status == before {
                return;
            }
            status.clone()
        };
        let observer = lock(&self.on_state).clone();
        if let Some(observer) = observer {
            observer.on_state(updated);
        }
    }

    /// Sets the phase, leaving the rest of the snapshot alone.
    fn set_phase(&self, phase: ConnPhase) {
        self.update_status(|status| status.phase = phase);
    }

    /// The paired daemon, from the in-memory cache.
    fn paired_daemon(&self) -> Option<PairedDaemon> {
        lock(&self.daemon).clone()
    }

    /// How long a request waits for its response.
    fn request_timeout(&self) -> Duration {
        *lock(&self.request_timeout)
    }

    /// The live connection, if there is one that is still usable.
    ///
    /// A phone's socket dies when the network changes — on Tier 0 a TCP
    /// connection is its 4-tuple, so there is no migration (§4.4) — and the
    /// corpse is indistinguishable from a live connection until something is sent
    /// on it. Checking here means the state reported to the UI is corrected at the
    /// first opportunity rather than after a failed request.
    fn healthy_live(&self) -> Option<Arc<Live>> {
        // The guard is released at the end of this statement, before `tear_down`
        // takes it again below.
        let live = lock(&self.live).clone()?;
        if live.conn.is_closed() {
            drop(live);
            self.tear_down();
            return None;
        }
        Some(live)
    }

    /// The live connection, or an error naming why there is none.
    fn require_live(&self) -> Result<Arc<Live>, ClientError> {
        if let Some(live) = self.healthy_live() {
            return Ok(live);
        }
        if lock(&self.daemon).is_none() {
            return Err(ClientError::NotPaired);
        }
        Err(ClientError::NotConnected)
    }

    /// Issues a request over the live connection.
    async fn call<P, R>(&self, method: &str, params: &P) -> Result<R, ClientError>
    where
        P: Serialize,
        R: DeserializeOwned,
    {
        let live = self.require_live()?;
        let result = live.request(method, params, self.request_timeout()).await;
        if matches!(
            result,
            Err(ClientError::ConnectionLost | ClientError::Transport(_))
        ) {
            // The connection is gone; drop it so the next call reports
            // `NotConnected` instead of failing against a corpse.
            self.tear_down();
        }
        result
    }

    /// Dials the stored daemon and completes the hello exchange.
    async fn connect(&self) -> Result<(), ClientError> {
        let Some(daemon) = self.paired_daemon() else {
            self.set_phase(ConnPhase::Unpaired);
            return Err(ClientError::NotPaired);
        };
        // Idempotent while a *usable* connection exists. A dead one is discarded
        // rather than reported as success, which is what makes `connect` the right
        // thing to call from a network-change callback (§6.5).
        if self.healthy_live().is_some() {
            return Ok(());
        }
        self.set_phase(ConnPhase::Connecting);

        let hints: Vec<AddrHint> = daemon
            .addr_hints
            .iter()
            .map(|h| AddrHint::parse(h))
            .collect();
        let config = ClientConfig::reconnect(Arc::clone(&self.identity));
        let peer = PeerId::from_noise_key(daemon.noise_key);

        match establish(config, peer, &hints).await {
            Ok(live) => {
                self.adopt(live, &daemon);
                Ok(())
            }
            Err(err) => {
                self.set_phase(match err {
                    ClientError::Unpaired => ConnPhase::Unpaired,
                    ClientError::Revoked => ConnPhase::Revoked,
                    _ => ConnPhase::Disconnected,
                });
                Err(err)
            }
        }
    }

    /// Installs a freshly established connection as the live one.
    fn adopt(&self, live: Live, daemon: &PairedDaemon) {
        let path = live.conn.path_info();
        let live = Arc::new(live);
        *lock(&self.live) = Some(live);
        self.update_status(|status| {
            status.phase = ConnPhase::Connected;
            status.daemon_name = Some(daemon.name.clone());
            status.rtt_ms = path.rtt_ms;
            status.transport = Some(path.tier);
        });
        self.touch_last_seen(daemon);
    }

    /// Records that the daemon was reachable just now.
    ///
    /// Best-effort: failing to update a display timestamp must not fail a
    /// connection the user is waiting on.
    fn touch_last_seen(&self, daemon: &PairedDaemon) {
        let mut updated = daemon.clone();
        updated.last_seen_ms = Some(now_ms());
        if let Err(err) = self.storage.save_daemon(&updated) {
            tracing::warn!(error = %err, "could not record the last-seen time");
            return;
        }
        *lock(&self.daemon) = Some(updated);
    }

    /// Drops the live connection and every terminal poller attached to it.
    fn tear_down(&self) {
        for (_, poller) in lock(&self.terminals).drain() {
            poller.abort();
        }
        let live = lock(&self.live).take();
        drop(live);
        self.update_status(|status| {
            if status.phase == ConnPhase::Connected || status.phase == ConnPhase::Connecting {
                status.phase = ConnPhase::Disconnected;
            }
            status.rtt_ms = None;
            status.transport = None;
        });
    }

    /// Runs the pairing handshake and returns the SAS, registering nothing.
    async fn begin_pairing(&self, qr_payload: &str) -> Result<String, ClientError> {
        let (ticket, secret) = PairingTicket::decode(qr_payload)?;
        // A previous attempt's session must not survive: the daemon's window
        // allows three attempts and holding a stale one wastes the budget.
        self.cancel_pairing();
        self.set_phase(ConnPhase::Connecting);

        let hints = AddrHint::from_ticket(&ticket);
        let config = ClientConfig::pairing(Arc::clone(&self.identity), &secret);
        let peer = PeerId::from_noise_key(ticket.daemon_key);

        // A wrong pairing code fails here, when the initiator authenticates the
        // responder's message. Nothing has been written to storage at this point
        // and nothing will be: the only writer is `confirm_pairing` (§19 R24).
        // `map_err` rather than `inspect_err`, which needs Rust 1.76 and the
        // workspace MSRV is 1.75.
        let live = establish(config, peer, &hints).await.map_err(|err| {
            self.set_phase(if self.paired_daemon().is_some() {
                ConnPhase::Disconnected
            } else {
                ConnPhase::Unpaired
            });
            err
        })?;

        let sas = *live.conn.sas();
        let peer = live.conn.peer_key();
        *lock(&self.pairing) = Some(Pairing {
            live: Arc::new(live),
            sas,
            peer,
            addr_hints: ticket.addr_hints,
        });
        Ok(sas.grouped())
    }

    /// Registers this device, then persists the daemon — in that order.
    ///
    /// **This ordering is `ARCHITECTURE.md` §19 R24.** With `IKpsk2` the daemon
    /// completes its side of the handshake even when the pairing code was wrong,
    /// so handshake completion proves nothing. Only a request that the daemon
    /// could decrypt — which requires matching session keys, which requires the
    /// right pre-shared key — proves the phone saw the QR. Persisting before the
    /// round trip would remember a machine that never accepted us.
    async fn confirm_pairing(&self, device_name: &str) -> Result<(), ClientError> {
        let (live, sas, peer, addr_hints) = {
            let pairing = lock(&self.pairing);
            let pairing = pairing.as_ref().ok_or(ClientError::NoPairingInProgress)?;
            (
                Arc::clone(&pairing.live),
                pairing.sas,
                pairing.peer,
                pairing.addr_hints.clone(),
            )
        };

        let params = SysRegisterParams {
            device_name: device_name.to_owned(),
            device_model: None,
            // Sent so the daemon can confirm both ends derived the same digits
            // before committing, rather than relying only on the human.
            sas: sas.digits(),
        };
        let registered: SysRegisterResult = live
            .request(method::SYS_REGISTER, &params, self.request_timeout())
            .await
            .map_err(|err| {
                // A refused registration spends the session: the daemon's
                // pairing window allows three attempts and this one is used.
                self.cancel_pairing();
                err
            })?;

        let name = daemon_name(&live, &addr_hints, self.request_timeout()).await;
        let daemon = PairedDaemon {
            noise_key: peer,
            // The record describes the *machine*, so its identifier is the
            // machine's key — not the id the daemon assigned this phone, which is
            // kept alongside it.
            device_id: peer.to_hex(),
            registered_device_id: registered.device_id,
            name,
            addr_hints,
            paired_at_ms: now_ms(),
            last_seen_ms: Some(now_ms()),
        };
        self.storage.save_daemon(&daemon)?;
        *lock(&self.daemon) = Some(daemon.clone());

        // The pairing window closes on the daemon the moment it registers us, so
        // this session is spent. `connect` re-dials with `Purpose::Reconnect`,
        // which is the pattern every later session uses.
        self.cancel_pairing();
        self.update_status(|status| {
            status.phase = ConnPhase::Disconnected;
            status.daemon_name = Some(daemon.name.clone());
        });
        Ok(())
    }

    /// Abandons an in-flight pairing session.
    fn cancel_pairing(&self) {
        drop(lock(&self.pairing).take());
    }

    /// Forgets the daemon and wipes the device key.
    fn unpair(&self) -> Result<(), ClientError> {
        self.cancel_pairing();
        self.tear_down();
        *lock(&self.daemon) = None;
        self.update_status(|status| {
            status.phase = ConnPhase::Unpaired;
            status.daemon_name = None;
        });
        self.storage.wipe()?;
        Ok(())
    }

    /// Starts a terminal and attaches a poller to it.
    async fn spawn_terminal(
        self: &Arc<Self>,
        cwd: Option<String>,
    ) -> Result<PtySpawnResult, ClientError> {
        let params = PtySpawnParams {
            cwd,
            shell: None,
            cols: DEFAULT_COLS,
            rows: DEFAULT_ROWS,
        };
        let spawned: PtySpawnResult = self.call(method::PTY_SPAWN, &params).await?;
        let poller = tokio::spawn(poll_screen(Arc::downgrade(self), spawned.pty_id));
        if let Some(previous) = lock(&self.terminals).insert(spawned.pty_id, poller) {
            // A reused id means the daemon recycled one; the old poller is
            // pointing at a terminal that no longer exists.
            previous.abort();
        }
        Ok(spawned)
    }

    /// Lists the terminals the daemon currently has running.
    async fn list_terminals(&self) -> Result<Vec<u64>, ClientError> {
        let listed: PtyListResult = self.call(method::PTY_LIST, &Empty {}).await?;
        Ok(listed.pty_ids)
    }

    /// Reattaches to a terminal that is already running on the daemon.
    ///
    /// The counterpart to [`Self::spawn_terminal`], and the thing that makes
    /// "background terminals keep working" usable rather than merely true.
    ///
    /// Without it, the daemon's PTYs survive a disconnect exactly as designed
    /// (`ARCHITECTURE.md` §2) but the phone has no way back to them: after a
    /// reconnect or an app restart every tab is frozen and the running build is
    /// unreachable. That is the same failure mode as losing the work, from the
    /// user's chair.
    ///
    /// Returns the current screen, so the caller can render immediately rather
    /// than waiting a poll interval on a blank surface.
    async fn attach_terminal(self: &Arc<Self>, pty_id: u64) -> Result<ScreenFrame, ClientError> {
        // Fetch the screen first. If the terminal is gone the daemon answers
        // NotFound and no poller is started, so a stale id from a previous
        // session cannot leave a poller running against nothing.
        let screen = self.screen(pty_id).await?;

        let poller = tokio::spawn(poll_screen(Arc::downgrade(self), pty_id));
        if let Some(previous) = lock(&self.terminals).insert(pty_id, poller) {
            // Already attached — replace rather than run two pollers against one
            // terminal, which would double the request rate for no benefit.
            previous.abort();
        }
        Ok(screen)
    }

    /// Kills a terminal and stops its poller.
    async fn close_terminal(&self, pty_id: u64) -> Result<(), ClientError> {
        if let Some(poller) = lock(&self.terminals).remove(&pty_id) {
            poller.abort();
        }
        let _: Empty = self.call(method::PTY_KILL, &PtyIdParams { pty_id }).await?;
        Ok(())
    }

    /// Fetches one screen.
    async fn screen(&self, pty_id: u64) -> Result<ScreenFrame, ClientError> {
        self.call(method::PTY_SCREEN, &PtyIdParams { pty_id }).await
    }
}

/// Dials, opens the control stream, and completes the hello exchange.
async fn establish(
    config: ClientConfig,
    peer: PeerId,
    hints: &[AddrHint],
) -> Result<Live, ClientError> {
    // Read before the config is moved into the transport. This is the **Ed25519
    // signing key**: the daemon registers it and later verifies presence
    // signatures against it. The X25519 Noise key authenticated the socket and is
    // a different value entirely (`gonomad_core::identity`).
    let device_key = config.identity.public_key();

    let transport = TcpTransport::client(config)?;
    let conn = transport.connect_lan(peer, hints).await?;
    let (mut tx, mut rx) = conn.open_bi()?;

    let hello = ControlMessage::Hello(Hello {
        proto_version: PROTOCOL_VERSION,
        min_supported: MIN_PROTOCOL_VERSION,
        client_version: CLIENT_VERSION.to_owned(),
        device_key,
        capabilities_requested: gonomad_proto::CapabilitySet::default_grant(),
        compression_dicts: Vec::new(),
        features: Vec::new(),
        resume_session: None,
    });
    tx.send(&Frame::cbor(FrameFlags::LAST, &hello)?).await?;

    let accepted = tokio::time::timeout(HELLO_TIMEOUT, read_hello(&mut rx))
        .await
        .map_err(|_| ClientError::Timeout)??;
    tracing::debug!(
        session = accepted.session_id,
        server = %accepted.server_version,
        "control stream established"
    );
    Ok(Live::start(conn, tx, rx, accepted))
}

/// Reads the control stream until the daemon accepts or refuses the hello.
async fn read_hello(rx: &mut RecvStream) -> Result<HelloOk, ClientError> {
    loop {
        let Some(frame) = rx.recv().await? else {
            return Err(ClientError::ConnectionLost);
        };
        match frame.decode_cbor::<ControlMessage>() {
            Ok(ControlMessage::HelloOk(ok)) => return Ok(ok),
            Ok(ControlMessage::HelloReject(reject)) => return Err(from_reject(&reject.reason)),
            // Anything else before the handshake completes is a protocol
            // violation on the daemon's part. Tolerated by ignoring rather than
            // by acting on it: acting would mean processing a message whose
            // authorization has not been established.
            Ok(other) => tracing::debug!(?other, "ignoring a message sent before HelloOk"),
            Err(_) => {
                return Err(ClientError::Malformed {
                    detail: "the hello reply was not a control message",
                })
            }
        }
    }
}

/// Routes responses to the requests waiting for them, until the stream ends.
async fn route_control(
    mut rx: RecvStream,
    tx: Arc<tokio::sync::Mutex<SendStream>>,
    pending: Arc<PendingMap>,
) {
    loop {
        let frame = match rx.recv().await {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(err) => {
                tracing::debug!(error = %err, "control stream ended");
                break;
            }
        };
        let Ok(message) = frame.decode_cbor::<ControlMessage>() else {
            // One unreadable frame does not desynchronise the stream — the mux
            // delivers whole frames — so this is dropped rather than fatal.
            tracing::debug!("dropping an undecodable control frame");
            continue;
        };
        match message {
            ControlMessage::Response(response) => {
                if response.body.is_terminal() {
                    pending.deliver(response);
                } else {
                    tracing::trace!(id = response.correlation_id, "progress");
                }
            }
            ControlMessage::Ping(beat) => {
                let Ok(frame) = Frame::cbor(FrameFlags::LAST, &ControlMessage::Pong(beat)) else {
                    continue;
                };
                if let Err(err) = tx.lock().await.send(&frame).await {
                    tracing::debug!(error = %err, "could not answer a heartbeat");
                    break;
                }
            }
            other => tracing::debug!(?other, "ignoring an unexpected control message"),
        }
    }
    // Waking every waiting request now, rather than letting each hit its own
    // deadline, is what turns a dropped connection into an immediate error.
    pending.abandon_all();
}

/// Polls one terminal's screen while it stays attached.
///
/// A stopgap until the daemon pushes `pty.output` on the PTY stream (§10.2, M2).
/// Holds a [`Weak`] reference so an attached terminal cannot keep the client
/// alive after Kotlin has released it — `Inner` owns this task's handle, and an
/// `Arc` here would be a cycle that never drops.
async fn poll_screen(inner: Weak<Inner>, pty_id: u64) {
    let mut ticker = tokio::time::interval(SCREEN_POLL_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last: Option<ScreenFrame> = None;

    loop {
        ticker.tick().await;
        let Some(inner) = inner.upgrade() else { return };

        let frame = match inner.screen(pty_id).await {
            Ok(frame) => frame,
            Err(err) => {
                tracing::debug!(pty_id, error = %err, "terminal poll stopped");
                return;
            }
        };
        let exited = frame.exited;

        // Only publish on change: at seven polls a second an idle shell would
        // otherwise wake the UI thread for nothing.
        if last.as_ref() != Some(&frame) {
            let observer = lock(&inner.on_screen).clone();
            if let Some(observer) = observer {
                observer.on_screen(frame.clone());
            }
            last = Some(frame);
        }
        if exited {
            lock(&inner.terminals).remove(&pty_id);
            return;
        }
    }
}

/// Asks the daemon what it is called, falling back to where it was reached.
///
/// Called *after* registration succeeded, so a failure here costs a display name
/// and not the pairing. Showing an address is worse than showing a host name and
/// far better than discarding a completed pairing.
async fn daemon_name(live: &Live, addr_hints: &[String], timeout: Duration) -> String {
    let info: Result<SysInfoResult, _> = live
        .request(method::SYS_INFO, &SysInfoParams {}, timeout)
        .await;
    match info {
        Ok(info) => info.host_name,
        Err(err) => {
            tracing::warn!(error = %err, "paired, but could not read the machine's name");
            addr_hints
                .first()
                .cloned()
                .unwrap_or_else(|| "Your machine".to_owned())
        }
    }
}

/// Encodes one request, refusing anything that cannot cross this transport.
fn encode_request<P: Serialize>(
    id: CorrelationId,
    method: &str,
    params: &P,
) -> Result<Frame, ClientError> {
    let mut encoded = Vec::new();
    ciborium::into_writer(params, &mut encoded)
        .map_err(|_| ClientError::Internal("request parameters could not be encoded"))?;

    let message = ControlMessage::Request(Request {
        correlation_id: id,
        method: method.to_owned(),
        params: encoded,
        // Absent for this slice: every method here is a read or a terminal
        // interaction, where repetition is harmless. It becomes mandatory with
        // `fs.write` (§11.2).
        idempotency_key: None,
        presence_signature: None,
    });
    // `FrameFlags::LAST`: each control message is exactly one complete frame, so
    // every frame is the last of its sequence.
    let frame = Frame::cbor(FrameFlags::LAST, &message)?;

    // §19 R25. The mux returns credit on whole-frame consumption, so a frame
    // above the peer's window can never be reassembled and the sender would park
    // forever on credit the receiver is unable to return. Refused here, with the
    // numbers, rather than left to hang.
    let max = MuxConfig::default().max_frame_len;
    if frame.payload.len() > max {
        return Err(ClientError::TooLarge {
            len: frame.payload.len(),
            max,
        });
    }
    Ok(frame)
}

/// Decodes a method result from the CBOR the daemon returned.
fn decode_result<R: DeserializeOwned>(bytes: &[u8]) -> Result<R, ClientError> {
    ciborium::from_reader(bytes).map_err(|_| ClientError::Malformed {
        detail: "the result did not match what this app expected",
    })
}

/// Maps a hello refusal onto the reason the UI must act on.
fn from_reject(reason: &RejectReason) -> ClientError {
    match *reason {
        RejectReason::VersionTooOld { server_min } => ClientError::AppTooOld { server_min },
        RejectReason::VersionTooNew { server_max } => ClientError::DaemonTooOld { server_max },
        RejectReason::Unpaired => ClientError::Unpaired,
        RejectReason::Revoked => ClientError::Revoked,
        RejectReason::RateLimited { retry_after_ms } => ClientError::RateLimited { retry_after_ms },
        // A newer daemon may refuse for a reason this build has no screen for.
        _ => ClientError::Malformed {
            detail: "the machine refused the connection for an unknown reason",
        },
    }
}

/// Locks a mutex, recovering from a poisoned one.
///
/// A panic elsewhere must not turn every later call into a panic of its own:
/// across an FFI boundary that is an application crash with no diagnostic. The
/// data behind these locks is a cache and a set of handles, and neither is left
/// in a state that a poisoned flag would protect us from.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The client, as consumed by [`crate::ffi`] and by tests.
///
/// Async methods dispatch onto the owned runtime and can be awaited from any
/// context, including a foreign one with no reactor of its own.
pub struct GonomadClient {
    /// `Option` only so [`Drop`] can take it. Never `None` while a method can be
    /// called; see the `Drop` impl for why the indirection is necessary.
    runtime: Option<tokio::runtime::Runtime>,
    inner: Arc<Inner>,
}

impl GonomadClient {
    /// Loads the persisted identity and pairing, creating an identity on first
    /// run.
    ///
    /// # Errors
    ///
    /// [`ClientError::Storage`] when the state directory is unusable or the
    /// stored identity is corrupt, and [`ClientError::Internal`] when the tokio
    /// runtime cannot be started — which in practice means the process is out of
    /// threads.
    pub fn create(state_dir: impl Into<std::path::PathBuf>) -> Result<Self, ClientError> {
        let storage = Storage::new(state_dir);
        let identity = Arc::new(storage.load_or_create_identity()?);
        let daemon = storage.load_daemon()?;

        // Multi-threaded: nothing on the Kotlin side ever blocks on this
        // runtime, so a current-thread runtime would only make progress while a
        // call happened to be awaiting inside it — the reader task and the
        // terminal poller would stall between calls.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("gonomad")
            .enable_all()
            .build()
            .map_err(|_| ClientError::Internal("could not start the async runtime"))?;

        Ok(Self {
            runtime: Some(runtime),
            inner: Arc::new(Inner {
                identity,
                storage,
                status: Mutex::new(ConnectionStatus::idle(daemon.as_ref())),
                daemon: Mutex::new(daemon),
                live: Mutex::new(None),
                pairing: Mutex::new(None),
                terminals: Mutex::new(HashMap::new()),
                on_state: Mutex::new(None),
                on_screen: Mutex::new(None),
                request_timeout: Mutex::new(DEFAULT_REQUEST_TIMEOUT),
            }),
        })
    }

    /// This device's Ed25519 public key — its credential.
    pub fn device_key(&self) -> PublicKey {
        self.inner.identity.public_key()
    }

    /// This device's X25519 Noise static key, which the daemon authenticates.
    ///
    /// Distinct from [`GonomadClient::device_key`] and not interchangeable with
    /// it (`gonomad_core::identity`).
    pub fn noise_key(&self) -> PublicKey {
        self.inner.identity.noise_public_key()
    }

    /// Whether this device has completed pairing. Answers from memory.
    pub fn is_paired(&self) -> bool {
        self.inner.paired_daemon().is_some()
    }

    /// The paired daemon, from memory.
    pub fn paired_daemon(&self) -> Option<PairedDaemon> {
        self.inner.paired_daemon()
    }

    /// The current connection status, from memory.
    pub fn status(&self) -> ConnectionStatus {
        self.inner.status()
    }

    /// Replaces the connection-state observer.
    pub fn observe_state(&self, observer: Arc<dyn StateObserver>) {
        *lock(&self.inner.on_state) = Some(observer);
    }

    /// Replaces the terminal-screen observer.
    pub fn observe_screens(&self, observer: Arc<dyn ScreenObserver>) {
        *lock(&self.inner.on_screen) = Some(observer);
    }

    /// Overrides how long a request waits for its response.
    ///
    /// Exists so tests do not have to wait [`DEFAULT_REQUEST_TIMEOUT`], and so a
    /// future settings screen can shorten it on a bad network. Takes effect from
    /// the next request.
    pub fn set_request_timeout(&self, timeout: Duration) {
        *lock(&self.inner.request_timeout) = timeout;
    }

    /// Connects to the stored daemon.
    ///
    /// # Errors
    ///
    /// [`ClientError::NotPaired`] with no pairing on record, a
    /// [`ClientError::Transport`] when the machine cannot be reached, or the
    /// specific refusal the daemon replied with.
    pub async fn connect(&self) -> Result<(), ClientError> {
        let inner = Arc::clone(&self.inner);
        self.run(async move { inner.connect().await }).await
    }

    /// Drops the connection, keeping the pairing.
    pub fn disconnect(&self) {
        self.inner.tear_down();
    }

    /// Runs the pairing handshake for a scanned QR payload and returns the SAS.
    ///
    /// Registers nothing: the user must confirm the digits match the laptop, and
    /// [`GonomadClient::confirm_pairing`] is what commits.
    ///
    /// # Errors
    ///
    /// [`ClientError::Pairing`] when the payload is not a GoNomad ticket, or a
    /// [`ClientError::Transport`] when the handshake fails — which is what a
    /// wrong pairing code looks like from this side.
    pub async fn begin_pairing(&self, qr_payload: String) -> Result<String, ClientError> {
        let inner = Arc::clone(&self.inner);
        self.run(async move { inner.begin_pairing(&qr_payload).await })
            .await
    }

    /// Commits the pairing after the user confirmed the SAS.
    ///
    /// # Errors
    ///
    /// [`ClientError::NoPairingInProgress`] when nothing is in flight,
    /// [`ClientError::Remote`] when the daemon refuses to register this device,
    /// or [`ClientError::Storage`] when the record cannot be written. Nothing is
    /// persisted in any of those cases.
    pub async fn confirm_pairing(&self, device_name: String) -> Result<(), ClientError> {
        let inner = Arc::clone(&self.inner);
        self.run(async move { inner.confirm_pairing(&device_name).await })
            .await
    }

    /// Abandons an in-progress pairing.
    pub fn cancel_pairing(&self) {
        self.inner.cancel_pairing();
    }

    /// Forgets the daemon and wipes the device key.
    ///
    /// # Errors
    ///
    /// [`ClientError::Storage`] when a file could not be removed. The in-memory
    /// state is cleared regardless, so the app is unpaired either way.
    pub fn unpair(&self) -> Result<(), ClientError> {
        self.inner.unpair()
    }

    /// Lists one directory level.
    ///
    /// # Errors
    ///
    /// [`ClientError::NotConnected`] without a live connection, or the daemon's
    /// own error — commonly [`ProtoError`] `NotFound` for a path outside the
    /// workspace roots.
    pub async fn list_dir(&self, path: String) -> Result<Vec<DirEntry>, ClientError> {
        let inner = Arc::clone(&self.inner);
        self.run(async move {
            let result: FsListResult = inner.call(method::FS_LIST, &FsListParams { path }).await?;
            Ok(result.entries)
        })
        .await
    }

    /// Reads a file as text.
    ///
    /// # Errors
    ///
    /// As [`GonomadClient::list_dir`].
    pub async fn read_file(&self, path: String) -> Result<FsReadResult, ClientError> {
        let inner = Arc::clone(&self.inner);
        self.run(async move { inner.call(method::FS_READ, &FsReadParams { path }).await })
            .await
    }

    /// The workspace roots this device may reach.
    ///
    /// Taken from the `HelloOk` of the live connection rather than fetched, so it
    /// cannot disagree with what the session was actually granted.
    ///
    /// # Errors
    ///
    /// [`ClientError::NotConnected`] without a live connection.
    pub async fn workspace_roots(&self) -> Result<Vec<String>, ClientError> {
        let inner = Arc::clone(&self.inner);
        self.run(async move { Ok(inner.require_live()?.hello.workspace_roots.clone()) })
            .await
    }

    /// What the daemon reports about itself.
    ///
    /// # Errors
    ///
    /// [`ClientError::NotConnected`] without a live connection.
    pub async fn sys_info(&self) -> Result<SysInfoResult, ClientError> {
        let inner = Arc::clone(&self.inner);
        self.run(async move { inner.call(method::SYS_INFO, &SysInfoParams {}).await })
            .await
    }

    /// Spawns a terminal and starts polling its screen.
    ///
    /// # Errors
    ///
    /// [`ClientError::NotConnected`] without a live connection, or the daemon's
    /// own error when the working directory is outside the workspace roots.
    pub async fn spawn_terminal(&self, cwd: Option<String>) -> Result<PtySpawnResult, ClientError> {
        let inner = Arc::clone(&self.inner);
        self.run(async move { inner.spawn_terminal(cwd).await })
            .await
    }

    /// Sends input to a terminal.
    ///
    /// # Errors
    ///
    /// [`ClientError::TooLarge`] for a paste too big for one frame, or the
    /// daemon's error for an unknown terminal.
    pub async fn send_input(&self, pty_id: u64, data: String) -> Result<(), ClientError> {
        let inner = Arc::clone(&self.inner);
        self.run(async move {
            let _: Empty = inner
                .call(method::PTY_INPUT, &PtyInputParams { pty_id, data })
                .await?;
            Ok(())
        })
        .await
    }

    /// Resizes a terminal.
    ///
    /// # Errors
    ///
    /// The daemon's error for an unknown terminal.
    pub async fn resize_terminal(
        &self,
        pty_id: u64,
        cols: u16,
        rows: u16,
    ) -> Result<(), ClientError> {
        let inner = Arc::clone(&self.inner);
        self.run(async move {
            let _: Empty = inner
                .call(method::PTY_RESIZE, &PtyResizeParams { pty_id, cols, rows })
                .await?;
            Ok(())
        })
        .await
    }

    /// Fetches a terminal's current screen.
    ///
    /// # Errors
    ///
    /// The daemon's error for an unknown terminal.
    pub async fn screen(&self, pty_id: u64) -> Result<ScreenFrame, ClientError> {
        let inner = Arc::clone(&self.inner);
        self.run(async move { inner.screen(pty_id).await }).await
    }

    /// Lists the terminals still running on the daemon.
    ///
    /// # Errors
    ///
    /// [`ClientError::NotConnected`] when offline, or the daemon's error.
    pub async fn list_terminals(&self) -> Result<Vec<u64>, ClientError> {
        let inner = Arc::clone(&self.inner);
        self.run(async move { inner.list_terminals().await }).await
    }

    /// Reattaches to a terminal already running on the daemon and returns its
    /// current screen.
    ///
    /// Call this for each id from [`Self::list_terminals`] after connecting, so
    /// that a reconnect or an app restart restores the user's terminals instead
    /// of leaving them frozen. The daemon never stopped them.
    ///
    /// # Errors
    ///
    /// The daemon's `NotFound` if the terminal has since exited and been reaped;
    /// no poller is started in that case.
    pub async fn attach_terminal(&self, pty_id: u64) -> Result<ScreenFrame, ClientError> {
        let inner = Arc::clone(&self.inner);
        self.run(async move { inner.attach_terminal(pty_id).await })
            .await
    }

    /// Terminates a terminal and stops its poller.
    ///
    /// # Errors
    ///
    /// The daemon's error for an unknown terminal. The poller is stopped either
    /// way, so a failure here cannot leave the UI receiving frames for a
    /// terminal the user closed.
    pub async fn close_terminal(&self, pty_id: u64) -> Result<(), ClientError> {
        let inner = Arc::clone(&self.inner);
        self.run(async move { inner.close_terminal(pty_id).await })
            .await
    }

    /// Runs `work` on the owned runtime and awaits it from the caller's context.
    async fn run<T, F>(&self, work: F) -> Result<T, ClientError>
    where
        F: Future<Output = Result<T, ClientError>> + Send + 'static,
        T: Send + 'static,
    {
        let Some(runtime) = self.runtime.as_ref() else {
            // Unreachable: the runtime is only taken by `Drop`, and a method
            // cannot be called on a dropped value. Returned rather than
            // asserted, because a panic here would unwind across the FFI
            // boundary.
            return Err(ClientError::Internal("the client is shutting down"));
        };
        match runtime.spawn(work).await {
            Ok(result) => result,
            // A panic in client code must surface as an error rather than
            // unwinding across the FFI boundary, which is undefined behaviour.
            Err(err) => {
                tracing::error!(error = %err, "a client task failed");
                Err(ClientError::Internal("a background task failed"))
            }
        }
    }
}

impl Drop for GonomadClient {
    fn drop(&mut self) {
        // Dropping a `Runtime` normally *blocks* until its worker threads have
        // stopped, and blocking inside another runtime's context panics. Kotlin
        // releases this object on whatever thread ran the last reference — a JNI
        // finalizer, or a coroutine dispatcher — so which context that is cannot
        // be controlled from here. `shutdown_background` never blocks: it stops
        // accepting work and lets the workers wind down on their own.
        //
        // The tasks being abandoned are the mux, the response reader, and any
        // terminal poller. All of them are per-connection and hold nothing that
        // needs flushing, so there is nothing to wait for.
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

impl core::fmt::Debug for GonomadClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GonomadClient")
            .field("device", &self.inner.identity.device_id())
            .field("paired", &self.is_paired())
            .field("phase", &lock(&self.inner.status).phase)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drives a future to completion with no async runtime in scope.
    ///
    /// This is what UniFFI's generated Kotlin does: it polls the future from a
    /// coroutine and wakes it from a `Waker` of its own, with no tokio context on
    /// the calling thread. The whole design rests on the client's futures
    /// tolerating that, so it is asserted rather than assumed.
    fn block_on_without_a_runtime<F: Future>(future: F) -> F::Output {
        struct Unpark(std::thread::Thread);
        impl std::task::Wake for Unpark {
            fn wake(self: Arc<Self>) {
                self.0.unpark();
            }
        }

        let waker = std::task::Waker::from(Arc::new(Unpark(std::thread::current())));
        let mut context = std::task::Context::from_waker(&waker);
        let mut future = Box::pin(future);
        loop {
            match future.as_mut().poll(&mut context) {
                std::task::Poll::Ready(value) => return value,
                std::task::Poll::Pending => std::thread::park(),
            }
        }
    }

    #[test]
    fn async_methods_need_no_ambient_runtime_on_the_calling_thread() {
        // Kotlin cannot give Rust a reactor, so a method that only worked inside
        // a tokio context would work in tests and hang in the app.
        let dir = tempfile::TempDir::new().expect("temp dir");
        let client = GonomadClient::create(dir.path()).expect("create");
        assert!(matches!(
            block_on_without_a_runtime(client.connect()),
            Err(ClientError::NotPaired)
        ));
        assert!(matches!(
            block_on_without_a_runtime(client.workspace_roots()),
            Err(ClientError::NotPaired)
        ));
    }

    #[test]
    fn a_fresh_client_is_unpaired_and_disconnected() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let client = GonomadClient::create(dir.path()).expect("create");
        assert!(!client.is_paired());
        assert_eq!(client.paired_daemon(), None);
        assert_eq!(client.status().phase, ConnPhase::Unpaired);
    }

    #[test]
    fn the_signing_key_and_the_noise_key_are_different_values() {
        // Conflating them was a real bug: an Ed25519 public key is not a valid
        // X25519 public key even when both derive from one seed.
        let dir = tempfile::TempDir::new().expect("temp dir");
        let client = GonomadClient::create(dir.path()).expect("create");
        assert_ne!(client.device_key(), client.noise_key());
    }

    #[test]
    fn debug_output_names_the_device_without_leaking_the_key() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let client = GonomadClient::create(dir.path()).expect("create");
        let rendered = format!("{client:?}");
        assert!(!rendered.contains(&client.device_key().to_hex()));
        assert!(rendered.contains("paired"));
    }

    #[tokio::test]
    async fn calls_without_a_pairing_report_not_paired_rather_than_hanging() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let client = GonomadClient::create(dir.path()).expect("create");
        assert!(matches!(
            client.connect().await,
            Err(ClientError::NotPaired)
        ));
        assert!(matches!(
            client.list_dir("/".into()).await,
            Err(ClientError::NotPaired)
        ));
    }

    #[tokio::test]
    async fn confirming_a_pairing_that_was_never_begun_is_refused() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let client = GonomadClient::create(dir.path()).expect("create");
        assert!(matches!(
            client.confirm_pairing("Pixel".into()).await,
            Err(ClientError::NoPairingInProgress)
        ));
        assert!(!client.is_paired());
    }

    #[tokio::test]
    async fn scanning_some_other_qr_code_is_reported_as_such() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let client = GonomadClient::create(dir.path()).expect("create");
        assert!(matches!(
            client.begin_pairing("https://example.com".into()).await,
            Err(ClientError::Pairing(PairingError::WrongScheme))
        ));
    }

    #[test]
    fn a_request_larger_than_one_frame_is_refused_not_parked() {
        // §19 R25: the sender would otherwise wait for credit the receiver
        // cannot return until the frame it is waiting on completes.
        let max = MuxConfig::default().max_frame_len;
        let huge = PtyInputParams {
            pty_id: 1,
            data: "x".repeat(max + 1),
        };
        match encode_request(1, method::PTY_INPUT, &huge) {
            Err(ClientError::TooLarge { len, max: limit }) => {
                assert!(len > limit);
                assert_eq!(limit, max);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn a_request_that_fits_encodes_to_one_last_frame() {
        let frame =
            encode_request(7, method::FS_LIST, &FsListParams { path: "/".into() }).expect("encode");
        assert!(frame.flags.is_last());
        let message: ControlMessage = frame.decode_cbor().expect("decode");
        match message {
            ControlMessage::Request(request) => {
                assert_eq!(request.correlation_id, 7);
                assert_eq!(request.method, method::FS_LIST);
            }
            other => panic!("expected a Request, got {other:?}"),
        }
    }

    #[test]
    fn every_hello_refusal_maps_to_something_the_ui_can_act_on() {
        assert!(matches!(
            from_reject(&RejectReason::Unpaired),
            ClientError::Unpaired
        ));
        assert!(matches!(
            from_reject(&RejectReason::Revoked),
            ClientError::Revoked
        ));
        assert!(matches!(
            from_reject(&RejectReason::VersionTooOld { server_min: 3 }),
            ClientError::AppTooOld { server_min: 3 }
        ));
        assert!(matches!(
            from_reject(&RejectReason::VersionTooNew { server_max: 1 }),
            ClientError::DaemonTooOld { server_max: 1 }
        ));
        assert!(matches!(
            from_reject(&RejectReason::RateLimited { retry_after_ms: 5 }),
            ClientError::RateLimited { retry_after_ms: 5 }
        ));
    }

    #[test]
    fn a_state_observer_is_notified_and_replaced_not_added() {
        #[derive(Default)]
        struct Counter(Mutex<Vec<ConnPhase>>);
        impl StateObserver for Counter {
            fn on_state(&self, status: ConnectionStatus) {
                lock(&self.0).push(status.phase);
            }
        }

        let dir = tempfile::TempDir::new().expect("temp dir");
        let client = GonomadClient::create(dir.path()).expect("create");
        let first = Arc::new(Counter::default());
        let second = Arc::new(Counter::default());
        client.observe_state(Arc::clone(&first) as Arc<dyn StateObserver>);
        client.observe_state(Arc::clone(&second) as Arc<dyn StateObserver>);

        client.inner.set_phase(ConnPhase::Connecting);
        // Repeating a phase must not emit: the UI would flicker for nothing.
        client.inner.set_phase(ConnPhase::Connecting);

        assert!(
            lock(&first.0).is_empty(),
            "the replaced observer must stop receiving"
        );
        assert_eq!(*lock(&second.0), vec![ConnPhase::Connecting]);
    }
}
