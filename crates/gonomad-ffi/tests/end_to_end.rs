//! End-to-end tests against a stub daemon over a real socket.
//!
//! Nothing here is mocked below the client's own API: every test binds a
//! [`TcpTransport`] on `127.0.0.1:0`, runs a real Noise IK handshake, and speaks
//! the real §10.3 framing over the real multiplexer. That is the point — the
//! interesting failures in this crate are ordering and lifetime failures between
//! the reader task, the mux, and the runtime, and a fake transport would hide
//! every one of them.
//!
//! The daemon's request router does not exist yet (`gonomad-server` renders the
//! pairing QR and stops), so [`Stub`] stands in for it. It implements only what
//! these tests need and answers everything else with `Unsupported`, which is what
//! the real router must do (`gonomad_proto::method::ALL`).

use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use gonomad_core::{DeviceIdentity, PairingSecret, PairingTicket};
use gonomad_ffi::client::{
    ClientError, ConnPhase, ConnectionStatus, GonomadClient, ScreenObserver, StateObserver,
};
use gonomad_ffi::storage::{PairedDaemon, Storage};
use gonomad_proto::methods::{
    method, DirEntry, Empty, EntryKind, FsListParams, FsListResult, FsReadResult, PtySpawnResult,
    ScreenFrame, SysInfoResult, SysRegisterParams, SysRegisterResult,
};
use gonomad_proto::{
    CapabilitySet, ControlMessage, Digest, ErrorKind, Frame, FrameFlags, HelloOk, ProtoError,
    Response, ResponseBody, PROTOCOL_VERSION,
};
use gonomad_transport::{
    AllowAny, Allowlist, SendStream, ServerConfig, TcpConnection, TcpTransport,
};
use serde::Serialize;
use tempfile::TempDir;

/// The host name the stub reports, so tests can assert it reached the UI.
const STUB_NAME: &str = "DESKTOP-STUB";

/// The workspace root the stub grants.
const STUB_ROOT: &str = "C:/code/gonomad";

/// Short enough that a timeout test finishes quickly, long enough that a real
/// round trip over loopback never trips it.
const TEST_TIMEOUT: Duration = Duration::from_millis(400);

/// How the stub answers requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Behaviour {
    /// Implements every method these tests use.
    Full,
    /// Completes the hello exchange and then never answers anything.
    Silent,
    /// Implements `sys.info` only, so anything else is version skew.
    OnlySysInfo,
    /// Implements everything but refuses to register the device.
    RefuseRegister,
    /// Answers the hello, then closes the control stream on the first request.
    HangUp,
}

/// A daemon stand-in: a bound listener plus the task serving it.
struct Stub {
    addr: SocketAddr,
    /// Aborted on drop, which also drops the listener and every connection.
    accepting: tokio::task::JoinHandle<()>,
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.accepting.abort();
    }
}

impl Stub {
    /// Binds a stub that accepts reconnects from one already-paired device.
    async fn reconnect(
        daemon: &Arc<DeviceIdentity>,
        phone: gonomad_proto::PublicKey,
        behaviour: Behaviour,
    ) -> Self {
        let policy = Arc::new(Allowlist::new(vec![phone]));
        let config = ServerConfig::reconnect(Arc::clone(daemon), policy);
        Self::bind(config, behaviour).await
    }

    /// Binds a stub with an open pairing window.
    async fn pairing(
        daemon: &Arc<DeviceIdentity>,
        secret: &PairingSecret,
        behaviour: Behaviour,
    ) -> Self {
        let mut config = ServerConfig::pairing(Arc::clone(daemon), secret);
        // Explicit, so the test states the property R24 depends on: during a
        // pairing window the peer's key is by definition unknown, and the
        // pre-shared key is the only thing authenticating it.
        config.policy = Arc::new(AllowAny);
        Self::bind(config, behaviour).await
    }

    async fn bind(config: ServerConfig, behaviour: Behaviour) -> Self {
        let transport = TcpTransport::bind("127.0.0.1:0".parse().expect("literal"), config)
            .await
            .expect("bind the stub");
        let addr = transport.local_addr().expect("bound");
        let accepting = tokio::spawn(async move {
            while let Ok(conn) = transport.accept_lan().await {
                tokio::spawn(serve(conn, behaviour));
            }
        });
        Self { addr, accepting }
    }

    /// The stub's address as a pairing-ticket hint.
    fn hint(&self) -> String {
        self.addr.to_string()
    }
}

/// Serves one connection: hello, then requests, until the peer goes away.
async fn serve(conn: TcpConnection, behaviour: Behaviour) {
    let Ok((mut tx, mut rx)) = conn.accept_bi().await else {
        return;
    };
    let sas = conn.sas().digits();
    let screens = AtomicU64::new(0);

    while let Ok(Some(frame)) = rx.recv().await {
        let Ok(message) = frame.decode_cbor::<ControlMessage>() else {
            continue;
        };
        match message {
            ControlMessage::Hello(_) => send(&mut tx, &ControlMessage::HelloOk(hello_ok())).await,
            ControlMessage::Request(request) => {
                if behaviour == Behaviour::Silent {
                    continue;
                }
                if behaviour == Behaviour::HangUp {
                    // Closes the channel in both directions, which is what a
                    // daemon restarting under the client looks like. Done on the
                    // first request rather than straight after the hello, so the
                    // teardown cannot race the HelloOk out of the client's queue.
                    tx.finish();
                    return;
                }
                let body = dispatch(&request.method, &request.params, &sas, behaviour, &screens);
                let response = ControlMessage::Response(Response {
                    correlation_id: request.correlation_id,
                    body,
                });
                send(&mut tx, &response).await;
            }
            // Cancellations and heartbeats need no reply from a stub.
            _ => {}
        }
    }
}

fn hello_ok() -> HelloOk {
    HelloOk {
        proto_version: PROTOCOL_VERSION,
        server_version: "gonomad-stub/0.0.1".into(),
        granted_capabilities: CapabilitySet::default_grant(),
        workspace_roots: vec![STUB_ROOT.to_owned()],
        compression_dict: None,
        server_features: Vec::new(),
        session_id: 1,
    }
}

/// Answers one request.
fn dispatch(
    method_name: &str,
    params: &[u8],
    sas: &str,
    behaviour: Behaviour,
    screens: &AtomicU64,
) -> ResponseBody {
    if behaviour == Behaviour::OnlySysInfo && method_name != method::SYS_INFO {
        return unsupported(method_name);
    }
    match method_name {
        method::SYS_INFO => ok(&SysInfoResult {
            host_name: STUB_NAME.into(),
            daemon_version: "0.0.1".into(),
            os: "windows".into(),
            capabilities: CapabilitySet::default_grant(),
            workspace_roots: vec![STUB_ROOT.to_owned()],
            shells: vec!["pwsh".into()],
        }),
        method::SYS_REGISTER => register(params, sas, behaviour),
        method::FS_LIST => list(params),
        method::FS_READ => ok(&FsReadResult {
            path: format!("{STUB_ROOT}/main.rs"),
            text: "fn main() {}".into(),
            content_hash: Digest::of(b"fn main() {}"),
            truncated: false,
        }),
        method::PTY_SPAWN => ok(&PtySpawnResult {
            pty_id: 7,
            shell: "pwsh".into(),
            initial: screen(7, 0),
        }),
        method::PTY_SCREEN => ok(&screen(7, screens.fetch_add(1, Ordering::Relaxed) + 1)),
        method::PTY_INPUT | method::PTY_RESIZE | method::PTY_KILL => ok(&Empty {}),
        other => unsupported(other),
    }
}

/// The `sys.register` half of R24: the daemon commits only when the digits agree.
fn register(params: &[u8], sas: &str, behaviour: Behaviour) -> ResponseBody {
    if behaviour == Behaviour::RefuseRegister {
        return ResponseBody::Error {
            error: ProtoError::bad_request("this machine declined to register the device"),
        };
    }
    let Ok(params) = ciborium::from_reader::<SysRegisterParams, _>(params) else {
        return ResponseBody::Error {
            error: ProtoError::bad_request("unreadable registration"),
        };
    };
    // A mismatch here means something sat in the middle: the two sides derived
    // different transcripts, so the daemon refuses rather than relying on the
    // human comparison alone.
    if params.sas != sas {
        return ResponseBody::Error {
            error: ProtoError::bad_request("the six digits did not match"),
        };
    }
    ok(&SysRegisterResult {
        device_id: "f".repeat(64),
        capabilities: CapabilitySet::default_grant(),
    })
}

fn list(params: &[u8]) -> ResponseBody {
    let path = ciborium::from_reader::<FsListParams, _>(params)
        .map_or_else(|_| STUB_ROOT.to_owned(), |p| p.path);
    ok(&FsListResult {
        path,
        entries: vec![
            DirEntry {
                name: "src".into(),
                kind: EntryKind::Directory,
                size_bytes: None,
                modified_ms: Some(1_700_000_000_000),
                is_hidden: false,
            },
            DirEntry {
                name: "main.rs".into(),
                kind: EntryKind::File,
                size_bytes: Some(1234),
                modified_ms: None,
                is_hidden: false,
            },
        ],
    })
}

fn screen(pty_id: u64, tick: u64) -> ScreenFrame {
    ScreenFrame {
        pty_id,
        rows: vec![format!("PS {STUB_ROOT}> tick {tick}")],
        cursor_row: 0,
        cursor_col: 4,
        cols: 80,
        exited: false,
    }
}

fn unsupported(method_name: &str) -> ResponseBody {
    ResponseBody::Error {
        error: ProtoError::new(ErrorKind::Unsupported {
            feature: method_name.to_owned(),
            since_version: None,
        }),
    }
}

fn ok<T: Serialize>(value: &T) -> ResponseBody {
    let mut result = Vec::new();
    ciborium::into_writer(value, &mut result).expect("stub results are serializable");
    ResponseBody::Ok { result }
}

async fn send(tx: &mut SendStream, message: &ControlMessage) {
    let frame = Frame::cbor(FrameFlags::LAST, message).expect("stub messages are serializable");
    if let Err(err) = tx.send(&frame).await {
        eprintln!("stub could not send: {err}");
    }
}

/// A directory to hold client state, kept alive for the test's duration.
struct Fixture {
    _dir: TempDir,
    state: std::path::PathBuf,
    storage: Storage,
    phone_noise_key: gonomad_proto::PublicKey,
}

impl Fixture {
    /// Creates the state directory and the phone's identity.
    ///
    /// The identity is created *first* so the stub can allowlist it: a daemon
    /// admits a device by its Noise static key and nothing else.
    fn new() -> Self {
        let dir = TempDir::new().expect("temp dir");
        let state = dir.path().join("state");
        let storage = Storage::new(&state);
        let phone_noise_key = storage
            .load_or_create_identity()
            .expect("create identity")
            .noise_public_key();
        Self {
            _dir: dir,
            state,
            storage,
            phone_noise_key,
        }
    }

    /// Records a paired daemon, as `confirm_pairing` would have.
    fn remember(&self, daemon: &DeviceIdentity, hint: &str) {
        self.storage
            .save_daemon(&PairedDaemon {
                noise_key: daemon.noise_public_key(),
                device_id: daemon.noise_public_key().to_hex(),
                registered_device_id: "a".repeat(64),
                name: STUB_NAME.to_owned(),
                addr_hints: vec![hint.to_owned()],
                paired_at_ms: 1_700_000_000_000,
                last_seen_ms: None,
            })
            .expect("save the daemon");
    }

    /// Builds a client over this state directory.
    fn client(&self) -> GonomadClient {
        let client = GonomadClient::create(&self.state).expect("create the client");
        client.set_request_timeout(TEST_TIMEOUT);
        client
    }

    fn path(&self) -> &Path {
        &self.state
    }
}

/// Records every terminal screen the poller pushes.
#[derive(Default)]
struct Screens(Mutex<Vec<ScreenFrame>>);

impl ScreenObserver for Screens {
    fn on_screen(&self, frame: ScreenFrame) {
        self.0.lock().expect("not poisoned").push(frame);
    }
}

/// Records every status the client publishes.
#[derive(Default)]
struct Recorder(Mutex<Vec<ConnectionStatus>>);

impl StateObserver for Recorder {
    fn on_state(&self, status: ConnectionStatus) {
        self.0.lock().expect("not poisoned").push(status);
    }
}

impl Recorder {
    fn phases(&self) -> Vec<ConnPhase> {
        self.0
            .lock()
            .expect("not poisoned")
            .iter()
            .map(|status| status.phase)
            .collect()
    }
}

/// Builds the QR payload a phone would scan.
fn qr(daemon: &DeviceIdentity, hint: &str, secret: &PairingSecret) -> String {
    PairingTicket {
        // The X25519 Noise static key, which is what the ticket actually carries
        // and what the IK initiator must know in advance.
        daemon_key: daemon.noise_public_key(),
        addr_hints: vec![hint.to_owned()],
        relay_hint: None,
    }
    .encode(secret)
}

#[tokio::test]
async fn connect_then_sys_info_then_list_a_directory() {
    let fixture = Fixture::new();
    let daemon = Arc::new(DeviceIdentity::generate());
    let stub = Stub::reconnect(&daemon, fixture.phone_noise_key, Behaviour::Full).await;
    fixture.remember(&daemon, &stub.hint());

    let client = fixture.client();
    let recorder = Arc::new(Recorder::default());
    client.observe_state(Arc::clone(&recorder) as Arc<dyn StateObserver>);

    client.connect().await.expect("connect");
    assert_eq!(client.status().phase, ConnPhase::Connected);
    assert_eq!(
        recorder.phases(),
        vec![ConnPhase::Connecting, ConnPhase::Connected],
        "the UI must see the intermediate state, or the spinner never appears"
    );

    let info = client.sys_info().await.expect("sys.info");
    assert_eq!(info.host_name, STUB_NAME);
    assert_eq!(info.shells, vec!["pwsh"]);

    let entries = client
        .list_dir(STUB_ROOT.to_owned())
        .await
        .expect("fs.list");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, "src");
    assert_eq!(entries[0].kind, EntryKind::Directory);
    assert_eq!(entries[1].size_bytes, Some(1234));

    // The roots come from the session's HelloOk, so they cannot disagree with
    // what this session was actually granted.
    assert_eq!(
        client.workspace_roots().await.expect("roots"),
        vec![STUB_ROOT.to_owned()]
    );

    let file = client
        .read_file(format!("{STUB_ROOT}/main.rs"))
        .await
        .expect("fs.read");
    assert_eq!(file.text, "fn main() {}");
    assert_eq!(file.content_hash, Digest::of(b"fn main() {}"));

    // Connecting recorded that the machine was reachable, so the pairing card
    // can say "last seen" without a round trip.
    let stored = fixture
        .storage
        .load_daemon()
        .expect("load")
        .expect("paired");
    assert!(stored.last_seen_ms.is_some());
}

#[tokio::test]
async fn many_requests_are_correlated_to_their_own_responses() {
    // The property the reader task exists for: a response must never be
    // delivered to the wrong caller.
    let fixture = Fixture::new();
    let daemon = Arc::new(DeviceIdentity::generate());
    let stub = Stub::reconnect(&daemon, fixture.phone_noise_key, Behaviour::Full).await;
    fixture.remember(&daemon, &stub.hint());

    let client = Arc::new(fixture.client());
    client.connect().await.expect("connect");

    // Spawned rather than awaited in turn, so the requests really are in flight
    // together and the reader task has to route them.
    let mut calls = Vec::new();
    for index in 0..8 {
        let client = Arc::clone(&client);
        calls.push(tokio::spawn(async move {
            client.list_dir(format!("{STUB_ROOT}/{index}")).await
        }));
    }
    for (index, call) in calls.into_iter().enumerate() {
        let entries = call
            .await
            .expect("the task ran")
            .expect("each call answered");
        assert_eq!(entries.len(), 2, "call {index} got the wrong response");
    }
}

#[tokio::test]
async fn a_request_that_is_never_answered_times_out() {
    // Without a deadline this future would stay pending forever, which the user
    // experiences as the app being broken rather than as a failure.
    let fixture = Fixture::new();
    let daemon = Arc::new(DeviceIdentity::generate());
    let stub = Stub::reconnect(&daemon, fixture.phone_noise_key, Behaviour::Silent).await;
    fixture.remember(&daemon, &stub.hint());

    let client = fixture.client();
    client.connect().await.expect("the hello still completes");

    let started = std::time::Instant::now();
    let outcome = client.list_dir(STUB_ROOT.to_owned()).await;
    assert!(
        matches!(outcome, Err(ClientError::Timeout)),
        "expected a timeout, got {outcome:?}"
    );
    assert!(
        started.elapsed() < TEST_TIMEOUT * 8,
        "the deadline was not honoured"
    );

    // The connection survives a timed-out request: one slow call must not cost
    // the session.
    assert_eq!(client.status().phase, ConnPhase::Connected);
}

#[tokio::test]
async fn an_unknown_method_surfaces_as_unsupported() {
    // Phone and daemon update independently, so skew is guaranteed. It has to
    // arrive as the version-skew signal rather than a generic failure (§24.7).
    let fixture = Fixture::new();
    let daemon = Arc::new(DeviceIdentity::generate());
    let stub = Stub::reconnect(&daemon, fixture.phone_noise_key, Behaviour::OnlySysInfo).await;
    fixture.remember(&daemon, &stub.hint());

    let client = fixture.client();
    client.connect().await.expect("connect");
    client.sys_info().await.expect("sys.info is implemented");

    match client.read_file("whatever".to_owned()).await {
        Err(ClientError::Remote(remote)) => match remote.kind {
            ErrorKind::Unsupported { feature, .. } => assert_eq!(feature, method::FS_READ),
            other => panic!("expected Unsupported, got {other:?}"),
        },
        other => panic!("expected a remote error, got {other:?}"),
    }
}

#[tokio::test]
async fn pairing_with_the_wrong_secret_persists_nothing() {
    // `ARCHITECTURE.md` §19 R24. With IKpsk2 the daemon completes its side of the
    // handshake even when the code is wrong, so this is the property that stops a
    // device that guessed nothing from ending up registered: the phone's AEAD
    // check fails, and the only writer of the daemon record is `confirm_pairing`.
    let fixture = Fixture::new();
    let daemon = Arc::new(DeviceIdentity::generate());
    let real_secret = PairingSecret::generate();
    let stub = Stub::pairing(&daemon, &real_secret, Behaviour::Full).await;

    // The scanned code carries a different secret: a photographed QR, a replayed
    // code, or a guess.
    let scanned = qr(&daemon, &stub.hint(), &PairingSecret::generate());

    let client = fixture.client();
    let outcome = client.begin_pairing(scanned).await;
    assert!(
        matches!(outcome, Err(ClientError::Transport(_))),
        "expected the handshake to fail, got {outcome:?}"
    );

    assert!(!client.is_paired());
    assert_eq!(client.paired_daemon(), None);
    assert_eq!(client.status().phase, ConnPhase::Unpaired);
    assert_eq!(fixture.storage.load_daemon().expect("load"), None);
    assert!(
        !fixture.storage.daemon_path().exists(),
        "a failed pairing must leave no record at all"
    );

    // And there is nothing left to commit afterwards.
    assert!(matches!(
        client.confirm_pairing("Pixel 9".to_owned()).await,
        Err(ClientError::NoPairingInProgress)
    ));
    assert!(!client.is_paired());

    // A second client over the same state directory agrees, so this is not just
    // an in-memory cache reporting what we want to hear.
    assert!(!fixture.client().is_paired());
    assert!(fixture.path().join("identity.key").is_file());
}

#[tokio::test]
async fn pairing_shows_the_sas_first_and_persists_only_after_registering() {
    let fixture = Fixture::new();
    let daemon = Arc::new(DeviceIdentity::generate());
    let secret = PairingSecret::generate();
    let stub = Stub::pairing(&daemon, &secret, Behaviour::Full).await;
    let client = fixture.client();

    let sas = client
        .begin_pairing(qr(&daemon, &stub.hint(), &secret))
        .await
        .expect("the handshake completes with the right secret");
    // Six digits, grouped three and three, as the UI shows them.
    assert_eq!(sas.len(), 7, "got {sas:?}");
    assert_eq!(
        sas.chars().filter(char::is_ascii_digit).count(),
        6,
        "got {sas:?}"
    );

    // Nothing is stored yet: the user has not confirmed the digits.
    assert!(!client.is_paired());
    assert_eq!(fixture.storage.load_daemon().expect("load"), None);

    client
        .confirm_pairing("Pixel 9".to_owned())
        .await
        .expect("registration round-trips");

    assert!(client.is_paired());
    let info = client.paired_daemon().expect("paired");
    // The stub only answers `sys.register` when the digits it derived match the
    // ones the phone sent, so reaching here proves both ends agreed.
    assert_eq!(info.name, STUB_NAME, "the name comes from sys.info");
    // The record names the machine, so its id is the machine's key. The id the
    // daemon assigned this phone is kept beside it, for the audit trail.
    assert_eq!(info.device_id, daemon.noise_public_key().to_hex());
    assert_eq!(info.registered_device_id, "f".repeat(64));
    assert_eq!(info.addr_hints, vec![stub.hint()]);
    assert_eq!(info.noise_key, daemon.noise_public_key());
    assert_eq!(client.status().phase, ConnPhase::Disconnected);
}

#[tokio::test]
async fn a_machine_that_refuses_to_register_leaves_nothing_stored() {
    // The other half of R24: the handshake succeeded, so a client that treated
    // that as success would be paired with a machine that declined it.
    let fixture = Fixture::new();
    let daemon = Arc::new(DeviceIdentity::generate());
    let secret = PairingSecret::generate();
    let stub = Stub::pairing(&daemon, &secret, Behaviour::RefuseRegister).await;
    let client = fixture.client();

    client
        .begin_pairing(qr(&daemon, &stub.hint(), &secret))
        .await
        .expect("the handshake completes");

    let outcome = client.confirm_pairing("Pixel 9".to_owned()).await;
    assert!(
        matches!(outcome, Err(ClientError::Remote(_))),
        "expected the machine's refusal, got {outcome:?}"
    );
    assert!(!client.is_paired());
    assert_eq!(fixture.storage.load_daemon().expect("load"), None);
}

#[tokio::test]
async fn a_spawned_terminal_pushes_frames_until_it_is_closed() {
    let fixture = Fixture::new();
    let daemon = Arc::new(DeviceIdentity::generate());
    let stub = Stub::reconnect(&daemon, fixture.phone_noise_key, Behaviour::Full).await;
    fixture.remember(&daemon, &stub.hint());

    let screens = Arc::new(Screens::default());

    let client = fixture.client();
    client.observe_screens(Arc::clone(&screens) as Arc<dyn ScreenObserver>);
    client.connect().await.expect("connect");

    let terminal = client.spawn_terminal(None).await.expect("pty.spawn");
    assert_eq!(terminal.pty_id, 7);
    assert!(
        !terminal.initial.rows.is_empty(),
        "the first frame ships with the spawn so a blank screen is distinguishable"
    );

    // The poller is a stopgap until the daemon pushes pty.output (M2), so what is
    // asserted is that frames arrive at all — not their cadence.
    let mut seen = 0;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        seen = screens.0.lock().expect("not poisoned").len();
        if seen >= 2 {
            break;
        }
    }
    assert!(seen >= 2, "the poller delivered {seen} frames");

    client.close_terminal(7).await.expect("pty.kill");
    let after_close = screens.0.lock().expect("not poisoned").len();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        screens.0.lock().expect("not poisoned").len(),
        after_close,
        "closing a terminal must stop its poller"
    );
}

#[tokio::test]
async fn disconnecting_reports_it_and_leaves_the_pairing_intact() {
    let fixture = Fixture::new();
    let daemon = Arc::new(DeviceIdentity::generate());
    let stub = Stub::reconnect(&daemon, fixture.phone_noise_key, Behaviour::Full).await;
    fixture.remember(&daemon, &stub.hint());

    let client = fixture.client();
    client.connect().await.expect("connect");
    client.disconnect();

    assert_eq!(client.status().phase, ConnPhase::Disconnected);
    assert!(client.is_paired());
    assert!(matches!(
        client.list_dir(STUB_ROOT.to_owned()).await,
        Err(ClientError::NotConnected)
    ));

    // Reconnecting works, which is what makes disconnect usable on a background
    // transition rather than a one-way door.
    client.connect().await.expect("reconnect");
    assert_eq!(client.status().phase, ConnPhase::Connected);
}

#[tokio::test]
async fn a_machine_that_hangs_up_is_noticed_and_the_state_corrected() {
    // What a daemon restart looks like from the phone. The reader task ends, every
    // waiting request is woken rather than left to its own deadline, and the state
    // reported to the UI stops claiming a connection that is gone.
    let fixture = Fixture::new();
    let daemon = Arc::new(DeviceIdentity::generate());
    let stub = Stub::reconnect(&daemon, fixture.phone_noise_key, Behaviour::HangUp).await;
    fixture.remember(&daemon, &stub.hint());

    let client = fixture.client();
    client
        .connect()
        .await
        .expect("the hello completes before the hang-up");

    let outcome = client.list_dir(STUB_ROOT.to_owned()).await;
    assert!(
        matches!(
            outcome,
            Err(ClientError::ConnectionLost
                | ClientError::Transport(_)
                | ClientError::NotConnected)
        ),
        "expected the connection to be reported as gone, got {outcome:?}"
    );
    assert_eq!(client.status().phase, ConnPhase::Disconnected);
    assert!(
        client.is_paired(),
        "a lost connection is not a lost pairing"
    );
}

#[tokio::test]
async fn unpairing_wipes_the_key_so_the_old_registration_cannot_be_reused() {
    let fixture = Fixture::new();
    let daemon = Arc::new(DeviceIdentity::generate());
    let stub = Stub::reconnect(&daemon, fixture.phone_noise_key, Behaviour::Full).await;
    fixture.remember(&daemon, &stub.hint());

    let client = fixture.client();
    client.connect().await.expect("connect");
    client.unpair().expect("unpair");

    assert!(!client.is_paired());
    assert_eq!(client.status().phase, ConnPhase::Unpaired);
    assert!(!fixture.path().join("identity.key").exists());
    assert!(!fixture.storage.daemon_path().exists());

    // A fresh client over the same directory gets a new key, which the stub's
    // allowlist does not admit.
    let replacement = fixture.client();
    assert_ne!(replacement.noise_key(), fixture.phone_noise_key);
    assert!(matches!(
        replacement.connect().await,
        Err(ClientError::NotPaired)
    ));
}

#[tokio::test]
async fn a_daemon_that_is_not_listening_reports_a_transport_failure() {
    let fixture = Fixture::new();
    let daemon = Arc::new(DeviceIdentity::generate());
    // A hint that points at nothing: what a stale address looks like after the
    // laptop changed network.
    fixture.remember(&daemon, "127.0.0.1:1");

    let client = fixture.client();
    let outcome = client.connect().await;
    assert!(
        matches!(outcome, Err(ClientError::Transport(_))),
        "expected a transport failure, got {outcome:?}"
    );
    assert_eq!(client.status().phase, ConnPhase::Disconnected);
    assert!(client.is_paired(), "an unreachable machine is still paired");
}
