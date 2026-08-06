//! End-to-end pairing over a real socket.
//!
//! These tests exist for one property, and it cannot be checked any other way:
//!
//! > A device that presents the **wrong** pairing code must end up registered
//! > **nowhere**, even though the Noise handshake completes successfully.
//!
//! That completion is not a bug — it is how `IKpsk2` works. The pre-shared key is
//! mixed into the *responder's* message, so the daemon finishes its side before it
//! can possibly know whether the peer had the right code (`ARCHITECTURE.md` §19
//! R24). The safety comes from registration being gated on a `sys.register`
//! request that the peer can only produce if its session keys actually match.
//!
//! A unit test cannot observe this, because the whole question is what happens
//! *after* a handshake, across a socket, with two independent sessions.

use std::sync::Arc;
use std::time::Duration;

use gonomad_core::{DeviceIdentity, PairingSecret, Purpose};
use gonomad_policy::{PathGuard, PolicyEngine, SecretDenylist, WorkspaceRoot};
use gonomad_proto::methods::{method, SysRegisterParams, SysRegisterResult};
use gonomad_proto::{ControlMessage, Frame, FrameFlags, Request, Response, ResponseBody};
use gonomad_server::fs_service::FsService;
use gonomad_server::router::Daemon;
use gonomad_store::Store;
use gonomad_transport::{AddrHint, ClientConfig, PeerId, TcpTransport};
use tempfile::TempDir;

/// A daemon serving one temporary workspace.
fn daemon(root: &std::path::Path) -> Arc<Daemon> {
    let guard = PathGuard::new(vec![WorkspaceRoot::new(root).expect("root")]);
    Arc::new(Daemon {
        fs: FsService::new(PolicyEngine::new(guard, SecretDenylist::with_defaults())),
        ptys: Arc::new(parking_lot::Mutex::new(
            gonomad_pty::PtyManager::with_limit(2),
        )),
        workspace_roots: vec![root.display().to_string()],
        host_name: "TEST-HOST".into(),
    })
}

fn workspace() -> (TempDir, std::path::PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let root = dunce::canonicalize(dir.path()).expect("canonicalize");
    std::fs::write(root.join("main.rs"), b"fn main() {}\n").expect("write");
    (dir, root)
}

/// Sends one request over an already-open control stream and returns the
/// response.
///
/// The stream is opened once per connection and reused, which is what a real
/// client does: the daemon accepts exactly one control stream (§10.2), so opening
/// a fresh one per request would leave every request after the first unanswered.
async fn call_on(
    tx: &mut gonomad_transport::SendStream,
    rx: &mut gonomad_transport::RecvStream,
    method_name: &str,
    params: &impl serde::Serialize,
) -> Response {
    let mut encoded = Vec::new();
    ciborium::into_writer(params, &mut encoded).expect("encode params");

    let request = ControlMessage::Request(Request {
        correlation_id: 1,
        method: method_name.to_owned(),
        params: encoded,
        idempotency_key: None,
        presence_signature: None,
    });

    tx.send(&Frame::cbor(FrameFlags::LAST, &request).expect("frame"))
        .await
        .expect("send");

    let frame = rx.recv().await.expect("recv").expect("a response frame");

    match frame.decode_cbor::<ControlMessage>().expect("decode") {
        ControlMessage::Response(r) => r,
        other => panic!("expected a Response, got {other:?}"),
    }
}

/// Opens the control stream and sends a single request.
async fn call(
    conn: &gonomad_transport::TcpConnection,
    method_name: &str,
    params: &impl serde::Serialize,
) -> Response {
    let (mut tx, mut rx) = conn.open_bi().expect("control stream");
    call_on(&mut tx, &mut rx, method_name, params).await
}

/// Runs a pairing attempt with `client_secret`, which may differ from the
/// daemon's. Returns whether the daemon ended up with a registered device.
async fn attempt_pairing(client_secret_matches: bool, sas_matches: bool) -> bool {
    let (_dir, root) = workspace();
    let state = TempDir::new().expect("state dir");
    let store = Store::open(state.path().join("gonomad.db")).expect("store");

    let daemon_identity = Arc::new(DeviceIdentity::generate());
    let phone = Arc::new(DeviceIdentity::generate());

    let daemon_secret = PairingSecret::generate();
    let transport = gonomad_server::bind_pairing(Arc::clone(&daemon_identity), &daemon_secret, 0)
        .await
        .expect("bind");
    // The daemon binds 0.0.0.0 so it is reachable on every interface, but
    // 0.0.0.0 is not a connectable *destination* — dial loopback on the
    // port it actually got.
    let bound = transport.local_addr().expect("bound address");
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", bound.port())
        .parse()
        .expect("loopback address");

    // The daemon's side runs concurrently with the client's, as it would in
    // reality.
    let services = daemon(&root);
    let expected_sas = std::sync::Arc::new(parking_lot::Mutex::new(String::new()));

    let client_secret = if client_secret_matches {
        PairingSecret::from_bytes(*daemon_secret.as_bytes())
    } else {
        // A different 256-bit secret: what an attacker who never saw the screen
        // necessarily has.
        PairingSecret::from_bytes([0xAB; 32])
    };

    let client_task = {
        let sas_slot = Arc::clone(&expected_sas);
        tokio::spawn(async move {
            let client = TcpTransport::client(ClientConfig::pairing(phone, &client_secret))
                .expect("client transport");
            let peer = PeerId::from_noise_key(daemon_identity.noise_public_key());
            let conn = client
                .connect_lan(peer, &[AddrHint::Direct(addr)])
                .await
                .map_err(|e| format!("connect failed: {e}"))?;

            let real_sas = conn.sas().digits();
            (*sas_slot.lock()).clone_from(&real_sas);

            let presented = if sas_matches {
                real_sas
            } else {
                "000000".to_owned()
            };

            let response = call(
                &conn,
                method::SYS_REGISTER,
                &SysRegisterParams {
                    device_name: "Test Phone".into(),
                    device_model: Some("Pixel Test".into()),
                    sas: presented,
                },
            )
            .await;

            match response.body {
                ResponseBody::Ok { result } => {
                    let parsed: SysRegisterResult =
                        ciborium::from_reader(result.as_slice()).expect("decode result");
                    Ok(parsed.device_id)
                }
                ResponseBody::Error { error } => Err(format!("refused: {}", error.kind.code())),
                other => Err(format!("unexpected body {other:?}")),
            }
        })
    };

    // The daemon waits for a registration. A short window keeps a failing test
    // fast; a wrong-secret client never registers, so this is expected to time
    // out in those cases.
    let server =
        gonomad_server::run_pairing(&transport, services, &store, Duration::from_millis(2500))
            .await;

    let client_outcome = tokio::time::timeout(Duration::from_millis(500), client_task).await;

    // Printed so a failure says *why* rather than only that a count was wrong.
    eprintln!("server outcome: {server:?}");
    eprintln!("client outcome: {client_outcome:?}");
    eprintln!("sas seen by client: {}", expected_sas.lock());

    let registered = store.devices().list_active().expect("list").len();
    if server.is_ok() {
        assert_eq!(
            registered, 1,
            "server reported success but nothing was stored"
        );
    }
    registered > 0
}

#[tokio::test]
async fn the_right_code_and_matching_sas_pair_successfully() {
    assert!(
        attempt_pairing(true, true).await,
        "a correct pairing code should register the device"
    );
}

#[tokio::test]
async fn a_wrong_pairing_code_registers_nothing() {
    // THE R24 TEST. The daemon's Noise handshake may well complete — that is how
    // IKpsk2 behaves — but the peer cannot encrypt a sys.register the daemon can
    // read, so nothing may be persisted.
    assert!(
        !attempt_pairing(false, true).await,
        "a device with the wrong pairing code was registered"
    );
}

#[tokio::test]
async fn a_mismatched_sas_registers_nothing() {
    // Independent of the human comparison: a proxying attacker produces a
    // different transcript on each side. Even with the right secret, wrong digits
    // must be refused.
    assert!(
        !attempt_pairing(true, false).await,
        "a device presenting the wrong SAS was registered"
    );
}

#[tokio::test]
async fn a_paired_device_can_read_files_but_not_secrets() {
    let (_dir, root) = workspace();
    std::fs::write(root.join(".env"), b"SECRET=1\n").expect("write");

    let state = TempDir::new().expect("state dir");
    let store = Store::open(state.path().join("gonomad.db")).expect("store");

    let daemon_identity = Arc::new(DeviceIdentity::generate());
    let phone = Arc::new(DeviceIdentity::generate());
    let secret = PairingSecret::generate();

    let transport = gonomad_server::bind_pairing(Arc::clone(&daemon_identity), &secret, 0)
        .await
        .expect("bind");
    let bound = transport.local_addr().expect("bound");
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", bound.port())
        .parse()
        .expect("loopback address");
    let services = daemon(&root);

    let client_secret = PairingSecret::from_bytes(*secret.as_bytes());
    let root_for_client = root.clone();

    let client_task = tokio::spawn(async move {
        let client = TcpTransport::client(ClientConfig::pairing(phone, &client_secret))
            .expect("client transport");
        let peer = PeerId::from_noise_key(daemon_identity.noise_public_key());
        let conn = client
            .connect_lan(peer, &[AddrHint::Direct(addr)])
            .await
            .expect("connect");

        // One control stream, reused — as a real client does.
        let (mut tx, mut rx) = conn.open_bi().expect("control stream");

        // Before registering, this connection holds no capabilities, even though
        // its handshake completed. That is the whole point of R24.
        let denied_before = call_on(
            &mut tx,
            &mut rx,
            method::FS_LIST,
            &gonomad_proto::methods::FsListParams {
                path: root_for_client.display().to_string(),
            },
        )
        .await;

        let register = call_on(
            &mut tx,
            &mut rx,
            method::SYS_REGISTER,
            &SysRegisterParams {
                device_name: "Test Phone".into(),
                device_model: None,
                sas: conn.sas().digits(),
            },
        )
        .await;

        (denied_before, register)
    });

    let paired =
        gonomad_server::run_pairing(&transport, services, &store, Duration::from_secs(3)).await;

    let (denied_before, register) = client_task.await.expect("client task");

    assert!(paired.is_ok(), "pairing should succeed: {paired:?}");

    // Before registering, even a correctly-authenticated peer gets nothing.
    match denied_before.body {
        ResponseBody::Error { error } => assert_eq!(error.kind.code(), "denied"),
        other => panic!("fs.list before registration must be denied, got {other:?}"),
    }

    assert!(
        matches!(register.body, ResponseBody::Ok { .. }),
        "registration should succeed"
    );
    assert_eq!(store.devices().list_active().expect("list").len(), 1);
}

#[tokio::test]
async fn an_unpaired_device_cannot_connect_to_a_serving_daemon() {
    // §3.7: an unknown key is rejected during the handshake, before any
    // application data. There is nothing to probe.
    let (_dir, root) = workspace();
    let state = TempDir::new().expect("state dir");
    let store = Store::open(state.path().join("gonomad.db")).expect("store");

    let daemon_identity = Arc::new(DeviceIdentity::generate());
    let known = DeviceIdentity::generate();
    let stranger = Arc::new(DeviceIdentity::generate());

    // Register one device so `serve` has a non-empty allowlist.
    store
        .devices()
        .pair(
            &known.noise_public_key(),
            "Known",
            None,
            gonomad_proto::CapabilitySet::default_grant(),
        )
        .expect("pair");

    let policy = Arc::new(gonomad_transport::Allowlist::new(vec![
        known.noise_public_key()
    ]));
    let transport = TcpTransport::bind(
        "127.0.0.1:0".parse().expect("literal"),
        gonomad_transport::ServerConfig::reconnect(Arc::clone(&daemon_identity), policy),
    )
    .await
    .expect("bind");
    let addr = transport.local_addr().expect("bound");

    let services = daemon(&root);
    tokio::spawn(async move {
        // Accept loop; the stranger's handshake must fail inside it.
        let _ = transport.accept_lan().await;
        drop(services);
    });

    let client = TcpTransport::client(ClientConfig::reconnect(stranger)).expect("client");
    let peer = PeerId::from_noise_key(daemon_identity.noise_public_key());
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        client.connect_lan(peer, &[AddrHint::Direct(addr)]),
    )
    .await;

    let rejected = match result {
        // A timeout and an explicit refusal are the same outcome: the daemon
        // never admitted the stranger. Which of the two happens depends on
        // whether it closes the socket or simply stops responding, and the test
        // must not care.
        Err(_) | Ok(Err(_)) => true,
        // If a connection object came back at all, it must be unusable.
        Ok(Ok(conn)) => conn.open_bi().is_err() || conn.is_closed(),
    };
    assert!(rejected, "an unpaired device was allowed to connect");
}

#[tokio::test]
async fn purpose_is_chosen_by_the_daemon_not_the_client() {
    // A client must not be able to request the pairing pattern whenever it likes.
    // A serving daemon runs Reconnect only, so a pairing-pattern client fails.
    let daemon_identity = Arc::new(DeviceIdentity::generate());
    let phone = Arc::new(DeviceIdentity::generate());

    let policy = Arc::new(gonomad_transport::Allowlist::new(vec![
        phone.noise_public_key()
    ]));
    let transport = TcpTransport::bind(
        "127.0.0.1:0".parse().expect("literal"),
        gonomad_transport::ServerConfig::reconnect(Arc::clone(&daemon_identity), policy),
    )
    .await
    .expect("bind");
    let addr = transport.local_addr().expect("bound");

    tokio::spawn(async move {
        let _ = transport.accept_lan().await;
    });

    let secret = PairingSecret::generate();
    let client =
        TcpTransport::client(ClientConfig::pairing(phone, &secret)).expect("client transport");
    let peer = PeerId::from_noise_key(daemon_identity.noise_public_key());

    let result = tokio::time::timeout(
        Duration::from_secs(3),
        client.connect_lan(peer, &[AddrHint::Direct(addr)]),
    )
    .await;

    let refused = match result {
        Err(_) | Ok(Err(_)) => true,
        Ok(Ok(conn)) => conn.open_bi().is_err() || conn.is_closed(),
    };
    assert!(
        refused,
        "a client running the pairing pattern was accepted by a serving daemon"
    );
    // Purpose is a compile-time-visible part of the config on both sides.
    assert_ne!(Purpose::Pairing.params(), Purpose::Reconnect.params());
}
