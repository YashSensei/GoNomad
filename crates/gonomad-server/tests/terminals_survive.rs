//! Terminals must outlive the connection that created them.
//!
//! This is the product's central invariant (`ARCHITECTURE.md` §2) and the
//! feature users ask for first: switch away, lose signal, or have Android kill
//! the app, and the build you started keeps running.
//!
//! It cannot be checked from a unit test, because the whole claim is about what
//! survives a socket closing. So these tests stand up a real daemon, run a real
//! command in a real ConPTY, drop the connection, reconnect as the same device,
//! and assert the terminal is still there with its output intact.

use std::sync::Arc;
use std::time::Duration;

use gonomad_core::DeviceIdentity;
use gonomad_policy::{PathGuard, PolicyEngine, SecretDenylist, WorkspaceRoot};
use gonomad_proto::methods::{
    method, PtyIdParams, PtyInputParams, PtyListResult, PtySpawnParams, PtySpawnResult, ScreenFrame,
};
use gonomad_proto::{ControlMessage, Frame, FrameFlags, Request, Response, ResponseBody};
use gonomad_server::fs_service::FsService;
use gonomad_server::router::Daemon;
use gonomad_store::Store;
use gonomad_transport::{AddrHint, Allowlist, ClientConfig, PeerId, ServerConfig, TcpTransport};
use tempfile::TempDir;

/// A client that keeps one control stream open, as a real client does.
struct Client {
    _conn: gonomad_transport::TcpConnection,
    tx: gonomad_transport::SendStream,
    rx: gonomad_transport::RecvStream,
    next_id: u64,
}

impl Client {
    async fn connect(
        phone: Arc<DeviceIdentity>,
        daemon_key: gonomad_proto::PublicKey,
        addr: std::net::SocketAddr,
    ) -> Self {
        let transport =
            TcpTransport::client(ClientConfig::reconnect(phone)).expect("client transport");
        let conn = transport
            .connect_lan(
                PeerId::from_noise_key(daemon_key),
                &[AddrHint::Direct(addr)],
            )
            .await
            .expect("connect");
        let (tx, rx) = conn.open_bi().expect("control stream");
        Self {
            _conn: conn,
            tx,
            rx,
            next_id: 1,
        }
    }

    async fn call(&mut self, method_name: &str, params: &impl serde::Serialize) -> Response {
        let mut encoded = Vec::new();
        ciborium::into_writer(params, &mut encoded).expect("encode");

        let id = self.next_id;
        self.next_id += 1;

        let request = ControlMessage::Request(Request {
            correlation_id: id,
            method: method_name.to_owned(),
            params: encoded,
            idempotency_key: None,
            presence_signature: None,
        });
        self.tx
            .send(&Frame::cbor(FrameFlags::LAST, &request).expect("frame"))
            .await
            .expect("send");

        let frame = self.rx.recv().await.expect("recv").expect("a response");
        match frame.decode_cbor::<ControlMessage>().expect("decode") {
            ControlMessage::Response(r) => r,
            other => panic!("expected a Response, got {other:?}"),
        }
    }
}

fn ok_of<T: serde::de::DeserializeOwned>(response: &Response) -> T {
    match &response.body {
        ResponseBody::Ok { result } => {
            ciborium::from_reader(result.as_slice()).expect("decode result")
        }
        other => panic!("expected Ok, got {other:?}"),
    }
}

/// Stands up a daemon serving one paired device, returning its loopback address.
async fn daemon_for(
    phone: &DeviceIdentity,
    root: &std::path::Path,
    store: &Store,
) -> (
    Arc<DeviceIdentity>,
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
) {
    let identity = Arc::new(DeviceIdentity::generate());

    store
        .devices()
        .pair(
            &phone.noise_public_key(),
            "Test Phone",
            None,
            gonomad_proto::CapabilitySet::default_grant(),
        )
        .expect("pair");

    let guard = PathGuard::new(vec![WorkspaceRoot::new(root).expect("root")]);
    let services = Arc::new(Daemon {
        fs: FsService::new(PolicyEngine::new(guard, SecretDenylist::with_defaults())),
        // Shared across connections, which is the whole point.
        ptys: Arc::new(parking_lot::Mutex::new(
            gonomad_pty::PtyManager::with_limit(4),
        )),
        workspace_roots: vec![root.display().to_string()],
        host_name: "TEST-HOST".into(),
    });

    let policy = Arc::new(Allowlist::new(vec![phone.noise_public_key()]));
    let transport = TcpTransport::bind(
        "127.0.0.1:0".parse().expect("literal"),
        ServerConfig::reconnect(Arc::clone(&identity), policy),
    )
    .await
    .expect("bind");
    let addr = transport.local_addr().expect("bound");

    let grant = gonomad_policy::DeviceGrant::new(
        gonomad_proto::DeviceId::from_public_key(&phone.noise_public_key()),
        gonomad_proto::CapabilitySet::default_grant(),
    );

    // Accept connections for the life of the test. Each gets its own router but
    // they all share `services`, and therefore the same PtyManager.
    let handle = tokio::spawn(async move {
        loop {
            let Ok(conn) = transport.accept_lan().await else {
                continue;
            };
            let peer = conn.peer_key();
            let services = Arc::clone(&services);
            // DeviceGrant is Copy, so each connection gets its own by value.
            let grant = grant;
            tokio::spawn(async move {
                let mut router = gonomad_server::router::Router::established(services, peer, grant);
                let Ok((mut tx, mut rx)) = conn.accept_bi().await else {
                    return;
                };
                while let Ok(Some(frame)) = rx.recv().await {
                    let Ok(ControlMessage::Request(req)) = frame.decode_cbor() else {
                        break;
                    };
                    let (response, _) = router.handle(&req);
                    let out = ControlMessage::Response(response);
                    let Ok(encoded) = Frame::cbor(FrameFlags::LAST, &out) else {
                        break;
                    };
                    if tx.send(&encoded).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    (identity, addr, handle)
}

/// Polls a terminal's screen until `needle` appears, or gives up.
async fn wait_for_output(client: &mut Client, pty_id: u64, needle: &str) -> String {
    for _ in 0..120 {
        let screen: ScreenFrame = ok_of(
            &client
                .call(method::PTY_SCREEN, &PtyIdParams { pty_id })
                .await,
        );
        let text = screen.rows.join("\n");
        if text.contains(needle) {
            return text;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let screen: ScreenFrame = ok_of(
        &client
            .call(method::PTY_SCREEN, &PtyIdParams { pty_id })
            .await,
    );
    screen.rows.join("\n")
}

#[tokio::test]
async fn a_terminal_survives_the_connection_that_created_it() {
    let dir = TempDir::new().expect("tempdir");
    let root = dunce::canonicalize(dir.path()).expect("canonicalize");
    let state = TempDir::new().expect("state");
    let store = Store::open(state.path().join("gonomad.db")).expect("store");

    let phone = Arc::new(DeviceIdentity::generate());
    let (daemon_identity, addr, server) = daemon_for(&phone, &root, &store).await;

    // --- first session: start a terminal and run something -----------------
    let pty_id = {
        let mut client =
            Client::connect(Arc::clone(&phone), daemon_identity.noise_public_key(), addr).await;

        let spawned: PtySpawnResult = ok_of(
            &client
                .call(
                    method::PTY_SPAWN,
                    &PtySpawnParams {
                        cwd: Some(root.display().to_string()),
                        shell: None,
                        cols: 80,
                        rows: 24,
                    },
                )
                .await,
        );

        // The first frame arrives with the spawn, so a UI never renders blank.
        assert_eq!(spawned.initial.pty_id, spawned.pty_id);

        // Wait for a prompt, then leave a marker in the scrollback.
        wait_for_output(&mut client, spawned.pty_id, ">").await;
        let _: gonomad_proto::methods::Empty = ok_of(
            &client
                .call(
                    method::PTY_INPUT,
                    &PtyInputParams {
                        pty_id: spawned.pty_id,
                        data: "echo surviving-marker\r".into(),
                    },
                )
                .await,
        );
        let text = wait_for_output(&mut client, spawned.pty_id, "surviving-marker").await;
        assert!(
            text.contains("surviving-marker"),
            "marker never appeared:\n{text}"
        );

        spawned.pty_id
        // `client` drops here: the socket closes, exactly as it would when a
        // phone loses signal or Android kills the app.
    };

    // Give the daemon a moment to notice the peer went away.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // --- second session: the terminal is still there -----------------------
    let mut client =
        Client::connect(Arc::clone(&phone), daemon_identity.noise_public_key(), addr).await;

    let listed: PtyListResult = ok_of(&client.call(method::PTY_LIST, &()).await);
    assert!(
        listed.pty_ids.contains(&pty_id),
        "the terminal vanished when the connection dropped; pty.list returned {:?}",
        listed.pty_ids
    );

    // Reattaching returns the screen, marker and all — the daemon kept the
    // scrollback, so nothing had to be replayed over the wire.
    let screen: ScreenFrame = ok_of(
        &client
            .call(method::PTY_SCREEN, &PtyIdParams { pty_id })
            .await,
    );
    let text = screen.rows.join("\n");
    assert!(
        text.contains("surviving-marker"),
        "output from before the disconnect was lost:\n{text}"
    );

    // And it still accepts input, which is what makes it usable rather than a
    // read-only relic.
    let _: gonomad_proto::methods::Empty = ok_of(
        &client
            .call(
                method::PTY_INPUT,
                &PtyInputParams {
                    pty_id,
                    data: "echo second-session\r".into(),
                },
            )
            .await,
    );
    let text = wait_for_output(&mut client, pty_id, "second-session").await;
    assert!(
        text.contains("second-session"),
        "the reattached terminal is inert:\n{text}"
    );

    let _: gonomad_proto::methods::Empty =
        ok_of(&client.call(method::PTY_KILL, &PtyIdParams { pty_id }).await);
    server.abort();
}

#[tokio::test]
async fn several_terminals_survive_and_stay_independent() {
    // The multi-tab case: three terminals, one connection drop, all three still
    // running and still holding their own output.
    let dir = TempDir::new().expect("tempdir");
    let root = dunce::canonicalize(dir.path()).expect("canonicalize");
    let state = TempDir::new().expect("state");
    let store = Store::open(state.path().join("gonomad.db")).expect("store");

    let phone = Arc::new(DeviceIdentity::generate());
    let (daemon_identity, addr, server) = daemon_for(&phone, &root, &store).await;

    let mut ids = Vec::new();
    {
        let mut client =
            Client::connect(Arc::clone(&phone), daemon_identity.noise_public_key(), addr).await;

        for n in 0..3 {
            let spawned: PtySpawnResult = ok_of(
                &client
                    .call(
                        method::PTY_SPAWN,
                        &PtySpawnParams {
                            cwd: Some(root.display().to_string()),
                            shell: None,
                            cols: 80,
                            rows: 24,
                        },
                    )
                    .await,
            );
            wait_for_output(&mut client, spawned.pty_id, ">").await;
            let _: gonomad_proto::methods::Empty = ok_of(
                &client
                    .call(
                        method::PTY_INPUT,
                        &PtyInputParams {
                            pty_id: spawned.pty_id,
                            data: format!("echo tab-{n}-marker\r"),
                        },
                    )
                    .await,
            );
            wait_for_output(&mut client, spawned.pty_id, &format!("tab-{n}-marker")).await;
            ids.push(spawned.pty_id);
        }
        assert_eq!(ids.len(), 3);
    }

    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut client =
        Client::connect(Arc::clone(&phone), daemon_identity.noise_public_key(), addr).await;

    let listed: PtyListResult = ok_of(&client.call(method::PTY_LIST, &()).await);
    for id in &ids {
        assert!(listed.pty_ids.contains(id), "terminal {id} did not survive");
    }

    // Each tab still holds only its own output — no cross-talk.
    for (n, id) in ids.iter().enumerate() {
        let screen: ScreenFrame = ok_of(
            &client
                .call(method::PTY_SCREEN, &PtyIdParams { pty_id: *id })
                .await,
        );
        let text = screen.rows.join("\n");
        assert!(
            text.contains(&format!("tab-{n}-marker")),
            "tab {n} lost its output:\n{text}"
        );
        for other in 0..3 {
            if other != n {
                assert!(
                    !text.contains(&format!("tab-{other}-marker")),
                    "tab {n} shows tab {other}'s output"
                );
            }
        }
    }

    for id in ids {
        let _: gonomad_proto::methods::Empty = ok_of(
            &client
                .call(method::PTY_KILL, &PtyIdParams { pty_id: id })
                .await,
        );
    }
    server.abort();
}
