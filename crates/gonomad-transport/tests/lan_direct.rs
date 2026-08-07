//! End-to-end tests for Tier 0 over real loopback sockets.
//!
//! Every test here binds `127.0.0.1:0`, runs a genuine Noise IK handshake across
//! a real TCP connection, and exchanges real frames. Nothing is mocked, because
//! the failures worth catching in a transport — a half-read frame, a peer that
//! vanishes, a handshake that authenticates the wrong key — are exactly the ones
//! a mock socket cannot produce.
//!
//! Several tests drive the wire format by hand rather than through
//! [`gonomad_transport::TcpTransport`]. That is deliberate: it makes them
//! *conformance* tests. If the documented framing in `tcp.rs` and `mux.rs` ever
//! stops matching the implementation, these break.

use std::sync::Arc;
use std::time::{Duration, Instant};

use gonomad_core::{DeviceIdentity, Handshake, PairingSecret, Purpose, Session};
use gonomad_proto::{Frame, FrameFlags, PublicKey};
use gonomad_transport::mux::{RECORD_PREFIX_LEN, SEGMENT_HEADER_LEN};
use gonomad_transport::{
    AddrHint, Allowlist, ClientConfig, MuxConfig, PeerId, ServerConfig, TcpConnection,
    TcpTransport, TransportError, CONTROL_STREAM,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Segment kinds, restated here rather than imported.
///
/// These are private to the multiplexer on purpose — nothing outside it should
/// build a segment. Restating the numbers is what makes the hand-rolled tests
/// below a check on the documented wire format instead of a tautology.
const KIND_OPEN: u8 = 0;
const KIND_DATA: u8 = 1;

/// A generous ceiling for any single await in these tests.
///
/// Present so a regression that deadlocks fails the suite in seconds instead of
/// hanging CI until it is killed with no useful output.
const PATIENCE: Duration = Duration::from_secs(10);

fn identity() -> Arc<DeviceIdentity> {
    Arc::new(DeviceIdentity::generate())
}

fn loopback() -> std::net::SocketAddr {
    "127.0.0.1:0".parse().expect("literal address")
}

fn frame(payload: &[u8]) -> Frame {
    Frame::new(FrameFlags::NONE, payload.to_vec()).expect("frame within limits")
}

/// Binds a daemon that accepts reconnects from exactly `allowed`.
async fn bind_reconnect(daemon: &Arc<DeviceIdentity>, allowed: Vec<PublicKey>) -> TcpTransport {
    let policy = Arc::new(Allowlist::new(allowed));
    TcpTransport::bind(
        loopback(),
        ServerConfig::reconnect(Arc::clone(daemon), policy),
    )
    .await
    .expect("bind")
}

/// Dials `server` as `phone`, using the given client configuration.
async fn dial(
    phone_config: ClientConfig,
    daemon: &Arc<DeviceIdentity>,
    server: &TcpTransport,
) -> Result<TcpConnection, TransportError> {
    let client = TcpTransport::client(phone_config).expect("client transport");
    let peer = PeerId::from_noise_key(daemon.noise_public_key());
    let hints = [AddrHint::Direct(server.local_addr().expect("bound"))];
    client.connect_lan(peer, &hints).await
}

/// Awaits `future`, failing the test rather than hanging if it stalls.
async fn within<F: std::future::Future>(what: &str, future: F) -> F::Output {
    let Ok(value) = tokio::time::timeout(PATIENCE, future).await else {
        panic!("{what} did not finish within {PATIENCE:?}")
    };
    value
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_paired_device_reconnects_and_exchanges_frames_both_ways() {
    let daemon = identity();
    let phone = identity();
    let server = bind_reconnect(&daemon, vec![phone.noise_public_key()]).await;

    let client_conn = dial(
        ClientConfig::reconnect(Arc::clone(&phone)),
        &daemon,
        &server,
    )
    .await
    .expect("reconnect");
    let server_conn = within("accept", server.accept_lan()).await.expect("accept");

    // Each side authenticated the other's Noise static key, which is the whole
    // credential: no tokens, no cookies (§3.2).
    assert_eq!(client_conn.peer_key(), daemon.noise_public_key());
    assert_eq!(server_conn.peer_key(), phone.noise_public_key());

    let (mut ctx, mut crx) = client_conn.open_bi().expect("open control stream");
    assert_eq!(ctx.id(), CONTROL_STREAM, "the first stream is control");
    ctx.send(&frame(b"fs.read src/main.rs"))
        .await
        .expect("client send");

    let (mut stx, mut srx) = within("accept_bi", server_conn.accept_bi())
        .await
        .expect("accept stream");
    let got = within("server recv", srx.recv())
        .await
        .expect("recv")
        .expect("frame");
    assert_eq!(got.payload, b"fs.read src/main.rs");

    stx.send(&frame(b"fn main() {}"))
        .await
        .expect("server send");
    let back = within("client recv", crx.recv())
        .await
        .expect("recv")
        .expect("frame");
    assert_eq!(back.payload, b"fn main() {}");
}

#[tokio::test]
async fn a_first_time_pairing_completes_with_the_qr_secret() {
    let daemon = identity();
    let phone = identity();
    let secret = PairingSecret::generate();

    // The pairing window: the daemon runs IKpsk2 and admits any key, because
    // the peer's key is by definition not yet known (§9.2).
    let server = TcpTransport::bind(
        loopback(),
        ServerConfig::pairing(Arc::clone(&daemon), &secret),
    )
    .await
    .expect("bind pairing listener");

    let client_conn = dial(
        ClientConfig::pairing(Arc::clone(&phone), &secret),
        &daemon,
        &server,
    )
    .await
    .expect("pairing handshake");
    let server_conn = within("accept", server.accept_lan()).await.expect("accept");

    // Both sides must derive the same six digits, or the human comparison that
    // detects a man-in-the-middle is impossible.
    assert_eq!(client_conn.sas(), server_conn.sas());
    assert_eq!(
        client_conn.channel_binding(),
        server_conn.channel_binding(),
        "the channel binding must agree, or a presence signature cannot be bound to the session"
    );
    assert_eq!(server_conn.peer_key(), phone.noise_public_key());
}

#[tokio::test]
async fn pairing_with_the_wrong_secret_is_refused() {
    // Knowing the daemon's public key is not enough. The key is not secret; the
    // 256-bit QR secret is what proves the phone actually saw the screen.
    let daemon = identity();
    let phone = identity();
    let server = TcpTransport::bind(
        loopback(),
        ServerConfig::pairing(Arc::clone(&daemon), &PairingSecret::generate()),
    )
    .await
    .expect("bind pairing listener");

    let result = dial(
        ClientConfig::pairing(Arc::clone(&phone), &PairingSecret::generate()),
        &daemon,
        &server,
    )
    .await;
    assert_eq!(result.err(), Some(TransportError::HandshakeFailed));

    // IKpsk2 mixes the secret into the responder's message, so the daemon
    // cannot detect the mismatch and may hold a half-open session (see the
    // `tcp` module docs). It must be unusable: the keys disagree, so the first
    // record fails to authenticate.
    if let Ok(Ok(conn)) =
        tokio::time::timeout(Duration::from_millis(300), server.accept_lan()).await
    {
        let outcome = within("recv on a mismatched session", conn.accept_bi()).await;
        assert!(
            outcome.is_err(),
            "a session built on a mismatched PSK must carry no data"
        );
    }
}

#[tokio::test]
async fn an_unpaired_device_is_dropped_before_it_learns_anything() {
    let daemon = identity();
    let stranger = identity();
    let paired = identity();
    // The allowlist knows about `paired`, not about `stranger`.
    let server = bind_reconnect(&daemon, vec![paired.noise_public_key()]).await;

    let result = dial(
        ClientConfig::reconnect(Arc::clone(&stranger)),
        &daemon,
        &server,
    )
    .await;
    assert!(result.is_err(), "an unpaired key must not connect");

    // And the daemon never surfaces the attempt as a connection, so no request
    // handler and no session ever exists for it (§3.7).
    assert!(
        tokio::time::timeout(Duration::from_millis(300), server.accept_lan())
            .await
            .is_err(),
        "a rejected peer must not appear as an accepted connection"
    );

    // The listener is still healthy afterwards.
    dial(
        ClientConfig::reconnect(Arc::clone(&paired)),
        &daemon,
        &server,
    )
    .await
    .expect("a paired device still connects");
}

#[tokio::test]
async fn dialling_the_wrong_daemon_key_fails() {
    // A phone that scanned one laptop's QR must not authenticate to another.
    let daemon = identity();
    let impostor = identity();
    let phone = identity();
    let server = bind_reconnect(&daemon, vec![phone.noise_public_key()]).await;

    let client = TcpTransport::client(ClientConfig::reconnect(Arc::clone(&phone))).expect("client");
    let peer = PeerId::from_noise_key(impostor.noise_public_key());
    let hints = [AddrHint::Direct(server.local_addr().expect("bound"))];
    assert!(client.connect_lan(peer, &hints).await.is_err());
}

#[tokio::test]
async fn a_lan_connection_reports_tier_zero_and_measures_its_round_trip() {
    let daemon = identity();
    let phone = identity();
    let server = bind_reconnect(&daemon, vec![phone.noise_public_key()]).await;
    let conn = dial(
        ClientConfig::reconnect(Arc::clone(&phone)),
        &daemon,
        &server,
    )
    .await
    .expect("connect");

    let info = conn.path_info();
    assert_eq!(info.tier, gonomad_transport::Tier::Lan);
    assert!(!info.relayed, "Tier 0 is never relayed");
    assert!(
        info.rtt_ms.is_some(),
        "the initiator measures the handshake round trip"
    );
}

// ---------------------------------------------------------------------------
// Multiplexing and flow control
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_large_transfer_cannot_starve_the_control_channel() {
    // The property the credit scheme exists for (§10.6). The daemon deliberately
    // drains the bulk channel slowly, so the bulk sender spends most of its time
    // parked waiting for credit. Control traffic must keep flowing throughout —
    // if it did not, a file download would freeze the terminal.
    let daemon = identity();
    let phone = identity();
    let server = bind_reconnect(&daemon, vec![phone.noise_public_key()]).await;

    let client_conn = dial(
        ClientConfig::reconnect(Arc::clone(&phone)),
        &daemon,
        &server,
    )
    .await
    .expect("connect");
    let server_conn = within("accept", server.accept_lan()).await.expect("accept");

    let (mut control_tx, mut control_rx) = client_conn.open_bi().expect("control");
    let (mut bulk_tx, _bulk_rx) = client_conn.open_bi().expect("bulk");
    assert_eq!(control_tx.id(), CONTROL_STREAM);
    assert_ne!(bulk_tx.id(), CONTROL_STREAM);

    // Channels arrive in the order they were opened.
    let (mut server_control_tx, mut server_control_rx) =
        within("accept control", server_conn.accept_bi())
            .await
            .expect("accept control");
    let (_server_bulk_tx, mut server_bulk_rx) = within("accept bulk", server_conn.accept_bi())
        .await
        .expect("accept bulk");
    assert_eq!(server_control_tx.id(), CONTROL_STREAM);

    // The daemon echoes control frames immediately...
    let echo = tokio::spawn(async move {
        while let Ok(Some(got)) = server_control_rx.recv().await {
            if server_control_tx.send(&got).await.is_err() {
                break;
            }
        }
    });

    // ...and drains the bulk channel at a crawl. Because credit is only
    // returned when a frame is consumed, this parks the client's bulk sender
    // for most of the test.
    let bulk_reader = tokio::spawn(async move {
        let mut seen = 0usize;
        while let Ok(Some(_got)) = server_bulk_rx.recv().await {
            seen += 1;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        seen
    });

    let payload = vec![0x5Au8; 200_000];
    let bulk_sender = tokio::spawn(async move {
        for _ in 0..40 {
            if bulk_tx.send(&frame(&payload)).await.is_err() {
                break;
            }
        }
    });

    // Ten control round trips, while roughly 8 MB is queued behind a consumer
    // that accepts 200 KB every 50 ms.
    let started = Instant::now();
    for i in 0..10u8 {
        control_tx.send(&frame(&[i])).await.expect("control send");
        let echoed = within("control echo", control_rx.recv())
            .await
            .expect("recv")
            .expect("frame");
        assert_eq!(echoed.payload, vec![i]);
    }
    let control_time = started.elapsed();

    assert!(
        !bulk_sender.is_finished(),
        "the bulk transfer finished too quickly for this test to prove anything"
    );
    assert!(
        control_time < Duration::from_secs(3),
        "control traffic was starved by the bulk transfer: {control_time:?} for 10 round trips"
    );

    bulk_sender.abort();
    bulk_reader.abort();
    echo.abort();
}

// ---------------------------------------------------------------------------
// Hostile and abrupt peers
// ---------------------------------------------------------------------------

/// Writes one length-prefixed handshake message, exactly as `tcp.rs` documents.
async fn write_prefixed(sock: &mut TcpStream, message: &[u8]) {
    let len = u16::try_from(message.len()).expect("noise messages fit in u16");
    sock.write_all(&len.to_be_bytes()).await.expect("write len");
    sock.write_all(message).await.expect("write body");
    sock.flush().await.expect("flush");
}

/// Reads one length-prefixed handshake message.
async fn read_prefixed(sock: &mut TcpStream, buf: &mut [u8]) -> usize {
    let mut prefix = [0u8; RECORD_PREFIX_LEN];
    sock.read_exact(&mut prefix).await.expect("read len");
    let len = usize::from(u16::from_be_bytes(prefix));
    sock.read_exact(&mut buf[..len]).await.expect("read body");
    len
}

/// Builds one mux segment: `channel: u32 BE | kind: u8 | body`.
fn segment(channel: u32, kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SEGMENT_HEADER_LEN + body.len());
    out.extend_from_slice(&channel.to_be_bytes());
    out.push(kind);
    out.extend_from_slice(body);
    out
}

/// Seals a segment into a record, returning `len prefix ‖ ciphertext`.
fn record(session: &mut Session, plaintext: &[u8]) -> Vec<u8> {
    let mut ciphertext = vec![0u8; plaintext.len() + 16];
    let written = session
        .encrypt(plaintext, &mut ciphertext)
        .expect("encrypt");
    let len = u16::try_from(written).expect("record fits in u16");
    let mut out = len.to_be_bytes().to_vec();
    out.extend_from_slice(&ciphertext[..written]);
    out
}

/// Completes the initiator handshake by hand and returns the raw socket.
async fn raw_client(
    addr: std::net::SocketAddr,
    phone: &DeviceIdentity,
    daemon_key: &PublicKey,
) -> (TcpStream, Session) {
    let mut sock = TcpStream::connect(addr).await.expect("connect");
    let mut handshake =
        Handshake::initiator(phone, daemon_key, Purpose::Reconnect, None).expect("initiator");
    let mut buf = vec![0u8; 65535];
    let mut scratch = vec![0u8; 65535];

    let len = handshake.write_message(&[], &mut buf).expect("msg1");
    write_prefixed(&mut sock, &buf[..len]).await;
    let len = read_prefixed(&mut sock, &mut buf).await;
    handshake
        .read_message(&buf[..len], &mut scratch)
        .expect("msg2");

    let session = handshake.into_session().expect("session");
    (sock, session)
}

#[tokio::test]
async fn a_peer_that_vanishes_mid_frame_is_reported_as_a_lost_connection() {
    let daemon = identity();
    let phone = identity();
    let server = bind_reconnect(&daemon, vec![phone.noise_public_key()]).await;
    let addr = server.local_addr().expect("bound");

    let (mut sock, mut session) = raw_client(addr, &phone, &daemon.noise_public_key()).await;

    // Open channel 0 and start a 4 KiB frame, then cut the socket in the middle
    // of a record. This is what a phone walking out of Wi-Fi range looks like.
    sock.write_all(&record(&mut session, &segment(0, KIND_OPEN, &[])))
        .await
        .expect("open");
    let payload = frame(&vec![7u8; 4096]).encode();
    sock.write_all(&record(
        &mut session,
        &segment(0, KIND_DATA, &payload[..100]),
    ))
    .await
    .expect("first chunk");

    let truncated = record(&mut session, &segment(0, KIND_DATA, &payload[100..]));
    let half = truncated.len() / 2;
    sock.write_all(&truncated[..half]).await.expect("half");
    sock.flush().await.expect("flush");
    drop(sock);

    let conn = within("accept", server.accept_lan()).await.expect("accept");
    let (_tx, mut rx) = within("accept_bi", conn.accept_bi())
        .await
        .expect("accept stream");
    let outcome = within("recv", rx.recv()).await;
    assert_eq!(
        outcome.err(),
        Some(TransportError::ConnectionLost),
        "a truncated record must be reported, not silently treated as a clean end"
    );
}

#[tokio::test]
async fn a_clean_disconnect_ends_the_stream_without_an_error() {
    // The contrast to the test above: a peer that closes on a record boundary
    // finished, and the caller must be able to tell the two apart.
    let daemon = identity();
    let phone = identity();
    let server = bind_reconnect(&daemon, vec![phone.noise_public_key()]).await;

    let client_conn = dial(
        ClientConfig::reconnect(Arc::clone(&phone)),
        &daemon,
        &server,
    )
    .await
    .expect("connect");
    let (mut tx, _rx) = client_conn.open_bi().expect("open");
    tx.send(&frame(b"bye")).await.expect("send");

    let server_conn = within("accept", server.accept_lan()).await.expect("accept");
    let (_stx, mut srx) = within("accept_bi", server_conn.accept_bi())
        .await
        .expect("accept stream");
    assert_eq!(
        within("recv", srx.recv())
            .await
            .expect("recv")
            .expect("frame")
            .payload,
        b"bye"
    );

    drop(tx);
    drop(client_conn);
    assert_eq!(
        within("recv after close", srx.recv()).await,
        Ok(None),
        "a clean close is not an error"
    );
}

#[tokio::test]
async fn garbage_before_the_handshake_does_not_disturb_the_listener() {
    let daemon = identity();
    let phone = identity();
    let server = bind_reconnect(&daemon, vec![phone.noise_public_key()]).await;
    let addr = server.local_addr().expect("bound");

    // A port scanner, a TLS client hello, and a truncated length prefix. None
    // may panic the daemon or leave the listener wedged.
    for probe in [
        vec![0x00u8],
        vec![0xFF, 0xFF],
        b"GET / HTTP/1.1\r\n\r\n".to_vec(),
        vec![0x16, 0x03, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5],
    ] {
        let mut sock = TcpStream::connect(addr).await.expect("connect");
        sock.write_all(&probe).await.expect("write probe");
        drop(sock);
    }

    dial(
        ClientConfig::reconnect(Arc::clone(&phone)),
        &daemon,
        &server,
    )
    .await
    .expect("the listener still works after being probed");
}

#[tokio::test]
async fn a_frame_larger_than_the_channel_limit_tears_the_connection_down() {
    // Claiming a huge frame is how a peer would try to make the daemon buffer
    // without bound. The declared length is checked before the bytes arrive.
    let daemon = identity();
    let phone = identity();
    let server = bind_reconnect(&daemon, vec![phone.noise_public_key()]).await;
    let addr = server.local_addr().expect("bound");

    let (mut sock, mut session) = raw_client(addr, &phone, &daemon.noise_public_key()).await;
    sock.write_all(&record(&mut session, &segment(0, KIND_OPEN, &[])))
        .await
        .expect("open");

    // A frame header declaring far more than MuxConfig::max_frame_len, followed
    // by nothing at all.
    let mut header = u32::try_from(MuxConfig::default().max_frame_len + 1)
        .expect("fits")
        .to_be_bytes()
        .to_vec();
    header.push(0);
    sock.write_all(&record(&mut session, &segment(0, KIND_DATA, &header)))
        .await
        .expect("oversized header");
    sock.flush().await.expect("flush");

    let conn = within("accept", server.accept_lan()).await.expect("accept");
    let (_tx, mut rx) = within("accept_bi", conn.accept_bi())
        .await
        .expect("accept stream");
    let outcome = within("recv", rx.recv()).await;
    assert!(
        matches!(outcome, Err(TransportError::Protocol(_))),
        "expected a protocol violation, got {outcome:?}"
    );
    drop(sock);
}

#[tokio::test]
async fn a_peer_using_the_wrong_channel_parity_is_rejected() {
    // Channel ids are split by parity so both sides can allocate without
    // negotiating. A peer that ignores it is trying to collide with an id we
    // allocated.
    let daemon = identity();
    let phone = identity();
    let server = bind_reconnect(&daemon, vec![phone.noise_public_key()]).await;
    let addr = server.local_addr().expect("bound");

    let (mut sock, mut session) = raw_client(addr, &phone, &daemon.noise_public_key()).await;
    // The initiator owns even ids; 1 belongs to the responder.
    sock.write_all(&record(&mut session, &segment(1, KIND_OPEN, &[])))
        .await
        .expect("bad open");
    sock.flush().await.expect("flush");

    let conn = within("accept", server.accept_lan()).await.expect("accept");
    let outcome = within("accept_bi", conn.accept_bi()).await;
    assert!(
        matches!(outcome, Err(TransportError::Protocol(_))),
        "expected a protocol violation, got {:?}",
        outcome.map(|_| "a stream")
    );
    drop(sock);
}

#[tokio::test]
async fn an_unknown_segment_kind_is_rejected_rather_than_skipped() {
    let daemon = identity();
    let phone = identity();
    let server = bind_reconnect(&daemon, vec![phone.noise_public_key()]).await;
    let addr = server.local_addr().expect("bound");

    let (mut sock, mut session) = raw_client(addr, &phone, &daemon.noise_public_key()).await;
    sock.write_all(&record(&mut session, &segment(0, 0xEE, &[1, 2, 3])))
        .await
        .expect("unknown kind");
    sock.flush().await.expect("flush");

    let conn = within("accept", server.accept_lan()).await.expect("accept");
    let outcome = within("accept_bi", conn.accept_bi()).await;
    assert!(matches!(outcome, Err(TransportError::Protocol(_))));
    drop(sock);
}

#[tokio::test]
async fn a_tampered_record_is_detected_and_ends_the_connection() {
    let daemon = identity();
    let phone = identity();
    let server = bind_reconnect(&daemon, vec![phone.noise_public_key()]).await;
    let addr = server.local_addr().expect("bound");

    let (mut sock, mut session) = raw_client(addr, &phone, &daemon.noise_public_key()).await;
    let mut bad = record(&mut session, &segment(0, KIND_OPEN, &[]));
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    sock.write_all(&bad).await.expect("tampered record");
    sock.flush().await.expect("flush");

    let conn = within("accept", server.accept_lan()).await.expect("accept");
    let outcome = within("accept_bi", conn.accept_bi()).await;
    assert_eq!(outcome.err(), Some(TransportError::Crypto));
    drop(sock);
}

// ---------------------------------------------------------------------------
// Throughput
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_multi_megabyte_transfer_arrives_intact() {
    let daemon = identity();
    let phone = identity();
    let server = bind_reconnect(&daemon, vec![phone.noise_public_key()]).await;

    let client_conn = dial(
        ClientConfig::reconnect(Arc::clone(&phone)),
        &daemon,
        &server,
    )
    .await
    .expect("connect");
    let server_conn = within("accept", server.accept_lan()).await.expect("accept");

    let chunk: Vec<u8> = (0..=255u8).cycle().take(200_000).collect();
    let frames = 20;
    let expected = chunk.clone();

    let (mut tx, _rx) = client_conn.open_bi().expect("open");
    let sender = tokio::spawn(async move {
        for _ in 0..frames {
            tx.send(&frame(&chunk)).await.expect("send");
        }
        tx.finish();
    });

    let (_stx, mut srx) = within("accept_bi", server_conn.accept_bi())
        .await
        .expect("accept stream");
    let started = Instant::now();
    let mut received = 0usize;
    while let Some(got) = within("bulk recv", srx.recv()).await.expect("recv") {
        assert_eq!(got.payload, expected, "payload corrupted in transit");
        received += 1;
    }
    assert_eq!(received, frames);
    sender.await.expect("sender task");
    assert!(
        started.elapsed() < PATIENCE,
        "4 MB over loopback should not take {:?}",
        started.elapsed()
    );
}
