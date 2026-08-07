//! End-to-end tests for Tiers 1 and 2 over real iroh endpoints.
//!
//! Two endpoints, two UDP sockets, real QUIC, real Noise, real frames. Nothing is
//! mocked: the failures worth catching in a transport — a handshake that
//! authenticates the wrong key, a stream that blocks another stream, a peer that
//! offers the wrong ALPN — are precisely the ones a mock cannot produce.
//!
//! # Which tests need a network, and which do not
//!
//! Everything except [`a_relayed_path_upgrades_to_direct`] runs entirely on
//! loopback, with iroh's relays and address publication switched off, so the suite
//! is fast and works on a machine with no internet at all. Those tests exercise
//! genuine QUIC hole-punching-free direct paths — which is what a LAN or a
//! successful hole punch looks like once it is established.
//!
//! What loopback *cannot* reproduce is a relayed path and its upgrade to direct,
//! because that needs a relay server neither endpoint is. That test is
//! `#[ignore]`d and dials n0's public relays. It is written to **fail** rather
//! than pass when the network is unavailable: a test that quietly succeeds
//! offline would be worse than no test, because it would report a green tick for
//! the one property the product cannot be shipped without.

use std::sync::Arc;
use std::time::{Duration, Instant};

use gonomad_core::{DeviceIdentity, PairingSecret, PairingTicket};
use gonomad_proto::{Frame, FrameFlags, PublicKey, ALPN};
use gonomad_transport::{
    AddrHint, Allowlist, Conn, IrohConfig, IrohConnection, IrohTransport, MuxConfig, PeerId,
    RelayPolicy, Tier, Transport, TransportError, CONTROL_STREAM,
};

/// A generous ceiling for any single await in these tests.
///
/// Present so a regression that deadlocks fails the suite in seconds instead of
/// hanging CI until it is killed with no useful output.
const PATIENCE: Duration = Duration::from_secs(20);

/// How long the relayed-to-direct test will wait for hole punching.
///
/// Only used by the `#[ignore]`d test, where the work involves a real relay
/// round trip and a real address-discovery cycle.
const UPGRADE_PATIENCE: Duration = Duration::from_secs(45);

fn identity() -> Arc<DeviceIdentity> {
    Arc::new(DeviceIdentity::generate())
}

fn frame(payload: &[u8]) -> Frame {
    Frame::new(FrameFlags::NONE, payload.to_vec()).expect("frame within limits")
}

/// Fails with a useful message instead of hanging when something deadlocks.
async fn within<F: std::future::Future>(what: &str, future: F) -> F::Output {
    let Ok(value) = tokio::time::timeout(PATIENCE, future).await else {
        panic!("{what} did not finish within {PATIENCE:?}")
    };
    value
}

/// A configuration that talks only to loopback: no relay, no address publication.
///
/// Every knob that could reach the internet is off, so these tests cannot pass or
/// fail for reasons outside this process.
fn local(base: IrohConfig) -> IrohConfig {
    IrohConfig {
        relay: RelayPolicy::Disabled,
        address_lookup: false,
        bind_addrs: vec!["127.0.0.1:0".parse().expect("literal address")],
        ..base
    }
}

/// The same, with both loopback address families bound.
///
/// Used by the path-watcher test, which needs a second path to appear after the
/// connection is already established.
fn dual_stack(base: IrohConfig) -> IrohConfig {
    IrohConfig {
        bind_addrs: vec![
            "127.0.0.1:0".parse().expect("literal address"),
            "[::1]:0".parse().expect("literal address"),
        ],
        ..local(base)
    }
}

/// Binds a daemon that accepts reconnects from exactly `allowed`.
async fn bind_daemon(daemon: &Arc<DeviceIdentity>, allowed: Vec<PublicKey>) -> IrohTransport {
    let policy = Arc::new(Allowlist::new(allowed));
    IrohTransport::bind(local(IrohConfig::reconnect(Arc::clone(daemon), policy)))
        .await
        .expect("bind the daemon endpoint")
}

/// The hints a phone would have scanned: the node id plus a pinned direct address.
fn hints(server: &IrohTransport) -> Vec<AddrHint> {
    let mut hints = vec![AddrHint::Node(server.node_id())];
    hints.extend(server.bound_sockets().into_iter().map(AddrHint::Direct));
    hints
}

/// Connects a phone to a daemon and returns both ends of the connection.
async fn connect(
    phone: &IrohTransport,
    daemon_identity: &Arc<DeviceIdentity>,
    daemon: &IrohTransport,
) -> (IrohConnection, IrohConnection) {
    let peer = PeerId::from_noise_key(daemon_identity.noise_public_key());
    let hints = hints(daemon);
    let (client, server) = tokio::join!(
        within("connect", phone.connect_iroh(peer, &hints)),
        within("accept", daemon.accept_iroh()),
    );
    (
        client.expect("the phone connects"),
        server.expect("the daemon accepts"),
    )
}

#[tokio::test]
async fn a_paired_phone_connects_authenticates_and_exchanges_frames() {
    let daemon_id = identity();
    let phone_id = identity();
    let daemon = bind_daemon(&daemon_id, vec![phone_id.noise_public_key()]).await;
    let phone = IrohTransport::bind(local(IrohConfig::dialer(Arc::clone(&phone_id))))
        .await
        .expect("bind the phone endpoint");

    let (client, server) = connect(&phone, &daemon_id, &daemon).await;

    // Each side authenticated the other's Noise static key — the credential the
    // paired-device table is keyed on, not the transport's node id.
    assert_eq!(client.peer_key(), daemon_id.noise_public_key());
    assert_eq!(server.peer_key(), phone_id.noise_public_key());

    // And the node ids, which are what iroh dialled.
    assert_eq!(client.peer_node_id(), daemon_id.iroh_node_id());
    assert_eq!(server.peer_node_id(), phone_id.iroh_node_id());

    // Both derive the same six digits, or pairing could not work (§9.2).
    assert_eq!(client.sas(), server.sas());
    assert_eq!(client.channel_binding(), server.channel_binding());

    // The first stream the dialling side opens is the control stream (§10.2), and
    // it is the one the connection handshake already ran on, so it costs no extra
    // round trip.
    let (mut ctx, mut crx) = client.open_stream().await.expect("control stream");
    assert_eq!(ctx.id(), CONTROL_STREAM);
    ctx.send(&frame(b"hello")).await.expect("client sends");

    let (mut stx, mut srx) = within("accept the control stream", server.accept_stream())
        .await
        .expect("control stream");
    assert_eq!(srx.id(), CONTROL_STREAM);
    let got = within("server receives", srx.recv())
        .await
        .expect("recv")
        .expect("a frame");
    assert_eq!(got.payload, b"hello");

    stx.send(&frame(b"world")).await.expect("server replies");
    let back = within("client receives", crx.recv())
        .await
        .expect("recv")
        .expect("a frame");
    assert_eq!(back.payload, b"world");

    phone.close().await;
    daemon.close().await;
}

#[tokio::test]
async fn a_loopback_path_is_reported_as_direct_and_not_relayed() {
    // The honest-tier property (§4.2): the chip in the UI must say what is true.
    // A path over an IP address is Tier 1, and `relayed` must be false so that
    // nothing downstream shows a relay warning on a direct session.
    let daemon_id = identity();
    let phone_id = identity();
    let daemon = bind_daemon(&daemon_id, vec![phone_id.noise_public_key()]).await;
    let phone = IrohTransport::bind(local(IrohConfig::dialer(Arc::clone(&phone_id))))
        .await
        .expect("bind the phone endpoint");

    let (client, server) = connect(&phone, &daemon_id, &daemon).await;

    let info = client.path_info();
    assert_eq!(info.tier, Tier::Direct);
    assert!(!info.relayed);
    assert!(
        info.rtt_ms.is_some(),
        "the dialling side measures the handshake round trip"
    );
    assert_eq!(server.path_info().tier, Tier::Direct);

    // The watch channel starts at the current path rather than empty, so a
    // subscriber that arrives late still learns the tier without waiting for a
    // change that may never come.
    let watcher = client.path_changes();
    assert_eq!(watcher.borrow().tier, Tier::Direct);

    phone.close().await;
    daemon.close().await;
}

#[tokio::test]
async fn a_second_network_path_fires_the_path_watcher() {
    // `Conn::path_changes` must *fire*, not merely hold a value seeded once at
    // connect time. This is the channel the UI's connection chip reads and the
    // channel the §4.4 relay-to-direct upgrade is delivered on, and a publisher
    // task that had died — or was never spawned — would be indistinguishable from a
    // quiet network.
    //
    // The trigger is a second path appearing mid-connection. Both endpoints bind
    // IPv4 *and* IPv6 loopback, and the phone is told only the IPv4 address, so
    // iroh discovers the other family after the connection is already up and
    // reports it. That is the same event sequence a relay-to-direct upgrade
    // produces — a path opens, becomes selected, and the observed path changes —
    // with the one part loopback cannot supply being the relay itself. The tier
    // flip is covered by `a_relayed_path_upgrades_to_direct`.
    let daemon_id = identity();
    let phone_id = identity();
    let daemon = IrohTransport::bind(dual_stack(IrohConfig::reconnect(
        Arc::clone(&daemon_id),
        Arc::new(Allowlist::new(vec![phone_id.noise_public_key()])),
    )))
    .await
    .expect("bind the daemon endpoint");
    let phone = IrohTransport::bind(dual_stack(IrohConfig::dialer(Arc::clone(&phone_id))))
        .await
        .expect("bind the phone endpoint");

    // Only the IPv4 socket is pinned, so the IPv6 path has to be *discovered*.
    let mut dial_hints = vec![AddrHint::Node(daemon.node_id())];
    dial_hints.extend(
        daemon
            .bound_sockets()
            .into_iter()
            .filter(std::net::SocketAddr::is_ipv4)
            .map(AddrHint::Direct),
    );
    let peer = PeerId::from_noise_key(daemon_id.noise_public_key());
    let (client, _server) = tokio::join!(
        within("connect", phone.connect_iroh(peer, &dial_hints)),
        within("accept", daemon.accept_iroh()),
    );
    let client = client.expect("the phone connects");

    let mut paths = client.path_changes();
    let (mut tx, _rx) = client.open_stream().await.expect("control stream");

    // Traffic gives iroh's path probing something to measure, and therefore
    // something to report.
    let started = Instant::now();
    let mut fired = false;
    while !fired && started.elapsed() < PATIENCE {
        tx.send(&frame(b"probe")).await.expect("send");
        if tokio::time::timeout(Duration::from_millis(250), paths.changed())
            .await
            .is_ok()
        {
            fired = true;
        }
    }
    assert!(
        fired,
        "path_changes never fired in {PATIENCE:?}: the watcher is not wired to iroh"
    );
    // And what it published is a coherent path rather than a default.
    let info = *paths.borrow_and_update();
    assert_eq!(info.tier, Tier::Direct);
    assert!(!info.relayed);

    phone.close().await;
    daemon.close().await;
}

#[tokio::test]
async fn everything_works_through_the_object_safe_traits() {
    // The premise of §4.5 is that the daemon holds `Box<dyn Transport>` and
    // `Box<dyn Conn>` so the active rung can be chosen at runtime. Exercising the
    // trait path rather than the inherent methods is what keeps that true: an
    // `IrohTransport` that only worked through its own inherent API would compile,
    // pass every other test here, and be useless to a ladder.
    let daemon_id = identity();
    let phone_id = identity();
    // The hints are read off the concrete type first: the §4.5 trait deliberately
    // has no "how do I reach you" method, because answering that is the pairing
    // ticket's job and not the transport's.
    let concrete = IrohTransport::bind(local(IrohConfig::reconnect(
        Arc::clone(&daemon_id),
        Arc::new(Allowlist::new(vec![phone_id.noise_public_key()])),
    )))
    .await
    .expect("bind the daemon endpoint");
    let dial_hints = hints(&concrete);
    let daemon: Box<dyn Transport> = Box::new(concrete);
    let phone: Box<dyn Transport> = Box::new(
        IrohTransport::bind(local(IrohConfig::dialer(Arc::clone(&phone_id))))
            .await
            .expect("bind the phone endpoint"),
    );

    // Before any connection exists the transport reports the pessimistic tier: a
    // relay might yet be needed, and over-claiming Direct is the mistake §4.2 warns
    // about.
    assert_eq!(phone.path_info().tier, Tier::Relay);

    let peer = PeerId::from_noise_key(daemon_id.noise_public_key());
    let (client, server) = tokio::join!(
        within("connect", phone.connect(peer, &dial_hints)),
        within("accept", daemon.accept()),
    );
    let client: Box<dyn Conn> = client.expect("the phone connects");
    let server: Box<dyn Conn> = server.expect("the daemon accepts");

    assert_eq!(client.peer_key(), daemon_id.noise_public_key());
    assert_eq!(server.peer_key(), phone_id.noise_public_key());
    assert_eq!(client.path_info().tier, Tier::Direct);
    assert_eq!(client.path_changes().borrow().tier, Tier::Direct);

    let (mut tx, _rx) = within("open_bi", client.open_bi())
        .await
        .expect("control stream");
    tx.send(&frame(b"through the trait")).await.expect("send");
    let (_stx, mut srx) = within("accept_bi", server.accept_bi())
        .await
        .expect("control stream");
    assert_eq!(
        within("recv", srx.recv())
            .await
            .expect("recv")
            .expect("a frame")
            .payload,
        b"through the trait"
    );

    client.close();
    server.close();
}

#[tokio::test]
async fn several_streams_carry_traffic_concurrently() {
    let daemon_id = identity();
    let phone_id = identity();
    let daemon = bind_daemon(&daemon_id, vec![phone_id.noise_public_key()]).await;
    let phone = IrohTransport::bind(local(IrohConfig::dialer(Arc::clone(&phone_id))))
        .await
        .expect("bind the phone endpoint");
    let (client, server) = connect(&phone, &daemon_id, &daemon).await;

    // Three streams, each with its own Noise session and its own QUIC flow
    // control. The second and third pay a handshake round trip; the first does not.
    let mut sent = Vec::new();
    for index in 0..3u8 {
        let (mut tx, _rx) = within("open a stream", client.open_stream())
            .await
            .expect("stream");
        tx.send(&frame(&[index; 64])).await.expect("send");
        sent.push(tx);
    }

    let mut seen = Vec::new();
    for _ in 0..3 {
        let (_tx, mut rx) = within("accept a stream", server.accept_stream())
            .await
            .expect("stream");
        let got = within("receive", rx.recv())
            .await
            .expect("recv")
            .expect("a frame");
        seen.push(got.payload[0]);
    }
    seen.sort_unstable();
    assert_eq!(seen, vec![0, 1, 2]);

    // Distinct stream ids, so nothing was silently multiplexed onto one channel.
    let mut ids: Vec<_> = sent.iter().map(gonomad_transport::SendStream::id).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 3);

    phone.close().await;
    daemon.close().await;
}

#[tokio::test]
async fn a_large_payload_on_one_stream_does_not_block_a_small_one_on_another() {
    // The §4.4 property that TCP cannot give us. On Tier 0 the mux keeps a bulk
    // transfer from *starving* a keystroke, but a single lost segment stalls every
    // channel because they share one sequence space. Here the streams are genuinely
    // independent, so a keystroke overtakes an 8 MiB download.
    //
    // The payload is also 32× the mux's 256 KiB single-frame cap, which is R25 in
    // §19 retiring: QUIC flow-controls a byte stream rather than whole messages, so
    // one frame may be as large as the protocol allows.
    const BULK_LEN: usize = 8 * 1024 * 1024;
    assert!(BULK_LEN > MuxConfig::default().max_frame_len);

    let daemon_id = identity();
    let phone_id = identity();
    let daemon = bind_daemon(&daemon_id, vec![phone_id.noise_public_key()]).await;
    let phone = IrohTransport::bind(local(IrohConfig::dialer(Arc::clone(&phone_id))))
        .await
        .expect("bind the phone endpoint");
    let (client, server) = connect(&phone, &daemon_id, &daemon).await;

    // Both streams are opened, and their handshakes completed, *before* any bulk
    // data moves. Otherwise this would also be measuring whether a saturated link
    // delays a stream handshake, which is a different question.
    let (mut bulk_tx, _bulk_rx) = within("open the bulk stream", client.open_stream())
        .await
        .expect("bulk stream");
    let (mut chat_tx, _chat_rx) = within("open the chat stream", client.open_stream())
        .await
        .expect("chat stream");
    let bulk_id = bulk_tx.id();

    let (_a_tx, a_rx) = within("accept the first stream", server.accept_stream())
        .await
        .expect("stream");
    let (_b_tx, b_rx) = within("accept the second stream", server.accept_stream())
        .await
        .expect("stream");
    // Streams arrive in the order the client opened them, so the bulk stream is
    // whichever of the two carries the bulk id.
    let (mut bulk_rx, mut chat_rx) = if a_rx.id() == bulk_id {
        (a_rx, b_rx)
    } else {
        (b_rx, a_rx)
    };

    let (order_tx, mut order_rx) = tokio::sync::mpsc::unbounded_channel();

    let bulk_reader = {
        let order_tx = order_tx.clone();
        tokio::spawn(async move {
            let got = bulk_rx.recv().await.expect("bulk recv").expect("a frame");
            let _ = order_tx.send(("bulk", got.payload.len()));
        })
    };
    let chat_reader = tokio::spawn(async move {
        let got = chat_rx.recv().await.expect("chat recv").expect("a frame");
        let _ = order_tx.send(("chat", got.payload.len()));
    });

    let sender = tokio::spawn(async move {
        // The bulk write starts first and is far larger, so if the streams shared
        // one ordered byte stream the small frame behind it would arrive last.
        let bulk = tokio::spawn(async move { bulk_tx.send(&frame(&vec![0xAB; BULK_LEN])).await });
        chat_tx.send(&frame(b"keystroke")).await.expect("chat send");
        bulk.await.expect("bulk task").expect("bulk send");
    });

    let started = Instant::now();
    let first = within("the first stream to deliver", order_rx.recv())
        .await
        .expect("an arrival");
    assert_eq!(
        first.0, "chat",
        "the 8 MiB frame blocked a 9-byte frame on another stream"
    );
    let chat_latency = started.elapsed();

    let second = within("the second stream to deliver", order_rx.recv())
        .await
        .expect("an arrival");
    assert_eq!(second, ("bulk", BULK_LEN));
    // Not just first, but *promptly* first: the small frame must not have waited
    // for a meaningful share of the bulk transfer.
    assert!(
        chat_latency < started.elapsed(),
        "the small frame arrived no sooner than the bulk one"
    );

    within("the sender", sender).await.expect("sender task");
    within("the bulk reader", bulk_reader)
        .await
        .expect("bulk reader");
    within("the chat reader", chat_reader)
        .await
        .expect("chat reader");

    phone.close().await;
    daemon.close().await;
}

#[tokio::test]
async fn a_frame_far_larger_than_the_mux_cap_round_trips_intact() {
    // R25 in §19, asserted on the bytes rather than in prose: the TCP binding caps
    // a single frame at 256 KiB because mux credit is returned per whole frame. On
    // QUIC that constraint does not exist, and `IrohConfig::max_frame_len` defaults
    // to the protocol's own 32 MiB maximum.
    const LEN: usize = 2 * 1024 * 1024;
    assert!(LEN > MuxConfig::default().max_frame_len);

    let daemon_id = identity();
    let phone_id = identity();
    let daemon = bind_daemon(&daemon_id, vec![phone_id.noise_public_key()]).await;
    let phone = IrohTransport::bind(local(IrohConfig::dialer(Arc::clone(&phone_id))))
        .await
        .expect("bind the phone endpoint");
    let (client, server) = connect(&phone, &daemon_id, &daemon).await;

    let (mut tx, _rx) = client.open_stream().await.expect("control stream");
    let payload: Vec<u8> = (0..LEN)
        .map(|i| u8::try_from(i % 251).unwrap_or(0))
        .collect();
    let expected = payload.clone();
    let sender = tokio::spawn(async move { tx.send(&frame(&payload)).await });

    let (_stx, mut srx) = within("accept the control stream", server.accept_stream())
        .await
        .expect("stream");
    let got = within("receive a large frame", srx.recv())
        .await
        .expect("recv")
        .expect("a frame");
    // Compared in full: a reassembler that dropped or duplicated a record boundary
    // would otherwise produce a frame of the right length and the wrong contents.
    assert_eq!(got.payload, expected);
    within("the sender", sender)
        .await
        .expect("sender task")
        .expect("send");

    phone.close().await;
    daemon.close().await;
}

#[tokio::test]
async fn pairing_with_the_wrong_secret_is_refused() {
    // R24 in §19: `IKpsk2` mixes the pre-shared key into the responder's message,
    // so the daemon completes its half and the *phone* rejects. What must never
    // happen is the phone believing it paired.
    let daemon_id = identity();
    let phone_id = identity();
    let daemon = IrohTransport::bind(local(IrohConfig::pairing(
        Arc::clone(&daemon_id),
        &PairingSecret::generate(),
    )))
    .await
    .expect("bind the pairing window");
    let phone = IrohTransport::bind(local(IrohConfig::pairing_dialer(
        Arc::clone(&phone_id),
        // A different secret: what a phone that scanned a stale QR would have.
        &PairingSecret::generate(),
    )))
    .await
    .expect("bind the phone endpoint");

    let peer = PeerId::from_noise_key(daemon_id.noise_public_key());
    let outcome = within(
        "a doomed pairing",
        phone.connect_iroh(peer, &hints(&daemon)),
    )
    .await;
    assert!(
        matches!(outcome, Err(TransportError::HandshakeFailed)),
        "expected the phone to refuse, got {outcome:?}"
    );

    phone.close().await;
    daemon.close().await;
}

#[tokio::test]
async fn pairing_with_the_right_secret_succeeds_and_shows_matching_digits() {
    let daemon_id = identity();
    let phone_id = identity();
    let secret = PairingSecret::generate();

    // The path a real pairing takes: the daemon renders a ticket, the phone scans
    // it, and every hint the phone dials with comes out of that ticket.
    let ticket = PairingTicket {
        daemon_key: daemon_id.noise_public_key(),
        node_id: daemon_id.iroh_node_id(),
        addr_hints: Vec::new(),
        relay_hint: None,
    };
    let payload = ticket.encode(&secret);

    let daemon = IrohTransport::bind(local(IrohConfig::pairing(Arc::clone(&daemon_id), &secret)))
        .await
        .expect("bind the pairing window");

    let (scanned, scanned_secret) = PairingTicket::decode(&payload).expect("the phone scans");
    assert_eq!(scanned.node_id, daemon_id.iroh_node_id());

    let phone = IrohTransport::bind(local(IrohConfig::pairing_dialer(
        Arc::clone(&phone_id),
        &scanned_secret,
    )))
    .await
    .expect("bind the phone endpoint");

    // The ticket carried no address hints, so the node id is the only thing to dial
    // by. On loopback with discovery off it needs a nudge, which is what a real
    // deployment gets from the relay and the DNS lookup.
    let mut dial_hints = AddrHint::from_ticket(&scanned);
    assert_eq!(dial_hints[0], AddrHint::Node(daemon_id.iroh_node_id()));
    dial_hints.extend(daemon.bound_sockets().into_iter().map(AddrHint::Direct));

    let peer = PeerId::from_noise_key(scanned.daemon_key);
    let (client, server) = tokio::join!(
        within("pair", phone.connect_iroh(peer, &dial_hints)),
        within("accept a pairing", daemon.accept_iroh()),
    );
    let client = client.expect("the phone pairs");
    let server = server.expect("the daemon accepts");
    assert_eq!(
        client.sas(),
        server.sas(),
        "the digits the human compares must match"
    );

    phone.close().await;
    daemon.close().await;
}

#[tokio::test]
async fn an_unpaired_device_is_rejected_before_any_application_byte() {
    // The §3.7 allowlist gate. The daemon knows the peer's key after the first
    // Noise message and drops it without a reply, so the connection never reaches
    // `accept_iroh` and the caller learns nothing about why.
    let daemon_id = identity();
    let phone_id = identity();
    let daemon = bind_daemon(&daemon_id, vec![/* nobody is paired */]).await;
    let phone = IrohTransport::bind(local(IrohConfig::dialer(Arc::clone(&phone_id))))
        .await
        .expect("bind the phone endpoint");

    let peer = PeerId::from_noise_key(daemon_id.noise_public_key());
    let outcome = within("a rejected dial", phone.connect_iroh(peer, &hints(&daemon))).await;
    assert!(outcome.is_err(), "an unpaired device was admitted");

    // And nothing was handed to the application.
    let leaked = tokio::time::timeout(Duration::from_millis(500), daemon.accept_iroh()).await;
    assert!(
        leaked.is_err(),
        "a rejected connection was surfaced to the daemon"
    );

    phone.close().await;
    daemon.close().await;
}

#[tokio::test]
async fn a_connection_offering_the_wrong_alpn_is_dropped() {
    // "Presents nothing to a scanner" (§3.7). The ALPN gate is enforced by iroh
    // during the QUIC handshake, before any GoNomad code runs, so this dials with a
    // raw iroh endpoint — the only way to offer something other than `gonomad/1`.
    let daemon_id = identity();
    let daemon = bind_daemon(&daemon_id, vec![identity().noise_public_key()]).await;

    let scanner = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .clear_address_lookup()
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")
        .expect("literal address")
        .bind()
        .await
        .expect("bind a bare endpoint");

    let mut addr = iroh::EndpointAddr::new(
        iroh::EndpointId::from_bytes(daemon.node_id().as_bytes()).expect("the daemon's node id"),
    );
    for socket in daemon.bound_sockets() {
        addr = addr.with_ip_addr(socket);
    }

    let refused = within(
        "a dial with the wrong ALPN",
        scanner.connect(addr.clone(), b"http/1.1"),
    )
    .await;
    assert!(refused.is_err(), "a foreign ALPN was accepted");

    // The same endpoint, the same address, the right ALPN: the QUIC handshake now
    // succeeds. Without this the test would also pass if the daemon were simply
    // unreachable.
    let accepted = within("a dial with the right ALPN", scanner.connect(addr, ALPN)).await;
    assert!(
        accepted.is_ok(),
        "the ALPN gate rejected its own protocol: {accepted:?}"
    );

    scanner.close().await;
    daemon.close().await;
}

#[tokio::test]
async fn a_dialer_that_never_accepts_answers_nothing_at_all() {
    // The phone dials and is never dialled. With no ALPN configured its endpoint
    // has no server configuration, so an inbound QUIC handshake is not refused —
    // it is *ignored*. That is the strongest form of the §3.7 property: a scanner
    // that finds the UDP port learns nothing, not even that something is there.
    let phone_id = identity();
    let phone = IrohTransport::bind(local(IrohConfig::dialer(Arc::clone(&phone_id))))
        .await
        .expect("bind the phone endpoint");

    let prober = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .clear_address_lookup()
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")
        .expect("literal address")
        .bind()
        .await
        .expect("bind a bare endpoint");

    let mut addr = iroh::EndpointAddr::new(
        iroh::EndpointId::from_bytes(phone.node_id().as_bytes()).expect("the phone's node id"),
    );
    for socket in phone.bound_sockets() {
        addr = addr.with_ip_addr(socket);
    }

    // Short on purpose: the assertion is that nothing *succeeds*, and waiting the
    // full patience for silence would add twenty seconds to every run.
    let outcome = tokio::time::timeout(Duration::from_secs(3), prober.connect(addr, ALPN)).await;
    assert!(
        !matches!(outcome, Ok(Ok(_))),
        "the phone accepted an inbound connection"
    );

    prober.close().await;
    phone.close().await;
}

#[tokio::test]
async fn dialling_without_a_node_id_says_so() {
    // A ticket that predates the node id, or a caller passing only addresses.
    // "No reachable address" would send a user hunting for a firewall that is not
    // the problem.
    let phone = IrohTransport::bind(local(IrohConfig::dialer(identity())))
        .await
        .expect("bind the phone endpoint");
    let peer = PeerId::from_noise_key(identity().noise_public_key());
    let hints = [AddrHint::Direct(
        "127.0.0.1:41234".parse().expect("literal"),
    )];
    assert!(matches!(
        phone.connect_iroh(peer, &hints).await,
        Err(TransportError::NoNodeId)
    ));
    phone.close().await;
}

#[tokio::test]
async fn closing_a_connection_ends_a_waiting_receiver() {
    let daemon_id = identity();
    let phone_id = identity();
    let daemon = bind_daemon(&daemon_id, vec![phone_id.noise_public_key()]).await;
    let phone = IrohTransport::bind(local(IrohConfig::dialer(Arc::clone(&phone_id))))
        .await
        .expect("bind the phone endpoint");
    let (client, server) = connect(&phone, &daemon_id, &daemon).await;

    let (mut tx, _rx) = client.open_stream().await.expect("control stream");
    tx.send(&frame(b"last")).await.expect("send");
    let (_stx, mut srx) = within("accept", server.accept_stream())
        .await
        .expect("stream");
    assert_eq!(
        within("recv", srx.recv())
            .await
            .expect("recv")
            .expect("a frame")
            .payload,
        b"last"
    );

    client.close();
    // A receiver parked on a closed connection must be woken with an error rather
    // than left waiting for a peer that has gone.
    let after = within("recv after close", srx.recv()).await;
    assert!(
        after.is_err() || matches!(after, Ok(None)),
        "a closed connection left the receiver hanging on a value: {after:?}"
    );

    phone.close().await;
    daemon.close().await;
}

/// A relayed connection must upgrade itself to a direct one, and say so.
///
/// `#[ignore]`d because it is the one test here that needs the public internet:
/// it dials n0's relay network, publishes to n0's DNS-based address lookup, and
/// waits for a real hole-punching cycle. Run it with
/// `cargo test -p gonomad-transport -- --ignored`.
///
/// It deliberately **fails** rather than skips when the network is unavailable.
/// The relay→direct upgrade is the one behaviour iroh has that the TCP binding
/// structurally cannot (§4.4), and a test that reported success offline would be
/// worse than no test at all.
#[tokio::test]
#[ignore = "requires the public internet: n0's relays and DNS-based address lookup"]
async fn a_relayed_path_upgrades_to_direct() {
    let daemon_id = identity();
    let phone_id = identity();

    let daemon = IrohTransport::bind(IrohConfig::reconnect(
        Arc::clone(&daemon_id),
        Arc::new(Allowlist::new(vec![phone_id.noise_public_key()])),
    ))
    .await
    .expect("bind the daemon endpoint");
    let phone = IrohTransport::bind(IrohConfig::dialer(Arc::clone(&phone_id)))
        .await
        .expect("bind the phone endpoint");

    // Both must have reached a relay, or there is no relayed path to start from.
    within("the daemon reaching a relay", daemon.online()).await;
    within("the phone reaching a relay", phone.online()).await;

    // Dial with the relay only, and deliberately *no* direct addresses. That is the
    // CGNAT case: the phone knows who to call and has no idea where they are.
    let relay_only: Vec<AddrHint> = daemon
        .addr_hints()
        .into_iter()
        .filter(|hint| !matches!(hint, AddrHint::Direct(_)))
        .collect();
    assert!(
        relay_only.iter().any(|h| matches!(h, AddrHint::Relay(_))),
        "the daemon reported no relay to dial through: {relay_only:?}"
    );

    let peer = PeerId::from_noise_key(daemon_id.noise_public_key());
    let (client, _server) = tokio::join!(
        within(
            "connect through a relay",
            phone.connect_iroh(peer, &relay_only)
        ),
        within("accept through a relay", daemon.accept_iroh()),
    );
    let client = client.expect("the phone connects through the relay");

    // Traffic has to keep flowing for hole punching to have anything to punch
    // through, and for the upgrade to be observable.
    let (mut tx, _rx) = client.open_stream().await.expect("control stream");
    tx.send(&frame(b"over the relay")).await.expect("send");

    // Wait for the direct path. On two machines on different networks the flip
    // from Relay to Direct is observable through `path_changes`, which is the whole
    // point of the channel. On a single machine — including CI — hole punching to
    // the loopback interface completes before this connection object even exists,
    // so what is asserted here is the end state: a dial that had nothing but a
    // relay to go on ends up direct, and says so honestly.
    let mut paths = client.path_changes();
    let started = Instant::now();
    loop {
        if paths.borrow_and_update().tier == Tier::Direct {
            break;
        }
        let remaining = UPGRADE_PATIENCE
            .checked_sub(started.elapsed())
            .expect("no direct path appeared before the deadline");
        tokio::time::timeout(remaining, paths.changed())
            .await
            .expect("path_changes stopped firing before a direct path appeared")
            .expect("the path watcher died");
    }

    let info = client.path_info();
    assert_eq!(info.tier, Tier::Direct);
    assert!(!info.relayed);

    phone.close().await;
    daemon.close().await;
}

/// A connection bootstrapped entirely through a public relay carries frames both
/// ways.
///
/// `#[ignore]`d for the same reason as the upgrade test: it needs a real relay.
/// The phone is given the daemon's relay and *no* direct address, so the QUIC
/// handshake, the Noise handshake and the first frames all cross n0's
/// infrastructure — Noise-sealed, which is the §4.3 claim that makes a public
/// relay safe by default.
///
/// It asserts frames rather than a tier: both peers are on one machine here, so
/// iroh punches its way to a direct path almost immediately and the *selected*
/// path is whatever won that race. A permanently relayed path needs a peer that
/// genuinely cannot be reached directly — a symmetric NAT or CGNAT on a second
/// network — which no single-host test can arrange.
#[tokio::test]
#[ignore = "requires the public internet: n0's relays and DNS-based address lookup"]
async fn a_connection_bootstrapped_through_a_public_relay_carries_frames() {
    let daemon_id = identity();
    let phone_id = identity();

    let daemon = IrohTransport::bind(IrohConfig::reconnect(
        Arc::clone(&daemon_id),
        Arc::new(Allowlist::new(vec![phone_id.noise_public_key()])),
    ))
    .await
    .expect("bind the daemon endpoint");
    let phone = IrohTransport::bind(IrohConfig::dialer(Arc::clone(&phone_id)))
        .await
        .expect("bind the phone endpoint");

    within("the daemon reaching a relay", daemon.online()).await;
    within("the phone reaching a relay", phone.online()).await;

    // Relay only: no direct address is offered, so there is nothing to dial but the
    // relay and the node id.
    let relay_only: Vec<AddrHint> = daemon
        .addr_hints()
        .into_iter()
        .filter(|hint| !matches!(hint, AddrHint::Direct(_)))
        .collect();

    let peer = PeerId::from_noise_key(daemon_id.noise_public_key());
    let (client, server) = tokio::join!(
        within(
            "connect through a relay",
            phone.connect_iroh(peer, &relay_only)
        ),
        within("accept through a relay", daemon.accept_iroh()),
    );
    let client = client.expect("the phone connects through the relay");
    let server = server.expect("the daemon accepts through the relay");

    // Frames flow with the same session layer, the same codec and the same
    // authentication as on a direct path. That equivalence is the §3.4 promise, and
    // it is what lets the relay be a dumb forwarder of ciphertext.
    let (mut tx, mut rx) = client.open_stream().await.expect("control stream");
    tx.send(&frame(b"relayed")).await.expect("send");
    let (mut stx, mut srx) = within("accept the control stream", server.accept_stream())
        .await
        .expect("stream");
    assert_eq!(
        within("recv", srx.recv())
            .await
            .expect("recv")
            .expect("a frame")
            .payload,
        b"relayed"
    );
    stx.send(&frame(b"and back")).await.expect("reply");
    assert_eq!(
        within("recv the reply", rx.recv())
            .await
            .expect("recv")
            .expect("a frame")
            .payload,
        b"and back"
    );
    assert_eq!(client.sas(), server.sas());

    phone.close().await;
    daemon.close().await;
}
