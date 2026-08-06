//! The connection loop: accept, handshake, serve, and pair.
//!
//! Two entry points, deliberately separate rather than one function with a mode
//! flag (`ARCHITECTURE.md` §3.7, §9.1):
//!
//! - [`serve_pairing`] opens a **time-boxed, single-use** window that accepts an
//!   unknown key. It is the only moment an unpaired device can connect at all.
//! - [`serve`] accepts only keys on the paired allowlist. An unknown key is
//!   rejected during the Noise handshake, before any application data.
//!
//! Keeping them separate is what stops a client from *asking* for the pairing
//! pattern: the daemon's listener is configured for one purpose or the other by
//! the operator, never by the peer.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use gonomad_core::{DeviceIdentity, PairingSecret};
use gonomad_proto::{ControlMessage, Frame, FrameFlags, PublicKey};
use gonomad_store::Store;
use gonomad_transport::{Allowlist, ServerConfig, TcpConnection, TcpTransport, DEFAULT_PORT};

use crate::router::{Daemon, Effect, Router};

/// A device that completed pairing.
#[derive(Debug, Clone)]
pub struct PairedDevice {
    /// The name the phone asked to be known by.
    pub name: String,
    /// The device's Noise public key — its credential from now on.
    pub key: PublicKey,
}

/// Runs one pairing window.
///
/// Accepts connections until a device successfully registers or the window
/// expires. **Registration happens on `sys.register`, never on handshake
/// completion** — see [`crate::router::PairingState`] for why that distinction is
/// load-bearing rather than pedantic.
///
/// A peer that presents the wrong pairing code completes the Noise handshake
/// (that is how `IKpsk2` works) but cannot encrypt anything the daemon can read,
/// so it never gets as far as registering, and this function keeps waiting.
///
/// # Errors
///
/// Fails if the port cannot be bound, or if the window expires with no
/// registration.
pub async fn serve_pairing(
    identity: Arc<DeviceIdentity>,
    secret: &PairingSecret,
    daemon: Arc<Daemon>,
    store: &Store,
    window: Duration,
) -> Result<PairedDevice> {
    let transport = bind_pairing(identity, secret, DEFAULT_PORT).await?;
    run_pairing(&transport, daemon, store, window).await
}

/// Binds a pairing listener.
///
/// Split from [`run_pairing`] so a test can bind port 0 and discover the
/// ephemeral port before a client connects. Without the split there is no way to
/// exercise pairing end to end without claiming the real port.
///
/// # Errors
///
/// Fails if the port cannot be bound.
pub async fn bind_pairing(
    identity: Arc<DeviceIdentity>,
    secret: &PairingSecret,
    port: u16,
) -> Result<TcpTransport> {
    TcpTransport::bind(
        all_interfaces(port),
        ServerConfig::pairing(identity, secret),
    )
    .await
    .with_context(|| format!("could not listen on port {port}"))
}

/// `0.0.0.0:port` — every IPv4 interface.
///
/// Built directly rather than parsed from a string so there is no failure case to
/// `expect` on. Binding all interfaces is deliberate: a phone reaches the daemon
/// over Wi-Fi, not loopback. Note that the returned `local_addr()` is therefore
/// `0.0.0.0`, which is a valid bind address but **not** a connectable
/// destination — callers that need something to dial must use a real interface
/// address (see [`crate::serve`] tests and `local_addresses` in the CLI).
fn all_interfaces(port: u16) -> std::net::SocketAddr {
    std::net::SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, port))
}

/// Runs a pairing window on an already-bound listener.
///
/// # Errors
///
/// Fails if the window expires with no registration.
pub async fn run_pairing(
    transport: &TcpTransport,
    daemon: Arc<Daemon>,
    store: &Store,
    window: Duration,
) -> Result<PairedDevice> {
    let deadline = tokio::time::Instant::now() + window;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            bail!("the pairing window expired before a device registered");
        }

        let accepted = tokio::time::timeout(remaining, transport.accept_lan()).await;
        let conn = match accepted {
            Err(_) => bail!("the pairing window expired before a device registered"),
            Ok(Err(e)) => {
                // A failed handshake is the normal outcome of a wrong pairing
                // code or a port scan. Log and keep waiting rather than
                // abandoning the window, which would let one bad attempt force
                // the user to generate a new code.
                tracing::debug!(error = %e, "pairing attempt failed during handshake");
                continue;
            }
            Ok(Ok(conn)) => conn,
        };

        let sas = conn.sas().digits();
        let peer = conn.peer_key();
        tracing::info!(peer = %peer.short(), "pairing handshake completed; awaiting registration");

        let mut router = Router::pairing(Arc::clone(&daemon), peer, sas);

        // The closure captures `&Store`, which is fine here because the pairing
        // loop is never spawned onto another thread. `serve` passes a no-op for
        // exactly that reason — see the note on `run_connection`.
        let persist = |key: &PublicKey, name: &str, model: Option<&str>| {
            store
                .devices()
                .pair(
                    key,
                    name,
                    model,
                    gonomad_proto::CapabilitySet::default_grant(),
                )
                .context("could not record the paired device")?;

            // Reported from inside the callback rather than after the loop
            // returns, because the loop deliberately keeps serving so the reply
            // is not truncated. Without this the user would stare at "Waiting
            // for a device…" long after their phone said it had paired.
            println!();
            println!("Paired: {name}  ({})", key.short());
            println!("This device can now connect. Ctrl-C when you are done, then");
            println!("run `gonomad serve` for normal use.");
            Ok(())
        };

        match run_connection(&conn, &mut router, persist).await {
            Ok(Some(device)) => return Ok(device),
            Ok(None) => {
                tracing::debug!("peer disconnected without registering");
            }
            Err(e) => tracing::debug!(error = %e, "pairing connection ended"),
        }
    }
}

/// Serves paired devices until cancelled.
///
/// # Errors
///
/// Fails if the port cannot be bound.
pub async fn serve(
    identity: Arc<DeviceIdentity>,
    daemon: Arc<Daemon>,
    store: Store,
    port: u16,
) -> Result<()> {
    let allowed: Vec<PublicKey> = store
        .devices()
        .list_active()
        .context("could not read the device list")?
        .iter()
        .map(|d| d.public_key)
        .collect();

    if allowed.is_empty() {
        bail!("no devices are paired — run `gonomad pair` first");
    }

    let policy = Arc::new(Allowlist::new(allowed.clone()));
    let transport = TcpTransport::bind(
        all_interfaces(port),
        ServerConfig::reconnect(identity, policy),
    )
    .await
    .with_context(|| format!("could not listen on port {port}"))?;

    tracing::info!(port, devices = allowed.len(), "serving");

    loop {
        let conn = match transport.accept_lan().await {
            Ok(conn) => conn,
            Err(e) => {
                // An unpaired key or a scanner fails here, before any
                // application data. Expected traffic, not an error condition.
                tracing::debug!(error = %e, "connection rejected");
                continue;
            }
        };

        let peer = conn.peer_key();
        let device_id = gonomad_proto::DeviceId::from_public_key(&peer);
        let grant = gonomad_policy::DeviceGrant::new(
            device_id,
            store.devices().grants(&device_id).unwrap_or_default(),
        );

        tracing::info!(device = %device_id.short(), "device connected");
        let daemon = Arc::clone(&daemon);

        // One task per connection. Terminals and other state live in the daemon,
        // so a dropped connection costs a task and nothing else (§2).
        tokio::spawn(async move {
            let mut router = Router::established(daemon, peer, grant);
            // No registration on an established connection, and crucially no
            // `Store` captured: a rusqlite connection is not `Sync`, so holding
            // one across an await would make this future non-`Send` and
            // `tokio::spawn` would refuse it.
            let no_registration = |_: &PublicKey, _: &str, _: Option<&str>| Ok(());
            if let Err(e) = run_connection(&conn, &mut router, no_registration).await {
                tracing::debug!(error = %e, "connection ended");
            }
            tracing::info!(device = %device_id.short(), "device disconnected");
        });
    }
}

/// Serves one connection's control stream until it closes.
///
/// Returns `Ok(Some(device))` if the peer registered during this connection.
///
/// `on_register` is a closure rather than a `&Store` for a concrete reason: a
/// rusqlite connection is not `Sync`, so a `&Store` held across an await makes
/// the whole future non-`Send` and `tokio::spawn` rejects it. Taking a closure
/// lets the pairing path (single-threaded, captures the store) and the serving
/// path (spawned per connection, captures nothing) share this loop.
async fn run_connection<F>(
    conn: &TcpConnection,
    router: &mut Router,
    mut on_register: F,
) -> Result<Option<PairedDevice>>
where
    F: FnMut(&PublicKey, &str, Option<&str>) -> Result<()>,
{
    // The initiator opens the control stream, so the daemon accepts it (§10.2).
    let (mut tx, mut rx) = conn.accept_bi().await.context("no control stream")?;
    let mut registered = None;

    while let Some(frame) = rx.recv().await.context("control stream failed")? {
        let message: ControlMessage = match frame.decode_cbor() {
            Ok(m) => m,
            Err(_) => {
                // A malformed frame from an authenticated peer is a client bug,
                // not an attack we can act on. Drop the connection rather than
                // continuing to parse a stream we may have lost sync with.
                bail!("malformed control message");
            }
        };

        match message {
            ControlMessage::Request(request) => {
                let (response, effect) = router.handle(&request);

                if let Effect::Registered {
                    peer_key,
                    device_name,
                    device_model,
                } = effect
                {
                    // Persist *before* replying, so the phone is never told it is
                    // paired when the daemon failed to record it.
                    on_register(&peer_key, &device_name, device_model.as_deref())?;
                    tracing::info!(device = %device_name, "device paired");
                    registered = Some(PairedDevice {
                        name: device_name,
                        key: peer_key,
                    });
                }

                send(&mut tx, &ControlMessage::Response(response)).await?;

                // Deliberately *not* returning here, even though pairing is
                // single-use.
                //
                // Returning immediately after replying tears the connection down
                // while the response may still be queued in the multiplexer's
                // writer, so the phone can miss it entirely. It would then believe
                // pairing failed while the daemon has already registered it —
                // the worst possible split, because the user's only recourse looks
                // like "pair again" and the daemon already trusts the device.
                //
                // So the loop keeps serving. The caller learns about the
                // registration through `on_register`, which has already run, and
                // this function returns when the peer closes the stream.
            }

            ControlMessage::Ping(beat) => {
                send(&mut tx, &ControlMessage::Pong(beat)).await?;
            }

            // A daemon never receives these. Ignoring rather than erroring keeps
            // a newer client that sends something unexpected from being dropped.
            other => tracing::debug!(kind = ?other.correlation_id(), "ignoring client message"),
        }
    }

    Ok(registered)
}

async fn send(tx: &mut gonomad_transport::SendStream, message: &ControlMessage) -> Result<()> {
    let frame = Frame::cbor(FrameFlags::LAST, message).context("could not encode a response")?;
    tx.send(&frame).await.context("could not send a response")?;
    Ok(())
}
