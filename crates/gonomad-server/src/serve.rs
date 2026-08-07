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

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use gonomad_core::{DeviceIdentity, PairingSecret};
use gonomad_proto::{ControlMessage, Frame, FrameFlags, PublicKey};
use gonomad_store::Store;
use gonomad_transport::{
    Allowlist, Conn, IrohConfig, IrohTransport, PeerPolicy, ServerConfig, TcpTransport,
    DEFAULT_PORT,
};

use crate::router::{Daemon, Effect, Router};

/// A [`PeerPolicy`] that answers from the database on every handshake.
///
/// The alternative — snapshotting `list_active()` once at startup — makes
/// revocation a no-op until the daemon is restarted, which contradicts §3.6.
/// Worse, it fails in the direction that matters: a device the user explicitly
/// revoked keeps connecting.
///
/// Re-reading is necessary rather than merely tidy, because `gonomad devices
/// revoke` runs in a **different process** and edits the SQLite file directly. No
/// in-process channel can observe that; only a fresh read can.
///
/// One query per handshake is affordable — handshakes happen per connection, not
/// per request — and this deliberately does *not* cache. A TTL here would be a
/// window during which a revoked key still works, which is the whole bug.
struct LiveAllowlist {
    /// `Mutex` because `rusqlite::Connection` is `Send` but not `Sync`, and
    /// [`PeerPolicy`] requires `Sync`. Held only for the duration of one indexed
    /// read, with no `await` inside, so it cannot stall the runtime.
    store: Arc<Mutex<Store>>,
}

impl PeerPolicy for LiveAllowlist {
    fn authorize(&self, peer: &PublicKey) -> bool {
        let keys = {
            let Ok(store) = self.store.lock() else {
                // A poisoned lock means another thread panicked mid-read. Fail
                // closed: the paired-device list is unreadable, so no key can be
                // shown to be on it.
                tracing::error!("the device database lock is poisoned; refusing the peer");
                return false;
            };
            match store.devices().list_active() {
                Ok(devices) => devices.iter().map(|d| d.public_key).collect::<Vec<_>>(),
                Err(error) => {
                    // Fail closed for the same reason. An unreadable database is
                    // not evidence that a peer is authorised.
                    tracing::error!(%error, "could not read the device list; refusing the peer");
                    return false;
                }
            }
        };

        // Delegated rather than compared here so the constant-time scan in
        // `Allowlist` stays the single implementation of this check — including
        // its property of visiting every entry so the matching *position* does not
        // leak through timing.
        Allowlist::new(keys).authorize(peer)
    }
}

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

/// Runs one pairing window over iroh, so the phone can be on any network.
///
/// The Tier 1/2 counterpart to [`serve_pairing`]. Prefer this: the TCP binding
/// only works when both machines are on the same LAN, which is the single biggest
/// limitation of the Tier 0 path (`ARCHITECTURE.md` §4.2).
///
/// # Errors
///
/// Fails if the iroh endpoint cannot bind, or if the window expires with no
/// registration.
pub async fn serve_pairing_iroh(
    identity: Arc<DeviceIdentity>,
    secret: &PairingSecret,
    daemon: Arc<Daemon>,
    store: &Store,
    window: Duration,
) -> Result<(PairedDevice, IrohTransport)> {
    let transport = bind_pairing_iroh(identity, secret).await?;
    let device = run_pairing_iroh(&transport, daemon, store, window).await?;
    Ok((device, transport))
}

/// Brings up the pairing endpoint without yet waiting for a device.
///
/// Split out of [`serve_pairing_iroh`] because a pairing QR has to describe an
/// endpoint that already exists. The addresses and the relay a ticket pins are
/// properties of the bound endpoint — [`IrohTransport::addr_hints`] — so binding
/// has to happen *before* the ticket is built, not as a side effect of starting
/// to listen. Guessing them instead produces a QR that pins addresses nothing is
/// listening on.
///
/// Callers should await [`IrohTransport::online`] before rendering a ticket, so
/// the relay hint is the one the endpoint actually settled on.
///
/// # Errors
///
/// Fails if the iroh endpoint cannot bind.
pub async fn bind_pairing_iroh(
    identity: Arc<DeviceIdentity>,
    secret: &PairingSecret,
) -> Result<IrohTransport> {
    IrohTransport::bind(IrohConfig::pairing(identity, secret))
        .await
        .context("could not start the iroh endpoint")
}

/// Accepts iroh connections until a device registers or the window closes.
///
/// A failed handshake does not end the window: a wrong code, or a passer-by's QR
/// scanner, must not cost the user a fresh QR.
///
/// # Errors
///
/// Fails if the window expires before a device registers, or if the registration
/// cannot be persisted.
pub async fn run_pairing_iroh(
    transport: &IrohTransport,
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

        let accepted = tokio::time::timeout(remaining, transport.accept_iroh()).await;
        let conn = match accepted {
            Err(_) => bail!("the pairing window expired before a device registered"),
            Ok(Err(e)) => {
                // A wrong pairing code, or a scanner. Keep waiting rather than
                // making one bad attempt cost the user a fresh QR.
                tracing::debug!(error = %e, "pairing attempt failed during handshake");
                continue;
            }
            Ok(Ok(conn)) => conn,
        };

        let sas = conn.sas().digits();
        let peer = conn.peer_key();
        let tier = conn.path_info().tier;
        tracing::info!(
            peer = %peer.short(),
            tier = tier.label(),
            "pairing handshake completed; awaiting registration"
        );

        let mut router = Router::pairing(Arc::clone(&daemon), peer, sas);
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
            println!();
            println!("Paired: {name}  ({})", key.short());
            println!("Connected over {}.", tier.label());
            println!("This device can now connect from any network. Ctrl-C when you");
            println!("are done, then run `gonomad serve` for normal use.");
            Ok(())
        };

        match serve_connection(&conn, &mut router, persist).await {
            Ok(Some(device)) => return Ok(device),
            Ok(None) => tracing::debug!("peer disconnected without registering"),
            Err(e) => tracing::debug!(error = %e, "pairing connection ended"),
        }
    }
}

/// Serves paired devices over iroh until cancelled.
///
/// # Errors
///
/// Fails if no device is paired, or if the endpoint cannot bind.
pub async fn serve_iroh(
    identity: Arc<DeviceIdentity>,
    daemon: Arc<Daemon>,
    store: Store,
) -> Result<()> {
    let paired_at_start = store
        .devices()
        .list_active()
        .context("could not read the device list")?
        .len();

    // Only a startup courtesy, so `gonomad serve` with nothing paired says so
    // instead of waiting silently forever. It is *not* the authorisation decision:
    // that is `LiveAllowlist`, which re-reads per handshake, so a device paired
    // after this point is admitted without a restart.
    if paired_at_start == 0 {
        bail!("no devices are paired — run `gonomad pair` first");
    }

    let store = Arc::new(Mutex::new(store));
    let policy = Arc::new(LiveAllowlist {
        store: Arc::clone(&store),
    });
    let transport = IrohTransport::bind(IrohConfig::reconnect(identity, policy))
        .await
        .context("could not start the iroh endpoint")?;

    // Wait for the endpoint to learn its own reachability before claiming to be
    // serving. Without this the first line printed can be a lie: the endpoint
    // exists but has no relay assigned yet, so a phone dialling immediately fails.
    transport.online().await;

    println!("  node id     {}", transport.node_id().short());
    println!("  devices     {paired_at_start}");
    tracing::info!(devices = paired_at_start, "serving over iroh");

    loop {
        let conn = match transport.accept_iroh().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::debug!(error = %e, "connection rejected");
                continue;
            }
        };

        let peer = conn.peer_key();
        let device_id = gonomad_proto::DeviceId::from_public_key(&peer);
        // Read afresh here too, so a capability changed on the machine applies to
        // the next connection rather than to the next daemon restart.
        let granted = store
            .lock()
            .map(|store| store.devices().grants(&device_id).unwrap_or_default())
            .unwrap_or_default();
        let grant = gonomad_policy::DeviceGrant::new(device_id, granted);

        tracing::info!(
            device = %device_id.short(),
            tier = conn.path_info().tier.label(),
            "device connected"
        );
        let daemon = Arc::clone(&daemon);

        tokio::spawn(async move {
            let mut router = Router::established(daemon, peer, grant);
            let no_registration = |_: &PublicKey, _: &str, _: Option<&str>| Ok(());
            if let Err(e) = serve_connection(&conn, &mut router, no_registration).await {
                tracing::debug!(error = %e, "connection ended");
            }
            tracing::info!(device = %device_id.short(), "device disconnected");
        });
    }
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

        match serve_connection(&conn, &mut router, persist).await {
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
            if let Err(e) = serve_connection(&conn, &mut router, no_registration).await {
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
async fn serve_connection<F>(
    conn: &dyn Conn,
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

#[cfg(test)]
mod tests {
    use gonomad_proto::{CapabilitySet, DeviceId};

    use super::{Arc, LiveAllowlist, Mutex, PeerPolicy, PublicKey, Store};

    /// Builds a live allowlist over an empty in-memory database.
    fn allowlist() -> (LiveAllowlist, Arc<Mutex<Store>>) {
        let store = Arc::new(Mutex::new(
            Store::open_in_memory().expect("open an in-memory store"),
        ));
        (
            LiveAllowlist {
                store: Arc::clone(&store),
            },
            store,
        )
    }

    #[test]
    fn revoking_a_device_takes_effect_without_restarting_the_daemon() {
        // `ARCHITECTURE.md` §3.6 and §19 R29. The bug this pins: building the
        // allowlist once at startup made `gonomad devices revoke` a no-op until the
        // daemon was restarted, so a device the user had explicitly cut off kept
        // connecting. The policy object here is created ONCE and never rebuilt —
        // that is the whole point, because it stands in for a daemon that is still
        // running while the device list changes underneath it.
        let (policy, store) = allowlist();
        let key = PublicKey::from_bytes([7; 32]);

        // Not paired yet, so refused.
        assert!(
            !policy.authorize(&key),
            "an unknown key must never be authorised"
        );

        store
            .lock()
            .expect("lock")
            .devices()
            .pair(&key, "Pixel 9", None, CapabilitySet::default_grant())
            .expect("pair");
        assert!(
            policy.authorize(&key),
            "a freshly paired device must be admitted without a restart"
        );

        assert!(store
            .lock()
            .expect("lock")
            .devices()
            .revoke(&DeviceId::from_public_key(&key))
            .expect("revoke"));
        assert!(
            !policy.authorize(&key),
            "a revoked device must be refused by the same policy object, with no restart"
        );
    }

    #[test]
    fn an_unreadable_device_list_refuses_the_peer_rather_than_admitting_it() {
        // Fail closed. An unreadable database is not evidence that a key is on the
        // allowlist, and the safe default for an authorisation check that cannot
        // reach its data is "no".
        let (policy, store) = allowlist();
        let key = PublicKey::from_bytes([9; 32]);
        store
            .lock()
            .expect("lock")
            .devices()
            .pair(&key, "Pixel 9", None, CapabilitySet::default_grant())
            .expect("pair");
        assert!(policy.authorize(&key), "sanity: the device is paired");

        // Poison the lock, which is what a panic in another thread leaves behind.
        let poisoned = Arc::clone(&store);
        std::thread::spawn(move || {
            let _guard = poisoned.lock().expect("lock");
            panic!("poison the mutex on purpose");
        })
        .join()
        .expect_err("the thread panicked as intended");

        assert!(
            !policy.authorize(&key),
            "a poisoned lock must refuse, not admit"
        );
    }
}
