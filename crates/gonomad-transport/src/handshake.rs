//! The Noise IK handshake, and the length-prefixed framing that carries it.
//!
//! Shared verbatim by every binding: [`crate::tcp`] runs it over a TCP socket and
//! [`crate::iroh`] runs it inside a QUIC stream. That sharing is the point.
//! `ARCHITECTURE.md` §3.4 puts Noise *inside* the transport so that security is a
//! property of the session layer rather than of whichever rung of the ladder
//! happens to be carrying traffic — and a reviewer auditing the handshake should
//! have exactly one implementation to audit, not one per transport.
//!
//! # Framing
//!
//! ```text
//! → u16 len | Noise message 1   (initiator: e, es, s, ss [, psk])
//! ← u16 len | Noise message 2   (responder: e, ee, se [, psk])
//! ```
//!
//! A `u16` prefix, not a [`gonomad_proto::Frame`], for three reasons:
//!
//! 1. **The bound is structural.** A Noise message cannot exceed 65535 bytes by
//!    specification, so a `u16` makes an over-long claim unrepresentable rather
//!    than something to validate. `Frame`'s `u32` would have to be bounds-checked
//!    against a limit chosen by us, on the pre-authentication path, which is
//!    exactly where the fewest moving parts are worth the most (§3.7).
//! 2. **No attacker-controlled fields before authentication.** `Frame` carries a
//!    flags byte with rejection rules. Parsing it before anything is
//!    authenticated adds surface for no benefit — a handshake message has no
//!    flags, is never compressed, and is never CBOR.
//! 3. **Nothing identifies the protocol.** There is no magic number, no version
//!    byte, and no ALPN-equivalent in the clear. On TCP, a port scanner sees an
//!    accepting socket that emits a length-prefixed blob of high-entropy bytes
//!    and closes. That is the §3.7 "presents nothing to a scanner" property. (On
//!    QUIC the ALPN does the gating, one layer down, before this code runs at
//!    all.)
//!
//! There is no purpose byte announcing pairing versus reconnect either. The
//! responder already knows: pairing is an explicit, operator-initiated,
//! 120-second window (§9.1), so the daemon is configured for
//! [`Purpose::Pairing`] only while that window is open. Letting the *client*
//! choose which pattern to run would let an attacker ask for the pairing pattern
//! whenever it liked.
//!
//! # A wrong pairing secret is detected by the initiator, not the responder
//!
//! Worth stating because it looks like a hole and is not one (R24 in §19). In
//! `IKpsk2` the pre-shared key is mixed into the **second** message — the one the
//! responder writes — so the responder cannot tell a wrong PSK from a right one.
//! It completes its side and produces a session; the initiator's AEAD check then
//! fails and it aborts.
//!
//! The consequence is that a daemon in a pairing window can be made to hold a
//! short-lived, useless session by anyone who can reach it: useless because the
//! two sides derived different keys, so the very first record fails to decrypt.
//! What must **not** happen is a device being registered on the strength of a
//! completed handshake alone. Registration is the caller's job and must wait for
//! an authenticated application exchange over the control stream — which is
//! impossible to fake, precisely because the keys disagree.

use std::time::{Duration, Instant};

use gonomad_core::session::NOISE_MAX_MESSAGE_LEN;
use gonomad_core::{DeviceIdentity, Handshake, Purpose};
use gonomad_proto::PublicKey;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{from_session, Result, TransportError};
use crate::traits::PeerPolicy;

/// Bytes of length prefix in front of each handshake message.
pub(crate) const PREFIX_LEN: usize = 2;

/// A completed, mutually authenticated handshake.
///
/// Returned by both [`initiate`] and [`respond`] so the two paths converge on one
/// shape: the caller turns it into a [`gonomad_core::Session`] and never has to
/// know which side it was.
pub(crate) struct Authenticated {
    /// The finished handshake, ready for `into_session`.
    pub handshake: Handshake,
    /// The peer's authenticated X25519 Noise static key.
    pub peer: PublicKey,
    /// Round-trip time measured across the two flights.
    ///
    /// `Some` only for the initiator: it is the side that has both a send and a
    /// matching receive to time. The responder reports `None` rather than
    /// inventing a number (see [`crate::PathInfo::rtt_ms`]).
    pub rtt: Option<Duration>,
}

/// Runs the initiator half of the handshake over `stream`.
///
/// Writes message 1, reads message 2, and verifies that the peer that answered is
/// the one we dialled.
///
/// # Errors
///
/// Returns [`TransportError::HandshakeFailed`] for any Noise or I/O failure —
/// deliberately without distinguishing them — or [`TransportError::WrongPeer`] if
/// the responder's static key is not `remote`.
pub(crate) async fn initiate<S>(
    stream: &mut S,
    identity: &DeviceIdentity,
    remote: &PublicKey,
    purpose: Purpose,
    psk: Option<&[u8; 32]>,
) -> Result<Authenticated>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut handshake =
        Handshake::initiator(identity, remote, purpose, psk).map_err(from_session)?;

    let mut buf = vec![0u8; NOISE_MAX_MESSAGE_LEN];
    let mut scratch = vec![0u8; NOISE_MAX_MESSAGE_LEN];

    let len = handshake
        .write_message(&[], &mut buf)
        .map_err(|_| TransportError::HandshakeFailed)?;

    // The RTT sample the UI shows is taken here: one flight out, one back, with
    // no application work in between, so it measures the path and not the
    // daemon's scheduler.
    let started = Instant::now();
    write_message(stream, &buf[..len]).await?;
    let len = read_message(stream, &mut buf).await?;
    let rtt = started.elapsed();

    handshake
        .read_message(&buf[..len], &mut scratch)
        .map_err(|_| TransportError::HandshakeFailed)?;

    if !handshake.is_finished() {
        return Err(TransportError::HandshakeFailed);
    }

    // IK authenticates the responder by construction, so this can only fire if
    // something is deeply wrong. Checked anyway: proceeding on a connection whose
    // peer is not who we dialled is never the right recovery.
    let peer = handshake
        .remote_static()
        .ok_or(TransportError::HandshakeFailed)?;
    if &peer != remote {
        return Err(TransportError::WrongPeer);
    }

    Ok(Authenticated {
        handshake,
        peer,
        rtt: Some(rtt),
    })
}

/// Runs the responder half of the handshake over `stream`.
///
/// Authorisation runs **between the two flights**: the peer's static key is known
/// once message 1 is read, so an unpaired device is dropped without a reply and
/// learns nothing beyond "the connection closed" (§3.7).
///
/// # Errors
///
/// Returns [`TransportError::HandshakeFailed`] for any Noise or I/O failure, or
/// [`TransportError::PeerNotAuthorized`] when `policy` rejects the peer's key.
pub(crate) async fn respond<S>(
    stream: &mut S,
    identity: &DeviceIdentity,
    purpose: Purpose,
    psk: Option<&[u8; 32]>,
    policy: &dyn PeerPolicy,
) -> Result<Authenticated>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut handshake = Handshake::responder(identity, purpose, psk).map_err(from_session)?;

    let mut buf = vec![0u8; NOISE_MAX_MESSAGE_LEN];
    let mut scratch = vec![0u8; NOISE_MAX_MESSAGE_LEN];

    let len = read_message(stream, &mut buf).await?;
    handshake
        .read_message(&buf[..len], &mut scratch)
        .map_err(|_| TransportError::HandshakeFailed)?;

    let peer = handshake
        .remote_static()
        .ok_or(TransportError::HandshakeFailed)?;
    if !policy.authorize(&peer) {
        return Err(TransportError::PeerNotAuthorized);
    }

    let len = handshake
        .write_message(&[], &mut buf)
        .map_err(|_| TransportError::HandshakeFailed)?;
    write_message(stream, &buf[..len]).await?;

    if !handshake.is_finished() {
        return Err(TransportError::HandshakeFailed);
    }

    Ok(Authenticated {
        handshake,
        peer,
        rtt: None,
    })
}

/// Writes one length-prefixed handshake message.
async fn write_message<S>(stream: &mut S, message: &[u8]) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let len = u16::try_from(message.len()).map_err(|_| TransportError::HandshakeFailed)?;
    // One write, so the prefix and the body cannot be split across a packet
    // boundary by Nagle being off.
    let mut out = Vec::with_capacity(PREFIX_LEN + message.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(message);
    stream
        .write_all(&out)
        .await
        .map_err(|_| TransportError::HandshakeFailed)?;
    stream
        .flush()
        .await
        .map_err(|_| TransportError::HandshakeFailed)
}

/// Reads one length-prefixed handshake message into `buf`.
///
/// Bounded by `buf`, which callers size to the Noise maximum, so a peer cannot
/// make this allocate. An empty or over-long message is refused before any read
/// of the body.
async fn read_message<S>(stream: &mut S, buf: &mut [u8]) -> Result<usize>
where
    S: AsyncRead + Unpin,
{
    let mut prefix = [0u8; PREFIX_LEN];
    stream
        .read_exact(&mut prefix)
        .await
        .map_err(|_| TransportError::HandshakeFailed)?;
    let len = usize::from(u16::from_be_bytes(prefix));
    if len == 0 || len > buf.len() {
        return Err(TransportError::HandshakeFailed);
    }
    stream
        .read_exact(&mut buf[..len])
        .await
        .map_err(|_| TransportError::HandshakeFailed)?;
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{AllowAny, Allowlist};
    use std::sync::Arc;

    /// Runs both halves against each other over an in-memory duplex.
    async fn exchange(
        purpose: Purpose,
        client_psk: Option<[u8; 32]>,
        server_psk: Option<[u8; 32]>,
        policy: Arc<dyn PeerPolicy>,
    ) -> (Result<Authenticated>, Result<Authenticated>) {
        let client = Arc::new(DeviceIdentity::generate());
        let daemon = Arc::new(DeviceIdentity::generate());
        let daemon_key = daemon.noise_public_key();
        let (a, b) = tokio::io::duplex(64 * 1024);

        let dialing = tokio::spawn({
            let client = Arc::clone(&client);
            async move {
                let mut a = a;
                initiate(&mut a, &client, &daemon_key, purpose, client_psk.as_ref()).await
            }
        });
        let accepting = tokio::spawn(async move {
            let mut b = b;
            respond(
                &mut b,
                &daemon,
                purpose,
                server_psk.as_ref(),
                policy.as_ref(),
            )
            .await
        });

        (
            dialing.await.expect("dialer task"),
            accepting.await.expect("responder task"),
        )
    }

    #[tokio::test]
    async fn a_reconnect_handshake_authenticates_both_sides() {
        let (client, server) = exchange(Purpose::Reconnect, None, None, Arc::new(AllowAny)).await;
        let client = client.expect("initiator");
        let server = server.expect("responder");
        // Both must derive the same SAS, or pairing could not work at all.
        assert_eq!(
            client.handshake.sas().expect("client sas"),
            server.handshake.sas().expect("server sas")
        );
        assert!(client.rtt.is_some(), "the initiator times the round trip");
        assert!(server.rtt.is_none(), "the responder has nothing to time");
    }

    #[tokio::test]
    async fn a_wrong_pre_shared_key_is_caught_by_the_initiator() {
        // R24: IKpsk2 mixes the PSK into the responder's message, so the
        // responder completes and the *initiator* rejects.
        let (client, _server) = exchange(
            Purpose::Pairing,
            Some([1u8; 32]),
            Some([2u8; 32]),
            Arc::new(AllowAny),
        )
        .await;
        assert!(matches!(client, Err(TransportError::HandshakeFailed)));
    }

    #[tokio::test]
    async fn an_unlisted_peer_is_refused_between_the_two_flights() {
        let (_client, server) = exchange(
            Purpose::Reconnect,
            None,
            None,
            Arc::new(Allowlist::default()),
        )
        .await;
        assert!(matches!(server, Err(TransportError::PeerNotAuthorized)));
    }

    #[tokio::test]
    async fn a_zero_length_message_is_refused_without_reading_a_body() {
        // A peer that claims zero bytes is either broken or probing; either way
        // there is no Noise message to parse.
        let (mut a, mut b) = tokio::io::duplex(64);
        let writer = tokio::spawn(async move { a.write_all(&0u16.to_be_bytes()).await });
        let mut buf = [0u8; 64];
        assert!(matches!(
            read_message(&mut b, &mut buf).await,
            Err(TransportError::HandshakeFailed)
        ));
        drop(writer.await.expect("writer task"));
    }

    #[tokio::test]
    async fn a_message_longer_than_the_buffer_is_refused() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let writer = tokio::spawn(async move { a.write_all(&99u16.to_be_bytes()).await });
        let mut buf = [0u8; 8];
        assert!(matches!(
            read_message(&mut b, &mut buf).await,
            Err(TransportError::HandshakeFailed)
        ));
        drop(writer.await.expect("writer task"));
    }
}
