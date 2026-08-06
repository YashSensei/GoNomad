//! The Noise IK session layer.
//!
//! Every byte of application traffic is encrypted here, on top of whatever
//! transport is carrying it (`ARCHITECTURE.md` §3.4).
//!
//! # Why this exists on top of QUIC, which is already encrypted
//!
//! iroh's QUIC already provides mutual TLS 1.3 with raw public keys, so this
//! layer is genuinely redundant on the default path. It is here anyway, and the
//! reason is worth stating precisely because "we encrypt twice" invites deletion
//! by a future contributor looking for simplifications:
//!
//! - It makes security **independent of transport**. Adding the WebSocket
//!   fallback binding (§10.6) or a Cloudflare Tunnel later cannot weaken the
//!   threat model. Cloudflare terminates TLS and would otherwise see plaintext;
//!   with Noise inside, it sees ciphertext.
//! - The relayed path and the direct path therefore have *identical* security
//!   properties. Users never face a "is relaying safe?" question, and we never
//!   face pressure to answer it optimistically.
//! - The security review has one thing to audit, not one per transport.
//!
//! The cost is one extra AEAD pass per frame, which is immaterial against
//! ChaCha20-Poly1305 throughput on any ARMv8 core and is dwarfed by the
//! compression that runs beside it.
//!
//! # Why the IK pattern
//!
//! In `IK`, the initiator (the phone) already knows the responder's static key —
//! it learned it from the pairing QR over an optical channel (§9.2). That gives
//! three properties this product specifically needs:
//!
//! 1. **One round trip.** The phone's first message already carries application
//!    data, so a reconnect after a network change costs a single flight.
//! 2. **The initiator's identity is encrypted** to the responder's static key, so
//!    a passive observer — including a relay — cannot learn *which* device is
//!    connecting. That is real metadata protection the relay would otherwise get
//!    for free.
//! 3. **The responder authenticates the initiator before any application data**,
//!    which is what lets the daemon reject an unpaired key without ever running
//!    a request handler.
//!
//! `XX` was the alternative and is rejected: it takes an extra round trip and
//! transmits the initiator's identity without the responder's key being known in
//! advance — solving a problem the QR already solved, at a cost the phone pays on
//! every reconnect.
//!
//! # Pairing versus reconnecting
//!
//! Both use `IK`, differing only in whether a pre-shared key is mixed in:
//!
//! | Phase | PSK | Why |
//! |---|---|---|
//! | Pairing | The 256-bit [`crate::PairingSecret`] | Proves the initiator actually saw the screen, not merely that it knows the daemon's public key — which is not secret |
//! | Reconnecting | None | The device's registered static key is the credential; there is nothing else to prove |

use core::fmt;

use gonomad_proto::PublicKey;
use snow::{HandshakeState, TransportState};
use zeroize::Zeroizing;

use crate::identity::{DeviceIdentity, SEED_LEN};
use crate::sas::Sas;

/// The Noise pattern and cipher suite, as a Noise protocol name.
///
/// ChaCha20-Poly1305 rather than AES-GCM: it is constant-time in software on
/// every platform, which matters because the phone's Rust core cannot rely on
/// AES-NI being present or on the JVM exposing it.
pub const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// The Noise pattern used while pairing, which additionally mixes in the
/// pairing secret as a pre-shared key at position 2.
///
/// `psk2` places the PSK mix after the initiator's static key is known, so the
/// PSK authenticates the whole exchange rather than only its start.
pub const NOISE_PARAMS_PAIRING: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

/// Largest ciphertext a single Noise message can hold, from the Noise spec.
pub const NOISE_MAX_MESSAGE_LEN: usize = 65535;

/// Bytes of AEAD tag overhead added to every encrypted message.
pub const NOISE_TAG_LEN: usize = 16;

/// Largest plaintext that fits in one Noise message.
pub const MAX_PLAINTEXT_LEN: usize = NOISE_MAX_MESSAGE_LEN - NOISE_TAG_LEN;

/// Errors from the session layer.
///
/// Deliberately coarse. A handshake failure must not tell a peer *why* it
/// failed — whether the key was unrecognised, the PSK wrong, or the message
/// malformed — because that distinction is exactly what an attacker probes for.
/// The daemon logs the precise cause locally and returns
/// [`SessionError::HandshakeFailed`] to the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SessionError {
    /// The handshake did not complete.
    #[error("handshake failed")]
    HandshakeFailed,

    /// A message could not be decrypted or authenticated.
    ///
    /// Covers a wrong key, a tampered ciphertext, and a replayed message
    /// alike — all are "this byte stream is not what it claims".
    #[error("message failed to decrypt or authenticate")]
    DecryptFailed,

    /// A plaintext exceeded [`MAX_PLAINTEXT_LEN`].
    #[error("plaintext of {len} bytes exceeds the {MAX_PLAINTEXT_LEN} byte Noise message limit")]
    TooLong {
        /// The length that was attempted.
        len: usize,
    },

    /// An operation was attempted in the wrong phase.
    ///
    /// For example encrypting before the handshake completed, or reading the
    /// remote key before it has been received.
    #[error("operation is not valid in this session state")]
    WrongState,

    /// The nonce counter is exhausted.
    ///
    /// Noise permits 2^64 - 1 messages per key; past that, reuse would be
    /// catastrophic, so the session refuses to continue and must be rekeyed by
    /// reconnecting. Unreachable in practice at any plausible message rate, and
    /// handled rather than assumed away.
    #[error("nonce space exhausted; the session must be re-established")]
    NonceExhausted,
}

/// Whether a handshake is establishing a new pairing or resuming a known one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// A first-time pairing, authenticated by the QR's pre-shared secret.
    Pairing,
    /// A reconnect by an already-paired device.
    Reconnect,
}

impl Purpose {
    /// The Noise protocol name for this purpose.
    #[must_use]
    pub const fn params(self) -> &'static str {
        match self {
            Self::Pairing => NOISE_PARAMS_PAIRING,
            Self::Reconnect => NOISE_PARAMS,
        }
    }
}

/// A handshake in progress.
///
/// Consumed by [`Handshake::into_session`] once complete, so the type system
/// prevents encrypting application data before authentication finishes — the
/// mistake that would make the whole layer decorative.
pub struct Handshake {
    state: HandshakeState,
    purpose: Purpose,
}

impl Handshake {
    /// Starts a handshake as the initiator (the phone).
    ///
    /// `remote_static` is the daemon's public key, learned from the pairing QR.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::HandshakeFailed`] if the Noise state cannot be
    /// built, which indicates a malformed key rather than a network condition.
    pub fn initiator(
        identity: &DeviceIdentity,
        remote_static: &PublicKey,
        purpose: Purpose,
        psk: Option<&[u8; 32]>,
    ) -> Result<Self, SessionError> {
        // The seed must outlive the builder, because `snow::Builder` borrows the
        // key rather than copying it. Keeping it in this scope and completing the
        // build here is what makes that safe; factoring the builder out into a
        // helper would drop the seed while it was still borrowed.
        // The X25519 static secret, NOT the master seed and NOT the Ed25519 key.
        // See `DeviceIdentity::noise_public_key` for why these are separate.
        let seed: Zeroizing<[u8; SEED_LEN]> = identity.expose_noise_secret();

        let mut builder = snow::Builder::new(Self::params(purpose)?)
            .local_private_key(seed.as_ref())
            .remote_public_key(remote_static.as_bytes());

        if let Some(psk) = psk {
            builder = builder.psk(2, psk);
        }

        let state = builder
            .build_initiator()
            .map_err(|_| SessionError::HandshakeFailed)?;
        Ok(Self { state, purpose })
    }

    /// Starts a handshake as the responder (the daemon).
    ///
    /// The responder does not need to know the initiator's key in advance: `IK`
    /// delivers it, encrypted, inside the first message. That is precisely what
    /// keeps a relay from learning which device is connecting.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::HandshakeFailed`] if the Noise state cannot be
    /// built.
    pub fn responder(
        identity: &DeviceIdentity,
        purpose: Purpose,
        psk: Option<&[u8; 32]>,
    ) -> Result<Self, SessionError> {
        // The X25519 static secret, NOT the master seed and NOT the Ed25519 key.
        // See `DeviceIdentity::noise_public_key` for why these are separate.
        let seed: Zeroizing<[u8; SEED_LEN]> = identity.expose_noise_secret();

        let mut builder =
            snow::Builder::new(Self::params(purpose)?).local_private_key(seed.as_ref());

        if let Some(psk) = psk {
            builder = builder.psk(2, psk);
        }

        let state = builder
            .build_responder()
            .map_err(|_| SessionError::HandshakeFailed)?;
        Ok(Self { state, purpose })
    }

    /// Parses the Noise protocol name for `purpose`.
    ///
    /// # A note on key reuse
    ///
    /// Noise uses X25519 for Diffie-Hellman, while the device identity is an
    /// Ed25519 signing key. Both are derived from the same 32-byte seed, so a
    /// device has exactly one secret to store, back up, and revoke.
    ///
    /// This is safe here because each algorithm derives its own scalar by
    /// hashing the seed with its own procedure, so neither ever operates on the
    /// other's scalar, and the two are never applied to a shared message space.
    /// It is nonetheless the kind of reuse that is unsafe in general, so it is
    /// documented rather than left for a reviewer to infer. If a future audit
    /// objects, the fix is to derive two subkeys with domain-separated HKDF from
    /// one seed, which changes no stored material.
    fn params(purpose: Purpose) -> Result<snow::params::NoiseParams, SessionError> {
        purpose
            .params()
            .parse()
            .map_err(|_| SessionError::HandshakeFailed)
    }

    /// Writes the next handshake message into `out`, returning its length.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::HandshakeFailed`] if it is not this side's turn
    /// to write, or if the buffer is too small.
    pub fn write_message(&mut self, payload: &[u8], out: &mut [u8]) -> Result<usize, SessionError> {
        self.state
            .write_message(payload, out)
            .map_err(|_| SessionError::HandshakeFailed)
    }

    /// Reads a handshake message from the peer, writing any payload into `out`.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::HandshakeFailed`] on a malformed message, a
    /// failed authentication, or a wrong-turn read. The cause is deliberately
    /// not distinguished (see [`SessionError`]).
    pub fn read_message(&mut self, message: &[u8], out: &mut [u8]) -> Result<usize, SessionError> {
        self.state
            .read_message(message, out)
            .map_err(|_| SessionError::HandshakeFailed)
    }

    /// Whether the handshake has completed and can become a session.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// The peer's static public key, once received.
    ///
    /// For the daemon this is the device's credential, checked against the
    /// paired allowlist. It is available after the first message is read, which
    /// is why the daemon can reject an unpaired key before running any handler.
    #[must_use]
    pub fn remote_static(&self) -> Option<PublicKey> {
        self.state
            .get_remote_static()
            .and_then(|k| PublicKey::from_slice(k).ok())
    }

    /// The six-digit SAS derived from the handshake transcript.
    ///
    /// Both peers compute this independently. A man-in-the-middle proxying the
    /// connection necessarily produces a different transcript on each side, so
    /// the digits disagree and the human comparing them sees it (§9.2).
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::WrongState`] before the handshake is finished,
    /// since a partial transcript would produce digits that do not match the
    /// peer's.
    pub fn sas(&self) -> Result<Sas, SessionError> {
        if !self.is_finished() {
            return Err(SessionError::WrongState);
        }
        Ok(Sas::derive(self.state.get_handshake_hash()))
    }

    /// Which kind of handshake this is.
    #[must_use]
    pub const fn purpose(&self) -> Purpose {
        self.purpose
    }

    /// Converts a completed handshake into a transport session.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::WrongState`] if the handshake has not finished.
    pub fn into_session(self) -> Result<Session, SessionError> {
        if !self.is_finished() {
            return Err(SessionError::WrongState);
        }
        let remote_static = self.remote_static();
        let handshake_hash = {
            let mut h = [0u8; 32];
            let got = self.state.get_handshake_hash();
            let n = got.len().min(32);
            h[..n].copy_from_slice(&got[..n]);
            h
        };
        let state = self
            .state
            .into_transport_mode()
            .map_err(|_| SessionError::WrongState)?;
        Ok(Session {
            state,
            remote_static,
            handshake_hash,
        })
    }
}

// Never prints key material or transcript state.
impl fmt::Debug for Handshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Handshake")
            .field("purpose", &self.purpose)
            .field("finished", &self.is_finished())
            .finish_non_exhaustive()
    }
}

/// An established session that encrypts and decrypts application frames.
pub struct Session {
    state: TransportState,
    remote_static: Option<PublicKey>,
    handshake_hash: [u8; 32],
}

impl Session {
    /// Encrypts `plaintext` into `out`, returning the ciphertext length.
    ///
    /// Noise's internal nonce counter increments per message, so replay within a
    /// session is rejected by construction and nonce reuse is impossible.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::TooLong`] if `plaintext` exceeds
    /// [`MAX_PLAINTEXT_LEN`], or [`SessionError::NonceExhausted`] if the nonce
    /// space is spent.
    pub fn encrypt(&mut self, plaintext: &[u8], out: &mut [u8]) -> Result<usize, SessionError> {
        if plaintext.len() > MAX_PLAINTEXT_LEN {
            return Err(SessionError::TooLong {
                len: plaintext.len(),
            });
        }
        self.state
            .write_message(plaintext, out)
            .map_err(|e| match e {
                snow::Error::State(snow::error::StateProblem::Exhausted) => {
                    SessionError::NonceExhausted
                }
                _ => SessionError::DecryptFailed,
            })
    }

    /// Decrypts `ciphertext` into `out`, returning the plaintext length.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::DecryptFailed`] if authentication fails for any
    /// reason, or [`SessionError::NonceExhausted`] if the nonce space is spent.
    pub fn decrypt(&mut self, ciphertext: &[u8], out: &mut [u8]) -> Result<usize, SessionError> {
        self.state
            .read_message(ciphertext, out)
            .map_err(|e| match e {
                snow::Error::State(snow::error::StateProblem::Exhausted) => {
                    SessionError::NonceExhausted
                }
                _ => SessionError::DecryptFailed,
            })
    }

    /// The peer's static public key.
    #[must_use]
    pub const fn remote_static(&self) -> Option<PublicKey> {
        self.remote_static
    }

    /// The final handshake hash, suitable as a channel binding.
    ///
    /// Binding a later signature to this value ties it to *this* session, so a
    /// signature captured from one connection cannot be replayed into another.
    #[must_use]
    pub const fn channel_binding(&self) -> &[u8; 32] {
        &self.handshake_hash
    }

    /// The SAS for this session's transcript.
    #[must_use]
    pub fn sas(&self) -> Sas {
        Sas::derive(&self.handshake_hash)
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("remote", &self.remote_static.map(|k| k.short()))
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs a full IK handshake and returns both sides' sessions.
    fn handshake(
        purpose: Purpose,
        psk: Option<&[u8; 32]>,
        client: &DeviceIdentity,
        daemon: &DeviceIdentity,
    ) -> Result<(Session, Session), SessionError> {
        let mut init = Handshake::initiator(client, &daemon.noise_public_key(), purpose, psk)?;
        let mut resp = Handshake::responder(daemon, purpose, psk)?;

        let mut buf1 = vec![0u8; NOISE_MAX_MESSAGE_LEN];
        let n = init.write_message(&[], &mut buf1)?;

        let mut scratch = vec![0u8; NOISE_MAX_MESSAGE_LEN];
        resp.read_message(&buf1[..n], &mut scratch)?;

        let mut buf2 = vec![0u8; NOISE_MAX_MESSAGE_LEN];
        let n2 = resp.write_message(&[], &mut buf2)?;
        init.read_message(&buf2[..n2], &mut scratch)?;

        assert!(init.is_finished() && resp.is_finished());
        Ok((init.into_session()?, resp.into_session()?))
    }

    fn pair() -> (DeviceIdentity, DeviceIdentity) {
        (DeviceIdentity::generate(), DeviceIdentity::generate())
    }

    #[test]
    fn reconnect_handshake_completes_in_two_messages() {
        let (client, daemon) = pair();
        handshake(Purpose::Reconnect, None, &client, &daemon).expect("handshake");
    }

    #[test]
    fn pairing_handshake_completes_with_a_psk() {
        let (client, daemon) = pair();
        let psk = [0x5Au8; 32];
        handshake(Purpose::Pairing, Some(&psk), &client, &daemon).expect("handshake");
    }

    #[test]
    fn pairing_fails_when_the_psk_differs() {
        // The property that makes the QR secret meaningful: knowing the daemon's
        // public key is not enough, because that key is not secret.
        let (client, daemon) = pair();
        let mut init = Handshake::initiator(
            &client,
            &daemon.noise_public_key(),
            Purpose::Pairing,
            Some(&[1u8; 32]),
        )
        .unwrap();
        let mut resp = Handshake::responder(&daemon, Purpose::Pairing, Some(&[2u8; 32])).unwrap();

        let mut buf = vec![0u8; NOISE_MAX_MESSAGE_LEN];
        let n = init.write_message(&[], &mut buf).unwrap();
        let mut scratch = vec![0u8; NOISE_MAX_MESSAGE_LEN];

        // IKpsk2 mixes the PSK into the second message, so the mismatch surfaces
        // when the initiator reads the response rather than immediately.
        let first = resp.read_message(&buf[..n], &mut scratch);
        if first.is_ok() {
            let n2 = resp.write_message(&[], &mut buf).unwrap();
            assert_eq!(
                init.read_message(&buf[..n2], &mut scratch),
                Err(SessionError::HandshakeFailed)
            );
        }
    }

    #[test]
    fn the_daemon_learns_the_client_key_and_can_check_its_allowlist() {
        // This is what lets an unpaired key be rejected before any handler runs.
        let (client, daemon) = pair();
        let (_client_session, daemon_session) =
            handshake(Purpose::Reconnect, None, &client, &daemon).unwrap();
        assert_eq!(
            daemon_session.remote_static(),
            Some(client.noise_public_key())
        );
    }

    #[test]
    fn the_client_confirms_it_reached_the_expected_daemon() {
        let (client, daemon) = pair();
        let (client_session, _) = handshake(Purpose::Reconnect, None, &client, &daemon).unwrap();
        assert_eq!(
            client_session.remote_static(),
            Some(daemon.noise_public_key())
        );
    }

    #[test]
    fn connecting_to_the_wrong_daemon_key_fails() {
        // A phone that scanned one laptop's QR must not authenticate to another.
        let (client, daemon) = pair();
        let impostor = DeviceIdentity::generate();

        let mut init = Handshake::initiator(
            &client,
            &impostor.noise_public_key(),
            Purpose::Reconnect,
            None,
        )
        .unwrap();
        let mut resp = Handshake::responder(&daemon, Purpose::Reconnect, None).unwrap();

        let mut buf = vec![0u8; NOISE_MAX_MESSAGE_LEN];
        let n = init.write_message(&[], &mut buf).unwrap();
        let mut scratch = vec![0u8; NOISE_MAX_MESSAGE_LEN];
        assert_eq!(
            resp.read_message(&buf[..n], &mut scratch),
            Err(SessionError::HandshakeFailed)
        );
    }

    #[test]
    fn both_sides_derive_the_same_sas() {
        // Pairing is impossible unless this holds.
        let (client, daemon) = pair();
        let (a, b) = handshake(Purpose::Reconnect, None, &client, &daemon).unwrap();
        assert_eq!(a.sas(), b.sas());
    }

    #[test]
    fn distinct_sessions_derive_distinct_sas_values() {
        // The MITM signal: two different connections must not show the same
        // digits, or a proxying attacker could not be distinguished.
        let (client, daemon) = pair();
        let (a, _) = handshake(Purpose::Reconnect, None, &client, &daemon).unwrap();
        let (b, _) = handshake(Purpose::Reconnect, None, &client, &daemon).unwrap();
        assert_ne!(
            a.sas(),
            b.sas(),
            "ephemeral keys should make every transcript unique"
        );
    }

    #[test]
    fn sas_is_unavailable_before_the_handshake_finishes() {
        // A partial transcript would produce digits that do not match the peer's,
        // which would train users to ignore a mismatch.
        let (client, daemon) = pair();
        let init = Handshake::initiator(
            &client,
            &daemon.noise_public_key(),
            Purpose::Reconnect,
            None,
        )
        .unwrap();
        assert_eq!(init.sas(), Err(SessionError::WrongState));
    }

    #[test]
    fn an_unfinished_handshake_cannot_become_a_session() {
        // The type-level guarantee that application data cannot be sent before
        // authentication completes.
        let (client, daemon) = pair();
        let init = Handshake::initiator(
            &client,
            &daemon.noise_public_key(),
            Purpose::Reconnect,
            None,
        )
        .unwrap();
        assert!(matches!(init.into_session(), Err(SessionError::WrongState)));
    }

    #[test]
    fn messages_round_trip_in_both_directions() {
        let (client, daemon) = pair();
        let (mut c, mut d) = handshake(Purpose::Reconnect, None, &client, &daemon).unwrap();

        let mut ct = vec![0u8; NOISE_MAX_MESSAGE_LEN];
        let mut pt = vec![0u8; NOISE_MAX_MESSAGE_LEN];

        let n = c.encrypt(b"fs.read src/main.rs", &mut ct).unwrap();
        let m = d.decrypt(&ct[..n], &mut pt).unwrap();
        assert_eq!(&pt[..m], b"fs.read src/main.rs");

        let n = d.encrypt(b"fn main() {}", &mut ct).unwrap();
        let m = c.decrypt(&ct[..n], &mut pt).unwrap();
        assert_eq!(&pt[..m], b"fn main() {}");
    }

    #[test]
    fn ciphertext_does_not_contain_the_plaintext() {
        let (client, daemon) = pair();
        let (mut c, _) = handshake(Purpose::Reconnect, None, &client, &daemon).unwrap();
        let secret = b"AWS_SECRET_ACCESS_KEY=hunter2";
        let mut ct = vec![0u8; NOISE_MAX_MESSAGE_LEN];
        let n = c.encrypt(secret, &mut ct).unwrap();
        assert!(
            !ct[..n].windows(secret.len()).any(|w| w == secret),
            "plaintext appears in ciphertext"
        );
    }

    #[test]
    fn tampering_with_any_ciphertext_byte_is_detected() {
        let (client, daemon) = pair();
        let (mut c, _) = handshake(Purpose::Reconnect, None, &client, &daemon).unwrap();
        let mut ct = vec![0u8; NOISE_MAX_MESSAGE_LEN];
        let n = c.encrypt(b"approve", &mut ct).unwrap();

        for i in 0..n {
            // A fresh receiver per attempt: a failed decrypt advances nonce
            // state, so reusing one would conflate tampering with desync.
            let (_, mut fresh_d) = handshake(Purpose::Reconnect, None, &client, &daemon).unwrap();
            let mut corrupted = ct[..n].to_vec();
            corrupted[i] ^= 0x01;
            let mut pt = vec![0u8; NOISE_MAX_MESSAGE_LEN];
            assert!(
                fresh_d.decrypt(&corrupted, &mut pt).is_err(),
                "flipping ciphertext byte {i} was not detected"
            );
        }
    }

    #[test]
    fn replaying_a_message_is_rejected() {
        // Noise's per-message nonce counter makes in-session replay impossible.
        let (client, daemon) = pair();
        let (mut c, mut d) = handshake(Purpose::Reconnect, None, &client, &daemon).unwrap();
        let mut ct = vec![0u8; NOISE_MAX_MESSAGE_LEN];
        let mut pt = vec![0u8; NOISE_MAX_MESSAGE_LEN];

        let n = c.encrypt(b"git push --force", &mut ct).unwrap();
        assert!(d.decrypt(&ct[..n], &mut pt).is_ok());
        assert_eq!(
            d.decrypt(&ct[..n], &mut pt),
            Err(SessionError::DecryptFailed)
        );
    }

    #[test]
    fn a_message_from_a_different_session_does_not_decrypt() {
        let (client, daemon) = pair();
        let (mut c1, _) = handshake(Purpose::Reconnect, None, &client, &daemon).unwrap();
        let (_, mut d2) = handshake(Purpose::Reconnect, None, &client, &daemon).unwrap();

        let mut ct = vec![0u8; NOISE_MAX_MESSAGE_LEN];
        let n = c1.encrypt(b"cross-session", &mut ct).unwrap();
        let mut pt = vec![0u8; NOISE_MAX_MESSAGE_LEN];
        assert_eq!(
            d2.decrypt(&ct[..n], &mut pt),
            Err(SessionError::DecryptFailed)
        );
    }

    #[test]
    fn oversized_plaintext_is_rejected_with_its_length() {
        let (client, daemon) = pair();
        let (mut c, _) = handshake(Purpose::Reconnect, None, &client, &daemon).unwrap();
        let too_big = vec![0u8; MAX_PLAINTEXT_LEN + 1];
        let mut ct = vec![0u8; NOISE_MAX_MESSAGE_LEN + 64];
        assert_eq!(
            c.encrypt(&too_big, &mut ct),
            Err(SessionError::TooLong {
                len: MAX_PLAINTEXT_LEN + 1
            })
        );
    }

    #[test]
    fn the_largest_allowed_plaintext_round_trips() {
        let (client, daemon) = pair();
        let (mut c, mut d) = handshake(Purpose::Reconnect, None, &client, &daemon).unwrap();
        let payload = vec![0xABu8; MAX_PLAINTEXT_LEN];
        let mut ct = vec![0u8; NOISE_MAX_MESSAGE_LEN];
        let n = c.encrypt(&payload, &mut ct).unwrap();
        let mut pt = vec![0u8; NOISE_MAX_MESSAGE_LEN];
        let m = d.decrypt(&ct[..n], &mut pt).unwrap();
        assert_eq!(&pt[..m], &payload[..]);
    }

    #[test]
    fn empty_payloads_round_trip() {
        let (client, daemon) = pair();
        let (mut c, mut d) = handshake(Purpose::Reconnect, None, &client, &daemon).unwrap();
        let mut ct = [0u8; 64];
        let n = c.encrypt(b"", &mut ct).unwrap();
        let mut pt = [0u8; 64];
        assert_eq!(d.decrypt(&ct[..n], &mut pt).unwrap(), 0);
    }

    #[test]
    fn channel_binding_agrees_on_both_sides_and_differs_per_session() {
        let (client, daemon) = pair();
        let (a, b) = handshake(Purpose::Reconnect, None, &client, &daemon).unwrap();
        assert_eq!(a.channel_binding(), b.channel_binding());

        let (c, _) = handshake(Purpose::Reconnect, None, &client, &daemon).unwrap();
        assert_ne!(a.channel_binding(), c.channel_binding());
    }

    #[test]
    fn the_initiator_identity_is_not_sent_in_the_clear() {
        // The metadata property IK buys: a relay must not learn which device is
        // connecting by watching the first flight.
        let (client, daemon) = pair();
        let mut init = Handshake::initiator(
            &client,
            &daemon.noise_public_key(),
            Purpose::Reconnect,
            None,
        )
        .unwrap();
        let mut buf = vec![0u8; NOISE_MAX_MESSAGE_LEN];
        let n = init.write_message(&[], &mut buf).unwrap();

        let key = client.noise_public_key();
        assert!(
            !buf[..n].windows(32).any(|w| w == key.as_bytes()),
            "the initiator's static key appears in plaintext in the first message"
        );
    }

    #[test]
    fn debug_output_never_contains_key_material() {
        let (client, daemon) = pair();
        let (session, _) = handshake(Purpose::Reconnect, None, &client, &daemon).unwrap();
        let rendered = format!("{session:?}");
        assert!(!rendered.contains(&hex::encode(*client.expose_seed())));
        assert!(!rendered.contains(&hex::encode(session.channel_binding())));
    }

    #[test]
    fn purpose_selects_the_right_noise_pattern() {
        assert_eq!(Purpose::Reconnect.params(), NOISE_PARAMS);
        assert_eq!(Purpose::Pairing.params(), NOISE_PARAMS_PAIRING);
        // The pairing pattern must actually mix a PSK, or the QR secret is
        // decorative.
        assert!(Purpose::Pairing.params().contains("psk2"));
        assert!(!Purpose::Reconnect.params().contains("psk"));
    }

    proptest::proptest! {
        #[test]
        fn any_payload_round_trips(payload: Vec<u8>) {
            proptest::prop_assume!(payload.len() <= MAX_PLAINTEXT_LEN);
            let (client, daemon) = pair();
            let (mut c, mut d) = handshake(Purpose::Reconnect, None, &client, &daemon).unwrap();

            let mut ct = vec![0u8; payload.len() + NOISE_TAG_LEN + 64];
            let n = c.encrypt(&payload, &mut ct).unwrap();
            let mut pt = vec![0u8; ct.len()];
            let m = d.decrypt(&ct[..n], &mut pt).unwrap();
            proptest::prop_assert_eq!(&pt[..m], &payload[..]);
        }

        /// Decrypting arbitrary bytes must never panic: this runs on data from a
        /// peer that may be hostile.
        #[test]
        fn decrypting_arbitrary_bytes_never_panics(bytes: Vec<u8>) {
            proptest::prop_assume!(bytes.len() <= NOISE_MAX_MESSAGE_LEN);
            let (client, daemon) = pair();
            let (_, mut d) = handshake(Purpose::Reconnect, None, &client, &daemon).unwrap();
            let mut pt = vec![0u8; NOISE_MAX_MESSAGE_LEN];
            let _ = d.decrypt(&bytes, &mut pt);
        }

        /// Reading an arbitrary first message must never panic. This is the
        /// daemon's exposed surface before any authentication has happened.
        #[test]
        fn reading_arbitrary_handshake_bytes_never_panics(bytes: Vec<u8>) {
            proptest::prop_assume!(bytes.len() <= NOISE_MAX_MESSAGE_LEN);
            let daemon = DeviceIdentity::generate();
            let mut resp = Handshake::responder(&daemon, Purpose::Reconnect, None).unwrap();
            let mut out = vec![0u8; NOISE_MAX_MESSAGE_LEN];
            let _ = resp.read_message(&bytes, &mut out);
        }
    }
}
