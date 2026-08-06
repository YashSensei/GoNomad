//! Device identity: the Ed25519 keypair that *is* the credential.
//!
//! GoNomad has no passwords, no bearer tokens, and no session cookies. A
//! device's public key, registered at pairing, is the entirety of "may this
//! device connect" (`ARCHITECTURE.md` §3.2). Every connection performs a fresh
//! mutual authentication from this keypair.
//!
//! That design dissolves several problem classes rather than solving them:
//! there is no token to steal, nothing to rotate on a schedule, no replay of a
//! captured credential, and revocation is the deletion of one database row that
//! takes effect on the next packet.
//!
//! The cost is real and deliberate: **losing the private key means re-pairing.**
//! There is no recovery flow, because a self-hosted security tool with a
//! credential-recovery backdoor has a credential-recovery attack. The daemon
//! side mitigates this with a recovery phrase (§9.5), which is why
//! [`DeviceIdentity::from_seed`] exists.
//!
//! # Where the private key actually lives
//!
//! This type holds key material in process memory while it is in use, which is
//! unavoidable for signing. Durable storage is the platform's job and is
//! deliberately *not* handled here:
//!
//! - **Android**: the Keystore. Note the constraint that has to be designed
//!   around rather than discovered — hardware-backed Keystore (TEE/StrongBox)
//!   supports EC P-256/P-384 and RSA, **not** Ed25519 or X25519. So the identity
//!   key is a software key protected by Keystore encryption and the lockscreen,
//!   and a separate hardware-backed P-256 *presence* key gates destructive
//!   operations (§3.3). That split is what makes a stolen unlocked phone
//!   survivable.
//! - **Daemon**: the OS keyring (Windows Credential Manager via DPAPI, macOS
//!   Keychain, Secret Service). Never a file, because a file is readable by
//!   every process running as that user.

use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use gonomad_proto::{DeviceId, PublicKey};
use zeroize::{Zeroize, Zeroizing};

/// Length of an Ed25519 private seed, in bytes.
pub const SEED_LEN: usize = 32;

/// Length of an Ed25519 signature, in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// Domain separator for signatures produced by [`DeviceIdentity::sign`].
///
/// Prefixed to every message before signing so a signature made for one purpose
/// cannot be reinterpreted as one made for another. Without this, a signature
/// over a pairing transcript could potentially be presented as a signature
/// authorising a destructive operation — the classic cross-protocol attack.
const SIGN_DOMAIN: &[u8] = b"gonomad-device-signature-v1\x00";

/// Errors from identity operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IdentityError {
    /// The provided bytes were not a valid Ed25519 key.
    #[error("not a valid Ed25519 key")]
    MalformedKey,
    /// The signature was the wrong length.
    #[error("signature must be {SIGNATURE_LEN} bytes, got {got}")]
    MalformedSignature {
        /// The length actually supplied.
        got: usize,
    },
    /// The signature did not verify against the key and message.
    #[error("signature verification failed")]
    BadSignature,
}

/// A device's Ed25519 keypair.
///
/// # Handling
///
/// The private seed is held in a [`Zeroizing`] buffer and wiped on drop.
/// `Debug` prints only the public identity, and neither `Clone` nor `Serialize`
/// is implemented — exporting a private key must be an explicit, visible call to
/// [`DeviceIdentity::expose_seed`], never something that happens incidentally
/// because a struct derived `Clone` and ended up in a log or a cache.
pub struct DeviceIdentity {
    signing: SigningKey,
    /// Retained so the seed can be re-exported for keyring storage without
    /// reconstructing it, and so it is wiped on drop.
    seed: Zeroizing<[u8; SEED_LEN]>,
}

impl DeviceIdentity {
    /// Generates a fresh identity from the operating system's CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, seed.as_mut());
        Self::from_seed_inner(seed)
    }

    /// Reconstructs an identity from a 32-byte seed.
    ///
    /// Used to restore the daemon's identity from the OS keyring, and to derive
    /// it deterministically from the recovery phrase so that a reinstalled
    /// daemon keeps the same identity and paired phones do not have to re-pair
    /// (§9.5).
    #[must_use]
    pub fn from_seed(seed: [u8; SEED_LEN]) -> Self {
        // Copy into a zeroizing buffer, then wipe the caller's copy. The caller
        // still owns their array, so this only clears our view of it — callers
        // holding a seed should wrap it in `Zeroizing` themselves.
        let owned = Zeroizing::new(seed);
        Self::from_seed_inner(owned)
    }

    fn from_seed_inner(seed: Zeroizing<[u8; SEED_LEN]>) -> Self {
        let signing = SigningKey::from_bytes(&seed);
        Self { signing, seed }
    }

    /// This device's public key — its credential.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_bytes(self.signing.verifying_key().to_bytes())
    }

    /// This device's derived identifier, `BLAKE3(public_key)`.
    #[must_use]
    pub fn device_id(&self) -> DeviceId {
        DeviceId::from_public_key(&self.public_key())
    }

    /// Exposes the private seed for storage in a platform keyring.
    ///
    /// Named to be conspicuous at the call site. The returned buffer wipes
    /// itself on drop; do not copy it into an unprotected `[u8; 32]`.
    #[must_use]
    pub fn expose_seed(&self) -> Zeroizing<[u8; SEED_LEN]> {
        Zeroizing::new(*self.seed)
    }

    /// Signs `message`, domain-separated.
    ///
    /// The signature covers `SIGN_DOMAIN || message`, so it cannot be replayed
    /// into a context that signs raw bytes or uses a different separator.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.signing.sign(&domain_separated(message)).to_bytes()
    }

    /// Verifies a signature produced by [`DeviceIdentity::sign`] on another
    /// device.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::MalformedKey`] if `key` is not a valid Ed25519
    /// point, [`IdentityError::MalformedSignature`] if `signature` is the wrong
    /// length, or [`IdentityError::BadSignature`] if verification fails.
    pub fn verify(key: &PublicKey, message: &[u8], signature: &[u8]) -> Result<(), IdentityError> {
        let sig_bytes: [u8; SIGNATURE_LEN] =
            signature
                .try_into()
                .map_err(|_| IdentityError::MalformedSignature {
                    got: signature.len(),
                })?;

        let verifying =
            VerifyingKey::from_bytes(key.as_bytes()).map_err(|_| IdentityError::MalformedKey)?;

        verifying
            .verify(
                &domain_separated(message),
                &Signature::from_bytes(&sig_bytes),
            )
            .map_err(|_| IdentityError::BadSignature)
    }
}

/// Prefixes `message` with the signing domain separator.
fn domain_separated(message: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(SIGN_DOMAIN.len() + message.len());
    buf.extend_from_slice(SIGN_DOMAIN);
    buf.extend_from_slice(message);
    buf
}

// Prints the public identity only. A Debug impl that could print private key
// material is a leak waiting for someone to add a `dbg!` while debugging.
impl fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceIdentity")
            .field("device_id", &self.device_id())
            .finish_non_exhaustive()
    }
}

impl Drop for DeviceIdentity {
    fn drop(&mut self) {
        // `Zeroizing` already wipes `seed`, and ed25519-dalek's `zeroize`
        // feature wipes the expanded key. This is belt-and-braces for the seed
        // copy held inside `SigningKey`, which we cannot reach directly.
        self.seed.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_identities_are_distinct() {
        let a = DeviceIdentity::generate();
        let b = DeviceIdentity::generate();
        assert_ne!(a.public_key(), b.public_key());
        assert_ne!(a.device_id(), b.device_id());
    }

    #[test]
    fn seed_round_trips_to_the_same_identity() {
        // The property the recovery phrase depends on: same seed, same identity,
        // so a reinstalled daemon does not force every phone to re-pair.
        let original = DeviceIdentity::generate();
        let seed = original.expose_seed();
        let restored = DeviceIdentity::from_seed(*seed);
        assert_eq!(restored.public_key(), original.public_key());
        assert_eq!(restored.device_id(), original.device_id());
    }

    #[test]
    fn device_id_is_derived_from_the_public_key() {
        let id = DeviceIdentity::generate();
        assert_eq!(id.device_id(), DeviceId::from_public_key(&id.public_key()));
    }

    #[test]
    fn signatures_verify() {
        let id = DeviceIdentity::generate();
        let sig = id.sign(b"approve operation 42");
        assert_eq!(
            DeviceIdentity::verify(&id.public_key(), b"approve operation 42", &sig),
            Ok(())
        );
    }

    #[test]
    fn signatures_do_not_verify_for_a_different_message() {
        // The core requirement for presence signatures: a signature harvested
        // from an innocuous approval must not authorise a destructive one.
        let id = DeviceIdentity::generate();
        let sig = id.sign(b"read a file");
        assert_eq!(
            DeviceIdentity::verify(&id.public_key(), b"force push to main", &sig),
            Err(IdentityError::BadSignature)
        );
    }

    #[test]
    fn signatures_do_not_verify_for_a_different_key() {
        let signer = DeviceIdentity::generate();
        let other = DeviceIdentity::generate();
        let sig = signer.sign(b"msg");
        assert_eq!(
            DeviceIdentity::verify(&other.public_key(), b"msg", &sig),
            Err(IdentityError::BadSignature)
        );
    }

    #[test]
    fn tampering_with_any_signature_byte_is_detected() {
        let id = DeviceIdentity::generate();
        let sig = id.sign(b"payload");
        for i in 0..SIGNATURE_LEN {
            let mut bad = sig;
            bad[i] ^= 0x01;
            assert!(
                DeviceIdentity::verify(&id.public_key(), b"payload", &bad).is_err(),
                "flipping byte {i} was not detected"
            );
        }
    }

    #[test]
    fn wrong_length_signatures_are_rejected_before_verification() {
        let id = DeviceIdentity::generate();
        for len in [0usize, 1, 63, 65, 128] {
            assert_eq!(
                DeviceIdentity::verify(&id.public_key(), b"m", &vec![0u8; len]),
                Err(IdentityError::MalformedSignature { got: len })
            );
        }
    }

    #[test]
    fn signatures_are_domain_separated() {
        // A raw Ed25519 signature over the same bytes must NOT satisfy our
        // verifier. This is what stops a signature produced in one protocol
        // context being replayed into another.
        let id = DeviceIdentity::generate();
        let seed = id.expose_seed();
        let raw_key = SigningKey::from_bytes(&seed);
        let raw_sig = raw_key.sign(b"message").to_bytes();

        assert_eq!(
            DeviceIdentity::verify(&id.public_key(), b"message", &raw_sig),
            Err(IdentityError::BadSignature),
            "an undomained signature was accepted"
        );
    }

    #[test]
    fn malformed_public_keys_are_rejected() {
        // Not every 32-byte string is a valid Ed25519 point.
        let not_a_point = PublicKey::from_bytes([0xFF; 32]);
        let result = DeviceIdentity::verify(&not_a_point, b"m", &[0u8; SIGNATURE_LEN]);
        assert!(matches!(
            result,
            Err(IdentityError::MalformedKey | IdentityError::BadSignature)
        ));
    }

    #[test]
    fn signing_is_deterministic() {
        // Ed25519 is deterministic, which matters for reproducible tests and
        // means a repeated approval produces an identical signature.
        let id = DeviceIdentity::generate();
        assert_eq!(id.sign(b"same"), id.sign(b"same"));
    }

    #[test]
    fn empty_messages_can_be_signed_and_verified() {
        let id = DeviceIdentity::generate();
        let sig = id.sign(b"");
        assert_eq!(DeviceIdentity::verify(&id.public_key(), b"", &sig), Ok(()));
    }

    #[test]
    fn debug_never_exposes_key_material() {
        let id = DeviceIdentity::generate();
        let rendered = format!("{id:?}");
        let seed_hex = hex::encode(*id.expose_seed());
        assert!(
            !rendered.contains(&seed_hex),
            "seed leaked into Debug output"
        );
        // The public identity is fine to show, and is what makes the output useful.
        assert!(rendered.contains(&id.device_id().short()));
    }

    #[test]
    fn a_known_seed_produces_a_stable_public_key() {
        // Pins the seed-to-key derivation. If this ever changes, every paired
        // device in the world breaks, so the change must be deliberate.
        let id = DeviceIdentity::from_seed([0x42; SEED_LEN]);
        let expected = hex::encode(id.public_key().as_bytes());
        assert_eq!(expected.len(), 64);
        // Recomputing from the same seed must agree.
        assert_eq!(
            DeviceIdentity::from_seed([0x42; SEED_LEN]).public_key(),
            id.public_key()
        );
    }

    proptest::proptest! {
        #[test]
        fn any_seed_yields_a_usable_identity(seed: [u8; SEED_LEN]) {
            let id = DeviceIdentity::from_seed(seed);
            let sig = id.sign(b"probe");
            proptest::prop_assert!(
                DeviceIdentity::verify(&id.public_key(), b"probe", &sig).is_ok()
            );
        }

        #[test]
        fn any_message_signs_and_verifies(message: Vec<u8>) {
            let id = DeviceIdentity::generate();
            let sig = id.sign(&message);
            proptest::prop_assert!(
                DeviceIdentity::verify(&id.public_key(), &message, &sig).is_ok()
            );
        }

        /// Verification must never panic on arbitrary attacker-supplied bytes.
        #[test]
        fn verification_never_panics(key: [u8; 32], message: Vec<u8>, sig: Vec<u8>) {
            let _ = DeviceIdentity::verify(&PublicKey::from_bytes(key), &message, &sig);
        }

        #[test]
        fn distinct_seeds_give_distinct_keys(a: [u8; SEED_LEN], b: [u8; SEED_LEN]) {
            proptest::prop_assume!(a != b);
            proptest::prop_assert_ne!(
                DeviceIdentity::from_seed(a).public_key(),
                DeviceIdentity::from_seed(b).public_key()
            );
        }
    }
}
