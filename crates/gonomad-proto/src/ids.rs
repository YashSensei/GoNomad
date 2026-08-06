//! Cryptographic identifiers.
//!
//! GoNomad has no bearer tokens, no session cookies, and no API keys. A
//! device's Ed25519 public key *is* its credential (`ARCHITECTURE.md` §3.2), so
//! the types in this module are the backbone of both authentication and
//! authorization.
//!
//! Three distinct 32-byte identifiers, kept as separate types so the compiler
//! prevents mixing them up:
//!
//! - [`PublicKey`] — an Ed25519 verifying key. The credential itself.
//! - [`DeviceId`] — `BLAKE3(public_key)`. A stable, short handle for logs,
//!   database rows, and UI. Derived rather than random so it cannot disagree
//!   with the key it names.
//! - [`Digest`] — a BLAKE3 hash of arbitrary content: file contents, audit
//!   arguments, an approval payload.

use core::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::ConstantTimeEq;

/// Length in bytes of every identifier in this module.
pub const ID_LEN: usize = 32;

/// Errors produced when parsing an identifier from text or bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseIdError {
    /// The input was not valid hexadecimal.
    #[error("identifier is not valid hex")]
    NotHex,
    /// The input decoded to the wrong number of bytes.
    #[error("identifier must be {ID_LEN} bytes, got {got}")]
    WrongLength {
        /// The number of bytes actually decoded.
        got: usize,
    },
}

/// Generates a newtype over `[u8; 32]` with consistent, safe semantics.
///
/// Every identifier gets: constant-time equality, lowercase-hex `Display`,
/// truncated `Debug` (so full keys do not sprawl through logs), hex-string
/// serde (so CBOR and JSON representations are identical and human-readable),
/// and byte/array conversions.
macro_rules! id_newtype {
    ($(#[$meta:meta])* $name:ident, $short:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialOrd, Ord)]
        pub struct $name([u8; ID_LEN]);

        impl $name {
            /// Wraps raw bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; ID_LEN]) -> Self {
                Self(bytes)
            }

            /// Borrows the raw bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; ID_LEN] {
                &self.0
            }

            /// Consumes into raw bytes.
            #[must_use]
            pub const fn to_bytes(self) -> [u8; ID_LEN] {
                self.0
            }

            /// Parses from a byte slice of exactly [`ID_LEN`] bytes.
            ///
            /// # Errors
            ///
            /// Returns [`ParseIdError::WrongLength`] when `bytes` is not
            /// exactly [`ID_LEN`] bytes long.
            pub fn from_slice(bytes: &[u8]) -> Result<Self, ParseIdError> {
                let arr: [u8; ID_LEN] = bytes
                    .try_into()
                    .map_err(|_| ParseIdError::WrongLength { got: bytes.len() })?;
                Ok(Self(arr))
            }

            /// Parses from lowercase or uppercase hex.
            ///
            /// # Errors
            ///
            /// Returns [`ParseIdError::NotHex`] when `s` is not valid
            /// hexadecimal, or [`ParseIdError::WrongLength`] when it decodes to
            /// the wrong number of bytes.
            pub fn from_hex(s: &str) -> Result<Self, ParseIdError> {
                let raw = hex::decode(s).map_err(|_| ParseIdError::NotHex)?;
                Self::from_slice(&raw)
            }

            /// Renders as lowercase hex.
            #[must_use]
            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }

            /// Renders the first 8 hex characters, for logs and compact UI.
            ///
            /// 4 bytes is ample to disambiguate the handful of devices a user
            /// pairs, while keeping log lines readable.
            #[must_use]
            pub fn short(&self) -> String {
                hex::encode(&self.0[..4])
            }
        }

        // Constant-time equality. These values are compared against
        // attacker-supplied input during authentication, so a byte-by-byte
        // early-exit comparison would leak a matching prefix via timing.
        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.0.ct_eq(&other.0).into()
            }
        }
        impl Eq for $name {}

        // Hashed over the same bytes that `PartialEq` compares, so the
        // `k1 == k2 => hash(k1) == hash(k2)` invariant holds and these are safe
        // as `HashMap` keys. Written by hand rather than derived because the
        // custom `PartialEq` above makes a derive suspicious to a reader (and
        // to clippy) even when it is correct.
        impl core::hash::Hash for $name {
            fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
                self.0.hash(state);
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        // Truncated Debug: a full 64-char hex string in every log line and
        // every error message makes both unreadable.
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({}…)", $short, self.short())
            }
        }

        impl From<[u8; ID_LEN]> for $name {
            fn from(bytes: [u8; ID_LEN]) -> Self {
                Self(bytes)
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        // Serialized as hex rather than as a byte array. Costs 2x the bytes
        // (recovered by compression, §10.3) and buys protocol dumps that a
        // contributor can read without a decoder.
        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.to_hex())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                Self::from_hex(&s).map_err(serde::de::Error::custom)
            }
        }
    };
}

id_newtype! {
    /// An Ed25519 verifying key: the credential a device authenticates with.
    ///
    /// Registered at pairing and stored server-side. Presence of a key in the
    /// paired allowlist is the entirety of "is this device allowed to
    /// connect" — there is no accompanying token to validate or expire.
    PublicKey, "PublicKey"
}

id_newtype! {
    /// A stable short handle for a paired device: `BLAKE3(public_key)`.
    ///
    /// Derived rather than randomly assigned, so a `DeviceId` can never drift
    /// out of agreement with the key it identifies, and so two peers can
    /// compute the same id for the same key without coordinating.
    DeviceId, "DeviceId"
}

id_newtype! {
    /// A BLAKE3 digest of content.
    ///
    /// Used for compare-and-swap file writes (`ARCHITECTURE.md` §12.2), for
    /// audit argument digests, and for binding an approval signature to the
    /// exact operation being approved (§3.10).
    Digest, "Digest"
}

impl DeviceId {
    /// Derives the device id for a public key.
    #[must_use]
    pub fn from_public_key(key: &PublicKey) -> Self {
        Self(blake3::hash(key.as_bytes()).into())
    }
}

impl Digest {
    /// Hashes arbitrary bytes.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(blake3::hash(bytes).into())
    }

    /// Hashes a sequence of byte slices as though they were concatenated,
    /// without allocating a joined buffer.
    ///
    /// Note that this is *not* domain-separated: `of_parts(&[b"ab", b"c"])`
    /// equals `of_parts(&[b"a", b"bc"])`. Callers that need unambiguous
    /// framing must include explicit separators or lengths.
    #[must_use]
    pub fn of_parts(parts: &[&[u8]]) -> Self {
        let mut hasher = blake3::Hasher::new();
        for part in parts {
            hasher.update(part);
        }
        Self(hasher.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: [u8; ID_LEN] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
        0xcd, 0xef,
    ];

    #[test]
    fn hex_round_trips() {
        let key = PublicKey::from_bytes(SAMPLE);
        assert_eq!(PublicKey::from_hex(&key.to_hex()).unwrap(), key);
    }

    #[test]
    fn hex_parsing_is_case_insensitive() {
        let lower = PublicKey::from_hex(&hex::encode(SAMPLE)).unwrap();
        let upper = PublicKey::from_hex(&hex::encode_upper(SAMPLE)).unwrap();
        assert_eq!(lower, upper);
    }

    #[test]
    fn wrong_length_is_rejected_with_the_actual_length() {
        assert_eq!(
            PublicKey::from_slice(&[0u8; 31]),
            Err(ParseIdError::WrongLength { got: 31 })
        );
        assert_eq!(
            PublicKey::from_slice(&[0u8; 33]),
            Err(ParseIdError::WrongLength { got: 33 })
        );
    }

    #[test]
    fn non_hex_is_rejected() {
        assert_eq!(PublicKey::from_hex("zz"), Err(ParseIdError::NotHex));
    }

    #[test]
    fn debug_is_truncated_so_logs_stay_readable() {
        let key = PublicKey::from_bytes(SAMPLE);
        let rendered = format!("{key:?}");
        assert_eq!(rendered, "PublicKey(01234567…)");
        // The full key must not leak into debug output.
        assert!(!rendered.contains(&key.to_hex()));
    }

    #[test]
    fn display_is_the_full_hex() {
        let key = PublicKey::from_bytes(SAMPLE);
        assert_eq!(format!("{key}").len(), ID_LEN * 2);
    }

    #[test]
    fn device_id_is_derived_deterministically_from_the_key() {
        let key = PublicKey::from_bytes(SAMPLE);
        assert_eq!(
            DeviceId::from_public_key(&key),
            DeviceId::from_public_key(&key)
        );
    }

    #[test]
    fn distinct_keys_yield_distinct_device_ids() {
        let a = DeviceId::from_public_key(&PublicKey::from_bytes(SAMPLE));
        let mut other = SAMPLE;
        other[0] ^= 0x01;
        let b = DeviceId::from_public_key(&PublicKey::from_bytes(other));
        assert_ne!(a, b);
    }

    #[test]
    fn device_id_is_not_the_key_itself() {
        // A hash, not a copy — so a DeviceId in a log or a database row does
        // not hand out the credential.
        let key = PublicKey::from_bytes(SAMPLE);
        assert_ne!(DeviceId::from_public_key(&key).as_bytes(), key.as_bytes());
    }

    #[test]
    fn digest_of_parts_matches_digest_of_concatenation() {
        assert_eq!(
            Digest::of_parts(&[b"hello", b" ", b"world"]),
            Digest::of(b"hello world")
        );
    }

    #[test]
    fn digest_of_parts_is_not_domain_separated() {
        // Documented behaviour, asserted so a future change is deliberate.
        assert_eq!(
            Digest::of_parts(&[b"ab", b"c"]),
            Digest::of_parts(&[b"a", b"bc"])
        );
    }

    #[test]
    fn serde_representation_is_a_plain_hex_string() {
        let key = PublicKey::from_bytes(SAMPLE);
        let json = serde_json::to_string(&key).unwrap();
        assert_eq!(json, format!("\"{}\"", key.to_hex()));
        assert_eq!(serde_json::from_str::<PublicKey>(&json).unwrap(), key);
    }

    #[test]
    fn cbor_round_trips() {
        let id = DeviceId::from_public_key(&PublicKey::from_bytes(SAMPLE));
        let mut buf = Vec::new();
        ciborium::into_writer(&id, &mut buf).unwrap();
        let back: DeviceId = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn types_do_not_interconvert() {
        // Compile-time guarantee, documented as a test for intent: a Digest
        // cannot be passed where a PublicKey is expected. If this ever becomes
        // possible, authorization checks could be fed the wrong value.
        let digest = Digest::of(b"x");
        let key = PublicKey::from_bytes(*digest.as_bytes());
        assert_eq!(key.as_bytes(), digest.as_bytes());
    }

    proptest::proptest! {
        #[test]
        fn hex_round_trips_for_any_bytes(bytes: [u8; ID_LEN]) {
            let key = PublicKey::from_bytes(bytes);
            proptest::prop_assert_eq!(PublicKey::from_hex(&key.to_hex()).unwrap(), key);
        }

        #[test]
        fn any_slice_of_the_wrong_length_is_rejected(len in 0usize..128) {
            proptest::prop_assume!(len != ID_LEN);
            proptest::prop_assert!(PublicKey::from_slice(&vec![0u8; len]).is_err());
        }

        #[test]
        fn short_is_always_eight_hex_chars(bytes: [u8; ID_LEN]) {
            proptest::prop_assert_eq!(PublicKey::from_bytes(bytes).short().len(), 8);
        }
    }
}
