//! Conversions between SQLite column values and this project's domain types.
//!
//! SQLite has five storage classes and no `u64`, no fixed-width byte array, and
//! no notion of "this text is 64 hex characters". Every one of those gaps is a
//! place where a corrupt or tampered row could otherwise be decoded into a
//! plausible-looking value, so all decoding funnels through here and every
//! failure names the table it came from.

use gonomad_proto::{DeviceId, Digest, PublicKey};

use crate::error::{Result, StoreError};

/// Reads a `u64` that SQLite stored in its signed `INTEGER` column.
///
/// A negative value means the row was written by something other than this
/// crate, which for the audit table is a tamper signal.
pub(crate) fn u64_from_i64(table: &'static str, column: &str, raw: i64) -> Result<u64> {
    u64::try_from(raw).map_err(|_| StoreError::corrupt(table, format!("{column} is negative: {raw}")))
}

/// Narrows a `u64` for storage in SQLite's signed `INTEGER` column.
pub(crate) fn i64_from_u64(table: &'static str, column: &str, raw: u64) -> Result<i64> {
    i64::try_from(raw)
        .map_err(|_| StoreError::corrupt(table, format!("{column} exceeds i64 range: {raw}")))
}

/// Decodes a 32-byte BLOB column into a [`Digest`].
pub(crate) fn digest(table: &'static str, column: &str, raw: &[u8]) -> Result<Digest> {
    Digest::from_slice(raw)
        .map_err(|e| StoreError::corrupt(table, format!("{column} is not a digest: {e}")))
}

/// Decodes a hex TEXT column into a [`DeviceId`].
pub(crate) fn device_id(table: &'static str, column: &str, raw: &str) -> Result<DeviceId> {
    DeviceId::from_hex(raw)
        .map_err(|e| StoreError::corrupt(table, format!("{column} is not a device id: {e}")))
}

/// Decodes a hex TEXT column into a [`PublicKey`].
pub(crate) fn public_key(table: &'static str, column: &str, raw: &str) -> Result<PublicKey> {
    PublicKey::from_hex(raw)
        .map_err(|e| StoreError::corrupt(table, format!("{column} is not a public key: {e}")))
}

/// Decodes a 64-byte BLOB column into an Ed25519 signature.
pub(crate) fn signature(table: &'static str, column: &str, raw: &[u8]) -> Result<[u8; 64]> {
    <[u8; 64]>::try_from(raw).map_err(|_| {
        StoreError::corrupt(
            table,
            format!("{column} must be 64 bytes, got {}", raw.len()),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_integers_are_rejected_rather_than_wrapped() {
        // Wrapping would turn a tampered `seq = -1` into `seq = u64::MAX`,
        // which is exactly the sort of silent reinterpretation the audit log
        // must never do.
        let err = u64_from_i64("audit", "seq", -1).unwrap_err();
        assert!(err.to_string().contains("seq is negative"), "{err}");
    }

    #[test]
    fn valid_integers_round_trip() {
        assert_eq!(u64_from_i64("audit", "seq", 42).unwrap(), 42);
        assert_eq!(i64_from_u64("audit", "seq", 42).unwrap(), 42);
        assert!(i64_from_u64("audit", "seq", u64::MAX).is_err());
    }

    #[test]
    fn short_digests_are_rejected() {
        assert!(digest("audit", "hash", &[0u8; 31]).is_err());
        assert!(digest("audit", "hash", &[0u8; 32]).is_ok());
        assert!(digest("audit", "hash", &[0u8; 33]).is_err());
    }

    #[test]
    fn malformed_hex_identifiers_are_rejected() {
        assert!(device_id("devices", "id", "not hex").is_err());
        assert!(public_key("devices", "pubkey", "aabb").is_err());
        assert!(device_id("devices", "id", &"ab".repeat(32)).is_ok());
    }

    #[test]
    fn signatures_must_be_exactly_64_bytes() {
        assert!(signature("audit_checkpoints", "signature", &[0u8; 63]).is_err());
        assert!(signature("audit_checkpoints", "signature", &[0u8; 64]).is_ok());
    }

    #[test]
    fn errors_name_the_table_they_came_from() {
        let err = digest("audit", "prev_hash", &[0u8; 5]).unwrap_err();
        assert!(err.to_string().contains("`audit`"), "{err}");
        assert!(err.to_string().contains("prev_hash"), "{err}");
    }
}
