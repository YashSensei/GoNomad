//! Paired devices, their capability grants, and their workspace roots.
//!
//! A device's Ed25519 public key *is* its credential (`ARCHITECTURE.md` §3.2) —
//! there is no token to issue, refresh, or expire. So this table is the
//! allowlist, and "is this device allowed to connect" is a lookup here plus a
//! null check on `revoked_at`.
//!
//! Two rules that the SQL enforces and the API exposes:
//!
//! - **Revocation is a tombstone, never a `DELETE`.** The audit log references
//!   these rows by id (§3.9); deleting a device would make its own history
//!   unattributable, which is precisely what an attacker would want. Revocation
//!   is also final: re-admitting a key is not offered, because "I revoked my
//!   phone by mistake" is solved by pairing it again with a fresh key, whereas
//!   an un-revoke button is a privilege-escalation path.
//! - **A missing or unreadable grant denies.** [`Devices::grants`] returns the
//!   empty set for an unknown or revoked device rather than erroring, so a
//!   caller that forgets to check revocation still gets a safe answer.

use gonomad_proto::{Capability, CapabilitySet, DeviceId, PublicKey};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};

use crate::clock;
use crate::error::{Result, StoreError};
use crate::row;

const TABLE: &str = "devices";

/// A paired device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    /// `BLAKE3(public_key)`. Derived, so it can never disagree with the key.
    pub id: DeviceId,
    /// The credential itself.
    pub public_key: PublicKey,
    /// A user-chosen label, e.g. "Pixel 8".
    pub name: String,
    /// The hardware model reported at pairing, for the devices screen.
    pub model: Option<String>,
    /// When pairing completed, Unix milliseconds UTC.
    pub paired_at_ms: i64,
    /// When this device last authenticated, if ever.
    pub last_seen_ms: Option<i64>,
    /// When the device was revoked, or `None` while it is active.
    pub revoked_at_ms: Option<i64>,
}

impl Device {
    /// `true` when this device may no longer authenticate.
    pub fn is_revoked(&self) -> bool {
        self.revoked_at_ms.is_some()
    }
}

/// The devices repository. Obtained from [`crate::Store::devices`].
pub struct Devices<'a> {
    conn: &'a Connection,
}

impl<'a> Devices<'a> {
    pub(crate) fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// Registers a newly paired device together with its initial grant.
    ///
    /// The device row and its grants are written in one transaction: a device
    /// that existed for a moment with no grants, or grants attached to a device
    /// that failed to insert, are both states no caller should have to reason
    /// about.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::AlreadyPaired`] when this public key is already
    /// registered (including when it is registered but revoked), or
    /// [`StoreError::Database`] on engine failure.
    pub fn pair(
        &self,
        public_key: &PublicKey,
        name: &str,
        model: Option<&str>,
        grants: CapabilitySet,
    ) -> Result<Device> {
        let now = clock::now_unix_ms();
        let id = DeviceId::from_public_key(public_key);

        // IMMEDIATE so the duplicate check and the insert cannot interleave
        // with a concurrent pairing of the same key.
        let tx = Transaction::new_unchecked(self.conn, TransactionBehavior::Immediate)?;

        if let Some(existing) = find_by_public_key_within(&tx, public_key)? {
            return Err(StoreError::AlreadyPaired {
                device_id: existing.id,
            });
        }

        tx.execute(
            "INSERT INTO devices (id, pubkey, name, model, paired_at, last_seen, revoked_at)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL)",
            rusqlite::params![id.to_hex(), public_key.to_hex(), name, model, now],
        )?;
        write_grants(&tx, &id, grants, None, now)?;
        tx.commit()?;

        tracing::info!(device = %id.short(), %name, "paired a device");
        Ok(Device {
            id,
            public_key: *public_key,
            name: name.to_owned(),
            model: model.map(ToOwned::to_owned),
            paired_at_ms: now,
            last_seen_ms: None,
            revoked_at_ms: None,
        })
    }

    /// Looks a device up by its identifier, revoked or not.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::CorruptRow`] or [`StoreError::Database`].
    pub fn get(&self, device_id: &DeviceId) -> Result<Option<Device>> {
        let raw = self
            .conn
            .query_row(
                &format!("SELECT {} FROM devices WHERE id = ?1", RawDevice::COLUMNS),
                [device_id.to_hex()],
                RawDevice::from_row,
            )
            .optional()?;
        raw.map(RawDevice::decode).transpose()
    }

    /// Looks a device up by its credential, revoked or not.
    ///
    /// The authentication path wants this variant, not the active-only one: a
    /// connection from a revoked key must be recognised so it can be *denied
    /// and logged*, rather than treated as an unknown stranger.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::CorruptRow`] or [`StoreError::Database`].
    pub fn find_by_public_key(&self, public_key: &PublicKey) -> Result<Option<Device>> {
        find_by_public_key_within(self.conn, public_key)
    }

    /// Looks up a device by credential, returning `None` if it is revoked.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::CorruptRow`] or [`StoreError::Database`].
    pub fn find_active_by_public_key(&self, public_key: &PublicKey) -> Result<Option<Device>> {
        Ok(self
            .find_by_public_key(public_key)?
            .filter(|d| !d.is_revoked()))
    }

    /// Every device ever paired, newest first, including revoked ones.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::CorruptRow`] or [`StoreError::Database`].
    pub fn list(&self) -> Result<Vec<Device>> {
        self.collect(
            &format!(
                "SELECT {} FROM devices ORDER BY paired_at DESC",
                RawDevice::COLUMNS
            ),
            [],
        )
    }

    /// Devices that may currently authenticate, newest first.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::CorruptRow`] or [`StoreError::Database`].
    pub fn list_active(&self) -> Result<Vec<Device>> {
        self.collect(
            &format!(
                "SELECT {} FROM devices WHERE revoked_at IS NULL ORDER BY paired_at DESC",
                RawDevice::COLUMNS
            ),
            [],
        )
    }

    fn collect(&self, sql: &str, params: impl rusqlite::Params) -> Result<Vec<Device>> {
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map(params, RawDevice::from_row)?;
        let mut out = Vec::new();
        for raw in rows {
            out.push(raw?.decode()?);
        }
        Ok(out)
    }

    /// Changes a device's display name.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] when no such device exists.
    pub fn rename(&self, device_id: &DeviceId, name: &str) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE devices SET name = ?2 WHERE id = ?1",
            rusqlite::params![device_id.to_hex(), name],
        )?;
        if changed == 0 {
            return Err(StoreError::not_found("device", device_id));
        }
        Ok(())
    }

    /// Records that a device just authenticated.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] when no such device exists.
    pub fn touch_last_seen(&self, device_id: &DeviceId) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE devices SET last_seen = ?2 WHERE id = ?1",
            rusqlite::params![device_id.to_hex(), clock::now_unix_ms()],
        )?;
        if changed == 0 {
            return Err(StoreError::not_found("device", device_id));
        }
        Ok(())
    }

    /// Revokes a device. Returns `false` when it was already revoked.
    ///
    /// The row survives — see the module documentation. The first revocation
    /// timestamp is kept if this is called twice, because *when the user first
    /// cut the device off* is the security-relevant fact and a later call must
    /// not push it forward.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] when no such device exists.
    pub fn revoke(&self, device_id: &DeviceId) -> Result<bool> {
        let changed = self.conn.execute(
            "UPDATE devices SET revoked_at = ?2 WHERE id = ?1 AND revoked_at IS NULL",
            rusqlite::params![device_id.to_hex(), clock::now_unix_ms()],
        )?;
        if changed > 0 {
            tracing::warn!(device = %device_id.short(), "revoked a device");
            return Ok(true);
        }
        if self.get(device_id)?.is_none() {
            return Err(StoreError::not_found("device", device_id));
        }
        Ok(false)
    }

    /// The capabilities a device may currently exercise.
    ///
    /// Returns [`CapabilitySet::EMPTY`] for an unknown or revoked device. That
    /// is a deliberate fail-closed default rather than an error: this is called
    /// on the hot path of every request, and the only safe answer when the
    /// question is malformed is "nothing".
    ///
    /// A capability string this build does not recognise (a database written by
    /// a newer version) is skipped with a warning, which is also fail-closed
    /// for that capability while leaving the rest of the grant usable.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`] on engine failure.
    pub fn grants(&self, device_id: &DeviceId) -> Result<CapabilitySet> {
        let Some(device) = self.get(device_id)? else {
            return Ok(CapabilitySet::EMPTY);
        };
        if device.is_revoked() {
            return Ok(CapabilitySet::EMPTY);
        }

        let mut stmt = self
            .conn
            .prepare("SELECT capability FROM grants WHERE device_id = ?1")?;
        let rows = stmt.query_map([device_id.to_hex()], |row| row.get::<_, String>(0))?;

        let mut set = CapabilitySet::EMPTY;
        for name in rows {
            let name = name?;
            match name.parse::<Capability>() {
                Ok(capability) => set.insert(capability),
                Err(e) => tracing::warn!(
                    device = %device_id.short(),
                    error = %e,
                    "ignoring an unrecognised capability; a newer build may have written it"
                ),
            }
        }
        Ok(set)
    }

    /// Replaces a device's grant wholesale.
    ///
    /// `granted_by` is the device that authorised the change, or `None` for the
    /// operator acting at the laptop.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] when no such device exists.
    pub fn set_grants(
        &self,
        device_id: &DeviceId,
        grants: CapabilitySet,
        granted_by: Option<&DeviceId>,
    ) -> Result<()> {
        let tx = Transaction::new_unchecked(self.conn, TransactionBehavior::Immediate)?;
        if !exists_within(&tx, device_id)? {
            return Err(StoreError::not_found("device", device_id));
        }
        write_grants(&tx, device_id, grants, granted_by, clock::now_unix_ms())?;
        tx.commit()?;
        tracing::info!(device = %device_id.short(), grants = %grants, "updated grants");
        Ok(())
    }

    /// The workspace roots a device may reach, sorted.
    ///
    /// Paths are stored exactly as supplied; canonicalisation and symlink
    /// resolution belong to `gonomad-policy`'s path guard, which is the only
    /// place that should be trusted to decide what a path means.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`] on engine failure.
    pub fn workspace_roots(&self, device_id: &DeviceId) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT path FROM workspace_roots WHERE device_id = ?1 ORDER BY path ASC")?;
        let rows = stmt.query_map([device_id.to_hex()], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for path in rows {
            out.push(path?);
        }
        Ok(out)
    }

    /// Grants a device access to a workspace root. Returns `false` when it was
    /// already present.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] when no such device exists.
    pub fn add_workspace_root(&self, device_id: &DeviceId, path: &str) -> Result<bool> {
        if !exists_within(self.conn, device_id)? {
            return Err(StoreError::not_found("device", device_id));
        }
        let changed = self.conn.execute(
            "INSERT OR IGNORE INTO workspace_roots (device_id, path, added_at)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![device_id.to_hex(), path, clock::now_unix_ms()],
        )?;
        Ok(changed > 0)
    }

    /// Withdraws a workspace root. Returns `false` when it was not present.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`] on engine failure.
    pub fn remove_workspace_root(&self, device_id: &DeviceId, path: &str) -> Result<bool> {
        let changed = self.conn.execute(
            "DELETE FROM workspace_roots WHERE device_id = ?1 AND path = ?2",
            rusqlite::params![device_id.to_hex(), path],
        )?;
        Ok(changed > 0)
    }
}

fn exists_within(conn: &Connection, device_id: &DeviceId) -> Result<bool> {
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM devices WHERE id = ?1",
            [device_id.to_hex()],
            |row| row.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}

fn find_by_public_key_within(conn: &Connection, public_key: &PublicKey) -> Result<Option<Device>> {
    let raw = conn
        .query_row(
            &format!(
                "SELECT {} FROM devices WHERE pubkey = ?1",
                RawDevice::COLUMNS
            ),
            [public_key.to_hex()],
            RawDevice::from_row,
        )
        .optional()?;
    raw.map(RawDevice::decode).transpose()
}

/// Replaces the grant rows for one device.
///
/// Delete-then-insert rather than a diff: the set is at most eleven rows, and a
/// diff is one more place for a stale capability to survive a revocation.
fn write_grants(
    conn: &Connection,
    device_id: &DeviceId,
    grants: CapabilitySet,
    granted_by: Option<&DeviceId>,
    now: i64,
) -> Result<()> {
    conn.execute(
        "DELETE FROM grants WHERE device_id = ?1",
        [device_id.to_hex()],
    )?;
    let mut stmt = conn.prepare(
        "INSERT INTO grants (device_id, capability, granted_at, granted_by)
         VALUES (?1, ?2, ?3, ?4)",
    )?;
    for capability in grants.iter() {
        stmt.execute(rusqlite::params![
            device_id.to_hex(),
            capability.as_str(),
            now,
            granted_by.map(DeviceId::to_hex),
        ])?;
    }
    Ok(())
}

struct RawDevice {
    id: String,
    pubkey: String,
    name: String,
    model: Option<String>,
    paired_at: i64,
    last_seen: Option<i64>,
    revoked_at: Option<i64>,
}

impl RawDevice {
    const COLUMNS: &'static str = "id, pubkey, name, model, paired_at, last_seen, revoked_at";

    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            pubkey: row.get(1)?,
            name: row.get(2)?,
            model: row.get(3)?,
            paired_at: row.get(4)?,
            last_seen: row.get(5)?,
            revoked_at: row.get(6)?,
        })
    }

    fn decode(self) -> Result<Device> {
        let public_key = row::public_key(TABLE, "pubkey", &self.pubkey)?;
        let id = row::device_id(TABLE, "id", &self.id)?;

        // The id is defined as BLAKE3(pubkey). If the two disagree, some path
        // other than `pair` wrote this row, and trusting either value would
        // mean trusting a row that contradicts itself.
        if id != DeviceId::from_public_key(&public_key) {
            return Err(StoreError::corrupt(
                TABLE,
                format!("id {id} is not BLAKE3 of the stored public key"),
            ));
        }

        Ok(Device {
            id,
            public_key,
            name: self.name,
            model: self.model,
            paired_at_ms: self.paired_at,
            last_seen_ms: self.last_seen,
            revoked_at_ms: self.revoked_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;

    fn on_disk() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("gonomad.db")).unwrap();
        (dir, store)
    }

    fn key(seed: u8) -> PublicKey {
        PublicKey::from_bytes([seed; 32])
    }

    #[test]
    fn pairing_derives_the_device_id_from_the_key() {
        let (_dir, store) = on_disk();
        let pubkey = key(1);
        let device = store
            .devices()
            .pair(
                &pubkey,
                "Pixel 8",
                Some("Google Pixel 8"),
                CapabilitySet::default_grant(),
            )
            .unwrap();

        assert_eq!(device.id, DeviceId::from_public_key(&pubkey));
        assert_eq!(device.name, "Pixel 8");
        assert_eq!(device.model.as_deref(), Some("Google Pixel 8"));
        assert!(!device.is_revoked());
        assert_eq!(device.last_seen_ms, None);
    }

    #[test]
    fn a_paired_device_round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gonomad.db");
        let pubkey = key(2);
        let paired = {
            let store = Store::open(&path).unwrap();
            store
                .devices()
                .pair(&pubkey, "Phone", None, CapabilitySet::default_grant())
                .unwrap()
        };

        let store = Store::open(&path).unwrap();
        assert_eq!(
            store.devices().get(&paired.id).unwrap(),
            Some(paired.clone())
        );
        assert_eq!(
            store.devices().find_by_public_key(&pubkey).unwrap(),
            Some(paired)
        );
    }

    #[test]
    fn pairing_the_same_key_twice_is_refused() {
        let (_dir, store) = on_disk();
        let pubkey = key(3);
        let first = store
            .devices()
            .pair(&pubkey, "A", None, CapabilitySet::EMPTY)
            .unwrap();

        match store
            .devices()
            .pair(&pubkey, "B", None, CapabilitySet::all())
            .unwrap_err()
        {
            StoreError::AlreadyPaired { device_id } => assert_eq!(device_id, first.id),
            other => panic!("expected AlreadyPaired, got {other:?}"),
        }

        // The refusal must not have altered the existing registration.
        let stored = store.devices().get(&first.id).unwrap().unwrap();
        assert_eq!(stored.name, "A");
        assert!(store.devices().grants(&first.id).unwrap().is_empty());
    }

    #[test]
    fn unknown_lookups_return_none_rather_than_erroring() {
        let (_dir, store) = on_disk();
        assert_eq!(
            store.devices().get(&DeviceId::from_bytes([9; 32])).unwrap(),
            None
        );
        assert_eq!(store.devices().find_by_public_key(&key(9)).unwrap(), None);
        assert!(store.devices().list().unwrap().is_empty());
    }

    #[test]
    fn renaming_works_and_missing_devices_error() {
        let (_dir, store) = on_disk();
        let device = store
            .devices()
            .pair(&key(4), "Old", None, CapabilitySet::EMPTY)
            .unwrap();
        store.devices().rename(&device.id, "New").unwrap();
        assert_eq!(
            store.devices().get(&device.id).unwrap().unwrap().name,
            "New"
        );

        let missing = DeviceId::from_bytes([0xee; 32]);
        assert!(matches!(
            store.devices().rename(&missing, "x"),
            Err(StoreError::NotFound { .. })
        ));
    }

    #[test]
    fn last_seen_is_recorded() {
        let (_dir, store) = on_disk();
        let device = store
            .devices()
            .pair(&key(5), "Phone", None, CapabilitySet::EMPTY)
            .unwrap();
        assert_eq!(device.last_seen_ms, None);
        store.devices().touch_last_seen(&device.id).unwrap();
        assert!(store
            .devices()
            .get(&device.id)
            .unwrap()
            .unwrap()
            .last_seen_ms
            .is_some());
    }

    #[test]
    fn a_revoked_device_is_not_returned_as_active() {
        let (_dir, store) = on_disk();
        let pubkey = key(6);
        let device = store
            .devices()
            .pair(&pubkey, "Lost phone", None, CapabilitySet::default_grant())
            .unwrap();
        assert_eq!(store.devices().list_active().unwrap().len(), 1);

        assert!(store.devices().revoke(&device.id).unwrap());

        assert!(store.devices().list_active().unwrap().is_empty());
        assert!(store
            .devices()
            .find_active_by_public_key(&pubkey)
            .unwrap()
            .is_none());

        // But the row survives, so the audit trail stays attributable.
        assert_eq!(store.devices().list().unwrap().len(), 1);
        let stored = store.devices().get(&device.id).unwrap().unwrap();
        assert!(stored.is_revoked());
        assert!(store
            .devices()
            .find_by_public_key(&pubkey)
            .unwrap()
            .unwrap()
            .is_revoked());
    }

    #[test]
    fn revocation_zeroes_the_effective_grant() {
        // Defence in depth: even a caller that forgets to check `is_revoked`
        // gets no capabilities back.
        let (_dir, store) = on_disk();
        let device = store
            .devices()
            .pair(&key(7), "Phone", None, CapabilitySet::all())
            .unwrap();
        assert!(!store.devices().grants(&device.id).unwrap().is_empty());
        store.devices().revoke(&device.id).unwrap();
        assert!(store.devices().grants(&device.id).unwrap().is_empty());
    }

    #[test]
    fn revoking_twice_keeps_the_first_timestamp() {
        let (_dir, store) = on_disk();
        let device = store
            .devices()
            .pair(&key(8), "Phone", None, CapabilitySet::EMPTY)
            .unwrap();
        assert!(store.devices().revoke(&device.id).unwrap());
        let first = store
            .devices()
            .get(&device.id)
            .unwrap()
            .unwrap()
            .revoked_at_ms;

        assert!(!store.devices().revoke(&device.id).unwrap());
        assert_eq!(
            store
                .devices()
                .get(&device.id)
                .unwrap()
                .unwrap()
                .revoked_at_ms,
            first
        );

        assert!(matches!(
            store.devices().revoke(&DeviceId::from_bytes([1; 32])),
            Err(StoreError::NotFound { .. })
        ));
    }

    #[test]
    fn grants_round_trip() {
        let (_dir, store) = on_disk();
        let device = store
            .devices()
            .pair(&key(10), "Phone", None, CapabilitySet::default_grant())
            .unwrap();
        assert_eq!(
            store.devices().grants(&device.id).unwrap(),
            CapabilitySet::default_grant()
        );

        for grant in [
            CapabilitySet::EMPTY,
            CapabilitySet::all(),
            CapabilitySet::from_iter([Capability::FsRead]),
            CapabilitySet::from_iter([Capability::GitDangerous, Capability::PolicyWrite]),
            CapabilitySet::default_grant(),
        ] {
            store.devices().set_grants(&device.id, grant, None).unwrap();
            assert_eq!(
                store.devices().grants(&device.id).unwrap(),
                grant,
                "round trip failed for {grant:?}"
            );
        }
    }

    #[test]
    fn setting_grants_replaces_rather_than_merges() {
        // A merge would make it impossible to take a capability away, which is
        // the operation that matters most.
        let (_dir, store) = on_disk();
        let device = store
            .devices()
            .pair(&key(11), "Phone", None, CapabilitySet::all())
            .unwrap();
        store
            .devices()
            .set_grants(
                &device.id,
                CapabilitySet::from_iter([Capability::FsRead]),
                None,
            )
            .unwrap();
        let grants = store.devices().grants(&device.id).unwrap();
        assert!(grants.contains(Capability::FsRead));
        assert!(!grants.contains(Capability::PolicyWrite));
        assert_eq!(grants.len(), 1);
    }

    #[test]
    fn the_granting_device_is_recorded() {
        let (_dir, store) = on_disk();
        let admin = store
            .devices()
            .pair(&key(12), "Laptop-paired admin", None, CapabilitySet::all())
            .unwrap();
        let phone = store
            .devices()
            .pair(&key(13), "Phone", None, CapabilitySet::EMPTY)
            .unwrap();

        store
            .devices()
            .set_grants(
                &phone.id,
                CapabilitySet::from_iter([Capability::FsRead]),
                Some(&admin.id),
            )
            .unwrap();

        let granted_by: Option<String> = store
            .raw_for_test()
            .query_row(
                "SELECT granted_by FROM grants WHERE device_id = ?1",
                [phone.id.to_hex()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(granted_by, Some(admin.id.to_hex()));
    }

    #[test]
    fn grants_for_an_unknown_device_are_empty_not_an_error() {
        let (_dir, store) = on_disk();
        assert!(store
            .devices()
            .grants(&DeviceId::from_bytes([0xab; 32]))
            .unwrap()
            .is_empty());
        assert!(matches!(
            store.devices().set_grants(
                &DeviceId::from_bytes([0xab; 32]),
                CapabilitySet::all(),
                None
            ),
            Err(StoreError::NotFound { .. })
        ));
    }

    #[test]
    fn an_unrecognised_capability_is_skipped_not_granted() {
        // Forward compatibility: a database written by a newer build must not
        // brick this one, and must not be interpreted generously either.
        let (_dir, store) = on_disk();
        let device = store
            .devices()
            .pair(
                &key(14),
                "Phone",
                None,
                CapabilitySet::from_iter([Capability::FsRead]),
            )
            .unwrap();
        store
            .raw_for_test()
            .execute(
                "INSERT INTO grants (device_id, capability, granted_at, granted_by)
                 VALUES (?1, 'kernel:root', 0, NULL)",
                [device.id.to_hex()],
            )
            .unwrap();

        let grants = store.devices().grants(&device.id).unwrap();
        assert_eq!(grants, CapabilitySet::from_iter([Capability::FsRead]));
    }

    #[test]
    fn workspace_roots_add_list_and_remove() {
        let (_dir, store) = on_disk();
        let device = store
            .devices()
            .pair(&key(15), "Phone", None, CapabilitySet::default_grant())
            .unwrap();
        let devices = store.devices();

        assert!(devices.workspace_roots(&device.id).unwrap().is_empty());
        assert!(devices
            .add_workspace_root(&device.id, "C:/code/gonomad")
            .unwrap());
        assert!(devices
            .add_workspace_root(&device.id, "C:/code/other")
            .unwrap());
        // Adding the same root twice is a no-op, not a duplicate row.
        assert!(!devices
            .add_workspace_root(&device.id, "C:/code/other")
            .unwrap());

        assert_eq!(
            devices.workspace_roots(&device.id).unwrap(),
            vec!["C:/code/gonomad".to_owned(), "C:/code/other".to_owned()]
        );

        assert!(devices
            .remove_workspace_root(&device.id, "C:/code/other")
            .unwrap());
        assert!(!devices
            .remove_workspace_root(&device.id, "C:/code/other")
            .unwrap());
        assert_eq!(
            devices.workspace_roots(&device.id).unwrap(),
            vec!["C:/code/gonomad".to_owned()]
        );
    }

    #[test]
    fn workspace_roots_are_per_device() {
        let (_dir, store) = on_disk();
        let a = store
            .devices()
            .pair(&key(16), "A", None, CapabilitySet::EMPTY)
            .unwrap();
        let b = store
            .devices()
            .pair(&key(17), "B", None, CapabilitySet::EMPTY)
            .unwrap();
        store.devices().add_workspace_root(&a.id, "/a").unwrap();
        assert_eq!(store.devices().workspace_roots(&a.id).unwrap(), vec!["/a"]);
        assert!(store.devices().workspace_roots(&b.id).unwrap().is_empty());

        assert!(matches!(
            store
                .devices()
                .add_workspace_root(&DeviceId::from_bytes([0xcd; 32]), "/x"),
            Err(StoreError::NotFound { .. })
        ));
    }

    #[test]
    fn a_row_whose_id_contradicts_its_key_is_rejected() {
        let (_dir, store) = on_disk();
        store
            .raw_for_test()
            .execute(
                "INSERT INTO devices (id, pubkey, name, paired_at)
                 VALUES (?1, ?2, 'forged', 0)",
                rusqlite::params![DeviceId::from_bytes([0; 32]).to_hex(), key(20).to_hex()],
            )
            .unwrap();

        match store.devices().list().unwrap_err() {
            StoreError::CorruptRow { table, detail } => {
                assert_eq!(table, "devices");
                assert!(detail.contains("BLAKE3"), "{detail}");
            }
            other => panic!("expected CorruptRow, got {other:?}"),
        }
    }
}
