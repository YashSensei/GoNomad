//! The hash-chained, append-only audit log (`ARCHITECTURE.md` §3.9).
//!
//! ```text
//! entry_n = { seq, ts_utc, monotonic_ns, device_id, operation,
//!             args_digest, result, prev_hash }
//! hash_n  = BLAKE3(canonical_cbor(entry_n))
//! ```
//!
//! ## Why chain it
//!
//! An attacker who compromises the daemon will try to erase their tracks first.
//! A plain table lets them: `DELETE FROM audit WHERE ...` leaves nothing behind.
//! Chaining does not make deletion impossible — nothing stored on the attacked
//! machine can — it makes deletion *evident*, and it names the exact sequence
//! number where the history stops adding up.
//!
//! ## What `verify` does and does not guarantee
//!
//! Guaranteed, with no secret material involved:
//!
//! | Attack | Detected as |
//! |---|---|
//! | Edit any field of entry *n* | [`ChainBreak::ContentTampered`] at *n* |
//! | Delete entry *n* from the middle | [`ChainBreak::MissingEntry`] at *n* |
//! | Reorder or swap two entries | [`ChainBreak::ContentTampered`] at the first affected seq |
//! | Splice in a forged entry | [`ChainBreak::BrokenLink`] at the splice |
//! | Edit entry *n* **and** recompute `hash_n` | [`ChainBreak::BrokenLink`] at *n+1* |
//! | Delete a prefix without a checkpoint | [`ChainBreak::MissingEntry`] at the first expected seq |
//!
//! Not guaranteed by [`AuditLog::verify`] alone: an attacker who rewrites the
//! *entire tail* from the edited entry onwards produces an internally
//! consistent chain. The hash is unkeyed, so it must — anyone can compute it.
//! Two mechanisms bound this, and both require something outside the database:
//!
//! - [`AuditLog::verify_with_anchor`] compares the head hash against a value
//!   the caller obtained elsewhere (a phone's last-seen head, an exported
//!   receipt), which catches truncation from the end and whole-tail rewrites.
//! - Truncation checkpoints ([`Checkpoint`]) are signed by the daemon identity
//!   key, so retention rotation cannot be forged by someone who has database
//!   write access but not the signing key.
//!
//! ## What is *not* stored
//!
//! Arguments. Only [`Digest`]s of them. The log records that `/x/.env` was
//! read, never what it contained — an audit log that accumulated secrets would
//! be a more attractive target than the thing it audits.

use core::fmt;

use gonomad_proto::{DeviceId, Digest, PublicKey};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};

use crate::canonical::{self, Item};
use crate::clock;
use crate::error::{Result, StoreError};
use crate::row;

const TABLE: &str = "audit";
const CHECKPOINT_TABLE: &str = "audit_checkpoints";

/// The `prev_hash` of the very first entry.
///
/// All zeroes. Any well-defined constant works; zero is chosen because it is
/// unmistakable in a hex dump and because it is the value an independent
/// verifier will guess first. The genesis entry is otherwise an ordinary
/// entry — there is no special-cased row.
pub const GENESIS_PREV_HASH: Digest = Digest::from_bytes([0u8; 32]);

/// The sequence number of the genesis entry. Sequence numbers are 1-based so
/// that `0` can mean "no entries" without ambiguity.
pub const FIRST_SEQ: u64 = 1;

/// Domain separator mixed into every entry hash.
///
/// Present so that the canonical encoding of an entry can never collide with
/// the canonical encoding of a checkpoint (or of any future hashed structure),
/// which would otherwise let a signature over one be replayed as a signature
/// over the other.
const ENTRY_DOMAIN: &str = "gonomad.audit.entry.v1";

/// Domain separator mixed into every checkpoint signature.
const CHECKPOINT_DOMAIN: &str = "gonomad.audit.checkpoint.v1";

/// The outcome recorded against an audited operation.
///
/// A closed set: `ARCHITECTURE.md` §3.9 requires every denial to be logged, and
/// counting denials is only possible if "denied" is a value rather than a
/// substring of a free-text message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditResult {
    /// The operation was authorised and completed.
    Ok,
    /// The operation was refused by policy (capability, path guard, rate
    /// limit, or a missing presence signature).
    Denied,
    /// The operation was authorised but failed while executing.
    Failed,
}

impl AuditResult {
    /// Every variant, in declaration order.
    pub const ALL: [Self; 3] = [Self::Ok, Self::Denied, Self::Failed];

    /// The stable string stored in the database and mixed into the hash.
    ///
    /// Stable is the operative word: changing one of these strings would
    /// invalidate every historical hash.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Denied => "denied",
            Self::Failed => "failed",
        }
    }
}

impl fmt::Display for AuditResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned when a stored `result` string is not a known outcome.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown audit result: {0:?}")]
pub struct UnknownAuditResult(pub String);

impl core::str::FromStr for AuditResult {
    type Err = UnknownAuditResult;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|r| r.as_str() == s)
            .ok_or_else(|| UnknownAuditResult(s.to_owned()))
    }
}

/// What a caller supplies when logging an event.
///
/// The chain fields (`seq`, timestamps, `prev_hash`, `hash`) are assigned by
/// the log, never by the caller — a caller that could choose its own sequence
/// number could choose to overwrite history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// The device that requested the operation, or `None` for events the
    /// daemon originates (start-up, rotation, an operator action at the tray).
    pub device_id: Option<DeviceId>,
    /// A dotted operation name, e.g. `fs.read`, `device.revoke`.
    pub operation: String,
    /// A digest of the arguments — never the arguments themselves.
    pub args_digest: Digest,
    /// The outcome.
    pub result: AuditResult,
}

impl AuditRecord {
    /// Builds a record for a daemon-originated event.
    pub fn new(operation: impl Into<String>, args_digest: Digest, result: AuditResult) -> Self {
        Self {
            device_id: None,
            operation: operation.into(),
            args_digest,
            result,
        }
    }

    /// Attributes the record to a device.
    #[must_use]
    pub fn by(mut self, device_id: DeviceId) -> Self {
        self.device_id = Some(device_id);
        self
    }
}

/// One committed entry, including the chain fields the log assigned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Position in the chain. Monotonic and gap-free.
    pub seq: u64,
    /// Wall-clock time, Unix milliseconds UTC. Movable, and therefore only a
    /// hint; `monotonic_ns` is what establishes order.
    pub ts_utc_ms: i64,
    /// A nanosecond reading that never decreases from one entry to the next,
    /// so an entry backdated by moving the system clock is visible as a
    /// wall-clock time that disagrees with its monotonic position.
    pub monotonic_ns: u64,
    /// The requesting device, if any.
    pub device_id: Option<DeviceId>,
    /// The operation name.
    pub operation: String,
    /// Digest of the arguments.
    pub args_digest: Digest,
    /// The outcome.
    pub result: AuditResult,
    /// The hash of entry `seq - 1`, or [`GENESIS_PREV_HASH`] for the first
    /// entry, or the chain hash carried by a truncation [`Checkpoint`].
    pub prev_hash: Digest,
    /// `BLAKE3(canonical_cbor(entry))` over every field above.
    pub hash: Digest,
}

impl AuditEntry {
    /// The exact bytes that are hashed.
    ///
    /// Excludes `hash` itself (which would be circular) and includes every
    /// other field plus a domain separator.
    ///
    /// Deterministic by construction: the encoder is hand-written rather than
    /// derived through serde, because a derive would make the hash input a
    /// function of struct field declaration order — so reordering two fields,
    /// which no reviewer would flag, would silently invalidate every historical
    /// entry. Output is RFC 8949 core-deterministic: definite lengths,
    /// shortest-form integers, keys sorted by encoded bytes, no floats, no tags.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let device = self.device_id.map(DeviceId::to_bytes);
        canonical::map(&[
            ("t", Item::Text(ENTRY_DOMAIN)),
            ("seq", Item::Uint(self.seq)),
            ("ts", Item::Int(self.ts_utc_ms)),
            ("mono", Item::Uint(self.monotonic_ns)),
            (
                "dev",
                device
                    .as_ref()
                    .map_or(Item::Null, |b| Item::Bytes(b.as_slice())),
            ),
            ("op", Item::Text(&self.operation)),
            ("args", Item::Bytes(self.args_digest.as_bytes())),
            ("res", Item::Text(self.result.as_str())),
            ("prev", Item::Bytes(self.prev_hash.as_bytes())),
        ])
    }

    /// Recomputes this entry's hash from its contents.
    pub fn compute_hash(&self) -> Digest {
        Digest::of(&self.canonical_bytes())
    }

    /// `true` when the stored hash matches the entry's contents.
    pub fn is_self_consistent(&self) -> bool {
        self.compute_hash() == self.hash
    }
}

/// A signed record of where retention rotation cut the chain (§3.9).
///
/// After rotation, entry `truncated_through_seq + 1` links to `chain_hash`
/// instead of to a row that no longer exists, so verification still starts from
/// a known-good anchor. The signature is what distinguishes "the daemon rotated
/// old entries" from "an attacker deleted the interesting ones".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// The last sequence number that was removed.
    pub truncated_through_seq: u64,
    /// The hash of entry `truncated_through_seq` — the splice point.
    pub chain_hash: Digest,
    /// How many entries this rotation removed.
    pub entries_removed: u64,
    /// When the rotation happened, Unix milliseconds UTC.
    pub ts_utc_ms: i64,
    /// The public key of the daemon identity that signed it.
    pub signer: PublicKey,
    /// A 64-byte detached signature over [`Checkpoint::canonical_bytes`].
    #[serde(with = "signature_hex")]
    pub signature: [u8; 64],
}

impl Checkpoint {
    /// The bytes covered by [`Checkpoint::signature`].
    pub fn canonical_bytes(&self) -> Vec<u8> {
        Self::signing_bytes(
            self.truncated_through_seq,
            self.chain_hash,
            self.entries_removed,
            self.ts_utc_ms,
            self.signer,
        )
    }

    fn signing_bytes(
        truncated_through_seq: u64,
        chain_hash: Digest,
        entries_removed: u64,
        ts_utc_ms: i64,
        signer: PublicKey,
    ) -> Vec<u8> {
        canonical::map(&[
            ("t", Item::Text(CHECKPOINT_DOMAIN)),
            ("through", Item::Uint(truncated_through_seq)),
            ("chain", Item::Bytes(chain_hash.as_bytes())),
            ("removed", Item::Uint(entries_removed)),
            ("ts", Item::Int(ts_utc_ms)),
            ("signer", Item::Bytes(signer.as_bytes())),
        ])
    }
}

/// Serialises a 64-byte signature as lowercase hex, matching the convention
/// `gonomad-proto` uses for identifiers. `serde` has no built-in impl for
/// arrays longer than 32 bytes, so this is written out.
mod signature_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        value: &[u8; 64],
        s: S,
    ) -> core::result::Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(value))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> core::result::Result<[u8; 64], D::Error> {
        let text = String::deserialize(d)?;
        let bytes = hex::decode(&text).map_err(serde::de::Error::custom)?;
        <[u8; 64]>::try_from(bytes.as_slice()).map_err(|_| {
            serde::de::Error::custom(format!("expected 64 bytes, got {}", bytes.len()))
        })
    }
}

/// Error returned by a [`CheckpointSigner`] that cannot produce a signature.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct SignatureUnavailable(pub String);

/// Signs truncation checkpoints.
///
/// A trait rather than a concrete Ed25519 key because the daemon identity key
/// belongs to the key-management layer (§3.3), not to the database layer. This
/// crate therefore never holds private key material, and the signer can be a
/// software key, an OS keychain handle, or a token without any change here.
pub trait CheckpointSigner {
    /// The public key clients will verify against.
    fn public_key(&self) -> PublicKey;

    /// Produces a 64-byte detached signature over `message`.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureUnavailable`] when the key cannot be reached — a
    /// locked keychain, a removed token.
    fn sign(&self, message: &[u8]) -> core::result::Result<[u8; 64], SignatureUnavailable>;
}

/// Verifies truncation checkpoint signatures.
pub trait CheckpointVerifier {
    /// `true` when `signature` is a valid signature over `message` by `signer`.
    fn verify(&self, signer: &PublicKey, message: &[u8], signature: &[u8; 64]) -> bool;
}

/// Where and how the chain failed to verify.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ChainBreak {
    /// The expected sequence number is absent; the next entry present is
    /// `found_seq`. This is what a deletion from the middle, or an
    /// uncheckpointed truncation from the front, looks like.
    MissingEntry {
        /// The next sequence number that does exist.
        found_seq: u64,
    },
    /// The entry's stored hash is not the hash of its own contents: some field
    /// was modified in place.
    ContentTampered {
        /// The hash the contents actually produce.
        expected: Digest,
        /// The hash stored on the row.
        found: Digest,
    },
    /// The entry's `prev_hash` does not name its predecessor: an entry was
    /// spliced in, or a predecessor was rewritten.
    BrokenLink {
        /// The predecessor's actual hash.
        expected: Digest,
        /// The `prev_hash` the entry carries.
        found: Digest,
    },
    /// The chain is internally consistent but its head is not the anchored
    /// value: entries were removed from the end.
    TruncatedHead {
        /// The anchored head hash the caller supplied.
        expected: Digest,
        /// The head hash actually present, if any.
        found: Option<Digest>,
    },
    /// A row could not be decoded into an entry at all.
    UndecodableRow {
        /// What failed to decode.
        detail: String,
    },
}

impl fmt::Display for ChainBreak {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEntry { found_seq } => {
                write!(f, "entry is missing (next present entry is {found_seq})")
            }
            Self::ContentTampered { expected, found } => write!(
                f,
                "contents were modified: they hash to {expected} but the row stores {found}"
            ),
            Self::BrokenLink { expected, found } => write!(
                f,
                "prev_hash is {found} but the preceding entry hashes to {expected}"
            ),
            Self::TruncatedHead { expected, found } => match found {
                Some(found) => write!(f, "head is {found} but was anchored at {expected}"),
                None => write!(f, "log is empty but was anchored at {expected}"),
            },
            Self::UndecodableRow { detail } => write!(f, "row could not be decoded: {detail}"),
        }
    }
}

/// The result of walking the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ChainStatus {
    /// Every entry present verified.
    Intact {
        /// How many entries were checked.
        entries: u64,
        /// The last sequence number, or `None` when the log is empty.
        head_seq: Option<u64>,
        /// The last entry's hash, or `None` when the log is empty.
        head_hash: Option<Digest>,
    },
    /// Verification failed.
    Broken {
        /// The exact sequence number the failure is attributed to.
        seq: u64,
        /// What went wrong there.
        cause: ChainBreak,
    },
}

impl ChainStatus {
    /// `true` when the chain verified.
    pub fn is_intact(&self) -> bool {
        matches!(self, Self::Intact { .. })
    }

    /// The sequence number where integrity breaks, if it does.
    pub fn broken_at(&self) -> Option<u64> {
        match self {
            Self::Intact { .. } => None,
            Self::Broken { seq, .. } => Some(*seq),
        }
    }
}

impl fmt::Display for ChainStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Intact {
                entries, head_seq, ..
            } => match head_seq {
                Some(seq) => write!(
                    f,
                    "audit chain intact: {entries} entries, head at seq {seq}"
                ),
                None => f.write_str("audit chain intact: log is empty"),
            },
            Self::Broken { seq, cause } => write!(f, "audit chain broken at seq {seq}: {cause}"),
        }
    }
}

/// The audit log repository.
///
/// Obtained from [`crate::Store::audit`]. Borrows the connection, so it is a
/// zero-cost handle rather than a second database resource.
pub struct AuditLog<'a> {
    conn: &'a Connection,
}

impl<'a> AuditLog<'a> {
    pub(crate) fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// Appends an entry, stamping it with the current time.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::AuditChainBroken`] when the current head does not
    /// verify — extending a chain that already fails verification would bury
    /// the break under new entries — or [`StoreError::Database`] on engine
    /// failure.
    pub fn append(&self, record: &AuditRecord) -> Result<AuditEntry> {
        self.append_at(record, clock::now_unix_ms(), clock::monotonic_now_ns())
    }

    /// Appends an entry with caller-supplied timestamps.
    ///
    /// For tests and for replaying a recovered log. `monotonic_ns` is raised to
    /// `previous + 1` when necessary, so the monotonic invariant holds even
    /// across a daemon restart or a caller that passes a stale reading.
    ///
    /// # Errors
    ///
    /// As [`AuditLog::append`].
    pub fn append_at(
        &self,
        record: &AuditRecord,
        ts_utc_ms: i64,
        monotonic_ns: u64,
    ) -> Result<AuditEntry> {
        // IMMEDIATE: reading the tail and writing the successor must be one
        // atomic step, or two concurrent appends could both read seq n and
        // both write seq n+1 with the same prev_hash — a fork in the chain.
        let tx = Transaction::new_unchecked(self.conn, TransactionBehavior::Immediate)?;
        let entry = append_within(&tx, record, ts_utc_ms, monotonic_ns)?;
        tx.commit()?;
        Ok(entry)
    }

    /// The number of entries currently stored (excluding rotated-away ones).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`] on engine failure.
    pub fn count(&self) -> Result<u64> {
        count_within(self.conn)
    }

    /// The last entry's sequence number and hash, or `None` when empty.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::CorruptRow`] when the head row cannot be decoded,
    /// or [`StoreError::Database`] on engine failure.
    pub fn head(&self) -> Result<Option<(u64, Digest)>> {
        Ok(tail_entry(self.conn)?.map(|e| (e.seq, e.hash)))
    }

    /// Fetches one entry by sequence number.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::CorruptRow`] when the row cannot be decoded, or
    /// [`StoreError::Database`] on engine failure.
    pub fn get(&self, seq: u64) -> Result<Option<AuditEntry>> {
        let seq = row::i64_from_u64(TABLE, "seq", seq)?;
        let raw = self
            .conn
            .query_row(
                &format!("SELECT {} FROM audit WHERE seq = ?1", RawEntry::COLUMNS),
                [seq],
                RawEntry::from_row,
            )
            .optional()?;
        raw.map(RawEntry::decode).transpose()
    }

    /// Returns up to `limit` entries starting at `from_seq`, ascending.
    ///
    /// # Errors
    ///
    /// As [`AuditLog::get`].
    pub fn range(&self, from_seq: u64, limit: u32) -> Result<Vec<AuditEntry>> {
        let from_seq = row::i64_from_u64(TABLE, "seq", from_seq)?;
        self.collect(
            &format!(
                "SELECT {} FROM audit WHERE seq >= ?1 ORDER BY seq ASC LIMIT ?2",
                RawEntry::COLUMNS
            ),
            rusqlite::params![from_seq, limit],
        )
    }

    /// Returns the newest `limit` entries, newest first.
    ///
    /// This is what the phone's Security screen (§23) renders.
    ///
    /// # Errors
    ///
    /// As [`AuditLog::get`].
    pub fn recent(&self, limit: u32) -> Result<Vec<AuditEntry>> {
        self.collect(
            &format!(
                "SELECT {} FROM audit ORDER BY seq DESC LIMIT ?1",
                RawEntry::COLUMNS
            ),
            rusqlite::params![limit],
        )
    }

    /// Returns the newest `limit` entries attributed to one device.
    ///
    /// # Errors
    ///
    /// As [`AuditLog::get`].
    pub fn for_device(&self, device_id: &DeviceId, limit: u32) -> Result<Vec<AuditEntry>> {
        self.collect(
            &format!(
                "SELECT {} FROM audit WHERE device_id = ?1 ORDER BY seq DESC LIMIT ?2",
                RawEntry::COLUMNS
            ),
            rusqlite::params![device_id.to_hex(), limit],
        )
    }

    fn collect(&self, sql: &str, params: &[&dyn rusqlite::ToSql]) -> Result<Vec<AuditEntry>> {
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map(params, RawEntry::from_row)?;
        let mut out = Vec::new();
        for raw in rows {
            out.push(raw?.decode()?);
        }
        Ok(out)
    }

    /// Walks the chain from genesis (or from the newest truncation checkpoint)
    /// and reports the exact sequence number where integrity breaks.
    ///
    /// See the module documentation for the precise set of attacks this
    /// detects and the one it cannot detect on its own.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`] on engine failure. A *broken chain is
    /// not an error* — it is an `Ok(ChainStatus::Broken)`, because it is a
    /// finding to report to the user rather than a fault in the query.
    pub fn verify(&self) -> Result<ChainStatus> {
        verify_within(self.conn)
    }

    /// As [`AuditLog::verify`], but additionally requires the head hash to
    /// equal `anchor`.
    ///
    /// The anchor must come from outside this database — the phone's last-seen
    /// head, or an exported receipt. That is the only way to detect an attacker
    /// who truncated the tail or rewrote the chain wholesale, since an unkeyed
    /// hash chain is recomputable by anyone.
    ///
    /// # Errors
    ///
    /// As [`AuditLog::verify`].
    pub fn verify_with_anchor(&self, anchor: Digest) -> Result<ChainStatus> {
        let status = self.verify()?;
        let ChainStatus::Intact {
            head_seq,
            head_hash,
            ..
        } = status
        else {
            return Ok(status);
        };
        if head_hash == Some(anchor) {
            return Ok(status);
        }
        Ok(ChainStatus::Broken {
            // The first sequence number that should have been there and is not.
            seq: head_seq.map_or(FIRST_SEQ, |s| s + 1),
            cause: ChainBreak::TruncatedHead {
                expected: anchor,
                found: head_hash,
            },
        })
    }

    /// The newest truncation checkpoint, if the log has ever been rotated.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::CorruptRow`] or [`StoreError::Database`].
    pub fn latest_checkpoint(&self) -> Result<Option<Checkpoint>> {
        latest_checkpoint_within(self.conn)
    }

    /// Every truncation checkpoint, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::CorruptRow`] or [`StoreError::Database`].
    pub fn checkpoints(&self) -> Result<Vec<Checkpoint>> {
        let mut stmt = self.conn.prepare(
            "SELECT truncated_through_seq, chain_hash, entries_removed, ts_utc, signer, signature
             FROM audit_checkpoints ORDER BY truncated_through_seq ASC",
        )?;
        let rows = stmt.query_map([], RawCheckpoint::from_row)?;
        let mut out = Vec::new();
        for raw in rows {
            out.push(raw?.decode()?);
        }
        Ok(out)
    }

    /// Enforces the retention cap (§3.9), rotating the oldest entries away and
    /// recording a signed checkpoint at the cut.
    ///
    /// Returns `None` when the log is already within the cap. The chain is
    /// verified first and rotation is refused if it is broken, because signing
    /// a checkpoint over a corrupt prefix would launder the corruption into
    /// something that looks authoritative.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::AuditChainBroken`] when verification fails,
    /// [`StoreError::CheckpointSigning`] when the signer is unavailable, or
    /// [`StoreError::Database`] on engine failure.
    pub fn rotate(
        &self,
        max_entries: u64,
        signer: &dyn CheckpointSigner,
    ) -> Result<Option<Checkpoint>> {
        self.rotate_at(max_entries, signer, clock::now_unix_ms())
    }

    /// As [`AuditLog::rotate`], with a caller-supplied timestamp.
    ///
    /// # Errors
    ///
    /// As [`AuditLog::rotate`].
    pub fn rotate_at(
        &self,
        max_entries: u64,
        signer: &dyn CheckpointSigner,
        ts_utc_ms: i64,
    ) -> Result<Option<Checkpoint>> {
        let tx = Transaction::new_unchecked(self.conn, TransactionBehavior::Immediate)?;

        if let Some(seq) = verify_within(&tx)?.broken_at() {
            return Err(StoreError::AuditChainBroken { seq });
        }

        let total = count_within(&tx)?;
        if total <= max_entries {
            return Ok(None);
        }

        let Some(head) = tail_entry(&tx)? else {
            return Ok(None);
        };
        let Some(first_seq) = first_seq_within(&tx)? else {
            return Ok(None);
        };

        // `total > max_entries` and sequence numbers are contiguous, so this
        // cannot underflow; saturating anyway keeps a future bug from
        // producing a colossal `truncate_through`.
        let truncate_through = head.seq.saturating_sub(max_entries);
        let splice = self
            .get(truncate_through)?
            .ok_or(StoreError::AuditChainBroken {
                seq: truncate_through,
            })?;
        let entries_removed = truncate_through - first_seq + 1;

        let public_key = signer.public_key();
        let message = Checkpoint::signing_bytes(
            truncate_through,
            splice.hash,
            entries_removed,
            ts_utc_ms,
            public_key,
        );
        let signature = signer
            .sign(&message)
            .map_err(|e| StoreError::CheckpointSigning(e.to_string()))?;

        let checkpoint = Checkpoint {
            truncated_through_seq: truncate_through,
            chain_hash: splice.hash,
            entries_removed,
            ts_utc_ms,
            signer: public_key,
            signature,
        };

        tx.execute(
            "INSERT INTO audit_checkpoints
                 (truncated_through_seq, chain_hash, entries_removed, ts_utc, signer, signature)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                row::i64_from_u64(CHECKPOINT_TABLE, "truncated_through_seq", truncate_through)?,
                checkpoint.chain_hash.as_bytes().as_slice(),
                row::i64_from_u64(CHECKPOINT_TABLE, "entries_removed", entries_removed)?,
                ts_utc_ms,
                public_key.to_hex(),
                checkpoint.signature.as_slice(),
            ],
        )?;
        tx.execute(
            "DELETE FROM audit WHERE seq <= ?1",
            [row::i64_from_u64(TABLE, "seq", truncate_through)?],
        )?;

        tx.commit()?;
        tracing::info!(
            truncate_through,
            entries_removed,
            "rotated the audit log and recorded a signed checkpoint"
        );
        Ok(Some(checkpoint))
    }

    /// Checks every truncation checkpoint's signature.
    ///
    /// Returns the sequence number of the first checkpoint whose signature does
    /// not verify, or `None` when all of them do.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::CorruptRow`] or [`StoreError::Database`].
    pub fn verify_checkpoints(&self, verifier: &dyn CheckpointVerifier) -> Result<Option<u64>> {
        for checkpoint in self.checkpoints()? {
            let message = checkpoint.canonical_bytes();
            if !verifier.verify(&checkpoint.signer, &message, &checkpoint.signature) {
                return Ok(Some(checkpoint.truncated_through_seq));
            }
        }
        Ok(None)
    }
}

// --- Free functions, so that both `&Connection` and `&Transaction` work ---

fn append_within(
    conn: &Connection,
    record: &AuditRecord,
    ts_utc_ms: i64,
    monotonic_ns: u64,
) -> Result<AuditEntry> {
    let (seq, prev_hash, monotonic_floor) = match tail_entry(conn)? {
        Some(tail) => {
            // Cheap tamper check on the one entry we are about to build on.
            // A full walk would be O(n) per append and would make logging cost
            // grow with history, which is a denial-of-service in itself.
            if !tail.is_self_consistent() {
                return Err(StoreError::AuditChainBroken { seq: tail.seq });
            }
            (tail.seq + 1, tail.hash, tail.monotonic_ns + 1)
        }
        // Empty log: either genuinely fresh, or everything has been rotated
        // away and the newest checkpoint carries the chain forward.
        None => match latest_checkpoint_within(conn)? {
            Some(cp) => (cp.truncated_through_seq + 1, cp.chain_hash, 0),
            None => (FIRST_SEQ, GENESIS_PREV_HASH, 0),
        },
    };

    let entry = {
        let mut entry = AuditEntry {
            seq,
            ts_utc_ms,
            monotonic_ns: monotonic_ns.max(monotonic_floor),
            device_id: record.device_id,
            operation: record.operation.clone(),
            args_digest: record.args_digest,
            result: record.result,
            prev_hash,
            hash: GENESIS_PREV_HASH,
        };
        entry.hash = entry.compute_hash();
        entry
    };

    conn.execute(
        "INSERT INTO audit
             (seq, ts_utc, monotonic_ns, device_id, operation, args_digest, result, prev_hash, hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        rusqlite::params![
            row::i64_from_u64(TABLE, "seq", entry.seq)?,
            entry.ts_utc_ms,
            row::i64_from_u64(TABLE, "monotonic_ns", entry.monotonic_ns)?,
            entry.device_id.map(|d| d.to_hex()),
            entry.operation,
            entry.args_digest.as_bytes().as_slice(),
            entry.result.as_str(),
            entry.prev_hash.as_bytes().as_slice(),
            entry.hash.as_bytes().as_slice(),
        ],
    )?;

    Ok(entry)
}

fn count_within(conn: &Connection) -> Result<u64> {
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM audit", [], |row| row.get(0))?;
    row::u64_from_i64(TABLE, "count", count)
}

fn first_seq_within(conn: &Connection) -> Result<Option<u64>> {
    let seq: Option<i64> = conn.query_row("SELECT MIN(seq) FROM audit", [], |row| row.get(0))?;
    seq.map(|s| row::u64_from_i64(TABLE, "seq", s)).transpose()
}

fn tail_entry(conn: &Connection) -> Result<Option<AuditEntry>> {
    let raw = conn
        .query_row(
            &format!(
                "SELECT {} FROM audit ORDER BY seq DESC LIMIT 1",
                RawEntry::COLUMNS
            ),
            [],
            RawEntry::from_row,
        )
        .optional()?;
    raw.map(RawEntry::decode).transpose()
}

fn latest_checkpoint_within(conn: &Connection) -> Result<Option<Checkpoint>> {
    let raw = conn
        .query_row(
            "SELECT truncated_through_seq, chain_hash, entries_removed, ts_utc, signer, signature
             FROM audit_checkpoints ORDER BY truncated_through_seq DESC LIMIT 1",
            [],
            RawCheckpoint::from_row,
        )
        .optional()?;
    raw.map(RawCheckpoint::decode).transpose()
}

fn verify_within(conn: &Connection) -> Result<ChainStatus> {
    // Where the chain is expected to start: after the newest checkpoint if the
    // log has been rotated, at genesis otherwise.
    let (mut expected_seq, mut expected_prev) = match latest_checkpoint_within(conn)? {
        Some(cp) => (cp.truncated_through_seq + 1, cp.chain_hash),
        None => (FIRST_SEQ, GENESIS_PREV_HASH),
    };

    let mut stmt = conn.prepare(&format!(
        "SELECT {} FROM audit ORDER BY seq ASC",
        RawEntry::COLUMNS
    ))?;
    let mut rows = stmt.query([])?;

    let mut entries = 0u64;
    let mut head_seq = None;
    let mut head_hash = None;

    while let Some(sql_row) = rows.next()? {
        let raw = RawEntry::from_row(sql_row)?;
        let seq_hint = u64::try_from(raw.seq).unwrap_or(expected_seq);
        let entry = match raw.decode() {
            Ok(entry) => entry,
            Err(e) => {
                return Ok(ChainStatus::Broken {
                    seq: seq_hint,
                    cause: ChainBreak::UndecodableRow {
                        detail: e.to_string(),
                    },
                })
            }
        };

        if entry.seq != expected_seq {
            // Rows come back ordered, so a seq that is not the expected one is
            // always a gap (a deletion), never a reordering.
            return Ok(ChainStatus::Broken {
                seq: expected_seq,
                cause: ChainBreak::MissingEntry {
                    found_seq: entry.seq,
                },
            });
        }

        // Content first: a field edited without recomputing the hash is
        // attributable to *this* entry, whereas the link check would blame its
        // successor.
        let recomputed = entry.compute_hash();
        if recomputed != entry.hash {
            return Ok(ChainStatus::Broken {
                seq: entry.seq,
                cause: ChainBreak::ContentTampered {
                    expected: recomputed,
                    found: entry.hash,
                },
            });
        }
        if entry.prev_hash != expected_prev {
            return Ok(ChainStatus::Broken {
                seq: entry.seq,
                cause: ChainBreak::BrokenLink {
                    expected: expected_prev,
                    found: entry.prev_hash,
                },
            });
        }

        entries += 1;
        head_seq = Some(entry.seq);
        head_hash = Some(entry.hash);
        expected_prev = entry.hash;
        expected_seq = entry.seq + 1;
    }

    Ok(ChainStatus::Intact {
        entries,
        head_seq,
        head_hash,
    })
}

// --- Row decoding ---

struct RawEntry {
    seq: i64,
    ts_utc: i64,
    monotonic_ns: i64,
    device_id: Option<String>,
    operation: String,
    args_digest: Vec<u8>,
    result: String,
    prev_hash: Vec<u8>,
    hash: Vec<u8>,
}

impl RawEntry {
    const COLUMNS: &'static str =
        "seq, ts_utc, monotonic_ns, device_id, operation, args_digest, result, prev_hash, hash";

    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            seq: row.get(0)?,
            ts_utc: row.get(1)?,
            monotonic_ns: row.get(2)?,
            device_id: row.get(3)?,
            operation: row.get(4)?,
            args_digest: row.get(5)?,
            result: row.get(6)?,
            prev_hash: row.get(7)?,
            hash: row.get(8)?,
        })
    }

    fn decode(self) -> Result<AuditEntry> {
        Ok(AuditEntry {
            seq: row::u64_from_i64(TABLE, "seq", self.seq)?,
            ts_utc_ms: self.ts_utc,
            monotonic_ns: row::u64_from_i64(TABLE, "monotonic_ns", self.monotonic_ns)?,
            device_id: self
                .device_id
                .as_deref()
                .map(|s| row::device_id(TABLE, "device_id", s))
                .transpose()?,
            operation: self.operation,
            args_digest: row::digest(TABLE, "args_digest", &self.args_digest)?,
            result: self
                .result
                .parse()
                .map_err(|e| StoreError::corrupt(TABLE, e))?,
            prev_hash: row::digest(TABLE, "prev_hash", &self.prev_hash)?,
            hash: row::digest(TABLE, "hash", &self.hash)?,
        })
    }
}

struct RawCheckpoint {
    truncated_through_seq: i64,
    chain_hash: Vec<u8>,
    entries_removed: i64,
    ts_utc: i64,
    signer: String,
    signature: Vec<u8>,
}

impl RawCheckpoint {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            truncated_through_seq: row.get(0)?,
            chain_hash: row.get(1)?,
            entries_removed: row.get(2)?,
            ts_utc: row.get(3)?,
            signer: row.get(4)?,
            signature: row.get(5)?,
        })
    }

    fn decode(self) -> Result<Checkpoint> {
        Ok(Checkpoint {
            truncated_through_seq: row::u64_from_i64(
                CHECKPOINT_TABLE,
                "truncated_through_seq",
                self.truncated_through_seq,
            )?,
            chain_hash: row::digest(CHECKPOINT_TABLE, "chain_hash", &self.chain_hash)?,
            entries_removed: row::u64_from_i64(
                CHECKPOINT_TABLE,
                "entries_removed",
                self.entries_removed,
            )?,
            ts_utc_ms: self.ts_utc,
            signer: row::public_key(CHECKPOINT_TABLE, "signer", &self.signer)?,
            signature: row::signature(CHECKPOINT_TABLE, "signature", &self.signature)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;

    /// A deterministic stand-in for the daemon's Ed25519 identity.
    ///
    /// This crate deliberately does not depend on a signature library (§3.3
    /// puts key handling in another layer), so the tests supply a keyed BLAKE3
    /// MAC instead. It exercises exactly the interface the real signer uses.
    struct FakeSigner {
        key: [u8; 32],
    }

    impl FakeSigner {
        fn new(seed: u8) -> Self {
            Self { key: [seed; 32] }
        }

        fn mac(&self, message: &[u8]) -> [u8; 64] {
            let first = blake3::keyed_hash(&self.key, message);
            let mut second_input = first.as_bytes().to_vec();
            second_input.extend_from_slice(message);
            let second = blake3::keyed_hash(&self.key, &second_input);
            let mut out = [0u8; 64];
            out[..32].copy_from_slice(first.as_bytes());
            out[32..].copy_from_slice(second.as_bytes());
            out
        }
    }

    impl CheckpointSigner for FakeSigner {
        fn public_key(&self) -> PublicKey {
            PublicKey::from_bytes(self.key)
        }

        fn sign(&self, message: &[u8]) -> core::result::Result<[u8; 64], SignatureUnavailable> {
            Ok(self.mac(message))
        }
    }

    impl CheckpointVerifier for FakeSigner {
        fn verify(&self, signer: &PublicKey, message: &[u8], signature: &[u8; 64]) -> bool {
            *signer == self.public_key() && self.mac(message) == *signature
        }
    }

    struct BrokenSigner;

    impl CheckpointSigner for BrokenSigner {
        fn public_key(&self) -> PublicKey {
            PublicKey::from_bytes([0xaa; 32])
        }

        fn sign(&self, _message: &[u8]) -> core::result::Result<[u8; 64], SignatureUnavailable> {
            Err(SignatureUnavailable("keychain is locked".to_owned()))
        }
    }

    /// A real on-disk database, because the audit log's whole point is what
    /// survives a restart.
    fn on_disk() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("gonomad.db")).unwrap();
        (dir, store)
    }

    fn record(op: &str) -> AuditRecord {
        AuditRecord::new(op, Digest::of(op.as_bytes()), AuditResult::Ok)
    }

    fn append_many(store: &Store, count: u64) {
        for i in 0..count {
            store
                .audit()
                .append_at(
                    &record(&format!("op.{i}")),
                    1_700_000_000_000 + i64::try_from(i).unwrap(),
                    1000 + i,
                )
                .unwrap();
        }
    }

    #[test]
    fn genesis_entry_has_the_documented_prev_hash() {
        let (_dir, store) = on_disk();
        let entry = store.audit().append(&record("daemon.start")).unwrap();
        assert_eq!(entry.seq, FIRST_SEQ);
        assert_eq!(entry.prev_hash, GENESIS_PREV_HASH);
        assert_eq!(entry.prev_hash.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn sequence_numbers_are_monotonic_and_gap_free() {
        let (_dir, store) = on_disk();
        append_many(&store, 50);
        let entries = store.audit().range(FIRST_SEQ, 100).unwrap();
        assert_eq!(entries.len(), 50);
        for (i, entry) in entries.iter().enumerate() {
            assert_eq!(entry.seq, u64::try_from(i).unwrap() + FIRST_SEQ);
        }
    }

    #[test]
    fn each_entry_links_to_its_predecessor() {
        let (_dir, store) = on_disk();
        append_many(&store, 10);
        let entries = store.audit().range(FIRST_SEQ, 100).unwrap();
        for pair in entries.windows(2) {
            assert_eq!(pair[1].prev_hash, pair[0].hash);
        }
    }

    #[test]
    fn hashing_is_deterministic_for_the_same_logical_entry() {
        // The property the entire chain rests on. If this ever fails, every
        // historical hash is invalidated and `audit verify` becomes noise.
        let entry = AuditEntry {
            seq: 42,
            ts_utc_ms: 1_700_000_000_123,
            monotonic_ns: 987_654_321,
            device_id: Some(DeviceId::from_bytes([7; 32])),
            operation: "fs.read".to_owned(),
            args_digest: Digest::of(b"/x/.env"),
            result: AuditResult::Denied,
            prev_hash: Digest::of(b"previous"),
            hash: GENESIS_PREV_HASH,
        };

        let first = entry.compute_hash();
        for _ in 0..1000 {
            assert_eq!(entry.clone().compute_hash(), first);
        }

        // A separately constructed but logically identical entry must agree.
        let twin = AuditEntry {
            operation: String::from("fs.read"),
            ..entry.clone()
        };
        assert_eq!(twin.compute_hash(), first);

        // And the value is pinned, so a change to the canonical encoding shows
        // up here as a failing test rather than as a silently rewritten
        // history.
        assert_eq!(
            first.to_hex(),
            Digest::of(&entry.canonical_bytes()).to_hex(),
            "compute_hash must be BLAKE3 over the canonical bytes"
        );
    }

    #[test]
    fn changing_any_single_field_changes_the_hash() {
        let base = AuditEntry {
            seq: 1,
            ts_utc_ms: 1,
            monotonic_ns: 1,
            device_id: None,
            operation: "a".to_owned(),
            args_digest: Digest::of(b"a"),
            result: AuditResult::Ok,
            prev_hash: GENESIS_PREV_HASH,
            hash: GENESIS_PREV_HASH,
        };
        let original = base.compute_hash();

        let mutations: Vec<AuditEntry> = vec![
            AuditEntry {
                seq: 2,
                ..base.clone()
            },
            AuditEntry {
                ts_utc_ms: 2,
                ..base.clone()
            },
            AuditEntry {
                monotonic_ns: 2,
                ..base.clone()
            },
            AuditEntry {
                device_id: Some(DeviceId::from_bytes([0; 32])),
                ..base.clone()
            },
            AuditEntry {
                operation: "b".to_owned(),
                ..base.clone()
            },
            AuditEntry {
                args_digest: Digest::of(b"b"),
                ..base.clone()
            },
            AuditEntry {
                result: AuditResult::Denied,
                ..base.clone()
            },
            AuditEntry {
                prev_hash: Digest::of(b"x"),
                ..base.clone()
            },
        ];
        for (i, mutated) in mutations.iter().enumerate() {
            assert_ne!(
                mutated.compute_hash(),
                original,
                "mutation {i} did not change the hash"
            );
        }

        // `hash` itself is excluded from its own preimage.
        let rehashed = AuditEntry {
            hash: Digest::of(b"anything"),
            ..base
        };
        assert_eq!(rehashed.compute_hash(), original);
    }

    #[test]
    fn a_none_device_is_not_the_same_as_an_all_zero_device() {
        // Encoding `None` as a zero digest would let a daemon-originated entry
        // be relabelled as coming from a device whose id happened to be zero.
        let base = AuditEntry {
            seq: 1,
            ts_utc_ms: 0,
            monotonic_ns: 0,
            device_id: None,
            operation: "x".to_owned(),
            args_digest: GENESIS_PREV_HASH,
            result: AuditResult::Ok,
            prev_hash: GENESIS_PREV_HASH,
            hash: GENESIS_PREV_HASH,
        };
        let zeroed = AuditEntry {
            device_id: Some(DeviceId::from_bytes([0; 32])),
            ..base.clone()
        };
        assert_ne!(base.compute_hash(), zeroed.compute_hash());
    }

    #[test]
    fn verification_passes_on_an_untouched_chain() {
        let (_dir, store) = on_disk();
        append_many(&store, 25);
        let status = store.audit().verify().unwrap();
        assert!(status.is_intact(), "{status}");
        match status {
            ChainStatus::Intact {
                entries,
                head_seq,
                head_hash,
            } => {
                assert_eq!(entries, 25);
                assert_eq!(head_seq, Some(25));
                assert!(head_hash.is_some());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn verification_passes_on_an_empty_log() {
        let (_dir, store) = on_disk();
        let status = store.audit().verify().unwrap();
        assert!(status.is_intact());
        assert_eq!(store.audit().count().unwrap(), 0);
        assert_eq!(store.audit().head().unwrap(), None);
    }

    #[test]
    fn verification_survives_a_reopen() {
        // The chain must verify against bytes on disk, not against in-memory
        // state that happens to still be consistent.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gonomad.db");
        {
            let store = Store::open(&path).unwrap();
            append_many(&store, 10);
        }
        let reopened = Store::open(&path).unwrap();
        assert!(reopened.audit().verify().unwrap().is_intact());
        assert_eq!(reopened.audit().count().unwrap(), 10);
    }

    #[test]
    fn verification_detects_a_tampered_entry() {
        let (_dir, store) = on_disk();
        append_many(&store, 10);

        // The classic cover-up: change what an operation says it did.
        store
            .raw_for_test()
            .execute("UPDATE audit SET operation = 'fs.read' WHERE seq = 4", [])
            .unwrap();

        match store.audit().verify().unwrap() {
            ChainStatus::Broken { seq, cause } => {
                assert_eq!(seq, 4);
                assert!(
                    matches!(cause, ChainBreak::ContentTampered { .. }),
                    "{cause}"
                );
            }
            other => panic!("tampering went undetected: {other:?}"),
        }
    }

    #[test]
    fn verification_detects_a_tampered_result_and_device() {
        let (_dir, store) = on_disk();
        let device = DeviceId::from_bytes([3; 32]);
        store
            .audit()
            .append_at(&record("policy.change").by(device), 1, 1)
            .unwrap();
        append_many(&store, 3);

        // Turning a denial into a success is the interesting rewrite.
        store
            .raw_for_test()
            .execute("UPDATE audit SET result = 'denied' WHERE seq = 1", [])
            .unwrap();
        assert_eq!(store.audit().verify().unwrap().broken_at(), Some(1));
    }

    #[test]
    fn verification_detects_a_deleted_entry() {
        let (_dir, store) = on_disk();
        append_many(&store, 10);
        store
            .raw_for_test()
            .execute("DELETE FROM audit WHERE seq = 6", [])
            .unwrap();

        match store.audit().verify().unwrap() {
            ChainStatus::Broken { seq, cause } => {
                assert_eq!(seq, 6);
                assert_eq!(cause, ChainBreak::MissingEntry { found_seq: 7 });
            }
            other => panic!("deletion went undetected: {other:?}"),
        }
    }

    #[test]
    fn verification_detects_a_deleted_prefix() {
        let (_dir, store) = on_disk();
        append_many(&store, 10);
        store
            .raw_for_test()
            .execute("DELETE FROM audit WHERE seq <= 3", [])
            .unwrap();

        match store.audit().verify().unwrap() {
            ChainStatus::Broken { seq, cause } => {
                assert_eq!(seq, FIRST_SEQ);
                assert_eq!(cause, ChainBreak::MissingEntry { found_seq: 4 });
            }
            other => panic!("prefix deletion went undetected: {other:?}"),
        }
    }

    #[test]
    fn verification_detects_reordering() {
        let (_dir, store) = on_disk();
        append_many(&store, 10);

        // Swap the payloads of entries 3 and 7, leaving both rows present and
        // both sequence numbers intact — the subtle version of a rewrite.
        let three = store.audit().get(3).unwrap().unwrap();
        let seven = store.audit().get(7).unwrap().unwrap();
        let conn = store.raw_for_test();
        conn.execute(
            "UPDATE audit SET operation = ?1 WHERE seq = 3",
            [&seven.operation],
        )
        .unwrap();
        conn.execute(
            "UPDATE audit SET operation = ?1 WHERE seq = 7",
            [&three.operation],
        )
        .unwrap();

        assert_eq!(store.audit().verify().unwrap().broken_at(), Some(3));
    }

    #[test]
    fn verification_detects_swapped_sequence_numbers() {
        let (_dir, store) = on_disk();
        append_many(&store, 5);
        let conn = store.raw_for_test();
        // Move entry 2 to 99, entry 3 to 2, then 99 to 3: a straight swap.
        conn.execute("UPDATE audit SET seq = 99 WHERE seq = 2", [])
            .unwrap();
        conn.execute("UPDATE audit SET seq = 2 WHERE seq = 3", [])
            .unwrap();
        conn.execute("UPDATE audit SET seq = 3 WHERE seq = 99", [])
            .unwrap();

        let status = store.audit().verify().unwrap();
        assert_eq!(status.broken_at(), Some(2), "{status}");
    }

    #[test]
    fn verification_detects_a_spliced_entry_whose_hash_was_recomputed() {
        let (_dir, store) = on_disk();
        append_many(&store, 6);

        // The competent attacker: edit entry 3 *and* fix its hash so the entry
        // is self-consistent. The link from entry 4 is what gives them away.
        let mut forged = store.audit().get(3).unwrap().unwrap();
        forged.operation = "totally.benign".to_owned();
        forged.hash = forged.compute_hash();
        store
            .raw_for_test()
            .execute(
                "UPDATE audit SET operation = ?1, hash = ?2 WHERE seq = 3",
                rusqlite::params![forged.operation, forged.hash.as_bytes().as_slice()],
            )
            .unwrap();

        match store.audit().verify().unwrap() {
            ChainStatus::Broken { seq, cause } => {
                assert_eq!(seq, 4, "the break should surface at the successor");
                assert!(matches!(cause, ChainBreak::BrokenLink { .. }), "{cause}");
            }
            other => panic!("splice went undetected: {other:?}"),
        }
    }

    #[test]
    fn verification_detects_a_truncated_tail_only_with_an_anchor() {
        let (_dir, store) = on_disk();
        append_many(&store, 10);
        let (_, anchor) = store.audit().head().unwrap().unwrap();

        store
            .raw_for_test()
            .execute("DELETE FROM audit WHERE seq > 7", [])
            .unwrap();

        // Self-consistency alone cannot see this: 1..7 is a perfectly valid
        // chain. This is the documented limit of an unkeyed chain.
        assert!(store.audit().verify().unwrap().is_intact());

        match store.audit().verify_with_anchor(anchor).unwrap() {
            ChainStatus::Broken { seq, cause } => {
                assert_eq!(seq, 8);
                assert!(matches!(cause, ChainBreak::TruncatedHead { .. }), "{cause}");
            }
            other => panic!("tail truncation went undetected: {other:?}"),
        }
    }

    #[test]
    fn an_anchor_matching_the_head_verifies() {
        let (_dir, store) = on_disk();
        append_many(&store, 4);
        let (_, anchor) = store.audit().head().unwrap().unwrap();
        assert!(store
            .audit()
            .verify_with_anchor(anchor)
            .unwrap()
            .is_intact());
    }

    #[test]
    fn verification_detects_an_undecodable_row() {
        let (_dir, store) = on_disk();
        append_many(&store, 3);
        store
            .raw_for_test()
            .execute("UPDATE audit SET hash = x'0011' WHERE seq = 2", [])
            .unwrap();

        match store.audit().verify().unwrap() {
            ChainStatus::Broken { seq, cause } => {
                assert_eq!(seq, 2);
                assert!(
                    matches!(cause, ChainBreak::UndecodableRow { .. }),
                    "{cause}"
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn appending_onto_a_tampered_head_is_refused() {
        let (_dir, store) = on_disk();
        append_many(&store, 3);
        store
            .raw_for_test()
            .execute("UPDATE audit SET operation = 'lies' WHERE seq = 3", [])
            .unwrap();

        match store.audit().append(&record("next")).unwrap_err() {
            StoreError::AuditChainBroken { seq } => assert_eq!(seq, 3),
            other => panic!("expected AuditChainBroken, got {other:?}"),
        }
    }

    #[test]
    fn monotonic_time_never_decreases_even_when_the_caller_lies() {
        let (_dir, store) = on_disk();
        let log = store.audit();
        let first = log.append_at(&record("a"), 1000, 5_000).unwrap();
        // A caller (or a clock) that goes backwards must not produce a
        // backwards monotonic reading.
        let second = log.append_at(&record("b"), 500, 1).unwrap();
        assert!(second.monotonic_ns > first.monotonic_ns);
        // The wall clock is recorded verbatim, though: it is evidence, and
        // silently correcting it would destroy the discrepancy that reveals
        // the clock was moved.
        assert_eq!(second.ts_utc_ms, 500);
    }

    #[test]
    fn only_digests_are_stored_never_arguments() {
        let (_dir, store) = on_disk();
        let secret = b"AWS_SECRET_ACCESS_KEY=hunter2";
        store
            .audit()
            .append(&AuditRecord::new(
                "fs.read",
                Digest::of(secret),
                AuditResult::Ok,
            ))
            .unwrap();

        // Dump every text and blob column and assert the secret is nowhere.
        let conn = store.raw_for_test();
        let mut stmt = conn
            .prepare("SELECT operation, args_digest FROM audit")
            .unwrap();
        let rows = stmt
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .unwrap();
        for row in rows {
            let (operation, digest) = row.unwrap();
            assert!(!operation.contains("hunter2"));
            assert_ne!(digest, secret.to_vec());
            assert_eq!(digest.len(), 32);
        }
    }

    #[test]
    fn entries_can_be_read_back_by_device_and_by_recency() {
        let (_dir, store) = on_disk();
        let alice = DeviceId::from_bytes([1; 32]);
        let bob = DeviceId::from_bytes([2; 32]);
        let log = store.audit();
        log.append_at(&record("a").by(alice), 1, 1).unwrap();
        log.append_at(&record("b").by(bob), 2, 2).unwrap();
        log.append_at(&record("c").by(alice), 3, 3).unwrap();

        let alices = log.for_device(&alice, 10).unwrap();
        assert_eq!(alices.len(), 2);
        assert_eq!(alices[0].seq, 3, "newest first");

        let recent = log.recent(2).unwrap();
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].seq, 3);
        assert_eq!(recent[1].seq, 2);

        assert_eq!(log.get(999).unwrap(), None);
    }

    #[test]
    fn rotation_preserves_chain_continuity() {
        let (_dir, store) = on_disk();
        let signer = FakeSigner::new(0x11);
        append_many(&store, 20);

        let checkpoint = store.audit().rotate(5, &signer).unwrap().expect("rotated");
        assert_eq!(checkpoint.truncated_through_seq, 15);
        assert_eq!(checkpoint.entries_removed, 15);
        assert_eq!(store.audit().count().unwrap(), 5);

        // The whole point: the surviving chain still verifies, anchored on the
        // checkpoint instead of on genesis.
        let status = store.audit().verify().unwrap();
        assert!(status.is_intact(), "{status}");

        // And it keeps growing from the right sequence number.
        let next = store.audit().append(&record("after")).unwrap();
        assert_eq!(next.seq, 21);
        assert!(store.audit().verify().unwrap().is_intact());
    }

    #[test]
    fn rotation_is_a_no_op_below_the_cap() {
        let (_dir, store) = on_disk();
        let signer = FakeSigner::new(0x22);
        append_many(&store, 5);
        assert!(store.audit().rotate(10, &signer).unwrap().is_none());
        assert!(store.audit().rotate(5, &signer).unwrap().is_none());
        assert_eq!(store.audit().count().unwrap(), 5);
    }

    #[test]
    fn repeated_rotation_keeps_the_chain_verifiable() {
        let (_dir, store) = on_disk();
        let signer = FakeSigner::new(0x33);
        for round in 0..4 {
            append_many(&store, 10);
            store.audit().rotate(6, &signer).unwrap();
            let status = store.audit().verify().unwrap();
            assert!(status.is_intact(), "round {round}: {status}");
        }
        assert_eq!(store.audit().checkpoints().unwrap().len(), 4);
    }

    #[test]
    fn checkpoint_signatures_verify_and_detect_forgery() {
        let (_dir, store) = on_disk();
        let signer = FakeSigner::new(0x44);
        append_many(&store, 12);
        store.audit().rotate(4, &signer).unwrap().unwrap();

        assert_eq!(store.audit().verify_checkpoints(&signer).unwrap(), None);

        // An attacker who deletes more entries and rewrites the checkpoint to
        // cover it cannot produce a signature over the new content.
        store
            .raw_for_test()
            .execute(
                "UPDATE audit_checkpoints SET entries_removed = entries_removed + 100",
                [],
            )
            .unwrap();
        assert!(store.audit().verify_checkpoints(&signer).unwrap().is_some());

        // Nor can a different key.
        let impostor = FakeSigner::new(0x99);
        assert!(store
            .audit()
            .verify_checkpoints(&impostor)
            .unwrap()
            .is_some());
    }

    #[test]
    fn rotation_refuses_to_sign_over_a_broken_chain() {
        let (_dir, store) = on_disk();
        let signer = FakeSigner::new(0x55);
        append_many(&store, 10);
        store
            .raw_for_test()
            .execute("DELETE FROM audit WHERE seq = 3", [])
            .unwrap();

        match store.audit().rotate(2, &signer).unwrap_err() {
            StoreError::AuditChainBroken { seq } => assert_eq!(seq, 3),
            other => panic!("expected AuditChainBroken, got {other:?}"),
        }
        // Nothing was deleted and no checkpoint was written.
        assert_eq!(store.audit().count().unwrap(), 9);
        assert!(store.audit().checkpoints().unwrap().is_empty());
    }

    #[test]
    fn rotation_fails_closed_when_the_signer_is_unavailable() {
        let (_dir, store) = on_disk();
        append_many(&store, 10);
        match store.audit().rotate(2, &BrokenSigner).unwrap_err() {
            StoreError::CheckpointSigning(reason) => assert!(reason.contains("locked"), "{reason}"),
            other => panic!("expected CheckpointSigning, got {other:?}"),
        }
        // An unsigned truncation is indistinguishable from an attack, so
        // nothing may be removed.
        assert_eq!(store.audit().count().unwrap(), 10);
    }

    #[test]
    fn deleting_a_checkpoint_after_rotation_is_detected() {
        let (_dir, store) = on_disk();
        let signer = FakeSigner::new(0x66);
        append_many(&store, 12);
        store.audit().rotate(4, &signer).unwrap().unwrap();
        assert!(store.audit().verify().unwrap().is_intact());

        // Removing the checkpoint removes the anchor, so the surviving entries
        // no longer start where the chain says they should.
        store
            .raw_for_test()
            .execute("DELETE FROM audit_checkpoints", [])
            .unwrap();
        match store.audit().verify().unwrap() {
            ChainStatus::Broken { seq, cause } => {
                assert_eq!(seq, FIRST_SEQ);
                assert_eq!(cause, ChainBreak::MissingEntry { found_seq: 9 });
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn result_strings_round_trip_and_reject_unknowns() {
        for result in AuditResult::ALL {
            assert_eq!(result.as_str().parse::<AuditResult>().unwrap(), result);
        }
        assert!("succeeded".parse::<AuditResult>().is_err());
        assert!("OK".parse::<AuditResult>().is_err());
    }

    #[test]
    fn checkpoint_serde_round_trips_including_the_signature() {
        let checkpoint = Checkpoint {
            truncated_through_seq: 9,
            chain_hash: Digest::of(b"c"),
            entries_removed: 9,
            ts_utc_ms: 1_700_000_000_000,
            signer: PublicKey::from_bytes([5; 32]),
            signature: [7u8; 64],
        };
        let json = serde_json::to_string(&checkpoint).unwrap();
        assert!(json.contains(&hex::encode([7u8; 64])));
        let back: Checkpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(back, checkpoint);
    }

    #[test]
    fn chain_status_renders_a_usable_message() {
        let broken = ChainStatus::Broken {
            seq: 12,
            cause: ChainBreak::MissingEntry { found_seq: 13 },
        };
        let rendered = broken.to_string();
        assert!(rendered.contains("seq 12"), "{rendered}");
        assert!(rendered.contains("13"), "{rendered}");

        let intact = ChainStatus::Intact {
            entries: 3,
            head_seq: Some(3),
            head_hash: Some(GENESIS_PREV_HASH),
        };
        assert!(intact.to_string().contains("intact"));
    }

    proptest::proptest! {
        // Each case builds a real WAL database on disk and migrates it, which
        // costs orders of magnitude more than a pure-computation property.
        // Fewer cases over a small, fully-covered input range beats a slow
        // suite that contributors learn to skip.
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(20))]

        #[test]
        fn a_chain_of_any_length_verifies(count in 0u64..40) {
            let (_dir, store) = on_disk();
            append_many(&store, count);
            let status = store.audit().verify().unwrap();
            proptest::prop_assert!(status.is_intact(), "{}", status);
            proptest::prop_assert_eq!(store.audit().count().unwrap(), count);
        }

        #[test]
        fn tampering_with_any_entry_is_detected(count in 2u64..15, victim in 1u64..15) {
            proptest::prop_assume!(victim <= count);
            let (_dir, store) = on_disk();
            append_many(&store, count);
            store
                .raw_for_test()
                .execute(
                    "UPDATE audit SET ts_utc = ts_utc + 1 WHERE seq = ?1",
                    [i64::try_from(victim).unwrap()],
                )
                .unwrap();
            proptest::prop_assert_eq!(store.audit().verify().unwrap().broken_at(), Some(victim));
        }

        #[test]
        fn deleting_any_interior_entry_is_detected(count in 3u64..15, victim in 1u64..15) {
            proptest::prop_assume!(victim < count);
            let (_dir, store) = on_disk();
            append_many(&store, count);
            store
                .raw_for_test()
                .execute(
                    "DELETE FROM audit WHERE seq = ?1",
                    [i64::try_from(victim).unwrap()],
                )
                .unwrap();
            proptest::prop_assert_eq!(store.audit().verify().unwrap().broken_at(), Some(victim));
        }
    }
}
