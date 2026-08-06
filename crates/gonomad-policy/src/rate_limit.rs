//! Token-bucket rate limiting and hard resource ceilings (`ARCHITECTURE.md` §3.8).
//!
//! The threat model here is unusual and worth stating, because it changes the
//! design: this is **not** about protecting a public service from load. It is
//! about protecting *the developer's laptop* from a buggy or compromised phone.
//! The client is authenticated and paired; the question is only how much damage
//! a misbehaving one can do before the daemon pushes back.
//!
//! Two failure modes are deliberately distinguished, because they need
//! different client behaviour:
//!
//! - [`ErrorKind::RateLimited`] — a *rate* was exceeded. Waiting helps, and the
//!   error carries exactly how long to wait.
//! - [`ErrorKind::ResourceExhausted`] — a *ceiling* was reached. Waiting does
//!   not help; the client must release something (close a PTY, end a search)
//!   or, for pairing, obtain a fresh QR code.
//!
//! Collapsing those two into one error would make the client either spin
//! retrying something that can never succeed, or give up on something that
//! would have succeeded a second later.
//!
//! # Time is injected, and monotonic
//!
//! Nothing in this module reads a clock on its own. A [`Clock`] is supplied by
//! the caller, which makes every test deterministic instead of sleep-based, and
//! makes it structurally impossible to accidentally reach for wall-clock time.
//!
//! Wall-clock time is banned here (`ARCHITECTURE.md` §24.3). A rate limiter
//! driven by `SystemTime` can be reset by an NTP step, a daylight-saving
//! transition, or a user changing the system clock — all of which would let an
//! attacker refill every bucket at will. [`Monotonic`] cannot go backwards.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use gonomad_proto::{DeviceId, ErrorKind, ProtoError};

/// Fixed-point scale for token accounting.
///
/// Tokens are stored as integers scaled by this factor rather than as floats,
/// so that refill arithmetic is exactly reproducible on every platform and
/// cannot drift. One whole token is `TOKEN_SCALE` units.
const TOKEN_SCALE: u64 = 1_000_000;

/// 32 MiB — the per-operation payload ceiling for file reads and writes.
const MAX_FILE_PAYLOAD_BYTES: u64 = 32 * 1024 * 1024;

/// 64 MiB — the total send-buffer ceiling before the daemon applies backpressure.
const MAX_SEND_BUFFER_BYTES: u64 = 64 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Clock
// ---------------------------------------------------------------------------

/// A point on a monotonic timeline, as a duration since an unspecified epoch.
///
/// Deliberately *not* `std::time::Instant`: `Instant` cannot be constructed at
/// an arbitrary value, which forces tests to sleep. It is also deliberately not
/// `SystemTime`, because security decisions must never depend on a clock a user
/// or an attacker can move backwards (§24.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Monotonic(Duration);

impl Monotonic {
    /// The epoch of the timeline. Only meaningful relative to other values.
    pub const ZERO: Self = Self(Duration::ZERO);

    /// Constructs a point `nanos` nanoseconds after the epoch.
    #[must_use]
    pub const fn from_nanos(nanos: u64) -> Self {
        Self(Duration::from_nanos(nanos))
    }

    /// Constructs a point `millis` milliseconds after the epoch.
    #[must_use]
    pub const fn from_millis(millis: u64) -> Self {
        Self(Duration::from_millis(millis))
    }

    /// The elapsed time since `earlier`.
    ///
    /// Saturates at zero rather than panicking. A monotonic clock should never
    /// go backwards, but a saturating subtraction means that if one ever does —
    /// a platform bug, a suspend/resume edge case — the limiter becomes
    /// momentarily *stricter*, never more permissive.
    #[must_use]
    pub fn saturating_since(self, earlier: Self) -> Duration {
        self.0.saturating_sub(earlier.0)
    }

    /// The point `delta` after this one.
    #[must_use]
    pub fn saturating_add(self, delta: Duration) -> Self {
        Self(self.0.saturating_add(delta))
    }
}

/// A source of monotonic time.
///
/// Injected rather than called directly so that tests can advance time by an
/// exact amount. Implementations must never return a value earlier than one
/// they previously returned.
pub trait Clock {
    /// The current point on the monotonic timeline.
    fn now(&self) -> Monotonic;
}

/// The production clock, backed by [`std::time::Instant`].
///
/// This is the *only* place in the crate that reads a real clock, and it reads
/// a monotonic one.
#[derive(Debug, Clone, Copy)]
pub struct SystemClock {
    epoch: Instant,
}

impl SystemClock {
    /// Creates a clock whose epoch is now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            epoch: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Monotonic {
        Monotonic(self.epoch.elapsed())
    }
}

/// A clock that only moves when told to.
///
/// Exported rather than kept behind `#[cfg(test)]` because the crates that
/// embed the limiter — the router, the PTY supervisor — need it to test their
/// own back-off behaviour deterministically.
#[derive(Debug, Default)]
pub struct ManualClock {
    nanos: AtomicU64,
}

impl ManualClock {
    /// Creates a clock sitting at the epoch.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            nanos: AtomicU64::new(0),
        }
    }

    /// Moves the clock forward. Saturates rather than wrapping.
    pub fn advance(&self, delta: Duration) {
        let add = u64::try_from(delta.as_nanos()).unwrap_or(u64::MAX);
        // `fetch_update` with a saturating add: wrapping would move the clock
        // backwards, which every consumer is entitled to assume cannot happen.
        let _ = self
            .nanos
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |cur| {
                Some(cur.saturating_add(add))
            });
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Monotonic {
        Monotonic::from_nanos(self.nanos.load(Ordering::SeqCst))
    }
}

impl<T: Clock + ?Sized> Clock for &T {
    fn now(&self) -> Monotonic {
        (**self).now()
    }
}

impl<T: Clock + ?Sized> Clock for std::sync::Arc<T> {
    fn now(&self) -> Monotonic {
        (**self).now()
    }
}

// ---------------------------------------------------------------------------
// Classes and limits
// ---------------------------------------------------------------------------

/// Whether a limit is counted per device or across the whole daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LimitScope {
    /// Counted separately for each paired device.
    PerDevice,
    /// Counted once for the daemon, regardless of which device asked.
    ///
    /// Pairing mode is the motivating case: "one concurrent pairing mode" is a
    /// property of the laptop, not of a device — and the device asking is by
    /// definition not yet paired.
    Global,
}

/// A refill rate: `tokens` tokens become available every `per`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refill {
    /// How many whole tokens are restored per period.
    pub tokens: u32,
    /// The period over which `tokens` are restored.
    pub per: Duration,
}

/// The complete limit configuration for one operation class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassLimits {
    /// Bucket capacity, i.e. the largest instantaneous burst permitted.
    pub burst: u32,
    /// How the bucket refills. `None` means the class is not rate limited —
    /// either it has no rate in the specification, or (as for pairing) the
    /// budget is one-shot and refilling would defeat the point.
    pub refill: Option<Refill>,
    /// How many of these may be in flight at once.
    pub max_concurrent: Option<u32>,
    /// The largest payload a single operation of this class may carry.
    pub max_bytes_per_op: Option<u64>,
    /// The largest total number of bytes of this class that may be outstanding.
    pub max_bytes_in_flight: Option<u64>,
    /// The largest number of result items a single operation may produce.
    pub max_items: Option<u32>,
    /// The wall-budget after which an operation of this class is abandoned.
    ///
    /// Enforced by the executing actor, not here; carried alongside the other
    /// limits so that every ceiling from §3.8 has exactly one home.
    pub deadline: Option<Duration>,
}

impl ClassLimits {
    /// A class with no limits at all, used as a base for the const table below.
    const NONE: Self = Self {
        burst: 0,
        refill: None,
        max_concurrent: None,
        max_bytes_per_op: None,
        max_bytes_in_flight: None,
        max_items: None,
        deadline: None,
    };
}

/// A class of operation with its own rate budget.
///
/// Classes are coarse on purpose. Per-method buckets would give an attacker a
/// separate budget for every method name, so `fs.read`, `fs.stat`, and
/// `fs.list` share one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OperationClass {
    /// An attempt to complete pairing against the currently displayed QR code.
    Pairing,
    /// A Noise handshake from an already-paired key.
    Handshake,
    /// Reading file content, metadata, or directory entries.
    FsRead,
    /// Creating, modifying, moving, or deleting files.
    FsWrite,
    /// Content and filename search across a workspace.
    Search,
    /// Opening a pseudo-terminal.
    PtySpawn,
    /// Registering a filesystem watcher.
    Watcher,
    /// Starting an AI agent session.
    AgentSpawn,
    /// Response frames buffered for transmission.
    SendBuffer,
    /// Everything else: git queries, policy reads, session control.
    ///
    /// Not in the §3.8 table. It exists so that a method added later is
    /// rate limited by default rather than unlimited by default — the same
    /// fail-closed reflex the rest of this crate is built on. The budget is
    /// deliberately generous, because it is a safety net rather than a
    /// considered per-class limit; a new class that needs a real budget should
    /// be given its own variant here.
    Control,
}

impl OperationClass {
    /// Every class, in declaration order.
    pub const ALL: [Self; 10] = [
        Self::Pairing,
        Self::Handshake,
        Self::FsRead,
        Self::FsWrite,
        Self::Search,
        Self::PtySpawn,
        Self::Watcher,
        Self::AgentSpawn,
        Self::SendBuffer,
        Self::Control,
    ];

    /// The stable identifier used in logs, metrics, and audit entries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pairing => "pairing",
            Self::Handshake => "handshake",
            Self::FsRead => "fs.read",
            Self::FsWrite => "fs.write",
            Self::Search => "search",
            Self::PtySpawn => "pty.spawn",
            Self::Watcher => "watcher",
            Self::AgentSpawn => "agent.spawn",
            Self::SendBuffer => "send_buffer",
            Self::Control => "control",
        }
    }

    /// The noun used in [`ErrorKind::ResourceExhausted`], phrased for the
    /// message the user actually sees ("Reached the limit of 16 ptys").
    #[must_use]
    pub const fn resource_name(self) -> &'static str {
        match self {
            Self::Pairing => "pairing attempts",
            Self::Handshake => "handshakes",
            Self::FsRead => "reads",
            Self::FsWrite => "writes",
            Self::Search => "searches",
            Self::PtySpawn => "ptys",
            Self::Watcher => "watchers",
            Self::AgentSpawn => "agent sessions",
            Self::SendBuffer => "buffered bytes",
            Self::Control => "requests",
        }
    }

    /// Whether this class is budgeted per device or daemon-wide.
    #[must_use]
    pub const fn scope(self) -> LimitScope {
        match self {
            // Pairing mode is a state of the laptop, and the peer is not yet a
            // known device, so there is nothing to key a per-device budget on.
            // The send buffer is one shared allocation.
            Self::Pairing | Self::SendBuffer => LimitScope::Global,
            _ => LimitScope::PerDevice,
        }
    }

    /// The limits for this class, straight from `ARCHITECTURE.md` §3.8.
    #[must_use]
    pub const fn limits(self) -> ClassLimits {
        match self {
            // "3 per QR, then invalidate": a one-shot budget with no refill, so
            // exhaustion is reported as ResourceExhausted rather than
            // RateLimited — waiting genuinely does not help, the user must
            // generate a new code. `reset` is called when one is generated.
            Self::Pairing => ClassLimits {
                burst: 3,
                refill: None,
                max_concurrent: Some(1),
                ..ClassLimits::NONE
            },
            // "10/min, exponential backoff". The exponential component lives in
            // the transport layer, which is what owns the connection being
            // backed off; the sustained rate lives here.
            Self::Handshake => ClassLimits {
                burst: 10,
                refill: Some(Refill {
                    tokens: 10,
                    per: Duration::from_secs(60),
                }),
                ..ClassLimits::NONE
            },
            Self::FsRead => ClassLimits {
                burst: 100,
                refill: Some(Refill {
                    tokens: 100,
                    per: Duration::from_secs(1),
                }),
                max_bytes_per_op: Some(MAX_FILE_PAYLOAD_BYTES),
                ..ClassLimits::NONE
            },
            Self::FsWrite => ClassLimits {
                burst: 20,
                refill: Some(Refill {
                    tokens: 20,
                    per: Duration::from_secs(1),
                }),
                max_bytes_per_op: Some(MAX_FILE_PAYLOAD_BYTES),
                ..ClassLimits::NONE
            },
            Self::Search => ClassLimits {
                burst: 2,
                refill: Some(Refill {
                    tokens: 2,
                    per: Duration::from_secs(1),
                }),
                max_concurrent: Some(4),
                max_items: Some(10_000),
                deadline: Some(Duration::from_secs(30)),
                ..ClassLimits::NONE
            },
            Self::PtySpawn => ClassLimits {
                burst: 1,
                refill: Some(Refill {
                    tokens: 1,
                    per: Duration::from_secs(1),
                }),
                max_concurrent: Some(16),
                ..ClassLimits::NONE
            },
            // No rate in the table — only a ceiling. A watcher is cheap to
            // create and expensive to hold, so the cap is what matters.
            Self::Watcher => ClassLimits {
                max_concurrent: Some(8),
                ..ClassLimits::NONE
            },
            Self::AgentSpawn => ClassLimits {
                burst: 1,
                refill: Some(Refill {
                    tokens: 1,
                    per: Duration::from_secs(5),
                }),
                max_concurrent: Some(8),
                ..ClassLimits::NONE
            },
            Self::SendBuffer => ClassLimits {
                max_bytes_in_flight: Some(MAX_SEND_BUFFER_BYTES),
                ..ClassLimits::NONE
            },
            Self::Control => ClassLimits {
                burst: 50,
                refill: Some(Refill {
                    tokens: 50,
                    per: Duration::from_secs(1),
                }),
                ..ClassLimits::NONE
            },
        }
    }
}

impl fmt::Display for OperationClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Handles for things that must be given back
// ---------------------------------------------------------------------------

/// A held concurrency slot, returned to the limiter by [`RateLimiter::release`].
///
/// There is no `Drop` implementation, because releasing needs `&mut` access to
/// the limiter and a destructor cannot have it. The type is `#[must_use]` and
/// carries the key it was issued for, so a slot cannot be released against the
/// wrong class — the remaining discipline is that the owning actor releases it
/// in its own teardown path.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a slot that is never released permanently consumes capacity"]
pub struct Slot {
    key: Key,
}

impl Slot {
    /// The class this slot was issued for.
    #[must_use]
    pub const fn class(&self) -> OperationClass {
        self.key.1
    }

    /// Consumes the slot, yielding the bucket it belongs to.
    ///
    /// Takes `self` so that surrendering a slot is a move: after
    /// [`RateLimiter::release`] has called this, the caller no longer holds a
    /// value it could release a second time.
    fn into_key(self) -> Key {
        self.key
    }
}

/// A reservation against a byte ceiling, returned by
/// [`RateLimiter::release_bytes`].
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a reservation that is never released permanently consumes the budget"]
pub struct ByteReservation {
    key: Key,
    bytes: u64,
}

impl ByteReservation {
    /// The number of bytes reserved.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Consumes the reservation, yielding the bucket and the amount to return.
    ///
    /// By value for the same reason as [`Slot::into_key`]: a reservation that
    /// can be released twice inflates the budget permanently.
    fn into_parts(self) -> (Key, u64) {
        (self.key, self.bytes)
    }
}

/// Map key: the device (absent for daemon-wide classes) plus the class.
type Key = (Option<DeviceId>, OperationClass);

#[derive(Debug, Clone, Copy)]
struct Bucket {
    /// Whole tokens scaled by [`TOKEN_SCALE`].
    tokens: u64,
    last_refill: Monotonic,
    in_flight: u32,
    bytes_in_flight: u64,
}

impl Bucket {
    fn new(limits: ClassLimits, now: Monotonic) -> Self {
        Self {
            // Buckets start full: a device that has been idle should not be
            // throttled on its first request after reconnecting.
            tokens: u64::from(limits.burst) * TOKEN_SCALE,
            last_refill: now,
            in_flight: 0,
            bytes_in_flight: 0,
        }
    }

    fn refill(&mut self, now: Monotonic, limits: ClassLimits) {
        let Some(rate) = limits.refill else { return };
        if rate.tokens == 0 {
            return;
        }
        let elapsed = now.saturating_since(self.last_refill).as_nanos();
        let per_nanos = rate.per.as_nanos().max(1);
        let added = elapsed
            .saturating_mul(u128::from(rate.tokens))
            .saturating_mul(u128::from(TOKEN_SCALE))
            / per_nanos;
        if added == 0 {
            // Do not advance `last_refill` here. Integer division truncates, so
            // advancing on a zero-token refill would silently discard the
            // fractional time — and a client polling faster than one token
            // period would then never refill at all.
            return;
        }
        let capacity = u64::from(limits.burst) * TOKEN_SCALE;
        self.tokens = u64::try_from(u128::from(self.tokens).saturating_add(added))
            .unwrap_or(u64::MAX)
            .min(capacity);
        self.last_refill = now;
    }

    fn try_take_token(&mut self) -> bool {
        if self.tokens >= TOKEN_SCALE {
            self.tokens -= TOKEN_SCALE;
            true
        } else {
            false
        }
    }
}

/// How long until one whole token is available again, rounded up, never zero.
fn retry_after_ms(tokens: u64, rate: Refill) -> u32 {
    let deficit = u128::from(TOKEN_SCALE.saturating_sub(tokens));
    let denominator = u128::from(rate.tokens).saturating_mul(u128::from(TOKEN_SCALE));
    if denominator == 0 {
        return u32::MAX;
    }
    let nanos = deficit.saturating_mul(rate.per.as_nanos()) / denominator;
    // Round up, and never report zero: a client told to wait 0 ms retries
    // immediately and is rate limited again, producing a hot loop.
    let ms = nanos.div_ceil(1_000_000).max(1);
    u32::try_from(ms).unwrap_or(u32::MAX)
}

fn exhausted(class: OperationClass, limit: u64) -> ProtoError {
    ProtoError::new(ErrorKind::ResourceExhausted {
        resource: class.resource_name().to_owned(),
        limit: u32::try_from(limit).unwrap_or(u32::MAX),
    })
}

// ---------------------------------------------------------------------------
// The limiter
// ---------------------------------------------------------------------------

/// Per-device, per-class token buckets and resource ceilings.
///
/// Takes `&mut self` throughout rather than using interior mutability. The
/// daemon is an actor system (`ARCHITECTURE.md` §2), the limiter lives inside
/// the router actor, and there are no `Mutex`-guarded structures on any hot
/// path — so exclusive access is free and a lock would be a regression.
#[derive(Debug)]
pub struct RateLimiter<C: Clock> {
    clock: C,
    buckets: HashMap<Key, Bucket>,
}

impl<C: Clock> RateLimiter<C> {
    /// Creates a limiter driven by `clock`.
    pub fn new(clock: C) -> Self {
        Self {
            clock,
            buckets: HashMap::new(),
        }
    }

    /// The clock this limiter reads.
    pub const fn clock(&self) -> &C {
        &self.clock
    }

    /// The number of tracked buckets. Exposed for tests and for a memory metric.
    #[must_use]
    pub fn tracked_buckets(&self) -> usize {
        self.buckets.len()
    }

    fn key(device: DeviceId, class: OperationClass) -> Key {
        match class.scope() {
            LimitScope::PerDevice => (Some(device), class),
            LimitScope::Global => (None, class),
        }
    }

    fn bucket(&mut self, key: Key, now: Monotonic) -> &mut Bucket {
        let limits = key.1.limits();
        self.buckets
            .entry(key)
            .or_insert_with(|| Bucket::new(limits, now))
    }

    /// Charges one token for an operation in `class`.
    ///
    /// This is the check for operations that complete immediately and hold
    /// nothing: a file read, a git status. Operations that occupy a slot for a
    /// while use [`RateLimiter::try_acquire_slot`] instead.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::RateLimited`] with the exact wait when the bucket is empty
    /// and will refill; [`ErrorKind::ResourceExhausted`] when the budget is
    /// one-shot (pairing) and waiting cannot help.
    pub fn try_acquire(
        &mut self,
        device: DeviceId,
        class: OperationClass,
    ) -> Result<(), ProtoError> {
        let limits = class.limits();
        if limits.refill.is_none() && limits.burst == 0 {
            // No rate configured for this class — only ceilings apply.
            return Ok(());
        }
        let now = self.clock.now();
        let key = Self::key(device, class);
        let bucket = self.bucket(key, now);
        bucket.refill(now, limits);
        if bucket.try_take_token() {
            return Ok(());
        }
        Err(match limits.refill {
            Some(rate) => ProtoError::rate_limited(retry_after_ms(bucket.tokens, rate)),
            // A bucket that never refills is a ceiling wearing a rate's
            // clothing: report it as one, so the client stops retrying.
            None => exhausted(class, u64::from(limits.burst)),
        })
    }

    /// Charges a token *and* takes a concurrency slot.
    ///
    /// The concurrency ceiling is checked before the token is spent, so a
    /// client that is at its PTY limit is not also charged for the attempt.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::ResourceExhausted`] when the class is at its concurrency
    /// ceiling, otherwise as [`RateLimiter::try_acquire`].
    pub fn try_acquire_slot(
        &mut self,
        device: DeviceId,
        class: OperationClass,
    ) -> Result<Slot, ProtoError> {
        let limits = class.limits();
        let now = self.clock.now();
        let key = Self::key(device, class);

        if let Some(max) = limits.max_concurrent {
            let bucket = self.bucket(key, now);
            if bucket.in_flight >= max {
                return Err(exhausted(class, u64::from(max)));
            }
        }

        self.try_acquire(device, class)?;
        self.bucket(key, now).in_flight += 1;
        Ok(Slot { key })
    }

    /// Returns a slot to its class.
    ///
    /// Consumes the slot, so releasing the same one twice — which would inflate
    /// the ceiling by one for the life of the daemon — is a compile error.
    pub fn release(&mut self, slot: Slot) {
        let key = slot.into_key();
        if let Some(bucket) = self.buckets.get_mut(&key) {
            bucket.in_flight = bucket.in_flight.saturating_sub(1);
        }
    }

    /// How many operations of `class` this device currently holds.
    #[must_use]
    pub fn in_flight(&self, device: DeviceId, class: OperationClass) -> u32 {
        self.buckets
            .get(&Self::key(device, class))
            .map_or(0, |b| b.in_flight)
    }

    /// Checks a single operation's payload against its per-operation ceiling.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::ResourceExhausted`] when `bytes` exceeds the ceiling.
    /// A larger transfer is not a rate problem and never becomes possible by
    /// waiting, so it is never reported as [`ErrorKind::RateLimited`].
    pub fn check_payload_size(&self, class: OperationClass, bytes: u64) -> Result<(), ProtoError> {
        match class.limits().max_bytes_per_op {
            Some(max) if bytes > max => Err(exhausted(class, max)),
            _ => Ok(()),
        }
    }

    /// The largest number of result items an operation of `class` may return.
    #[must_use]
    pub fn max_items(class: OperationClass) -> Option<u32> {
        class.limits().max_items
    }

    /// The deadline after which an operation of `class` must be abandoned.
    #[must_use]
    pub fn deadline(class: OperationClass) -> Option<Duration> {
        class.limits().deadline
    }

    /// Reserves `bytes` against a class's in-flight byte ceiling.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::ResourceExhausted`] when the reservation would exceed the
    /// ceiling. The caller applies backpressure; it must not drop the work
    /// (§3.8: "Neither ever silently drops work").
    pub fn reserve_bytes(
        &mut self,
        device: DeviceId,
        class: OperationClass,
        bytes: u64,
    ) -> Result<ByteReservation, ProtoError> {
        let Some(max) = class.limits().max_bytes_in_flight else {
            return Ok(ByteReservation {
                key: Self::key(device, class),
                bytes: 0,
            });
        };
        let now = self.clock.now();
        let key = Self::key(device, class);
        let bucket = self.bucket(key, now);
        let after = bucket.bytes_in_flight.saturating_add(bytes);
        if after > max {
            return Err(exhausted(class, max));
        }
        bucket.bytes_in_flight = after;
        Ok(ByteReservation { key, bytes })
    }

    /// Returns a byte reservation to its class.
    ///
    /// Consumes the reservation, for the same reason as
    /// [`RateLimiter::release`]: a double release permanently inflates the
    /// budget.
    pub fn release_bytes(&mut self, reservation: ByteReservation) {
        let (key, bytes) = reservation.into_parts();
        if let Some(bucket) = self.buckets.get_mut(&key) {
            bucket.bytes_in_flight = bucket.bytes_in_flight.saturating_sub(bytes);
        }
    }

    /// Bytes currently reserved for `class`.
    #[must_use]
    pub fn bytes_in_flight(&self, device: DeviceId, class: OperationClass) -> u64 {
        self.buckets
            .get(&Self::key(device, class))
            .map_or(0, |b| b.bytes_in_flight)
    }

    /// Refills one bucket to full, preserving anything currently held.
    ///
    /// The one legitimate caller is pairing: a freshly generated QR code is a
    /// new secret, so it gets a new three-attempt budget. Nothing else should
    /// call this — a device must not be able to reset its own limits.
    pub fn reset(&mut self, device: DeviceId, class: OperationClass) {
        let now = self.clock.now();
        let limits = class.limits();
        let key = Self::key(device, class);
        let bucket = self.bucket(key, now);
        bucket.tokens = u64::from(limits.burst) * TOKEN_SCALE;
        bucket.last_refill = now;
    }

    /// Drops every bucket belonging to a device.
    ///
    /// Called on unpair and on revocation, so that a revoked device leaves no
    /// state behind, and so the map cannot grow without bound across a long
    /// daemon lifetime. Global buckets are untouched.
    pub fn forget_device(&mut self, device: DeviceId) {
        self.buckets
            .retain(|(owner, _), _| owner.as_ref() != Some(&device));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(byte: u8) -> DeviceId {
        DeviceId::from_bytes([byte; 32])
    }

    fn limiter() -> RateLimiter<ManualClock> {
        RateLimiter::new(ManualClock::new())
    }

    #[test]
    fn class_identifiers_are_unique() {
        let mut names: Vec<&str> = OperationClass::ALL.iter().map(|c| c.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), OperationClass::ALL.len());
    }

    #[test]
    fn fs_read_allows_a_full_burst_then_refuses() {
        let mut rl = limiter();
        let d = device(1);
        for i in 0..100 {
            assert!(
                rl.try_acquire(d, OperationClass::FsRead).is_ok(),
                "read {i}"
            );
        }
        let err = rl.try_acquire(d, OperationClass::FsRead).unwrap_err();
        assert_eq!(err.kind.code(), "rate_limited");
    }

    #[test]
    fn rate_limit_recovers_over_injected_time() {
        let mut rl = limiter();
        let d = device(1);
        for _ in 0..100 {
            rl.try_acquire(d, OperationClass::FsRead).unwrap();
        }
        assert!(rl.try_acquire(d, OperationClass::FsRead).is_err());

        // 100/s: 10 ms buys exactly one token.
        rl.clock().advance(Duration::from_millis(10));
        assert!(rl.try_acquire(d, OperationClass::FsRead).is_ok());
        assert!(rl.try_acquire(d, OperationClass::FsRead).is_err());

        // A full second refills the whole bucket, and no more than the bucket.
        rl.clock().advance(Duration::from_secs(10));
        for _ in 0..100 {
            rl.try_acquire(d, OperationClass::FsRead).unwrap();
        }
        assert!(rl.try_acquire(d, OperationClass::FsRead).is_err());
    }

    #[test]
    fn retry_after_is_accurate_and_never_zero() {
        let mut rl = limiter();
        let d = device(1);
        // agent.spawn is 1 per 5 s, so the second attempt must be told to wait
        // very nearly the full five seconds.
        rl.try_acquire(d, OperationClass::AgentSpawn).unwrap();
        let err = rl.try_acquire(d, OperationClass::AgentSpawn).unwrap_err();
        match err.kind {
            ErrorKind::RateLimited { retry_after_ms } => {
                assert_eq!(retry_after_ms, 5_000);
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }

        rl.clock().advance(Duration::from_millis(4_999));
        let err = rl.try_acquire(d, OperationClass::AgentSpawn).unwrap_err();
        match err.kind {
            ErrorKind::RateLimited { retry_after_ms } => assert_eq!(retry_after_ms, 1),
            other => panic!("expected RateLimited, got {other:?}"),
        }

        rl.clock().advance(Duration::from_millis(1));
        assert!(rl.try_acquire(d, OperationClass::AgentSpawn).is_ok());
    }

    #[test]
    fn a_polling_client_still_refills() {
        // Regression guard: an earlier design advanced `last_refill` even when
        // the computed refill truncated to zero tokens, so a client polling
        // every millisecond against a 1-per-5s bucket would never refill.
        let mut rl = limiter();
        let d = device(1);
        rl.try_acquire(d, OperationClass::AgentSpawn).unwrap();
        for _ in 0..5_000 {
            rl.clock().advance(Duration::from_millis(1));
            let _ = rl.try_acquire(d, OperationClass::AgentSpawn);
        }
        rl.clock().advance(Duration::from_secs(5));
        assert!(rl.try_acquire(d, OperationClass::AgentSpawn).is_ok());
    }

    #[test]
    fn budgets_are_per_device() {
        let mut rl = limiter();
        for _ in 0..20 {
            rl.try_acquire(device(1), OperationClass::FsWrite).unwrap();
        }
        assert!(rl.try_acquire(device(1), OperationClass::FsWrite).is_err());
        // A second phone must not be punished for the first one's behaviour.
        assert!(rl.try_acquire(device(2), OperationClass::FsWrite).is_ok());
    }

    #[test]
    fn pairing_budget_is_global_not_per_device() {
        // Pairing happens before a device is known, so three attempts is three
        // attempts total — an attacker cannot claim a fresh budget by
        // presenting a different key.
        let mut rl = limiter();
        assert!(rl.try_acquire(device(1), OperationClass::Pairing).is_ok());
        assert!(rl.try_acquire(device(2), OperationClass::Pairing).is_ok());
        assert!(rl.try_acquire(device(3), OperationClass::Pairing).is_ok());
        assert!(rl.try_acquire(device(4), OperationClass::Pairing).is_err());
    }

    #[test]
    fn pairing_exhaustion_is_not_retryable_by_waiting() {
        let mut rl = limiter();
        let d = device(1);
        for _ in 0..3 {
            rl.try_acquire(d, OperationClass::Pairing).unwrap();
        }
        let err = rl.try_acquire(d, OperationClass::Pairing).unwrap_err();
        match err.kind {
            ErrorKind::ResourceExhausted {
                ref resource,
                limit,
            } => {
                assert_eq!(resource, "pairing attempts");
                assert_eq!(limit, 3);
            }
            other => panic!("expected ResourceExhausted, got {other:?}"),
        }

        // A century of waiting changes nothing.
        rl.clock()
            .advance(Duration::from_secs(3_600 * 24 * 365 * 100));
        assert!(rl.try_acquire(d, OperationClass::Pairing).is_err());

        // Only a fresh QR code does.
        rl.reset(d, OperationClass::Pairing);
        assert!(rl.try_acquire(d, OperationClass::Pairing).is_ok());
    }

    #[test]
    fn pty_concurrency_cap_exhausts_and_recovers_on_release() {
        let mut rl = limiter();
        let d = device(1);
        let mut slots = Vec::new();
        for i in 0..16 {
            // 1/s, so time must advance between spawns.
            rl.clock().advance(Duration::from_secs(1));
            slots.push(
                rl.try_acquire_slot(d, OperationClass::PtySpawn)
                    .unwrap_or_else(|e| panic!("pty {i}: {e}")),
            );
        }
        assert_eq!(rl.in_flight(d, OperationClass::PtySpawn), 16);

        rl.clock().advance(Duration::from_secs(1));
        let err = rl
            .try_acquire_slot(d, OperationClass::PtySpawn)
            .unwrap_err();
        match err.kind {
            ErrorKind::ResourceExhausted {
                ref resource,
                limit,
            } => {
                assert_eq!(resource, "ptys");
                assert_eq!(limit, 16);
            }
            other => panic!("expected ResourceExhausted, got {other:?}"),
        }

        rl.release(slots.pop().unwrap());
        assert_eq!(rl.in_flight(d, OperationClass::PtySpawn), 15);
        assert!(rl.try_acquire_slot(d, OperationClass::PtySpawn).is_ok());
    }

    #[test]
    fn a_full_concurrency_cap_does_not_also_burn_a_token() {
        // Otherwise a client at its search ceiling would be charged for every
        // rejected attempt and end up rate limited as well, turning a clear
        // "close a search" into a confusing "wait".
        let mut rl = limiter();
        let d = device(1);
        let mut slots = Vec::new();
        for _ in 0..4 {
            rl.clock().advance(Duration::from_secs(1));
            slots.push(rl.try_acquire_slot(d, OperationClass::Search).unwrap());
        }
        rl.clock().advance(Duration::from_secs(1));
        assert!(rl.try_acquire_slot(d, OperationClass::Search).is_err());
        rl.release(slots.pop().unwrap());
        // The token that the refused attempt would have spent is still there.
        assert!(rl.try_acquire_slot(d, OperationClass::Search).is_ok());
    }

    #[test]
    fn watchers_have_a_cap_but_no_rate() {
        let mut rl = limiter();
        let d = device(1);
        let mut slots = Vec::new();
        for _ in 0..8 {
            slots.push(rl.try_acquire_slot(d, OperationClass::Watcher).unwrap());
        }
        let err = rl.try_acquire_slot(d, OperationClass::Watcher).unwrap_err();
        match err.kind {
            ErrorKind::ResourceExhausted {
                ref resource,
                limit,
            } => {
                assert_eq!(resource, "watchers");
                assert_eq!(limit, 8);
            }
            other => panic!("expected ResourceExhausted, got {other:?}"),
        }
    }

    #[test]
    fn payload_ceiling_is_enforced_at_exactly_32_mib() {
        let rl = limiter();
        let max = 32 * 1024 * 1024;
        assert!(rl.check_payload_size(OperationClass::FsRead, max).is_ok());
        assert!(rl
            .check_payload_size(OperationClass::FsRead, max + 1)
            .is_err());
        assert!(rl
            .check_payload_size(OperationClass::FsWrite, max + 1)
            .is_err());
        // Classes without a payload ceiling accept anything.
        assert!(rl
            .check_payload_size(OperationClass::Watcher, u64::MAX)
            .is_ok());
    }

    #[test]
    fn send_buffer_budget_is_shared_and_released() {
        let mut rl = limiter();
        let mib = 1024 * 1024;
        let a = rl
            .reserve_bytes(device(1), OperationClass::SendBuffer, 60 * mib)
            .unwrap();
        // Global budget: the second device sees the first device's usage.
        let err = rl
            .reserve_bytes(device(2), OperationClass::SendBuffer, 5 * mib)
            .unwrap_err();
        assert_eq!(err.kind.code(), "resource_exhausted");
        rl.release_bytes(a);
        assert_eq!(rl.bytes_in_flight(device(1), OperationClass::SendBuffer), 0);
        assert!(rl
            .reserve_bytes(device(2), OperationClass::SendBuffer, 5 * mib)
            .is_ok());
    }

    #[test]
    fn search_ceilings_match_the_specification() {
        assert_eq!(
            RateLimiter::<ManualClock>::max_items(OperationClass::Search),
            Some(10_000)
        );
        assert_eq!(
            RateLimiter::<ManualClock>::deadline(OperationClass::Search),
            Some(Duration::from_secs(30))
        );
    }

    #[test]
    fn handshake_rate_is_ten_per_minute() {
        let mut rl = limiter();
        let d = device(1);
        for _ in 0..10 {
            rl.try_acquire(d, OperationClass::Handshake).unwrap();
        }
        assert!(rl.try_acquire(d, OperationClass::Handshake).is_err());
        rl.clock().advance(Duration::from_secs(6));
        assert!(rl.try_acquire(d, OperationClass::Handshake).is_ok());
    }

    #[test]
    fn forgetting_a_device_drops_its_state_but_not_global_state() {
        let mut rl = limiter();
        let d = device(1);
        rl.try_acquire(d, OperationClass::FsRead).unwrap();
        rl.try_acquire(d, OperationClass::Pairing).unwrap();
        assert_eq!(rl.tracked_buckets(), 2);
        rl.forget_device(d);
        assert_eq!(rl.tracked_buckets(), 1);
        // The global pairing budget survives: unpairing must not hand an
        // attacker three fresh attempts.
        assert_eq!(rl.bytes_in_flight(d, OperationClass::SendBuffer), 0);
        rl.try_acquire(d, OperationClass::Pairing).unwrap();
        rl.try_acquire(d, OperationClass::Pairing).unwrap();
        assert!(rl.try_acquire(d, OperationClass::Pairing).is_err());
    }

    #[test]
    fn a_clock_that_goes_backwards_makes_the_limiter_stricter_not_looser() {
        // Saturating subtraction means elapsed time reads as zero, so no
        // tokens are granted. The alternative — wrapping — would grant an
        // enormous refill.
        let mut bucket = Bucket::new(OperationClass::FsRead.limits(), Monotonic::from_millis(500));
        bucket.tokens = 0;
        bucket.refill(Monotonic::ZERO, OperationClass::FsRead.limits());
        assert_eq!(bucket.tokens, 0);
    }

    #[test]
    fn manual_clock_saturates_instead_of_wrapping() {
        let clock = ManualClock::new();
        clock.advance(Duration::from_secs(u64::MAX / 2));
        clock.advance(Duration::from_secs(u64::MAX / 2));
        clock.advance(Duration::from_secs(u64::MAX / 2));
        assert_eq!(clock.now(), Monotonic::from_nanos(u64::MAX));
    }

    #[test]
    fn system_clock_is_monotonic() {
        let clock = SystemClock::new();
        let a = clock.now();
        let b = clock.now();
        assert!(b >= a);
    }

    #[test]
    fn slots_remember_their_class() {
        let mut rl = limiter();
        let slot = rl
            .try_acquire_slot(device(1), OperationClass::Watcher)
            .unwrap();
        assert_eq!(slot.class(), OperationClass::Watcher);
        rl.release(slot);
    }

    #[test]
    fn every_class_has_a_budget_or_a_ceiling() {
        // Fail-closed audit: a class with neither is unlimited, which is how a
        // new operation quietly becomes a denial-of-service vector.
        for class in OperationClass::ALL {
            let l = class.limits();
            assert!(
                l.refill.is_some()
                    || l.max_concurrent.is_some()
                    || l.max_bytes_per_op.is_some()
                    || l.max_bytes_in_flight.is_some()
                    || l.burst > 0,
                "{class} has no limit of any kind"
            );
        }
    }
}
