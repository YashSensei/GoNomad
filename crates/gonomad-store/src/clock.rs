//! Time sources.
//!
//! Two clocks, because the audit log needs both and they answer different
//! questions (`ARCHITECTURE.md` §3.9, §24.3):
//!
//! - **Wall clock** — "when did this happen", in a form a human and a phone can
//!   render. Truthful but *movable*: NTP steps it, and so does anyone with
//!   administrator rights.
//! - **Monotonic** — "in what order did this happen, really". Cannot be moved
//!   backwards, which is what makes a backdated audit entry detectable.

use std::sync::OnceLock;
use std::time::Instant;

/// Milliseconds, not seconds: two audit entries in the same second are routine
/// (a burst of denials, a rapid grant change), and a log that cannot order them
/// is a log a reader has to guess about.
pub(crate) fn now_unix_ms() -> i64 {
    let nanos = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
    // Saturating rather than panicking: a wall clock set to year 300,000,000 is
    // a broken machine, not a reason to take the daemon down. The monotonic
    // component below still orders the entries correctly.
    i64::try_from(nanos / 1_000_000).unwrap_or(i64::MAX)
}

/// A nanosecond reading that never goes backwards within a process.
///
/// Anchored to the wall clock once at process start and advanced by a
/// [`Instant`], so the value is comparable to a Unix timestamp *and* immune to
/// the clock being stepped afterwards. Across a daemon restart the anchor is
/// re-read, so the audit log's `monotonic_ns` is additionally clamped against
/// the previous entry when appending (see [`crate::audit`]) — that clamp is
/// what extends the guarantee across restarts.
pub(crate) fn monotonic_now_ns() -> u64 {
    struct Anchor {
        epoch_ns: u64,
        instant: Instant,
    }
    static ANCHOR: OnceLock<Anchor> = OnceLock::new();

    let anchor = ANCHOR.get_or_init(|| Anchor {
        epoch_ns: u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp_nanos())
            .unwrap_or(0),
        instant: Instant::now(),
    });

    let elapsed = u64::try_from(anchor.instant.elapsed().as_nanos()).unwrap_or(u64::MAX);
    anchor.epoch_ns.saturating_add(elapsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wall_clock_is_plausibly_now() {
        // 2020-01-01 in ms. Catches a units mix-up (seconds vs millis vs
        // nanos), which would otherwise only show up as unreadable timestamps
        // in the security screen.
        let ms = now_unix_ms();
        assert!(ms > 1_577_836_800_000, "{ms} is before 2020");
        assert!(ms < 4_102_444_800_000, "{ms} is after 2100");
    }

    #[test]
    fn monotonic_never_goes_backwards() {
        let mut previous = monotonic_now_ns();
        for _ in 0..1000 {
            let next = monotonic_now_ns();
            assert!(next >= previous, "{next} < {previous}");
            previous = next;
        }
    }

    #[test]
    fn monotonic_is_anchored_near_the_wall_clock() {
        // Same order of magnitude as a Unix nanosecond timestamp, so the two
        // columns in the audit table are comparable by eye.
        let mono_ms = monotonic_now_ns() / 1_000_000;
        let wall_ms = u64::try_from(now_unix_ms()).unwrap();
        assert!(mono_ms.abs_diff(wall_ms) < 60_000);
    }
}
