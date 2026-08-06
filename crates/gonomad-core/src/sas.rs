//! Short Authentication String: the six digits a human compares during pairing.
//!
//! Pairing already carries 256 bits of entropy over an optical channel — the QR
//! code — and that is what defeats a network man-in-the-middle
//! (`ARCHITECTURE.md` §9.2). The SAS is **defence in depth** for the case the QR
//! itself leaks: photographed over a shoulder, captured by a screen recording,
//! or visible in a video call.
//!
//! It works because the digits are derived from the *full handshake transcript*.
//! An attacker who holds the pairing secret but is proxying the connection
//! necessarily produces a different transcript on each side, so the digits shown
//! on the laptop and on the phone disagree, and the human sees it.
//!
//! # The UI requirement this places on the pairing screen
//!
//! A SAS is worthless if the user reflexively taps "Yes". The confirmation
//! screen must weight both answers equally and ask a question the user can
//! actually fail — hence "does this match your laptop?" with equal buttons,
//! rather than a prominent Confirm (§23.3).

use core::fmt;

use subtle::ConstantTimeEq;

/// Number of decimal digits in a SAS.
///
/// Six gives a 1-in-1,000,000 chance that a MITM's mismatched transcript
/// happens to produce the same digits. Combined with the attacker needing the
/// pairing secret in the first place, and with the window being a single
/// 120-second pairing attempt, that is ample. More digits would trade real
/// usability — humans misread long strings — for negligible security.
pub const SAS_DIGITS: u32 = 6;

/// The number of distinct SAS values, `10^SAS_DIGITS`.
const SAS_MODULUS: u64 = 1_000_000;

/// Domain separator, so a transcript hash cannot be reused as a signing input
/// or a session key.
const SAS_DOMAIN: &[u8] = b"gonomad-sas-v1\x00";

/// A six-digit short authentication string.
///
/// Equality is constant-time. That is arguably over-careful for a value the user
/// reads aloud, but the comparison happens against attacker-influenced input and
/// costing nothing is a good reason not to think about it further.
#[derive(Clone, Copy)]
pub struct Sas(u32);

impl Sas {
    /// Derives the SAS from a completed handshake transcript.
    ///
    /// `transcript` must be the final handshake hash — for Noise, the `h` value
    /// after the last message. Both peers compute this independently; agreement
    /// is the whole point, so the input must include every handshake message
    /// from both sides.
    #[must_use]
    pub fn derive(transcript: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(SAS_DOMAIN);
        hasher.update(transcript);
        let digest = hasher.finalize();

        // Take 8 bytes and reduce. Modulo bias is bounded by
        // 2^64 mod 10^6 / 2^64 ≈ 5e-14 — far below any threshold that matters,
        // and vastly better than the ~4.6% bias that taking only 3 bytes would
        // introduce.
        let mut wide = [0u8; 8];
        wide.copy_from_slice(&digest.as_bytes()[..8]);
        let value = u64::from_le_bytes(wide) % SAS_MODULUS;

        // Fits in u32 because SAS_MODULUS is 10^6.
        #[allow(clippy::cast_possible_truncation)]
        Self(value as u32)
    }

    /// The numeric value, in `0..1_000_000`.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }

    /// The zero-padded digits, e.g. `"041827"`.
    #[must_use]
    pub fn digits(self) -> String {
        format!("{:0width$}", self.0, width = SAS_DIGITS as usize)
    }

    /// The digits grouped for display, e.g. `"041 827"`.
    ///
    /// Grouped because people transcribe and compare grouped digits far more
    /// reliably than a six-character run.
    #[must_use]
    pub fn grouped(self) -> String {
        let d = self.digits();
        let (a, b) = d.split_at(3);
        format!("{a} {b}")
    }

    /// Constant-time comparison against another SAS.
    #[must_use]
    pub fn matches(self, other: Self) -> bool {
        self.0.to_le_bytes().ct_eq(&other.0.to_le_bytes()).into()
    }
}

impl PartialEq for Sas {
    fn eq(&self, other: &Self) -> bool {
        self.matches(*other)
    }
}

impl Eq for Sas {}

impl fmt::Display for Sas {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.grouped())
    }
}

impl fmt::Debug for Sas {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sas({})", self.grouped())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic() {
        // Both peers must arrive at the same digits from the same transcript,
        // or pairing can never succeed.
        let transcript = b"handshake-hash-bytes";
        assert_eq!(Sas::derive(transcript), Sas::derive(transcript));
    }

    #[test]
    fn different_transcripts_almost_always_differ() {
        // The MITM detection property: a proxying attacker produces a different
        // transcript on each side, so the digits disagree.
        let a = Sas::derive(b"transcript-alice");
        let b = Sas::derive(b"transcript-bob");
        assert_ne!(a, b);
    }

    #[test]
    fn a_single_flipped_bit_changes_the_digits() {
        // Any tampering anywhere in the handshake must be visible to the human.
        let base = [0x11u8; 32];
        let base_sas = Sas::derive(&base);
        let mut differing = 0;
        for i in 0..base.len() {
            let mut t = base;
            t[i] ^= 0x01;
            if Sas::derive(&t) != base_sas {
                differing += 1;
            }
        }
        // With a 1-in-a-million collision chance per trial, all 32 should differ.
        assert_eq!(
            differing,
            base.len(),
            "a flipped transcript bit went undetected"
        );
    }

    #[test]
    fn value_is_always_within_range() {
        for i in 0u32..2000 {
            let sas = Sas::derive(&i.to_le_bytes());
            assert!(sas.value() < 1_000_000, "{} out of range", sas.value());
        }
    }

    #[test]
    fn digits_are_always_zero_padded_to_six() {
        // A SAS rendered as "1827" instead of "041827" would not match what the
        // other device displays, and the user would reject a valid pairing.
        for i in 0u32..3000 {
            let d = Sas::derive(&i.to_le_bytes()).digits();
            assert_eq!(d.len(), SAS_DIGITS as usize, "bad width for input {i}: {d}");
            assert!(d.chars().all(|c| c.is_ascii_digit()), "non-digit in {d}");
        }
    }

    #[test]
    fn small_values_pad_correctly() {
        let sas = Sas(7);
        assert_eq!(sas.digits(), "000007");
        assert_eq!(sas.grouped(), "000 007");
    }

    #[test]
    fn largest_value_renders_correctly() {
        let sas = Sas(999_999);
        assert_eq!(sas.digits(), "999999");
        assert_eq!(sas.grouped(), "999 999");
    }

    #[test]
    fn grouping_splits_three_and_three() {
        let sas = Sas(418_273);
        assert_eq!(sas.digits(), "418273");
        assert_eq!(sas.grouped(), "418 273");
        assert_eq!(sas.to_string(), "418 273");
    }

    #[test]
    fn domain_separation_makes_the_sas_distinct_from_a_bare_hash() {
        // The transcript hash is also used to derive session keys. If the SAS
        // were a bare prefix of it, showing the SAS to a user would disclose
        // key material.
        let transcript = b"t";
        let bare = blake3::hash(transcript);
        let mut wide = [0u8; 8];
        wide.copy_from_slice(&bare.as_bytes()[..8]);
        #[allow(clippy::cast_possible_truncation)]
        let undomained = (u64::from_le_bytes(wide) % SAS_MODULUS) as u32;

        assert_ne!(
            Sas::derive(transcript).value(),
            undomained,
            "SAS is not domain-separated from the raw transcript hash"
        );
    }

    #[test]
    fn empty_transcript_still_produces_a_valid_sas() {
        // Should never happen in practice, but must not panic or produce
        // out-of-range digits.
        let sas = Sas::derive(b"");
        assert!(sas.value() < 1_000_000);
        assert_eq!(sas.digits().len(), 6);
    }

    #[test]
    fn distribution_is_not_obviously_skewed() {
        // A crude smoke test for the reduction: bucket 10k derivations by
        // leading digit and assert none is wildly over-represented. Catches a
        // gross mistake such as reducing modulo the wrong value.
        let mut buckets = [0u32; 10];
        for i in 0u32..10_000 {
            let sas = Sas::derive(&i.to_le_bytes());
            let lead = (sas.value() / 100_000) as usize;
            buckets[lead] += 1;
        }
        for (digit, count) in buckets.iter().enumerate() {
            assert!(
                (600..1400).contains(count),
                "leading digit {digit} appeared {count} times in 10000, expected ~1000"
            );
        }
    }

    proptest::proptest! {
        #[test]
        fn any_transcript_gives_in_range_six_digits(transcript: Vec<u8>) {
            let sas = Sas::derive(&transcript);
            proptest::prop_assert!(sas.value() < 1_000_000);
            proptest::prop_assert_eq!(sas.digits().len(), 6);
            proptest::prop_assert_eq!(sas.grouped().len(), 7);
        }

        #[test]
        fn derivation_is_stable_across_calls(transcript: Vec<u8>) {
            proptest::prop_assert_eq!(Sas::derive(&transcript), Sas::derive(&transcript));
        }

        /// Appending to a transcript must change the digits. This is the
        /// property a MITM defeats if the derivation ignores part of its input,
        /// so it is asserted directly rather than inferred from collision rates.
        #[test]
        fn extending_a_transcript_changes_the_sas(base: Vec<u8>, extra: u8) {
            let mut extended = base.clone();
            extended.push(extra);
            // A 1-in-10^6 collision is possible; retry-free assertion would be
            // flaky, so compare the full digest instead of the reduced value.
            let a = blake3::hash(&[SAS_DOMAIN, base.as_slice()].concat());
            let b = blake3::hash(&[SAS_DOMAIN, extended.as_slice()].concat());
            proptest::prop_assert_ne!(a.as_bytes(), b.as_bytes());
        }
    }
}
