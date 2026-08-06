//! Pairing: the QR ticket, the manual fallback code, and the pairing secret.
//!
//! Pairing is the single moment an unpaired key can be accepted, so it is
//! deliberately narrow: opt-in, time-boxed to 120 seconds, single-use,
//! rate-limited to three attempts, and requiring physical access to the laptop
//! to read the QR (`ARCHITECTURE.md` §9).
//!
//! # Why the QR is the security boundary
//!
//! The QR carries the daemon's *authentic* public key over an optical channel an
//! attacker must be physically present to observe. That is what defeats a
//! network man-in-the-middle, and it is strictly stronger than SSH's
//! trust-on-first-use, which is vulnerable at exactly this moment.
//!
//! The 256-bit [`PairingSecret`] additionally proves to the daemon that whoever
//! is connecting actually saw the screen, rather than merely knowing the
//! daemon's public key (which is not secret).
//!
//! # Two paths, two threat models
//!
//! | Path | Entropy | How the secret is used |
//! |---|---|---|
//! | [`PairingTicket`] (QR) | 256 bits | Directly, as a pre-shared key |
//! | [`ManualCode`] (typed) | 40 bits | **Must** go through a PAKE |
//!
//! The distinction is not decorative. A 40-bit secret is brute-forceable
//! offline, so the manual path must use a password-authenticated key exchange
//! (SPAKE2+ or CPace) where every guess costs one online round against a
//! rate-limited server. Treating a short human-typed code the way we treat the
//! QR secret would be a genuine vulnerability, which is why the two are separate
//! types rather than one type with a length field.

use core::fmt;

use data_encoding::{Encoding, Specification};
use gonomad_proto::PublicKey;
use zeroize::{Zeroize, Zeroizing};

/// Length of a QR pairing secret, in bytes.
pub const PAIRING_SECRET_LEN: usize = 32;

/// Characters in a manual pairing code, excluding the separating dash.
pub const MANUAL_CODE_CHARS: usize = 8;

/// How long a pairing window stays open, in milliseconds.
///
/// Long enough to walk to the phone and scan; short enough that a QR left on a
/// screen after the user walks away is not a standing invitation.
pub const PAIRING_WINDOW_MS: u64 = 120_000;

/// Maximum attempts against one ticket before it is invalidated.
///
/// Three, then the ticket dies and a new `gonomad pair` is required. This is the
/// bound that makes the 40-bit manual code safe: online guessing gets three
/// tries, not billions.
pub const MAX_PAIRING_ATTEMPTS: u32 = 3;

/// URI scheme prefix for the QR payload.
const TICKET_PREFIX: &str = "gonomad1:";

/// Crockford base32: no padding, and no ambiguous `I`, `L`, `O`, or `U`.
///
/// Chosen because a human reads these characters off a laptop screen and types
/// them into a phone. Standard base32 puts `O` next to `0` and `I` next to `1`,
/// which produces support tickets rather than pairings.
fn crockford() -> Encoding {
    let mut spec = Specification::new();
    spec.symbols.push_str("0123456789ABCDEFGHJKMNPQRSTVWXYZ");
    spec.translate.from.push_str("OoIiLlabcdefghjkmnpqrstvwxyz");
    spec.translate.to.push_str("001111ABCDEFGHJKMNPQRSTVWXYZ");
    spec.encoding()
        .expect("Crockford base32 specification is valid")
}

/// Errors from parsing or validating pairing material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PairingError {
    /// The payload did not start with the expected scheme prefix.
    #[error("not a GoNomad pairing ticket")]
    WrongScheme,
    /// The payload was not valid base32.
    #[error("pairing payload is not valid base32")]
    NotBase32,
    /// The payload decoded to an unexpected length.
    #[error("pairing payload has the wrong length")]
    BadLength,
    /// The ticket declared a version this build cannot parse.
    #[error("pairing ticket version {version} is not supported")]
    UnsupportedVersion {
        /// The version the ticket declared.
        version: u8,
    },
    /// The manual code was not the expected number of characters.
    #[error("manual code must be {MANUAL_CODE_CHARS} characters")]
    BadCodeLength,
    /// The pairing window has closed.
    #[error("this pairing code has expired")]
    Expired,
}

/// A 256-bit single-use secret carried in the QR code.
///
/// Wiped on drop. No `Clone`, no `Serialize`, and `Debug` reveals nothing —
/// a pairing secret in a log file is a pairing secret an attacker can use, and
/// the 120-second window is small comfort if the log is read later.
pub struct PairingSecret(Zeroizing<[u8; PAIRING_SECRET_LEN]>);

impl PairingSecret {
    /// Generates a fresh secret from the operating system's CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0u8; PAIRING_SECRET_LEN]);
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, bytes.as_mut());
        Self(bytes)
    }

    /// Wraps existing bytes, for the scanning side.
    #[must_use]
    pub fn from_bytes(bytes: [u8; PAIRING_SECRET_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Borrows the raw bytes, for use as a Noise pre-shared key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; PAIRING_SECRET_LEN] {
        &self.0
    }
}

impl fmt::Debug for PairingSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately opaque: not even a prefix, which would leak entropy.
        f.write_str("PairingSecret(<redacted>)")
    }
}

impl Drop for PairingSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Everything the phone needs to reach and authenticate the daemon.
///
/// Rendered as a QR code on the laptop. Address hints are included so the first
/// connection needs no discovery round trip at all (§4.6) — but they are hints
/// only, and a stale hint costs a fallback, never a failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingTicket {
    /// The daemon's Ed25519 public key. Learning this over the optical channel
    /// is what makes a network man-in-the-middle impossible.
    pub daemon_key: PublicKey,
    /// Direct socket addresses to try first, e.g. `192.168.1.4:41234`.
    pub addr_hints: Vec<String>,
    /// The daemon's home relay URL, for the CGNAT case.
    pub relay_hint: Option<String>,
}

/// Ticket format version, so a future layout change is detectable.
const TICKET_VERSION: u8 = 1;

/// Fixed-size portion of a ticket body: version, key, secret, hint length.
const TICKET_FIXED_LEN: usize = 1 + 32 + PAIRING_SECRET_LEN + 2;

impl PairingTicket {
    /// Encodes the ticket and secret into the string placed in the QR code.
    ///
    /// Layout: `gonomad1:` + Crockford-base32( version ‖ key ‖ secret ‖ hints ).
    /// Base32 rather than base64 because QR codes have a dedicated alphanumeric
    /// mode that covers uppercase base32 and stores it far more densely than
    /// mixed-case binary-safe encodings.
    #[must_use]
    pub fn encode(&self, secret: &PairingSecret) -> String {
        let mut body = Vec::with_capacity(96);
        body.push(TICKET_VERSION);
        body.extend_from_slice(self.daemon_key.as_bytes());
        body.extend_from_slice(secret.as_bytes());

        // Hints are length-prefixed UTF-8. A single joined string with a
        // separator would break on any address containing that separator.
        let joined = self.hint_blob();
        let len = u16::try_from(joined.len()).unwrap_or(u16::MAX);
        body.extend_from_slice(&len.to_be_bytes());
        body.extend_from_slice(&joined.as_bytes()[..len as usize]);

        format!("{TICKET_PREFIX}{}", crockford().encode(&body))
    }

    /// Serialises the address and relay hints into one newline-separated blob.
    fn hint_blob(&self) -> String {
        let mut parts: Vec<String> = self.addr_hints.iter().map(|a| format!("a{a}")).collect();
        if let Some(relay) = &self.relay_hint {
            parts.push(format!("r{relay}"));
        }
        parts.join("\n")
    }

    /// Decodes a scanned QR payload.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::WrongScheme`] if the prefix is absent — which is
    /// what happens when the user scans some other QR code, so the message must
    /// be a clear "that is not a GoNomad code" rather than a parse failure.
    /// Also returns [`PairingError::NotBase32`], [`PairingError::BadLength`], or
    /// [`PairingError::UnsupportedVersion`] as appropriate.
    pub fn decode(payload: &str) -> Result<(Self, PairingSecret), PairingError> {
        let encoded = payload
            .strip_prefix(TICKET_PREFIX)
            .ok_or(PairingError::WrongScheme)?;

        let body = crockford()
            .decode(encoded.as_bytes())
            .map_err(|_| PairingError::NotBase32)?;

        if body.len() < TICKET_FIXED_LEN {
            return Err(PairingError::BadLength);
        }

        let version = body[0];
        if version != TICKET_VERSION {
            return Err(PairingError::UnsupportedVersion { version });
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&body[1..33]);

        let mut secret = [0u8; PAIRING_SECRET_LEN];
        secret.copy_from_slice(&body[33..33 + PAIRING_SECRET_LEN]);

        let hint_len =
            u16::from_be_bytes([body[TICKET_FIXED_LEN - 2], body[TICKET_FIXED_LEN - 1]]) as usize;
        if body.len() != TICKET_FIXED_LEN + hint_len {
            return Err(PairingError::BadLength);
        }
        let hint_str = core::str::from_utf8(&body[TICKET_FIXED_LEN..TICKET_FIXED_LEN + hint_len])
            .map_err(|_| PairingError::BadLength)?;

        let mut addr_hints = Vec::new();
        let mut relay_hint = None;
        for part in hint_str.split('\n').filter(|s| !s.is_empty()) {
            match part.as_bytes()[0] {
                b'a' => addr_hints.push(part[1..].to_owned()),
                b'r' => relay_hint = Some(part[1..].to_owned()),
                // Unknown hint kinds are skipped rather than rejected: a newer
                // daemon adding a hint type must not break an older phone,
                // since hints are advisory and the connection can still succeed.
                _ => {}
            }
        }

        let secret = PairingSecret::from_bytes(secret);
        // Wipe the stack copy now that ownership has moved into the zeroizing type.
        let mut scratch = key;
        scratch.zeroize();

        Ok((
            Self {
                daemon_key: PublicKey::from_bytes(key),
                addr_hints,
                relay_hint,
            },
            secret,
        ))
    }
}

/// The typed fallback when a camera is unavailable, e.g. `K7M2-9QRX`.
///
/// 8 Crockford base32 characters — 40 bits. **This is not enough entropy to use
/// as a pre-shared key**, and the type exists partly to make that impossible to
/// forget: it deliberately exposes no `as_bytes`, only
/// [`ManualCode::pake_password`], whose name states the required treatment.
#[derive(Clone, PartialEq, Eq)]
pub struct ManualCode(String);

impl ManualCode {
    /// Derives the displayable code from a pairing secret.
    ///
    /// Taken from the same secret as the QR so the daemon has one pairing state
    /// to track, not two that could disagree about attempts remaining.
    #[must_use]
    pub fn from_secret(secret: &PairingSecret) -> Self {
        let digest = blake3::hash(secret.as_bytes());
        // 5 bytes -> exactly 8 Crockford characters at 5 bits each.
        let code = crockford().encode(&digest.as_bytes()[..5]);
        Self(code[..MANUAL_CODE_CHARS].to_owned())
    }

    /// Parses user input, tolerating case, dashes, and spaces.
    ///
    /// Humans insert dashes, hold shift, and add trailing spaces. Rejecting any
    /// of that would produce a failure the user cannot see the cause of.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::BadCodeLength`] when the input does not reduce to
    /// exactly [`MANUAL_CODE_CHARS`] characters, or [`PairingError::NotBase32`]
    /// when it contains characters outside the alphabet.
    pub fn parse(input: &str) -> Result<Self, PairingError> {
        let cleaned: String = input
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-' && *c != '_')
            .flat_map(char::to_uppercase)
            .collect();

        if cleaned.len() != MANUAL_CODE_CHARS {
            return Err(PairingError::BadCodeLength);
        }

        // Normalise Crockford's confusable characters (O->0, I/L->1) by making a
        // round trip through the codec, so a user who types "O" for zero pairs
        // successfully instead of being told the code is wrong.
        let bytes = crockford()
            .decode(cleaned.as_bytes())
            .map_err(|_| PairingError::NotBase32)?;
        Ok(Self(
            crockford().encode(&bytes)[..MANUAL_CODE_CHARS].to_owned(),
        ))
    }

    /// The code grouped for display, e.g. `"K7M2-9QRX"`.
    #[must_use]
    pub fn grouped(&self) -> String {
        let (a, b) = self.0.split_at(4);
        format!("{a}-{b}")
    }

    /// The value to feed a PAKE as the low-entropy password.
    ///
    /// Named for the only correct use. This must **never** be used directly as a
    /// key or a pre-shared secret: 40 bits is offline-brute-forceable, and only
    /// a PAKE plus the three-attempt cap makes it safe (§9.3).
    #[must_use]
    pub fn pake_password(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ManualCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.grouped())
    }
}

// Shows the code: unlike a PairingSecret this is displayed on screen to be read
// aloud, and it is useless without a live pairing window and the PAKE.
impl fmt::Debug for ManualCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ManualCode({})", self.grouped())
    }
}

/// Tracks one open pairing window.
///
/// Time is passed in rather than read, so expiry is deterministic in tests and
/// uses the daemon's **monotonic** clock. Wall-clock expiry would be defeatable
/// by changing the system clock, and cross-device wall-clock comparison is
/// unreliable anyway (§24.3).
#[derive(Debug)]
pub struct PairingWindow {
    opened_at_ms: u64,
    attempts: u32,
    consumed: bool,
}

impl PairingWindow {
    /// Opens a window at the given monotonic timestamp.
    #[must_use]
    pub const fn open(now_ms: u64) -> Self {
        Self {
            opened_at_ms: now_ms,
            attempts: 0,
            consumed: false,
        }
    }

    /// Records an attempt and reports whether it may proceed.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::Expired`] once the window has timed out, the
    /// attempt budget is spent, or the ticket has already been used. All three
    /// collapse to one error on purpose: telling a caller *which* limit it hit
    /// would let it distinguish "wrong secret, try again" from "out of attempts"
    /// and tune an attack accordingly.
    pub fn try_attempt(&mut self, now_ms: u64) -> Result<(), PairingError> {
        if self.consumed
            || self.attempts >= MAX_PAIRING_ATTEMPTS
            || now_ms.saturating_sub(self.opened_at_ms) > PAIRING_WINDOW_MS
        {
            return Err(PairingError::Expired);
        }
        self.attempts += 1;
        Ok(())
    }

    /// Marks the ticket used, so it is single-use even inside its time window.
    pub fn consume(&mut self) {
        self.consumed = true;
    }

    /// Whether this window can still accept an attempt.
    #[must_use]
    pub const fn is_open(&self, now_ms: u64) -> bool {
        !self.consumed
            && self.attempts < MAX_PAIRING_ATTEMPTS
            && now_ms.saturating_sub(self.opened_at_ms) <= PAIRING_WINDOW_MS
    }

    /// Attempts remaining before the ticket is invalidated.
    #[must_use]
    pub const fn attempts_remaining(&self) -> u32 {
        MAX_PAIRING_ATTEMPTS.saturating_sub(self.attempts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ticket() -> PairingTicket {
        PairingTicket {
            daemon_key: PublicKey::from_bytes([0xAB; 32]),
            addr_hints: vec!["192.168.1.4:41234".into(), "[2001:db8::1]:41234".into()],
            relay_hint: Some("https://relay.example.com".into()),
        }
    }

    #[test]
    fn ticket_round_trips() {
        let t = ticket();
        let secret = PairingSecret::generate();
        let expected_secret = *secret.as_bytes();

        let encoded = t.encode(&secret);
        let (decoded, decoded_secret) = PairingTicket::decode(&encoded).unwrap();

        assert_eq!(decoded, t);
        assert_eq!(decoded_secret.as_bytes(), &expected_secret);
    }

    #[test]
    fn ticket_without_hints_round_trips() {
        let t = PairingTicket {
            daemon_key: PublicKey::from_bytes([1u8; 32]),
            addr_hints: vec![],
            relay_hint: None,
        };
        let secret = PairingSecret::generate();
        let (decoded, _) = PairingTicket::decode(&t.encode(&secret)).unwrap();
        assert_eq!(decoded, t);
    }

    #[test]
    fn encoded_ticket_is_uppercase_base32_for_qr_alphanumeric_mode() {
        // QR's alphanumeric mode stores uppercase alphanumerics far more densely
        // than binary mode. A lowercase or mixed-case payload silently costs
        // capacity and makes the code harder to scan.
        let encoded = ticket().encode(&PairingSecret::generate());
        let body = encoded.strip_prefix(TICKET_PREFIX).unwrap();
        assert!(
            body.chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()),
            "payload is not uppercase base32: {body}"
        );
    }

    /// Extracts just the error from a decode attempt.
    ///
    /// `PairingSecret` deliberately implements neither `PartialEq` nor `Clone`,
    /// so a whole `Result` cannot be compared. That is the intended design — a
    /// secret should not be casually comparable — and this helper keeps the
    /// tests readable without weakening it.
    fn decode_err(payload: &str) -> PairingError {
        PairingTicket::decode(payload)
            .map(|_| ())
            .expect_err("expected a decode failure")
    }

    #[test]
    fn scanning_some_other_qr_code_gives_a_clear_error() {
        // The most likely real failure: the user scans a Wi-Fi or URL QR code.
        assert_eq!(decode_err("https://example.com"), PairingError::WrongScheme);
        assert_eq!(decode_err(""), PairingError::WrongScheme);
        assert_eq!(
            decode_err("WIFI:S:MyNetwork;T:WPA;P:pass;;"),
            PairingError::WrongScheme
        );
    }

    #[test]
    fn malformed_payloads_are_rejected_not_panicked_on() {
        // Characters outside the alphabet.
        assert_eq!(decode_err("gonomad1:!!!!"), PairingError::NotBase32);

        // A bit-length that base32 cannot represent. Four symbols is 20 bits,
        // which is not a whole number of bytes, so this is rejected as bad
        // base32 before any length check on the decoded body.
        assert_eq!(decode_err("gonomad1:AAAA"), PairingError::NotBase32);

        // Valid base32 that decodes to too few bytes to be a ticket. Eight
        // symbols is exactly 5 bytes, far short of TICKET_FIXED_LEN.
        assert_eq!(decode_err("gonomad1:"), PairingError::BadLength);
        assert_eq!(decode_err("gonomad1:AAAAAAAA"), PairingError::BadLength);
    }

    #[test]
    fn a_future_ticket_version_is_reported_as_such() {
        // So the phone can say "update your app" rather than "invalid code".
        let mut body = vec![99u8];
        body.extend_from_slice(&[0u8; 32]);
        body.extend_from_slice(&[0u8; PAIRING_SECRET_LEN]);
        body.extend_from_slice(&0u16.to_be_bytes());
        let payload = format!("{TICKET_PREFIX}{}", crockford().encode(&body));
        assert_eq!(
            decode_err(&payload),
            PairingError::UnsupportedVersion { version: 99 }
        );
    }

    #[test]
    fn truncating_the_payload_is_always_rejected() {
        let encoded = ticket().encode(&PairingSecret::generate());
        let body = encoded.strip_prefix(TICKET_PREFIX).unwrap();
        for cut in 1..body.len() {
            let candidate = format!("{TICKET_PREFIX}{}", &body[..cut]);
            assert!(
                PairingTicket::decode(&candidate).is_err(),
                "truncation to {cut} chars was accepted"
            );
        }
    }

    #[test]
    fn unknown_hint_kinds_are_skipped_for_forward_compatibility() {
        // A newer daemon adding a hint type must not break an older phone.
        let mut body = vec![TICKET_VERSION];
        body.extend_from_slice(&[7u8; 32]);
        body.extend_from_slice(&[8u8; PAIRING_SECRET_LEN]);
        let hints = "a1.2.3.4:1\nzsomething-new\nrhttps://r";
        body.extend_from_slice(&u16::try_from(hints.len()).unwrap().to_be_bytes());
        body.extend_from_slice(hints.as_bytes());

        let payload = format!("{TICKET_PREFIX}{}", crockford().encode(&body));
        let (t, _) = PairingTicket::decode(&payload).unwrap();
        assert_eq!(t.addr_hints, vec!["1.2.3.4:1"]);
        assert_eq!(t.relay_hint.as_deref(), Some("https://r"));
    }

    #[test]
    fn pairing_secret_never_appears_in_debug_output() {
        let secret = PairingSecret::generate();
        let rendered = format!("{secret:?}");
        assert_eq!(rendered, "PairingSecret(<redacted>)");
        // Not even a prefix, which would leak entropy from a short-lived secret
        // that may outlive the window in a log file.
        assert!(!rendered.contains(&hex::encode(&secret.as_bytes()[..2])));
    }

    #[test]
    fn generated_secrets_differ() {
        assert_ne!(
            PairingSecret::generate().as_bytes(),
            PairingSecret::generate().as_bytes()
        );
    }

    #[test]
    fn manual_code_is_eight_characters_and_grouped_for_display() {
        let code = ManualCode::from_secret(&PairingSecret::generate());
        assert_eq!(code.pake_password().len(), MANUAL_CODE_CHARS);
        assert_eq!(code.grouped().len(), MANUAL_CODE_CHARS + 1);
        assert!(code.grouped().contains('-'));
    }

    #[test]
    fn manual_code_uses_no_ambiguous_characters() {
        // The whole point of Crockford: a user reading digits off a screen must
        // not have to distinguish O from 0 or I from 1.
        for i in 0u8..100 {
            let code = ManualCode::from_secret(&PairingSecret::from_bytes([i; 32]));
            for c in code.pake_password().chars() {
                assert!(
                    !"ILOU".contains(c),
                    "ambiguous character {c} in code {}",
                    code.pake_password()
                );
            }
        }
    }

    #[test]
    fn manual_code_derivation_is_deterministic() {
        let secret = PairingSecret::from_bytes([0x5A; 32]);
        assert_eq!(
            ManualCode::from_secret(&secret),
            ManualCode::from_secret(&secret)
        );
    }

    #[test]
    fn manual_code_parsing_tolerates_human_input() {
        let canonical = ManualCode::from_secret(&PairingSecret::from_bytes([3u8; 32]));
        let raw = canonical.pake_password().to_owned();
        let grouped = canonical.grouped();

        for variant in [
            raw.clone(),
            raw.to_lowercase(),
            grouped.clone(),
            grouped.to_lowercase(),
            format!(" {grouped} "),
            // Every character space-separated, as a user might read it aloud.
            raw.chars().flat_map(|c| [c, ' ']).collect::<String>(),
            grouped.replace('-', "_"),
        ] {
            assert_eq!(
                ManualCode::parse(&variant)
                    .as_ref()
                    .map(ManualCode::pake_password),
                Ok(raw.as_str()),
                "failed to parse variant {variant:?}"
            );
        }
    }

    #[test]
    fn manual_code_parsing_normalises_confusable_characters() {
        // A user who types the letter O for a zero should pair, not be told the
        // code is wrong.
        let with_zero = ManualCode::parse("01234567").unwrap();
        let with_letter_o = ManualCode::parse("O1234567").unwrap();
        assert_eq!(with_zero, with_letter_o);

        let with_one = ManualCode::parse("10234567").unwrap();
        assert_eq!(ManualCode::parse("I0234567").unwrap(), with_one);
        assert_eq!(ManualCode::parse("L0234567").unwrap(), with_one);
    }

    #[test]
    fn manual_code_rejects_wrong_lengths_and_bad_characters() {
        assert_eq!(ManualCode::parse("ABC"), Err(PairingError::BadCodeLength));
        assert_eq!(
            ManualCode::parse("ABCDEFGHI"),
            Err(PairingError::BadCodeLength)
        );
        assert_eq!(ManualCode::parse(""), Err(PairingError::BadCodeLength));
        assert_eq!(ManualCode::parse("ABCDEF!!"), Err(PairingError::NotBase32));
    }

    #[test]
    fn window_allows_exactly_three_attempts() {
        let mut w = PairingWindow::open(0);
        assert_eq!(w.attempts_remaining(), 3);
        assert!(w.try_attempt(0).is_ok());
        assert!(w.try_attempt(0).is_ok());
        assert!(w.try_attempt(0).is_ok());
        assert_eq!(w.attempts_remaining(), 0);
        // Fourth attempt dies, which is what makes a 40-bit code safe.
        assert_eq!(w.try_attempt(0), Err(PairingError::Expired));
    }

    #[test]
    fn window_closes_after_the_timeout() {
        let mut w = PairingWindow::open(1_000);
        assert!(
            w.try_attempt(1_000 + PAIRING_WINDOW_MS).is_ok(),
            "boundary must be inclusive"
        );

        let mut w2 = PairingWindow::open(1_000);
        assert_eq!(
            w2.try_attempt(1_000 + PAIRING_WINDOW_MS + 1),
            Err(PairingError::Expired)
        );
    }

    #[test]
    fn window_is_single_use_even_within_its_time_budget() {
        let mut w = PairingWindow::open(0);
        assert!(w.try_attempt(0).is_ok());
        w.consume();
        assert_eq!(w.try_attempt(0), Err(PairingError::Expired));
        assert!(!w.is_open(0));
    }

    #[test]
    fn all_window_failures_report_the_same_error() {
        // Distinguishing "expired" from "out of attempts" from "already used"
        // would let a caller tune an attack. All three collapse to Expired.
        let mut timed_out = PairingWindow::open(0);
        let mut exhausted = PairingWindow::open(0);
        for _ in 0..MAX_PAIRING_ATTEMPTS {
            exhausted.try_attempt(0).unwrap();
        }
        let mut consumed = PairingWindow::open(0);
        consumed.consume();

        assert_eq!(
            timed_out.try_attempt(PAIRING_WINDOW_MS + 1),
            Err(PairingError::Expired)
        );
        assert_eq!(exhausted.try_attempt(0), Err(PairingError::Expired));
        assert_eq!(consumed.try_attempt(0), Err(PairingError::Expired));
    }

    #[test]
    fn a_clock_that_goes_backwards_does_not_extend_the_window() {
        // saturating_sub means a backwards monotonic reading yields 0 elapsed
        // rather than a huge wrapped value that would appear expired, and it
        // cannot be used to reopen a closed window either.
        let mut w = PairingWindow::open(10_000);
        assert!(w.try_attempt(5_000).is_ok());
    }

    proptest::proptest! {
        #[test]
        fn any_ticket_round_trips(
            key: [u8; 32],
            secret_bytes: [u8; PAIRING_SECRET_LEN],
            addrs: Vec<String>,
        ) {
            // Hints go through a newline-separated blob, so exclude newlines and
            // the empty string, which are not valid socket addresses anyway.
            let addrs: Vec<String> = addrs
                .into_iter()
                .filter(|a| !a.contains('\n') && !a.is_empty())
                .take(4)
                .collect();

            let t = PairingTicket {
                daemon_key: PublicKey::from_bytes(key),
                addr_hints: addrs,
                relay_hint: None,
            };
            let secret = PairingSecret::from_bytes(secret_bytes);
            let encoded = t.encode(&secret);
            let (decoded, decoded_secret) = PairingTicket::decode(&encoded).unwrap();

            proptest::prop_assert_eq!(decoded, t);
            proptest::prop_assert_eq!(decoded_secret.as_bytes(), &secret_bytes);
        }

        /// Decoding arbitrary scanned text must never panic — a QR code can
        /// contain anything at all.
        #[test]
        fn decoding_arbitrary_text_never_panics(payload: String) {
            let _ = PairingTicket::decode(&payload);
        }

        #[test]
        fn decoding_arbitrary_prefixed_text_never_panics(body: String) {
            let _ = PairingTicket::decode(&format!("{TICKET_PREFIX}{body}"));
        }

        #[test]
        fn parsing_arbitrary_manual_codes_never_panics(input: String) {
            let _ = ManualCode::parse(&input);
        }

        #[test]
        fn window_never_allows_more_than_the_attempt_cap(times: Vec<u64>) {
            let mut w = PairingWindow::open(0);
            let mut allowed = 0;
            for t in times.into_iter().take(50) {
                if w.try_attempt(t % PAIRING_WINDOW_MS).is_ok() {
                    allowed += 1;
                }
            }
            proptest::prop_assert!(allowed <= MAX_PAIRING_ATTEMPTS);
        }
    }
}
