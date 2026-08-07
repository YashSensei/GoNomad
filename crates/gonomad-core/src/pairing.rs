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
///
/// # Two keys, and why both are mandatory
///
/// [`PairingTicket::daemon_key`] is the X25519 Noise static: it authenticates
/// the *session* (§3.4), on every transport. [`PairingTicket::node_id`] is the
/// iroh `NodeId`: it is the *address* off-LAN, because iroh dials public keys
/// rather than IP addresses (§4.3). Neither substitutes for the other, and a
/// ticket carrying only the first is a ticket that works on the sofa and fails
/// on mobile data — which is why the field is required rather than optional.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingTicket {
    /// The daemon's X25519 Noise static key. Learning this over the optical
    /// channel is what makes a network man-in-the-middle impossible.
    pub daemon_key: PublicKey,
    /// The daemon's iroh `NodeId` — `DeviceIdentity::iroh_node_id`.
    ///
    /// An Ed25519 public key, and **not** the same key as
    /// [`PairingTicket::daemon_key`]. Without it the phone cannot dial at all
    /// once the two devices are on different networks: there is no address to
    /// fall back to, because in iroh the key *is* the address.
    pub node_id: PublicKey,
    /// Direct socket addresses to try first, e.g. `192.168.1.4:41234`.
    ///
    /// Retained even though iroh discovers addresses on its own: a hint that is
    /// still valid makes the LAN path succeed on the first packet, with no
    /// discovery round trip and no relay.
    pub addr_hints: Vec<String>,
    /// The daemon's home relay URL, for the CGNAT case.
    pub relay_hint: Option<String>,
}

/// Ticket format version, so a future layout change is detectable.
///
/// Bumped to 2 when the iroh `NodeId` was added. A version 1 ticket is not
/// parsed as a truncated version 2 one: the version byte is checked before any
/// field is read, so an old ticket fails with
/// [`PairingError::UnsupportedVersion`] and the phone can say "update your
/// daemon" rather than "invalid code".
const TICKET_VERSION: u8 = 2;

/// Fixed-size portion of a ticket body: version, both keys, secret, hint length.
const TICKET_FIXED_LEN: usize = 1 + 32 + 32 + PAIRING_SECRET_LEN + 2;

/// Byte offsets of the fixed fields, so the parser never counts by hand.
const NODE_ID_AT: usize = 1 + 32;
const SECRET_AT: usize = NODE_ID_AT + 32;

/// A hint's type tag. Every hint is `kind ‖ len ‖ payload`, so a kind this build
/// does not know is *skipped* rather than fatal.
const HINT_IPV4: u8 = 1;
/// An IPv6 socket address: 16 address bytes then a big-endian port.
const HINT_IPV6: u8 = 2;
/// A direct address that is not a canonical socket address, kept as UTF-8.
const HINT_TEXT: u8 = 3;
/// A relay URL, as UTF-8.
const HINT_RELAY: u8 = 4;

/// Bytes of hint header: the kind tag plus the one-byte length.
const HINT_HEADER_LEN: usize = 2;

impl PairingTicket {
    /// Encodes the ticket and secret into the string placed in the QR code.
    ///
    /// Layout: `gonomad1:` + Crockford-base32( version ‖ noise key ‖ node id ‖
    /// secret ‖ u16 hint length ‖ hints ). Base32 rather than base64 because QR
    /// codes have a dedicated alphanumeric mode that covers uppercase base32 and
    /// stores it far more densely than mixed-case binary-safe encodings.
    ///
    /// # Why the hints are binary rather than text
    ///
    /// Every byte here is a denser QR code and a harder scan, and the ticket had
    /// to grow by a 32-byte public key that nothing can shrink. The address hints
    /// pay some of that back: `192.168.1.4:41234` is 17 characters as text and
    /// 6 bytes as an address plus a port. A socket address that does not
    /// round-trip through its own `Display` — anything unusual — falls back to a
    /// verbatim text record, so fidelity never depends on formatting rules
    /// agreeing across versions.
    #[must_use]
    pub fn encode(&self, secret: &PairingSecret) -> String {
        let mut body = Vec::with_capacity(TICKET_FIXED_LEN + 64);
        body.push(TICKET_VERSION);
        body.extend_from_slice(self.daemon_key.as_bytes());
        body.extend_from_slice(self.node_id.as_bytes());
        body.extend_from_slice(secret.as_bytes());

        let hints = self.encode_hints();
        // A hint blob that cannot be described by the u16 length is dropped
        // wholesale rather than truncated: half a hint list is worse than none,
        // because a truncated final hint would decode as a different address.
        let len = u16::try_from(hints.len()).unwrap_or(0);
        body.extend_from_slice(&len.to_be_bytes());
        body.extend_from_slice(&hints[..usize::from(len)]);

        format!("{TICKET_PREFIX}{}", crockford().encode(&body))
    }

    /// Serialises the address and relay hints as length-tagged records.
    fn encode_hints(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for hint in &self.addr_hints {
            match hint.parse::<std::net::SocketAddr>() {
                // Only take the compact form when the address renders back to
                // exactly what was given. Otherwise `[::0001]:80` would decode
                // as `[::1]:80`, and a round trip that silently rewrites its
                // input is a bug waiting for a hint that matters.
                Ok(std::net::SocketAddr::V4(v4)) if v4.to_string() == *hint => {
                    let mut payload = Vec::with_capacity(6);
                    payload.extend_from_slice(&v4.ip().octets());
                    payload.extend_from_slice(&v4.port().to_be_bytes());
                    push_hint(&mut out, HINT_IPV4, &payload);
                }
                Ok(std::net::SocketAddr::V6(v6)) if v6.to_string() == *hint => {
                    let mut payload = Vec::with_capacity(18);
                    payload.extend_from_slice(&v6.ip().octets());
                    payload.extend_from_slice(&v6.port().to_be_bytes());
                    push_hint(&mut out, HINT_IPV6, &payload);
                }
                _ => push_hint(&mut out, HINT_TEXT, hint.as_bytes()),
            }
        }
        if let Some(relay) = &self.relay_hint {
            push_hint(&mut out, HINT_RELAY, relay.as_bytes());
        }
        out
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

        // The version is checked before the length, not after. A version 1
        // ticket is *shorter* than this layout's fixed portion, so a
        // length-first parser would report it as malformed — and "invalid code"
        // sends the user to look for a typo in a QR they cannot read, when the
        // real answer is "update your daemon". The version byte is the first byte
        // on the wire precisely so it can be trusted before anything else.
        let Some(&version) = body.first() else {
            return Err(PairingError::BadLength);
        };
        if version != TICKET_VERSION {
            return Err(PairingError::UnsupportedVersion { version });
        }
        if body.len() < TICKET_FIXED_LEN {
            return Err(PairingError::BadLength);
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&body[1..NODE_ID_AT]);

        let mut node_id = [0u8; 32];
        node_id.copy_from_slice(&body[NODE_ID_AT..SECRET_AT]);

        let mut secret = [0u8; PAIRING_SECRET_LEN];
        secret.copy_from_slice(&body[SECRET_AT..SECRET_AT + PAIRING_SECRET_LEN]);

        let hint_len =
            u16::from_be_bytes([body[TICKET_FIXED_LEN - 2], body[TICKET_FIXED_LEN - 1]]) as usize;
        if body.len() != TICKET_FIXED_LEN + hint_len {
            return Err(PairingError::BadLength);
        }
        let (addr_hints, relay_hint) = decode_hints(&body[TICKET_FIXED_LEN..])?;

        let secret = PairingSecret::from_bytes(secret);
        // Wipe the stack copies now that ownership has moved on. Neither is
        // secret, but the buffers are adjacent to one that is and a uniform
        // habit is cheaper than a case-by-case judgement.
        let mut scratch = key;
        scratch.zeroize();

        Ok((
            Self {
                daemon_key: PublicKey::from_bytes(key),
                node_id: PublicKey::from_bytes(node_id),
                addr_hints,
                relay_hint,
            },
            secret,
        ))
    }
}

/// Appends one `kind ‖ len ‖ payload` record, dropping anything too long to
/// describe.
///
/// A hint longer than 255 bytes is skipped rather than truncated: hints are
/// advisory, so losing one costs a fallback, while a truncated relay URL would
/// send the phone somewhere else entirely.
fn push_hint(out: &mut Vec<u8>, kind: u8, payload: &[u8]) {
    let Ok(len) = u8::try_from(payload.len()) else {
        return;
    };
    out.reserve(HINT_HEADER_LEN + payload.len());
    out.push(kind);
    out.push(len);
    out.extend_from_slice(payload);
}

/// Parses the hint records, returning the direct addresses in order and the
/// relay.
///
/// Runs on bytes from a scanned QR code, so every read is bounds-checked and
/// nothing here can panic.
fn decode_hints(mut rest: &[u8]) -> Result<(Vec<String>, Option<String>), PairingError> {
    let mut addr_hints = Vec::new();
    let mut relay_hint = None;

    while !rest.is_empty() {
        if rest.len() < HINT_HEADER_LEN {
            return Err(PairingError::BadLength);
        }
        let kind = rest[0];
        let len = usize::from(rest[1]);
        let end = HINT_HEADER_LEN + len;
        // A record claiming more bytes than remain means the blob is corrupt.
        // Rejected rather than salvaged: the alternative is deciding what a
        // half-parsed address list means, and there is no good answer.
        if rest.len() < end {
            return Err(PairingError::BadLength);
        }
        let payload = &rest[HINT_HEADER_LEN..end];

        match kind {
            HINT_IPV4 => {
                if let Ok(raw) = <[u8; 6]>::try_from(payload) {
                    let ip = std::net::Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]);
                    let port = u16::from_be_bytes([raw[4], raw[5]]);
                    addr_hints.push(std::net::SocketAddrV4::new(ip, port).to_string());
                }
            }
            HINT_IPV6 => {
                if let Ok(raw) = <[u8; 18]>::try_from(payload) {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&raw[..16]);
                    let ip = std::net::Ipv6Addr::from(octets);
                    let port = u16::from_be_bytes([raw[16], raw[17]]);
                    addr_hints.push(std::net::SocketAddrV6::new(ip, port, 0, 0).to_string());
                }
            }
            HINT_TEXT => {
                if let Ok(text) = core::str::from_utf8(payload) {
                    addr_hints.push(text.to_owned());
                }
            }
            HINT_RELAY => {
                if let Ok(text) = core::str::from_utf8(payload) {
                    relay_hint = Some(text.to_owned());
                }
            }
            // Unknown kinds are skipped rather than rejected: a newer daemon
            // adding a hint type must not break an older phone, since hints are
            // advisory and the connection can still succeed without them. The
            // length byte is what makes skipping possible at all.
            _ => {}
        }
        rest = &rest[end..];
    }

    Ok((addr_hints, relay_hint))
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
            node_id: PublicKey::from_bytes([0xCD; 32]),
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
            node_id: PublicKey::from_bytes([2u8; 32]),
            addr_hints: vec![],
            relay_hint: None,
        };
        let secret = PairingSecret::generate();
        let (decoded, _) = PairingTicket::decode(&t.encode(&secret)).unwrap();
        assert_eq!(decoded, t);
    }

    #[test]
    fn the_two_keys_do_not_get_swapped_in_transit() {
        // They are both 32 bytes at adjacent offsets, so a transposed pair would
        // decode cleanly and then fail every handshake with no clue why.
        let t = ticket();
        let (decoded, _) = PairingTicket::decode(&t.encode(&PairingSecret::generate())).unwrap();
        assert_eq!(decoded.daemon_key, PublicKey::from_bytes([0xAB; 32]));
        assert_eq!(decoded.node_id, PublicKey::from_bytes([0xCD; 32]));
    }

    #[test]
    fn the_node_id_costs_a_bounded_number_of_qr_characters() {
        // The QR is scanned by a phone camera, so payload length is a product
        // constraint, not a detail. This pins the budget: a representative
        // ticket — two address hints and a relay URL — must stay inside a payload
        // that QR version 11 encodes comfortably in alphanumeric mode at
        // error-correction level M (468 characters).
        let payload = ticket().encode(&PairingSecret::generate());
        assert!(
            payload.len() <= 260,
            "ticket payload grew to {} characters",
            payload.len()
        );
    }

    #[test]
    fn a_real_machines_hint_set_still_fits_a_scannable_qr() {
        // The test above uses a *representative* ticket. This one uses what a real
        // Windows laptop actually produced: the STUN-discovered public address, the
        // Wi-Fi address, two virtual-adapter addresses that Hyper-V and WSL add, two
        // IPv6 addresses, and an n0 relay URL. That is 7 records, not 3, and it is
        // the ordinary case rather than a pathological one — so the budget has to
        // hold here or the QR stops scanning on ordinary machines.
        //
        // 468 characters is QR version 11 at error-correction level M in
        // alphanumeric mode. Past that the code needs more modules than a laptop
        // screen renders legibly for a phone camera held at arm's length.
        //
        // Measured: this ticket is **342 characters**, so there is real headroom.
        // Two of those hints are Hyper-V and WSL virtual adapters the phone can
        // never reach, and they are deliberately *not* filtered: they cost about 16
        // characters, iroh races hints so a dead one costs nothing at dial time, and
        // any heuristic sharp enough to drop them would also drop a legitimate
        // `192.168.x.x` LAN address — breaking the fast path the hints exist for.
        let mut t = ticket();
        t.addr_hints = vec![
            "122.172.80.215:18835".into(),
            "192.168.1.17:65101".into(),
            "192.168.67.1:65101".into(),
            "192.168.73.1:65101".into(),
            "[2401:4900:894d:3a7b:4ff8:3509:4ad3:39c8]:65103".into(),
            "[2401:4900:894d:3a7b:e421:8a83:7818:3c52]:65103".into(),
        ];
        t.relay_hint = Some("https://aps1-1.relay.n0.iroh.link./".into());

        let payload = t.encode(&PairingSecret::generate());
        assert!(
            payload.len() <= 468,
            "a real machine's ticket is {} characters, past QR v11 capacity",
            payload.len()
        );
    }

    #[test]
    fn address_hints_are_stored_compactly() {
        // The binary hint encoding is what pays for the node id. An IPv4 hint
        // costs 8 bytes of body (kind, length, four octets, port) rather than
        // the 18 the old text form needed.
        let mut with_hint = ticket();
        with_hint.addr_hints = vec!["192.168.1.4:41234".into()];
        with_hint.relay_hint = None;
        let mut bare = with_hint.clone();
        bare.addr_hints = vec![];

        let secret = PairingSecret::generate();
        let grown = with_hint.encode(&secret).len() - bare.encode(&secret).len();
        // 8 bytes of body is at most 13 base32 characters once alignment is
        // accounted for; text encoding could not be under 29.
        assert!(grown <= 14, "an IPv4 hint cost {grown} characters");
    }

    #[test]
    fn an_unusual_address_hint_survives_verbatim() {
        // A hint that is not a canonical socket address must not be rewritten or
        // dropped: a daemon may one day emit a hostname, and a silently mangled
        // hint is worse than a missing one.
        let mut t = ticket();
        t.addr_hints = vec![
            "laptop.local:41234".into(),
            "[::0001]:80".into(),
            String::new(),
        ];
        let (decoded, _) = PairingTicket::decode(&t.encode(&PairingSecret::generate())).unwrap();
        assert_eq!(decoded.addr_hints, t.addr_hints);
    }

    #[test]
    fn a_hint_too_long_to_describe_is_dropped_not_truncated() {
        // A truncated relay URL would point the phone at a different host.
        let mut t = ticket();
        t.relay_hint = Some("h".repeat(300));
        let (decoded, _) = PairingTicket::decode(&t.encode(&PairingSecret::generate())).unwrap();
        assert_eq!(decoded.relay_hint, None);
        assert_eq!(decoded.addr_hints, t.addr_hints);
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

        // An empty body has no version byte to report on.
        assert_eq!(decode_err("gonomad1:"), PairingError::BadLength);

        // Valid base32 that decodes to five bytes (Crockford `A` is 10, so the
        // first byte is 0x52). The version byte is checked first, so this is
        // reported as an unsupported version rather than a length problem — see
        // `decode` for why that ordering matters.
        assert_eq!(
            decode_err("gonomad1:AAAAAAAA"),
            PairingError::UnsupportedVersion { version: 0x52 }
        );

        // A body that starts with the right version but stops short is a length
        // problem, and that is what a truncated scan looks like.
        let good = ticket().encode(&PairingSecret::generate());
        let short = &good.strip_prefix(TICKET_PREFIX).unwrap()[..8];
        assert_eq!(
            decode_err(&format!("{TICKET_PREFIX}{short}")),
            PairingError::BadLength
        );
    }

    #[test]
    fn a_future_ticket_version_is_reported_as_such() {
        // So the phone can say "update your app" rather than "invalid code".
        let mut body = vec![99u8];
        body.extend_from_slice(&[0u8; 32]);
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
    fn a_version_one_ticket_is_rejected_rather_than_misparsed() {
        // The layout that shipped before the node id: version, one key, secret,
        // and newline-separated text hints. It is a *prefix* of nothing valid, so
        // the danger is not that it fails — it is that it could decode into a
        // ticket whose node id was really the first half of the pairing secret.
        let mut body = vec![1u8];
        body.extend_from_slice(&[0xAB; 32]);
        body.extend_from_slice(&[0x5A; PAIRING_SECRET_LEN]);
        let hints = "a192.168.1.4:41234";
        body.extend_from_slice(&u16::try_from(hints.len()).unwrap().to_be_bytes());
        body.extend_from_slice(hints.as_bytes());

        let payload = format!("{TICKET_PREFIX}{}", crockford().encode(&body));
        assert_eq!(
            decode_err(&payload),
            PairingError::UnsupportedVersion { version: 1 }
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

    /// Assembles a ticket body with a hand-written hint blob.
    fn body_with_hints(hints: &[u8]) -> String {
        let mut body = vec![TICKET_VERSION];
        body.extend_from_slice(&[7u8; 32]);
        body.extend_from_slice(&[9u8; 32]);
        body.extend_from_slice(&[8u8; PAIRING_SECRET_LEN]);
        body.extend_from_slice(&u16::try_from(hints.len()).unwrap().to_be_bytes());
        body.extend_from_slice(hints);
        format!("{TICKET_PREFIX}{}", crockford().encode(&body))
    }

    #[test]
    fn unknown_hint_kinds_are_skipped_for_forward_compatibility() {
        // A newer daemon adding a hint type must not break an older phone. The
        // length byte on every record is what makes skipping possible.
        let mut hints = vec![HINT_IPV4, 6, 1, 2, 3, 4, 0, 1];
        hints.extend_from_slice(&[200, 3, b'n', b'e', b'w']);
        hints.extend_from_slice(&[HINT_RELAY, 9]);
        hints.extend_from_slice(b"https://r");

        let (t, _) = PairingTicket::decode(&body_with_hints(&hints)).unwrap();
        assert_eq!(t.addr_hints, vec!["1.2.3.4:1"]);
        assert_eq!(t.relay_hint.as_deref(), Some("https://r"));
    }

    #[test]
    fn a_hint_record_running_past_the_blob_is_rejected() {
        // Corrupt rather than forward-compatible: there is no honest reading of a
        // record that claims more bytes than exist.
        assert_eq!(
            decode_err(&body_with_hints(&[HINT_RELAY, 40, b'x'])),
            PairingError::BadLength
        );
        assert_eq!(
            decode_err(&body_with_hints(&[HINT_IPV4])),
            PairingError::BadLength
        );
    }

    #[test]
    fn an_address_record_of_the_wrong_size_is_skipped_not_fatal() {
        // A five-byte "IPv4" address is nonsense, but it is describable, so the
        // record is skipped and the rest of the list still parses.
        let mut hints = vec![HINT_IPV4, 5, 1, 2, 3, 4, 0];
        hints.extend_from_slice(&[HINT_RELAY, 1, b'r']);
        let (t, _) = PairingTicket::decode(&body_with_hints(&hints)).unwrap();
        assert!(t.addr_hints.is_empty());
        assert_eq!(t.relay_hint.as_deref(), Some("r"));
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
            node: [u8; 32],
            secret_bytes: [u8; PAIRING_SECRET_LEN],
            addrs: Vec<String>,
        ) {
            // Each hint carries a `u8` length, so anything over 255 bytes is
            // deliberately dropped rather than round-tripped.
            let addrs: Vec<String> = addrs
                .into_iter()
                .filter(|a| a.len() <= 255)
                .take(4)
                .collect();

            let t = PairingTicket {
                daemon_key: PublicKey::from_bytes(key),
                node_id: PublicKey::from_bytes(node),
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

        /// The hint parser runs on bytes taken straight from a camera. It must
        /// bounds-check every read rather than trusting a length byte.
        #[test]
        fn decoding_arbitrary_hint_records_never_panics(blob: Vec<u8>) {
            let _ = decode_hints(&blob);
        }

        #[test]
        fn a_well_formed_ticket_with_arbitrary_hint_bytes_never_panics(blob: Vec<u8>) {
            proptest::prop_assume!(u16::try_from(blob.len()).is_ok());
            let _ = PairingTicket::decode(&body_with_hints(&blob));
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
