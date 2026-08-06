//! Frame layout and the length-prefixed codec.
//!
//! Every message crossing the wire is a frame (`ARCHITECTURE.md` §10.3):
//!
//! ```text
//! ┌────────────┬───────────┬──────────────────────────────┐
//! │ len: u32   │ flags: u8 │ payload                      │
//! │ big-endian │           │ (CBOR or raw, maybe zstd)    │
//! └────────────┴───────────┴──────────────────────────────┘
//! ```
//!
//! `len` counts the payload only — neither itself nor the flags byte. That
//! choice makes the "how many more bytes do I need" calculation in
//! [`Frame::decode`] impossible to get subtly wrong, which matters because it
//! runs on attacker-controlled input.
//!
//! # This module parses untrusted input
//!
//! A frame arrives from whatever is on the other end of the socket. Before the
//! Noise handshake completes that is an unauthenticated peer, and afterwards it
//! is a phone that may itself be compromised. Consequently:
//!
//! - **Decoding never panics.** No slice indexing without a prior length check,
//!   no `unwrap`, no arithmetic that can overflow. Verified by `proptest`
//!   against arbitrary byte strings.
//! - **The length prefix is bounded before allocation.** A `u32` prefix can
//!   claim 4 GiB. Trusting it would let a single 5-byte frame header exhaust
//!   memory — a trivial denial of service. [`MAX_PAYLOAD_LEN`] is checked
//!   *before* any buffer is reserved.
//! - **Unknown flag bits are rejected**, not ignored. Silently dropping bits we
//!   do not understand is how a peer ends up believing a payload was
//!   authenticated, compressed, or terminal when it was not.

use core::fmt;

/// Bytes of framing overhead: the `u32` length plus the flags byte.
pub const HEADER_LEN: usize = 5;

/// Largest payload this build will decode, in bytes.
///
/// Sized to the largest legitimate single response — a 32 MiB file read
/// (`ARCHITECTURE.md` §3.8) — and no larger. The bound exists because the
/// length prefix is attacker-controlled: without it, a peer sends a 5-byte
/// header claiming 4 GiB and the daemon allocates it.
///
/// Bulk transfers that genuinely exceed this are chunked across frames on a
/// dedicated stream (§10.2), so raising this is not the fix for a large file.
pub const MAX_PAYLOAD_LEN: usize = 32 * 1024 * 1024;

/// Payloads at or below this size skip compression.
///
/// Below roughly this threshold, zstd framing overhead exceeds the savings even
/// with a trained dictionary, and the CPU cost is pure loss on a phone battery.
pub const COMPRESSION_THRESHOLD: usize = 128;

/// Per-frame flags.
///
/// A hand-rolled bitfield rather than a `bitflags` dependency: there are three
/// bits, and the validation this needs (reject unknown bits) is the opposite of
/// what `bitflags` makes convenient.
#[derive(Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct FrameFlags(u8);

impl FrameFlags {
    /// No flags: an uncompressed CBOR frame that is not the last in a sequence.
    pub const NONE: Self = Self(0);

    /// Bit 0 — the payload is zstd-compressed.
    pub const COMPRESSED: Self = Self(1 << 0);

    /// Bit 1 — the payload is raw bytes, not CBOR.
    ///
    /// Set for bulk transfer and PTY passthrough, where wrapping a file's bytes
    /// in a self-describing encoding would buy nothing.
    pub const RAW: Self = Self(1 << 1);

    /// Bit 2 — the last frame in a multi-frame sequence.
    ///
    /// Lets a receiver know a streamed response is complete without waiting for
    /// a stream close, so a request can finish while the stream stays open for
    /// the next one.
    pub const LAST: Self = Self(1 << 2);

    /// Every bit this build understands. Anything outside this mask is rejected.
    const KNOWN: u8 = 0b0000_0111;

    /// Wraps a raw bits value, rejecting unknown bits.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::UnknownFlags`] when any bit outside the three
    /// defined flags is set. Rejecting rather than masking is deliberate: a peer
    /// that sets a bit we do not implement is either a newer version or an
    /// attacker, and in both cases proceeding while ignoring its meaning is
    /// unsafe.
    pub const fn from_bits(bits: u8) -> Result<Self, FrameError> {
        if bits & !Self::KNOWN != 0 {
            return Err(FrameError::UnknownFlags { bits });
        }
        Ok(Self(bits))
    }

    /// The raw bits.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Returns `true` when every flag in `other` is set here.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Returns the union of two flag sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns `true` when the payload is zstd-compressed.
    #[must_use]
    pub const fn is_compressed(self) -> bool {
        self.contains(Self::COMPRESSED)
    }

    /// Returns `true` when the payload is raw bytes rather than CBOR.
    #[must_use]
    pub const fn is_raw(self) -> bool {
        self.contains(Self::RAW)
    }

    /// Returns `true` when this is the final frame of a sequence.
    #[must_use]
    pub const fn is_last(self) -> bool {
        self.contains(Self::LAST)
    }
}

impl core::ops::BitOr for FrameFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

impl fmt::Debug for FrameFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut names = heapless_names(*self);
        if names.is_empty() {
            names.push_str("NONE");
        }
        write!(f, "FrameFlags({names})")
    }
}

fn heapless_names(flags: FrameFlags) -> String {
    let mut out = String::new();
    for (flag, name) in [
        (FrameFlags::COMPRESSED, "COMPRESSED"),
        (FrameFlags::RAW, "RAW"),
        (FrameFlags::LAST, "LAST"),
    ] {
        if flags.contains(flag) {
            if !out.is_empty() {
                out.push('|');
            }
            out.push_str(name);
        }
    }
    out
}

/// Errors produced while encoding or decoding a frame.
///
/// Distinct from [`crate::ProtoError`]: those are *application* failures a peer
/// reports about a well-formed request. These are *framing* failures, which mean
/// the byte stream itself is unusable and the connection must be torn down —
/// there is no correlation id to attach a reply to, and continuing to parse a
/// stream we have lost sync with is how a parser desynchronisation bug becomes a
/// vulnerability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FrameError {
    /// The declared payload length exceeds [`MAX_PAYLOAD_LEN`].
    #[error("frame payload of {len} bytes exceeds the {MAX_PAYLOAD_LEN} byte limit")]
    TooLarge {
        /// The length the peer declared.
        len: usize,
    },

    /// The flags byte set a bit this build does not understand.
    #[error("frame flags {bits:#010b} contain unknown bits")]
    UnknownFlags {
        /// The full flags byte as received.
        bits: u8,
    },

    /// A payload was declared CBOR but did not decode.
    #[error("frame payload is not valid CBOR")]
    MalformedPayload,

    /// A value could not be encoded to CBOR.
    #[error("value could not be serialized to CBOR")]
    Unserializable,
}

/// A single wire frame: flags plus an opaque payload.
///
/// The payload stays opaque here on purpose. Compression
/// ([`FrameFlags::COMPRESSED`]) and encryption are applied by layers above and
/// below this one respectively, so the codec neither compresses nor decrypts —
/// it only delimits. Keeping those concerns separate is what allows the same
/// frame format to be carried over QUIC streams and over the WebSocket fallback
/// binding (§10.6) without change.
#[derive(Clone, PartialEq, Eq)]
pub struct Frame {
    /// Per-frame flags.
    pub flags: FrameFlags,
    /// The payload bytes, exactly as they will appear on the wire.
    pub payload: Vec<u8>,
}

impl Frame {
    /// Builds a frame from flags and payload.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::TooLarge`] when `payload` exceeds
    /// [`MAX_PAYLOAD_LEN`]. Checked at construction so an over-large frame can
    /// never reach the encoder.
    pub fn new(flags: FrameFlags, payload: Vec<u8>) -> Result<Self, FrameError> {
        if payload.len() > MAX_PAYLOAD_LEN {
            return Err(FrameError::TooLarge { len: payload.len() });
        }
        Ok(Self { flags, payload })
    }

    /// Builds a CBOR frame by serializing `value`.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::Unserializable`] if `value` cannot be encoded, or
    /// [`FrameError::TooLarge`] if the encoding exceeds [`MAX_PAYLOAD_LEN`].
    pub fn cbor<T: serde::Serialize>(flags: FrameFlags, value: &T) -> Result<Self, FrameError> {
        let mut payload = Vec::new();
        ciborium::into_writer(value, &mut payload).map_err(|_| FrameError::Unserializable)?;
        Self::new(flags, payload)
    }

    /// Builds a raw-bytes frame, setting [`FrameFlags::RAW`].
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::TooLarge`] when `payload` exceeds
    /// [`MAX_PAYLOAD_LEN`].
    pub fn raw(payload: Vec<u8>) -> Result<Self, FrameError> {
        Self::new(FrameFlags::RAW, payload)
    }

    /// Deserializes the payload as CBOR.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::MalformedPayload`] when the payload is flagged raw,
    /// is still compressed, or is not valid CBOR. Refusing to parse a
    /// still-compressed payload prevents a caller from silently decoding
    /// compressed bytes as CBOR and getting garbage.
    pub fn decode_cbor<T: serde::de::DeserializeOwned>(&self) -> Result<T, FrameError> {
        if self.flags.is_raw() || self.flags.is_compressed() {
            return Err(FrameError::MalformedPayload);
        }
        ciborium::from_reader(self.payload.as_slice()).map_err(|_| FrameError::MalformedPayload)
    }

    /// Total wire size of this frame, including the header.
    ///
    // Not `const`: `Vec::len` is only const-stable from Rust 1.87 and the
    // workspace MSRV is 1.75. Trivially inlined either way.
    #[must_use]
    pub fn wire_len(&self) -> usize {
        HEADER_LEN + self.payload.len()
    }

    /// Whether this payload is large enough that compressing it is worthwhile.
    #[must_use]
    pub fn should_compress(&self) -> bool {
        !self.flags.is_compressed() && self.payload.len() > COMPRESSION_THRESHOLD
    }

    /// Appends the encoded frame to `buf`.
    ///
    /// Appends rather than allocating, so a writer can batch several frames into
    /// one syscall — which matters for the 16 ms input-coalescing window
    /// (`ARCHITECTURE.md` §14.2).
    pub fn encode_to(&self, buf: &mut Vec<u8>) {
        // `Frame::new` and `Frame::raw` are the only constructors and both
        // enforce MAX_PAYLOAD_LEN, which is far below u32::MAX, so this cast
        // cannot truncate.
        debug_assert!(self.payload.len() <= MAX_PAYLOAD_LEN);
        #[allow(clippy::cast_possible_truncation)]
        let len = self.payload.len() as u32;

        buf.reserve(self.wire_len());
        buf.extend_from_slice(&len.to_be_bytes());
        buf.push(self.flags.bits());
        buf.extend_from_slice(&self.payload);
    }

    /// Encodes the frame into a fresh buffer.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.wire_len());
        self.encode_to(&mut buf);
        buf
    }

    /// Attempts to decode one frame from the front of `buf`.
    ///
    /// Returns:
    /// - `Ok(Some((frame, consumed)))` — a complete frame; the caller advances
    ///   its buffer by `consumed`.
    /// - `Ok(None)` — `buf` holds a valid but incomplete prefix; read more.
    /// - `Err(_)` — the stream is unusable and the connection must be dropped.
    ///
    /// The `Ok(None)` case is what makes this usable as a streaming codec
    /// without pulling in `tokio-util`.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::TooLarge`] when the declared length exceeds
    /// [`MAX_PAYLOAD_LEN`], or [`FrameError::UnknownFlags`] when the flags byte
    /// sets a bit this build does not understand.
    pub fn decode(buf: &[u8]) -> Result<Option<(Self, usize)>, FrameError> {
        // Not enough bytes for a header yet. Checked before any indexing.
        if buf.len() < HEADER_LEN {
            return Ok(None);
        }

        // Indexing is safe: the length check above guarantees 5 bytes.
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;

        // Bound the length BEFORE reserving anything. This is the check that
        // stops a 5-byte header from causing a 4 GiB allocation.
        if len > MAX_PAYLOAD_LEN {
            return Err(FrameError::TooLarge { len });
        }

        // Reject unknown flag bits before committing to the frame.
        let flags = FrameFlags::from_bits(buf[4])?;

        // `len <= MAX_PAYLOAD_LEN` so this addition cannot overflow.
        let total = HEADER_LEN + len;
        if buf.len() < total {
            return Ok(None);
        }

        Ok(Some((
            Self {
                flags,
                payload: buf[HEADER_LEN..total].to_vec(),
            },
            total,
        )))
    }

    /// How many more bytes are needed to complete the frame at the front of
    /// `buf`, or `None` if a complete frame is already present.
    ///
    /// Lets a reader size its next read exactly instead of guessing, avoiding
    /// both short reads and over-reading into the following frame.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::TooLarge`] when the declared length exceeds
    /// [`MAX_PAYLOAD_LEN`].
    pub fn bytes_needed(buf: &[u8]) -> Result<Option<usize>, FrameError> {
        if buf.len() < HEADER_LEN {
            return Ok(Some(HEADER_LEN - buf.len()));
        }
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if len > MAX_PAYLOAD_LEN {
            return Err(FrameError::TooLarge { len });
        }
        let total = HEADER_LEN + len;
        Ok(if buf.len() >= total {
            None
        } else {
            Some(total - buf.len())
        })
    }
}

// Debug prints the payload's size, never its bytes. Frame payloads carry file
// contents, terminal output, and command lines; dumping them into a log would
// undo the secret-shielding work done everywhere else (ARCHITECTURE.md §24.5).
impl fmt::Debug for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Frame")
            .field("flags", &self.flags)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_an_empty_payload() {
        let frame = Frame::new(FrameFlags::NONE, Vec::new()).unwrap();
        let bytes = frame.encode();
        assert_eq!(bytes.len(), HEADER_LEN);
        let (back, consumed) = Frame::decode(&bytes).unwrap().unwrap();
        assert_eq!(back, frame);
        assert_eq!(consumed, HEADER_LEN);
    }

    #[test]
    fn round_trips_with_every_flag_combination() {
        for bits in 0..=FrameFlags::KNOWN {
            let flags = FrameFlags::from_bits(bits).unwrap();
            let frame = Frame::new(flags, b"payload".to_vec()).unwrap();
            let (back, _) = Frame::decode(&frame.encode()).unwrap().unwrap();
            assert_eq!(back, frame, "failed for flags {bits:#b}");
        }
    }

    #[test]
    fn length_prefix_is_big_endian_and_counts_only_the_payload() {
        let frame = Frame::new(FrameFlags::NONE, vec![0xAA; 300]).unwrap();
        let bytes = frame.encode();
        assert_eq!(&bytes[0..4], &[0, 0, 1, 44]); // 300 = 0x0000_012C
        assert_eq!(bytes.len(), HEADER_LEN + 300);
    }

    #[test]
    fn decode_returns_none_for_every_incomplete_prefix() {
        let frame = Frame::new(FrameFlags::LAST, b"hello world".to_vec()).unwrap();
        let bytes = frame.encode();
        for cut in 0..bytes.len() {
            assert_eq!(
                Frame::decode(&bytes[..cut]),
                Ok(None),
                "expected incomplete at {cut} of {}",
                bytes.len()
            );
        }
        assert!(Frame::decode(&bytes).unwrap().is_some());
    }

    #[test]
    fn decode_leaves_trailing_bytes_for_the_next_frame() {
        let a = Frame::new(FrameFlags::NONE, b"first".to_vec()).unwrap();
        let b = Frame::new(FrameFlags::LAST, b"second".to_vec()).unwrap();
        let mut buf = Vec::new();
        a.encode_to(&mut buf);
        b.encode_to(&mut buf);

        let (got_a, used) = Frame::decode(&buf).unwrap().unwrap();
        assert_eq!(got_a, a);
        let (got_b, used_b) = Frame::decode(&buf[used..]).unwrap().unwrap();
        assert_eq!(got_b, b);
        assert_eq!(used + used_b, buf.len());
    }

    #[test]
    fn oversized_length_prefix_is_rejected_without_allocating() {
        // A 5-byte header claiming 4 GiB. Trusting it would be a trivial DoS.
        let mut header = Vec::new();
        header.extend_from_slice(&u32::MAX.to_be_bytes());
        header.push(0);
        assert_eq!(
            Frame::decode(&header),
            Err(FrameError::TooLarge {
                len: u32::MAX as usize
            })
        );
    }

    #[test]
    fn length_exactly_at_the_limit_is_accepted() {
        let mut header = Vec::new();
        #[allow(clippy::cast_possible_truncation)]
        let at_limit = MAX_PAYLOAD_LEN as u32;
        header.extend_from_slice(&at_limit.to_be_bytes());
        header.push(0);
        // Incomplete, but not rejected as too large — the boundary is inclusive.
        assert_eq!(Frame::decode(&header), Ok(None));
    }

    #[test]
    fn length_one_past_the_limit_is_rejected() {
        let mut header = Vec::new();
        #[allow(clippy::cast_possible_truncation)]
        let past = (MAX_PAYLOAD_LEN + 1) as u32;
        header.extend_from_slice(&past.to_be_bytes());
        header.push(0);
        assert_eq!(
            Frame::decode(&header),
            Err(FrameError::TooLarge {
                len: MAX_PAYLOAD_LEN + 1
            })
        );
    }

    #[test]
    fn constructing_an_oversized_frame_fails() {
        let too_big = vec![0u8; MAX_PAYLOAD_LEN + 1];
        assert_eq!(
            Frame::new(FrameFlags::NONE, too_big),
            Err(FrameError::TooLarge {
                len: MAX_PAYLOAD_LEN + 1
            })
        );
    }

    #[test]
    fn unknown_flag_bits_are_rejected_not_ignored() {
        for bit in 3..8u8 {
            let bits = 1 << bit;
            assert_eq!(
                FrameFlags::from_bits(bits),
                Err(FrameError::UnknownFlags { bits })
            );

            let mut header = vec![0, 0, 0, 0];
            header.push(bits);
            assert_eq!(
                Frame::decode(&header),
                Err(FrameError::UnknownFlags { bits })
            );
        }
    }

    #[test]
    fn cbor_payloads_round_trip() {
        #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
        struct Msg {
            id: u64,
            name: String,
        }
        let msg = Msg {
            id: 7,
            name: "terminal".into(),
        };
        let frame = Frame::cbor(FrameFlags::LAST, &msg).unwrap();
        let (back, _) = Frame::decode(&frame.encode()).unwrap().unwrap();
        assert_eq!(back.decode_cbor::<Msg>().unwrap(), msg);
    }

    #[test]
    fn decoding_cbor_from_a_raw_frame_is_refused() {
        // Guards against a caller decoding opaque bytes as CBOR by accident.
        let frame = Frame::raw(b"not cbor".to_vec()).unwrap();
        assert_eq!(
            frame.decode_cbor::<u32>(),
            Err(FrameError::MalformedPayload)
        );
    }

    #[test]
    fn decoding_cbor_from_a_compressed_frame_is_refused() {
        // A still-compressed payload would decode as garbage rather than fail
        // loudly, so refuse it outright.
        let frame = Frame::new(FrameFlags::COMPRESSED, b"\x00\x01".to_vec()).unwrap();
        assert_eq!(
            frame.decode_cbor::<u32>(),
            Err(FrameError::MalformedPayload)
        );
    }

    #[test]
    fn malformed_cbor_is_an_error_not_a_panic() {
        let frame = Frame::new(FrameFlags::NONE, vec![0xFF, 0xFF, 0xFF]).unwrap();
        assert_eq!(
            frame.decode_cbor::<u32>(),
            Err(FrameError::MalformedPayload)
        );
    }

    #[test]
    fn raw_constructor_sets_the_raw_flag() {
        assert!(Frame::raw(b"bytes".to_vec()).unwrap().flags.is_raw());
    }

    #[test]
    fn bytes_needed_guides_a_reader_exactly() {
        let frame = Frame::new(FrameFlags::NONE, vec![7u8; 100]).unwrap();
        let bytes = frame.encode();

        assert_eq!(Frame::bytes_needed(&[]).unwrap(), Some(HEADER_LEN));
        assert_eq!(Frame::bytes_needed(&bytes[..2]).unwrap(), Some(3));
        assert_eq!(
            Frame::bytes_needed(&bytes[..HEADER_LEN]).unwrap(),
            Some(100)
        );
        assert_eq!(
            Frame::bytes_needed(&bytes[..HEADER_LEN + 40]).unwrap(),
            Some(60)
        );
        assert_eq!(Frame::bytes_needed(&bytes).unwrap(), None);
        // Extra trailing data still reports the current frame as complete.
        assert_eq!(
            Frame::bytes_needed(&[bytes.as_slice(), b"more"].concat()).unwrap(),
            None
        );
    }

    #[test]
    fn bytes_needed_rejects_an_oversized_prefix() {
        let mut header = Vec::new();
        header.extend_from_slice(&u32::MAX.to_be_bytes());
        header.push(0);
        assert!(Frame::bytes_needed(&header).is_err());
    }

    #[test]
    fn should_compress_respects_the_threshold() {
        let small = Frame::new(FrameFlags::NONE, vec![0; COMPRESSION_THRESHOLD]).unwrap();
        assert!(!small.should_compress());

        let big = Frame::new(FrameFlags::NONE, vec![0; COMPRESSION_THRESHOLD + 1]).unwrap();
        assert!(big.should_compress());

        // Never recompress.
        let already = Frame::new(FrameFlags::COMPRESSED, vec![0; 5000]).unwrap();
        assert!(!already.should_compress());
    }

    #[test]
    fn debug_never_prints_payload_bytes() {
        // Payloads carry file contents and command lines. Logging them would
        // undo the secret-shielding done elsewhere (§24.5).
        let frame =
            Frame::new(FrameFlags::NONE, b"AWS_SECRET_ACCESS_KEY=hunter2".to_vec()).unwrap();
        let rendered = format!("{frame:?}");
        assert!(!rendered.contains("hunter2"), "got {rendered}");
        assert!(!rendered.contains("AWS_SECRET"), "got {rendered}");
        assert!(rendered.contains("payload_len: 29"), "got {rendered}");
    }

    #[test]
    fn flag_debug_is_readable() {
        assert_eq!(format!("{:?}", FrameFlags::NONE), "FrameFlags(NONE)");
        assert_eq!(
            format!("{:?}", FrameFlags::COMPRESSED | FrameFlags::LAST),
            "FrameFlags(COMPRESSED|LAST)"
        );
    }

    #[test]
    fn encode_to_appends_so_writes_can_be_batched() {
        let mut buf = b"existing".to_vec();
        let frame = Frame::new(FrameFlags::NONE, b"x".to_vec()).unwrap();
        frame.encode_to(&mut buf);
        assert!(buf.starts_with(b"existing"));
        assert_eq!(buf.len(), 8 + frame.wire_len());
    }

    proptest::proptest! {
        /// The property that matters most: decoding arbitrary bytes must never
        /// panic. This runs on data from an unauthenticated peer.
        #[test]
        fn decoding_arbitrary_bytes_never_panics(bytes: Vec<u8>) {
            let _ = Frame::decode(&bytes);
            let _ = Frame::bytes_needed(&bytes);
        }

        #[test]
        fn decoding_arbitrary_headers_never_panics(a: u8, b: u8, c: u8, d: u8, flags: u8) {
            let _ = Frame::decode(&[a, b, c, d, flags]);
        }

        #[test]
        fn any_valid_frame_round_trips(payload: Vec<u8>, bits in 0u8..=FrameFlags::KNOWN) {
            let flags = FrameFlags::from_bits(bits).unwrap();
            let frame = Frame::new(flags, payload).unwrap();
            let (back, consumed) = Frame::decode(&frame.encode()).unwrap().unwrap();
            proptest::prop_assert_eq!(&back, &frame);
            proptest::prop_assert_eq!(consumed, frame.wire_len());
        }

        /// Splitting the stream at any point must yield the same frame — a
        /// streaming codec that only works on whole-frame reads is broken.
        #[test]
        fn decoding_is_independent_of_read_boundaries(payload: Vec<u8>, split in 0usize..64) {
            let frame = Frame::new(FrameFlags::NONE, payload).unwrap();
            let bytes = frame.encode();
            let at = split.min(bytes.len());

            if at < bytes.len() {
                proptest::prop_assert_eq!(Frame::decode(&bytes[..at]).unwrap(), None);
            }
            let (back, _) = Frame::decode(&bytes).unwrap().unwrap();
            proptest::prop_assert_eq!(back, frame);
        }

        #[test]
        fn unknown_bits_are_always_rejected(bits in 8u8..=255) {
            proptest::prop_assume!(bits & !FrameFlags::KNOWN != 0);
            proptest::prop_assert!(FrameFlags::from_bits(bits).is_err());
        }
    }
}
