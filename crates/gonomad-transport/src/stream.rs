//! The logical stream that [`crate::Conn`] hands out, over either binding.
//!
//! One pair of types — [`SendStream`] and [`RecvStream`] — with two backends
//! underneath:
//!
//! | Backend | Stream is | Independence comes from |
//! |---|---|---|
//! | [`crate::mux`] (Tier 0, TCP) | A channel id inside one byte stream | Userspace credit windows; **not** loss recovery (§10.6) |
//! | [`crate::iroh`] (Tiers 1–2, QUIC) | A real QUIC stream | QUIC's own per-stream flow control and loss recovery (§4.4) |
//!
//! # Why one type rather than two
//!
//! Because §4.5 says the ladder must be swappable at runtime, and everything
//! above this crate — the daemon's session actor, the FFI client — names these
//! types concretely in struct fields and function signatures. If the QUIC binding
//! introduced its own stream types, every caller would need a generic parameter
//! or a trait object, and "nothing above this crate changes" would stop being
//! true. The enum is one branch on a pointer per call, which is nothing next to an
//! AEAD pass.
//!
//! # What is on the wire, per backend
//!
//! Both backends carry the same thing — a stream of [`Frame`]s (§10.3) sealed in
//! Noise records — and differ only in what wraps it:
//!
//! ```text
//! mux  : [u16 record len][ Noise( channel:u32 | kind:u8 | frame bytes ) ]  × N
//! quic : [u16 record len][ Noise(                        frame bytes ) ]  × N
//! ```
//!
//! The QUIC form needs no channel id, because the QUIC stream *is* the channel,
//! and no credit segments, because QUIC flow-controls each stream itself. That
//! deletion is the whole reason the QUIC binding does not route through
//! [`crate::mux`]: reusing the userspace multiplexer over QUIC would put every
//! logical stream back into one ordered byte stream and reintroduce exactly the
//! head-of-line blocking QUIC exists to avoid.
//!
//! It also removes the 256 KiB single-frame cap the mux imposes (R25 in §19):
//! mux credit is returned when a *whole frame* is consumed, so a frame larger
//! than the receive window can never be reassembled. QUIC flow-controls a byte
//! stream instead, so the QUIC binding carries the protocol's full 32 MiB frame.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use gonomad_core::session::{NOISE_MAX_MESSAGE_LEN, NOISE_TAG_LEN};
use gonomad_core::{Session, MAX_PLAINTEXT_LEN};
use gonomad_proto::frame::HEADER_LEN;
use gonomad_proto::Frame;

use crate::error::{from_session, ProtocolViolation, Result, TransportError};
use crate::mux::{MuxRecv, MuxSend};

/// Identifies one logical stream inside a connection.
///
/// A `u64` because that is what QUIC uses. The mux's channel ids are `u32` and
/// widen into it, so the two backends report ids from one space and a log line is
/// comparable across tiers.
pub type StreamId = u64;

/// The control stream (§10.2): the first stream the initiator opens.
///
/// Zero on both backends, and not by coincidence — the mux borrowed QUIC's
/// stream-id parity trick, so the dialling side's first bidirectional stream is
/// numbered 0 either way.
pub const CONTROL_STREAM: StreamId = 0;

/// Bytes read from a QUIC stream per call.
const READ_CHUNK: usize = 16 * 1024;

/// Bytes of length prefix in front of each Noise record.
const RECORD_PREFIX_LEN: usize = 2;

// A `u16` prefix cannot describe a record longer than a Noise message, so an
// over-long claim is *unrepresentable* rather than something the reader has to
// validate. Asserted here rather than in a test so that widening the prefix
// without widening the scratch buffer fails to compile.
const _: () = assert!(
    u16::MAX as usize <= NOISE_MAX_MESSAGE_LEN,
    "the record prefix must not be able to describe more than one Noise message"
);

/// The write half of a logical stream.
///
/// On the mux backend, sending parks when the channel is out of credit; that
/// parking happens on *this* stream's future rather than on the connection, so a
/// bulk transfer waiting for window does not delay a keystroke. On the QUIC
/// backend the same property comes from QUIC's per-stream flow control, one layer
/// down and with loss recovery included.
pub struct SendStream(SendBackend);

enum SendBackend {
    Mux(MuxSend),
    Quic(QuicSend),
}

impl SendStream {
    /// Wraps a multiplexed channel.
    pub(crate) const fn from_mux(inner: MuxSend) -> Self {
        Self(SendBackend::Mux(inner))
    }

    /// Wraps a QUIC stream and the Noise session that seals it.
    pub(crate) const fn from_quic(inner: QuicSend) -> Self {
        Self(SendBackend::Quic(inner))
    }

    /// This stream's identifier within its connection.
    #[must_use]
    pub fn id(&self) -> StreamId {
        match &self.0 {
            SendBackend::Mux(inner) => StreamId::from(inner.id()),
            SendBackend::Quic(inner) => inner.id,
        }
    }

    /// Sends one frame, waiting for flow-control credit as needed.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::FrameTooLarge`] when the payload exceeds the
    /// binding's per-frame cap, [`TransportError::StreamClosed`] when this stream
    /// has been torn down, or the connection's close reason once the link is gone.
    pub async fn send(&mut self, frame: &Frame) -> Result<()> {
        match &mut self.0 {
            SendBackend::Mux(inner) => inner.send(frame).await,
            SendBackend::Quic(inner) => inner.send(frame).await,
        }
    }

    /// Closes this stream and tells the peer, leaving the connection open.
    pub fn finish(self) {
        match self.0 {
            SendBackend::Mux(inner) => inner.finish(),
            SendBackend::Quic(inner) => inner.finish(),
        }
    }
}

impl core::fmt::Debug for SendStream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SendStream")
            .field("stream", &self.id())
            .field(
                "backend",
                match &self.0 {
                    SendBackend::Mux(_) => &"mux",
                    SendBackend::Quic(_) => &"quic",
                },
            )
            .finish_non_exhaustive()
    }
}

/// The read half of a logical stream.
pub struct RecvStream(RecvBackend);

enum RecvBackend {
    Mux(MuxRecv),
    Quic(QuicRecv),
}

impl RecvStream {
    /// Wraps a multiplexed channel.
    pub(crate) const fn from_mux(inner: MuxRecv) -> Self {
        Self(RecvBackend::Mux(inner))
    }

    /// Wraps a QUIC stream and the Noise session that opens it.
    pub(crate) const fn from_quic(inner: QuicRecv) -> Self {
        Self(RecvBackend::Quic(inner))
    }

    /// This stream's identifier within its connection.
    #[must_use]
    pub fn id(&self) -> StreamId {
        match &self.0 {
            RecvBackend::Mux(inner) => StreamId::from(inner.id()),
            RecvBackend::Quic(inner) => inner.id,
        }
    }

    /// Receives the next frame.
    ///
    /// Returns `Ok(None)` when the peer closed this stream or the connection
    /// cleanly, and an error when the link died with bytes still in flight. The
    /// distinction matters to the caller: a clean close is a finished transfer, an
    /// abrupt one is a transfer that must be retried.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ConnectionLost`] after an abrupt disconnect, or
    /// the specific protocol violation that tore the stream down.
    pub async fn recv(&mut self) -> Result<Option<Frame>> {
        match &mut self.0 {
            RecvBackend::Mux(inner) => inner.recv().await,
            RecvBackend::Quic(inner) => inner.recv().await,
        }
    }
}

impl core::fmt::Debug for RecvStream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecvStream")
            .field("stream", &self.id())
            .field(
                "backend",
                match &self.0 {
                    RecvBackend::Mux(_) => &"mux",
                    RecvBackend::Quic(_) => &"quic",
                },
            )
            .finish_non_exhaustive()
    }
}

/// The Noise session sealing one QUIC stream.
///
/// One session **per stream**, not one per connection, and that is the load-bearing
/// decision in this module. `snow`'s transport state carries an implicit nonce
/// counter per direction, so it can only decrypt messages in the order they were
/// encrypted. Sharing one session across several QUIC streams would therefore make
/// every stream wait for every other stream's records to arrive in order — which is
/// head-of-line blocking rebuilt in userspace, on top of the transport chosen
/// specifically to avoid it (§4.4). A session per stream keeps the streams genuinely
/// independent, and costs one extra Noise handshake per stream (see
/// [`crate::iroh`], which pays it).
///
/// Behind a mutex because the send and receive halves are separate objects owned by
/// different tasks, while `snow` keeps both directions' cipher states in one value.
/// The lock is never held across an `await`.
pub(crate) struct StreamCrypto(Mutex<Session>);

impl StreamCrypto {
    /// Wraps a freshly completed session.
    pub(crate) fn new(session: Session) -> Self {
        Self(Mutex::new(session))
    }

    fn guard(&self) -> MutexGuard<'_, Session> {
        // Recover rather than panic. Every critical section here is a few
        // arithmetic operations and cannot panic, so poisoning should be
        // impossible — but "should be impossible" is not a reason to add a panic
        // to the read path of a network daemon.
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn seal(&self, plaintext: &[u8], out: &mut [u8]) -> Result<usize> {
        self.guard().encrypt(plaintext, out).map_err(from_session)
    }

    fn open(&self, ciphertext: &[u8], out: &mut [u8]) -> Result<usize> {
        self.guard().decrypt(ciphertext, out).map_err(from_session)
    }
}

/// The write half of one Noise-sealed QUIC stream.
pub(crate) struct QuicSend {
    id: StreamId,
    send: ::iroh::endpoint::SendStream,
    crypto: Arc<StreamCrypto>,
    max_frame_len: usize,
}

impl QuicSend {
    pub(crate) const fn new(
        id: StreamId,
        send: ::iroh::endpoint::SendStream,
        crypto: Arc<StreamCrypto>,
        max_frame_len: usize,
    ) -> Self {
        Self {
            id,
            send,
            crypto,
            max_frame_len,
        }
    }

    /// Seals a frame into as many records as it needs and writes them.
    ///
    /// One `write_all` for the whole frame rather than one per record: QUIC will
    /// pack them into packets itself, and a syscall per 64 KiB is pure loss.
    async fn send(&mut self, frame: &Frame) -> Result<()> {
        if frame.payload.len() > self.max_frame_len {
            return Err(TransportError::FrameTooLarge {
                len: frame.payload.len(),
                max: self.max_frame_len,
            });
        }
        let bytes = frame.encode();
        let mut out = Vec::with_capacity(bytes.len() + NOISE_TAG_LEN * 8);
        for chunk in bytes.chunks(MAX_PLAINTEXT_LEN) {
            let prefix_at = out.len();
            out.extend_from_slice(&[0u8; RECORD_PREFIX_LEN]);
            let body_at = out.len();
            out.resize(body_at + chunk.len() + NOISE_TAG_LEN, 0);
            let written = self.crypto.seal(chunk, &mut out[body_at..])?;
            out.truncate(body_at + written);
            // `written` is at most MAX_PLAINTEXT_LEN + tag = 65535, so the u16
            // fits by construction; `try_from` is here so that a future change to
            // the record budget fails loudly instead of truncating a prefix.
            let len = u16::try_from(written).map_err(|_| TransportError::Crypto)?;
            out[prefix_at..body_at].copy_from_slice(&len.to_be_bytes());
        }
        self.send
            .write_all(&out)
            .await
            .map_err(|_| TransportError::ConnectionLost)
    }

    /// Finishes the stream, which is how the peer's `recv` learns it ended.
    fn finish(mut self) {
        // A failure here means the stream was already gone, which is exactly what
        // finishing was asking for.
        drop(self.send.finish());
    }
}

/// The read half of one Noise-sealed QUIC stream.
pub(crate) struct QuicRecv {
    id: StreamId,
    recv: ::iroh::endpoint::RecvStream,
    crypto: Arc<StreamCrypto>,
    max_frame_len: usize,
    /// Ciphertext read from QUIC but not yet split into whole records.
    pending: Vec<u8>,
    /// Decrypted bytes of a frame that is not yet complete.
    assembler: Vec<u8>,
    /// Scratch for one record's plaintext, reused rather than reallocated.
    plaintext: Vec<u8>,
    /// Bytes read per call, reused for the same reason.
    chunk: Vec<u8>,
}

impl QuicRecv {
    pub(crate) fn new(
        id: StreamId,
        recv: ::iroh::endpoint::RecvStream,
        crypto: Arc<StreamCrypto>,
        max_frame_len: usize,
    ) -> Self {
        Self {
            id,
            recv,
            crypto,
            max_frame_len,
            pending: Vec::new(),
            assembler: Vec::new(),
            plaintext: vec![0u8; MAX_PLAINTEXT_LEN],
            chunk: vec![0u8; READ_CHUNK],
        }
    }

    /// Reads until one whole frame is available.
    async fn recv(&mut self) -> Result<Option<Frame>> {
        loop {
            if let Some(frame) = self.take_frame()? {
                return Ok(Some(frame));
            }
            // Two disjoint fields, so this borrows cleanly.
            let read = self
                .recv
                .read(&mut self.chunk)
                .await
                .map_err(|_| TransportError::ConnectionLost)?;
            match read {
                // A clean finish lands exactly on a frame boundary. Anything left
                // over means the peer vanished mid-frame, which the caller must be
                // able to tell apart from a completed transfer.
                None => {
                    return if self.pending.is_empty() && self.assembler.is_empty() {
                        Ok(None)
                    } else {
                        Err(TransportError::ConnectionLost)
                    };
                }
                Some(n) => self.pending.extend_from_slice(&self.chunk[..n]),
            }
        }
    }

    /// Decrypts and reassembles as far as the buffered bytes allow.
    ///
    /// Returns `Ok(None)` when more bytes are needed. Every failure here is fatal
    /// to the stream, and none of them may panic: this runs on bytes chosen by
    /// whatever is on the other end.
    fn take_frame(&mut self) -> Result<Option<Frame>> {
        loop {
            // A frame's declared length is attacker-controlled, so it is checked
            // against the cap before the assembler is allowed to grow to hold it.
            if self.assembler.len() >= HEADER_LEN {
                let declared = u32::from_be_bytes([
                    self.assembler[0],
                    self.assembler[1],
                    self.assembler[2],
                    self.assembler[3],
                ]) as usize;
                if declared > self.max_frame_len {
                    return Err(ProtocolViolation::OversizedFrame {
                        len: declared,
                        max: self.max_frame_len,
                    }
                    .into());
                }
            }
            if let Some((frame, used)) = Frame::decode(&self.assembler)? {
                self.assembler.drain(..used);
                return Ok(Some(frame));
            }
            if !self.open_one_record()? {
                return Ok(None);
            }
        }
    }

    /// Decrypts one complete record from `pending` into the assembler.
    ///
    /// Returns `false` when `pending` does not yet hold a whole record.
    fn open_one_record(&mut self) -> Result<bool> {
        if self.pending.len() < RECORD_PREFIX_LEN {
            return Ok(false);
        }
        let len = usize::from(u16::from_be_bytes([self.pending[0], self.pending[1]]));
        if len < NOISE_TAG_LEN {
            // Even an empty plaintext seals to exactly one tag, so anything
            // shorter cannot be a record this build produced.
            return Err(ProtocolViolation::ShortRecord { len }.into());
        }
        let end = RECORD_PREFIX_LEN + len;
        if self.pending.len() < end {
            return Ok(false);
        }
        let written = self
            .crypto
            .open(&self.pending[RECORD_PREFIX_LEN..end], &mut self.plaintext)?;
        // The bound on reassembly: one frame, header included, and no more. Without
        // it a peer could stream records forever on a frame it never completes.
        let ceiling = self.max_frame_len.saturating_add(HEADER_LEN);
        if self.assembler.len().saturating_add(written) > ceiling {
            return Err(ProtocolViolation::OversizedFrame {
                len: self.assembler.len().saturating_add(written),
                max: ceiling,
            }
            .into());
        }
        self.assembler.extend_from_slice(&self.plaintext[..written]);
        self.pending.drain(..end);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_control_stream_is_stream_zero_on_both_backends() {
        // The §10.2 convention. It only holds because the mux copied QUIC's
        // stream-id parity, so it is worth an assertion rather than a comment.
        assert_eq!(CONTROL_STREAM, 0);
        assert_eq!(StreamId::from(crate::mux::CONTROL_CHANNEL), CONTROL_STREAM);
    }
}
