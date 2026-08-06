//! A credit-based channel multiplexer over one encrypted byte stream.
//!
//! # Why this exists, and what it costs
//!
//! `ARCHITECTURE.md` §10.2 wants independent logical streams: a control stream,
//! one per PTY, one per bulk transfer, one per subscription. QUIC provides that
//! natively, with per-stream flow control and per-stream loss recovery, and
//! §4.4 is explicit that this is one of the three properties that decide the
//! product. TCP provides exactly one ordered byte stream.
//!
//! So Tier 0 does what §10.6 specifies for the non-QUIC binding: prepend a
//! 4-byte channel id and add a `WINDOW_UPDATE`-style credit scheme borrowed from
//! HTTP/2, because the problem is identical.
//!
//! **This binding accepts head-of-line blocking, and that is not a bug we
//! intend to fix here.** Credits stop a 40 MB download from *starving* a
//! keystroke — the bulk channel runs out of window and its sender parks while
//! the control channel keeps its own credit and keeps moving. What credits
//! cannot fix is packet loss: one lost TCP segment stalls the kernel's receive
//! queue, and every channel behind it waits, because they share one sequence
//! space. QUIC avoids that by giving each stream its own loss recovery. The
//! honest summary is:
//!
//! | Failure | This binding | QUIC / iroh |
//! |---|---|---|
//! | Bulk transfer saturating the link | Bounded by per-channel credit | Bounded by per-stream flow control |
//! | A lost packet during a bulk transfer | **Every channel stalls** | Only the affected stream stalls |
//! | Network change (Wi-Fi → LTE) | **Socket dies, reconnect** | Connection migrates, session survives |
//!
//! Rows two and three are why this is Tier 0 and not the destination.
//!
//! # Wire format
//!
//! Two nested layers sit between the socket and [`gonomad_proto::Frame`].
//!
//! ```text
//! ── on the socket ─────────────────────────────────────────────────────────
//! ┌────────────┬────────────────────────────────────────────┐
//! │ len: u16   │ Noise ciphertext (len bytes, incl. 16B tag) │   × N records
//! │ big-endian │                                            │
//! └────────────┴────────────────────────────────────────────┘
//!
//! ── inside one record, after Session::decrypt ─────────────────────────────
//! ┌──────────────┬──────────┬───────────────────────────────┐
//! │ channel: u32 │ kind: u8 │ body                          │
//! │ big-endian   │          │                               │
//! └──────────────┴──────────┴───────────────────────────────┘
//!
//! ── the DATA body is an opaque slice of the channel's frame byte stream ───
//! ┌────────────┬───────────┬──────────────────────────────┐
//! │ len: u32   │ flags: u8 │ payload                      │   (§10.3)
//! └────────────┴───────────┴──────────────────────────────┘
//! ```
//!
//! **Why `u16` for the record prefix and not [`gonomad_proto::Frame`].** A Noise
//! message cannot exceed 65535 bytes — that is the Noise specification's hard
//! limit, not a choice — so a `u16` makes an over-long claim *unrepresentable*
//! rather than something to validate after the fact. Reusing `Frame` here would
//! also put an attacker-controlled flags byte in front of the AEAD, adding a
//! parsed field before anything has been authenticated. The record prefix is the
//! only plaintext byte pair on the wire after the handshake, and it carries no
//! semantics beyond "this many bytes".
//!
//! **Why a channel id inside the ciphertext, not outside.** Putting it outside
//! would tell a passive observer how many terminals are open and how traffic
//! splits between control and bulk. Inside, it is covered by the AEAD, so a
//! relay (or, here, anything on the LAN) sees only record sizes and timing.
//!
//! **Why a DATA body carries an opaque byte slice rather than a whole frame.**
//! A frame may exceed one Noise record, so frames are chunked and the receiver
//! reassembles with [`gonomad_proto::Frame::decode`], which is already a
//! streaming codec that returns `Ok(None)` on a partial buffer. Chunking is also
//! what makes interleaving possible: a large frame yields the writer between
//! chunks instead of monopolising it.
//!
//! # Channel numbering
//!
//! The initiator opens even ids, the responder odd ones, so both sides allocate
//! concurrently with no negotiation. This is QUIC's stream-id parity trick, and
//! it means channel 0 is by convention the control stream — the first stream the
//! initiator opens (§10.2).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use gonomad_core::session::NOISE_TAG_LEN;
use gonomad_core::{Session, MAX_PLAINTEXT_LEN};
use gonomad_proto::frame::HEADER_LEN;
use gonomad_proto::Frame;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Notify, Semaphore};
use tokio::task::JoinHandle;

use crate::error::{from_session, ProtocolViolation, Result, TransportError};

/// Identifies one logical stream inside a connection.
pub type ChannelId = u32;

/// The control channel (§10.2): the first stream the initiator opens.
pub const CONTROL_CHANNEL: ChannelId = 0;

/// Bytes of mux segment header: the channel id plus the kind byte.
pub const SEGMENT_HEADER_LEN: usize = 5;

/// Bytes of record-length prefix on the wire.
pub const RECORD_PREFIX_LEN: usize = 2;

/// Largest DATA body that fits in one Noise record.
pub const MAX_SEGMENT_BODY: usize = MAX_PLAINTEXT_LEN - SEGMENT_HEADER_LEN;

/// A new channel is being opened by the sender. Body is empty.
const KIND_OPEN: u8 = 0;
/// Opaque bytes of the channel's frame stream.
const KIND_DATA: u8 = 1;
/// Grants the peer `u32` more bytes of send credit on this channel.
const KIND_WINDOW: u8 = 2;
/// Tears the channel down in both directions. Body is empty.
const KIND_RESET: u8 = 3;

/// How many segments the writer coalesces into a single socket write.
///
/// One `write_all` per segment would cost a syscall per 64 KiB at best and per
/// keystroke at worst. Batching also lets several small control frames share a
/// packet, which is the same motivation as the 16 ms input-coalescing window in
/// §14.2.
const WRITE_BATCH_SEGMENTS: usize = 16;

/// Bytes read from the socket per syscall.
const READ_CHUNK: usize = 16 * 1024;

/// How many closed channel ids are remembered.
///
/// A segment that crosses in flight with a teardown must be ignored, not treated
/// as a protocol violation, or an ordinary race would drop the connection. The
/// memory is bounded because it is attacker-influenced: a peer that opens and
/// closes channels in a loop must not be able to grow it without limit.
const RETIRED_MEMORY: usize = 4096;

/// Which side of the connection this endpoint is.
///
/// Determines the channel-id parity, and nothing else — after the handshake the
/// protocol is symmetric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The dialling side (the phone). Opens even channel ids, starting at 0.
    Initiator,
    /// The listening side (the daemon). Opens odd channel ids, starting at 1.
    Responder,
}

impl Role {
    /// The first channel id this side may allocate.
    const fn first_channel(self) -> ChannelId {
        match self {
            Self::Initiator => 0,
            Self::Responder => 1,
        }
    }

    /// The low bit every channel id opened by the *peer* must have.
    const fn peer_parity(self) -> u32 {
        match self {
            Self::Initiator => 1,
            Self::Responder => 0,
        }
    }
}

/// Tuning for the multiplexer.
///
/// The defaults are sized for Tier 0 — a LAN, sub-millisecond RTT — where the
/// bandwidth-delay product of a gigabit link is around 125 KB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MuxConfig {
    /// Bytes each channel may have in flight before it must wait for credit.
    ///
    /// This is the memory a hostile peer can pin per channel, so it is a
    /// security bound as much as a performance one (§3.8).
    pub initial_window: u32,

    /// Largest [`gonomad_proto::Frame`] payload this binding will carry.
    ///
    /// **Lower than `gonomad_proto::frame::MAX_PAYLOAD_LEN` (32 MiB), and that
    /// is deliberate.** Credit is returned when the application consumes a whole
    /// frame, so a frame larger than the window could never be reassembled: the
    /// sender would block waiting for credit the receiver cannot return until
    /// the frame completes. Capping the frame below the window makes that
    /// deadlock unrepresentable.
    ///
    /// QUIC does not need this cap, because its flow control operates on a byte
    /// stream rather than on whole application messages. When iroh lands, this
    /// field goes away and 32 MiB single-frame responses become possible again.
    /// Until then, larger responses chunk across frames and terminate with
    /// [`gonomad_proto::FrameFlags::LAST`] — which is what that flag is for.
    pub max_frame_len: usize,

    /// Maximum concurrently open channels, in each direction combined.
    ///
    /// Bounds `max_channels × initial_window` of buffer per connection.
    pub max_channels: usize,
}

impl Default for MuxConfig {
    fn default() -> Self {
        Self {
            initial_window: 512 * 1024,
            max_frame_len: 256 * 1024,
            max_channels: 64,
        }
    }
}

impl MuxConfig {
    /// Checks the invariants the multiplexer relies on.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Config`] when the window could not hold the
    /// largest permitted frame (which would deadlock), when a limit is zero, or
    /// when the window exceeds what a semaphore can represent.
    pub fn validate(&self) -> Result<()> {
        if self.max_channels == 0 {
            return Err(TransportError::Config("max_channels must be at least 1"));
        }
        if self.max_frame_len == 0 {
            return Err(TransportError::Config("max_frame_len must be at least 1"));
        }
        if self.initial_window as usize > Semaphore::MAX_PERMITS {
            return Err(TransportError::Config(
                "initial_window exceeds the maximum representable credit",
            ));
        }
        // The deadlock guard: one whole frame, header included, must fit.
        let needed = self.max_frame_len.saturating_add(HEADER_LEN);
        if (self.initial_window as usize) < needed {
            return Err(TransportError::Config(
                "initial_window must be at least max_frame_len + frame header",
            ));
        }
        Ok(())
    }

    /// The window as a `usize`, for semaphore accounting.
    const fn window(self) -> usize {
        self.initial_window as usize
    }
}

/// One segment queued for the writer.
#[derive(Debug)]
struct Segment {
    channel: ChannelId,
    kind: u8,
    body: Vec<u8>,
}

impl Segment {
    fn new(channel: ChannelId, kind: u8, body: Vec<u8>) -> Self {
        Self {
            channel,
            kind,
            body,
        }
    }

    fn open(channel: ChannelId) -> Self {
        Self::new(channel, KIND_OPEN, Vec::new())
    }

    fn reset(channel: ChannelId) -> Self {
        Self::new(channel, KIND_RESET, Vec::new())
    }

    fn window(channel: ChannelId, credit: u32) -> Self {
        Self::new(channel, KIND_WINDOW, credit.to_be_bytes().to_vec())
    }

    fn data(channel: ChannelId, body: Vec<u8>) -> Self {
        Self::new(channel, KIND_DATA, body)
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.reserve(SEGMENT_HEADER_LEN + self.body.len());
        out.extend_from_slice(&self.channel.to_be_bytes());
        out.push(self.kind);
        out.extend_from_slice(&self.body);
    }
}

/// Per-channel receive state.
struct ChannelState {
    /// Bytes this side may still send. Replenished by the peer's WINDOW updates.
    credit: Arc<Semaphore>,
    /// Delivers reassembled frames to the [`RecvStream`].
    ///
    /// Unbounded by count, bounded by *credit* in bytes: the peer cannot have
    /// more than one window of unconsumed data outstanding, so an unbounded
    /// queue here is not an unbounded memory commitment. A bounded queue would
    /// instead make the reader task park, stalling every other channel — the
    /// exact head-of-line blocking the credit scheme exists to avoid.
    inbound: Option<mpsc::UnboundedSender<Frame>>,
    /// Bytes of a frame received but not yet complete.
    assembler: Vec<u8>,
    /// Bytes received on this channel that have not yet been credited back.
    unacked: usize,
}

/// Everything both tasks and every stream handle share.
struct Shared {
    cfg: MuxConfig,
    role: Role,
    inner: Mutex<Inner>,
    notify: Notify,
    next_local: AtomicU32,
}

/// The mutable half, behind one lock.
///
/// A `std::sync::Mutex` rather than a `tokio::sync::Mutex`: it is never held
/// across an `await`, every critical section is a handful of pointer moves, and
/// an async mutex would add a scheduler round trip to the keystroke path.
struct Inner {
    /// Flow-control and lifecycle segments. Always sent before data: they are a
    /// few bytes each, and delaying a WINDOW update behind a bulk transfer is
    /// how a credit scheme deadlocks itself.
    urgent: VecDeque<Segment>,
    /// Per-channel outbound queues. **Per-channel, not one shared queue**: a
    /// shared queue would let a bulk transfer put megabytes of chunks ahead of a
    /// keystroke and reintroduce the starvation this module exists to prevent.
    ///
    /// Holds whole [`Segment`]s rather than raw chunks so that `OPEN` and
    /// `RESET` sit **in order** with the channel's data. Routing them through
    /// `urgent` instead would send a `RESET` ahead of the bytes it is supposed
    /// to follow, and the peer would see a stream close before its last frame.
    out: BTreeMap<ChannelId, VecDeque<Segment>>,
    /// Round-robin cursor over the data queues.
    cursor: ChannelId,
    channels: BTreeMap<ChannelId, ChannelState>,
    /// Recently closed ids, so a segment that crossed in flight is ignored.
    retired: BTreeSet<ChannelId>,
    retired_order: VecDeque<ChannelId>,
    /// Delivers peer-opened channels to [`Mux::accept_bi`].
    ///
    /// Lives here, not in [`Shared`], so that shutdown can drop it. If the
    /// sender outlived the link, a caller parked in `accept_bi` when the peer
    /// vanished would wait forever instead of learning the connection died.
    accept_tx: Option<mpsc::UnboundedSender<(SendStream, RecvStream)>>,
    closed: bool,
    /// Why the link ended. `None` after a clean close.
    close_err: Option<TransportError>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        // Recover rather than panic. The crate forbids `unsafe` and every
        // critical section is panic-free, so poisoning should be impossible —
        // but "should be impossible" is not a reason to add a panic to the
        // read path of a network daemon.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn is_closed(&self) -> bool {
        self.lock().closed
    }

    /// The error a stream should report once the link is gone.
    fn close_error(&self) -> TransportError {
        let inner = self.lock();
        inner.close_err.clone().unwrap_or(TransportError::Closed)
    }

    /// Registers a channel and hands back its two stream halves.
    fn insert_channel(
        self: &Arc<Self>,
        inner: &mut Inner,
        id: ChannelId,
    ) -> (SendStream, RecvStream) {
        let credit = Arc::new(Semaphore::new(self.cfg.window()));
        let (tx, rx) = mpsc::unbounded_channel();
        inner.channels.insert(
            id,
            ChannelState {
                credit: Arc::clone(&credit),
                inbound: Some(tx),
                assembler: Vec::new(),
                unacked: 0,
            },
        );
        inner.out.entry(id).or_default();

        let guard = Arc::new(ChannelGuard {
            id,
            shared: Arc::clone(self),
        });
        (
            SendStream {
                id,
                credit,
                shared: Arc::clone(self),
                _guard: Arc::clone(&guard),
            },
            RecvStream {
                id,
                rx,
                shared: Arc::clone(self),
                _guard: guard,
            },
        )
    }

    /// Allocates the next local channel id and announces it.
    fn open_local(self: &Arc<Self>) -> Result<(SendStream, RecvStream)> {
        let id = self.next_local.fetch_add(2, Ordering::Relaxed);
        let mut inner = self.lock();
        if inner.closed {
            return Err(inner.close_err.clone().unwrap_or(TransportError::Closed));
        }
        if inner.channels.len() >= self.cfg.max_channels {
            return Err(TransportError::TooManyChannels {
                max: self.cfg.max_channels,
            });
        }
        if inner.channels.contains_key(&id) || inner.retired.contains(&id) {
            // The id space wrapped. Refuse rather than reuse an id the peer may
            // still associate with an old channel.
            return Err(TransportError::TooManyChannels {
                max: self.cfg.max_channels,
            });
        }
        let pair = self.insert_channel(&mut inner, id);
        inner.out.entry(id).or_default().push_back(Segment::open(id));
        drop(inner);
        self.notify.notify_one();
        Ok(pair)
    }

    /// Queues one chunk of a channel's frame stream.
    fn push_data(&self, id: ChannelId, chunk: Vec<u8>) -> Result<()> {
        let mut inner = self.lock();
        if inner.closed {
            return Err(inner.close_err.clone().unwrap_or(TransportError::Closed));
        }
        if !inner.channels.contains_key(&id) {
            return Err(TransportError::StreamClosed);
        }
        inner
            .out
            .entry(id)
            .or_default()
            .push_back(Segment::data(id, chunk));
        drop(inner);
        self.notify.notify_one();
        Ok(())
    }

    /// Gives the peer back credit for bytes the application has consumed.
    fn return_credit(&self, id: ChannelId, bytes: usize) {
        let Ok(credit) = u32::try_from(bytes) else {
            return;
        };
        let mut inner = self.lock();
        if inner.closed {
            return;
        }
        let Some(state) = inner.channels.get_mut(&id) else {
            return;
        };
        state.unacked = state.unacked.saturating_sub(bytes);
        inner.urgent.push_back(Segment::window(id, credit));
        drop(inner);
        self.notify.notify_one();
    }

    /// Tears down a channel locally and tells the peer.
    ///
    /// The `RESET` goes on the **end of the channel's own queue**, not into
    /// `urgent`, so the peer sees every frame already queued before it sees the
    /// close. The queue entry survives the channel so the writer can flush it.
    fn close_channel(&self, id: ChannelId) {
        let mut inner = self.lock();
        if inner.closed || inner.channels.remove(&id).is_none() {
            return;
        }
        inner.retire(id);
        inner
            .out
            .entry(id)
            .or_default()
            .push_back(Segment::reset(id));
        drop(inner);
        self.notify.notify_one();
    }

    /// Picks the next segment to write, or `None` when there is nothing to do.
    ///
    /// Priority order, and the reasoning for each step:
    ///
    /// 1. **Urgent** — `WINDOW` updates only. Four bytes each, and a delayed
    ///    credit grant is a self-inflicted stall.
    /// 2. **The control channel** — keystrokes and RPC. Small by construction
    ///    and bounded by its own credit window, so it cannot starve the rest.
    /// 3. **Round-robin over the remaining channels** — so four PTYs and a bulk
    ///    download share the link rather than the first one taking it all.
    fn take_next(&self) -> Option<Segment> {
        let mut inner = self.lock();
        if let Some(segment) = inner.urgent.pop_front() {
            return Some(segment);
        }
        let cursor = inner.cursor;
        let pick = if inner
            .out
            .get(&CONTROL_CHANNEL)
            .is_some_and(|queue| !queue.is_empty())
        {
            CONTROL_CHANNEL
        } else {
            inner
                .out
                .range(cursor..)
                .find(|(_, queue)| !queue.is_empty())
                .map(|(id, _)| *id)
                .or_else(|| {
                    inner
                        .out
                        .iter()
                        .find(|(_, queue)| !queue.is_empty())
                        .map(|(id, _)| *id)
                })?
        };
        if pick != CONTROL_CHANNEL {
            inner.cursor = pick.saturating_add(1);
        }
        let segment = inner.out.get_mut(&pick)?.pop_front()?;
        // Reclaim the queue slot once a closed channel has flushed its last
        // segment, so a long session that opens a stream per PTY does not grow
        // an entry per stream it ever had.
        let drained = inner.out.get(&pick).is_some_and(VecDeque::is_empty);
        if drained && !inner.channels.contains_key(&pick) {
            inner.out.remove(&pick);
        }
        Some(segment)
    }

    /// Marks the link dead and wakes everything waiting on it.
    fn shutdown(&self, err: Option<TransportError>) {
        let mut inner = self.lock();
        if inner.closed {
            return;
        }
        inner.closed = true;
        inner.close_err = err;
        inner.urgent.clear();
        inner.out.clear();
        // Dropped so a caller parked in `accept_bi` learns the link is gone.
        inner.accept_tx = None;
        // Dropping the inbound senders is what makes `RecvStream::recv` return,
        // and closing the semaphores is what unparks a sender blocked on credit.
        // Without both, a peer that vanishes leaves tasks waiting forever.
        for state in inner.channels.values_mut() {
            state.inbound = None;
            state.credit.close();
        }
        inner.channels.clear();
        drop(inner);
        self.notify.notify_waiters();
    }
}

impl Inner {
    fn retire(&mut self, id: ChannelId) {
        if self.retired.insert(id) {
            self.retired_order.push_back(id);
            while self.retired_order.len() > RETIRED_MEMORY {
                if let Some(old) = self.retired_order.pop_front() {
                    self.retired.remove(&old);
                }
            }
        }
    }
}

/// The write half of a logical stream.
///
/// Sending parks when the channel is out of credit. That parking is the whole
/// point: it happens on *this* channel's future, not on the connection, so a
/// bulk transfer waiting for window does not delay a keystroke.
pub struct SendStream {
    id: ChannelId,
    credit: Arc<Semaphore>,
    shared: Arc<Shared>,
    /// Held so the channel is reclaimed once both halves are gone.
    _guard: Arc<ChannelGuard>,
}

impl SendStream {
    /// This stream's channel id.
    #[must_use]
    pub const fn id(&self) -> ChannelId {
        self.id
    }

    /// Sends one frame, waiting for credit as needed.
    ///
    /// Credit is acquired per chunk rather than for the whole frame, so a large
    /// frame starts moving as soon as *some* window is available instead of
    /// waiting for enough to cover all of it.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::FrameTooLarge`] when the payload exceeds
    /// [`MuxConfig::max_frame_len`], [`TransportError::StreamClosed`] when the
    /// channel has been torn down, or the connection's close reason once the
    /// link is gone.
    pub async fn send(&mut self, frame: &Frame) -> Result<()> {
        let max = self.shared.cfg.max_frame_len;
        if frame.payload.len() > max {
            return Err(TransportError::FrameTooLarge {
                len: frame.payload.len(),
                max,
            });
        }
        let bytes = frame.encode();
        for chunk in bytes.chunks(MAX_SEGMENT_BODY) {
            let Ok(cost) = u32::try_from(chunk.len()) else {
                return Err(TransportError::FrameTooLarge {
                    len: chunk.len(),
                    max,
                });
            };
            match self.credit.acquire_many(cost).await {
                // Forgotten rather than released: these bytes are spent until
                // the peer hands them back with a WINDOW update. A permit that
                // released on drop would defeat flow control entirely.
                Ok(permit) => permit.forget(),
                Err(_) => return Err(self.closed_error()),
            }
            self.shared.push_data(self.id, chunk.to_vec())?;
        }
        Ok(())
    }

    /// Closes the channel in both directions and tells the peer.
    pub fn finish(self) {
        self.shared.close_channel(self.id);
    }

    fn closed_error(&self) -> TransportError {
        if self.shared.is_closed() {
            self.shared.close_error()
        } else {
            TransportError::StreamClosed
        }
    }
}

impl core::fmt::Debug for SendStream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SendStream")
            .field("channel", &self.id)
            .field("credit", &self.credit.available_permits())
            .finish_non_exhaustive()
    }
}

/// The read half of a logical stream.
pub struct RecvStream {
    id: ChannelId,
    rx: mpsc::UnboundedReceiver<Frame>,
    shared: Arc<Shared>,
    /// Held so the channel is reclaimed once both halves are gone.
    _guard: Arc<ChannelGuard>,
}

impl RecvStream {
    /// This stream's channel id.
    #[must_use]
    pub const fn id(&self) -> ChannelId {
        self.id
    }

    /// Receives the next frame.
    ///
    /// Returns `Ok(None)` when the peer closed the channel or the connection
    /// cleanly, and an error when the link died with bytes still in flight. The
    /// distinction matters to the caller: a clean close is a finished transfer,
    /// an abrupt one is a transfer that must be retried.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ConnectionLost`] after an abrupt disconnect, or
    /// the specific protocol violation that tore the connection down.
    pub async fn recv(&mut self) -> Result<Option<Frame>> {
        match self.rx.recv().await {
            Some(frame) => {
                // Credit is returned on *consumption*, not on arrival. Returning
                // it earlier would let the peer refill the queue faster than the
                // application drains it, which is an unbounded buffer wearing a
                // flow-control costume.
                self.shared.return_credit(self.id, frame.wire_len());
                Ok(Some(frame))
            }
            None => {
                if self.shared.is_closed() {
                    match self.shared.close_error() {
                        TransportError::Closed => Ok(None),
                        other => Err(other),
                    }
                } else {
                    // Only this channel ended; the connection is still healthy.
                    Ok(None)
                }
            }
        }
    }
}

impl core::fmt::Debug for RecvStream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecvStream")
            .field("channel", &self.id)
            .finish_non_exhaustive()
    }
}

/// Tears a channel down once both halves are gone.
///
/// Shared by the two halves so a channel survives as long as either end is still
/// in use, and is reclaimed the moment neither is — without which a session that
/// opens a stream per PTY would leak channel slots until it hit the limit.
struct ChannelGuard {
    id: ChannelId,
    shared: Arc<Shared>,
}

impl Drop for ChannelGuard {
    fn drop(&mut self) {
        self.shared.close_channel(self.id);
    }
}

/// Encrypts and decrypts records.
///
/// The session is behind a mutex because the reader and writer are separate
/// tasks and `snow`'s transport state holds both directions' cipher states in
/// one object. Two tasks rather than one `select!` loop is deliberate: with a
/// single task, a socket write that blocks on a full send buffer would also
/// block reads, and the peer waiting to send us a WINDOW update would deadlock
/// against us waiting for credit.
struct Crypto {
    session: Mutex<Session>,
}

impl Crypto {
    fn guard(&self) -> MutexGuard<'_, Session> {
        self.session.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn seal(&self, plaintext: &[u8], out: &mut [u8]) -> Result<usize> {
        self.guard().encrypt(plaintext, out).map_err(from_session)
    }

    fn open(&self, ciphertext: &[u8], out: &mut [u8]) -> Result<usize> {
        self.guard().decrypt(ciphertext, out).map_err(from_session)
    }
}

/// Aborts background tasks when the owner is dropped.
///
/// Without this, dropping a connection would leak its reader and writer, which
/// hold the socket — so the peer would never see the close and the daemon would
/// accumulate tasks for the life of the process.
pub(crate) struct TaskGuard(pub(crate) Vec<JoinHandle<()>>);

impl Drop for TaskGuard {
    fn drop(&mut self) {
        for handle in &self.0 {
            handle.abort();
        }
    }
}

/// A multiplexed, encrypted connection over one byte stream.
///
/// Generic over the byte stream rather than tied to TCP, so the same
/// multiplexer can sit on a Tier 3 tunnel (§10.6) unchanged — and so it can be
/// tested over an in-memory duplex without a socket.
pub struct Mux {
    shared: Arc<Shared>,
    accept_rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<(SendStream, RecvStream)>>,
    _tasks: TaskGuard,
}

impl Mux {
    /// Starts the reader and writer over an already-authenticated session.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Config`] when `cfg` fails [`MuxConfig::validate`].
    pub fn spawn<R, W>(
        read: R,
        write: W,
        session: Session,
        role: Role,
        cfg: MuxConfig,
    ) -> Result<Self>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        cfg.validate()?;
        let (accept_tx, accept_rx) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared {
            cfg,
            role,
            inner: Mutex::new(Inner {
                urgent: VecDeque::new(),
                out: BTreeMap::new(),
                cursor: 0,
                channels: BTreeMap::new(),
                retired: BTreeSet::new(),
                retired_order: VecDeque::new(),
                accept_tx: Some(accept_tx),
                closed: false,
                close_err: None,
            }),
            notify: Notify::new(),
            next_local: AtomicU32::new(role.first_channel()),
        });
        let crypto = Arc::new(Crypto {
            session: Mutex::new(session),
        });

        let reader = tokio::spawn({
            let shared = Arc::clone(&shared);
            let crypto = Arc::clone(&crypto);
            async move {
                let outcome = read_loop(&shared, read, &crypto).await;
                shared.shutdown(outcome.err());
            }
        });
        let writer = tokio::spawn({
            let shared = Arc::clone(&shared);
            async move {
                let outcome = write_loop(&shared, write, &crypto).await;
                shared.shutdown(outcome.err());
            }
        });

        Ok(Self {
            shared,
            accept_rx: tokio::sync::Mutex::new(accept_rx),
            _tasks: TaskGuard(vec![reader, writer]),
        })
    }

    /// Opens a new bidirectional channel.
    ///
    /// # Errors
    ///
    /// Fails once the connection is closed or the channel limit is reached.
    pub fn open_bi(&self) -> Result<(SendStream, RecvStream)> {
        self.shared.open_local()
    }

    /// Waits for the peer to open a channel.
    ///
    /// # Errors
    ///
    /// Returns the connection's close reason once the link is gone.
    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream)> {
        let mut rx = self.accept_rx.lock().await;
        rx.recv().await.ok_or_else(|| self.shared.close_error())
    }

    /// Closes the connection and every channel on it.
    pub fn close(&self) {
        self.shared.shutdown(None);
    }

    /// Whether the connection has ended.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.shared.is_closed()
    }
}

impl core::fmt::Debug for Mux {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Mux")
            .field("role", &self.shared.role)
            .field("closed", &self.shared.is_closed())
            .finish_non_exhaustive()
    }
}

/// Appends one sealed record to `out`.
fn encode_record(crypto: &Crypto, plaintext: &[u8], out: &mut Vec<u8>) -> Result<()> {
    let prefix_at = out.len();
    out.extend_from_slice(&[0u8; RECORD_PREFIX_LEN]);
    let body_at = out.len();
    out.resize(body_at + plaintext.len() + NOISE_TAG_LEN, 0);
    let written = crypto.seal(plaintext, &mut out[body_at..])?;
    out.truncate(body_at + written);
    // `written` is at most MAX_PLAINTEXT_LEN + tag = 65535, so the u16 fits by
    // construction; `try_from` is here so that a future change to the record
    // budget fails loudly instead of truncating a length prefix.
    let len = u16::try_from(written).map_err(|_| TransportError::Crypto)?;
    out[prefix_at..body_at].copy_from_slice(&len.to_be_bytes());
    Ok(())
}

/// Drains queued segments to the socket until the connection ends.
async fn write_loop<W>(shared: &Arc<Shared>, mut write: W, crypto: &Crypto) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut out = Vec::with_capacity(64 * 1024);
    let mut plaintext = Vec::with_capacity(MAX_PLAINTEXT_LEN);
    loop {
        out.clear();
        let notified = shared.notify.notified();
        tokio::pin!(notified);
        // Armed *before* the queue is inspected, so a segment queued between the
        // check and the await cannot be missed.
        notified.as_mut().enable();

        for _ in 0..WRITE_BATCH_SEGMENTS {
            let Some(segment) = shared.take_next() else {
                break;
            };
            plaintext.clear();
            segment.encode_into(&mut plaintext);
            encode_record(crypto, &plaintext, &mut out)?;
        }

        if out.is_empty() {
            if shared.is_closed() {
                return Ok(());
            }
            notified.await;
            continue;
        }

        write
            .write_all(&out)
            .await
            .map_err(|_| TransportError::ConnectionLost)?;
        write
            .flush()
            .await
            .map_err(|_| TransportError::ConnectionLost)?;
    }
}

/// Reads, decrypts and dispatches records until the connection ends.
async fn read_loop<R>(shared: &Arc<Shared>, mut read: R, crypto: &Crypto) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut pending: Vec<u8> = Vec::with_capacity(READ_CHUNK * 2);
    let mut chunk = [0u8; READ_CHUNK];
    let mut plaintext = vec![0u8; MAX_PLAINTEXT_LEN];

    loop {
        let consumed = drain_records(shared, &pending, crypto, &mut plaintext)?;
        if consumed > 0 {
            pending.drain(..consumed);
        }

        let read_bytes = read
            .read(&mut chunk)
            .await
            .map_err(|_| TransportError::ConnectionLost)?;

        if read_bytes == 0 {
            // A clean close lands exactly on a record boundary. Anything left in
            // the buffer means the peer vanished mid-record, which the caller
            // must be able to tell apart from a finished transfer.
            return if pending.is_empty() {
                Ok(())
            } else {
                Err(TransportError::ConnectionLost)
            };
        }
        pending.extend_from_slice(&chunk[..read_bytes]);
    }
}

/// Processes every complete record in `pending`, returning how many bytes were
/// consumed.
fn drain_records(
    shared: &Arc<Shared>,
    pending: &[u8],
    crypto: &Crypto,
    plaintext: &mut [u8],
) -> Result<usize> {
    let mut at = 0usize;
    loop {
        let rest = &pending[at..];
        if rest.len() < RECORD_PREFIX_LEN {
            return Ok(at);
        }
        let len = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
        if len < NOISE_TAG_LEN {
            // Even an empty plaintext seals to exactly one tag, so anything
            // shorter cannot be a record this build produced.
            return Err(ProtocolViolation::ShortRecord { len }.into());
        }
        let end = RECORD_PREFIX_LEN + len;
        if rest.len() < end {
            return Ok(at);
        }
        let written = crypto.open(&rest[RECORD_PREFIX_LEN..end], plaintext)?;
        handle_segment(shared, &plaintext[..written])?;
        at += end;
    }
}

/// Dispatches one decrypted segment.
///
/// Every failure path here is fatal to the connection, and none of them may
/// panic: this runs on bytes chosen by whatever is on the other end of the
/// socket.
fn handle_segment(shared: &Arc<Shared>, segment: &[u8]) -> Result<()> {
    if segment.len() < SEGMENT_HEADER_LEN {
        return Err(ProtocolViolation::MalformedSegment {
            len: segment.len(),
            header: SEGMENT_HEADER_LEN,
        }
        .into());
    }
    let channel = u32::from_be_bytes([segment[0], segment[1], segment[2], segment[3]]);
    let kind = segment[4];
    let body = &segment[SEGMENT_HEADER_LEN..];

    match kind {
        KIND_OPEN => peer_open(shared, channel),
        KIND_DATA => peer_data(shared, channel, body),
        KIND_WINDOW => peer_window(shared, channel, body),
        KIND_RESET => {
            peer_reset(shared, channel);
            Ok(())
        }
        other => Err(ProtocolViolation::UnknownSegmentKind { kind: other }.into()),
    }
}

fn peer_open(shared: &Arc<Shared>, channel: ChannelId) -> Result<()> {
    if channel % 2 != shared.role.peer_parity() {
        return Err(ProtocolViolation::WrongChannelParity { channel }.into());
    }
    let mut inner = shared.lock();
    if inner.closed || inner.retired.contains(&channel) {
        return Ok(());
    }
    if inner.channels.contains_key(&channel) {
        return Err(ProtocolViolation::DuplicateChannel { channel }.into());
    }
    if inner.channels.len() >= shared.cfg.max_channels {
        return Err(ProtocolViolation::TooManyChannels {
            max: shared.cfg.max_channels,
        }
        .into());
    }
    let pair = shared.insert_channel(&mut inner, channel);
    // A dropped receiver means the application stopped accepting streams. The
    // returned pair must be dropped *after* the lock is released: dropping it
    // fires its `ChannelGuard`, which takes the same lock, and a
    // `std::sync::Mutex` is not reentrant.
    let undelivered = match inner.accept_tx.as_ref() {
        Some(tx) => tx.send(pair).err().map(|err| err.0),
        None => Some(pair),
    };
    drop(inner);
    drop(undelivered);
    Ok(())
}

fn peer_data(shared: &Arc<Shared>, channel: ChannelId, body: &[u8]) -> Result<()> {
    if body.is_empty() {
        return Ok(());
    }
    let window = shared.cfg.window();
    let max_frame = shared.cfg.max_frame_len;

    let mut inner = shared.lock();
    if inner.closed || inner.retired.contains(&channel) {
        return Ok(());
    }
    let Some(state) = inner.channels.get_mut(&channel) else {
        return Err(ProtocolViolation::UnknownChannel { channel }.into());
    };

    state.unacked = state.unacked.saturating_add(body.len());
    if state.unacked > window {
        return Err(ProtocolViolation::FlowControlExceeded { channel }.into());
    }
    state.assembler.extend_from_slice(body);

    // Bytes belonging to frames nobody will read: credited straight back so the
    // peer is not stalled by a receiver that went away.
    let mut refund = 0usize;
    loop {
        if state.assembler.len() >= HEADER_LEN {
            let declared = u32::from_be_bytes([
                state.assembler[0],
                state.assembler[1],
                state.assembler[2],
                state.assembler[3],
            ]) as usize;
            if declared > max_frame {
                return Err(ProtocolViolation::OversizedFrame {
                    len: declared,
                    max: max_frame,
                }
                .into());
            }
        }
        match Frame::decode(&state.assembler)? {
            None => break,
            Some((frame, used)) => {
                state.assembler.drain(..used);
                let delivered = state
                    .inbound
                    .as_ref()
                    .is_some_and(|tx| tx.send(frame).is_ok());
                if !delivered {
                    state.inbound = None;
                    refund = refund.saturating_add(used);
                }
            }
        }
    }

    if refund > 0 {
        if let Some(state) = inner.channels.get_mut(&channel) {
            state.unacked = state.unacked.saturating_sub(refund);
        }
        if let Ok(credit) = u32::try_from(refund) {
            inner.urgent.push_back(Segment::window(channel, credit));
            drop(inner);
            shared.notify.notify_one();
        }
    }
    Ok(())
}

fn peer_window(shared: &Arc<Shared>, channel: ChannelId, body: &[u8]) -> Result<()> {
    let Ok(raw) = <[u8; 4]>::try_from(body) else {
        return Err(ProtocolViolation::MalformedWindowUpdate { channel }.into());
    };
    let granted = u32::from_be_bytes(raw) as usize;
    let window = shared.cfg.window();

    let inner = shared.lock();
    if inner.closed || inner.retired.contains(&channel) {
        return Ok(());
    }
    let Some(state) = inner.channels.get(&channel) else {
        return Ok(());
    };
    // The peer may only hand back credit it previously consumed, so the total
    // can never exceed one window. A peer that inflates it is trying to make us
    // buffer more than we agreed to.
    if state.credit.available_permits().saturating_add(granted) > window {
        return Err(ProtocolViolation::FlowControlInflated { channel }.into());
    }
    state.credit.add_permits(granted);
    Ok(())
}

fn peer_reset(shared: &Arc<Shared>, channel: ChannelId) {
    let mut inner = shared.lock();
    if inner.closed {
        return;
    }
    if let Some(mut state) = inner.channels.remove(&channel) {
        state.inbound = None;
        state.credit.close();
    }
    inner.out.remove(&channel);
    inner.retire(channel);
}

#[cfg(test)]
mod tests {
    use super::*;
    use gonomad_core::{DeviceIdentity, Handshake, Purpose};
    use gonomad_proto::FrameFlags;

    /// Runs a real Noise handshake and returns both sides' sessions.
    fn sessions() -> (Session, Session) {
        let client = DeviceIdentity::generate();
        let daemon = DeviceIdentity::generate();
        let mut init = Handshake::initiator(
            &client,
            &daemon.noise_public_key(),
            Purpose::Reconnect,
            None,
        )
        .expect("initiator");
        let mut resp = Handshake::responder(&daemon, Purpose::Reconnect, None).expect("responder");

        let mut buf = vec![0u8; 65535];
        let mut scratch = vec![0u8; 65535];
        let n = init.write_message(&[], &mut buf).expect("msg1");
        resp.read_message(&buf[..n], &mut scratch).expect("read1");
        let n = resp.write_message(&[], &mut buf).expect("msg2");
        init.read_message(&buf[..n], &mut scratch).expect("read2");

        (
            init.into_session().expect("client session"),
            resp.into_session().expect("daemon session"),
        )
    }

    /// A pair of muxes wired to each other over in-memory duplex pipes.
    fn linked(cfg: MuxConfig) -> (Mux, Mux) {
        let (client_session, daemon_session) = sessions();
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (ar, aw) = tokio::io::split(a);
        let (br, bw) = tokio::io::split(b);
        (
            Mux::spawn(ar, aw, client_session, Role::Initiator, cfg).expect("client mux"),
            Mux::spawn(br, bw, daemon_session, Role::Responder, cfg).expect("daemon mux"),
        )
    }

    fn frame(payload: &[u8]) -> Frame {
        Frame::new(FrameFlags::NONE, payload.to_vec()).expect("frame")
    }

    #[test]
    fn the_default_configuration_is_valid() {
        MuxConfig::default()
            .validate()
            .expect("defaults are usable");
    }

    #[test]
    fn a_window_too_small_for_one_frame_is_rejected_at_construction() {
        // The deadlock this guard prevents: the sender waits for credit the
        // receiver cannot return until the frame it is buffering completes.
        let cfg = MuxConfig {
            initial_window: 1024,
            max_frame_len: 1024,
            max_channels: 4,
        };
        assert!(matches!(cfg.validate(), Err(TransportError::Config(_))));
    }

    #[test]
    fn zero_limits_are_rejected() {
        let base = MuxConfig::default();
        assert!(MuxConfig {
            max_channels: 0,
            ..base
        }
        .validate()
        .is_err());
        assert!(MuxConfig {
            max_frame_len: 0,
            ..base
        }
        .validate()
        .is_err());
    }

    #[test]
    fn channel_ids_are_split_by_parity_so_both_sides_can_allocate() {
        assert_eq!(Role::Initiator.first_channel(), CONTROL_CHANNEL);
        assert_eq!(Role::Responder.first_channel() % 2, 1);
        assert_eq!(Role::Initiator.peer_parity(), 1);
        assert_eq!(Role::Responder.peer_parity(), 0);
    }

    #[test]
    fn a_segment_encodes_its_header_big_endian() {
        let mut out = Vec::new();
        Segment::window(0x0102_0304, 7).encode_into(&mut out);
        assert_eq!(&out[..4], &[1, 2, 3, 4]);
        assert_eq!(out[4], KIND_WINDOW);
        assert_eq!(&out[5..], &7u32.to_be_bytes());
    }

    #[tokio::test]
    async fn the_initiators_first_channel_is_the_control_channel() {
        let (client, daemon) = linked(MuxConfig::default());
        let (mut tx, _rx) = client.open_bi().expect("open");
        assert_eq!(tx.id(), CONTROL_CHANNEL);
        tx.send(&frame(b"hello")).await.expect("send");
        let (_, mut server_rx) = daemon.accept_bi().await.expect("accept");
        assert_eq!(server_rx.id(), CONTROL_CHANNEL);
        assert_eq!(
            server_rx
                .recv()
                .await
                .expect("recv")
                .expect("frame")
                .payload,
            b"hello"
        );
    }

    #[tokio::test]
    async fn frames_round_trip_in_both_directions() {
        let (client, daemon) = linked(MuxConfig::default());
        let (mut ctx, mut crx) = client.open_bi().expect("open");
        ctx.send(&frame(b"ping")).await.expect("send");
        let (mut dtx, mut drx) = daemon.accept_bi().await.expect("accept");
        assert_eq!(
            drx.recv().await.expect("recv").expect("frame").payload,
            b"ping"
        );
        dtx.send(&frame(b"pong")).await.expect("send back");
        assert_eq!(
            crx.recv().await.expect("recv").expect("frame").payload,
            b"pong"
        );
    }

    #[tokio::test]
    async fn a_frame_larger_than_one_record_is_chunked_and_reassembled() {
        // The property the assembler exists for: a frame that cannot fit in one
        // Noise record must still arrive as exactly one frame.
        let (client, daemon) = linked(MuxConfig::default());
        let payload = vec![0xABu8; MAX_SEGMENT_BODY * 3 + 17];
        let (mut tx, _rx) = client.open_bi().expect("open");
        let sender = tokio::spawn(async move { tx.send(&frame(&payload)).await });

        let (_, mut rx) = daemon.accept_bi().await.expect("accept");
        let got = rx.recv().await.expect("recv").expect("frame");
        assert_eq!(got.payload.len(), MAX_SEGMENT_BODY * 3 + 17);
        assert!(got.payload.iter().all(|b| *b == 0xAB));
        sender.await.expect("join").expect("send");
    }

    #[tokio::test]
    async fn a_frame_above_the_configured_cap_is_refused_locally() {
        let (client, _daemon) = linked(MuxConfig::default());
        let (mut tx, _rx) = client.open_bi().expect("open");
        let big = frame(&vec![0u8; MuxConfig::default().max_frame_len + 1]);
        assert!(matches!(
            tx.send(&big).await,
            Err(TransportError::FrameTooLarge { .. })
        ));
    }

    #[tokio::test]
    async fn dropping_both_halves_frees_the_channel_slot() {
        // Without this, a session that opens a stream per PTY exhausts the
        // channel limit and never recovers.
        let cfg = MuxConfig {
            max_channels: 2,
            ..MuxConfig::default()
        };
        let (client, _daemon) = linked(cfg);
        for _ in 0..8 {
            let pair = client.open_bi().expect("open");
            drop(pair);
        }
    }

    #[tokio::test]
    async fn exceeding_the_channel_limit_is_an_error_not_a_panic() {
        let cfg = MuxConfig {
            max_channels: 2,
            ..MuxConfig::default()
        };
        let (client, _daemon) = linked(cfg);
        let _a = client.open_bi().expect("first");
        let _b = client.open_bi().expect("second");
        assert!(matches!(
            client.open_bi(),
            Err(TransportError::TooManyChannels { max: 2 })
        ));
    }

    #[tokio::test]
    async fn closing_the_connection_wakes_a_blocked_receiver() {
        let (client, daemon) = linked(MuxConfig::default());
        let (_tx, mut rx) = client.open_bi().expect("open");
        client.close();
        assert!(rx.recv().await.expect("clean close").is_none());
        assert!(client.is_closed());
        drop(daemon);
    }

    #[tokio::test]
    async fn finishing_a_stream_ends_the_peers_receiver() {
        let (client, daemon) = linked(MuxConfig::default());
        let (mut tx, _rx) = client.open_bi().expect("open");
        tx.send(&frame(b"last")).await.expect("send");
        let (_, mut rx) = daemon.accept_bi().await.expect("accept");
        assert_eq!(
            rx.recv().await.expect("recv").expect("frame").payload,
            b"last"
        );
        tx.finish();
        assert!(rx.recv().await.expect("channel end").is_none());
    }

    #[tokio::test]
    async fn several_channels_carry_traffic_concurrently() {
        // Two channels, four frames each, both delivered in order on their own
        // channel regardless of how the writer interleaved them on the wire.
        let (client, daemon) = linked(MuxConfig::default());
        let (mut a_tx, _a_rx) = client.open_bi().expect("a");
        let (mut b_tx, _b_rx) = client.open_bi().expect("b");
        let (a_id, b_id) = (a_tx.id(), b_tx.id());

        let body = vec![0u8; 40_000];
        let sender = tokio::spawn(async move {
            for _ in 0..4 {
                a_tx.send(&frame(&body)).await.expect("a send");
                b_tx.send(&frame(&body)).await.expect("b send");
            }
        });

        let (_, mut a_rx) = daemon.accept_bi().await.expect("accept a");
        let (_, mut b_rx) = daemon.accept_bi().await.expect("accept b");
        assert_eq!((a_rx.id(), b_rx.id()), (a_id, b_id));
        for _ in 0..4 {
            assert!(a_rx.recv().await.expect("a").is_some());
            assert!(b_rx.recv().await.expect("b").is_some());
        }
        sender.await.expect("join");
    }

    proptest::proptest! {
        /// Dispatching an arbitrary decrypted segment must never panic. A peer
        /// that has completed the handshake can still be compromised, so this
        /// path is as untrusted as the pre-authentication one.
        #[test]
        fn dispatching_arbitrary_segments_never_panics(bytes: Vec<u8>) {
            let shared = Arc::new(Shared {
                cfg: MuxConfig::default(),
                role: Role::Responder,
                inner: Mutex::new(Inner {
                    urgent: VecDeque::new(),
                    out: BTreeMap::new(),
                    cursor: 0,
                    channels: BTreeMap::new(),
                    retired: BTreeSet::new(),
                    retired_order: VecDeque::new(),
                    closed: false,
                    close_err: None,
                }),
                notify: Notify::new(),
                accept_tx: mpsc::unbounded_channel().0,
                next_local: AtomicU32::new(1),
            });
            let _ = handle_segment(&shared, &bytes);
        }
    }
}
