//! # GoNomad transport
//!
//! Tiers 0 through 2 of the transport ladder (`ARCHITECTURE.md` §4.2). A phone
//! and a daemon reach each other on the same Wi-Fi, across two different
//! networks with no port forwarding, or through a relay when a NAT refuses to be
//! punched — authenticated with Noise IK, framed with the §10.3 codec, and split
//! into the independent logical streams §10.2 asks for.
//!
//! ## Two bindings, one interface
//!
//! | Rung | Binding | Carried by |
//! |---|---|---|
//! | Tier 0 — LAN direct | [`TcpTransport`] | TCP, plus the userspace multiplexer in [`mux`] |
//! | Tier 1 — hole-punched direct | [`IrohTransport`] | QUIC over iroh |
//! | Tier 2 — relayed | [`IrohTransport`] | QUIC over an iroh relay that sees only ciphertext |
//!
//! Both implement the same [`Transport`] and [`Conn`] traits from §4.5 and hand
//! out the same [`SendStream`] and [`RecvStream`], so nothing above this crate
//! knows or cares which rung is active.
//!
//! ## How the two bindings differ
//!
//! Worth stating precisely, because these are real behavioural differences and
//! not implementation detail:
//!
//! | Property | [`TcpTransport`] (Tier 0) | [`IrohTransport`] (Tiers 1–2) |
//! |---|---|---|
//! | Works off-LAN | ❌ needs a routable address | ✅ hole punching, then a relay |
//! | Addressing | A `SocketAddr` from the QR's hints | A `NodeId`; addresses are discovered and change freely |
//! | Stream independence | Userspace mux with credit windows. Starvation prevented; **head-of-line blocking on packet loss is not** (§10.6) | Native QUIC streams, independent flow control *and* loss recovery |
//! | Network change | 4-tuple identity: the socket dies and the session reconnects | QUIC migrates the connection and the session survives (§4.4) |
//! | Max single frame | Capped by [`MuxConfig::max_frame_len`] at 256 KiB (R25, §19) | The protocol's full 32 MiB |
//! | [`Conn::path_changes`] | Never fires; a TCP path cannot change | Fires on migration and on relay→direct upgrade |
//! | Cost per extra stream | Free | One round trip and one Noise handshake (see [`iroh`]) |
//!
//! Tier 0 is kept rather than retired because on a LAN it is measurably the
//! cheaper way to get a byte from A to B: one `connect`, no address discovery, no
//! hole punching, no relay to rule out.
//!
//! ## Choosing a rung is the caller's job
//!
//! There is deliberately **no `TransportLadder`** here. §4.2 wants tiers attempted
//! concurrently with the fastest working path winning, and racing them *inside*
//! this crate would be wrong in three ways:
//!
//! 1. **A pairing window allows three attempts total** (`gonomad_core::PairingWindow`).
//!    Racing two rungs during pairing spends two of them on one scan.
//! 2. **Both rungs would succeed**, on a LAN, leaving the daemon holding two
//!    authenticated connections from one device and no rule about which to keep.
//!    Deciding that is session policy, not transport policy.
//! 3. **The caller already owns reconnection** — backoff, the §15.2 connection
//!    states, and whether a rung that failed once should be tried again. A ladder
//!    in here would either duplicate that or fight it.
//!
//! So the daemon and the FFI client hold whichever transports they want, race or
//! order them as they see fit, and keep the `Box<dyn Conn>` that wins. `IrohTransport`
//! already tries the QR's pinned direct addresses first, so the common LAN case is
//! fast without a ladder at all.
//!
//! ## Layout
//!
//! | Module | Contents |
//! |---|---|
//! | [`traits`] | The §4.5 abstraction: [`Transport`], [`Conn`], [`PathInfo`], [`Tier`] |
//! | [`iroh`] | Tiers 1–2: iroh endpoints, QUIC streams, path reporting |
//! | [`tcp`] | Tier 0: listen, dial, and the LAN path |
//! | [`handshake`] | The Noise IK handshake both bindings run, and its framing |
//! | [`stream`] | [`SendStream`]/[`RecvStream`] over either backend |
//! | [`mux`] | Channel ids and credit-based flow control over one byte stream |
//! | [`discovery`] | Enumerating the addresses that belong in a pairing QR |
//! | [`error`] | [`TransportError`], which leaks neither `std::io::Error` nor `snow` types |
//!
//! ## Design rules
//!
//! 1. **Nothing panics on peer input.** Every parser runs on bytes chosen by a
//!    peer that may be hostile, before *and* after authentication.
//! 2. **Nothing is plaintext after the handshake** but the 2-byte record length,
//!    which carries no semantics. This holds on both bindings, which is the whole
//!    reason §3.4 puts Noise inside the transport.
//! 3. **Every resource a peer can cause us to allocate is bounded**: credit
//!    windows, stream counts, frame sizes, handshake concurrency, and handshake
//!    time (§3.8).
//! 4. **No `unsafe`**, enforced by the `[lints]` table.
//!
//! ## Example
//!
//! ```no_run
//! use std::sync::Arc;
//! use gonomad_core::DeviceIdentity;
//! use gonomad_transport::{
//!     AddrHint, Allowlist, Conn, IrohConfig, IrohTransport, PeerId,
//! };
//!
//! # async fn run() -> Result<(), gonomad_transport::TransportError> {
//! let daemon = Arc::new(DeviceIdentity::generate());
//! let phone = Arc::new(DeviceIdentity::generate());
//!
//! // Daemon: bind an endpoint at its derived NodeId, admitting only paired devices.
//! let policy = Arc::new(Allowlist::new(vec![phone.noise_public_key()]));
//! let server = IrohTransport::bind(IrohConfig::reconnect(Arc::clone(&daemon), policy)).await?;
//! server.online().await; // reached a relay, so the QR can pin one
//!
//! // Phone: dial the hints the pairing QR carried. The NodeId is the one that
//! // matters off-LAN; the addresses only make the first attempt faster.
//! let client = IrohTransport::bind(IrohConfig::dialer(phone)).await?;
//! let peer = PeerId::from_noise_key(daemon.noise_public_key());
//! let conn = client.connect_iroh(peer, &server.addr_hints()).await?;
//!
//! // The first stream the dialling side opens is the control stream (§10.2).
//! let (mut tx, mut rx) = conn.open_stream().await?;
//! println!("connected over {}", conn.path_info().tier.label());
//! # Ok(())
//! # }
//! ```

// Lints are configured in this crate's `[lints]` table in Cargo.toml.
// Do not duplicate them here: source-level attributes silently override it.

pub mod discovery;
pub mod error;
pub mod handshake;
pub mod iroh;
pub mod mux;
pub mod stream;
pub mod tcp;
pub mod traits;

pub use discovery::{addr_hints, local_ipv4_addresses};
pub use error::{ProtocolViolation, Result, TransportError};
pub use iroh::{
    IrohConfig, IrohConnection, IrohTransport, RelayPolicy, DEFAULT_MAX_CONCURRENT_STREAMS,
};
pub use mux::{ChannelId, Mux, MuxConfig, Role, CONTROL_CHANNEL, MAX_SEGMENT_BODY};
pub use stream::{RecvStream, SendStream, StreamId, CONTROL_STREAM};
pub use tcp::{
    ClientConfig, ServerConfig, TcpConnection, TcpTransport, DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_HANDSHAKE_TIMEOUT, DEFAULT_PORT,
};
pub use traits::{
    AddrHint, AllowAny, Allowlist, BoxFuture, Conn, Discovery, PathInfo, PeerId, PeerPolicy, Tier,
    Transport,
};
