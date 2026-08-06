//! # GoNomad transport
//!
//! Tier 0 of the transport ladder (`ARCHITECTURE.md` §4.2): **LAN direct**. A
//! phone and a daemon on the same Wi-Fi, authenticated with Noise IK, framed
//! with the §10.3 codec, and multiplexed into the independent logical streams
//! §10.2 asks for.
//!
//! ## What this is, and what it is not
//!
//! This slice is **TCP + Noise, not QUIC**. That is a deliberate scope decision,
//! not an oversight. Tier 0 is the rung where there is no NAT to traverse and no
//! relay to fall back to, so it is the one rung that can be built without iroh —
//! and building it first means pairing, the session layer, the framing and the
//! stream topology are all exercised end-to-end over a real socket before the
//! NAT-traversal machinery lands.
//!
//! iroh brings Tiers 1 and 2 (hole-punched direct QUIC, and relayed QUIC). When
//! it does, it implements the same [`Transport`] and [`Conn`] traits from §4.5
//! and nothing above this crate changes.
//!
//! ## What changes when iroh lands
//!
//! Worth stating precisely, because these are the places where the TCP binding
//! behaves differently from what QUIC would give:
//!
//! | Property | This binding (Tier 0) | iroh / QUIC (Tiers 1–2) |
//! |---|---|---|
//! | Stream independence | Userspace mux with credit windows. Starvation prevented; **head-of-line blocking on packet loss is not** (§10.6) | Native streams, independent loss recovery |
//! | Network change | 4-tuple identity: the socket dies and the session reconnects | Connection migration keeps the session alive (§4.4) |
//! | Reconnect cost | Full TCP + Noise handshake, two flights | 0-RTT resumption from a cached ticket |
//! | Addressing | A `SocketAddr` from the QR's hints | A `NodeId`; addresses are discovered and change freely |
//! | Max single frame | Capped by [`MuxConfig::max_frame_len`], well below the protocol's 32 MiB | The protocol's full 32 MiB |
//! | Path changes | [`Conn::path_changes`] never fires | Fires on migration and on relay→direct upgrade |
//!
//! ## Layout
//!
//! | Module | Contents |
//! |---|---|
//! | [`traits`] | The §4.5 abstraction: [`Transport`], [`Conn`], [`PathInfo`], [`Tier`] |
//! | [`tcp`] | The Tier 0 binding: listen, dial, Noise IK handshake |
//! | [`mux`] | Channel ids and credit-based flow control over one byte stream |
//! | [`discovery`] | Enumerating the addresses that belong in a pairing QR |
//! | [`error`] | [`TransportError`], which leaks neither `std::io::Error` nor `snow` types |
//!
//! ## Design rules
//!
//! 1. **Nothing panics on socket input.** Every parser runs on bytes chosen by a
//!    peer that may be hostile, before *and* after authentication.
//! 2. **Nothing is plaintext after the handshake** but the 2-byte record length,
//!    which carries no semantics.
//! 3. **Every resource a peer can cause us to allocate is bounded**: credit
//!    windows, channel counts, handshake concurrency, and handshake time (§3.8).
//! 4. **No `unsafe`**, enforced by the `[lints]` table.
//!
//! ## Example
//!
//! ```no_run
//! use std::sync::Arc;
//! use gonomad_core::DeviceIdentity;
//! use gonomad_transport::{
//!     AddrHint, Allowlist, ClientConfig, PeerId, ServerConfig, TcpTransport,
//! };
//!
//! # async fn run() -> Result<(), gonomad_transport::TransportError> {
//! let daemon = Arc::new(DeviceIdentity::generate());
//! let phone = Arc::new(DeviceIdentity::generate());
//!
//! // Daemon: listen, admitting only paired devices.
//! let policy = Arc::new(Allowlist::new(vec![phone.noise_public_key()]));
//! let server = TcpTransport::bind(
//!     "0.0.0.0:0".parse().expect("literal"),
//!     ServerConfig::reconnect(Arc::clone(&daemon), policy),
//! )
//! .await?;
//!
//! // Phone: dial the hints from the pairing QR.
//! let client = TcpTransport::client(ClientConfig::reconnect(phone))?;
//! let peer = PeerId::from_noise_key(daemon.noise_public_key());
//! let hints = [AddrHint::Direct(server.local_addr().expect("bound"))];
//! let conn = client.connect_lan(peer, &hints).await?;
//!
//! // The first stream the initiator opens is the control stream (§10.2).
//! let (mut tx, mut rx) = conn.open_bi()?;
//! # Ok(())
//! # }
//! ```

// Lints are configured in this crate's `[lints]` table in Cargo.toml.
// Do not duplicate them here: source-level attributes silently override it.

pub mod discovery;
pub mod error;
pub mod mux;
pub mod tcp;
pub mod traits;

pub use discovery::{addr_hints, local_ipv4_addresses};
pub use error::{ProtocolViolation, Result, TransportError};
pub use mux::{
    ChannelId, Mux, MuxConfig, RecvStream, Role, SendStream, CONTROL_CHANNEL, MAX_SEGMENT_BODY,
};
pub use tcp::{
    ClientConfig, ServerConfig, TcpConnection, TcpTransport, DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_HANDSHAKE_TIMEOUT, DEFAULT_PORT,
};
pub use traits::{
    AddrHint, AllowAny, Allowlist, BoxFuture, Conn, Discovery, PathInfo, PeerId, PeerPolicy, Tier,
    Transport,
};
