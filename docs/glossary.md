# Glossary

GoNomad borrows vocabulary from terminal emulation, cryptography, NAT
traversal, Android platform security, and open-source governance, and the
design documents assume all of it. This page defines the terms in the order you
are likely to meet them, and points at the section of
[`../ARCHITECTURE.md`](../ARCHITECTURE.md) where each is used in anger.

Entries are alphabetical. If you are starting cold, the six that unlock the most
are [PTY](#pty), [VT and the cell grid](#vt-cell-grid), [capability
grant](#capability-grant), [`NodeId`](#nodeid), [hole punching](#hole-punching),
and [CAS write](#cas-write).

---

### 0-RTT

A QUIC feature that lets a client resume a previous connection and send
application data in its very first packet, using a cached session ticket,
instead of waiting a round trip for a handshake. In GoNomad this is why
reopening the app after a few minutes feels instant rather than merely fast,
and why reconnecting after a network change is one round trip.
`ARCHITECTURE.md` §4.4.

### ALPN

*Application-Layer Protocol Negotiation.* A TLS extension in which the client
states which application protocol it wants to speak — `h2`, `http/1.1`, or in
our case `gonomad/1` — as part of the handshake. GoNomad uses it as a gate: a
connection that does not offer `gonomad/1` is dropped during the QUIC handshake,
before any application code runs. This is one of the reasons a port scanner
finds nothing. `ARCHITECTURE.md` §3.7.

### Adapter, adapter manifest

A declarative TOML file describing how to launch an AI coding agent and how to
recognise its states from its output. Detection regexes, approval extraction,
resume arguments, and cancel keys all live in the manifest. **A new agent is
added by writing a file, not by writing code**, including by users, for internal
tools this project will never see. Manifests live in `adapters/` (shipped) and
`~/.gonomad/adapters/` (yours). `ARCHITECTURE.md` §7.2, §7.6. See also
[L0/L1/L2](#l0-l1-l2).

### Approval gating

The requirement that certain operations carry a fresh
[presence-key](#presence-key) signature — a live biometric or PIN — every time.
Reading a denylisted path, force-pushing, hard resetting, deleting a directory,
writing outside a workspace root, approving an agent's destructive action,
changing policy, and rotating the daemon identity all qualify. The signature
covers the canonical digest of the exact operation, so it cannot be harvested
for one action and spent on another. `ARCHITECTURE.md` §3.10.

### Audit chain

See [hash-chained audit log](#hash-chained-audit-log).

### CAS write

*Compare-and-swap write.* GoNomad's file-write primitive:
`fs.write(path, base_hash, edits[])`. The phone sends the hash of the content it
opened along with the edits it wants applied. The daemon re-reads the file,
hashes it, and applies the edits only if the hash still matches; otherwise it
returns `Conflict` with the current hash and attempts a three-way merge.

This makes lost updates structurally impossible. The alternative — writing the
whole buffer — would silently clobber an edit that VS Code, git, or an AI agent
made three seconds earlier, and the user would never know. GoNomad has no CRDT
because your files are concurrently edited by tools that will never speak our
protocol; CAS either applies exactly what you meant or tells you the world
moved. `ARCHITECTURE.md` §12.1, §12.2.

### CGNAT

*Carrier-grade NAT.* The address translation mobile carriers and some ISPs run
in front of their subscribers, so that many customers share one public IPv4
address. It is why port forwarding cannot work on a typical mobile connection,
and therefore why GoNomad needs [hole punching](#hole-punching) and a
[relay](#relay) rather than a listening port. Getting a connection from LTE
through CGNAT with zero router configuration is an explicit M0 spike exit
criterion.

### Capability grant

A per-device, server-side authorisation record naming exactly what that device
may do: `fs:read`, `fs:write`, `fs:secrets`, `pty:spawn`, `exec:allowlisted`,
`exec:arbitrary`, `git:read`, `git:write`, `git:dangerous`, `agent:spawn`,
`policy:write`. Some are granted by default and some — `fs:secrets`,
`git:dangerous`, `exec:arbitrary`, `policy:write` — are not.

Grants are rows in the daemon's database, editable from the laptop, viewable
from the phone, and revocable instantly. The phone never asserts its own
capabilities; it is told what it has, and every request is checked server-side
regardless. Note that `pty:spawn` transitively implies arbitrary execution,
because a shell can run anything. `ARCHITECTURE.md` §3.6.

### Cell grid

See [VT, cell grid](#vt-cell-grid).

### ConPTY

*Console Pseudo Console*, the Windows pseudo-terminal API introduced in Windows
10 1809. It is Windows' answer to the Unix [PTY](#pty), and it differs in ways
that must be designed for rather than discovered: there is no `SIGWINCH`, so
resizing is an API call (`ResizePseudoConsole`) and therefore an explicit
protocol operation; several behaviour flags matter
(`PSEUDOCONSOLE_RESIZE_QUIRK` to stop content duplicating on resize,
`PSEUDOCONSOLE_WIN32_INPUT_MODE` for full key events including modifiers,
`PSEUDOCONSOLE_PASSTHROUGH_MODE` on Windows 11 22H2+ for better VT fidelity);
and the default code page is the legacy OEM one, so UTF-8 is forced at spawn.
Windows is GoNomad's first-class host, which is a large part of why the daemon
is written in Rust — `portable-pty` is the only mature cross-platform PTY
library with real ConPTY support. `ARCHITECTURE.md` §8.2.

### DCO

*Developer Certificate of Origin.* A short statement, version 1.1, that a
contributor attaches to each commit with `git commit -s`, certifying that they
have the right to submit the contribution under the project's existing licence.
It grants the project nothing extra — unlike a **CLA**, which is a contract
transferring rights to the project owner, usually including the right to
relicense.

GoNomad requires DCO sign-off and has **no CLA**: lower friction for
contributors, sufficient for provenance, and no mechanism by which someone's
contribution could later be relicensed out from under them.
`ARCHITECTURE.md` §24.10,
[`../CONTRIBUTING.md`](../CONTRIBUTING.md#developer-certificate-of-origin).

### Denylist

See [secret denylist](#secret-denylist).

### FST index

*Finite-state transducer index.* A compressed automaton (the `fst` crate) used
to store every path in a workspace for fuzzy file open. One million paths fit in
single-digit megabytes, against roughly fifty megabytes for the same paths as a
`Vec<String>`, and prefix and Levenshtein-automaton queries run directly over
the compressed form without decompressing it.

The index is built lazily in the background on first use, persisted to
`~/.gonomad/index/<workspace>.fst`, and updated incrementally from filesystem
watcher events. It is chosen over a trie on space grounds and over `tantivy`
because a full-text search engine is far more machinery than path matching
needs. `ARCHITECTURE.md` §12.5.

### Glyph atlas

A GPU-resident texture containing every printable glyph, rasterised once per
(font, size, weight, style) combination at startup. Rendering a terminal frame
then walks the dirty-cell list and issues one textured quad per changed cell —
no text layout, no shaping, no per-frame measurement. This is what makes the
Compose `Canvas` terminal renderer both fast and small.
`ARCHITECTURE.md` §6.3.

### Hash-chained audit log

An append-only log in which each entry commits to the hash of its predecessor:

```text
entry_n = { seq, timestamp_utc, monotonic_ns, device_id, operation,
            args_digest, result, prev_hash }
hash_n  = BLAKE3(canonical_cbor(entry_n))
```

Any deletion, reordering, or modification breaks the chain, and
`gonomad audit verify` reports the exact sequence number where it broke. This
matters because an attacker who compromises the daemon will try to erase their
tracks first: a plain log lets them, a chained log makes the erasure evident.
Arguments are stored as *digests*, so the audit log does not itself become a
secret store — it records that `/x/.env` was read, not what it contained.
`ARCHITECTURE.md` §3.9.

### Hole punching

The technique that establishes a direct peer-to-peer connection between two
machines that are both behind NAT, without either opening a port. Both sides
send outbound UDP packets to each other's observed addresses, coordinated
through a rendezvous service; each outbound packet creates a NAT mapping that
lets the other side's packet in. It works through most NATs and fails through
some — symmetric NAT, [CGNAT](#cgnat) in unhelpful configurations, hostile
corporate firewalls — at which point traffic falls back to a [relay](#relay).

This is what lets GoNomad promise no port forwarding and no public IP.
`ARCHITECTURE.md` §4.2, §4.3.

### Idempotency key

A client-generated UUID attached to every mutating request and retained by the
daemon for five minutes. If a network-level retry delivers the same request
twice, the second is recognised and not re-applied — so a flaky connection
cannot double-commit or double-write. `ARCHITECTURE.md` §3.5, §11.2.

### iroh

The Rust peer-to-peer networking library GoNomad uses as its default transport:
QUIC, [hole punching](#hole-punching), and a self-hostable [relay](#relay), with
peers addressed by [`NodeId`](#nodeid) rather than IP. It was chosen over
Tailscale, Headscale, Cloudflare Tunnel, WebRTC, and raw WireGuard chiefly
because it is a *library* that compiles into both the daemon and the Android app
— no separate VPN application, no account, no conflict with a corporate VPN.
`ARCHITECTURE.md` §4.

### Job Object

A Windows kernel object that groups processes so they can be managed and
terminated together. Windows has no process groups, so killing a shell would
otherwise orphan every `node`, `python`, and `docker` process it started.
GoNomad creates one Job Object per PTY, which is what makes "close the terminal"
actually close the terminal rather than leak processes indefinitely.
`ARCHITECTURE.md` §8.2.

<a id="l0-l1-l2"></a>
### L0 / L1 / L2 — agent integration levels

A graceful ladder for integrating AI coding agents, which is what makes "future
agents" a solved problem rather than a backlog item. `ARCHITECTURE.md` §7.1.

| Level | Mechanism | Consequence |
|---|---|---|
| **L0** | Raw [PTY](#pty). Spawn the CLI, stream the grid, forward input | **Any** CLI works with zero configuration, including one released next week. This is the floor, and it means GoNomad is never blocked on someone writing an integration |
| **L1** | A declarative TOML [manifest](#adapter-adapter-manifest) turning screen output into structured events | Native UI: approval cards, diff previews, state badges. A new agent is a file, not code |
| **L2** | The tool's own machine-readable stream, such as Claude Code's streaming-JSON output mode | Strictly more reliable: no regex fragility, no ANSI parsing, nothing breaking when a vendor adjusts a spinner |

Level detection is automatic — probe for L2, fall back to a matching manifest,
else L0. Screen scraping is the fallback, not the plan. The phone's
`AgentSession` model is identical at every level and contains no vendor names.

### mDNS

*Multicast DNS.* Zero-configuration service discovery on a local network.
GoNomad advertises `_gonomad._udp.local` with its [`NodeId`](#nodeid) and port,
so a phone on the same Wi-Fi finds the laptop with sub-millisecond RTT, no
relay, and no internet at all. This is Tier 0 of the transport ladder.
`ARCHITECTURE.md` §4.6.

### Noise IK

The handshake pattern from the [Noise Protocol Framework](https://noiseprotocol.org/)
that GoNomad runs *inside* QUIC. In `IK`, the **I**nitiator's static key is
transmitted immediately and the responder's static key is already **K**nown to
the initiator — which it is, because the pairing QR carried it. That gives a
one-round-trip handshake, encrypts the initiator's identity to the responder's
key so a passive observer cannot learn which device is connecting, and
authenticates the initiator before any application data. Cipher suite:
`Noise_IK_25519_ChaChaPoly_BLAKE2s`.

Layering it inside QUIC's own TLS is deliberately redundant, so that security
is independent of transport: adding a WebSocket or tunnel fallback later cannot
weaken the threat model. `ARCHITECTURE.md` §3.4.

### NodeId

An Ed25519 public key used as a network address. In iroh you dial a peer by its
`NodeId`, not by IP — addresses change constantly on mobile (Wi-Fi → LTE →
another Wi-Fi → a fresh CGNAT mapping) while identity does not. This collapses
addressing and authentication into one fact rather than two that must be kept
consistent, and it removes an entire category of reconnection bug.
`ARCHITECTURE.md` §4.3.

### PAKE

*Password-Authenticated Key Exchange.* A protocol — SPAKE2+ or CPace in
GoNomad's case — that lets two parties establish a strong shared key from a
weak shared secret, such that each online guess costs a full protocol round
against a rate-limited server and offline brute force is impossible.

GoNomad uses one only on the **manual-entry pairing path**, where the code is
an eight-character Crockford-Base32 string worth about 40 bits. Treating 40 bits
as a bearer secret would be a genuine vulnerability; a PAKE makes it safe. The
QR path does not need one, because it carries 256 bits transferred optically.
`ARCHITECTURE.md` §9.3.

### Presence key

The second of the phone's two keys, and the thing that makes a stolen *unlocked*
phone survivable. An EC **P-256** keypair generated in
[StrongBox](#strongbox-keystore) where available, truly non-exportable, declared
with `setUserAuthenticationRequired(true)` and a **zero-second** validity
window — so every single use forces a fresh biometric or PIN, with no reusable
authentication window.

It is used exclusively to sign challenges for destructive operations. The
identity key proves *which device*; the presence key proves *a human is here,
right now, and has seen this specific operation*. The split exists because
Android's hardware-backed Keystore cannot hold Ed25519 or X25519 keys, so the
identity key is software-backed and adequate only for a locked device.
`ARCHITECTURE.md` §3.3. See also [approval gating](#approval-gating).

### PTY

*Pseudo-terminal.* A pair of virtual devices that let a program pretend to be a
terminal for another program: your shell believes it is attached to a real
terminal, while a controlling process reads its output and writes its input.
Every terminal emulator you have used works this way.

In GoNomad, PTYs are owned by the **daemon**, not by the connection that created
them. That is the central invariant: losing signal in a tunnel does not kill a
running test suite, and reconnecting restores a *view* of a session that never
stopped. On Windows the implementation is [ConPTY](#conpty).
`ARCHITECTURE.md` §2, §8.

### Reattach vs resume

Two different things that are easy to conflate, and conflating them is a bug.
**Reattach**: the agent process is still running, so attach to its existing PTY.
Instant. **Resume**: the process exited, so relaunch it with the adapter's
`resume_args` to restore the agent's own conversation state.

The phone presents both as one "continue" affordance, because from the user's
chair the distinction is an implementation detail. The daemon does the right
thing. `ARCHITECTURE.md` §7.4.

### Relay

A server that forwards packets between two peers that could not establish a
direct connection. GoNomad uses iroh's relays as Tier 2 of the transport ladder,
for [CGNAT](#cgnat), symmetric NAT, and hostile firewalls.

The relay is **untrusted by design**. Because [Noise IK](#noise-ik) sits inside
the session, it sees ciphertext and traffic timing and nothing else — it cannot
read code, commands, or output. That is what makes using the public relays safe
by default, and `iroh-relay` is self-hostable for anyone who objects to timing
metadata leaving their control. iroh keeps probing for a direct path while
relayed and upgrades transparently mid-session.
`ARCHITECTURE.md` §4.2, §4.3, and [`threat-model.md`](./threat-model.md#1-the-relay--untrusted-by-design).

### SAS

*Short Authentication String.* The six digits shown on both the laptop and the
phone during pairing, derived from the full handshake transcript
(`BLAKE2s(h_final)`, first three bytes). Two humans compare them.

With a 256-bit secret transferred optically by QR, the SAS is arguably
redundant. It is there because the QR *can* leak — photographed over a shoulder,
captured in a screen share, visible in a recording — and an attacker who has the
secret but is proxying the connection produces *different* digits on each side.
Any tampering with any handshake message changes the digits, and the mismatch is
visible to the person comparing them. The confirmation screen weights Yes and No
equally, because a visually dominant Yes trains exactly the reflex the SAS
exists to prevent. `ARCHITECTURE.md` §9.2, §3.5.

### Scrollback

The history of lines that have scrolled off the top of a terminal. In GoNomad it
is a fixed-capacity ring buffer per PTY (default 10,000 lines) held **in the
daemon**, spilled to a capped on-disk file and paged to the phone on demand. It
therefore survives disconnects and app kills, because it was never on the phone
in the first place. It is deliberately never synced into the phone's persistent
cache, because it may contain secrets that were printed to a terminal.
`ARCHITECTURE.md` §8.3.

### Secret denylist

A glob list — `**/.ssh/**`, `**/.aws/**`, `**/.env*`, `**/*.pem`, `**/*.key`,
`**/.git-credentials`, `**/.gnupg/**`, `**/.claude/**` and more — applied
*after* the workspace-root check. Reading a matching path requires both the
`fs:secrets` [capability](#capability-grant), which is denied by default, and a
fresh [presence-key](#presence-key) signature.

The concrete attack it exists to stop: a thief with an unlocked phone opens the
file tree, taps `~/.ssh/id_ed25519`, and now owns every server and repository
the developer can reach. Search results and directory listings honour the
denylist too, so secrets do not leak through grep output or filename
enumeration. Users can extend the list freely; narrowing it warns. Note that it
protects the *filesystem* only — typing `cat .env` in a terminal does not go
through it. `ARCHITECTURE.md` §3.6, §24.5.

<a id="strongbox-keystore"></a>
### StrongBox, Android Keystore

**Android Keystore** is the OS service that holds cryptographic keys on behalf
of an app such that the app can *use* them but never *read* them.
**StrongBox** is the strongest backing for it: a discrete, tamper-resistant
secure element separate from the main SoC, available on Pixel and some other
devices; where absent, keys fall back to the TEE.

The constraint that shapes GoNomad's design: **hardware-backed Keystore does not
support Ed25519 or X25519.** StrongBox and TEE keymaster support EC
P-256/P-384/P-521, RSA, and AES — not Curve25519. So the identity key used for
the Noise handshake is a software key in Keystore-encrypted storage, while the
[presence key](#presence-key) is P-256 in StrongBox. That asymmetry is not an
oversight; it is the reason the two-key split exists.
`ARCHITECTURE.md` §3.3.

### Tier ladder

GoNomad's transport preference order, attempted **concurrently** rather than in
sequence, with the fastest working path winning: Tier 0 LAN direct via
[mDNS](#mdns), Tier 1 [hole-punched](#hole-punching) direct P2P QUIC, Tier 2
[relay](#relay), Tier 3 opt-in tunnels (Tailscale, Cloudflare Tunnel, `ssh -L`,
post-MVP). The active tier is always visible in the app, because a silently
degraded session is worse than a visibly degraded one — a user who knows they
are relayed attributes slowness correctly, and one who does not files a bug.
`ARCHITECTURE.md` §4.2, §15.2.

### UniFFI

Mozilla's tool for generating safe foreign-language bindings to a Rust library.
GoNomad uses it to expose `gonomad-core` to Kotlin, including async functions
and callback interfaces adapted into Kotlin `Flow`s.

It is the mechanism behind the project's hardest architectural rule: **if logic
can live in Rust, it must.** Protocol, crypto, session state machines,
transport, reconnect policy, grid diffing, capability awareness, and caching all
live in Rust; Kotlin is Compose views and thin ViewModels. That means the
protocol is implemented exactly once, so client and server cannot drift, and a
future iOS client is a view layer rather than a rewrite.
`ARCHITECTURE.md` §6.2.

<a id="vt-cell-grid"></a>
### VT, cell grid

**VT** refers to the DEC VT-series terminals whose escape sequences every modern
terminal still emulates — the ANSI codes that move the cursor, set colours, and
clear the screen. A **cell grid** is the resulting two-dimensional array of
character cells, each holding a character, a foreground colour, a background
colour, and attribute bits.

GoNomad's central terminal decision is that the **VT emulator runs on the
server**, in the daemon, using `alacritty_terminal` as a library. The daemon
maintains the authoritative grid, and the phone is sent **cell diffs** — runs of
changed cells — rather than bytes. Three consequences justify the whole design:
reconnecting is one grid snapshot rather than a byte-stream replay; bandwidth
becomes a function of *what changes on screen* rather than of how much a program
prints, so a `yes` loop costs about what an idle prompt costs; and the phone
needs no VT parser, no ANSI state machine, and no reflow logic at all.
`ARCHITECTURE.md` §8.3, §13.1.

### Workspace root

An explicitly declared directory that a paired device is permitted to reach.
Every path in every request is canonicalised — resolving `..`, symlinks,
junctions, Windows 8.3 short names, and `\\?\` prefixes — then checked
**component-wise** to be a descendant of a root (never by string prefix, so
`/home/user/proj-evil` does not match root `/home/user/proj`), and re-validated
after opening using the file handle's identity, to close the window where a
symlink is swapped between check and use.

Windows gets extra scrutiny as the first-class host: reserved device names
(`CON`, `NUL`, `COM1`…), alternate data streams (`file.txt:hidden`), trailing
dots and spaces, and unconfigured UNC paths are all rejected. This is the
highest-consequence code in the project, which is why changes to it require
`proptest` coverage. `ARCHITECTURE.md` §3.6.
