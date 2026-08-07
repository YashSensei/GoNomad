# GoNomad

> **Your development machine, anywhere.**

[![CI](https://github.com/YashSensei/GoNomad/actions/workflows/ci.yml/badge.svg)](https://github.com/YashSensei/GoNomad/actions/workflows/ci.yml)
[![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](./LICENSE)
[![Status: pre-alpha](https://img.shields.io/badge/status-pre--alpha-red.svg)](#status-pre-alpha)
[![Rust 1.75+](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](./rust-toolchain.toml)
[![Host: Windows first](https://img.shields.io/badge/host-Windows%20first-informational.svg)](#platform-support)
[![Client: Android](https://img.shields.io/badge/client-Android-informational.svg)](#platform-support)
[![DCO](https://img.shields.io/badge/DCO-sign--off%20required-lightgrey.svg)](./CONTRIBUTING.md#developer-certificate-of-origin)

GoNomad is an open-source, self-hosted mobile companion for the development
machine you already own. A small Rust daemon runs on your laptop; a native
Android app gives you a purpose-built touch interface over that machine's
filesystem, terminals, git repositories, and AI coding agents.

**It is not a desktop stream.** No VNC, no RDP, no screen mirroring, no VS Code
in a browser. Your laptop performs every computation — compiling, testing,
indexing, inference — and the phone receives *semantics*, not pixels: "the file
at line 340 changed", "cell (12,40) is now `E`". There is no cloud account, no
SaaS control plane, and no port forwarding.

---

## Status: pre-alpha

> [!WARNING]
> **GoNomad runs, but it is not ready for anything you care about.**
>
> There is no tagged release and no published artifact — `cargo install gonomad`
> does not work, and you must build the daemon and the APK yourself. Pairing and
> terminals work end to end; files, search, git, and AI agents do not exist yet,
> so most of [Quickstart](#quickstart-not-yet-functional) is still a design
> target.
>
> **The security properties on this page are written and tested, not audited.**
> One is a known gap rather than an unknown: the daemon's identity key is stored
> in a plain file, not the OS keyring, so anyone who can read your user profile
> can impersonate your machine. That alone should keep this away from anything
> valuable.
>
> The roadmap, milestone by milestone, is in [`plan.md`](./plan.md).
> The design rationale is in [`ARCHITECTURE.md`](./ARCHITECTURE.md).

### What actually exists in this repository

| Path | State |
|---|---|
| [`ARCHITECTURE.md`](./ARCHITECTURE.md) | Complete design document — the canonical *why* |
| [`plan.md`](./plan.md) | Execution roadmap, M0 through M6, with exit criteria |
| `Cargo.toml`, `rust-toolchain.toml`, `deny.toml`, `.github/workflows/` | Workspace scaffold, pinned toolchain, supply-chain gates, CI |
| `crates/gonomad-proto` | Frame layout and CBOR codec, control and event types, identifiers, the capability vocabulary, the closed error enum |
| `crates/gonomad-core` | Device identity, the pairing state machine, SAS derivation |
| `crates/gonomad-policy` | Path guards, the secret denylist, the capability engine, rate limits |
| `crates/gonomad-store` | SQLite schema and forward-only migrations, device records, the hash-chained audit log |
| `crates/gonomad-transport` | The iroh endpoint (hole-punched QUIC and a relay fallback), the LAN TCP rung, and the Noise IK/IKpsk2 session that runs inside both |
| `crates/gonomad-pty` | ConPTY, Job Object process-tree teardown, shell detection, and the server-side `vt100` screen authority |
| `crates/gonomad-server` | The daemon and the `gonomad` CLI (`init`, `pair`, `serve`, `devices`, `doctor`) |
| `crates/gonomad-ffi` | The UniFFI surface the Android app is generated from |
| `android/` | The Kotlin/Compose app: pairing, device list, and multi-tab terminals |

**It runs end to end**, on Windows, for pairing and terminals: `gonomad init`,
`gonomad pair`, scan the QR, and drive real shells from the phone in switchable
tabs that keep running while the app is backgrounded or disconnected.

Not started: the tray UI, filesystem services, search, git, AI agents, and
notifications. The Compose `Canvas` terminal renderer and cell-diff streaming are
also still outstanding — terminals currently render whole screens.

Not yet verified: NAT traversal through real home routers, and the relay fallback
under CGNAT. Both need two genuinely separate networks, so neither can be proven
from a single machine.

---

## Why this exists

Remote-access tooling divides into two camps, and neither serves a developer
holding a phone. `ARCHITECTURE.md` §1 argues this at length; the short version:

**Pixel streamers** — VNC, RDP, AnyDesk, RustDesk, TeamViewer, Chrome Remote
Desktop — transmit a rectangle of pixels laid out for a 27-inch monitor and a
mouse. On a phone that means pinch-zoom, a floating cursor, and a 6pt font.
Latency is bounded by video encoding, bandwidth by frame rate, battery by
continuous decode. They are general-purpose, which is precisely the problem:
they know nothing about files, terminals, or git, so they cannot make any of it
better.

**Cloud IDEs** — Codespaces, Gitpod, Replit, StackBlitz — are good products
attached to the wrong machine. Your SSH keys, your Docker images, your local
models, your half-finished branch, your shell history, and your paid AI CLI
subscriptions live on *your laptop*. Reproducing that environment in a
container is a project, not a session.

GoNomad takes the third position: a native mobile client that speaks semantics
to a daemon on the machine you already use. The laptop computes; the phone
renders.

### Non-goals, and why they are load-bearing

These are not merely out of scope. Each one, if admitted, collapses the design.

- **No desktop streaming, VNC, RDP, or OS mirroring.** Admitting a pixel path
  removes the incentive to design real mobile screens, and every hard UX
  problem gets deferred to "just use the desktop view". The absence of an
  escape hatch is the feature.
- **No VS Code in a browser.** `code-server` and `openvscode-server` already
  exist and are good. Rebuilding them badly, inside a WebView, on a 6-inch
  screen, is worse than either using them or building something purpose-built.
- **No central server, account, or SaaS control plane.** Not ideology: a
  self-hosted security tool whose availability depends on someone else's uptime
  is not self-hosted.
- **No provider lock-in for AI.** Any agent that runs in a terminal must work on
  day one with zero configuration.

---

## How it fits together

```text
┌────────────────────────────────────────────────┐
│  ANDROID PHONE                                 │
│  ┌──────────────────────────────────────────┐  │
│  │  Jetpack Compose UI                      │  │
│  │  terminal · editor · git · agents        │  │
│  └────────────────────┬─────────────────────┘  │
│                       │ UniFFI                 │
│  ┌────────────────────▼─────────────────────┐  │
│  │  gonomad-core + gonomad-transport        │  │
│  │  the same Rust crates the daemon runs    │  │
│  └──────────────────────────────────────────┘  │
└───────────────────────┬────────────────────────┘
         ═══════════════▼═══════════════
         ║  Noise IK inside QUIC.      ║
         ║  Mutually authenticated     ║
         ║  by device keypair.         ║
         ║  Relays see ciphertext.     ║
         ═══════════════▲═══════════════
                        │
┌───────────────────────┼──────────────────────────────────────┐
│  LAPTOP · the gonomad daemon                                 │
│  ┌────────────────────▼─────────────────────┐                │
│  │  gonomad-transport                       │  iroh · mDNS   │
│  ├──────────────────────────────────────────┤                │
│  │  gonomad-core                            │  codec, Noise  │
│  ├──────────────────────────────────────────┤                │
│  │  gonomad-policy                          │  <- EVERY      │
│  │   capabilities · path guards · limits    │     request    │
│  ├──────────────────────────────────────────┤     passes     │
│  │  services (one actor per resource)       │     through    │
│  │   pty · fs · search · git · agents       │     here       │
│  ├──────────────────────────────────────────┤                │
│  │  gonomad-store (SQLite)                  │  devices,      │
│  │                                          │  grants,       │
│  │                                          │  audit chain   │
│  └────────────────────┬─────────────────────┘                │
│                       │                                      │
│  ┌────────────────────▼───────────────────────────────────┐  │
│  │  THE MACHINE                                           │  │
│  │   filesystem · ConPTY · git · docker · node · rust     │  │
│  │   claude · codex · gemini · opencode · local models    │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

Two properties do most of the work.

**The daemon owns all long-lived state; connections are disposable.** A PTY, an
agent session, scrollback, and editor tab state belong to the daemon, not to
the socket that created them. Losing signal in a tunnel does not kill a running
test suite or an agent mid-task, and "reconnect" restores a *view* of state
that never stopped existing. Anything the phone holds must be reconstructible
from the daemon. See `ARCHITECTURE.md` §2.

**Policy sits on the only path to services.** It is structurally impossible for
a service call to skip the capability check, the path guard, or the audit
entry, rather than merely conventional. See `ARCHITECTURE.md` §2 and §3.6.

---

## Features

Nothing below is shipping. **In progress** means library code exists in this
repository with tests, but is not yet reachable from any program you can run.
**Planned** gives the milestone from [`plan.md`](./plan.md) in which the work is
scheduled.

### Transport and pairing

| Feature | Status |
|---|---|
| Frame layout, CBOR codec, version negotiation, closed error enum | In progress — M1 |
| Capability vocabulary, capability engine, rate limits | In progress — M1 |
| Path canonicalisation and workspace-root guards; the secret denylist | In progress — M1 |
| Hash-chained audit log; SQLite schema and migrations | Built |
| QR pairing: 120-second single-use window, 6-digit SAS confirmation | Built — paired from a real phone |
| iroh QUIC transport; dial a laptop by its `NodeId`, never by IP | Built — untested across real NATs |
| LAN → hole-punched direct → relay tier ladder, visible in the UI | Built — the tier reaches the UI chip |
| mDNS discovery on the local network | Planned — M1 |
| Manual-entry pairing fallback over a real PAKE (SPAKE2+/CPace) | Planned — M1 |
| Device list, per-device capability editing, instant revocation | Planned — M1 |
| WebSocket fallback binding; Tailscale/Cloudflare Tier 3 | Planned — post-MVP |

### Terminal

| Feature | Status |
|---|---|
| ConPTY on Windows with Job Object process-tree teardown | Planned — M2 |
| Server-side headless VT emulator; the phone receives cell diffs | Planned — M2 |
| Scrollback that survives disconnects and app kills | Planned — M2 |
| Compose `Canvas` renderer with a glyph atlas | Planned — M2 |
| Accessory keyboard row with sticky `Ctrl`/`Alt` and user macros | Planned — M2 |
| Tabs, live thumbnails, gestures, pinch-to-resize | Planned — M2 |
| Tappable `file:line` linkification; output folding with summaries | Planned — M2 |
| TalkBack semantics for the grid | Planned — M2 |

### Files, editor, and search

| Feature | Status |
|---|---|
| Lazy gitignore-aware listing; one recursive watcher per root | Planned — M3 |
| Compare-and-swap writes with three-way merge on conflict | Planned — M3 |
| Streaming content search; FST-backed fuzzy file open | Planned — M3 |
| CodeMirror 6 editor in a network-blocked WebView | Planned — M3 |
| Trackpad strip for sub-character cursor positioning | Planned — M3 |
| Offline read cache and an inspectable offline write queue | Planned — M3 |
| Multiple editor tabs; LSP diagnostics | Planned — post-MVP |

### Git

| Feature | Status |
|---|---|
| Status, stage/unstage, diff viewer with per-hunk staging | Planned — M4 |
| Commit that runs your hooks and uses your signing configuration | Planned — M4 |
| Push/pull/fetch through your existing credential helper and SSH agent | Planned — M4 |
| Branches, history with a graph rail, stash, conflict listing | Planned — M4 |
| `git:dangerous` gate with a biometric signature for force-push and hard reset | Planned — M4 |
| Interactive rebase, cherry-pick, blame | Planned — post-MVP |

### AI agents and notifications

| Feature | Status |
|---|---|
| L0 raw-PTY integration — any CLI agent works with zero configuration | Planned — M5 |
| L1 declarative TOML manifests — a new agent is a file, not code | Planned — M5 |
| L2 native structured protocol, with Claude Code as the reference case | Planned — M5 |
| Shipped manifests: `claude-code`, `codex`, `gemini`, `opencode`, `aider`, `generic` | Planned — M5 |
| Approval sheet rendering the *actual diff*, never the agent's summary | Planned — M5 |
| Destructiveness classification with a biometric gate; no auto-approve, ever | Planned — M5 |
| ntfy notifications with opaque encrypted payloads; in-app inbox | Planned — M5 |

### Host platform and release

| Feature | Status |
|---|---|
| Windows host (ConPTY, `ReadDirectoryChangesW`, Credential Manager) | Planned — M1–M5 |
| macOS and Linux hosts | Planned — M6 |
| Reproducible builds, `cosign` signing, SLSA provenance, verifiable APK | Planned — M6 |
| `armeabi-v7a` and `x86_64` ABIs (`arm64-v8a` only before that) | Planned — M6 |
| v0.1.0 | Planned — M6 |

---

## Quickstart (not yet functional)

> [!WARNING]
> None of these commands exist. They are reproduced from `plan.md` so the
> intended shape of the product is reviewable, and so design discussion can
> happen before the code is written.

```bash
cargo install gonomad          # or download a signed release
gonomad init                   # generate identity, print the recovery phrase
gonomad workspace add .        # declare a project root
gonomad pair                   # 120s QR — scan it, confirm the 6 digits
```

No account. No port forwarding. No reverse proxy. No DNS. No certificates.

The full intended CLI surface, the configuration file, the loopback control
socket, and the uninstall path are described in
[`docs/deployment.md`](./docs/deployment.md), which is likewise forward-looking.

---

## How it's secured

The design assumption is that a paired phone can read your source, run
arbitrary commands, and reach every credential your shell can reach. The full
argument is `ARCHITECTURE.md` §3; the disclosure process and threat-model
summary are in [`SECURITY.md`](./SECURITY.md), and the complete model with
trust boundaries is in [`docs/threat-model.md`](./docs/threat-model.md).

**No bearer tokens, anywhere.** No JWT, no session cookie, no API key, no
refresh token. Each device holds an Ed25519 keypair generated on-device; the
public key registered at pairing *is* the credential, and every connection
performs a fresh mutual authentication against it. Token theft, rotation,
replay, expiry, and blacklists are not solved so much as *dissolved*, because
none of those objects exist. The honest cost: losing the key means re-pairing.

**Nothing observable before authentication.** The daemon holds a QUIC endpoint
over UDP and a loopback-only control socket. There is no `0.0.0.0:8080`, no
HTTP surface, no login page, no health endpoint, and therefore none of the
unauthenticated-web-endpoint bug class. A connection not offering the
`gonomad/1` ALPN is dropped during the QUIC handshake, and an unpaired public
key is rejected before a single application byte is read. Pairing is the only
moment an unpaired key can be accepted: opt-in, 120 seconds, single-use, rate
limited, and requiring a human at the laptop to approve.

**Capability grants, per device.** `fs:read`, `fs:write`, `pty:spawn`,
`git:write` and their siblings are individually granted and individually
revocable, with `fs:secrets`, `git:dangerous`, `exec:arbitrary`, and
`policy:write` denied by default. Each device also reaches only explicitly
declared workspace roots, checked after canonicalisation and symlink resolution
and re-validated after open to close the TOCTOU window.

**A secret denylist, applied after the root check.** `**/.ssh/**`, `**/.env*`,
`**/*.pem`, `**/.aws/**`, `**/.git-credentials` and similar require both the
`fs:secrets` capability and a fresh hardware-backed biometric signature. Search
results and directory listings honour the denylist too, so secrets do not leak
through grep output or filename enumeration.

**A hash-chained audit log.** Every mutating operation, denial, pairing,
revocation, capability change, and approval decision is appended with a hash
committing to its predecessor, so deletion or reordering is detectable and
`gonomad audit verify` reports the exact sequence number where the chain
breaks. Arguments are recorded as digests, so the audit log does not itself
become a secret store.

**A second, hardware-bound key for destructive operations.** Reading a
denylisted path, force-pushing, deleting a directory, changing policy, or
approving an agent's destructive diff each require a fresh signature from a
StrongBox-resident P-256 presence key with a zero-second authentication
validity window — so the signature cannot be produced without a live biometric,
and it covers the digest of the exact operation about to be performed.

> [!NOTE]
> A compromised laptop OS with root or administrator access is **explicitly out
> of the threat model**. If the attacker owns the machine that runs your
> compiler, GoNomad cannot help, and any design claiming otherwise is lying.

---

## Known limitations you should read before trusting it

Beyond "it does not work yet", these are properties of the design rather than
gaps in an implementation. [`SECURITY.md`](./SECURITY.md) and
[`docs/threat-model.md`](./docs/threat-model.md) cover each in more detail.

- **Notification metadata leaks.** Payloads are always ciphertext — no
  filename, diff, command, or project name ever leaves the laptop in the clear.
  But that *a* notification occurred, when, and roughly how large it was is
  visible to whatever notification server you use, self-hosted or not. This
  cannot be hidden, and it is stated plainly rather than glossed
  (`ARCHITECTURE.md` §24.1).
- **Terminal secret redaction is best-effort.** The denylist protects the
  filesystem; typing `env` or `cat .env` does not go through it. Pattern-based
  redaction helps and will never be complete.
- **`pty:spawn` transitively grants arbitrary code execution.** A shell can run
  anything. Users who want a genuinely read-only device must withhold
  `pty:spawn`, and the pairing UI is required to say so in those words.
- **Losing the device key means re-pairing.** There is no password reset,
  because there is no password. A 24-word recovery phrase covers the *daemon's*
  identity; a lost phone is re-paired.
- **Aggressive OEM battery managers will kill connections** on some Android
  devices, in ways that are unreproducible on a Pixel (`ARCHITECTURE.md` §24.2).

---

## Platform support

| | Now targeted | Planned |
|---|---|---|
| Host | Windows, first-class (ConPTY) | macOS and Linux at M6 |
| Mobile client | Android, native Kotlin + Compose | iOS as a SwiftUI view layer over the same Rust core, post-MVP |
| Android ABI | `arm64-v8a` | `armeabi-v7a` and `x86_64` at M6 |

Android-only is a starting point, not a dead end. Everything that is not a view
— protocol, crypto, session state machines, transport, reconnect policy, grid
diffing, capability checks, caching — lives in Rust `gonomad-core` and is
exposed through UniFFI. A future iOS or desktop client reimplements views only.
That is a hard architectural rule: **if logic can live in Rust, it must**
(`ARCHITECTURE.md` §6.2).

---

## Why these technology choices

Eight of the least obvious decisions. Each is argued fully in
`ARCHITECTURE.md` §18, with the complete decision log in its appendix.

| Decision | Rejected | Why |
|---|---|---|
| **iroh** (QUIC + hole punching + self-hostable relay) | Tailscale, Headscale, Cloudflare Tunnel, WebRTC | Tailscale is excellent, but its coordination server is a SaaS account, its Android client cannot be embedded in a third-party app, and only one `VpnService` can be active at a time — so GoNomad would be a two-app product that conflicts with your corporate VPN. iroh is a library that compiles into both the daemon and the APK. |
| **Rust** | Go, Bun, Node | Ecosystem fit more than language merit: ripgrep's `ignore` and `grep-searcher`, wezterm's `portable-pty` with real ConPTY, Alacritty's VT parser. In Go those are reimplementation projects; in Node the answer is "ship ripgrep alongside". Rust is also the only option where the same crate is both the daemon and the phone's core. |
| **Server-side VT emulator**; the phone receives cell diffs | Streaming raw bytes and parsing them on the phone | Bandwidth becomes a function of what changes on screen rather than of how much a program prints, so a `yes` loop costs about what an idle prompt costs. Reconnect is one grid snapshot instead of a scrollback replay, and the phone needs no VT parser at all. |
| **Authoritative filesystem + compare-and-swap writes** | CRDT, OT | Your files are concurrently edited by VS Code, git, and AI agents, and none of them will ever speak our protocol. A CRDT would have to model them as peers and would silently produce merges no participant intended. CAS either applies exactly what you meant or tells you the world moved. |
| **The `git` CLI for mutations** (`gix` for reads) | libgit2 or gitoxide for everything | A commit from the phone must be indistinguishable from one made at the desk. Library implementations bypass credential helpers, the SSH agent, GPG signing, `pre-commit` hooks, `.gitattributes` filters, and LFS. Reads have no side effects to get wrong; mutations have every side effect to get wrong. |
| **CodeMirror 6** in a network-blocked WebView | Monaco, Sora Editor, a hand-rolled Compose editor | No acceptable native mobile code editor exists. CM6 is the only serious editor rewritten with mobile as a design goal — touch selection, IME composition, virtual keyboards. Hand-rolling that in Compose is a multi-year project that would be worse at every intermediate point. |
| **Compose `Canvas` + glyph atlas** for the terminal | xterm.js in a WebView, an `AndroidView` text renderer | The terminal is a uniform grid of monospaced cells — the easiest thing in graphics to draw quickly, and the most latency-sensitive surface in the product. Putting a browser between the server's cell diff and the screen adds a JSON parse, a DOM diff, and a layout pass to a 16 ms budget for no benefit. |
| **Noise IK inside QUIC** | QUIC's own TLS 1.3 alone | Deliberately redundant, so that security is independent of transport. Adding a WebSocket or Cloudflare fallback later cannot weaken the threat model, the relay path and the direct path have identical properties, and a reviewer audits one thing rather than one per transport. |

---

## Contributing

Contributions are welcome, and pre-alpha is when design feedback is worth the
most. Start with [`CONTRIBUTING.md`](./CONTRIBUTING.md): prerequisites, the
build and lint commands, the non-obvious rule about where lints are configured,
commit conventions, and testing expectations.

Two things worth knowing before you open anything:

- Every commit requires a **DCO sign-off** (`git commit -s`). There is no CLA.
- **Security issues never go in a public issue.** Use the private process in
  [`SECURITY.md`](./SECURITY.md).

Participation is governed by the [Code of Conduct](./CODE_OF_CONDUCT.md).

Project documentation lives in [`docs/`](./docs/README.md) — start there for the
deployment model, the full threat model, the CI reference, and a glossary of
the project's terms.

---

## No cloud, no SaaS, no telemetry

GoNomad has no account system, no control plane, and no server operated by this
project that you are required to use. Every default must keep working with the
project's infrastructure permanently offline; that is an architectural
constraint a reviewer can enforce, not a marketing line.

The daemon does not transmit file content, command output, or metadata to any
third party. There is no analytics and no usage reporting. Crash reporting, if
it is ever added, will be opt-in and self-hosted or absent — a privacy-first
tool that phones home crash dumps by default has broken its own promise. iroh's
public relays may carry your ciphertext when hole punching fails; they can be
replaced with your own `iroh-relay`, and they can never read your traffic.

---

## Licence

Apache-2.0. See [`LICENSE`](./LICENSE).

Apache-2.0 was chosen over MIT for its explicit patent grant, which matters for
a security and networking tool. Contributions are accepted under a Developer
Certificate of Origin sign-off rather than a CLA (`ARCHITECTURE.md` §24.10).
