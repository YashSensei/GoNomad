# GoNomad — System Architecture

> **Your development machine, anywhere.**

**Status:** Design complete, pre-implementation.
**Audience:** Contributors and reviewers. This is the canonical design document; `plan.md` holds the execution roadmap.
**Document version:** 1.0

---

## Locked decisions

These were decided before design and constrain everything below.

| Axis | Decision | Consequence |
|---|---|---|
| Host OS | **Windows first**, macOS/Linux at M6 | ConPTY (not the Unix PTY model), `ReadDirectoryChangesW`, PowerShell + WSL as default shells |
| Phone | **Android only**, native Kotlin + Jetpack Compose | No app-store review, sideloadable APK, StrongBox keys, no iOS background-socket kill |
| Core | **Rust**, shared with the phone via UniFFI | One protocol implementation, one crypto implementation, one static server binary |
| Transport | **iroh** (QUIC + NAT hole punching + self-hostable relay) | No port forwarding, no cloud account, survives Wi-Fi↔cellular handoff |
| Licence | Apache-2.0 | Patent grant matters for a security tool; see §24.10 |

**On choosing Android-only.** All non-UI logic — protocol, crypto, session state machines, transport, reconnect policy, VT grid diffing, capability checks, caching — lives in Rust `gonomad-core` and is exposed through UniFFI. The Kotlin layer is Compose views plus thin ViewModels that forward to the core. A future iOS or desktop client reimplements *views only*. That is what makes native-Android-only a starting point rather than a dead end, and it is a hard architectural rule, not an aspiration: **if logic can live in Rust, it must.**

---

## Table of contents

1. [Product vision](#1-product-vision)
2. [System architecture](#2-system-architecture)
3. [Security architecture](#3-security-architecture)
4. [Networking architecture](#4-networking-architecture)
5. [Backend architecture](#5-backend-architecture)
6. [Mobile architecture](#6-mobile-architecture)
7. [AI abstraction layer](#7-ai-abstraction-layer)
8. [PTY management architecture](#8-pty-management-architecture)
9. [Authentication & pairing flow](#9-authentication--pairing-flow)
10. [Wire protocol](#10-wire-protocol)
11. [API design](#11-api-design)
12. [File synchronisation strategy](#12-file-synchronisation-strategy)
13. [Terminal architecture](#13-terminal-architecture)
14. [Performance optimisations](#14-performance-optimisations)
15. [Offline strategy](#15-offline-strategy)
16. [Database & storage decisions](#16-database--storage-decisions)
17. [Folder structure](#17-folder-structure)
18. [Recommended technology stack](#18-recommended-technology-stack)
19. [Risks and mitigations](#19-risks-and-mitigations)
20. [Development roadmap](#20-development-roadmap)
21. [MVP definition](#21-mvp-definition)
22. [Post-MVP roadmap](#22-post-mvp-roadmap)
23. [UX specification, screen by screen](#23-ux-specification-screen-by-screen)
24. [What has been overlooked](#24-what-has-been-overlooked)

---

## 1. Product vision

### The gap

Remote-access tools fall into two camps, and neither serves a developer holding a phone.

**Pixel streamers** — RustDesk, AnyDesk, TeamViewer, Chrome Remote Desktop, VNC, RDP. They transmit a rectangle of pixels laid out for a 27-inch monitor and a mouse. On a phone you get pinch-zoom, a floating cursor, and a 6pt font. Latency is bounded by video encoding, bandwidth by frame rate, and battery by continuous decode. They are general-purpose, which is exactly the problem: they know nothing about files, terminals, or git, so they cannot make any of it better.

**Cloud IDEs** — GitHub Codespaces, Gitpod, Replit, StackBlitz. Excellent products, wrong machine. Your SSH keys, your Docker images, your local models, your half-finished branch, your `~/.claude` history, and your paid AI CLI subscriptions are on *your laptop*. Reproducing that environment in a container is a project, not a session.

GoNomad occupies the third position: **a native mobile client that speaks semantics, not pixels, to a daemon on the machine you already use.** It sends "the file at line 340 changed" and "cell (12,40) is now `E`", not compressed video. Every computation — compiling, testing, inference, indexing — happens on the laptop. The phone renders.

### What it feels like

Open the app on a train. Your three terminals are exactly where you left them, because they never stopped. The Claude Code session you started at your desk is mid-task and waiting for approval on a diff; you read the diff, tap approve, and watch tests run. You fix a typo in a config file with a cursor you can actually position. You commit, push, and put the phone away. None of it involved a login, a port-forward, a cloud account, or squinting at a scaled-down VS Code.

### Positioning statements

- **"Cursor Mobile for your own laptop."** — the closest one-liner.
- **Not** a remote desktop. **Not** a browser IDE. **Not** a thin client to someone else's computer.

### Core principles as architectural constraints

Each principle is restated as something a code reviewer can enforce.

| Principle | Enforceable constraint |
|---|---|
| Open source | Apache-2.0. No proprietary dependency in any required path. Reproducible builds (§24.12). |
| Self-hosted | No component GoNomad requires may be operated by us. Every default must work with the project's servers permanently offline. |
| Privacy first | The daemon must never transmit file content, command output, or metadata to any third party. Relays and proxies see ciphertext only. |
| Mobile first | Any screen that could be described as "the desktop layout, smaller" is rejected in review. Every primary action reachable one-handed. |
| AI native | Agents are first-class domain objects with lifecycle, state, and approval semantics — not a terminal tab with a nice icon. |
| Extremely secure | Nothing observable before authentication. No bearer tokens. Least privilege by default. Every privileged act audited. |
| Fast | Enforced latency budgets in CI (§14). A regression is a build failure. |
| Simple to deploy | One binary, one command, no runtime, no reverse proxy, no DNS, no certificates, no router configuration. |

### Non-goals, and why they are load-bearing

These are not merely "out of scope"; each one, if admitted, would collapse the design.

- **No desktop streaming, VNC, RDP, or OS mirroring.** Admitting a pixel path removes the incentive to design real mobile screens, and every hard UX problem gets deferred to "just use the desktop view." The absence of an escape hatch is the feature.
- **No VS Code in a browser.** `code-server` and `openvscode-server` already exist and are excellent. Rebuilding them badly, inside a WebView, on a 6-inch screen, is strictly worse than either using them or building something purpose-built.
- **No central server, account, or SaaS control plane.** Not for ideology — because a self-hosted security tool whose availability depends on our uptime is not self-hosted.
- **No provider lock-in for AI.** Any agent that runs in a terminal must work on day one with zero configuration (§7, level L0).

### The design test

Applied to every feature and every screen:

> Would a developer who has never seen a desktop IDE recognise this as designed for a phone? Or is it a smaller version of something else?

---

## 2. System architecture

### Topology

```
┌─────────────────────────────────────┐
│  ANDROID PHONE                      │
│  ┌───────────────────────────────┐  │
│  │ Jetpack Compose UI            │  │   Views + thin ViewModels only.
│  │  terminal · editor · git · ai │  │   No protocol knowledge.
│  └──────────────┬────────────────┘  │
│                 │ UniFFI (Flow)     │
│  ┌──────────────▼────────────────┐  │
│  │ gonomad-core  (Rust)          │  │   Session state machines, Noise,
│  │ + gonomad-transport           │  │   reconnect policy, cache, codec.
│  └──────────────┬────────────────┘  │
└─────────────────┼───────────────────┘
                  │
        ══════════▼══════════   Noise IK inside QUIC, mutually
        ║  encrypted session ║   authenticated by device keypair.
        ══════════▲══════════   Relays see ciphertext only.
                  │
┌─────────────────┼───────────────────────────────────────────┐
│  LAPTOP         │                                           │
│  ┌──────────────▼────────────────┐                          │
│  │ gonomad-transport             │  iroh endpoint, mDNS,    │
│  │                               │  WebSocket fallback      │
│  ├───────────────────────────────┤                          │
│  │ gonomad-core (same crate)     │  identical codec + Noise │
│  ├───────────────────────────────┤                          │
│  │ gonomad-policy                │  ← EVERY request passes  │
│  │  capabilities · path guards   │    through here          │
│  │  rate limits · approvals      │                          │
│  ├───────────────────────────────┤                          │
│  │ Service layer (actors)        │                          │
│  │  pty · fs · search · git      │                          │
│  │  agents · notify · devices    │                          │
│  ├───────────────────────────────┤                          │
│  │ gonomad-store (SQLite)        │  devices · grants ·      │
│  │                               │  audit chain · sessions  │
│  └───────────────┬───────────────┘                          │
│                  │                                          │
│   ┌──────────────▼──────────────────────────────────┐       │
│   │ THE MACHINE                                     │       │
│   │  filesystem · ConPTY · git CLI · docker · node   │       │
│   │  bun · python · rust · claude · codex · gemini   │       │
│   │  opencode · local LLMs · ssh agent · any CLI     │       │
│   └─────────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────────┘
```

### The central invariant

> **The daemon owns all long-lived state. Connections are disposable.**

A PTY is owned by the daemon, not by the socket that created it. An agent session is owned by the daemon. Scrollback lives in the daemon. Editor tab state lives in the daemon.

Everything good about the product follows from this one property:

- Losing signal in a tunnel does not kill a running test suite, a `docker build`, or an AI agent mid-task.
- "Reconnect" restores a *view* of state that never stopped existing. There is no session recovery protocol to get wrong, because there is no session to recover.
- Scrollback survives the app being killed by Android's memory manager, because it was never on the phone.
- Two clients (phone now, tablet later) can attach to the same terminal and see the same thing without a synchronisation protocol.
- The phone can be a genuinely dumb renderer, which is why it can be fast and battery-cheap.

The corollary is a rule for reviewers: **any state the phone holds must be reconstructible from the daemon.** Phone-side storage is cache and outbound queue, never truth.

### Component responsibilities

| Component | Owns | Must never |
|---|---|---|
| `gonomad-proto` | Frame schema, CBOR codec, version negotiation | Depend on transport or any service |
| `gonomad-core` | Noise session, request correlation, reconnect policy, client-side cache, state machines | Touch the filesystem or spawn processes |
| `gonomad-transport` | iroh endpoint, mDNS discovery, WebSocket binding, path selection | Interpret frame contents |
| `gonomad-policy` | Capability checks, path canonicalisation, rate limits, approval gating | Be bypassable — it is the only route to services |
| `gonomad-pty` | ConPTY lifecycle, headless VT grid, scrollback ring | Know about the network |
| `gonomad-fs` | Directory listing, watchers, FST path index, CAS writes | Accept an unvalidated path |
| `gonomad-search` | Streaming content search, fuzzy path match | Materialise a full result set |
| `gonomad-git` | Read via `gix`, mutate via `git` CLI | Reimplement credential handling |
| `gonomad-agents` | Adapter registry, manifest loading, state detection | Hardcode a vendor |
| `gonomad-store` | SQLite schema, migrations, hash-chained audit | Store file content or scrollback |
| `gonomad-server` | Wiring, router, CLI, tray UI | Contain business logic |
| Android app | Rendering, gestures, platform integration | Contain protocol or crypto logic |

### Request lifecycle

Tracing `fs.read` end to end, because every request follows this shape:

1. Compose ViewModel calls a UniFFI method on `gonomad-core`.
2. Core assigns a correlation id, encodes a CBOR frame, seals it in the Noise session, writes it to the control stream.
3. Transport delivers over the currently selected path (LAN / direct / relay).
4. Daemon opens the frame, decodes, and hands it to the **router**.
5. Router resolves the device's grant set and calls `gonomad-policy`:
   - Is the device paired and its grant unrevoked?
   - Does it hold `fs:read`?
   - Does the canonicalised path resolve inside an allowed workspace root, after symlink resolution?
   - Is the path on the secret denylist?
   - Is the device within its rate-limit bucket?
6. On any failure: a typed error, an audit entry, and no syscall. On success: the `fs` actor is messaged.
7. The actor reads the file, returns content plus a content hash (the CAS baseline, §12).
8. Response frame → sealed → streamed back. Audit entry written.
9. Core resolves the pending correlation id, updates cache, emits on a Flow. Compose recomposes.

Two things to notice. **Policy sits on the only path to services** — it is structurally impossible for a service call to skip it, rather than merely conventional. And **the audit entry is written by the router, not the service**, so a service cannot forget to log.

### Concurrency model

Tokio, with an **actor per resource**. Each PTY, each watcher, each agent session, each search is a task that solely owns its state and is reached only by message passing over an `mpsc` channel. There are no `Mutex`-guarded shared structures in any hot path.

This is chosen over a shared-state-plus-locks design for three concrete reasons: a slow client cannot block a PTY from draining its output (backpressure is per-actor); cancellation is dropping a channel rather than coordinating a flag; and each resource gets an independent bounded queue, so one runaway terminal cannot starve the others.

Bounded queues everywhere, with an explicit overflow policy per actor type — PTY output coalesces on overflow (dropping intermediate frames is correct when only the latest grid matters), while control messages apply backpressure and never drop.

---

## 3. Security architecture

The stated requirement is to design as though the user's entire workstation is exposed — because it is. A paired phone can read source code, run arbitrary commands, and reach every credential the developer's shell can reach. This section is the most important in the document.

### 3.1 Threat model

| # | Adversary | Capability | Primary defence |
|---|---|---|---|
| T1 | Network attacker (café Wi-Fi, hostile ISP) | Observe, inject, replay, drop | Noise IK inside QUIC; nothing plaintext on the wire, including metadata |
| T2 | Internet scanner | Probe any reachable address | No routable listening port; no HTTP surface; ALPN mismatch dropped pre-handshake |
| T3 | Malicious relay | Sees all traffic, controls delivery timing | Relay is untrusted by design; sees ciphertext and traffic timing only |
| T4 | Stolen **locked** phone | Physical possession | Keys non-exportable in Keystore, gated on device unlock; remote revoke |
| T5 | Stolen **unlocked** phone | Full app access | Secret denylist, workspace roots, capability scoping, biometric gate on destructive ops, remote revoke |
| T6 | Shoulder-surfed / photographed QR | The pairing secret | Single-use, 120s expiry, laptop-side approval, transcript-derived SAS confirmation |
| T7 | Prompt-injected AI agent | Proposes malicious edits or commands | True-diff rendering (never the agent's summary), destructive-op detection, biometric gate |
| T8 | Malicious dependency in our own supply chain | Code execution in the daemon | `cargo-deny`, `cargo-audit`, vendored lockfile, minimal dependency set, reproducible builds |
| T9 | Rogue paired device (given away, sold, compromised) | Valid credential | Instant server-side revocation, per-device audit trail, capability minimisation |
| T10 | Local process running as a **different** OS user | Reads daemon files, connects to loopback | Keys in OS keyring not files; loopback control socket is peer-credential checked |

**Explicitly out of the model:** a compromised laptop OS with root/admin. If the attacker owns the machine that runs the compiler, GoNomad cannot help — and any design that claims otherwise is lying.

**Also out of the model, and worth naming precisely because T10 could be read as covering it:** a process running as *the same OS user* as the daemon. Such a process can already read the source tree, and on most platforms it can ask the keyring for the daemon's identity key, because the keyring's access control is the user account. GoNomad raises the cost — keys are not sitting in a readable file, and the control socket checks peer credentials — but it does not and cannot stop a same-user attacker. The security boundary is the OS user account, not the process.

### 3.2 Identity, not tokens

**The decision:** there are **no bearer tokens anywhere in GoNomad.** No JWT, no session cookie, no API key, no refresh token.

Each device holds an Ed25519 keypair generated on-device. The public key, registered at pairing, *is* the credential. Every connection performs a fresh mutual authentication from that keypair. Authorisation is a server-side row keyed by public key.

The requirements brief asked for token rotation, session expiration, and revocation. This design **dissolves** those requirements rather than implementing them, and that is a much stronger position:

| Conventional problem | Why it does not exist here |
|---|---|
| Token theft | There is no token to steal. The private key is non-exportable hardware-or-Keystore material. |
| Token rotation | Nothing to rotate. Key rotation is supported but is a re-pair, not a scheduled background chore. |
| Replay of a captured token | A captured handshake is useless; authentication requires proving possession of the private key against a fresh challenge. |
| Session expiry | A session *is* a live connection. It ends when the connection ends. Nothing outlives it. |
| Revocation lists / token blacklists | Revocation deletes one database row. Effective on the next packet. No propagation delay, no blacklist to grow unboundedly. |
| Logout | Force-disconnect closes the QUIC connection; revoke removes the grant. Both are immediate and server-side. |

The cost is real and worth naming: **losing the key means re-pairing.** There is no "forgot password" flow, because there is no password. This is mitigated by a recovery code (§9.5), and it is the correct trade — a self-hosted tool with a credential-recovery backdoor has a credential-recovery attack.

### 3.3 Key management

**Phone.** Two distinct keys, because one key cannot do both jobs:

1. **Identity key** — Ed25519, generated on-device, stored in Android Keystore, non-exportable, `setUnlockedDeviceRequired(true)`. Used for the Noise IK handshake on every connection.

   *A constraint that must be designed around, not discovered later:* **Android's hardware-backed Keystore does not support Ed25519 or X25519.** StrongBox and TEE keymaster support EC P-256/P-384/P-521, RSA, and AES — not Curve25519. So the identity key is a software key held in Keystore-encrypted storage. It is protected by the device's hardware-derived key encryption key and the lockscreen, but the private scalar is present in app memory during a handshake. This is honest and acceptable for T4; it is *not* sufficient for T5.

2. **Presence key** — EC **P-256**, generated in **StrongBox** where available (TEE otherwise), truly non-exportable, `setUserAuthenticationRequired(true)` with a 0-second validity window, so **every** use forces a fresh biometric or PIN. Used exclusively to sign challenges for destructive operations.

   This two-key split is precisely what makes T5 survivable. A thief with an unlocked phone can browse code — they cannot `git push --force`, cannot read a denylisted secret, cannot approve an agent's destructive diff, and cannot change security policy, because each of those requires a fresh hardware-attested biometric that the thief cannot produce.

**Laptop.** The daemon's Ed25519 identity key is stored in the OS keyring — Windows Credential Manager via DPAPI, macOS Keychain, Secret Service on Linux — through the `keyring` crate. Never a file on disk, because a file is readable by every process running as that user (T10). Where no keyring is available (headless Linux), fall back to a file at mode `0600` and warn loudly at startup.

**Rotation.** `gonomad rotate-identity` generates a new daemon key and re-signs all device grants; each phone shows a "this machine's identity changed — confirm the fingerprint" prompt, so rotation cannot be used as a MITM vector. Phone-side rotation is a re-pair.

### 3.4 Session layer

**Noise IK** over the transport, regardless of which transport is in use.

`IK` is the right pattern: the initiator (phone) already knows the responder's static key from the pairing QR, so the handshake is one round trip, the initiator's identity is encrypted to the responder's key (so a passive observer cannot learn *which* device is connecting), and the responder authenticates the initiator before any application data. Cipher suite: `Noise_IK_25519_ChaChaPoly_BLAKE2s`.

Layering Noise inside iroh's QUIC — which already provides mutual TLS 1.3 with raw public keys — is deliberately redundant. It is justified because it makes **security independent of transport**:

- Adding a Cloudflare Tunnel or WebSocket fallback later cannot weaken the threat model. Cloudflare terminates TLS and would otherwise see plaintext; with Noise inside, it sees ciphertext.
- The relay path and the direct path have *identical* security properties, so users never face a "is relaying safe?" question and we never face pressure to answer it optimistically.
- A vulnerability in one layer is not a total compromise.
- The security review has one thing to audit, not one per transport.

The cost is one extra AEAD pass over each frame — negligible next to compression, and immaterial against ChaCha20-Poly1305 throughput on any ARMv8 core.

### 3.5 Replay and integrity

Noise provides per-message nonce counters, so replay within a session is rejected by construction and nonce reuse is impossible. On top:

- Each stream carries a monotonic sequence number; the daemon rejects duplicates and out-of-order control frames.
- Handshakes include a fresh 32-byte responder nonce, so a captured handshake cannot be replayed to open a new session.
- Mutating requests carry a client-generated idempotency key, retained for 5 minutes, so a network-level retry cannot double-apply a commit or a file write.
- The SAS is derived from the full handshake transcript (`BLAKE2s(h_final)`), so any tampering with any handshake message changes the digits both users are comparing.

### 3.6 Authorisation: least privilege

Authentication answers *who*. Authorisation answers *what*, and it is where most of the real security lives.

**Capability grants**, per device, stored server-side, editable from the laptop and viewable from the phone:

| Capability | Grants | Default |
|---|---|---|
| `fs:read` | Read files inside allowed roots | ✅ |
| `fs:write` | Create, modify, delete, move inside allowed roots | ✅ |
| `fs:secrets` | Read denylisted paths | ❌ |
| `pty:spawn` | Open a shell | ✅ |
| `exec:allowlisted` | Run commands matching the project's allowlist | ✅ |
| `exec:arbitrary` | Run anything via the structured `exec` API | ❌ |
| `git:read` | Status, log, diff, blame | ✅ |
| `git:write` | Commit, push, pull, branch, stash | ✅ |
| `git:dangerous` | Force push, hard reset, history rewrite | ❌ |
| `agent:spawn` | Start AI agent sessions | ✅ |
| `policy:write` | Change security policy, pair devices | ❌ |

*An honesty note that belongs in the document rather than in a reviewer's head:* `pty:spawn` transitively implies arbitrary execution — a shell can run anything. `exec:arbitrary` therefore governs only the structured `exec` API, and granting `pty:spawn` is granting execution. GoNomad does not pretend otherwise. Users who want a genuinely read-only device withhold `pty:spawn`, and the pairing UI says so in those words.

**Workspace roots.** A device reaches only explicitly declared roots. Every path is:

1. Rejected if it contains a null byte or is not valid UTF-8.
2. Canonicalised via `std::fs::canonicalize` — resolving `..`, symlinks, and on Windows 8.3 short names, junctions, and `\\?\` prefixes.
3. Checked to be a prefix-descendant of an allowed root *after* canonicalisation, compared component-wise (never by string prefix — `/home/user/proj-evil` must not match root `/home/user/proj`).
4. Re-validated after opening, using the file handle's identity, to close the TOCTOU window where a symlink is swapped between check and use.

Windows earns extra attention as the first-class host: reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1‑9`, `LPT1‑9`) are rejected, alternate data streams (`file.txt:hidden`) are rejected, trailing dots and spaces are rejected, and UNC paths (`\\server\share`) are refused unless explicitly configured as a root.

**Secret denylist**, applied *after* root checks, requiring `fs:secrets` plus a biometric presence signature:

```
**/.ssh/**            **/.aws/**           **/.kube/config
**/.env*              **/*.pem             **/*.key         **/*.p12
**/.netrc             **/.npmrc            **/.pypirc       **/.docker/config.json
**/.git-credentials   **/id_rsa*           **/id_ed25519*
**/.gnupg/**          **/.config/gcloud/** **/.claude/**     **/.cursor/**
```

The concrete attack: a thief with an unlocked phone opens the file tree, taps `~/.ssh/id_ed25519`, and now owns every server and repository the developer can reach. The denylist plus biometric gate is what makes that fail. Users can extend or narrow the list; narrowing it warns.

`search` and file-tree listing honour the denylist too, so secrets do not leak through grep results or filename enumeration.

### 3.7 Pre-authentication surface

The brief requires that the server expose nothing before authentication. The transport choice delivers this almost for free, and that is a large part of why iroh was chosen:

- **No routable listening TCP port.** The daemon holds a QUIC endpoint over UDP and a loopback-only control socket. There is no `0.0.0.0:8080`.
- **No HTTP surface at all** — no login page, no health endpoint, no static assets, no WebSocket upgrade path on the default transport. The entire class of unauthenticated-web-endpoint bugs is absent.
- **ALPN gate.** A connection not offering `gonomad/1` is dropped during the QUIC handshake.
- **Allowlist gate.** iroh authenticates the peer's public key as part of QUIC TLS. An unpaired key is rejected before a single application byte is read.
- **Nothing to fingerprint.** A scanner sees a UDP port that does not respond to anything but a valid, authenticated handshake. No banner, no version string, no error page, no timing oracle.
- **Pairing mode is opt-in, time-boxed to 120 seconds, single-use, and requires physical access to the laptop** to read the QR. It is the only moment an unpaired key can be accepted, and even then only after explicit human approval.

The loopback control socket used by the `gonomad` CLI verifies peer credentials — `SO_PEERCRED` on Unix, `GetNamedPipeClientProcessId` plus token comparison on Windows named pipes — so another local user cannot drive the daemon (T10).

### 3.8 Rate limiting and resource caps

Token buckets per device per operation class, plus hard resource ceilings. Rate limiting here is primarily about protecting the *laptop* from a buggy or compromised phone, not about protecting a public service from load.

| Class | Rate | Hard cap |
|---|---|---|
| Pairing attempts | 3 per QR, then invalidate | 1 concurrent pairing mode |
| Handshakes per key | 10/min, exponential backoff | — |
| `fs.read` | 100/s | 32 MB per response |
| `fs.write` | 20/s | 32 MB per write |
| `search` | 2/s | 4 concurrent, 10k results, 30s deadline |
| `pty.spawn` | 1/s | 16 concurrent PTYs |
| Watchers | — | 8 roots, 1 recursive watcher each |
| `agent.spawn` | 1/5s | 8 concurrent sessions |
| Frames in flight | — | 64 MB total send buffer, then backpressure |

Exceeding a rate returns `RateLimited` with a `retry_after`; exceeding a hard cap returns `ResourceExhausted`. Neither ever silently drops work.

### 3.9 Audit log

Append-only and **hash-chained**: each entry commits to its predecessor.

```
entry_n = { seq, timestamp_utc, monotonic_ns, device_id, operation,
            args_digest, result, prev_hash }
hash_n  = BLAKE3(canonical_cbor(entry_n))
```

Verification walks the chain from a genesis entry. Any deletion, reordering, or modification breaks it and `gonomad audit verify` reports the exact sequence number. This matters because an attacker who compromises the daemon will try to erase their tracks first; a plain log lets them, a chained log makes the erasure evident.

Logged: every mutating operation, every denial, every pairing and revocation, every capability change, every biometric-gated approval, every agent approval decision, and every connection with its selected transport path. Argument *digests* rather than arguments, so the audit log does not itself become a secret store — the log records that `/x/.env` was read, not what it contained.

Retention is a configurable cap with a documented rotation that preserves chain continuity by recording the truncation point as a signed checkpoint. Readable from the phone (§23, Security screen).

### 3.10 Approval gating

Operations requiring a fresh presence-key signature (biometric or PIN, every time):

- Reading a denylisted path
- `git push --force`, `git reset --hard`, any history rewrite
- Deleting a directory, or any delete of more than 10 files
- Writing outside a declared workspace root (which also requires a laptop-side prompt)
- Approving an AI agent's destructive action (§7.5)
- Changing security policy, pairing a device, or revoking one
- Rotating the daemon identity

The phone sends the operation's canonical digest, signs it with the presence key, and the daemon verifies the signature *over the exact operation it is about to perform*. Signing the digest rather than a bare nonce is what prevents a compromised phone app from harvesting a signature for one action and spending it on another.

### 3.11 Supply chain and build integrity

A self-hosted security tool that ships unverifiable binaries has no security story. Therefore: `cargo-deny` and `cargo-audit` in CI as hard gates; a committed `Cargo.lock`; a deliberately small dependency set with every addition justified in review; `cargo-vet` for transitive review status; reproducible builds verified in CI by building twice and comparing hashes; release artifacts signed with `cosign` and published with SLSA provenance; the Android APK signed and reproducible, with `apksigner` verification instructions in the README. See §24.12.

---

## 4. Networking architecture

The requirement is stark: **no router configuration, no port forwarding, minimal setup, maximum security, no cloud account.** Those constraints eliminate most of the field.

### 4.1 Options evaluated

| Option | Account? | NAT / CGNAT | Who sees plaintext | Setup steps | Mobile battery | Embeddable | Verdict |
|---|---|---|---|---|---|---|---|
| **Direct TLS + port forward** | No | ❌ needs public IP | Nobody | Many: router, DDNS, certs, firewall | Good | ✅ | ❌ Violates the core constraint |
| **Tailscale** | ✅ Tailscale account | ✅ Excellent | Nobody | Install 2 apps, sign in | Good | ❌ | ⚠️ Tier 3 |
| **Headscale** | No (self-host) | ✅ Excellent | Nobody | Needs a public VPS + DNS + TLS | Good | ❌ | ⚠️ Tier 3 |
| **Cloudflare Tunnel** | ✅ CF account + domain | ✅ Always works | **Cloudflare** | Account, domain, DNS, `cloudflared` | Good | Partly | ⚠️ Tier 3 |
| **Raw WireGuard** | No | ❌ needs a public endpoint | Nobody | Manual keys, config, endpoint | Excellent | Partly | ❌ Needs a public IP |
| **Reverse SSH tunnel** | No | ❌ needs a public jump host | Jump host owner | Manual, fragile, needs a VPS | Poor | ❌ | ❌ |
| **WebRTC data channels** | No (needs signalling) | ✅ ICE/STUN/TURN | Nobody (DTLS) | Must build signalling + TURN | Poor | Heavy | ❌ See below |
| **UPnP / NAT-PMP** | No | ⚠️ Unreliable | Nobody | Zero, when it works | Good | ✅ | ❌ See below |
| **iroh (QUIC + hole punch + relay)** | **No** | ✅ Direct, relay fallback | **Nobody** | **Scan a QR** | Good | ✅ Native | ✅ **Default** |

**Why not WebRTC**, despite solving NAT traversal well: it still requires a signalling server we would have to host or make the user host, so it does not remove the account problem — it relocates it. The stack (ICE, STUN, TURN, DTLS, SCTP) is large, and the mature implementations are C++ (libwebrtc); `webrtc-rs` is capable but a heavy dependency for what would end up being a worse QUIC. Mobile WebRTC is tuned for real-time media with aggressive keepalives and is measurably battery-hungrier. And SCTP over DTLS gives less useful multiplexing than QUIC streams.

**Why not UPnP/NAT-PMP**, despite zero setup when it works: it works unpredictably (disabled by default on most modern routers, absent behind CGNAT, silently broken behind double NAT), and asking a router to open a hole to a developer workstation is a security posture we should not encourage. It could be an opportunistic optimisation; it cannot be a foundation.

**Why not Tailscale as the default**, despite being the best-in-class VPN and genuinely excellent: three blockers. Its coordination server is a SaaS account, which violates "no cloud account" — Headscale fixes that but demands a public VPS with DNS and TLS, which violates "minimal setup" far worse. Its mobile client **cannot be embedded** in a third-party Android app (the tunnel is a VpnService the user must install and run separately), so GoNomad would be a two-app product with a sign-in. And on Android, only one VpnService can be active, so GoNomad would conflict with any corporate VPN the user needs. Tailscale is superb, and it remains a fully supported Tier 3 transport for users who already run it.

### 4.2 Recommendation: a transport ladder with iroh as the default

```
Tier 0  LAN direct QUIC (mDNS discovery)     ← same network: lowest latency, no relay
   ↓ fails
Tier 1  iroh hole-punched direct P2P QUIC    ← typical remote case
   ↓ fails
Tier 2  iroh relay (self-hostable)           ← CGNAT, symmetric NAT, hostile firewall
   ↓ user opt-in
Tier 3  Tailscale · Cloudflare Tunnel · SSH -L
```

Tiers are attempted concurrently, not sequentially, and the fastest working path wins; iroh continues probing for a direct path while relayed and upgrades transparently mid-session. The UI always shows which tier is active (§23) because a silently relayed session that feels slow is worse than a visibly relayed one.

### 4.3 Why iroh

**Public keys as addresses.** A peer is dialled by its `NodeId` — an Ed25519 public key — not an IP. Addresses change constantly on mobile (Wi-Fi → LTE → different Wi-Fi → CGNAT re-NAT); identity does not. This removes an entire category of reconnection bug and makes authentication and addressing the same fact rather than two facts that must be kept consistent.

**Genuinely relay-free where possible.** QUIC hole punching over UDP establishes direct paths through most NATs. When it fails, the relay carries ciphertext.

**The relay is untrusted, and self-hostable.** Because Noise IK sits inside (§3.4), the relay is a dumb packet forwarder that sees ciphertext and traffic timing. It cannot read code, commands, or output. So using the public relays is safe, and `iroh-relay` can be self-hosted by anyone who objects to timing metadata leaving their control. This is the property that lets the default configuration require no account while still satisfying "privacy first."

**Embedded, not installed.** iroh is a Rust library. It compiles into the daemon and, via UniFFI, into the Android app. One app, no VPN profile, no sign-in, no conflict with a corporate VPN.

**Mature enough.** iroh 1.0 shipped in June 2026 with wire-protocol stability guarantees and official Kotlin and Swift bindings. The Kotlin bindings matter directly for the Android target; the Swift ones matter for the iOS port.

### 4.4 The three QUIC properties that decide this product

Worth stating separately, because they are why the answer to "just use WebSockets over a tunnel?" is no.

**Connection migration.** A QUIC connection is identified by a connection ID, not a 4-tuple. Walking out of the house and switching Wi-Fi → LTE keeps the connection, the terminal, and the editor buffer alive with no reconnect and no visible glitch. Over TCP, every network change is a dead socket, a reconnect, a re-handshake, and a UI stall. On a phone, network changes are not an edge case — they are the normal condition. **This one property is the difference between an app that feels reliable and one that feels broken.**

**Independent streams.** Each QUIC stream has its own flow control and its own loss recovery. Downloading a 40 MB log file cannot head-of-line-block a keystroke. With a single WebSocket we would have to hand-roll a multiplexer and re-implement per-stream flow control — reinventing, more badly, what QUIC already ships.

**0-RTT resumption.** Reopening the app after a few minutes resumes with a cached session ticket and sends application data in the first flight. Cold open feels instant rather than merely fast.

### 4.5 Transport abstraction

`gonomad-transport` exposes one interface so iroh is replaceable and Tier 3 is possible:

```rust
trait Transport {
    async fn connect(&self, peer: PeerId, hints: &[AddrHint]) -> Result<Conn>;
    async fn accept(&self) -> Result<Conn>;
    fn path_info(&self) -> PathInfo;   // tier, rtt, relayed?, mtu
}
trait Conn {
    async fn open_bi(&self) -> Result<(SendStream, RecvStream)>;
    async fn accept_bi(&self) -> Result<(SendStream, RecvStream)>;
    fn on_path_change(&self) -> impl Stream<Item = PathInfo>;
}
```

The WebSocket binding (§10.6) implements this interface with a userspace multiplexer, so Tier 3 tunnels work with the same protocol and the same security — accepting the head-of-line blocking that QUIC avoids, which is exactly why it is a fallback.

### 4.6 Discovery

- **LAN:** mDNS (`_gonomad._udp.local`) advertising `NodeId` and port. Sub-millisecond RTT, no relay, no internet.
- **Remote:** iroh's node-address publication — DNS-based discovery by default, with Mainline DHT (BEP 44) as a decentralised alternative for users who want no dependency on any named infrastructure.
- **Pinned hints:** the pairing QR embeds the last-known direct addresses and home relay, so the first reconnect after pairing needs no discovery at all.

---

## 5. Backend architecture

### 5.1 Language: Rust

Evaluated against Go, Bun, and Node.

| Criterion | Rust | Go | Bun | Node |
|---|---|---|---|---|
| Single static binary | ✅ | ✅ | ⚠️ large | ❌ needs runtime |
| Windows PTY (ConPTY) | ✅ `portable-pty` (wezterm) | ⚠️ third-party, thin | ⚠️ `node-pty` | ⚠️ `node-pty` |
| gitignore-aware walk | ✅ `ignore` (ripgrep) | ❌ hand-roll | ❌ | ❌ |
| Content search engine | ✅ `grep-searcher` (ripgrep) | ❌ shell out | ❌ shell out | ❌ shell out |
| Headless VT emulator | ✅ `alacritty_terminal` | ❌ | ⚠️ xterm.js (DOM-ish) | ⚠️ xterm.js |
| FS watching | ✅ `notify` | ✅ fsnotify | ⚠️ | ⚠️ |
| Git library | ✅ `gix` (pure Rust) | ✅ go-git | ❌ | ❌ |
| iroh | ✅ native | ⚠️ FFI | ❌ | ❌ |
| Shares code with the phone | ✅ UniFFI | ❌ | ❌ | ❌ |
| Idle memory | ~15 MB | ~30 MB | ~60 MB | ~80 MB |
| GC pauses in the hot path | none | sub-ms | yes | yes |
| Compile time | ✗ slow | ✅ fast | ✅ instant | ✅ instant |
| Contributor pool | smaller | large | large | largest |

**Rust wins on ecosystem fit more than on language merit.** Almost every hard problem in this product has a mature, best-in-class Rust crate written by someone who already solved it at scale: ripgrep's authors solved gitignore-aware traversal and fast search; wezterm's author solved cross-platform PTY including ConPTY; Alacritty's authors solved VT parsing. In Go those are reimplementation projects. In Node/Bun the answer is "shell out to ripgrep," which means shipping and version-managing external binaries — precisely the deployment complexity we promised to avoid.

Two decisive secondary factors: `node-pty` is a native module whose Windows build has historically been the most fragile part of every editor that depends on it, and Windows is our first-class host; and only Rust lets the same crate become both the daemon and the phone's core (§6.2), which eliminates protocol drift structurally rather than by discipline.

**Go is a genuinely close runner-up.** Faster compiles, a larger contributor pool, `tsnet` if we had chosen Tailscale, and goroutines map cleanly onto the actor model. It loses on PTY quality on our primary host and on having to rebuild ripgrep. If this were a Linux-first product with no code sharing with the client, Go would be defensible.

**Bun and Node are rejected**, notwithstanding fast iteration: native-module fragility on Windows, 4–5× the idle memory against our footprint goal, GC jitter in a path with a 50 ms keystroke budget, and shipping a runtime against "one binary."

### 5.2 Runtime and structure

Tokio multi-threaded runtime; actor per resource (§2); `tracing` for structured logs with a JSON layer for the audit sink.

Blocking work is isolated deliberately: filesystem and git operations run on `spawn_blocking` pools that are **separately bounded** — a slow network filesystem stalling 8 git calls must not exhaust the pool that directory listings need. Search gets its own pool sized to `min(cores, 8)`.

### 5.3 The daemon binary

`gonomad-server` is both the daemon and the CLI, dispatching on `argv[0]`/subcommand:

```
gonomad init                    # generate identity, write config, register autostart
gonomad start [--foreground]    # run the daemon
gonomad pair                    # 120s pairing mode, render QR in the terminal
gonomad devices [ls|rm|rename|revoke|grant]
gonomad status                  # transport tier, RTT, sessions, ptys
gonomad logs [--follow]
gonomad audit [verify|export]
gonomad workspace [add|rm|ls]
gonomad doctor                  # diagnose connectivity, permissions, shells, agents
gonomad rotate-identity
```

The CLI talks to the daemon over the peer-credential-checked loopback socket (§3.7). `gonomad doctor` matters more than it sounds: most support burden for a self-hosted networking tool is environment diagnosis, and a good doctor command converts issue reports into self-service.

**Tray UI** (§24.4) is a small native surface — `tray-icon` plus `rfd` for dialogs on Windows — showing connection state, the pairing dialog, approval prompts, and a kill switch. It is not optional: a security tool with no visible indicator that a phone is connected, and no one-click way to cut it off, is missing a control users will reasonably demand.

### 5.4 Configuration

`~/.gonomad/config.toml`, human-editable, hot-reloaded on change with validation-before-apply:

```toml
[server]
autostart = true

[[workspace]]
name = "gonomad"
path = "C:/Users/you/code/gonomad"
default_shell = "pwsh"

[policy]
deny_paths = ["**/.env*", "**/.ssh/**"]         # merged with built-in defaults
require_presence_for = ["git:dangerous", "fs:secrets", "agent:destructive"]
max_ptys = 16

[notifications]
backend = "ntfy"
ntfy_url = "https://ntfy.example.com"
ntfy_topic = "gonomad-a1b2c3"                   # random, treated as a secret

[transport]
prefer = ["lan", "direct", "relay"]
relay_url = ""                                   # empty = iroh public relays
```

Secrets are never in this file — they live in the OS keyring, and the file holds only references.

---

## 6. Mobile architecture

### 6.1 Kotlin + Jetpack Compose, native Android

Single activity, Compose Navigation with type-safe routes, Material 3 with a custom developer-tool theme and full dynamic-colour support.

The alternatives, assessed honestly:

- **React Native** — largest ecosystem, and `react-native-webview` is the most polished path to CodeMirror. But the Rust core would reach JS only through a hand-written TurboModule, and terminal cell-diffs at 60 fps would cross the JSI bridge on the hottest path in the app. Terminal rendering would need `react-native-skia` regardless, so the ecosystem advantage evaporates exactly where the hard work is.
- **Flutter** — excellent rendering, and `xterm.dart` exists. But it means Dart for the shell and JavaScript for the editor WebView: two non-Rust languages, and clunkier WebView interop.
- **Kotlin Multiplatform + Compose Multiplatform** — technically the strongest for a multi-platform future (Compose for iOS went stable in 1.8.0, May 2025), and UniFFI's Kotlin bindings via Gobley are first-class. Rejected for now only to avoid the multiplatform abstraction tax on an Android-only MVP.
- **Native Android (chosen)** — direct UniFFI consumption with no bridge, Compose `Canvas` for the terminal with no JS in the loop, best-in-class platform integration (Keystore, StrongBox, foreground services, biometrics), and the simplest possible build. The cost — iOS needs a new view layer — is bounded by the fat-core rule.

### 6.2 Fat core, thin UI

The single most important structural rule on the phone.

```
Compose UI            ← rendering + gestures. Zero business logic.
   ↕ StateFlow / events
ViewModel             ← ~50 lines each: map core state to UI state, forward intents.
   ↕ UniFFI
gonomad-core (Rust)   ← ALL logic: protocol, Noise, correlation, reconnect
                        policy, cache coherence, VT grid diff application,
                        offline queue, capability awareness, state machines.
```

`gonomad-ffi` exposes core state as UniFFI callback interfaces, adapted to Kotlin `Flow` with `callbackFlow`. Suspend functions map onto Rust async via UniFFI's async support.

Three reasons this is worth the FFI friction: **the protocol is implemented exactly once**, so client and server cannot drift (the most common and most painful failure mode in client/server projects); **the reconnect and cache-coherence state machines are the subtlest code in the product** and having them in one place, in Rust, with property tests, is worth a great deal; and **the iOS port becomes a view layer** rather than a reimplementation.

The rule for reviewers: if a piece of Kotlin contains a conditional about protocol state, it belongs in Rust.

### 6.3 Rendering strategy per surface

Each surface is genuinely different work and gets a different answer.

**Terminal → Compose `Canvas` with a glyph atlas.**

At startup, every printable ASCII glyph plus a Latin-1 range is rasterised once per (font, size, weight, style) combination into a GPU-resident texture atlas. Rendering a frame walks the dirty cell list from the server and issues one textured quad per changed cell. No text layout, no shaping, no measurement per frame.

No WebView, no `xterm.js`, no JS bridge on the hottest path in the application. Justification: the terminal is a uniform grid of monospaced cells with no reflow — the single easiest thing in graphics to draw fast, and the single most latency-sensitive surface in the product. Putting a browser between the server's cell diff and the screen would add a JSON parse, a DOM diff, and a layout pass to a 16 ms budget for no benefit. It also gives us complete control over touch interaction, which is where every existing mobile terminal is weakest.

Complex scripts, emoji, and CJK fall back to a Compose text path with a per-cell cache; wide characters occupy two cells, matching the server's VT model.

**Editor → CodeMirror 6 in an Android `WebView`.**

Assets bundled in the APK and served from `file:///android_asset` — no CDN, works offline, and no remote code load surface. JavaScript is enabled; network access in the WebView is blocked outright, so even a compromised bundle cannot exfiltrate.

Justified plainly: **no acceptable native mobile code editor exists**, and CodeMirror 6 is the only serious editor that was rewritten with mobile as a design goal rather than an afterthought — it handles touch selection, IME composition, and virtual keyboards in ways a hand-rolled Compose editor would take years to approach. Building a native text editor with syntax highlighting, IME, undo, and touch selection is a multi-year project that would be worse than CM6 at every point along the way.

The WebView is deliberately dumb: it renders, it reports edits, it holds no protocol knowledge and never touches the network. All I/O goes through a typed JSON bridge to Kotlin and then to Rust. The security boundary is explicit — the WebView is treated as untrusted, and the bridge validates every message.

**Everything else → native Compose.** File tree, git, diffs, agents, settings are lists and forms; `LazyColumn` with stable keys wins outright.

### 6.4 Build

Gradle with `cargo-ndk` producing `.so` per ABI. `arm64-v8a` only for MVP (>95% of active Android devices); `armeabi-v7a` and `x86_64` (emulator) added at M6. Editor bundle built by Vite into `app/src/main/assets/editor/` as a Gradle task, so a stale editor build cannot ship. R8 with a keep rule for UniFFI JNA bindings.

### 6.5 Platform integration

- **Foreground service** while a session is active, with a persistent notification showing transport tier and RTT — required for a long-lived socket on modern Android, and honest about what it is doing.
- **Battery-optimisation exemption** requested with a clear explanation, plus per-OEM guidance (§24.2).
- **`ConnectivityManager.NetworkCallback`** drives immediate reconnect on network change rather than waiting for a timeout.
- **BiometricPrompt** with `CryptoObject` bound to the presence key, so the biometric is cryptographically attested rather than a UI-level check that a rooted device could skip.
- **Hardware keyboard detection** hides the accessory bar and enables real key handling — a phone in a keyboard case should behave like a terminal.
- **Split-screen and freeform** window support: editor beside terminal is genuinely useful on a large phone or foldable.

---

## 7. AI abstraction layer

The requirement: agents abstracted behind a common interface, managed as PTY processes, with the phone not knowing which AI is running, and no dependency on any provider.

### 7.1 Three integration levels

The key design move is a **graceful ladder** rather than a single mechanism. This is what makes "future agents" a solved problem instead of a backlog item.

**L0 — raw PTY.** Any CLI works with zero configuration. Spawn it in a PTY, stream the grid, forward input. `aider`, a REPL, a tool that ships next week — all work immediately. This is the floor, and it means GoNomad is never blocked on us writing an integration.

**L1 — manifest adapter.** A declarative TOML per agent turns screen output into structured events and native UI: approval cards, diff previews, task lists, state badges. **A new agent is added by writing a TOML file, not code** — including by users, for internal tools we will never see. That is what makes provider independence real rather than rhetorical.

**L2 — native structured protocol.** Where a tool offers a machine-readable stream — Claude Code's streaming-JSON output mode being the reference case — use it instead of scraping a rendered screen. Strictly more reliable: no regex fragility, no ANSI parsing, no breakage when the vendor adjusts their spinner.

**Screen scraping is the fallback, not the plan.** Level detection is automatic: probe for L2 support, fall back to a manifest if one matches the binary, else L0. The phone is told the level so it can show what it can support, but the `AgentSession` model is identical at every level.

### 7.2 Manifest format

```toml
name = "claude-code"
display_name = "Claude Code"
binary = "claude"
version_check = ["--version"]

[launch]
args = []
resume_args = ["--resume", "{session_id}"]
env = { TERM = "xterm-256color" }

[structured]                       # L2 — preferred when available
mode = "json-stream"
args = ["--output-format", "stream-json", "--verbose"]

[detect]                           # L1 — used when structured is unavailable
thinking      = ['^\s*[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏]\s', 'Thinking…']
awaiting_input = ['❯\s*$', '\?\s.*\(y/n\)']
approval      = ['Do you want to (proceed|make this edit)\?']
error         = ['^Error:', 'API error']
idle          = ['^\s*│\s*>\s*$']

[approval]
approve_key = "\r"                 # after selecting "yes"
deny_key    = "\x1b"
extract_diff = 'diff --git[\s\S]*?(?=\n\n|\z)'

[capabilities]
supports_resume = true
supports_cancel = true
cancel_key = "\x03"
```

Shipped manifests: `claude-code`, `codex`, `gemini`, `opencode`, `aider`, `generic`. Users drop their own in `~/.gonomad/adapters/`.

### 7.3 The uniform session model

The phone sees only this, for every agent at every level:

```rust
struct AgentSession {
    id: SessionId,
    adapter: String,            // for display only
    integration_level: Level,   // L0 | L1 | L2
    workspace: PathBuf,
    state: AgentState,          // Starting | Idle | Thinking | AwaitingApproval
                                // | AwaitingInput | Error | Exited
    transcript: TranscriptRef,  // paged, server-held
    pending_approval: Option<Approval>,
    created_at: Timestamp,
    last_activity: Timestamp,
    token_usage: Option<TokenUsage>,
}
```

No vendor names in any protocol type, no vendor-specific fields, no vendor branch in the phone's code. `adapter` is a display string. Swapping an agent changes a label.

### 7.4 Lifecycle

Sessions are daemon-owned and outlive connections (§2). Reattach shows the current grid plus the paged transcript. Two distinct notions of resume, and conflating them is a bug:

- **Reattach** — the process is still running; attach to its PTY. Instant.
- **Resume** — the process exited; relaunch with the adapter's `resume_args` to restore the agent's *own* conversation state.

The phone presents these as one "continue" affordance while the daemon does the right thing, because the distinction is an implementation detail from the user's chair.

Cancellation sends the adapter's `cancel_key` (usually `Ctrl-C`) rather than killing the process, so the agent can clean up. Escalate to SIGTERM, then kill, on a timeout.

### 7.5 Approval flow, and why it is a security feature

```
adapter detects approval prompt
   → extract the proposed change from the stream
   → daemon classifies destructiveness (writes outside root? deletes?
     git history rewrite? network egress? package install? secret access?)
   → notification (§24.1) + agent.approval_required event
   → phone renders the ACTUAL DIFF, syntax-highlighted, not the agent's summary
   → destructive? require presence-key biometric signature over the diff digest
   → approve → adapter's approve_key written to the PTY
   → audit entry with the diff digest
```

Two decisions here are security-critical.

**The phone renders the true diff, never the agent's description of it.** A prompt-injected agent will describe a malicious edit benignly. Displaying the actual textual change, with the destructive parts highlighted, is the only defence that does not depend on trusting the thing being audited.

**Destructive approvals require a fresh biometric.** The realistic attack is not cryptographic — it is a habituated user tapping a green button on a 6-inch screen while walking. Forcing a fingerprint for destructive operations breaks the habit loop precisely where it matters, and the signature covers the diff digest so it cannot be replayed onto a different change.

There is no auto-approve mode, and there will not be one. It would be the single most requested feature and the single largest hole in the product.

### 7.6 Extensibility

New agent, no code: write a TOML, drop it in `~/.gonomad/adapters/`, restart. Detection regexes are validated at load with a `regex` size limit to prevent catastrophic backtracking from a hostile or careless manifest. Manifests are the most fragile part of the system, so each ships with a recorded-transcript golden test (§24.11).

---

## 8. PTY management architecture

### 8.1 Library

`portable-pty` from the wezterm project — the most battle-tested cross-platform PTY abstraction in Rust, with real ConPTY support on Windows, which is decisive given a Windows-first target. Alternatives: `pty-process` (Unix only), `winpty-rs` (Windows only, and winpty is legacy next to ConPTY), raw `CreatePseudoConsole` (we would be reimplementing wezterm's hard-won workarounds).

### 8.2 Windows specifics

Windows is the primary host, and its PTY model differs from Unix in ways that must be designed for rather than discovered:

- **No `SIGWINCH`.** Resize is `ResizePseudoConsole`, an API call. The resize path is therefore an explicit protocol operation, not a signal.
- **`PSEUDOCONSOLE_RESIZE_QUIRK`** avoids ConPTY reflowing and duplicating content on resize — without it, rotating the phone corrupts the display.
- **`PSEUDOCONSOLE_WIN32_INPUT_MODE`** delivers full key events (modifiers, key-up) rather than lossy translated characters. Needed for correct `Ctrl`, `Alt`, and function keys from the phone's accessory bar.
- **`PSEUDOCONSOLE_PASSTHROUGH_MODE`** (Windows 11 22H2+) relays VT sequences from the child directly, avoiding ConPTY's own emulation layer. Detected at runtime; a real fidelity improvement where available.
- **Process-tree teardown** uses a **Job Object** per PTY. Windows has no process groups; killing the shell otherwise orphans its children. Without this, a killed terminal leaks `node`, `python`, and `docker` processes indefinitely — a bug that would be reported as "GoNomad eats my RAM."
- **Shell detection order:** PowerShell 7 (`pwsh`) → Windows PowerShell → WSL default distro → `cmd`. WSL is offered as a first-class shell choice, since many Windows developers effectively live there. Note that a WSL PTY's paths are Linux paths, so the FS layer keeps per-PTY path-translation context and never assumes a PTY's cwd shares the host's path namespace.
- Encoding is forced to UTF-8 (`chcp 65001`) at spawn, since ConPTY defaults to the legacy OEM code page.

### 8.3 The central decision: a headless terminal emulator on the server

**Each PTY has a full terminal emulator in the daemon** — `alacritty_terminal`, used as a library — maintaining the authoritative screen grid, cursor state, modes, and a capped scrollback ring.

The phone is not sent bytes. It is sent **cell diffs**.

Three consequences justify the whole design:

**Reconnect is one snapshot.** Attaching sends the current grid (a few KB) rather than replaying a byte stream. There is no scrollback replay, no re-parsing of ANSI on the phone, and no possibility of the phone's emulator state diverging from the server's.

**Bandwidth gets a hard ceiling.** This is the big one. Naive stdout streaming has no upper bound: `npm install`, a verbose test suite, or `yes` produces megabytes per second, and every byte crosses a cellular link, gets decoded on the phone, and drains the battery — to render frames the user cannot possibly read. With server-side emulation, output is coalesced into at most N frames per second of *visible cell changes*. A runaway process becomes ~30 small diffs per second regardless of how fast it writes. **The bandwidth cost of a command becomes a function of what changes on screen, not of how much the program prints.**

**The phone can be genuinely dumb.** No VT parser, no ANSI state machine, no scrollback buffer, no reflow logic on the phone. That is why the Compose `Canvas` renderer can be a few hundred lines and still be fast.

Scrollback: a fixed-capacity ring buffer per PTY (default 10,000 lines), spilled to a capped on-disk file, paged on demand. It lives in the daemon, so it survives disconnects and app kills.

### 8.4 Lifecycle

```
spawn(shell, cwd, size, env) → PtyId
  ├─ Job Object created (Windows)
  ├─ VT emulator + scrollback ring allocated
  ├─ reader task → parse → update grid → mark dirty cells → coalesce → emit
  └─ writer task ← input frames (with a 16 ms coalescing window)

attach(PtyId)   → full grid snapshot + subscribe to diffs
detach(PtyId)   → stop diffs; process keeps running
resize(w, h)    → ResizePseudoConsole / TIOCSWINSZ; grid reflow; full resend
restart(PtyId)  → same argv, same cwd, same name; grid cleared
kill(PtyId)     → cancel_key → SIGTERM/CTRL_BREAK → timeout → job terminate
```

Named sessions, so "the test terminal" is findable across days. Optional idle reaping, off by default (a long-running dev server must not be reaped). Hard cap of 16 concurrent PTYs.

### 8.5 Output pipeline

```
PTY bytes → VT parser → grid mutation → dirty-cell set
   → coalesce over a frame window (adaptive 16–200 ms)
   → if dirty > 60% of cells: send a full-grid frame instead of diffs
   → zstd with a terminal-tuned dictionary
   → PTY stream
```

The 60% threshold matters: past it, a diff list is larger than the grid it describes, so sending the whole grid is both smaller and simpler. A full-screen redraw (`clear`, `vim` opening, `htop` refreshing) hits this path naturally.

---

## 9. Authentication & pairing flow

### 9.1 The flow

```
LAPTOP                                    PHONE
──────                                    ─────
$ gonomad pair
  ├─ enter pairing mode (120 s, single use)
  ├─ generate 256-bit pairing secret
  └─ render QR in the terminal + tray
        │
        │  QR: { v, node_id, relay_hint, addr_hints[], secret }
        │                                   │
        │                            scan QR ─┘
        │                                   │
        │◄────── connect by node_id ────────┤
        │                                   │
        │◄──── Noise IK, PSK = secret ─────►│   MITM impossible: the
        │                                   │   responder key came over
        │                                   │   the optical channel
        │                                   │
   both derive SAS = BLAKE2s(transcript)[0..3] → 6 digits
        │                                   │
  ┌─────▼──────────────────┐        ┌───────▼────────┐
  │ Allow this device?     │        │  418 273       │
  │ "Pixel 9 Pro"          │        │  Confirm this  │
  │ SAS: 418 273           │        │  matches your  │
  │ Roots: [gonomad]       │        │  laptop        │
  │ Caps:  [fs, pty, git]  │        └────────────────┘
  │   [Deny]  [Allow]      │
  └────────────────────────┘
        │
   store peer pubkey + grant + roots + caps
   audit: device_paired
        │
        └──► future connections: no login, no token. The key is the credential.
```

### 9.2 Why this is secure

**The QR is the out-of-band channel.** It carries 256 bits of entropy and is transferred optically over a channel an attacker must be physically present to observe. That is what defeats MITM (T1) — the phone learns the laptop's *authentic* static public key from a channel the network attacker cannot touch. This is strictly stronger than trust-on-first-use, which is what SSH does and which is vulnerable at exactly this moment.

**The SAS is defence in depth.** With a 256-bit optically-transferred secret, the PAKE-style confirmation is arguably redundant. It is included because the QR *can* leak — photographed over a shoulder, captured by a screen-sharing session, or visible in a recording. The 6-digit SAS is derived from the full handshake transcript, so an attacker who has the secret but is proxying the connection produces different digits on each side, and the mismatch is visible to the human.

**The laptop-side prompt requires physical presence.** Even with a valid secret, pairing needs a human at the laptop to approve, name the device, and set its scope. Pairing is the only moment an unpaired key can be accepted, and it is bounded to 120 seconds, single-use, and rate-limited to 3 attempts.

### 9.3 Manual-entry fallback

For a broken camera, an 8-character Crockford-Base32 code (~40 bits). Because 40 bits is brute-forceable in principle, this path uses a **real PAKE — SPAKE2+ or CPace** — rather than treating the code as a shared secret. A PAKE ensures each online guess costs one full protocol round against a rate-limited server (3 attempts, then the code dies), so a low-entropy secret remains safe. Using the same bearer-secret treatment as the QR path here would be a genuine vulnerability, which is why the two paths differ.

### 9.4 Device management

Rename; list with model, pairing date, last seen, current transport tier, capabilities; edit capabilities and workspace roots per device; revoke (immediate, server-side); force-disconnect without revoking; view a per-device audit trail. Available from the laptop, and from the phone with `policy:write` plus a biometric.

### 9.5 Recovery

At `gonomad init`, a 24-word recovery phrase is displayed once, with instructions to write it down. It seeds the daemon's identity key deterministically, so a reinstalled daemon can restore the same identity and existing phones reconnect without re-pairing. Device grants are exported alongside as an encrypted blob.

Because the recovery phrase is equivalent to the daemon identity, it is displayed exactly once, never stored, and never transmitted. Without it, re-pairing every device is the recovery path — inconvenient but not catastrophic, which is the correct failure mode for a tool with no account system.

---

## 10. Wire protocol

The brief asked for a "WebSocket protocol." The honest answer is that **QUIC streams are strictly better here**, and a WebSocket is the fallback binding rather than the primary design. This section explains why and specifies both.

### 10.1 Why not a WebSocket as the primary

A WebSocket is a single ordered byte stream. To carry 4 terminals, a file download, a search, and a keystroke concurrently, we would have to build a multiplexer with per-channel flow control on top — which is a poorer reimplementation of what QUIC ships natively. Worse, a single TCP connection means **head-of-line blocking across all channels**: one lost packet during a 40 MB download stalls every keystroke behind it. And TCP's 4-tuple identity means every Wi-Fi↔LTE switch kills the connection.

So: **an abstract framed protocol with two bindings.** QUIC streams (primary), and a single WebSocket with a userspace mux (fallback for Tier 3 tunnels). One codec, one security layer, both paths.

### 10.2 Stream topology

| Stream | Direction | Purpose |
|---|---|---|
| Control (first bi-stream) | Both | Hello, requests/responses, events, heartbeat, subscriptions |
| PTY stream (one per PTY) | Both | Grid diffs down, input up |
| Bulk stream (per transfer) | One | File up/download, transcript pages, diff blobs |
| Subscription stream | Down | FS change firehose, git state, agent state |

One stream per concern is not stylistic. A 40 MB download on its own stream cannot delay a keystroke on the control stream, because QUIC flow-controls them independently. A search returning 10,000 matches streams on its own stream and can be cancelled by resetting it, with no protocol-level cancel message needed.

### 10.3 Framing and encoding

```
┌────────────┬──────────┬──────────────────────────┐
│ len: u32   │ flags:u8 │ payload                  │
│ (BE)       │          │ (CBOR or raw, maybe zstd)│
└────────────┴──────────┴──────────────────────────┘
flags: bit0 compressed · bit1 raw (not CBOR) · bit2 last-in-sequence
```

**CBOR for control frames.** Chosen over Protobuf, JSON, and postcard/bincode:

- vs **JSON** — binary, so no base64 for file bytes and no number-precision hazards; meaningfully smaller and faster.
- vs **Protobuf/Cap'n Proto** — no schema-compiler build step in either the Rust or Kotlin build, and self-describing frames can be dumped and read during debugging. For a protocol evolving under an open-source contributor base, inspectability is worth more than the last few percent of size.
- vs **postcard/bincode** — these are more compact and faster, and would be the choice if both ends were Rust. Since `gonomad-core` *is* on both ends, that is nearly true. CBOR wins anyway because the WebSocket fallback and any future third-party client benefit from self-description, and because a non-self-describing format makes protocol debugging materially harder for contributors. Size is recovered by compression.

Raw bytes for bulk transfer and for the (rare) raw PTY passthrough mode — no reason to wrap a file's bytes in anything.

**Compression: zstd level 3 with a pre-trained dictionary.** A trained dictionary is the important part: control frames and terminal diffs are small (often <500 bytes) and highly repetitive, and generic compression performs poorly on small payloads because there is no window history to exploit. A dictionary trained offline on representative traffic yields large ratios on exactly these frames. Two dictionaries ship in the binary — one for control/JSON-ish frames, one for terminal grid diffs — versioned and negotiated at hello. Frames below 128 bytes skip compression; the flag bit records the decision per frame.

### 10.4 Handshake

```
→ Hello { proto_version, min_supported, client_version, device_id,
          capabilities_requested, compression_dicts[], features[] }
← HelloOk { proto_version, server_version, granted_capabilities,
            workspace_roots[], compression_dict, server_features[],
            session_id, resume_token }
   or HelloReject { reason: VersionTooOld | Unpaired | Revoked | RateLimited }
```

Version negotiation is explicit and fails loudly: additive-only fields, unknown fields ignored, and a hard minimum-supported floor. Skew between phone and daemon must produce a clear "update your daemon" screen (§24.7) rather than mysterious partial breakage — a genuine hazard for a self-hosted tool where the two halves update independently.

### 10.5 Request/response and events

Requests carry a `u64` correlation id and an optional `idempotency_key`. Responses carry the same id. Long operations stream `Progress` frames and terminate with `Done` or `Error`. Cancellation is `Cancel { correlation_id }`, or resetting the stream for stream-scoped work.

Events are unsolicited server pushes on the control or subscription stream, each with a monotonic sequence number so a client can detect a gap and resynchronise:

`fs.changed` · `pty.output` · `pty.exited` · `git.state_changed` · `agent.state_changed` · `agent.approval_required` · `task.finished` · `policy.changed` · `device.connected` · `notification`

### 10.6 WebSocket fallback binding

For Tier 3 transports, a single WebSocket carries the same frames with a 4-byte channel id prepended and a credit-based per-channel flow-control scheme (`WINDOW_UPDATE`-style, borrowed from HTTP/2 since the problem is identical). Noise IK still wraps everything, so a Cloudflare Tunnel or an nginx reverse proxy sees ciphertext. This binding accepts head-of-line blocking — which is precisely why it is the fallback and not the default.

---

## 11. API design

Namespaced RPC over the control stream. Every method is capability-checked, path-guarded, cancellable, and audited by the router (§2) rather than by the service, so a service cannot forget.

### 11.1 Method surface

**`fs.*`**

| Method | Notes |
|---|---|
| `fs.list(path, opts)` | One directory level. `opts`: `show_hidden`, `respect_gitignore`, `sort`, `limit`, `cursor`. Returns entries with name, kind, size, mtime, git status, symlink target |
| `fs.stat(path)` | Metadata + content hash |
| `fs.read(path, range?)` | Content + `content_hash` (the CAS baseline). `range` is a line or byte window for large files |
| `fs.write(path, base_hash, edits[])` | **Compare-and-swap.** Fails `Conflict` if `base_hash` is stale |
| `fs.create(path, kind)` · `fs.delete(paths[])` · `fs.move(from, to)` | `delete` of >10 entries needs presence |
| `fs.upload_begin/chunk/commit` · `fs.download(path)` | Bulk stream, resumable, hash-verified |
| `fs.watch(roots[])` · `fs.unwatch(id)` | Subscription; emits `fs.changed` |

**`search.*`** — `search.content(query, opts)` streams matches (regex or literal, case/word/glob filters, gitignore-aware, capped and cancellable); `search.files(query)` fuzzy path match against the FST index; `search.replace(query, replacement, paths[], dry_run)` which **defaults to `dry_run = true`** and returns a preview, because a regex replace across a repository from a phone is exactly the operation you want to be hard to do by accident.

**`pty.*`** — `spawn`, `attach`, `detach`, `input`, `resize`, `signal`, `restart`, `kill`, `list`, `scrollback(id, range)`, `rename`.

**`git.*`** — `status`, `diff(spec)`, `log(opts)`, `blame`, `show`, `branches`, `stage`/`unstage`, `commit(message, opts)`, `push`/`pull`/`fetch` (streaming progress), `checkout`, `branch_create`/`delete`, `stash_*`, `conflicts`, `resolve`. Mutations that rewrite history require `git:dangerous` plus presence.

**`agent.*`** — `adapters`, `spawn`, `attach`, `detach`, `input`, `approve(id, decision, presence_sig?)`, `cancel`, `restart`, `resume`, `list`, `transcript(id, range)`, `kill`.

**`device.*` / `policy.*`** — `device.list`, `rename`, `revoke`, `disconnect`, `grants`; `policy.get`, `set` (presence), `audit(range)`, `audit_verify`.

**`sys.*`** — `info` (OS, shells, detected tools, versions), `notify_config`, `task_list`, `doctor`.

### 11.2 Conventions

**Errors** are a closed enum, never strings: `Denied { capability }`, `NotFound`, `Conflict { current_hash }`, `RateLimited { retry_after_ms }`, `ResourceExhausted { resource }`, `Unsupported { feature }`, `PresenceRequired { challenge }`, `Cancelled`, `Internal { trace_id }`. A closed enum means the phone can render a *correct, actionable* message for every failure — `Conflict` opens the conflict screen, `PresenceRequired` triggers the biometric prompt and retries automatically, `Unsupported` shows the version-skew screen. String errors would make all of that impossible.

**Pagination** is cursor-based, never offset — directory contents change under you, and offsets skip or duplicate entries when they do.

**Cancellation** is universal. Every long operation takes a correlation id that can be cancelled, and cancellation propagates to the Tokio task, the `spawn_blocking` job, and the child process. Non-cancellable work on a mobile client is a bug: users navigate away constantly.

**Idempotency** on all mutations, keyed by a client UUID retained 5 minutes, so a network-level retry cannot double-commit or double-write.

---

## 12. File synchronisation strategy

### 12.1 No bidirectional sync, and no CRDT

The laptop's filesystem is the **single source of truth**. The phone holds an optimistic local buffer. There is no CRDT, no OT server, and no merge engine.

This is the most consequential decision in this section, and it is right for a reason specific to this product: **the laptop's files are concurrently edited by VS Code, git, and AI agents.** A CRDT would have to model those three as peers — but none of them will ever speak our protocol. `git checkout` rewrites a hundred files atomically with no per-character intent; Claude Code rewrites a function wholesale; VS Code writes through its own save pipeline. A CRDT in that environment provides the *illusion* of conflict-free merging while silently producing results no participant intended.

Instead: an authoritative filesystem with **compare-and-swap writes**, which is strictly honest — it either applies exactly what the user intended or tells them the world moved.

### 12.2 Compare-and-swap writes

```
phone → fs.write { path, base_hash: BLAKE3(content when opened), edits: [{from, to, insert}] }

daemon:
  read current file → hash it
  hash == base_hash ?
    ✅ apply edits atomically (temp file + rename) → return new_hash
    ❌ return Conflict { current_hash }
```

Lost updates become structurally impossible. Contrast with a naive "write the whole buffer" design: the phone would silently clobber an AI agent's edit made 3 seconds earlier, and the user would never know. That failure is invisible and unrecoverable, which is why CAS is worth the extra round trip.

On `Conflict`, the daemon attempts a three-way merge (base, phone edits, current file). Non-overlapping hunks merge automatically and the user is told. Overlapping hunks open the conflict screen showing both versions side by side. **Never a silent overwrite, and never a silent discard of the user's typing.**

Edits are transmitted as ranged operations, not whole files — a one-character fix in a 2 MB file is a ~100-byte frame.

### 12.3 Server → phone changes

`fs.changed` events carry a diff, not content. If the phone has the file open, the editor applies the patch, preserving the cursor and the undo stack where the patch does not intersect the cursor's line. If it does intersect, the user is prompted rather than having the cursor yanked mid-word.

An external change to a file with unsaved local edits shows a non-blocking banner — "changed on disk · [View diff] [Keep mine] [Take theirs]" — rather than a modal, because a modal that appears while you are typing is worse than the problem it reports.

### 12.4 Offline writes

Edits made offline queue in Room. On reconnect they replay through the same CAS path. If the base hash has gone stale, the same merge-then-conflict ladder applies. The queue is capped and visible, and the user can inspect and discard entries — a silent unbounded queue that eventually replays surprising writes is a genuine hazard.

### 12.5 Indexing at scale: millions of files

**No eager global scan, ever.** A `node_modules`-heavy monorepo can hold millions of paths and a full walk would take minutes, hammer the disk, and destroy battery on any device waiting for it.

**Directory listing** is lazy and per-level, through ripgrep's `ignore` crate — which brings correct, layered `.gitignore` / `.ignore` / `.git/info/exclude` / global-excludes handling for free, and which is genuinely hard to reimplement correctly. Results are cached per directory and invalidated by watcher events.

**Fuzzy file open** uses an **FST-backed path index** (`fst` crate — a compressed finite-state transducer). This is chosen over a naive in-memory trie or a `Vec<String>` on space grounds: 1M paths in an FST is single-digit MB versus roughly 50 MB unpacked, and it supports prefix and fuzzy (Levenshtein-automaton) queries directly over the compressed form. The index is built lazily in the background on first use, persisted to `~/.gonomad/index/<workspace>.fst`, and updated incrementally from watcher events. Users see a progress indicator on first build and never wait for it again.

**Content search** always streams through ripgrep's engine (`grep-searcher` + `grep-regex`) with result caps, a deadline, and early termination. It is never materialised and never cached — a search index over a working tree would be stale by the time it finished.

### 12.6 Watcher discipline

- **One recursive watcher per workspace root.** Per-directory watchers exhaust `inotify` limits on large trees (a common, hard-to-diagnose failure in every file-watching tool). `ReadDirectoryChangesW` is natively recursive, which favours the Windows-first target; macOS FSEvents likewise.
- **Filter before emitting.** Apply gitignore rules in the daemon. A `cargo build` generating 50,000 `target/` events must produce zero protocol frames — otherwise a single build saturates the connection.
- **Debounce 50–100 ms and coalesce** per path, collapsing the write-write-rename storms that editors produce into one logical change.
- **Degrade gracefully.** If the OS refuses to watch a tree (limits, network filesystem), fall back to on-demand polling of visible directories only, and tell the user the tree is not live rather than silently showing stale data.
- Never watch `.git/objects`, `node_modules`, `target`, `.next`, `dist`, `__pycache__`, or `venv` by default.

---

## 13. Terminal architecture

Server-side authority is covered in §8. This section is the client and the interaction model — the part that determines whether coding from a phone is pleasant or merely possible.

### 13.1 Grid diff protocol

```rust
enum GridFrame {
    Full  { cols, rows, cells: Vec<Cell>, cursor, modes },
    Diff  { runs: Vec<CellRun>, cursor, scroll: Option<ScrollRegion> },
    Scroll{ region, lines },           // scroll is a hint, not a repaint
    Bell, TitleChanged(String),
}
struct CellRun { row: u16, col: u16, cells: Vec<Cell> }   // runs, not points
struct Cell { ch: char, fg: Color, bg: Color, attrs: u8 }
```

Runs rather than individual cells, because terminal changes are overwhelmingly horizontal — a printed line is one run, not 80 point updates. Scroll is transmitted as a scroll hint so the client shifts its buffer instead of receiving a full repaint, which is what makes `tail -f` and a scrolling build log nearly free.

### 13.2 Adaptive frame rate

| Condition | Rate |
|---|---|
| Foreground, user interacting | 60 fps |
| Foreground, passive output | 30 fps |
| Poor network (RTT > 300 ms) | 10 fps |
| Backgrounded | 0 (buffer server-side; notify on completion) |

Frames are coalesced in the daemon, so a process printing at 100 MB/s still produces 30 small frames per second. Bandwidth is a function of visible change, not of program output volume.

### 13.3 Rendering

Compose `Canvas`, glyph atlas (§6.3). Only dirty regions repaint. Scrollback is virtualised — only the visible window plus a small overscan is materialised, and older pages are fetched on demand from the daemon's ring buffer. Default 12sp monospace at 8 pt-wide cells gives roughly 55 columns in portrait on a modern phone, which is enough for real work and far more than a scaled desktop stream provides.

### 13.4 Touch interaction

Every existing mobile terminal is weakest here, so this is specified in detail.

| Gesture | Action |
|---|---|
| Tap | Focus, show keyboard |
| Two-finger vertical drag | Scroll scrollback (one finger is reserved for selection) |
| Horizontal swipe | Shell history (↑/↓) — the single highest-value gesture in the app |
| Pinch | Font size, live |
| Long press | Selection with a magnifier |
| Two-finger tap | Paste |
| Edge swipe | Switch terminal tab |

**Accessory keyboard row** — persistent above the system keyboard, and the thing that makes a phone terminal usable at all:

```
┌──────────────────────────────────────────────────────────┐
│ Esc  Tab  Ctrl  Alt  ←  ↓  ↑  →   |   /   ~   $   -  ⌄  │
└──────────────────────────────────────────────────────────┘
   expanded (⌄):  ^C  ^D  ^Z  ^L  ^R  ^A  ^E  ^K  ^W  F1-12
   user macros:   [git status] [npm test] [clear] [+]
```

`Ctrl` and `Alt` are **sticky modifiers** — tap to arm, and the next key is modified. This is essential: holding a modifier while reaching for another key is not a gesture a thumb can perform, and every terminal app that requires it is unusable one-handed.

**Tappable `file:line` references.** Output is scanned for `path:line:col` patterns (and language-specific forms — Rust `-->`, Python tracebacks, TypeScript, ESLint), which render underlined and open the editor at that position. This converts a stack trace from something to squint at into navigation, and it is one of the highest-leverage features in the product for the effort involved.

**Output folding.** Long command output is collapsible with a summary line ("+ 4,213 lines"), auto-folding known-verbose blocks (`npm install` trees, webpack output). A 4,000-line build log becomes scannable instead of a wall to scroll past.

### 13.5 Tabs

A horizontally scrollable pill row, each pill showing name, a state dot (running / idle / exited non-zero), and an unread-output badge. A full-screen switcher shows live thumbnails of each grid — the best way to answer "which one was the dev server?" on a small screen. Reorder by drag; close by swipe-up in the switcher, which is deliberately not on the pill so a mis-swipe cannot kill a running process.

---

## 14. Performance optimisations

Each optimisation is tied to a stated product goal, and each budget is enforced in CI.

### 14.1 Latency budgets

| Path | Target | Ceiling |
|---|---|---|
| Keystroke → echo (LAN) | 20 ms | 50 ms |
| Keystroke → echo (relay, 60 ms RTT) | 80 ms | 150 ms |
| Editor keystroke → glyph (local buffer) | 8 ms | 16 ms |
| Cold app open → last session visible | 400 ms | 1 s |
| File open (< 100 KB) | 80 ms | 250 ms |
| Directory expand (cached) | 16 ms | 50 ms |
| Search first result | 150 ms | 500 ms |
| Reconnect after network change | 300 ms | 1.5 s |

| Resource | Target |
|---|---|
| Daemon idle memory | < 25 MB |
| Daemon per PTY | < 2 MB (10k-line scrollback) |
| Daemon idle CPU | < 0.1% |
| Phone memory | < 150 MB |
| Phone battery, active session | < 4%/hour |
| Phone battery, idle connected | < 1%/hour |
| Bandwidth, active terminal | < 5 KB/s |
| Bandwidth, idle connected | < 100 B/s |

### 14.2 Techniques

**Input coalescing.** Keystrokes batch over 16 ms, flushing immediately on Enter, Tab, or any control character. Typing "hello" is one frame, not five — a 5× reduction in packet count on the most frequent operation, with no perceptible added latency.

**Local echo in the editor.** The CM6 buffer applies keystrokes instantly and reconciles with the server asynchronously. Editor typing latency is therefore independent of network RTT — the difference between usable and unusable on a 200 ms link.

**Cell diffs, not byte streams** (§8.3). The single largest bandwidth and battery win.

**Dictionary-trained zstd** (§10.3). Large ratios on the small frames that dominate frame count.

**Adaptive frame rate** (§13.2) and network-quality adaptation driving frame rate, compression level, prefetch aggressiveness, and syntax-highlight strategy.

**FST path index** (§12.5) — instant fuzzy open over millions of paths, single-digit MB.

**Streaming search** with caps, deadlines, and early termination; first results render while the search continues.

**Lazy everything.** Directory levels on expand. File windows on scroll. Scrollback pages on demand. Transcript pages on demand. Nothing is prefetched that the user has not looked toward.

**QUIC 0-RTT and connection migration** (§4.4) — instant cold open, no reconnect on network change.

**Glyph atlas reuse** (§6.3) — no per-frame text layout.

**`LazyColumn` with stable keys** everywhere, so recomposition is bounded by visible items.

**Rust-side caching.** The core holds parsed state; Kotlin never re-parses a frame. Recomposition reads immutable snapshots.

**Bounded pools with explicit overflow policies** (§2), so one runaway resource cannot starve another.

### 14.3 CI enforcement

A benchmark suite runs on every PR: `criterion` for the VT parser, diff computation, codec, and path canonicalisation; a Macrobenchmark suite on a physical device for cold start, scroll jank, and frame timing; a bandwidth harness that replays recorded terminal sessions and asserts byte ceilings. Exceeding a budget fails the build. Without CI enforcement, performance goals decay into aspirations within a quarter.

---

## 15. Offline strategy

### 15.1 Why this is easy here

Because the daemon owns all state (§2), the phone going offline does not end a session — it ends a *view* of one. There is no session-recovery protocol to design, and no partial-state reconciliation, because the terminal, the agent, and the build never stopped. This is the payoff for the central invariant.

### 15.2 Connection states, made visible

```
Connected(Lan)      ← green   · "LAN · 2 ms"
Connected(Direct)   ← green   · "Direct · 34 ms"
Connected(Relay)    ← yellow  · "Relayed · 120 ms"
Degraded            ← yellow  · "Poor connection"
Reconnecting(n)     ← orange  · "Reconnecting… (3)"
Offline             ← grey    · "Offline · viewing cache"
Unpaired / Revoked  ← red     · terminal state, needs user action
```

Always visible as a chip in the top bar. **Silently-degraded is worse than visibly-degraded**: a user who knows they are on a relay attributes slowness correctly; a user who does not blames the app and files a bug.

### 15.3 Reconnection

Exponential backoff with full jitter: 500 ms → 1 s → 2 s → 4 s → 8 s → 15 s → 30 s cap. Jitter matters even with a single client, because a phone reconnecting in lockstep with a network flap produces a retry storm.

Triggers that bypass backoff: Android `NetworkCallback` reporting a new network, app returning to foreground, or the user tapping the status chip. Waiting out a 30-second backoff after the user has visibly regained signal feels broken, so network-change-driven immediate retry is not optional.

Heartbeat every 15 s while foregrounded (30 s when idle, none when backgrounded), on top of QUIC keepalive. QUIC connection migration means most network changes need no reconnect at all — the connection simply continues on the new path.

### 15.4 Resumption

`resume_token` from the hello exchange identifies prior session state, so on reconnect: re-attach to previously attached PTYs, re-establish watchers, re-subscribe to agent sessions, and receive a full grid snapshot per terminal. QUIC 0-RTT means this is a single round trip.

### 15.5 Offline capability

| Feature | Offline |
|---|---|
| Recently viewed files | ✅ read from cache |
| File tree (visited nodes) | ✅ cached, marked stale |
| Terminal scrollback (last screen) | ✅ read-only |
| Agent transcripts (fetched) | ✅ read-only |
| Git status (last known) | ✅ marked stale |
| Editing | ✅ queued, replayed via CAS (§12.4) |
| Anything requiring execution | ❌ queued or refused, clearly |

Stale data is labelled as stale. Presenting cached data as live is the fastest way to lose a user's trust in a development tool.

### 15.6 Backgrounding

The phone disconnects when backgrounded beyond a short grace period, to protect battery. The daemon buffers, coalesces, and — for events the user asked to be told about — sends a notification (§24.1). On return, one 0-RTT reconnect restores everything. A foreground service keeps the connection alive during explicitly long-running interactive work, with a persistent notification that says so.

---

## 16. Database & storage decisions

### 16.1 Laptop: SQLite

`rusqlite` with the `bundled` feature — SQLite compiled in, so there is no system dependency and the "one binary" promise holds. WAL mode, `synchronous = NORMAL`, foreign keys on.

Rejected: **Postgres/MySQL** (a database daemon violates simple-deploy outright); **sled/redb** (fine key-value stores, but we need relational queries over the audit log and device grants, and SQLite's durability record and tooling are unmatched at this size); **JSON files** (no atomicity, no concurrent access, and an audit log needs both); **an ORM** (`sqlx`/Diesel add compile-time cost and indirection for a schema this small — hand-written SQL in a repository module is clearer).

```sql
devices(id, pubkey UNIQUE, name, model, paired_at, last_seen, revoked_at)
grants(device_id, capability, granted_at, granted_by)
workspace_roots(device_id, path)
audit(seq PK, ts_utc, monotonic_ns, device_id, operation, args_digest,
      result, prev_hash, hash)                          -- §3.9 chain
pty_sessions(id, name, shell, cwd, created_at, exited_at, scrollback_path)
agent_sessions(id, adapter, workspace, state, created_at, last_activity,
               transcript_path, agent_native_session_id)
editor_tabs(device_id, path, cursor_line, cursor_col, scroll_top, dirty)
snippets(id, workspace, label, command, use_count)      -- run chips
notifications(id, ts, kind, payload, delivered, read)
settings(key, value)
schema_version(version)
```

**Not in SQLite:** file content, scrollback, and transcripts. Those are capped on-disk files (scrollback as a fixed-size ring, transcripts as append-only with rotation), because storing megabytes of terminal output as SQLite rows bloats the database, slows every query, and gains nothing — there is no query we want to run over raw scrollback that a paged file read does not serve.

Migrations are numbered, forward-only, and applied in a transaction at startup, with a pre-migration backup copy retained.

### 16.2 Phone: Room + Keystore

Room over SQLite, treated strictly as cache and outbound queue (§2):

```
cached_files(path, content, content_hash, fetched_at, stale)
cached_tree(path, entries_json, fetched_at, stale)
pending_writes(id, path, base_hash, edits_json, queued_at)   -- §12.4
recent_paths(path, opened_at)
agent_transcript_cache(session_id, page, content)
settings(key, value)
```

`EncryptedSharedPreferences` for small non-key secrets (the paired daemon's `NodeId`, relay hints, the ntfy topic). Keys never leave Keystore (§3.3). Cached content is subject to Android's file-based encryption plus an app-level size cap with LRU eviction, and a "clear cache" action in settings that actually clears it.

The rule: **anything in Room can be deleted at any time without data loss.** `pending_writes` is the sole exception, and it is the one table with a visible UI so the user is never surprised by a queued write.

---

## 17. Folder structure

```
gonomad/
├─ Cargo.toml                    # workspace
├─ ARCHITECTURE.md               # this document
├─ plan.md                       # roadmap + milestone checklists
├─ README.md
├─ LICENSE                       # Apache-2.0
├─ deny.toml                     # cargo-deny gates
│
├─ crates/
│  ├─ gonomad-proto/             # frame schema, CBOR codec, version negotiation
│  │  └─ src/{frame.rs, control.rs, events.rs, errors.rs, version.rs}
│  │
│  ├─ gonomad-core/              # ★ SHARED with the phone via UniFFI
│  │  └─ src/{session.rs,        #   Noise IK handshake + session
│  │           router.rs,        #   correlation ids, pending requests
│  │           reconnect.rs,     #   backoff, triggers, resumption
│  │           cache.rs,         #   client-side cache coherence
│  │           grid.rs,          #   apply cell diffs to a local grid
│  │           queue.rs,         #   offline write queue
│  │           state.rs}         #   observable state machines
│  │
│  ├─ gonomad-transport/
│  │  └─ src/{iroh.rs, mdns.rs, websocket.rs, ladder.rs, traits.rs}
│  │
│  ├─ gonomad-pty/
│  │  └─ src/{spawn.rs, conpty.rs, jobobject.rs, vt.rs, grid.rs,
│  │           scrollback.rs, diff.rs, shells.rs}
│  │
│  ├─ gonomad-fs/
│  │  └─ src/{list.rs, watch.rs, index.rs, cas.rs, path_guard.rs,
│  │           transfer.rs}
│  │
│  ├─ gonomad-search/            # grep-searcher streaming + fuzzy path match
│  ├─ gonomad-git/               # gix reads · git CLI mutations
│  ├─ gonomad-agents/            # registry, manifest loader, detectors, approvals
│  ├─ gonomad-policy/            # capabilities, path guards, rate limits, presence
│  ├─ gonomad-store/             # sqlite, migrations, hash-chained audit
│  ├─ gonomad-notify/            # ntfy · local · optional FCM relay
│  │
│  ├─ gonomad-ffi/               # UniFFI surface → Kotlin bindings
│  │  └─ src/{lib.rs, gonomad.udl}
│  │
│  └─ gonomad-server/            # daemon + `gonomad` CLI + tray UI
│     └─ src/{main.rs, cli/, daemon.rs, router.rs, tray.rs, config.rs,
│              doctor.rs, services/}
│
├─ android/
│  ├─ settings.gradle.kts
│  └─ app/src/main/
│     ├─ kotlin/dev/gonomad/
│     │  ├─ core/                # UniFFI wrappers, Flow adapters
│     │  ├─ ui/
│     │  │  ├─ pair/  workspace/  tree/  editor/  search/
│     │  │  ├─ terminal/          # ★ Canvas renderer + glyph atlas
│     │  │  ├─ agent/  git/  diff/  devices/  security/  settings/
│     │  │  └─ common/            # accessory bar, status chip, palette
│     │  ├─ platform/            # Keystore, biometrics, foreground service,
│     │  │                       #   network callbacks, notifications
│     │  └─ MainActivity.kt
│     └─ assets/editor/          # ← built by Vite from editor/
│
├─ editor/                       # CodeMirror 6 bundle
│  └─ src/{main.ts, bridge.ts, theme.ts, languages.ts, touch.ts}
│
├─ adapters/                     # AI agent manifests
│  └─ {claude-code,codex,gemini,opencode,aider,generic}.toml
│
├─ docs/
│  ├─ README.md  deployment.md  threat-model.md  glossary.md  ci.md
│  ├─ protocol.md  adapters.md          # land with M1 / M5
│  └─ threat-model.md  adapters.md
│
└─ .github/workflows/            # ci · bench · release (reproducible + signed)
```

Two structural notes. `gonomad-core` is deliberately unaware of the filesystem and of process spawning — it is a pure protocol and state crate, which is what makes compiling it into an Android app sane. And `gonomad-policy` is a dependency of the service layer rather than a sibling, so services cannot be reached except through it.

---

## 18. Recommended technology stack

Every choice with its rejected alternative and the reason.

### 18.1 Backend

| Concern | Choice | Rejected | Why |
|---|---|---|---|
| Language | **Rust** | Go, Bun, Node | §5.1 — ecosystem fit, Windows PTY, code sharing with the phone |
| Async runtime | **Tokio** | async-std, smol | Ecosystem gravity; everything below assumes it |
| Transport | **iroh 1.0** | Tailscale, CF Tunnel, WebRTC, raw WG | §4 — embeddable, accountless, self-hostable relay, QUIC |
| QUIC | **Quinn** (via iroh) | s2n-quic, quiche | iroh's choice; pure Rust, mature |
| PTY | **portable-pty** (wezterm) | pty-process, winpty-rs, raw ConPTY | Only mature cross-platform option with real ConPTY |
| VT emulator | **alacritty_terminal** | vt100, wezterm-term, termwiz | Fastest correct VT parser usable as a library; §8.3 needs it |
| Directory walk | **ignore** (ripgrep) | walkdir, jwalk, hand-rolled | Correct layered gitignore semantics for free — genuinely hard to replicate |
| Content search | **grep-searcher + grep-regex** | shelling out to `rg`, regex crate alone | ripgrep's engine in-process; no external binary to ship |
| Path index | **fst** | trie, Vec\<String\>, tantivy | Compressed FST: ~MBs for 1M paths, native fuzzy queries; tantivy is a full-text engine we do not need |
| FS watching | **notify** + `notify-debouncer-full` | hand-rolled per-platform | Wraps ReadDirectoryChangesW / inotify / FSEvents; debouncer solves editor write storms |
| Git reads | **gix** | git2 (libgit2), go-git | Pure Rust, no C dependency, fast status/diff/log |
| Git mutations | **the `git` CLI** | gix, libgit2 | See below — this one matters |
| Highlighting | **tree-sitter** (server) + CM6 (client) | server-only, client-only | Hybrid, see below |
| Storage | **rusqlite** (bundled) | Postgres, sled, redb, JSON | §16.1 |
| Serialisation | **ciborium** (CBOR) | JSON, Protobuf, postcard | §10.3 |
| Compression | **zstd** + trained dictionaries | gzip, lz4, brotli, none | Best ratio/speed at small frame sizes with a dictionary |
| Crypto | **snow** (Noise) + `ed25519-dalek` + `blake3` | rustls alone, libsodium, hand-rolled | Audited Rust implementations; Noise gives transport independence |
| FFI | **UniFFI** + `cargo-ndk` | hand-written JNI, cbindgen, Gobley | Generates safe Kotlin bindings incl. async and callback interfaces |
| Logging | **tracing** + `tracing-subscriber` | log, slog | Spans are what make an async request path debuggable |
| CLI | **clap** (derive) | argh, structopt | Standard; good help output matters for a self-hosted tool |
| Tray | **tray-icon** + **rfd** | egui, tauri, native per-platform | Small dependency for a small surface; §5.3 |

**Git: `gix` for reads, the `git` CLI for mutations.** This is the least obvious choice in the table and the most important to get right.

A commit made from the phone must be **indistinguishable** from one made on the laptop. Library implementations — libgit2 and gitoxide alike — bypass the user's real git environment: credential helpers (Windows Credential Manager, `gh auth`, `git-credential-osxkeychain`), the SSH agent and its keys, GPG and SSH commit signing, `commit.gpgsign`, hooks (`pre-commit`, `commit-msg`, `pre-push`), `.gitattributes` filters, LFS, and per-repo `includeIf` config. A commit made through a library can silently be unsigned, or skip a `pre-commit` hook that would have caught a lint error, or fail to authenticate a push because it cannot reach the credential helper. Those failures are subtle, land in the user's history, and are discovered later by someone else.

So mutations shell out to the `git` binary the user already has, with parsed porcelain output and streamed progress. Reads use `gix` because status and diff on a large repository are hot paths where process spawn overhead and output parsing genuinely cost. The split follows the correctness boundary exactly: reads have no side effects to get wrong, mutations have every side effect to get wrong.

**Highlighting is hybrid, not either/or.** CodeMirror's own Lezer grammars handle files under ~200 KB entirely client-side: zero round trip, instant highlighting, and it works offline on cached files. Above that threshold — and for languages CM6 lacks a grammar for — the daemon tokenises with tree-sitter and ships token spans for the visible window only, because parsing a 10 MB file in a WebView will drop frames. tree-sitter also produces the **symbol outline** that replaces a minimap on a phone (§23), which is reason enough to have it server-side regardless.

### 18.2 Mobile

| Concern | Choice | Rejected | Why |
|---|---|---|---|
| Platform | **Native Android**, Kotlin | RN, Flutter, KMP+CMP | §6.1 — direct UniFFI, no bridge on the terminal path |
| UI | **Jetpack Compose** + Material 3 | Views/XML | Declarative, `Canvas` for the terminal, less code |
| Terminal render | **Compose Canvas + glyph atlas** | xterm.js in WebView, AndroidView TextView | §6.3 — no browser on the hottest path |
| Editor | **CodeMirror 6 in WebView** | Monaco, Sora Editor, hand-rolled Compose | See below |
| Async | **Coroutines + Flow** | RxJava, LiveData | Maps cleanly onto UniFFI async and callback interfaces |
| DI | **Hilt** | Koin, manual | Compile-time verification |
| Local storage | **Room** | SQLDelight, raw SQLite, DataStore only | §16.2 |
| Nav | **Compose Navigation** (type-safe) | Voyager, custom | First-party, now type-safe |
| Biometrics | **AndroidX Biometric** + `CryptoObject` | hand-rolled | Crypto-bound so a rooted device cannot skip it |
| Images/icons | **Material Symbols** + vector | icon fonts | Themable, crisp |
| Bench | **Macrobenchmark** + `criterion` (Rust) | manual | §14.3 |

**Editor: CodeMirror 6, and the alternatives are all worse.** **Monaco** is not designed for touch, assumes a mouse and a large viewport, and is roughly an order of magnitude heavier. **Sora Editor** is a genuinely good native Android code editor and was the strongest challenger — rejected because it has no shared code with any future platform, its language support is narrower, and pushing highlighting/lint/diagnostics through it long-term means diverging from the ecosystem every other editor shares. **Hand-rolling in Compose** means implementing IME composition, touch selection, undo, bidirectional text, and syntax highlighting from scratch — a multi-year effort that would be worse than CM6 at every intermediate point. CM6 is the only serious editor rewritten with mobile as a *design goal*, and it is embedded as a dumb renderer behind a typed bridge (§6.3) to contain the WebView's downsides.

### 18.3 Editor bundle

| Concern | Choice |
|---|---|
| Build | Vite → single IIFE bundle into `assets/editor/` |
| Editor | `@codemirror/*` 6.x |
| Languages | Lezer grammars: TS/JS, Rust, Python, Go, JSON, YAML, TOML, Markdown, HTML, CSS, SQL, shell |
| Bridge | Typed JSON over `WebMessagePort`, generated from the same schema as `gonomad-proto` |
| Network in WebView | **Blocked entirely** — no `fetch`, no CDN, no remote assets |

### 18.4 What is deliberately absent

No HTTP framework (no HTTP surface, §3.7). No reverse proxy. No Docker requirement. No Redis (SQLite plus in-process state suffices). No message broker. No GraphQL. No auth library (§3.2 — there is no password, session, or token to manage). Every one of these would be a reasonable default in a web project and every one is wrong here.

---

## 19. Risks and mitigations

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | **Push notifications cannot be done without a third party** — the laptop cannot wake a backgrounded app unaided | Certain | High | Three-tier ladder with opaque encrypted payloads, documented as a product limitation. §24.1 |
| R2 | **OEM battery optimisation silently kills the connection** (Xiaomi, Samsung, OnePlus, Huawei) | High | High | Foreground service, exemption request with explanation, per-OEM in-app guidance, `doctor` detection, honest docs. §24.2 |
| R3 | **Scope is enormous for a small team** | Certain | High | Deliberately brutal MVP (§21) with a written not-in-MVP list, so scope creep must argue against a line item |
| R4 | Compose Canvas terminal renderer is real graphics work | Medium | Medium | M0 spike before committing; fallback is an `AndroidView` text renderer at reduced fps |
| R5 | iroh is young (1.0, June 2026) | Medium | High | Abstracted behind `Transport` (§4.5); Tier 3 fallbacks exist; wire stability guaranteed at 1.0 |
| R6 | ConPTY quirks break TUIs (`vim`, `htop`, `fzf`) | High | Medium | VT conformance fixture suite (§24.11); passthrough mode where available; documented known-bad list |
| R7 | **Prompt-injected agent gets a destructive action approved** on a small screen | Medium | Critical | True-diff rendering never the agent's summary, destructiveness classification, biometric gate, no auto-approve ever. §7.5 |
| R8 | **Stolen unlocked phone → workstation compromise** | Low | Critical | Secret denylist, capability scoping, workspace roots, presence key for destructive ops, instant remote revoke. §3.6 |
| R9 | Adapter regex detection is fragile; vendors change output | High | Medium | Prefer L2 structured protocols; L0 always works; golden transcript tests per manifest; manifests are user-editable so a break is user-fixable |
| R10 | UniFFI friction slows iteration | Medium | Medium | Keep the FFI surface narrow and coarse (few methods, rich types); regenerate in CI to catch drift |
| R11 | Android-only narrows the contributor pool | Medium | Medium | Fat-core rule (§6.2) makes an iOS port a view layer; documented as such to attract that contributor |
| R12 | Battery drain from a persistent connection | Medium | High | Adaptive heartbeat, disconnect-on-background, server-side buffering, enforced budgets (§14.1) |
| R13 | Version skew between phone and daemon | High | Medium | Explicit negotiation with a hard floor; a clear "update your daemon" screen, never partial breakage. §24.7 |
| R14 | Secrets leak through terminal output (`env`, `cat .env`) | High | High | Output redaction patterns, scrollback hygiene, a warning banner. §24.5 |
| R15 | Supply-chain compromise of a dependency | Low | Critical | `cargo-deny`/`audit`/`vet`, committed lockfile, minimal deps, reproducible signed builds. §3.11 |
| R16 | Users expose the daemon unsafely trying to "make it work" | Medium | High | `doctor` diagnoses instead of the user guessing; no port-forward instructions anywhere in the docs; relay is safe by default so there is no reason to |
| R17 | Large-repo indexing degrades the laptop | Medium | Medium | Lazy by default, background index with a visible progress and cancel, bounded pools, ignore-first filtering |
| R18 | Accessibility deferred and then structurally impossible | Medium | Medium | TalkBack semantics for the terminal grid designed in M2, not retrofitted. §24.9 |
| R19 | **Hard links defeat both path containment and the secret denylist** | Low | Critical | A hard link inside a workspace root pointing at a file outside it canonicalises to a path *inside* the root, and the denylist sees the link's harmless name — so `ln ~/.ssh/id_rsa ./notes.txt` defeats both checks. Unclosable in `gonomad-policy`, which does not perform the open. **Must** be closed in `gonomad-fs` by comparing the opened handle's volume + file index against the roots' volumes. Tracked as an M3 exit criterion. |
| R20 | Linux bind mounts are not resolved by canonicalisation | Low | High | A bind mount of `/etc` inside a root would be allowed, because `canonicalize` does not resolve bind mounts (Windows `subst` and mounted volumes *are* resolved). Needs `/proc/self/mountinfo` consultation in `gonomad-fs` at M6, when Linux becomes a first-class host. |
| R21 | TOCTOU between path check and file open | Low | High | Canonicalisation reflects the filesystem at check time; a local process can swap a directory for a reparse point before the caller's `open()`. `ResolvedPath::confirm_identity` exists so `gonomad-fs` can close the window with a handle-identity comparison, but it returns `Ok` when no identity was recorded — **so the window is open until callers supply identities.** Requires local code execution, which is not the primary threat. |
| R22 | Windows 8.3 short-name resolution is assumed, not verified | Low | Medium | `canonicalize` should resolve `PROGRA~1`-style names, but 8.3 generation was disabled on the development host so no real test case could be built. Needs a CI runner with 8.3 enabled, or an explicit fixture, before v0.1.0. |
| R23 | A panicking actor permanently leaks a concurrency slot | Medium | Low | `Slot`/`ByteReservation` are `#[must_use]` and consumed on release, but there is no `Drop`-based reclaim because a destructor cannot take `&mut` the limiter. An actor that panics without releasing costs one slot for the daemon's lifetime. Fix is a supervisor that rebuilds the limiter, or interior mutability, at M2. |

---

## 20. Development roadmap

Milestones are sequenced so that **risk is retired before investment**. Each has a hard exit criterion; a milestone is not done because its features exist, but because its criterion is demonstrably met.

### M0 — De-risking spikes (1–2 weeks)

Four throwaway spikes, in parallel, before any architecture is committed:

1. **Terminal renderer** — Compose `Canvas` + glyph atlas, 80×24 grid, synthetic diffs at 60 fps on a real device. *Exit: sustained 60 fps, no jank in Macrobenchmark.*
2. **iroh round trip** — phone dials laptop by `NodeId` over mobile data through CGNAT; measure direct vs relay RTT. *Exit: a connection from LTE with no router configuration.*
3. **UniFFI round trip** — a Rust struct, an async method, and a callback interface consumed as a Kotlin `Flow`. *Exit: `Flow` emits from a Rust task.*
4. **ConPTY** — spawn `pwsh`, run `vim` and `htop`, resize, kill the tree via a job object. *Exit: no orphaned processes, no display corruption on resize.*

If (1) or (2) fails, the architecture changes here — which is the entire point of M0.

### M1 — Transport, pairing, security foundation (3–4 weeks)

Workspace scaffold; `gonomad-proto` frames and codec; Noise IK in `gonomad-core`; iroh + mDNS in `gonomad-transport`; SQLite store with the hash-chained audit log; `gonomad-policy` with capabilities, path guards, and rate limits; QR pairing with SAS and the manual PAKE fallback; Keystore and StrongBox presence key; `gonomad` CLI (`init`, `start`, `pair`, `devices`, `status`, `doctor`, `audit`); tray UI; Android pairing and devices screens.

*Exit: pair a phone over LTE, `sys.info` round-trips, an unpaired key is rejected pre-handshake, revocation is effective on the next packet, `audit verify` passes, and an external port scan of the host finds nothing.*

### M2 — Terminal (3–4 weeks)

`gonomad-pty` with ConPTY, job objects, and shell detection; `alacritty_terminal` grid plus scrollback ring; run-based diff computation with adaptive frame rate; PTY streams; Compose Canvas renderer; tabs and the switcher; the accessory keyboard row with sticky modifiers; gestures; `file:line` linkification; output folding; TalkBack semantics.

*Exit: four concurrent PTYs; `vim` and `htop` render correctly; keystroke→echo under 50 ms on LAN; a `yes` loop stays under 5 KB/s; scrollback survives an app kill; rotate-and-resize does not corrupt the grid.*

### M3 — Files, editor, search (4–5 weeks)

`gonomad-fs` (lazy listing, single recursive watcher, gitignore filtering, CAS writes, path guards, transfer); `gonomad-search` (streaming content search, FST fuzzy paths); CodeMirror 6 bundle and the typed bridge; editor screen with the trackpad strip and accessory row; file tree; search and replace with `dry_run` default; conflict screen; offline write queue.

*Exit: open a 5 MB file without jank; edit and save with CAS; a concurrent external edit produces a conflict rather than a clobber; search a 500k-file repo with first results under 500 ms; a `cargo build` produces zero protocol frames from `target/`.*

### M4 — Git (2–3 weeks)

`gonomad-git` with `gix` reads and CLI mutations; status, stage/unstage; commit (signing and hooks working); push/pull/fetch with streaming progress and credential-helper passthrough; branches; the diff viewer; history; stash; conflict listing.

*Exit: a commit made from the phone is GPG-signed and runs `pre-commit`, identical to a laptop commit; push over SSH works through the agent; the diff viewer is readable one-handed.*

### M5 — AI agents & notifications (3–4 weeks)

`gonomad-agents` registry and manifest loader; L0/L1/L2 detection; the six shipped manifests; Claude Code at L2; session lifecycle with reattach and resume; approval extraction and destructiveness classification; approval sheet with true-diff rendering and the biometric gate; `gonomad-notify` with ntfy and local backends; the notification inbox.

*Exit: start Claude Code from the phone, background the app, receive an approval notification, open it, read the actual diff, approve with a fingerprint, and see the audit entry. All six adapters at least L0. Killing the app does not lose the session.*

### M6 — Hardening, platforms, release (4–5 weeks)

macOS and Linux hosts (Unix PTY path, FSEvents/inotify, keyring backends); VT conformance fixture suite; CI performance budgets; full security review against §3.1 and an external audit if funded; accessibility pass; reproducible signed builds with SLSA provenance; documentation (protocol, security, deployment, threat model, adapters, contributing); `armeabi-v7a` and `x86_64` ABIs; **v0.1.0**.

*Exit: all §14.1 budgets green in CI; the threat model has a documented mitigation per row; a fresh user pairs and commits within 5 minutes of `gonomad init` on all three host platforms; builds verify reproducibly.*

**Total to v0.1.0: roughly 20–26 weeks of focused work.** That estimate assumes one primary developer and no rework from M0 failures.

---

## 21. MVP definition

The MVP is M1–M5 with the scope inside those milestones cut hard. The purpose of writing the exclusions down is to make scope creep argue against a line rather than slip in unnoticed.

### In

- Pairing (QR + SAS), device management, revocation, capability grants, hash-chained audit
- iroh transport with the LAN → direct → relay ladder and a visible status chip
- Up to 4 terminals, ConPTY on Windows, accessory bar, tabs, scrollback, `file:line` links
- File tree, editor (CodeMirror 6, **one tab**), save with CAS, undo/redo, go-to-line
- Content search and fuzzy file open; replace with dry-run preview
- Git: status, stage, commit, push, pull, branch switch, diff view
- AI: adapter framework with all six manifests at L0, **Claude Code at L2** with approval cards
- Notifications via self-hosted ntfy; in-app inbox
- Reconnect, offline read of cache, offline write queue
- Windows host only; `arm64-v8a` only; one workspace root

### Explicitly not in the MVP

Multiple editor tabs · multi-workspace switching · diagnostics/LSP · plugin system · voice · iOS · iPad · desktop client · Docker or Kubernetes panels · SSH-to-remote-server · PR review · CI/CD monitoring · Wear OS · WebSocket fallback transport · Tailscale/Cloudflare Tier 3 transports · macOS/Linux hosts · conflict *resolution* editing (viewing both sides only) · file upload/download UI (API only) · themes beyond light/dark · terminal colour scheme customisation · remote debugging · local LLM management · rebase/cherry-pick/interactive git · blame · stash UI (API only) · agent transcript search.

### MVP success criteria

1. A developer pairs a phone and makes a real commit from a train, on cellular, with no router configuration.
2. An AI agent's approval arrives as a notification and is safely approved from a lock screen unlock.
3. A dropped connection loses no work and no session.
4. All §14.1 latency budgets are met on a mid-range device over LTE.
5. An external security reviewer finds no pre-authentication surface.

---

## 22. Post-MVP roadmap

Roughly ordered by value-to-effort, not by excitement.

**Near term (v0.2–v0.4)**
- macOS and Linux hosts (unblocks most contributors)
- Multiple editor tabs; multi-workspace switching; multiple laptops from one phone
- Conflict resolution editing; interactive git (rebase, cherry-pick, blame, stash UI)
- LSP proxy → real diagnostics, hover, go-to-definition. The largest single quality jump available for the editor, and the reason the editor is CM6 rather than something bespoke
- File upload/download UI; camera-to-repo (screenshot a whiteboard into the project)
- Terminal themes; per-project run chips learned from history
- WebSocket fallback and Tier 3 transports (Tailscale, Cloudflare Tunnel)

**Medium term (v0.5–v0.8)**
- **Plugin system** — WASM (Component Model) sandboxed server extensions with explicit capability grants, plus declarative Compose UI contributions. WASM rather than native so a plugin cannot escalate past the policy layer
- Docker panel (containers, logs, exec, compose); local LLM management (Ollama/llama.cpp model lifecycle)
- AI review mode; PR review (GitHub/GitLab); CI/CD monitoring; project dashboards
- Voice interaction — speech to an agent's stdin, and spoken summaries. High value precisely when a phone is the only device available
- iPad and iOS via a SwiftUI view layer over the same Rust core; Wear OS notifications and approvals

**Longer term (v1.0+)**
- Compose Desktop client (same core, third view layer)
- SSH into remote servers through the daemon; Kubernetes panel; remote debugging (DAP proxy)
- Collaborative sessions (two devices, one terminal — the point at which a CRDT finally earns its cost, for the *editor buffer only*, never for the filesystem)

---

## 23. UX specification, screen by screen

### 23.1 Principles

1. **Thumb-first.** Primary actions in the bottom third. Nothing critical in a top corner.
2. **Bottom sheets, not dialogs.** Reachable, dismissible, and they preserve context.
3. **One screen, one job.** No tabbed panels crammed into 6 inches.
4. **State is always visible.** Connection tier, sync state, git state, agent state — never guessing.
5. **Destructive actions are deliberate.** Confirmation, or biometric, never a bare tap.
6. **Optimistic, then honest.** Show the result instantly; if the server disagrees, say so clearly.
7. **The accessory bar is the real keyboard.** Context-aware, customisable, always there.

### 23.2 Signature interactions

These five are what make phone coding pleasant rather than merely possible, and they are the parts a competitor cannot copy by shrinking a desktop UI.

**The trackpad strip.** A ~60 dp textured strip below the editor. Dragging anywhere in it moves the cursor with sub-character precision — a relative pointing device, so your finger never covers the text it is positioning. This directly solves the single worst part of editing text on a phone: tiny selection handles under a fingertip that obscures the target. Long-press in the strip starts a selection; a second finger extends it. Velocity-scaled so a slow drag is per-character and a fast drag is per-word.

**Context-aware accessory bar.** Terminal: `Esc Tab Ctrl Alt ← ↓ ↑ → | / ~ $ -` with sticky modifiers, expanding to control keys, function keys, and user macros. Editor: `{ } ( ) => ; " '` plus indent/outdent, undo/redo, and go-to-line. Auto-hidden when a hardware keyboard is detected.

**Tappable `file:line` everywhere.** In terminal output, in agent transcripts, in git output, in search results. A stack trace becomes navigation. Language-aware patterns for Rust, Python, TypeScript, Go, and ESLint.

**One-tap run chips.** Per-project command chips sourced from `package.json` scripts, `Makefile` targets, `Cargo.toml`, and frequency-ranked shell history. Typing `npm run test:watch` on a phone is miserable; tapping it is not.

**Output folding with summaries.** Long output collapses to `▸ npm install · 4,213 lines · 38s`. Known-verbose blocks fold automatically. A build log becomes scannable.

### 23.3 Screens

**Onboarding & Pair.** Three cards: what GoNomad is (with the honest "this gives your phone access to your machine" statement), install the daemon (copyable one-liner per OS), scan the QR. Camera fills the screen with a corner-bracket target; on detection, an immediate progress state, then the SAS confirmation — **six large digits with "does this match your laptop?" and equally weighted Yes/No**, because a visually dominant Yes trains the exact reflex the SAS exists to prevent. Errors are specific and actionable: expired QR ("generate a new one with `gonomad pair`"), wrong network, camera permission. Manual-code entry behind a link.

**Workspaces.** Cards per root: name, path, branch chip with ahead/behind, dirty-file count, running-terminal and active-agent counts, last-opened. Tap enters; long-press for a sheet. Empty state explains `gonomad workspace add` with a copyable command.

**Project Home.** The hub, and the screen that decides whether the app feels alive: a status header (branch, dirty count, connection chip); **Continue** cards for running terminals and active agents with live state, so returning to work is one tap; run chips; recent files; a quick-action row (New terminal · New agent · Search · Commit). Nothing here is a menu — everything is a resumption.

**File Tree.** Indented `LazyColumn`, type-aware icons, git status colour on the left edge, dirty dots. Gitignored files dimmed and behind a toggle; hidden files behind a toggle. Long-press → sheet (rename, move, delete, duplicate, copy path, new file/folder here, download). Sticky breadcrumb header that is itself tappable for jumping up. A floating search button opens fuzzy find. Directory contents virtualised and paged.

**Editor.** Filename plus dirty indicator and a sync chip in a slim top bar; CM6 fills the screen; the trackpad strip and accessory bar below. Bottom sheet for tabs (MVP: one tab, so the sheet holds recent files). Save is automatic on a 2-second debounce and on background, with an explicit save in the accessory bar for people who want it. Conflict arrives as a non-blocking banner, never a modal — a modal while you are typing is worse than the problem it reports. Symbol outline in a sheet replaces a minimap, which is useless at this width. Read-only above 5 MB unless overridden, with the reason stated.

**Search & Replace.** Query field with regex/case/word toggles as chips. Results grouped by file, collapsible, each showing the matching line with the match highlighted and surrounding context on expand. Streaming, with a live count and a cancel button. Replace opens a **preview-first** sheet: "42 matches in 12 files" with a full diff and per-file checkboxes; the confirm button is destructive-styled and requires holding. A phone-initiated repo-wide regex replace should feel slightly effortful, on purpose.

**Terminal.** Full-bleed grid, minimal chrome. Tab pills scroll horizontally above; each shows name, a state dot, and an unread badge. Gestures per §13.4. The accessory bar is the primary input surface. Landscape gives more columns and hides the pills into a menu.

**Terminal Switcher.** Full-screen grid of live grid thumbnails with names and states — the fastest way to answer "which one is the dev server?" Drag to reorder, swipe up to close (deliberately not available on the pill, so a mis-swipe cannot kill a running process), plus a New button.

**AI Sessions.** List of session cards: adapter icon and name, workspace, a **prominent state badge** (Thinking with a live spinner / Awaiting approval in accent colour / Idle / Error), last activity, and a one-line transcript preview. Awaiting-approval sessions sort to the top and are visually loudest, because that is the state where the user is the blocker. FAB → New session (choose adapter and workspace).

**AI Session Detail.** Transcript as a native scrolling list — not a raw terminal grid — with role-styled messages, syntax-highlighted code blocks, collapsible tool calls, and tappable `file:line`. Composer at the bottom with the accessory bar; a Stop button while thinking. A "raw terminal" toggle drops to the PTY grid for L0 adapters and for debugging. Token usage and elapsed time in the header where the adapter reports them.

**Approval Sheet.** The most security-critical screen in the product, so it is designed against habituation. A modal bottom sheet at ~70% height: the agent name and the action classification ("Modify 3 files", "Run command", "Delete directory") with a destructiveness colour; then **the actual diff**, syntax-highlighted, with per-file expansion — never the agent's prose summary. The command, verbatim, in a monospace block for exec approvals. Approve and Deny are **equally weighted** and, for destructive actions, Approve requires a biometric with the operation named in the prompt. A "why is this destructive?" link explains the classification. No "always allow", ever.

**Git Status.** Sections for staged, unstaged, and untracked; per-file status letter, additions/deletions counts, and a tap to view the diff. Swipe right to stage, left to unstage — the highest-frequency action, so it is a gesture, not a menu. A sticky bottom bar shows branch with ahead/behind and buttons for Commit, Pull, Push. Push and pull show inline streaming progress.

**Commit.** Message field with a subject/body split and a 50/72 guide; staged-file summary; amend and sign-off toggles; a signing indicator showing whether the commit will be signed. Commit and Commit&Push as separate buttons, because deciding to push is a different decision. Hook output is shown on failure rather than swallowed — a `pre-commit` failure the user cannot see is the worst possible outcome.

**Diff Viewer.** Unified by default (side-by-side is unreadable at this width and is offered only in landscape). Word-level intra-line highlighting; collapsed context with expand handles; sticky hunk header; per-hunk stage/unstage buttons; horizontal scroll with syntax highlighting preserved. Swipe between changed files.

**Branches.** Local and remote sections, current branch pinned with ahead/behind, last-commit line per branch, search field. Tap to check out (with a dirty-tree warning offering stash), long-press for a sheet (merge, rebase, delete, rename, push, set upstream). Dangerous entries require `git:dangerous` and are visually separated.

**History.** Commit list with graph rail, message, author avatar initials, relative time, and short SHA. Tap → commit detail with full message, stats, and file list. Filters for branch, author, path. Paged.

**Stash.** List with name, branch, time, file count. Tap for a diff preview; actions apply, pop, drop. Create-from-current with an optional message.

**Conflict.** Conflicted-file list; per file, a three-pane switcher (Mine / Theirs / Result) since three columns do not fit, with hunk-level "take mine"/"take theirs"/"take both" buttons. MVP is view-and-choose-per-hunk; free-form editing is post-MVP. A clear "mark resolved" step, and a warning that resolving on a phone is best for simple conflicts — honesty beats a false promise here.

**Notifications Inbox.** Grouped by day, typed icons (approval, test result, build, git, task complete), unread markers. Tap deep-links to the source. Per-type mute; a settings link to the notification backend. Backend health is visible ("ntfy: connected"), because a silently broken notification path is invisible until something important is missed.

**Devices.** Card per device: name, model, paired date, last seen, current transport tier, capability chips. Tap for detail with capability toggles, workspace roots, and a per-device audit trail. Revoke and Force-disconnect are separated and both need a biometric. Pair-new-device shows the QR when initiated from the phone (with `policy:write`).

**Security & Policy.** Sections for the secret denylist (editable, with a warning when narrowing), presence-required operations, rate limits, and the audit log with a verify button that reports chain integrity explicitly. Every change requires a biometric. Written so a security-minded user can audit their own posture in one screen rather than reading a config file.

**Task Monitor.** Long-running operations (search, index build, push, test run, agent task) with progress and cancel. Reachable from the status chip. Nothing long-running should be invisible or uncancellable.

**Command Palette.** Bottom sheet, fuzzy, over commands, files, terminals, agents, and git actions, ranked by recency and frequency. Invoked from a persistent bottom-bar button. This is the power-user path that keeps the touch UI from being a ceiling.

**Settings.** Connection (transport preference, relay URL), appearance (theme, font, terminal font size), editor (auto-save delay, tab size, word wrap), terminal (scrollback, default shell, macros), notifications (backend, per-type), storage (cache size, clear cache), security (link to Policy), about (versions, protocol version, licences, reproducible-build verification instructions).

### 23.4 Accessibility

TalkBack semantics for the terminal grid — line-granularity reading with a "read current screen" action rather than per-cell announcement, which would be unusable. The editor WebView exposes CM6's ARIA tree. Dynamic type respected everywhere outside the fixed-metric terminal grid, which instead offers its own font-size control. All colour-coded state (git status, agent state, connection tier) carries a shape or text label, never colour alone. Minimum 48 dp touch targets, verified in review. Designed in M2 rather than retrofitted (§24.9).

---

## 24. What has been overlooked

The items most likely to be discovered painfully in month four, ordered by how much damage late discovery would do.

### 24.1 Push notifications fundamentally conflict with "no cloud account"

**The problem is structural, not an implementation gap.** Android will not keep a socket alive indefinitely for a backgrounded app, and the only mechanism to wake one is a push service. FCM requires a Google Cloud project and credentials — a cloud account, which the product principles forbid. The requirement "the laptop should notify the phone" and the requirement "no cloud account" cannot both be fully satisfied.

The resolution is an honest ladder, with the limitation documented in the README rather than discovered by users:

**Tier 1 — live connection.** Foreground, or briefly backgrounded with a foreground service. Zero third parties, instant. Covers active use, which is most use.

**Tier 2 — self-hosted ntfy (the default).** The user runs their own ntfy server; the Android ntfy app holds its own persistent connection. GoNomad publishes an **opaque encrypted blob** — a random topic name and a ChaCha20-Poly1305 ciphertext under a key established at pairing. The notification server, self-hosted or not, learns only that *something* happened and how large it was. The phone decrypts locally to render the real title and body. Content never leaves the laptop in plaintext under any circumstance.

**Tier 3 — optional user-deployed FCM relay.** For users who want native push and accept the trade, a documented ~100-line relay they deploy with their own Firebase project. Same encrypted-blob discipline.

The design constraint that makes all three safe: **the notification payload is always ciphertext.** No tier ever sees a filename, a diff, a command, or a project name. What the design cannot hide is *metadata* — that a notification occurred, when, and roughly how big — and that must be stated plainly rather than glossed.

### 24.2 Android OEM battery optimisation will silently kill connections

Xiaomi/MIUI, Samsung, OnePlus/ColorOS, and Huawei ship aggressive process killers that ignore standard Android lifecycle rules. Without deliberate handling, GoNomad will "randomly disconnect" on a large fraction of devices and the reports will be unreproducible on a Pixel.

Mitigations: a foreground service with a `dataSync`/`specialUse` type; a `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` prompt with a plain-language explanation; **per-OEM in-app guidance** with device-specific instructions (dontkillmyapp.com-style, detected from `Build.MANUFACTURER`); detection and reporting when the process was killed unexpectedly; and honest documentation. This is a top-three source of user-perceived unreliability in every app of this shape, and it needs to be engineered in M2, not patched later.

### 24.3 Clock skew and time

Two devices, two clocks, and no trusted time source. Anything security-relevant that depends on wall-clock time is a vulnerability if a clock is wrong or manipulated. Therefore: pairing-window expiry uses the **laptop's monotonic clock** only; audit entries carry both wall-clock (display) and monotonic (ordering) values, and ordering never relies on wall-clock; no protocol logic compares timestamps across devices; displayed times are converted at render time in the phone's timezone.

### 24.4 The laptop-side UX is a real product

Easy to treat the daemon as headless infrastructure. But the laptop is where pairing is approved, where a connected phone must be visible, and where the kill switch lives. A security tool with no visible indicator that a phone is attached, and no one-click disconnect, is missing a control users will demand the first time they feel uneasy.

Required: a tray icon whose state shows connected/idle/disconnected; a native pairing dialog (not just a terminal QR); a native approval prompt for operations requiring laptop presence; a **kill switch** that drops all connections instantly; a first-run experience for `gonomad init` that is genuinely readable; and Windows autostart registration that a user can find and remove.

### 24.5 Secret leakage through the terminal

The secret denylist (§3.6) protects the *filesystem*, and then a user types `env`, `printenv`, `cat .env`, or `docker inspect` and every secret lands on a phone screen, in the daemon's scrollback, in an on-disk ring buffer, and possibly in a cached transcript.

Mitigations: pattern-based redaction of high-entropy strings adjacent to known key names (`API_KEY=`, `TOKEN=`, `SECRET=`, `AWS_`, `sk-`, `ghp_`, JWT shapes) with a tap-to-reveal that is audited; a warning banner when a command likely to print secrets is detected; scrollback hygiene (a "clear scrollback and its on-disk buffer" action that actually deletes the file); and never syncing scrollback into the phone's persistent cache. Redaction is imperfect and must be documented as best-effort — but best-effort here is much better than nothing.

### 24.6 Multi-client coherence

The same file open in the phone editor and in VS Code, simultaneously, is not an edge case — it is Tuesday. CAS (§12.2) makes it *safe*, but safety is not enough: the user needs to *see* it. Hence the external-change banner, a live "changed on disk" indicator in the editor's sync chip, and a stale marker on cached tree nodes. The failure to avoid is a user who saves, gets a conflict, and has no idea why.

### 24.7 Version skew

Phone and daemon update independently — the APK from a store or a sideload, the daemon by `cargo install` or a package manager. Skew is guaranteed. Explicit negotiation with a hard minimum floor (§10.4), and a dedicated screen: "Your daemon is v0.3.1; this app needs v0.4.0 or later" with the exact upgrade command. Never partial functionality, never a confusing error — silent partial breakage from a protocol mismatch is among the hardest classes of bug for a user to report usefully.

### 24.8 Uninstall and complete revocation

A security tool must be cleanly removable, and the path must be documented before anyone asks. `gonomad uninstall` removes the keyring entry, deletes the config, index, scrollback, and database, deregisters autostart, and prints what it removed. On the phone, "unpair and wipe" deletes the Keystore keys and the Room cache. Documented in the README so a user evaluating GoNomad knows the exit before they commit to the entrance.

### 24.9 Accessibility must be designed in, not retrofitted

A terminal grid and a WebView editor are both hostile to screen readers, and both become far harder to fix after the fact. Terminal semantics (§23.4) are designed in M2. Retrofitting TalkBack onto a `Canvas` renderer after it ships means rewriting the renderer.

### 24.10 Legal and licensing

**Apache-2.0**, chosen over MIT for its explicit patent grant — meaningful for a security and networking tool where patent exposure is not hypothetical. No CLA; a DCO sign-off instead, which is lower friction for contributors and sufficient for provenance. "GoNomad" registered as a word mark if the project gains traction, with a trademark policy permitting forks to use the name for compatibility statements but not for distributions. A third-party licence inventory generated in CI (`cargo-about` plus a Gradle licence plugin) and shipped in-app, which the bundled CodeMirror and Lezer grammars require. `SECURITY.md` with a disclosure policy and a PGP key before v0.1.0 — a security tool without a disclosure channel will have vulnerabilities reported publicly.

### 24.11 Testing strategy

The fragile parts are not the ones unit tests naturally cover:

- **VT conformance** — a fixture suite of recorded byte streams (`vim`, `htop`, `fzf`, `tmux`, `less`, progress bars, ConPTY resize sequences) with expected grid snapshots. This is the regression net for the single most breakage-prone component, and it also gives a way to test Windows-specific ConPTY behaviour without a Windows machine in every CI job.
- **Protocol fuzzing** — `cargo-fuzz` against the frame decoder and the VT parser. Both parse untrusted input; both must not panic.
- **Adapter golden tests** — recorded transcripts per manifest with expected state transitions and approval extractions. §19/R9 makes these mandatory, not optional: a vendor changing a spinner character must fail CI, not fail a user.
- **Path-guard property tests** — `proptest` over adversarial paths (`..`, symlinks, UNC, 8.3 names, ADS, unicode normalisation, null bytes) asserting that nothing escapes a root. This is the highest-consequence code in the product and it deserves generative testing.
- **Handshake and crypto tests** — Noise test vectors; a MITM simulation asserting SAS divergence; replay attempts asserting rejection.
- **CAS concurrency tests** — concurrent writers asserting no lost updates.
- **Performance gates** in CI (§14.3).
- **Instrumented Android tests** on a physical device for the terminal renderer, the WebView bridge, and the biometric flow.

### 24.12 Reproducible builds and release integrity

The trust argument for a self-hosted security tool collapses if users cannot verify that the binary matches the source. So: pinned toolchain versions; `--locked` builds; no build-time timestamps or paths embedded; CI builds each release twice on separate runners and fails if hashes differ; artifacts signed with `cosign` and published with SLSA provenance; a reproducible, `apksigner`-verifiable APK with the verification command in the README; and F-Droid as a distribution target, since its reproducible-build requirement is a useful external forcing function.

### 24.13 Smaller items worth recording

- **First-run performance on a huge monorepo** — the FST index build must be cancellable, visibly progressing, and never block the UI. A user's first experience must not be a frozen tree.
- **WSL path translation** — a WSL PTY's cwd is a Linux path; the FS layer must not assume the host's namespace (§8.2).
- **Cloud-synced folders (OneDrive, Dropbox, iCloud Drive)** — developers routinely keep projects inside them, and sync engines produce spurious watcher events, placeholder files that block on read, and lock contention. Detect synced roots and warn, and treat reparse-point placeholders as a distinct file kind.
- **Long paths on Windows** — `MAX_PATH` requires `\\?\` prefixing and opt-in long-path support; deep `node_modules` trees hit this routinely.
- **Terminal bell and vibration** — a bell should be a haptic, not a sound, and should be mutable.
- **Battery-saver mode** should drop frame rate and disable the background connection automatically.
- **Data-saver mode** should force higher compression and a lower frame rate ceiling.
- **`git` binary absence or a wrong version** — `doctor` must detect it rather than failing at commit time.
- **Multiple daemons on one LAN** — mDNS must disambiguate by hostname and `NodeId` so pairing cannot target the wrong machine.
- **Editor IME** — CJK composition in a WebView inside a Compose scaffold with a custom accessory bar is a genuine integration hazard and needs an explicit test.
- **Crash reporting** — must be opt-in, self-hosted or absent. A privacy-first tool that phones home crash dumps by default has broken its own promise.

---

## Appendix: decision log

| Decision | Chosen | Over | Section |
|---|---|---|---|
| Transport | iroh (QUIC P2P) | Tailscale, CF Tunnel, WebRTC | §4 |
| Auth model | Device keypairs, no tokens | JWT/session tokens | §3.2 |
| Session crypto | Noise IK inside QUIC | QUIC TLS alone | §3.4 |
| Backend language | Rust | Go, Bun, Node | §5.1 |
| Mobile | Native Android + Compose | RN, Flutter, KMP | §6.1 |
| Terminal render | Compose Canvas + glyph atlas | xterm.js in WebView | §6.3 |
| Editor | CodeMirror 6 in WebView | Monaco, Sora, native | §18.2 |
| Terminal state | Server-side VT emulator | Client-side parsing | §8.3 |
| Protocol | QUIC streams + CBOR | WebSocket + JSON | §10 |
| File sync | Authoritative + CAS | CRDT / OT | §12.1 |
| Path index | FST | trie, tantivy | §12.5 |
| Git mutations | `git` CLI | gix / libgit2 | §18.1 |
| Storage | SQLite (bundled) | Postgres, sled | §16.1 |
| AI integration | L0/L1/L2 ladder + TOML manifests | Per-vendor code | §7.1 |
| Notifications | ntfy with encrypted blobs | FCM by default | §24.1 |
| Licence | Apache-2.0 + DCO | MIT, GPL, CLA | §24.10 |

