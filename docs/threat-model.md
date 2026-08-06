# GoNomad threat model

> [!WARNING]
> **Everything in this document is a design.** GoNomad is pre-alpha. Parts of
> the policy layer, the audit chain, and the pairing state machine exist as
> library code with tests; nothing has been assembled into a running daemon,
> and none of it has been reviewed or audited. A threat model is a statement of
> intent and a checklist for reviewers — it has never stopped an attacker on
> its own. See the [README status section](../README.md#status-pre-alpha).
>
> A full security review against this model, and an external audit if the
> project can fund one, are M6 exit criteria (`plan.md` §M6).

This document expands `ARCHITECTURE.md` §3.1. For the disclosure process,
response timelines, and safe harbour, see [`../SECURITY.md`](../SECURITY.md).
For definitions of the terms used here — SAS, PAKE, ALPN, presence key,
`NodeId` — see [`glossary.md`](./glossary.md).

---

## The premise

The stated design requirement is to build as though the user's entire
workstation is exposed, because it is. A paired phone can read source code, run
arbitrary commands, and reach every credential the developer's shell can reach:
SSH keys via the agent, cloud tokens in the environment, git credential
helpers, Docker sockets, package registry tokens.

That is not a flaw to be minimised. It is what makes the product useful, and it
is why the security work is front-loaded — `plan.md` builds the security
foundation in M1, before the terminal, before files, before git, because
retrofitting it is not possible.

The consequence for this document: the interesting question is never "can the
phone do dangerous things" (it can, by design) but "who or what can *become*
the phone, and what stops each of them".

---

## Contents

- [Adversaries T1–T10](#adversaries-t1t10)
- [Explicitly out of scope](#explicitly-out-of-scope)
- [Trust boundaries](#trust-boundaries)
- [Assets and what protects them](#assets-and-what-protects-them)
- [How the defences are verified](#how-the-defences-are-verified)

---

## Adversaries T1–T10

| # | Adversary | Capability | Primary defence |
|---|---|---|---|
| T1 | Network attacker — café Wi-Fi, hostile ISP, on-path router | Observe, inject, replay, drop, and reorder traffic | Noise IK inside QUIC; nothing plaintext on the wire, including metadata |
| T2 | Internet scanner | Probe any reachable address and port | No routable listening port; no HTTP surface; a connection not offering the `gonomad/1` ALPN is dropped during the QUIC handshake |
| T3 | Malicious relay | Sees all relayed traffic; controls delivery timing and availability | Relay is untrusted by design; sees ciphertext and traffic timing only; self-hostable |
| T4 | Stolen **locked** phone | Physical possession of the device | Keys non-exportable from Keystore and gated on device unlock; remote revoke from the laptop |
| T5 | Stolen **unlocked** phone | Full access to the running app | Secret denylist, workspace roots, capability scoping, biometric presence gate on every destructive operation, remote revoke |
| T6 | Shoulder-surfed or photographed pairing QR | The pairing secret, without physical access to the laptop | Single-use, 120-second expiry, three attempts then invalidation, laptop-side human approval, transcript-derived SAS confirmation |
| T7 | Prompt-injected AI agent | Proposes malicious edits or commands through a channel the user has learned to trust | True-diff rendering — never the agent's summary; destructive-operation classification; biometric over the diff digest; no auto-approve mode |
| T8 | Malicious dependency in our own supply chain | Arbitrary code execution inside the daemon | `cargo-deny`, `cargo-audit`, `cargo-vet`, committed lockfile, deliberately minimal dependency set, reproducible builds, signed releases |
| T9 | Rogue paired device — given away, sold, or compromised | A valid, unexpired credential | Instant server-side revocation effective on the next packet; per-device audit trail; capability minimisation at pairing |
| T10 | Local unprivileged process on the laptop | Reads files as the user, connects to loopback addresses | Keys in the OS keyring rather than in files; the loopback control socket verifies peer credentials |

### T1 — Network attacker

**Position.** Anywhere on the path: the café access point, a compromised home
router, an ISP, a state-level observer.

**What they attempt.** Read source code and command output in flight; inject
frames to trigger operations; replay a captured session; correlate metadata to
learn what you are working on.

**Defences.** Noise IK runs inside QUIC, so every application byte is encrypted
and authenticated twice by independent mechanisms. The IK pattern means the
initiator already knows the responder's static key from the pairing QR, so the
handshake takes one round trip and the initiator's identity is encrypted to the
responder's key — a passive observer cannot learn *which* device is connecting.
Cipher suite: `Noise_IK_25519_ChaChaPoly_BLAKE2s`.

Replay is rejected by construction: Noise provides per-message nonce counters,
each stream carries a monotonic sequence number, handshakes include a fresh
32-byte responder nonce so a captured handshake cannot open a new session, and
mutating requests carry an idempotency key retained for five minutes so a
network-level retry cannot double-apply a commit or a write
(`ARCHITECTURE.md` §3.5).

**What is not defended.** Traffic volume and timing. An observer learns that
you are connected and roughly how active you are.

### T2 — Internet scanner

**Position.** Anywhere on the internet, with no prior knowledge of you.

**What they attempt.** Find the service, fingerprint it, exploit an
unauthenticated endpoint.

**Defences.** There is nothing to find. The daemon holds a QUIC endpoint over
UDP and a loopback-only control socket — no `0.0.0.0:8080`, no login page, no
health endpoint, no static assets, no WebSocket upgrade path on the default
transport. The entire class of unauthenticated-web-endpoint bugs is absent
because the surface it lives on does not exist. A connection that does not
offer the `gonomad/1` ALPN is dropped during the QUIC handshake; iroh
authenticates the peer's public key as part of QUIC TLS, so an unpaired key is
rejected before a single application byte is read. A scanner sees a UDP port
that responds to nothing but a valid, authenticated handshake: no banner, no
version string, no error page, no timing oracle (`ARCHITECTURE.md` §3.7).

**Verification.** "An external port scan of the host finds nothing" is a
literal M1 exit criterion, and "an external security reviewer finds no
pre-authentication surface" is an MVP success criterion.

### T3 — Malicious relay

**Position.** Operating the relay that carries your traffic when hole punching
fails — whether that is a public iroh relay or one someone has interposed.

**What they attempt.** Read code, commands, and output; tamper with delivery;
correlate who talks to whom and when; deny service by dropping traffic.

**Defences.** The relay is a dumb packet forwarder. Because Noise IK sits
inside the QUIC session, the relay sees ciphertext regardless of what the
transport layer does or does not guarantee. It cannot read content, and it
cannot tamper without breaking authentication. This is the property that makes
"is relaying safe?" a question with an unambiguous answer, which in turn means
the project never faces pressure to answer it optimistically.

**What is not defended.** Timing and volume metadata, and availability — a
relay can refuse to forward. `iroh-relay` is self-hostable for users who object
to timing metadata leaving their control, and the transport ladder prefers
direct paths and keeps probing for one while relayed.

### T4 — Stolen locked phone

**Position.** Physical possession of a locked device.

**Defences.** The identity key is non-exportable from Android Keystore and
declared with `setUnlockedDeviceRequired(true)`, so it cannot be used while the
device is locked. The presence key lives in StrongBox where available and
requires a fresh user authentication for every single use. Remote revocation
from the laptop is immediate and does not require the phone's cooperation.

**Honest caveat.** Android's hardware-backed Keystore does not support Ed25519
or X25519 — StrongBox and TEE keymaster support EC P-256/P-384/P-521, RSA, and
AES, not Curve25519. The identity key is therefore a *software* key held in
Keystore-encrypted storage, protected by the device's hardware-derived key
encryption key and the lockscreen. This is acceptable for T4. It is explicitly
not sufficient for T5, which is why a second key exists
(`ARCHITECTURE.md` §3.3).

### T5 — Stolen unlocked phone

**Position.** The hardest realistic attack: an unlocked device with the app
already authorised. Snatched from a hand, or borrowed by someone trusted.

**What they attempt.** The concrete scenario is a thief opening the file tree,
tapping `~/.ssh/id_ed25519`, and thereby owning every server and repository the
developer can reach.

**Defences, in layers.**

- **Workspace roots** — only explicitly declared trees are reachable at all.
- **Secret denylist** — applied *after* the root check, covering `**/.ssh/**`,
  `**/.aws/**`, `**/.env*`, `**/*.pem`, `**/*.key`, `**/.git-credentials`,
  `**/.gnupg/**`, `**/.claude/**` and more. Reading a denylisted path requires
  both the `fs:secrets` capability, denied by default, and a presence
  signature. Search and directory listing honour the denylist, so secrets do
  not leak through grep results or filename enumeration either.
- **The presence key** — a P-256 key in StrongBox with
  `setUserAuthenticationRequired(true)` and a zero-second validity window, so
  *every* use forces a fresh biometric or PIN. A thief cannot produce one.
- **Capability scoping** — a device that was never granted `git:dangerous`
  cannot force-push no matter who is holding it.
- **Remote revoke** — one row deleted on the laptop, effective on the next
  packet.

The two-key split is precisely what makes T5 survivable. A thief with an
unlocked phone can browse code. They cannot read a denylisted secret,
`git push --force`, approve an agent's destructive diff, or change security
policy, because each of those requires a fresh hardware-attested biometric.

**What is not defended.** Reading non-secret source code in a declared
workspace, and running commands if `pty:spawn` was granted. Both are the
product working as designed; revocation is the response.

### T6 — Shoulder-surfed or photographed QR

**Position.** Someone who saw the pairing QR — over a shoulder, in a screen
share, in a recording — but was never physically at the laptop.

**Defences.** The pairing secret is single-use, expires after 120 seconds, and
is invalidated after three attempts. Even holding a valid secret, an attacker
must get past a laptop-side human approval dialog that names the device and its
proposed scope. And the six-digit SAS is derived from the full handshake
transcript, so an attacker who has the secret but is proxying the connection
produces *different* digits on each side, and the mismatch is visible to the
person comparing them.

This is why the confirmation screen weights "Yes" and "No" equally: a visually
dominant "Yes" trains exactly the reflex the SAS exists to prevent
(`ARCHITECTURE.md` §9.2, §23.3).

### T7 — Prompt-injected AI agent

**Position.** An agent running on the laptop that has been manipulated — by a
malicious repository, a poisoned dependency README, a crafted issue body, a web
page it fetched — into proposing something harmful.

**What they attempt.** Get a destructive change approved by describing it
benignly. Exfiltrate secrets through a command that looks routine. Exploit a
habituated user tapping a green button on a six-inch screen while walking.

**Defences.**

- **The phone renders the actual diff**, syntax-highlighted, with destructive
  parts highlighted — never the agent's prose description of what it did. A
  prompt-injected agent will describe a malicious edit benignly; displaying the
  real textual change is the only defence that does not depend on trusting the
  thing being audited.
- **The daemon classifies destructiveness** independently of the agent: writes
  outside a root, deletes, git history rewrites, network egress, package
  installation, secret access.
- **Destructive approvals require a fresh biometric**, and the presence
  signature covers the *digest of the diff*, so it cannot be harvested for one
  action and spent on another.
- **Approve and Deny are equally weighted** in the UI.
- **There is no auto-approve mode, and there will not be one.** It would be the
  single most requested feature and the single largest hole in the product
  (`ARCHITECTURE.md` §7.5).

**What is not defended.** A user who reads the real diff and approves it
anyway. The design can break the habit loop; it cannot substitute judgement.

### T8 — Malicious dependency

**Position.** A crate in the dependency tree, or a compromised release of one,
executing inside the daemon with the daemon's full access.

**Defences.** A deliberately small dependency set with every addition justified
in review; `cargo-deny` and `cargo-audit` as hard CI gates; `cargo-vet` for
transitive review status; a committed `Cargo.lock` and `--locked` builds;
reproducible builds verified in CI by building twice on separate runners and
comparing hashes; release artifacts signed with `cosign` and published with
SLSA provenance; an `apksigner`-verifiable, reproducible APK
(`ARCHITECTURE.md` §3.11, §24.12).

The trust argument for a self-hosted security tool collapses if users cannot
verify that the binary matches the source, which is why reproducibility is
treated as a security property rather than a build nicety.

### T9 — Rogue paired device

**Position.** A device that was legitimately paired and is no longer trusted:
sold, given away, lost, or compromised.

**Defences.** Revocation deletes one database row and is effective on the next
packet — no token blacklist to propagate, no expiry to wait out, no
revocation-list growth. Force-disconnect drops the QUIC connection without
removing the grant; revoke removes the grant. Both are immediate and enforced
server-side. Every device has its own audit trail, so what it did while trusted
is reconstructible. Capability minimisation at pairing bounds what that was.

This is the concrete payoff of having no bearer tokens: there is nothing
outstanding to invalidate (`ARCHITECTURE.md` §3.2).

### T10 — Local unprivileged process

**Position.** Another process on the laptop, running as another user or as a
sandboxed application, without administrator rights.

**What they attempt.** Read the daemon's key material from disk; drive the
daemon through its control socket; read the audit log or scrollback.

**Defences.** The daemon's identity key is in the OS keyring — Windows
Credential Manager via DPAPI, macOS Keychain, Secret Service on Linux — not in
a file, because a file is readable by every process running as that user. The
loopback control socket verifies peer credentials before accepting a command:
`GetNamedPipeClientProcessId` plus a token comparison on Windows,
`SO_PEERCRED` on Unix. Loopback reachability is not treated as authorisation.

**Honest caveat.** A process running as *the same user* as the daemon is a much
weaker boundary than a process running as a different user. On a single-user
desktop, malware running as you can read your source tree directly without
involving GoNomad at all — see the out-of-scope section below.

---

## Explicitly out of scope

> [!IMPORTANT]
> **A compromised laptop operating system, with root or administrator access,
> is explicitly outside this threat model. If the attacker owns the machine
> that runs your compiler, GoNomad cannot help — and any design that claims
> otherwise is lying.**

An attacker at that level can:

- read the daemon's process memory, including session keys and the identity key
  after it has been unsealed from the keyring;
- retrieve keyring entries as the user who owns them;
- replace the `gonomad` binary, or preload a library into it;
- hook the `git` process the daemon shells out to, so a "signed, hook-verified"
  commit means whatever they want it to mean;
- write audit entries, or rewrite the whole chain from genesis, because the
  chain is only tamper-*evident* to someone comparing it against a copy the
  attacker did not control;
- simply read the source tree, the SSH keys, and the environment directly,
  without going anywhere near GoNomad.

Every mechanism in this document — capability scoping, path guarding, biometric
gating, audit chaining, the denylist — is enforced by code the attacker
controls in that scenario. Stating this plainly is not a disclaimer; it is the
difference between a threat model and marketing.

**GoNomad's job is to make a remote phone a safe way to reach a machine you
trust. It is not, and will never be, a defence against a machine you cannot
trust.**

Also out of scope:

| Not defended against | Why |
|---|---|
| Physical attacks on the host — cold boot, DMA, evil maid | Below the layer GoNomad operates at; use full-disk encryption and firmware protections |
| Malicious host firmware or hypervisor | Same |
| Compromise of the Android OS below the app sandbox | A rooted or exploited phone can defeat the biometric binding; `CryptoObject` raises the cost, it does not eliminate it |
| A user who deliberately grants capabilities to a device they know to be hostile | Authorisation cannot fix intent |
| A user who reads a true diff and approves it anyway | The design surfaces the truth; it cannot supply judgement |
| Denial of service against your own machine by your own paired phone | Rate limits and resource caps bound the damage; a device you control is not an adversary in this model |
| Traffic-analysis correlation of when you work | Timing metadata is not hidden and cannot be, short of cover traffic nobody wants to pay for |

---

## Trust boundaries

Five boundaries matter. Each is a place where a component is *deliberately*
given less trust than it might appear to have.

### 1. The relay — untrusted, by design

**What it can see:** that two `NodeId`s are exchanging packets; how many bytes,
in which direction, and at what times; when a session starts and ends. Because
addressing in iroh is by public key rather than IP, it necessarily learns which
keys are talking.

**What it cannot see:** any content. File names, file contents, commands,
command output, diffs, project names, git branches, and every protocol frame
are inside the Noise session. The relay is a dumb packet forwarder that could
be replaced by a hostile one without changing the security properties.

**What it can do:** drop traffic. A relay can deny service; it cannot forge,
tamper, or read.

**Your control:** `relay_url` in the configuration points at your own
`iroh-relay`. This narrows *metadata* exposure. It does not change content
exposure, because there was none.

### 2. The paired phone — trusted with a lot, bounded deliberately

**What a legitimately paired phone can do:** everything its capability grant
permits, inside its declared workspace roots. With the defaults, that includes
reading and writing files, spawning shells — and therefore running arbitrary
code — and performing ordinary git operations.

**What it cannot do without a fresh biometric presence signature:** read a
denylisted path, force-push or hard-reset or rewrite history, delete a
directory or more than ten files, write outside a declared root, approve an
agent's destructive action, change security policy, pair or revoke a device, or
rotate the daemon identity.

**What it cannot do at all:** reach outside its declared workspace roots; use a
capability it was not granted; act after revocation.

**What a *compromised* phone can do:** everything in the first list, silently.
It cannot manufacture presence signatures, because those require a live
biometric against a StrongBox key with a zero-second validity window — but it
*can* wait for the user to produce one and try to spend it. That is why the
presence signature covers the canonical digest of the specific operation about
to be performed, rather than a bare nonce: a signature harvested for one action
cannot be replayed onto another (`ARCHITECTURE.md` §3.10).

**The corollary for reviewers:** the daemon never trusts anything the phone
asserts about authorisation. Capability checks, path canonicalisation, rate
limits, and audit writes all happen server-side, on the only path to services.
A phone that lies about its grants gets a typed error and an audit entry.

### 3. The editor WebView — untrusted, isolated

The CodeMirror 6 editor runs in an Android `WebView`, which is a JavaScript
execution environment rendering content that comes from arbitrary repositories.
It is treated as untrusted.

**What it is trusted with:** rendering text and reporting edits. That is the
entire list.

**What it holds:** no protocol knowledge, no keys, no capability state, no
network access. Assets are bundled in the APK and served from
`file:///android_asset`, so there is no CDN and no remote code load surface.
Network access from the WebView is **blocked outright**, so even a compromised
bundle cannot exfiltrate what it can see.

**How it communicates:** a typed JSON bridge over `WebMessagePort` to Kotlin,
and from there to Rust. **The bridge validates every message.** A WebView that
asks to write outside the file it has open, or to read a path it was not given,
is rejected at the bridge and again by the daemon's path guard
(`ARCHITECTURE.md` §6.3, §18.3).

**Why a WebView at all:** no acceptable native mobile code editor exists, and
CM6 is the only serious editor rewritten with mobile as a design goal. The
boundary above is the price of that, made explicit rather than assumed.

### 4. The notification server — untrusted, and only trusted with metadata

**What it sees:** that a message was published to an unguessable topic, when,
and roughly how large it was.

**What it cannot see:** anything else. Payloads are ChaCha20-Poly1305
ciphertext under a key established at pairing; the phone decrypts locally to
render the title and body. No filename, diff, command, or project name leaves
the laptop in the clear on any tier, including the optional user-deployed FCM
relay.

**What it can do:** fail to deliver, or delay delivery. Backend health is
surfaced in the app, because a silently broken notification path is invisible
until something important is missed.

**What cannot be fixed:** the metadata itself. This is documented as a product
limitation rather than left to be discovered (`ARCHITECTURE.md` §24.1,
[`../SECURITY.md`](../SECURITY.md#notification-metadata-leaks-and-cannot-be-hidden)).

### 5. The policy layer — the only path in

Not an external boundary but an internal one, and the most important structural
property in the daemon.

`gonomad-policy` is a *dependency of* the service layer, not a sibling of it.
Every request from a peer passes through capability checks, path
canonicalisation and guarding, denylist checks, and rate limiting before any
service is messaged. On failure: a typed error, an audit entry, and no syscall.

Two details make this stronger than a convention. **Policy sits on the only
path to services**, so skipping it is structurally impossible rather than
merely discouraged. And **the audit entry is written by the router, not by the
service**, so a service cannot forget to log (`ARCHITECTURE.md` §2).

A change that lets a service be reached without traversing policy is a security
regression regardless of how convenient it is, and reviewers are expected to
treat it as one.

---

## Assets and what protects them

| Asset | Where it lives | Primary protection |
|---|---|---|
| Daemon identity private key | OS keyring (DPAPI / Keychain / Secret Service) | Never written to a file; keyring ACLs; recovery phrase for restoration |
| Phone identity private key | Android Keystore, software-backed | Non-exportable, `setUnlockedDeviceRequired(true)` |
| Phone presence private key | StrongBox where available, TEE otherwise | Non-exportable, fresh user authentication required for every use |
| Pairing secret | Ephemeral, in memory, 120 seconds | Single-use, rate-limited, optical transfer only, SAS confirmation |
| Session keys | Ephemeral, per connection | Noise IK; a session is a live connection and nothing outlives it |
| Source code and file contents | The laptop's filesystem | Workspace roots, `fs:read`/`fs:write` capabilities, path canonicalisation |
| Credentials on disk (`~/.ssh`, `.env`, cloud config) | The laptop's filesystem | Secret denylist plus `fs:secrets` plus a presence signature |
| Credentials in terminal output | Daemon scrollback and on-disk ring buffer | Best-effort pattern redaction, scrollback hygiene, never cached to the phone. **Explicitly best-effort** |
| The audit log | SQLite on the laptop | Hash-chained; argument digests rather than arguments, so the log is not itself a secret store |
| Device grants | SQLite on the laptop | Server-side only; the phone can view but never assert them |
| The recovery phrase | Paper, wherever the user put it | Displayed exactly once, never stored, never transmitted |

---

## How the defences are verified

A threat model that is not tested is a wish list. The testing obligations that
correspond to the rows above (`ARCHITECTURE.md` §24.11,
[`../CONTRIBUTING.md`](../CONTRIBUTING.md#testing-expectations)):

| Defence | Verification |
|---|---|
| Path guards never escape a root (T5) | `proptest` over adversarial paths: `..`, symlinks, junctions, UNC, Windows 8.3 short names, alternate data streams, reserved device names, trailing dots and spaces, unicode normalisation, null bytes |
| Handshake authenticity and SAS divergence (T1, T6) | Noise test vectors; a MITM simulation asserting the two sides derive different digits; replay attempts asserting rejection |
| No pre-authentication surface (T2) | An external port scan of the host finding nothing — a literal M1 exit criterion; an external reviewer finding no pre-authentication surface — an MVP success criterion |
| Revocation is immediate (T9) | An M1 exit criterion: revocation effective on the next packet |
| Audit chain integrity | `gonomad audit verify` passing as an M1 exit criterion; the chain walk reports the exact sequence number of any break |
| Parsers do not panic on hostile input (T1, T8) | `cargo-fuzz` against the frame decoder and the VT parser |
| Adapter state detection does not silently break (T7) | Golden transcript tests per manifest; a vendor changing a spinner character must fail CI, not fail a user |
| Supply chain (T8) | `cargo deny check` and `cargo audit` as hard CI gates; reproducible builds compared across two runners |
| The whole model | A full security review against this document is an M6 exit criterion, with every row required to have a documented mitigation |

If you find a gap in this model — an adversary that is not listed, or a defence
that does not do what it claims — that is exactly the kind of report the
project wants. Send it privately via
[`../SECURITY.md`](../SECURITY.md#reporting-a-vulnerability).
