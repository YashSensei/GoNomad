# Deploying the GoNomad daemon

> [!WARNING]
> **Forward-looking document. None of this works yet.**
>
> There is no release, no installable binary, and no `gonomad` command. Every
> command, path, and configuration key below describes the intended design so
> it can be reviewed and argued with *before* it is built. Nothing on this page
> should be read as instructions you can follow today.
>
> Current state: [README status](../README.md#status-pre-alpha). Roadmap:
> [`plan.md`](../plan.md). The CLI surface lands with M1; the daemon becomes
> genuinely useful across M2–M5; macOS and Linux hosts arrive at M6.

The design goal this document serves is stated as a constraint in
`ARCHITECTURE.md` §1: **one binary, one command, no runtime, no reverse proxy,
no DNS, no certificates, no router configuration.** If a step below ever grows
into "now configure nginx", the design has failed and the step is the bug.

---

## Contents

- [What you will need](#what-you-will-need)
- [Installation](#installation)
- [First run: `gonomad init`](#first-run-gonomad-init)
- [Configuration](#configuration)
- [Declaring workspaces](#declaring-workspaces)
- [Pairing a phone](#pairing-a-phone)
- [Running the daemon](#running-the-daemon)
- [The loopback control socket](#the-loopback-control-socket)
- [Networking and firewall expectations](#networking-and-firewall-expectations)
- [Notifications](#notifications)
- [On-disk layout](#on-disk-layout)
- [Day-to-day operation](#day-to-day-operation)
- [Backup and recovery](#backup-and-recovery)
- [Uninstalling](#uninstalling)
- [Environment gotchas](#environment-gotchas)

---

## What you will need

| | Requirement |
|---|---|
| Host OS | Windows 10 1809 or later (ConPTY). Windows 11 22H2+ enables `PSEUDOCONSOLE_PASSTHROUGH_MODE` for better terminal fidelity. macOS and Linux at M6 |
| Phone | Android, `arm64-v8a`. `armeabi-v7a` and `x86_64` at M6 |
| Network | Outbound UDP. **No inbound port, no port forwarding, no public IP, no DNS record, no TLS certificate** |
| Accounts | None. There is no sign-in, and no service operated by this project that you are required to reach |
| Optional | `git` on `PATH` (required for git features); an ntfy server for notifications; your own `iroh-relay` if you do not want to use the public ones |

The daemon runs as your normal user account. It does not need administrator
rights, and it should not be given them: it exists to expose *your* development
environment — your credential helpers, your SSH agent, your shells — and
running it elevated would both break that and widen the blast radius.

---

## Installation

Two intended paths:

```bash
# From crates.io, building locally with the pinned toolchain.
cargo install gonomad --locked

# Or download a signed release artifact for your platform.
```

Release artifacts will be signed with `cosign` and published with SLSA
provenance, and CI will build each release twice on separate runners and fail
if the hashes differ (`ARCHITECTURE.md` §24.12). The verification commands will
be published alongside the first release. The Android APK will be
`apksigner`-verifiable and reproducible, with F-Droid as a distribution target
precisely because its reproducible-build requirement is a useful external
forcing function.

Until any of that exists, the only way to get the code is to build the
workspace from source; see [`../CONTRIBUTING.md`](../CONTRIBUTING.md).

---

## First run: `gonomad init`

```bash
gonomad init
```

One command, and it does four things:

1. **Generates the daemon's Ed25519 identity keypair.** The private key goes
   into the OS keyring — Windows Credential Manager via DPAPI, macOS Keychain,
   Secret Service on Linux — and **not** into a file, because a file is
   readable by every process running as that user (threat T10). Where no
   keyring is available, such as a headless Linux box, it falls back to a file
   at mode `0600` and warns loudly at startup.
2. **Prints a 24-word recovery phrase, exactly once.** It seeds the identity key
   deterministically, so a reinstalled daemon can restore the same identity and
   existing phones reconnect without re-pairing. It is never stored and never
   transmitted. Write it down on paper. See
   [Backup and recovery](#backup-and-recovery).
3. **Writes a default `~/.gonomad/config.toml`.**
4. **Registers autostart**, in a way you can find and remove — a Run-key entry
   or scheduled task on Windows, a LaunchAgent on macOS, a user systemd unit on
   Linux. Autostart is a configuration key, not a hidden behaviour.

> [!IMPORTANT]
> The recovery phrase is equivalent to the daemon's identity. Anyone who has it
> can impersonate your machine to your paired devices. Treat it like an SSH
> private key: on paper, offline, not in a password manager that syncs to a
> service you have not thought about.

---

## Configuration

`~/.gonomad/config.toml` is human-editable, validated before it is applied, and
hot-reloaded on change. An invalid file is rejected with a message naming the
key, and the previous configuration stays live rather than the daemon dying.

Adapted from `ARCHITECTURE.md` §5.4:

```toml
[server]
autostart = true

[[workspace]]
name = "myproject"
path = "C:/Users/you/code/myproject"
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

Notes that matter:

- **Secrets are never in this file.** They live in the OS keyring; the file
  holds references. The one thing that looks like a secret — `ntfy_topic` — is
  a random string that acts as an unguessable channel name, and it is treated
  as sensitive even though the payloads published to it are encrypted anyway.
- **`deny_paths` merges with the built-in denylist**, it does not replace it.
  The built-in list covers `**/.ssh/**`, `**/.aws/**`, `**/.env*`, `**/*.pem`,
  `**/*.key`, `**/.git-credentials`, `**/.gnupg/**`, `**/.claude/**` and more
  (`ARCHITECTURE.md` §3.6). Narrowing the list is allowed and produces a
  warning; you should know when you are doing it.
- **`require_presence_for`** lists the operation classes that demand a fresh
  biometric signature from the phone's presence key. Removing an entry weakens
  a real defence; adding entries is free.
- **`prefer`** orders the transport ladder. Removing `relay` means the daemon
  is unreachable when hole punching fails, which is a legitimate choice if you
  only ever use it on your own LAN.
- **`relay_url`** pointing at your own `iroh-relay` removes even traffic-timing
  metadata from third-party infrastructure. The relay never sees plaintext
  either way, because Noise IK sits inside the QUIC session
  (`ARCHITECTURE.md` §3.4).

---

## Declaring workspaces

```bash
gonomad workspace add .
gonomad workspace ls
gonomad workspace rm myproject
```

A workspace root is the only thing a paired device can reach. Every path in
every request is canonicalised — resolving `..`, symlinks, junctions, Windows
8.3 short names, and `\\?\` prefixes — and then checked component-wise to be a
descendant of a declared root, and re-validated after opening to close the
window where a symlink is swapped between check and use
(`ARCHITECTURE.md` §3.6).

Declare the narrowest roots that are actually useful. Adding `C:/Users/you` as
a workspace root technically works and defeats most of the point.

The MVP supports **one workspace root**; multi-workspace switching is
post-MVP (`plan.md`, MVP scope).

---

## Pairing a phone

```bash
gonomad pair
```

Pairing mode opens for **120 seconds**, is **single-use**, is rate-limited to
three attempts, and renders a QR code both in the terminal and in the tray
dialog. The QR carries the daemon's `NodeId`, relay and address hints, and a
256-bit single-use pairing secret.

The phone scans it, connects, and both sides derive a six-digit **SAS** from
the full handshake transcript. The laptop shows an approval dialog naming the
device and its proposed capabilities and workspace roots; the phone shows the
six digits. Confirm they match, approve on the laptop, and the device's public
key is stored as a grant.

After that there is no login and no token. The key is the credential
(`ARCHITECTURE.md` §9).

Things worth knowing:

- **The QR is the security boundary.** It transfers the daemon's authentic
  public key over an optical channel an attacker must be physically present to
  observe, which is what defeats a network man-in-the-middle. Do not screen
  share, photograph, or forward it.
- **The SAS is not ceremony.** It exists precisely because the QR *can* leak.
  If the digits do not match, something is proxying your connection; deny.
- **Manual entry** exists for a broken camera and uses a real PAKE rather than
  treating the short code as a shared secret, because 40 bits of entropy would
  otherwise be brute-forceable.
- **Grant the narrowest capability set that works.** Withholding `pty:spawn`
  is the only way to get a genuinely read-only device, because a shell can run
  anything (`ARCHITECTURE.md` §3.6).

---

## Running the daemon

```bash
gonomad start                 # background
gonomad start --foreground    # attached to the terminal, logs to stdout
```

With `autostart = true`, `gonomad init` registers the daemon to start at login
and you rarely run this by hand.

### The tray icon

The daemon is not headless infrastructure. A small native tray surface shows:

- connection state — connected, idle, disconnected — at a glance;
- a pairing dialog, so pairing does not require a terminal;
- approval prompts for operations that need laptop-side presence;
- a **kill switch** that drops every connection immediately.

This is not optional decoration. A security tool with no visible indicator that
a phone is attached, and no one-click way to cut it off, is missing a control
users will demand the first time they feel uneasy (`ARCHITECTURE.md` §24.4).

---

## The loopback control socket

The `gonomad` CLI does not manipulate the daemon's files. It connects to a
control socket bound to loopback only — a named pipe on Windows, a Unix domain
socket elsewhere — and the daemon **verifies the peer's credentials** before
accepting a command: `GetNamedPipeClientProcessId` plus a token comparison on
Windows, `SO_PEERCRED` on Unix.

The point is threat T10: another local user, or an unprivileged process running
as someone else, must not be able to drive your daemon just because it can
reach a loopback address. Loopback is not an authorisation boundary on a
multi-user machine; peer credentials are.

This socket is never routable. It is not a fallback transport, it is not
reachable from the phone, and there is no configuration key to expose it.

---

## Networking and firewall expectations

> [!NOTE]
> **No inbound port needs to be opened. That is the entire point.**
>
> There is no `0.0.0.0:8080`, no HTTP surface, no reverse proxy, no DDNS, no
> TLS certificate to obtain or renew, and no router configuration. If a
> troubleshooting suggestion anywhere ever tells you to forward a port to your
> development machine, it is wrong and you should not follow it
> (`ARCHITECTURE.md` §19/R16).

What the daemon actually needs:

| | Requirement |
|---|---|
| Outbound UDP | Yes — QUIC. This is how hole punching and the relay both work |
| Inbound UDP | Helpful when the NAT cooperates, never required. Hole punching creates the mapping from the inside |
| Inbound TCP | Never |
| mDNS (UDP 5353) | Only for LAN discovery. Blocking it costs you the fastest tier, nothing else |

On Windows, the first run may raise a Windows Defender Firewall prompt for the
`gonomad` binary. Allowing it on **private** networks improves LAN discovery
and direct connections; denying it falls back to relayed connections, which
remain fully encrypted and are slower rather than less safe.

### The transport ladder

```text
Tier 0   LAN direct QUIC via mDNS      same network: lowest latency, no relay
Tier 1   hole-punched direct P2P QUIC  the typical remote case
Tier 2   iroh relay (self-hostable)    CGNAT, symmetric NAT, hostile firewall
Tier 3   Tailscale · CF Tunnel · ssh   opt-in, post-MVP
```

Tiers are attempted concurrently rather than in sequence, and the fastest
working path wins. iroh keeps probing for a direct path while relayed and
upgrades transparently mid-session. The app always shows which tier is active,
because a silently relayed session that feels slow is worse than a visibly
relayed one.

### Self-hosting the relay

Set `relay_url` to your own `iroh-relay` instance if you object to traffic
timing crossing infrastructure you do not control. The relay is untrusted by
design and forwards ciphertext, so the default public relays are safe to use;
self-hosting narrows metadata exposure, not content exposure
(`ARCHITECTURE.md` §4.3).

---

## Notifications

Push notification and "no cloud account" are in genuine, structural conflict —
see `ARCHITECTURE.md` §24.1 and the
[known limitations in `SECURITY.md`](../SECURITY.md#notification-metadata-leaks-and-cannot-be-hidden).

The default is a **self-hosted ntfy** server. GoNomad publishes an opaque
ChaCha20-Poly1305 blob to a random topic, under a key established at pairing;
the phone decrypts locally to render the real title and body. The notification
server — yours or anyone's — learns only that something happened, when, and
roughly how big it was.

```toml
[notifications]
backend = "ntfy"                        # or "local" for live-connection only
ntfy_url = "https://ntfy.example.com"
ntfy_topic = "gonomad-a1b2c3"
```

Backend health is surfaced in the app, because a silently broken notification
path is invisible until something important is missed.

---

## On-disk layout

Everything the daemon owns lives under `~/.gonomad/`:

```text
~/.gonomad/
├─ config.toml            # the file above; human-editable, hot-reloaded
├─ gonomad.db             # SQLite: devices, grants, audit chain, sessions
├─ index/<workspace>.fst  # persisted FST path index, rebuilt on demand
├─ scrollback/            # capped per-PTY ring buffers, spilled from memory
├─ transcripts/           # agent transcripts, append-only with rotation
├─ adapters/              # your own AI agent manifests (*.toml)
└─ logs/
```

Not on disk, ever: the daemon's private key, which lives in the OS keyring.

Not in SQLite, ever: file content, scrollback, and transcripts. Those are
capped on-disk files, because storing megabytes of terminal output as rows
bloats the database and buys no query worth having (`ARCHITECTURE.md` §16.1).

`~/.gonomad/` contains keys' metadata, audit data, and scrollback that may
include secrets you typed. It is excluded by the repository's `.gitignore` and
should be excluded from any backup you would not treat as sensitive.

---

## Day-to-day operation

```bash
gonomad status                  # transport tier, RTT, live sessions, PTYs
gonomad doctor                  # diagnose connectivity, permissions, shells, agents
gonomad logs --follow
gonomad devices ls
gonomad devices revoke <name>   # immediate, server-side, effective next packet
gonomad devices rename <id> <name>
gonomad audit verify            # walk the hash chain, report the first break
gonomad audit export
gonomad rotate-identity
gonomad uninstall
```

**`gonomad doctor` matters more than it sounds.** Most of the support burden for
a self-hosted networking tool is environment diagnosis: is UDP blocked, is the
firewall rule missing, is `git` on `PATH` and a usable version, which shells
were detected, which AI agent binaries were found, is a workspace root inside a
cloud-synced folder. A good doctor command converts issue reports into
self-service.

**Revocation deletes one database row** and takes effect on the next packet.
There is no token blacklist to propagate and no expiry to wait out. Force
disconnect drops the QUIC connection without removing the grant; revoke removes
the grant. Both are immediate and both are enforced server-side.

**`gonomad audit verify`** walks the hash chain from genesis and reports the
exact sequence number at which continuity breaks. An attacker who compromises
the daemon will try to erase their tracks first; a plain log lets them, a
chained log makes the erasure evident (`ARCHITECTURE.md` §3.9).

**`gonomad rotate-identity`** generates a new daemon key and re-signs every
device grant. Each phone then shows a "this machine's identity changed —
confirm the fingerprint" prompt, so rotation cannot be used as a
man-in-the-middle vector.

---

## Backup and recovery

| Item | How to protect it |
|---|---|
| Daemon identity | The 24-word recovery phrase from `gonomad init`, on paper. It regenerates the key deterministically |
| Device grants | Exported alongside the recovery phrase as an encrypted blob |
| `config.toml` | Plain text and safe to keep in your dotfiles, as long as you accept that it lists your workspace paths and ntfy topic |
| `gonomad.db` | Contains the audit chain and device grants. Back it up if the audit history matters to you; restoring an older copy will make `audit verify` report a truncation |
| Scrollback, transcripts, index | Disposable. They regenerate |

Without the recovery phrase, recovery means re-pairing every device.
Inconvenient, not catastrophic — the correct failure mode for a tool with no
account system (`ARCHITECTURE.md` §9.5).

---

## Uninstalling

A security tool must be cleanly removable, and the exit is documented before
anyone asks (`ARCHITECTURE.md` §24.8).

```bash
gonomad uninstall
```

Removes the keyring entry, deletes the configuration, index, scrollback,
transcripts, and database, deregisters autostart, and **prints a list of what
it removed** so you can verify rather than trust.

On the phone, "unpair and wipe" deletes the Keystore keys — identity and
presence — and the Room cache including any queued offline writes. Do this
before selling or giving away a device; if you cannot, revoke the device from
the laptop, which is immediate and does not require the phone to cooperate.

---

## Environment gotchas

These are documented because they will otherwise be discovered as bugs
(`ARCHITECTURE.md` §24.13).

- **Cloud-synced folders.** OneDrive, Dropbox, and iCloud Drive produce
  spurious watcher events, placeholder files that block on read, and lock
  contention. The daemon detects a synced root and warns. Prefer a workspace
  root outside a sync engine.
- **Long paths on Windows.** `MAX_PATH` requires `\\?\` prefixing and opt-in
  long-path support; deep `node_modules` trees hit this routinely. Enable
  long paths in Windows if you work with such trees.
- **WSL.** WSL is offered as a first-class shell. A WSL PTY's working directory
  is a Linux path, and the filesystem layer keeps per-PTY path-translation
  context rather than assuming a PTY's cwd shares the host's namespace. Do not
  expect a WSL terminal's paths to be interchangeable with the file tree's.
- **`git` missing or too old.** Git mutations shell out to your real `git`
  binary so that hooks, signing, and credential helpers behave exactly as they
  do at the desk. `doctor` detects its absence rather than letting you find out
  at commit time.
- **Multiple daemons on one LAN.** mDNS disambiguates by hostname and `NodeId`
  so pairing cannot target the wrong machine. Check the device name in the
  laptop's approval dialog anyway.
- **Version skew.** The phone and the daemon update independently, so skew is
  guaranteed. Protocol negotiation has a hard minimum floor and produces an
  explicit "update your daemon" screen naming both versions, never partial
  functionality (`ARCHITECTURE.md` §24.7).
- **First run on a huge monorepo.** The FST path index builds lazily in the
  background, with visible progress and a cancel button. It should never block
  the file tree; if it does, that is a bug worth reporting.
