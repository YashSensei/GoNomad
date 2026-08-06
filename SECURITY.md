# Security Policy

GoNomad is designed to be pointed at a developer's primary machine. A paired
phone can read source code, run arbitrary commands, and reach every credential
that developer's shell can reach. That is the whole product, and it is why this
document exists before the product does.

The full security design is `ARCHITECTURE.md` §3. The complete threat model,
trust boundaries, and adversary capabilities are in
[`docs/threat-model.md`](./docs/threat-model.md). This file is the policy: what
is supported, how to report a problem, and what you should understand before
trusting anything here.

---

## Supported versions

> [!WARNING]
> **There are no supported versions. GoNomad is pre-alpha and has never been
> released.**

| Version | Supported | Notes |
|---|---|---|
| — | ❌ | No release exists. There is no daemon binary, no APK, and no published crate |
| `main` | ❌ | Unreleased, incomplete, and changing. Not intended for use against anything you care about |

There is no daemon you can run, so there is at present no deployed system to
attack. Security reports against the *design* in `ARCHITECTURE.md`, or against
the code in `crates/`, are welcome and useful — they are simply not
vulnerabilities in a shipped product.

A supported-versions policy will be published with v0.1.0 (`plan.md` §M6).
Until then, assume nothing here has been reviewed or audited. A full security
review against the threat model, and an external audit if the project can fund
one, are M6 exit criteria — not things that have happened.

---

## Reporting a vulnerability

**Do not open a public issue, pull request, or discussion.** Do not post a proof
of concept to a public branch or a social platform before coordinating.

### The channel

Report privately through **GitHub Security Advisories** on this repository:

> **<https://github.com/YashSensei/GoNomad/security/advisories/new>**

This is the only supported private channel today. It gives us a private fork to
develop and test a fix, a CVE request path, and a coordinated publication step,
without anything being visible until we publish together.

> [!NOTE]
> **There is no PGP key and no security email address yet, and this document
> will not invent one.** A PGP key for encrypted reports will be published
> before v0.1.0 (`ARCHITECTURE.md` §24.10, `plan.md` §M6), and its fingerprint
> will be listed here and in the release notes when it exists. Until then,
> GitHub Security Advisories is the only channel. If you see a `security@`
> address or a PGP fingerprint attributed to this project anywhere else, it is
> not ours.

If you cannot use GitHub Security Advisories for some reason, open a public
issue that says only *"I would like to report a security issue privately"* with
no technical detail whatsoever, and a maintainer will arrange a channel.

### What to include

The more of this you can provide, the faster the triage:

- The affected component — crate, commit hash, host platform, and, once they
  exist, daemon and app versions and the protocol version.
- What an attacker gains, and what position they need to start from. Map it to
  a threat-model row (T1–T10) if you can; if it does not fit any row, say so,
  because that is itself interesting.
- Reproduction steps, ideally minimal, and a proof of concept if you have one.
- The impact as you see it, and any mitigation a user could apply today.
- Whether you want credit, and the name and link you want credited.

### What we ask of you

- Give us a reasonable window to fix the issue before disclosing publicly. See
  the timelines below.
- Do not access, modify, or exfiltrate data that is not yours, and do not
  degrade anyone's service while testing.
- Test against your own machines and your own paired devices only.

---

## What to expect

GoNomad is a volunteer project with a very small maintainer group, so these are
honest targets rather than a contractual SLA. We will not promise a 24-hour
response we cannot keep.

| Stage | Target |
|---|---|
| Acknowledgement that the report was received | Within **5 business days** |
| Initial assessment: is it a vulnerability, what is the severity, is it in scope | Within **14 days** of acknowledgement |
| Regular status updates while work continues | At least every **14 days** |
| Fix developed and reviewed | Depends on severity and complexity; critical issues are prioritised over all other work |
| Coordinated public disclosure | By default **90 days** after the initial report, or sooner once a fix is available and users can act on it |

If a report is already being exploited, or is public elsewhere, the timeline
collapses and we will publish an advisory with mitigations as soon as we have
something useful to say, fix or no fix.

If we conclude a report is a *documented trade-off* rather than a
vulnerability — see [Known limitations](#known-limitations) — we will say so
explicitly and explain why, rather than letting the report go quiet. If you
disagree, say so; the classification is a judgement call and sometimes the
right outcome is to change the design.

Severity is assessed with CVSS v3.1 as a starting point, adjusted for this
project's context: anything that yields code execution on the host from an
unpaired position, or that defeats the pre-authentication surface guarantees of
`ARCHITECTURE.md` §3.7, is treated as critical regardless of what a score says.

---

## Safe harbour

We will not pursue or support legal action against researchers who report
vulnerabilities to us in good faith and in line with this policy. Specifically,
if you:

- make a good-faith effort to avoid privacy violations, data destruction, and
  interruption or degradation of anyone else's systems;
- test only against systems you own or are explicitly authorised to test;
- report promptly, and do not exploit an issue beyond what is necessary to
  demonstrate it;
- keep the details confidential until a coordinated disclosure;

then we consider your research authorised, we will not initiate legal action
against you, and we will work with you to understand and fix the issue. If a
third party initiates action against you for research conducted under this
policy, we will make it known that your activity was authorised.

There is no bug bounty. This is an unfunded open-source project and we would
rather say that plainly than imply a reward that does not exist. Credit in the
advisory and the release notes is offered to every reporter who wants it.

---

## Threat model summary

Adapted from `ARCHITECTURE.md` §3.1. The full version, with trust boundaries
and per-adversary detail, is in [`docs/threat-model.md`](./docs/threat-model.md).

Everything in the "Primary defence" column is **designed, not implemented**.
None of it has been built, tested, or reviewed yet.

| # | Adversary | Capability | Primary defence |
|---|---|---|---|
| T1 | Network attacker (café Wi-Fi, hostile ISP) | Observe, inject, replay, drop | Noise IK inside QUIC; nothing plaintext on the wire, including metadata |
| T2 | Internet scanner | Probe any reachable address | No routable listening port; no HTTP surface; ALPN mismatch dropped pre-handshake |
| T3 | Malicious relay | Sees all traffic, controls delivery timing | Relay is untrusted by design; sees ciphertext and traffic timing only |
| T4 | Stolen **locked** phone | Physical possession | Keys non-exportable in Keystore, gated on device unlock; remote revoke |
| T5 | Stolen **unlocked** phone | Full app access | Secret denylist, workspace roots, capability scoping, biometric gate on destructive operations, remote revoke |
| T6 | Shoulder-surfed or photographed QR | The pairing secret | Single-use, 120-second expiry, laptop-side approval, transcript-derived SAS confirmation |
| T7 | Prompt-injected AI agent | Proposes malicious edits or commands | True-diff rendering (never the agent's summary), destructive-operation detection, biometric gate |
| T8 | Malicious dependency in our own supply chain | Code execution in the daemon | `cargo-deny`, `cargo-audit`, vendored lockfile, minimal dependency set, reproducible builds |
| T9 | Rogue paired device (given away, sold, compromised) | A valid credential | Instant server-side revocation, per-device audit trail, capability minimisation |
| T10 | Local unprivileged process on the laptop | Reads daemon files, connects to loopback | Keys in the OS keyring rather than files; the loopback control socket is peer-credential checked |

### Explicitly out of scope: a compromised laptop OS

> [!IMPORTANT]
> **A compromised laptop operating system, with root or administrator access, is
> explicitly outside this threat model. If the attacker owns the machine that
> runs your compiler, GoNomad cannot help — and any design that claims
> otherwise is lying.**

An attacker with administrator or root on the host can read the daemon's
process memory, extract keys from the OS keyring as the user, replace the
`gonomad` binary, hook the `git` process, patch the audit log before it is
hashed, or simply read the source tree directly without going through GoNomad
at all. No amount of capability scoping, path guarding, biometric gating, or
audit chaining survives an adversary at that level, because every one of those
mechanisms is enforced by code that adversary controls.

This is stated plainly because the alternative — implying protection that does
not exist — is worse than the limitation itself. GoNomad's job is to make a
*remote phone* a safe way to reach a machine you trust. It is not, and will
never be, a defence against a machine you cannot trust.

Also out of scope: physical attacks on the host, malicious host firmware,
compromise of the Android OS itself below the app sandbox, and any attack that
requires the user to deliberately grant capabilities to a device they know to
be hostile.

---

## Known limitations

These are properties of the design, not gaps awaiting a patch. Understand them
before trusting GoNomad with anything, once there is something to trust.

### Notification metadata leaks, and cannot be hidden

Android will not keep a socket alive indefinitely for a backgrounded app, and
the only mechanism that can wake one is a push service. FCM requires a Google
Cloud project — a cloud account, which the product principles forbid. The
requirement "the laptop notifies the phone" and the requirement "no cloud
account" cannot both be fully satisfied (`ARCHITECTURE.md` §24.1).

The resolution: notification payloads are **always** ciphertext. A random topic
name and a ChaCha20-Poly1305 blob under a key established at pairing. No
filename, diff, command, or project name leaves the laptop in the clear, on any
tier, under any configuration.

What that does **not** hide is metadata. Your notification server — self-hosted
ntfy by default, but still a server — learns that *a* notification occurred,
when it occurred, and roughly how large it was. A sufficiently interested
observer of that server can infer activity patterns: when you are working, how
often an agent asks for approval, roughly how large the approvals are. Running
your own ntfy instance narrows who can see this; it does not eliminate the
signal.

### Terminal secret redaction is best-effort only

The secret denylist (`ARCHITECTURE.md` §3.6) protects the *filesystem*. It does
nothing about a user typing `env`, `printenv`, `cat .env`, or `docker inspect`,
after which secrets land on the phone screen, in the daemon's scrollback, and
in an on-disk ring buffer.

The mitigations — pattern-based redaction of high-entropy strings adjacent to
known key names (`API_KEY=`, `TOKEN=`, `AWS_`, `sk-`, `ghp_`, JWT shapes), a
warning banner for commands likely to print secrets, and a scrollback-clear
action that actually deletes the on-disk buffer — are heuristics. They will
miss secrets in formats they do not recognise, and they will occasionally
redact something that was not a secret. **Do not rely on redaction as a
security control.** It reduces accidental exposure; it does not prevent
deliberate exposure.

### `pty:spawn` transitively grants arbitrary code execution

A shell can run anything. The `exec:arbitrary` capability therefore governs only
the structured `exec` API — granting `pty:spawn` is granting arbitrary
execution on the host, and GoNomad does not pretend otherwise.

If you want a genuinely read-only device, you must withhold `pty:spawn`. The
pairing interface is required to say this in those words rather than presenting
`pty:spawn` as one checkbox among equals (`ARCHITECTURE.md` §3.6).

### Losing the device key means re-pairing

There are no bearer tokens, so there is no password, so there is no password
reset. A device's Ed25519 keypair *is* its credential.

- Lose the phone, or wipe it: the device is re-paired from scratch. Revoke the
  old one from the laptop.
- Lose the laptop's daemon identity: the 24-word recovery phrase shown once at
  `gonomad init` restores it deterministically, and existing phones reconnect
  without re-pairing. Without that phrase, every device is re-paired.

This is deliberate. A self-hosted tool with a credential-recovery backdoor has
a credential-recovery attack, and re-pairing is inconvenient rather than
catastrophic — the correct failure mode for a tool with no account system
(`ARCHITECTURE.md` §3.2, §9.5).

### The Android identity key is software-backed

Android's hardware-backed Keystore does not support Ed25519 or X25519 —
StrongBox and TEE keymaster support EC P-256/P-384/P-521, RSA, and AES, not
Curve25519. The identity key used for the Noise handshake is therefore a
software key held in Keystore-encrypted storage, protected by the device's
hardware-derived key encryption key and the lockscreen. Its private scalar is
present in app memory during a handshake.

That is adequate against a stolen locked phone (T4). It is **not** sufficient
against a stolen unlocked phone (T5), which is precisely why a second key
exists: a P-256 **presence key** in StrongBox where available, non-exportable,
requiring a fresh biometric for every single use, and required for every
destructive operation (`ARCHITECTURE.md` §3.3).

### Other limitations worth knowing

- **The relay sees traffic timing.** Noise IK means it sees ciphertext, never
  content — but volume and timing are observable. Self-host `iroh-relay` if
  that matters to you.
- **Aggressive OEM battery managers** on some Android devices will kill the
  connection in ways that are unreproducible on a Pixel
  (`ARCHITECTURE.md` §24.2). This is a reliability problem, not a security one,
  but it can silently stop security-relevant notifications from arriving.
- **Nothing has been audited.** Not the crypto, not the path guards, not the
  protocol. The threat model is a design document, and a design document has
  never stopped an attacker.

---

## Security-relevant design references

| Topic | Where |
|---|---|
| Full threat model, trust boundaries | [`docs/threat-model.md`](./docs/threat-model.md) |
| Identity and the no-bearer-token argument | `ARCHITECTURE.md` §3.2 |
| Key management, the two-key split, rotation | `ARCHITECTURE.md` §3.3 |
| Noise IK inside QUIC, and why the redundancy is deliberate | `ARCHITECTURE.md` §3.4 |
| Replay and integrity | `ARCHITECTURE.md` §3.5 |
| Capabilities, workspace roots, the secret denylist | `ARCHITECTURE.md` §3.6 |
| Pre-authentication surface | `ARCHITECTURE.md` §3.7 |
| Rate limits and resource caps | `ARCHITECTURE.md` §3.8 |
| Hash-chained audit log | `ARCHITECTURE.md` §3.9 |
| Approval gating and presence signatures | `ARCHITECTURE.md` §3.10 |
| Supply chain and build integrity | `ARCHITECTURE.md` §3.11, §24.12 |
| Pairing flow and why it resists MITM | `ARCHITECTURE.md` §9 |
| AI agent approval flow as a security feature | `ARCHITECTURE.md` §7.5 |
| Deployment, uninstall, complete revocation | [`docs/deployment.md`](./docs/deployment.md), `ARCHITECTURE.md` §24.8 |
