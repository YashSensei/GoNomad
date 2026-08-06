# Contributing to GoNomad

Thank you for looking. GoNomad is pre-alpha — see the status warning in the
[README](./README.md) — which means design feedback and foundational work are
worth more right now than feature contributions.

Two documents outrank everything here:

- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — the canonical design and the *why*
  behind every decision. Read at least §1 (product vision), §2 (system
  architecture), and §3 (security architecture) before writing code.
- [`plan.md`](./plan.md) — the execution roadmap. Work is sequenced so that risk
  is retired before investment; picking up something from a later milestone
  before its prerequisites exist usually wastes the effort.

> [!IMPORTANT]
> **Never report a security vulnerability in a public issue or pull request.**
> Use the private process in [`SECURITY.md`](./SECURITY.md).

Participation is governed by the [Code of Conduct](./CODE_OF_CONDUCT.md).

---

## Table of contents

- [Where to start](#where-to-start)
- [Prerequisites](#prerequisites)
- [Building, testing, linting](#building-testing-linting)
- [How lints are configured — read this one](#how-lints-are-configured--read-this-one)
- [The quality bar](#the-quality-bar)
- [Where things live](#where-things-live)
- [Testing expectations](#testing-expectations)
- [Commit conventions](#commit-conventions)
- [Developer Certificate of Origin](#developer-certificate-of-origin)
- [Pull requests](#pull-requests)
- [Proposing an architecture change](#proposing-an-architecture-change)
- [Security issues](#security-issues)
- [Licence of contributions](#licence-of-contributions)

---

## Where to start

Genuinely useful contributions at this stage, roughly in order:

1. **Review the design.** `ARCHITECTURE.md` is long and opinionated. If a
   decision looks wrong, say so in a discussion — it is cheaper to change now
   than after the code exists.
2. **The M0 spikes** (`plan.md` §M0). Four throwaway experiments — the Compose
   `Canvas` terminal renderer, an iroh round trip through CGNAT, a UniFFI
   round trip, and ConPTY process-tree teardown. Their whole purpose is to fail
   loudly before the architecture is committed to.
3. **M1 crates.** `gonomad-proto`, `gonomad-core`, `gonomad-policy`, and
   `gonomad-store` are under active construction; `gonomad-transport` and
   `gonomad-server` do not exist yet, so nothing runs end to end. The security
   foundation is built first because retrofitting it is not possible.
4. **Documentation and glossary gaps.** If something in [`docs/`](./docs/README.md)
   sent you to `ARCHITECTURE.md` to understand it, that is a docs bug.

Open an issue or discussion before starting anything substantial. Duplicate
effort is the most common waste in a project this early.

---

## Prerequisites

### All platforms

| Tool | Version | Notes |
|---|---|---|
| Rust | stable, pinned by [`rust-toolchain.toml`](./rust-toolchain.toml) | `rustup` reads the file automatically; do not override the channel |
| `rustfmt`, `clippy` | bundled | Listed as `components` in the toolchain file |
| Git | 2.30+ | Also a runtime dependency of the daemon (`ARCHITECTURE.md` §18.1) |

The workspace declares `rust-version = "1.75"` as its minimum supported Rust
version. The pinned channel is `stable`, so in practice you build with current
stable; the MSRV is what the crates promise, not what CI happens to run.

> [!NOTE]
> There is no Docker image, devcontainer, or Nix flake, and there is no plan for
> one to be required. The daemon needs a real toolchain because it compiles
> native code: `rusqlite` is built with the `bundled` feature, which compiles
> SQLite from C, so a working C compiler is a hard requirement rather than an
> optimisation.

### Windows (the first-class host)

| Tool | Notes |
|---|---|
| Visual Studio Build Tools | Install the **Desktop development with C++** workload |
| Windows 10 1809+ | ConPTY availability; Windows 11 22H2+ additionally offers `PSEUDOCONSOLE_PASSTHROUGH_MODE` |

Rust on Windows uses the MSVC toolchain (`x86_64-pc-windows-msvc`, the target
pinned in `rust-toolchain.toml`). Without `link.exe` and the Windows SDK on
`PATH`, `cargo build` fails at the link step with an error that does not
obviously say "install the C++ workload" — this is the single most common
first-build failure. The GNU toolchain is not supported: ConPTY, DPAPI-backed
credential storage, and Job Objects are all developed against MSVC.

### macOS and Linux

Host support lands at M6 (`plan.md` §M6). Until then you can build and test the
platform-independent crates — `gonomad-proto`, `gonomad-store`,
`gonomad-policy`, and later `gonomad-core` — on any platform, but nothing that
touches ConPTY, `ReadDirectoryChangesW`, or the Windows keyring will work.

You need a C toolchain (`build-essential` / Xcode command line tools) for the
same `rusqlite` reason.

### Android client

Nothing under `android/` exists yet; it arrives with M1. When it does, you will
need:

| Tool | Version | Notes |
|---|---|---|
| JDK | **17** | Android Gradle Plugin requires 17; newer JDKs are not interchangeable |
| Android SDK | API 34+ | Platform tools, build tools, and a physical device or emulator |
| Android NDK | matching the AGP pin | Required to cross-compile the Rust core |
| `cargo-ndk` | latest | `cargo install cargo-ndk`; builds the `.so` per ABI |
| Node.js | 20+ | Only for the CodeMirror bundle under `editor/`, which arrives at M3 |

Manual smoke testing happens on a **physical device over cellular**, not only
on Wi-Fi and not only on an emulator (`plan.md`, definition of done). Several
of the hardest bugs in this product — OEM battery killers, network handoff,
CGNAT traversal — are invisible on an emulator.

---

## Building, testing, linting

Run these from the repository root before opening a pull request.

```bash
# Format. CI checks; you fix.
cargo fmt --all
cargo fmt --all -- --check

# Lint. Zero warnings is the bar, not a goal.
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Test.
cargo test --workspace --all-features

# Documentation must build without warnings; every public item is documented.
cargo doc --workspace --no-deps --all-features

# Build with the committed lockfile, as a release would.
cargo build --workspace --locked
```

Supply-chain gates, configured by [`deny.toml`](./deny.toml):

```bash
cargo install cargo-deny --locked
cargo deny check      # licences, bans, advisories, sources
cargo audit           # RUSTSEC advisories against Cargo.lock
```

Every one of these also runs in CI. Which job gates what, how to reproduce each
locally, and which checks are blocking rather than advisory are documented in
[`docs/ci.md`](./docs/ci.md). Nothing in CI requires a secret, so the workflows
run identically on forks.

Android and editor commands (`./gradlew :app:assembleDebug`, `ktlint`, the Vite
bundle task) are documented once those trees exist.

---

## How lints are configured — read this one

**Lints are configured exclusively in each crate's `[lints]` table in its
`Cargo.toml`.**

```toml
# crates/gonomad-proto/Cargo.toml
[lints.rust]
missing_docs = "warn"
unsafe_code = "forbid"

[lints.clippy]
all = { level = "warn", priority = -1 }
pedantic = { level = "warn", priority = -1 }
module_name_repetitions = "allow"
must_use_candidate = "allow"
doc_markdown = "allow"
```

> [!WARNING]
> **Never add `#![warn(...)]`, `#![allow(...)]`, or `#![deny(...)]` inner
> attributes to a `lib.rs` or `main.rs`.** Source-level lint attributes take
> precedence over the manifest `[lints]` table and silently override it. There
> is no error, no warning, and no diagnostic pointing at the conflict — the
> manifest simply stops having any effect for that lint, and it will not be
> obvious why.

The concrete failure this rule exists to prevent: `clippy::doc_markdown` is
allowed in the manifest, because it flags product names ("GoNomad", "UniFFI",
"SQLite") as though they were code items and backticking prose nouns hurts
readability more than the lint helps. If someone adds a crate-level
`#![warn(clippy::pedantic)]` to `lib.rs` "for clarity", the manifest's `allow`
is overridden and the lint starts firing again across the whole crate. The
usual reaction is to sprinkle `#[allow]` on individual items, and the real
cause stays hidden.

The rules that follow from this:

- Changing a lint level for a crate means editing that crate's `Cargo.toml`,
  and nothing else.
- Item-level `#[allow(...)]` is acceptable for a genuinely local exception, and
  it must carry a comment explaining why the exception is correct here.
- Every crate in the workspace carries its own `[lints]` table. Copy the table
  from an existing crate when you add a new one, rather than inventing a
  variant.
- `unsafe_code = "forbid"` is not negotiable in any crate that currently
  forbids it. If you believe you need `unsafe`, that is an architecture
  discussion (see [below](#proposing-an-architecture-change)), not a diff.

Each `lib.rs` carries a short comment recording this. Keep it there.

---

## The quality bar

This is a security tool that runs on a developer's primary machine with access
to their credentials. The bar is correspondingly high, and it is uniform.

- **Clippy pedantic, zero warnings.** `-D warnings` in CI. Not "mostly clean".
- **`rustfmt` clean.** Default configuration; no per-file overrides.
- **Every public item is documented.** `missing_docs = "warn"` is on, and the
  documentation should say what the item is *for*, not restate its signature.
  Reference `ARCHITECTURE.md` sections by number where the reasoning lives
  there — do not duplicate the design document into doc comments.
- **Tests are required**, not optional. See
  [Testing expectations](#testing-expectations).
- **Comments explain *why*, not *what*.** The code already says what it does.
  A comment earns its place by recording a constraint, a rejected alternative,
  or a non-obvious consequence — "ConPTY defaults to the legacy OEM code page,
  so encoding is forced at spawn", not "set the code page".
- **Errors are typed.** Anything crossing the wire is a closed enum so the
  client can render a correct, actionable message for every failure
  (`ARCHITECTURE.md` §11.2). Stringly-typed errors are rejected in review.
- **No new dependency without justification in the pull request description.**
  The dependency set is deliberately small; every addition is attack surface in
  a tool with this much access (`ARCHITECTURE.md` §3.11).
- **No `unwrap()` or `expect()` in daemon paths** that can be reached by a
  remote peer. A panic reachable from the network is a denial of service.

---

## Where things live

The full tree is in `ARCHITECTURE.md` §17. Crates marked *not yet created*
arrive with the milestone shown; do not create them speculatively.

| Crate | Responsibility | Must never | State |
|---|---|---|---|
| `crates/gonomad-proto` | Frame schema, CBOR codec, version negotiation, identifiers, capabilities, the closed error enum | Depend on a transport or a service | In progress |
| `crates/gonomad-store` | SQLite schema, forward-only migrations, hash-chained audit log, device records | Store file content or scrollback | In progress |
| `crates/gonomad-policy` | Capability checks, path canonicalisation and guards, the secret denylist, rate limits, approval gating | Be bypassable — it is the only route to services | In progress |
| `crates/gonomad-core` | Device identity, pairing and SAS, Noise session, request correlation, reconnect policy, client cache, state machines. **Shared with the phone via UniFFI** | Touch the filesystem or spawn processes | In progress |
| `crates/gonomad-transport` | iroh endpoint, mDNS discovery, WebSocket binding, path selection | Interpret frame contents | Not yet created — M1 |
| `crates/gonomad-server` | Wiring, router, `gonomad` CLI, tray UI | Contain business logic | Not yet created — M1 |
| `crates/gonomad-pty` | ConPTY lifecycle, headless VT grid, scrollback ring | Know about the network | Not yet created — M2 |
| `crates/gonomad-fs` | Directory listing, watchers, FST path index, CAS writes | Accept an unvalidated path | Not yet created — M3 |
| `crates/gonomad-search` | Streaming content search, fuzzy path match | Materialise a full result set | Not yet created — M3 |
| `crates/gonomad-git` | Read via `gix`, mutate via the `git` CLI | Reimplement credential handling | Not yet created — M4 |
| `crates/gonomad-agents` | Adapter registry, manifest loading, state detection | Hardcode a vendor | Not yet created — M5 |
| `crates/gonomad-notify` | ntfy backend, local backend, optional FCM relay | Send anything but ciphertext | Not yet created — M5 |
| `crates/gonomad-ffi` | The UniFFI surface that becomes the Kotlin bindings | Grow a wide, chatty API | Not yet created — M6 |
| `android/` | Rendering, gestures, platform integration | Contain protocol or crypto logic | Not yet created — M1 |
| `editor/` | The CodeMirror 6 bundle built by Vite into the APK's assets | Touch the network | Not yet created — M3 |
| `adapters/` | Shipped AI agent TOML manifests | Require code changes for a new agent | Not yet created — M5 |

Two structural rules a reviewer will enforce:

- **`gonomad-core` is unaware of the filesystem and of process spawning.** It is
  a pure protocol and state crate, which is what makes compiling it into an
  Android application sane. Logic that needs I/O belongs in a service crate.
- **`gonomad-policy` is a dependency of the service layer, not a sibling.**
  Services cannot be reached except through it. A change that lets a service be
  called directly is a security regression regardless of how convenient it is.

And the rule that governs the phone: **if logic can live in Rust, it must.** If
a piece of Kotlin contains a conditional about protocol state, it belongs in
`gonomad-core` (`ARCHITECTURE.md` §6.2).

---

## Testing expectations

Unit tests for new logic are the floor. The parts of this system most likely to
break are not the parts unit tests naturally cover, so several categories are
mandatory rather than encouraged (`ARCHITECTURE.md` §24.11).

| Change touches | Required tests |
|---|---|
| **Path guards** (`gonomad-policy`, `gonomad-fs`) | **`proptest` coverage** over adversarial paths: `..` traversal, symlinks, junctions, UNC paths, Windows 8.3 short names, alternate data streams, reserved device names, trailing dots and spaces, unicode normalisation, null bytes. The property asserted is that nothing escapes a declared root. This is the highest-consequence code in the project. |
| **AI adapters / manifests** (`gonomad-agents`, `adapters/`) | **Golden transcript tests**: a recorded PTY transcript per manifest with the expected state transitions and approval extractions. Vendors change their spinner characters and prompt wording; that must fail CI, not fail a user. |
| Anything parsing untrusted input | Property tests, plus a `cargo-fuzz` target for the frame decoder and the VT parser. Neither may panic. |
| The VT emulator (`gonomad-pty`) | Conformance fixtures: recorded byte streams from `vim`, `htop`, `fzf`, `tmux`, `less`, progress bars, and ConPTY resize sequences, compared against expected grid snapshots. |
| Handshake and crypto | Noise test vectors, a MITM simulation asserting SAS divergence, and replay attempts asserting rejection. |
| CAS writes (`gonomad-fs`) | Concurrency tests with competing writers asserting no lost updates. |
| Anything on a latency-budget path | A `criterion` benchmark. Budgets in `ARCHITECTURE.md` §14.1 are enforced in CI; a regression is a build failure, not a ticket. |
| Android UI | Instrumented tests on a physical device for the terminal renderer, the WebView bridge, and the biometric flow. |

A pull request that adds a path-guard branch without a corresponding `proptest`
property, or an adapter manifest without a golden transcript, will be asked for
one before review continues. This is not pedantry: `ARCHITECTURE.md` §19 rates
both as high-likelihood failure modes.

---

## Commit conventions

**Conventional Commits**, with a scope naming the crate or area:

```
feat(policy): reject alternate data streams in path canonicalisation
fix(proto): correct CBOR tag for Digest on big-endian targets
docs: describe the DCO sign-off requirement
chore(deps): bump ciborium to 0.2.2
test(fs): add proptest coverage for UNC path rejection
refactor(store): extract the audit chain walk into its own module
perf(pty): coalesce dirty runs before the frame window closes
```

| Type | Use for |
|---|---|
| `feat` | A new capability visible to a user or another crate |
| `fix` | A bug fix |
| `docs` | Documentation only |
| `test` | Tests only |
| `refactor` | Behaviour-preserving restructuring |
| `perf` | A change whose point is a measured speed or resource improvement |
| `build` / `ci` | Build system, toolchain, workflows |
| `chore` | Everything else, including dependency bumps |

Common scopes: `proto`, `core`, `transport`, `policy`, `store`, `pty`, `fs`,
`search`, `git`, `agents`, `notify`, `server`, `ffi`, `android`, `editor`,
`docs`, `deps`.

Rules:

- **Imperative mood in the subject.** "add", not "added" or "adds".
- **Subject under ~72 characters**, no trailing full stop.
- **Small, modular commits.** One logical change each. A commit that renames a
  module *and* changes its behaviour is two commits.
- **The body explains the *why*.** What changed is visible in the diff; the
  reason it changed, the alternative you rejected, and the constraint that
  forced your hand are not. If the change is driven by a design decision, cite
  the section: "per `ARCHITECTURE.md` §3.6".
- **Breaking protocol changes** get a `!` (`feat(proto)!: …`) and a
  `BREAKING CHANGE:` footer explaining the version-negotiation consequence.
  Phone and daemon update independently and skew is guaranteed
  (`ARCHITECTURE.md` §24.7).

---

## Developer Certificate of Origin

**Every commit must be signed off.** Use `-s`:

```bash
git commit -s -m "fix(policy): reject trailing dots in Windows path components"
```

That appends a line to the commit message:

```
Signed-off-by: Your Name <your.email@example.com>
```

Your name and email must be real and must match your git configuration. Use
`git commit --amend -s` to fix a commit you forgot to sign, or
`git rebase --signoff <base>` for a branch.

### What you are certifying

The sign-off is your statement that the contribution is yours to give, in the
words of the [Developer Certificate of Origin 1.1](https://developercertificate.org/):
that you wrote it, or that it derives from work you are permitted to submit
under the project's licence, and that you understand the contribution and its
sign-off are public and permanent.

### Why DCO and not a CLA

A **Contributor Licence Agreement** is a contract in which you grant the project
owner rights over your contribution, usually including the right to relicense
it — which is what makes a CLA the mechanism behind most open-core relicensing
events. It requires a signing ceremony, a record of who signed which version,
and, for corporate contributors, a legal review before a first pull request.

A **Developer Certificate of Origin** grants nobody anything extra. It is a
statement of provenance: you are attesting that you have the right to submit
this code under the existing licence. Your contribution stays under Apache-2.0,
the same terms as everyone else's, including the maintainers'.

GoNomad chose DCO because it is lower friction for contributors and sufficient
for provenance, and because a self-hosted tool that asks contributors to sign
away relicensing rights has an obvious future its contributors did not sign up
for. This is recorded as a decision in `ARCHITECTURE.md` §24.10 and in the
locked decisions table of `plan.md`.

---

## Pull requests

The repository ships a pull request template and issue forms; fill them in
rather than deleting them — they exist to collect the things a reviewer would
otherwise have to ask for.

- **Small enough to review in one sitting.** The `plan.md` checklists are
  deliberately sized at roughly one pull request each.
- **Describe the *why*** in the body, and link the issue or discussion. If the
  change implements a milestone checklist item, say which one.
- **Note any new dependency** and why it is worth its supply-chain cost.
- **Say what you tested and on what.** "Tested on a Pixel 8 over LTE" is
  meaningful; "works for me" is not.
- **Run the full local check list** above. CI is a backstop, not your first
  test run.
- **Update documentation in the same pull request.** `ARCHITECTURE.md` if a
  decision changed, [`docs/`](./docs/README.md) if behaviour changed, doc
  comments always.

Milestones M1 and M5 require a security review before they are considered
complete, because they are the two that add attack surface (`plan.md`,
definition of done). Expect changes in those areas to be reviewed slowly and
in detail. That is not distrust; it is the product working as designed.

---

## Proposing an architecture change

`ARCHITECTURE.md` is the canonical design document, and several of its
decisions are load-bearing in ways that are not obvious from any single file —
the absence of a pixel path, the absence of bearer tokens, the fat-core rule,
and policy sitting on the only route to services all have consequences spread
across the tree.

So:

1. **Open a discussion first.** Not a pull request that rewrites the document,
   and not a large implementation branch that assumes the change is accepted.
2. **State the trade-off explicitly.** What gets better, what gets worse, and
   what previously impossible thing becomes possible. A proposal that only
   lists advantages has not been thought through.
3. **Say which principle or constraint you are relaxing.** The principles in
   `ARCHITECTURE.md` §1 are written as constraints a reviewer can enforce; if
   your change violates one, that is the conversation to have, and it is a
   legitimate conversation to have.
4. **Check the rejected alternatives first.** §18 and the appendix decision log
   record what was considered and why it lost. Re-raising a rejected option is
   fine when you have information the document did not, and that information is
   the substance of the proposal.
5. **Update `ARCHITECTURE.md` in the same pull request** as the implementation,
   including the appendix decision log. A design document that lags the code is
   worse than no design document, because people trust it.

Small corrections — a typo, a broken cross-reference, a factual error about a
dependency — can go straight to a pull request without ceremony.

---

## Security issues

Do not open a public issue, pull request, or discussion for a suspected
vulnerability. Do not include a proof of concept in a public branch.

Use the private process in [`SECURITY.md`](./SECURITY.md), which is GitHub
Security Advisories. That document also carries the threat model summary, the
explicit out-of-scope statement, and the known limitations, all of which are
worth reading before you decide whether something is a vulnerability or a
documented trade-off.

---

## Licence of contributions

By contributing, you agree that your contribution is licensed under the
[Apache License 2.0](./LICENSE), the same terms as the rest of the project, and
you certify its provenance with your DCO sign-off. There is no separate
agreement, no copyright assignment, and no relicensing clause.
