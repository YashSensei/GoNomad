# CI and local reproduction

Every check that can fail your pull request can be run on your own machine
before you push. This page lists them, what they gate, and the exact command.

Nothing in CI requires a secret. Workflows therefore run identically on forks
and on pull requests from forks.

---

## Getting `cargo` on PATH

On a fresh Windows box `cargo` is often not on the global `PATH` even though
rustup installed it. For the current PowerShell session:

```powershell
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
```

Then, from the repository root:

```powershell
cd C:\path\to\gonomad
cargo --version
```

The toolchain itself is pinned by `rust-toolchain.toml`, so you do not choose a
version — rustup reads that file. To materialise it explicitly (this is exactly
what CI does):

```powershell
rustup toolchain install --no-self-update
```

Passing no toolchain name is deliberate: it makes `rust-toolchain.toml` the
single source of truth, so CI and your machine cannot drift
(`ARCHITECTURE.md` §24.12).

---

## Workflows

| Workflow | File | Triggers | Blocking? |
|---|---|---|---|
| CI | `.github/workflows/ci.yml` | push to `main`, PRs, manual | **Yes** |
| Security | `.github/workflows/security.yml` | push to `main`, PRs, weekly cron (Mon 05:17 UTC), manual | **Yes** |

Both set `permissions: contents: read` at the workflow level. Neither writes to
the repository, comments on pull requests, or publishes artefacts.

Both use a `concurrency` group keyed on workflow + ref. Superseded **pull
request** runs are cancelled; runs on `main` are not, so every commit on the
default branch keeps a real status.

Third-party actions are pinned to full commit SHAs rather than tags, because a
tag can be repointed at new code by anyone who can push to that repository —
precisely the supply-chain failure this project exists to take seriously
(`ARCHITECTURE.md` §3.11). GitHub's own `actions/*` are pinned to a major tag.
Dependabot bumps both, weekly.

---

## CI — what each job gates

Environment applied to every job: `CARGO_TERM_COLOR=always`,
`RUSTFLAGS=-D warnings`, `CARGO_INCREMENTAL=0`, `RUST_BACKTRACE=1`.

`RUSTFLAGS=-D warnings` escalates warnings in *our* crates only; registry
dependencies are compiled with `--cap-lints allow`, so a warning in a
third-party crate cannot fail your build.

Every cargo command that resolves dependencies passes `--locked`. A stale
`Cargo.lock` is a build failure rather than a silent dependency upgrade. If CI
fails with `the lock file needs to be updated`, run `cargo check` locally and
commit the resulting `Cargo.lock`.

### `fmt` — rustfmt · ubuntu-latest

```powershell
cargo fmt --all -- --check
```

Single runner: rustfmt's output does not vary by host OS. To fix, run
`cargo fmt --all` without `-- --check`. (`cargo fmt` takes no `--locked`; it
does not resolve dependencies.)

### `clippy` — windows-latest **and** ubuntu-latest

```powershell
cargo clippy --all-targets --workspace --locked -- -D warnings
```

`--all-targets` covers tests, examples and benches, not just the library.

### `test` — windows-latest **and** ubuntu-latest

```powershell
cargo test --workspace --locked
```

### `docs` — windows-latest **and** ubuntu-latest

```powershell
$env:RUSTDOCFLAGS = "-D warnings"
cargo doc --no-deps --workspace --locked
```

A broken intra-doc link fails the build. Documentation that points at the wrong
type is worse than no documentation, and rustdoc's link resolution is the only
thing that catches it. Run on both hosts because `#[cfg(windows)]` and
`#[cfg(unix)]` items are only compiled — and only link-checked — on their own
platform.

### `ci-success`

An aggregate job that fails unless `fmt`, `clippy`, `test` and `docs` all
succeeded. Point branch protection at this one check rather than at the
individual matrix legs, so adding a leg does not require editing repository
settings. It runs with `if: always()` because a *skipped* required check is
reported as passing by branch protection.

### Why the matrix is Windows-first

`windows-latest` is listed first in every matrix because Windows is the
first-class host (`plan.md`, "Locked decisions"). ConPTY handles, UNC and
`\\?\` paths, `MAX_PATH`, case-insensitive filesystems and CRLF only misbehave
there, and a Windows-only regression that is caught a week later is a week of
bisecting. `ubuntu-latest` runs alongside to keep the codebase portable for the
macOS/Linux hosts scheduled for M6.

`fail-fast: false` on every matrix: a Windows failure must not hide a Linux
failure, and vice versa.

### Caching

`Swatinem/rust-cache` caches `~/.cargo/registry`, `~/.cargo/git` and `target/`,
keyed per-OS (`key: ${{ matrix.os }}`) so a Windows `target/` never restores
over a Linux one. The action also folds the rustc version and the lockfile hash
into the key automatically. `cache-on-failure: true` — a failed build still
produced useful dependency artefacts, and the fix-up push should be fast.

---

## Security — what each job gates

### `cargo-deny` — four checks, reported separately

```powershell
cargo install cargo-deny --locked   # slow; or grab a prebuilt release binary
cargo deny check                    # all four at once
cargo deny check advisories
cargo deny check licenses
cargo deny check bans
cargo deny check sources
```

Configuration and the reasoning behind every rule is in `deny.toml`, which is
heavily commented. In summary:

- **advisories** — RustSec vulnerabilities, plus unmaintained crates at the
  strictest setting (`unmaintained = "all"`, which includes transitive
  dependencies) and yanked crates.
- **licenses** — an allowlist compatible with distributing an Apache-2.0
  binary. There is no separate deny list in modern cargo-deny: the allowlist
  *is* the deny list, so GPL/AGPL/LGPL and other copyleft terms fail by being
  absent. CC0-1.0 and Unlicense are deliberately undecided and currently fail;
  see the note in `deny.toml`.
- **bans** — duplicate versions of a crate are denied, with a reasoned `skip`
  list for the duplicates the ecosystem currently forces (today: the syn 2→3
  migration and the RustCrypto rand/getrandom 0.6→0.9 split). Wildcard version
  requirements are denied. `openssl`, `openssl-sys`, `native-tls` and `git2`
  are banned outright.

  **If a dependency bump makes `bans` fail with a new duplicate, the fix is to
  add a `skip` entry *with a reason*, not to relax `multiple-versions`.**
  cargo-deny reports unused skips, so the list cannot rot silently.
- **sources** — crates.io only. No git dependencies, no alternate registries,
  no org-level trust.

`deny.toml` targets the cargo-deny version baked into the pinned
`EmbarkStudios/cargo-deny-action` SHA. The schema is version-sensitive; bump
the action SHA and the version comment at the top of `deny.toml` together.

### `cargo-audit`

```powershell
cargo install cargo-audit --locked
cargo audit --deny warnings
```

This overlaps with `cargo deny check advisories`, on purpose. cargo-audit is
the RustSec project's own reference implementation and occasionally interprets
a fresh advisory differently. For a tool that holds device keys, two
independent readers of the same database is cheap insurance. `--deny warnings`
escalates unmaintained, unsound and yanked findings to failures — a yanked
crate in the lockfile is a reproducibility bug (`ARCHITECTURE.md` §24.12), not
a note.

CI installs cargo-audit from a prebuilt binary via `taiki-e/install-action`
rather than compiling it, which turns a multi-minute step into a few seconds.

### The weekly cron is the point

New advisories are published against code that has not changed. Without the
schedule, a vulnerability disclosed on Tuesday would sit undetected until
someone happened to push. This means the Security workflow **can go red with no
commits in between** — that is working as intended, not a flaky job.

---

## Blocking vs advisory

**Blocking** — these fail the build and must be fixed before merge:

- `fmt`, `clippy`, `test`, `docs`, `ci-success`
- `cargo-deny` advisories, licenses, bans, sources
- `cargo-audit`

**Advisory** — visible but non-fatal:

- `cargo-deny` emits `license-not-encountered` warnings for entries in the
  `allow` list that nothing currently uses. Several of those entries are
  forward-looking allowances for crates that arrive with later milestones. The
  warnings are expected and do not fail the check.
- Dependabot pull requests are notifications, not gates. Note that Dependabot
  commits are not DCO signed off; a maintainer merging one should squash with a
  signed-off message until a DCO bot is configured.

Nothing is currently "advisory but should be blocking". If a check is worth
running, it is worth failing on — a check that is allowed to be red is a check
nobody reads.

---

## Repository settings this assumes

These are configured in the GitHub UI, not in this repository, and are worth
verifying:

- **Private vulnerability reporting enabled** — `.github/ISSUE_TEMPLATE/config.yml`
  links to `/security/advisories/new`, which 404s if the setting is off.
- **Discussions enabled** — the same file links to `/discussions`.
- **Branch protection on `main`** requiring the `CI success` and
  `Security success` checks.
- **Labels** `bug`, `enhancement` and `dependencies` — the first two ship with
  every new repository; Dependabot creates the third.

---

## Planned — not yet implemented

Everything below is deliberately **absent** from the workflows. Each arrives
with the milestone that makes it real; a job that references a directory which
does not exist yet fails confusingly and teaches people to ignore red marks.

| Planned check | Blocked on | Reference |
|---|---|---|
| Android build + `ktlint` + unit tests | `android/` existing | plan.md M1 |
| Instrumented Android tests on a physical device | A self-hosted runner with a device attached; GitHub's hosted runners cannot do this | ARCHITECTURE.md §24.11 |
| Macrobenchmark — cold start, scroll jank, frame timing | Same device requirement | ARCHITECTURE.md §14.3 |
| `editor/` npm build and typecheck | `editor/` existing (CodeMirror 6 Vite bundle) | plan.md M3 |
| `criterion` benchmarks with budgets enforced as build failures | Benchmarks existing, and a stable baseline to compare against | ARCHITECTURE.md §14.3, plan.md "Performance budgets" |
| Bandwidth harness replaying recorded terminal sessions against byte ceilings | `gonomad-pty` and the VT fixture suite | ARCHITECTURE.md §14.3, §24.11 |
| VT conformance fixture suite | `gonomad-pty` | plan.md M2 |
| `cargo-fuzz` on the frame decoder and VT parser | Fuzz targets existing | plan.md M6 |
| `cargo-vet` for transitive review status | A vetted baseline worth maintaining | ARCHITECTURE.md §3.11 |
| `[bans.build]` executable/build-script scanning in `deny.toml` | A dependency set stable enough for the baseline to mean something | ARCHITECTURE.md §3.11 |
| macOS runner in the CI matrix | macOS host support | plan.md M6 |
| Reproducible-build verification (build twice on separate runners, compare hashes) | Release artefacts existing | ARCHITECTURE.md §24.12 |
| Release workflow — `cosign` signing, SLSA provenance, `apksigner`-verifiable APK | v0.1.0, and signing keys being configured | ARCHITECTURE.md §24.12, plan.md M6 |
| Coverage reporting | A decision on a self-hosted or token-free reporter | — |

Two categories are called out because they will not simply appear when someone
has time:

- **Anything needing a secret** (signing keys, a coverage upload token) is
  absent on purpose. Such jobs fail confusingly on pull requests from forks,
  where secrets are not available. When release signing lands it should be a
  separate, tag-triggered workflow that never runs on a fork PR.
- **Anything needing a physical Android device** requires a self-hosted runner.
  GitHub's hosted runners offer no hardware acceleration for emulators on
  Linux and no attached devices anywhere, and `plan.md` requires smoke tests on
  real hardware over cellular precisely because emulators do not reproduce the
  OEM battery-manager and radio behaviour that matters.
