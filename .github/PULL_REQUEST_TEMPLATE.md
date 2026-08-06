<!--
Thanks for contributing to GoNomad.

Keep PRs small enough to review in one sitting (plan.md). The checklist items
in plan.md's "Definition of done" are each sized to be roughly one PR.

Delete sections that genuinely do not apply — but do not delete the security
section without reading it first.
-->

## What and why

<!-- One paragraph. What changes, and what problem it solves. Link the issue:
     "Closes #123". If there is no issue and this is more than a typo fix,
     say why the change is wanted. -->

## How

<!-- The approach, and anything a reviewer would otherwise have to reverse
     engineer from the diff. If you rejected an obvious alternative, say so
     here — that is usually the most useful paragraph in the description. -->

## Milestone

<!-- Which plan.md milestone this belongs to (M1–M6, or post-MVP), and which
     checklist item under it, if any. -->

---

## Definition of done

Mirrors `plan.md`. Tick what applies; strike through with an explanation what
genuinely does not.

- [ ] **Tests** — unit tests for new logic. Anything that parses untrusted
      input (protocol frames, VT sequences, paths, agent output) has property
      tests, not just examples.
- [ ] **Docs** — `ARCHITECTURE.md` updated if a *decision* changed; `docs/`
      updated if *behaviour* changed; rustdoc on new public items.
- [ ] `cargo fmt --all -- --check` clean.
- [ ] `cargo clippy --all-targets --workspace --locked -- -D warnings` clean.
- [ ] `cargo test --workspace --locked` passes **on Windows** — the first-class
      host, and where ConPTY and path handling actually differ.
- [ ] `cargo doc --no-deps --workspace` clean with `RUSTDOCFLAGS=-D warnings`
      (catches broken intra-doc links).
- [ ] `cargo deny check` and `cargo audit` clean if dependencies changed.
- [ ] `Cargo.lock` committed if dependencies changed. CI builds with
      `--locked`, so a stale lockfile is a build failure, by design
      (`ARCHITECTURE.md` §24.12).

See `docs/ci.md` for how to run every one of these locally.

## Dependencies

- [ ] No new dependencies — **or** each new one is named below with why it is
      worth its supply-chain cost, its licence, and why a smaller alternative
      or a hand-rolled version was rejected.

<!-- ARCHITECTURE.md §3.11: "a deliberately small dependency set with every
     addition justified in review". This is that review. -->

## Security

- [ ] This change does not touch authentication, capability grants, path
      guards, the audit log, pairing, crypto, or the policy layer.

If it does, **do not tick the box above** and fill in:

- **Threat-model row affected** (`ARCHITECTURE.md` §3.1):
- **What the mitigation was before, and what it is now:**
- **New attack surface introduced, if any:**
- **Why this does not weaken an existing invariant** — in particular: nothing
  reachable pre-authentication, no capability grantable without an explicit
  user action, no path escaping a workspace root, no break in the audit hash
  chain:

<!-- plan.md requires a security review for M1 and M5 specifically. If this PR
     lands in either, request one explicitly rather than assuming. -->

## Conventions

- [ ] **Lints are declared in `Cargo.toml`'s `[lints]` table**, not as
      `#![deny(...)]` / `#![warn(...)]` inner attributes in `lib.rs`. The table
      is workspace-inheritable, visible to `cargo metadata`, and cannot drift
      per-crate; inner attributes are invisible to tooling and silently
      diverge. If you added one to `lib.rs`, move it.
- [ ] Logic that *can* live in Rust *does* live in Rust. Kotlin is views and
      thin ViewModels only (`plan.md`, "The hard rule").
- [ ] No vendor names in protocol types (`ARCHITECTURE.md` §19 / M5).
- [ ] Public items have rustdoc; anything non-obvious says *why*, not *what*.

## Sign-off

- [ ] Commits are DCO signed off (`git commit -s`), per `plan.md`'s
      Apache-2.0 + DCO decision. Amend with
      `git commit --amend -s --no-edit`, or for a series:
      `git rebase --signoff main`.

<!-- The patent grant in Apache-2.0 is a deliberate choice for a security tool,
     and DCO is what makes the provenance of each commit checkable. -->
