# GoNomad — Development Plan

> **Your development machine, anywhere.**
> An open-source, self-hosted mobile companion for your own dev machine. Not a desktop stream — a purpose-built touch interface over the filesystem, terminals, git, and AI agents already on your laptop.

**Current status:** 🚧 Pre-alpha · **M1 substantially complete, M2 partially built** · runnable end to end on one machine
**Built so far:** all eight crates. `gonomad-proto` (wire contract + codec), `gonomad-core` (device identity, three domain-separated subkeys, pairing, SAS), `gonomad-store` (schema, migrations, hash-chained audit), `gonomad-policy` (capabilities, path guards, rate limits), `gonomad-transport` (**iroh** hole-punched QUIC + relay, LAN TCP, Noise IK/IKpsk2 inside both), `gonomad-pty` (ConPTY, job objects, `vt100` screen authority), `gonomad-server` (`gonomad` daemon + CLI), `gonomad-ffi` (UniFFI → Kotlin). Android app builds to a signed APK with multi-tab terminals that keep running while backgrounded. 674 tests, clippy pedantic clean, `cargo deny` clean.
**Verified working:** `init`, `pair` (QR + SAS), `serve`, pairing from a real phone, terminal spawn/input/resize/kill, terminals surviving disconnect and reattaching on reconnect.
**Not yet verified:** NAT traversal through real home routers and the CGNAT relay fallback — both need two genuinely separate networks and cannot be proven from one machine.
**Next action:** confirm off-network pairing from a phone on mobile data, then M2's remaining terminal work (cell diffs, adaptive frame rate, Compose Canvas renderer)
**Canonical design:** [`ARCHITECTURE.md`](./ARCHITECTURE.md) — this file is the execution roadmap; that file is the *why*

> [!NOTE]
> M0's spikes were partially superseded: the ConPTY and Compose-Canvas spikes are still outstanding and gate M2, but the workspace scaffold and shared-type contract were built first because every other crate depends on them.

---

## Locked decisions

| Axis | Decision | Rationale |
|---|---|---|
| Host OS | **Windows first**, macOS/Linux at M6 | Primary dev machine. ConPTY, `ReadDirectoryChangesW`, PowerShell + WSL |
| Phone | **Android only**, Kotlin + Jetpack Compose | No store review, sideloadable APK, StrongBox keys, no iOS background-socket kill |
| Core | **Rust**, shared with the phone via UniFFI | One protocol impl, one crypto impl, one static binary |
| Transport | **iroh** (QUIC + NAT hole punch + self-hostable relay) | No port forwarding, no cloud account, survives Wi-Fi↔LTE handoff |
| Auth | **Device keypairs, zero bearer tokens** | Deletes token theft/rotation/replay/expiry as problem classes |
| Terminal | **Server-side VT emulator**, phone gets cell diffs | Bounded bandwidth, snapshot reconnect, dumb fast client |
| File sync | **Authoritative FS + compare-and-swap writes** | No CRDT — VS Code, git, and AI agents will never speak our protocol |
| Licence | **Apache-2.0** + DCO | Patent grant matters for a security tool |

**The hard rule:** if logic *can* live in Rust `gonomad-core`, it *must*. Kotlin is views and thin ViewModels only. This is what makes a future iOS/desktop client a view-layer port instead of a rewrite — see `ARCHITECTURE.md` §6.2.

---

## Milestones

Sequenced so **risk is retired before investment**. A milestone is done when its exit criterion is *demonstrated*, not when its features exist.

### M0 — De-risking spikes · ~1–2 weeks

Four throwaway spikes, in parallel. **If (1) or (2) fails, the architecture changes here — that is the entire point.**

- [ ] **Terminal renderer spike** — Compose `Canvas` + glyph atlas, 80×24 grid, synthetic diffs at 60 fps on a physical device
  - *Exit: sustained 60 fps, no jank in Macrobenchmark. Fallback if it fails: `AndroidView` text renderer at reduced fps*
- [ ] **iroh round-trip spike** — phone dials laptop by `NodeId` over mobile data, through CGNAT; measure direct vs relay RTT
  - *Exit: a connection from LTE with zero router configuration*
- [ ] **UniFFI round-trip spike** — a Rust struct, an async method, and a callback interface consumed as a Kotlin `Flow`
  - *Exit: a `Flow` emits from a Rust task; `cargo-ndk` → Gradle build works end to end*
- [ ] **ConPTY spike** — spawn `pwsh`, run `vim` and `htop`, resize, kill the tree via a Job Object
  - *Exit: no orphaned processes, no display corruption on resize*

### M1 — Transport, pairing, security foundation · ~3–4 weeks

The security foundation is built first because retrofitting it is not possible.

- [ ] Cargo workspace scaffold per `ARCHITECTURE.md` §17; `deny.toml`; CI skeleton
- [ ] `gonomad-proto` — frame layout, CBOR codec, version negotiation, closed error enum
- [ ] `gonomad-core` — Noise IK session (`snow`), correlation router, observable state
- [ ] `gonomad-transport` — iroh endpoint, mDNS LAN discovery, the tier ladder, `Transport` trait
- [ ] `gonomad-store` — SQLite schema, forward-only migrations, **hash-chained audit log**
- [ ] `gonomad-policy` — capability grants, path canonicalisation + guards, rate limits, presence gating
- [ ] Pairing — 120s single-use QR, transcript-derived 6-digit SAS, SPAKE2+/CPace manual fallback
- [ ] Android — Keystore identity key + **StrongBox P-256 presence key**, pairing screen, devices screen
- [ ] `gonomad` CLI — `init`, `start`, `pair`, `devices`, `status`, `doctor`, `audit`, `workspace`
- [ ] Tray UI — connection state, pairing dialog, approval prompt, **kill switch**
- [ ] Recovery phrase at `init` (24 words, shown once)
- [ ] Property tests: adversarial paths (`..`, symlinks, UNC, 8.3, ADS, null bytes, unicode) never escape a root

- [ ] **Register a device only after an authenticated application exchange**, never on handshake completion (`ARCHITECTURE.md` §19 R24) — with `IKpsk2` the daemon completes its side even when the phone's PSK is wrong

**Exit:** pair a phone over LTE · `sys.info` round-trips · an unpaired key is rejected pre-handshake · revocation effective on the next packet · `gonomad audit verify` passes · **an external port scan of the host finds nothing** · **a wrong pairing code registers nothing on the daemon**

### M2 — Terminal · ~3–4 weeks

- [ ] `gonomad-pty` — `portable-pty`, ConPTY flags (`RESIZE_QUIRK`, `WIN32_INPUT_MODE`, `PASSTHROUGH_MODE` where available), Job Objects, shell detection (pwsh → PowerShell → WSL → cmd), forced UTF-8
- [ ] Headless VT — `alacritty_terminal` grid + capped scrollback ring, spilled to disk, paged on demand
- [ ] Run-based diff computation, adaptive frame rate (60/30/10/0 fps), full-grid switch above 60% dirty
- [ ] Per-PTY QUIC streams; zstd with a terminal-tuned dictionary; 16 ms input coalescing
- [ ] Compose `Canvas` renderer + glyph atlas; virtualised scrollback
- [ ] Tabs (pill row + full-screen switcher with live thumbnails)
- [ ] **Accessory keyboard row** with sticky `Ctrl`/`Alt`, control keys, function keys, user macros
- [ ] Gestures — two-finger scroll, horizontal swipe = shell history, pinch = font size, long-press selection
- [ ] **Tappable `file:line`** linkification (Rust, Python, TS, Go, ESLint patterns)
- [ ] Output folding with summaries
- [ ] TalkBack semantics for the grid — **designed now, not retrofitted**
- [ ] Foreground service + battery-optimisation exemption + per-OEM guidance (`ARCHITECTURE.md` §24.2)
- [ ] VT conformance fixture suite (`vim`, `htop`, `fzf`, `tmux`, `less`, progress bars, resize)

**Exit:** 4 concurrent PTYs · `vim`/`htop` render correctly · keystroke→echo < 50 ms on LAN · a `yes` loop stays under 5 KB/s · scrollback survives an app kill · rotate-and-resize does not corrupt the grid

### M3 — Files, editor, search · ~4–5 weeks

- [ ] `gonomad-fs` — lazy per-level listing via `ignore`, **one recursive watcher per root**, gitignore filtering *before* emit, 50–100 ms debounce, graceful degradation to polling
- [ ] **CAS writes** — `fs.write(path, base_hash, edits[])`, atomic temp+rename, 3-way merge on conflict
- [ ] `gonomad-search` — streaming `grep-searcher` with caps/deadline/cancel; **FST path index** built lazily, persisted, watcher-updated
- [ ] `editor/` — CodeMirror 6 Vite bundle → `assets/editor/`, network blocked in the WebView, typed JSON bridge
- [ ] Editor screen — **trackpad strip**, accessory row, auto-save debounce, symbol outline sheet, 5 MB read-only threshold
- [ ] File tree — `LazyColumn`, git status rail, gitignore/hidden toggles, long-press sheet, sticky breadcrumb
- [ ] Search & replace — chips for regex/case/word, grouped streaming results, **replace defaults to `dry_run`** with a hold-to-confirm preview
- [ ] Conflict screen (view-and-choose-per-hunk)
- [ ] Offline write queue in Room, visible and inspectable
- [ ] Hybrid highlighting — CM6 client-side < 200 KB, tree-sitter server-side above
- [ ] OneDrive/synced-folder detection + warning (`ARCHITECTURE.md` §24.13)

- [ ] **Close the hard-link escape** (`ARCHITECTURE.md` §19 R19) — compare the opened handle's volume + file index against the roots' volumes, and supply `FileIdentity` to `ResolvedPath::confirm_identity` so the TOCTOU window (R21) actually closes

**Exit:** open a 5 MB file without jank · edit and save via CAS · a concurrent external edit yields a *conflict*, never a clobber · search a 500k-file repo with first results < 500 ms · **a `cargo build` produces zero protocol frames from `target/`** · **a hard link to `~/.ssh/id_rsa` inside a workspace root is refused**

### M4 — Git · ~2–3 weeks

- [ ] `gonomad-git` — **`gix` for reads, the `git` CLI for mutations** (`ARCHITECTURE.md` §18.1)
- [ ] Status, stage/unstage (swipe gestures), diff
- [ ] Commit — subject/body split, amend, sign-off, **signing indicator**, hook output surfaced on failure
- [ ] Push/pull/fetch with streaming progress and credential-helper passthrough
- [ ] Branches (checkout with dirty-tree stash offer), history with graph rail, stash, conflict listing
- [ ] Diff viewer — unified, word-level intra-line highlighting, per-hunk staging, side-by-side in landscape only
- [ ] `git:dangerous` capability gate + presence signature for force-push / hard reset / history rewrite

**Exit:** a commit made from the phone is **GPG-signed and runs `pre-commit`**, byte-identical in provenance to a laptop commit · push over SSH works through the agent · the diff viewer is readable one-handed

### M5 — AI agents & notifications · ~3–4 weeks

- [ ] `gonomad-agents` — registry, TOML manifest loader with regex size limits, L0/L1/L2 auto-detection
- [ ] Ship manifests: `claude-code`, `codex`, `gemini`, `opencode`, `aider`, `generic`
- [ ] **Claude Code at L2** (streaming JSON, not screen scraping)
- [ ] Uniform `AgentSession` model — no vendor names in any protocol type
- [ ] Lifecycle — reattach (process alive) vs resume (relaunch with `resume_args`), presented as one affordance
- [ ] Approval extraction + **destructiveness classification**
- [ ] **Approval sheet** — the *actual diff*, never the agent's summary; equally weighted Approve/Deny; biometric for destructive; **no auto-approve, ever**
- [ ] `gonomad-notify` — ntfy backend with **opaque ChaCha20-Poly1305 payloads**, local backend, backend health visible
- [ ] Notification inbox with deep links; AI sessions list + detail (native transcript, not a raw grid)
- [ ] Golden transcript tests per manifest

**Exit:** start Claude Code from the phone → background the app → receive an approval notification → open it → **read the real diff** → approve with a fingerprint → see the audit entry. All six adapters at least L0. Killing the app loses no session.

### M6 — Hardening, platforms, release · ~4–5 weeks

- [ ] macOS + Linux hosts — Unix PTY path, FSEvents/inotify, Keychain/Secret Service backends
- [ ] CI performance budgets enforced as build failures (`ARCHITECTURE.md` §14.1)
- [ ] `cargo-fuzz` on the frame decoder and VT parser
- [ ] Full security review against the §3.1 threat model; external audit if funded
- [ ] Accessibility pass; `armeabi-v7a` + `x86_64` ABIs
- [ ] **Reproducible builds** verified in CI (build twice, compare hashes); `cosign` signing + SLSA provenance; `apksigner`-verifiable APK
- [ ] Docs — `docs/protocol.md` and `docs/adapters.md` (the only two still unwritten), plus a published PGP key for `SECURITY.md`
      <br>*(`README`, `CONTRIBUTING`, `CODE_OF_CONDUCT`, `SECURITY`, `docs/{README,deployment,threat-model,glossary,ci}.md` already landed)*
- [ ] `gonomad uninstall` — complete, and documented before anyone asks
- [ ] **v0.1.0**

**Exit:** every §14.1 budget green in CI · every threat-model row has a documented mitigation · a fresh user pairs and commits within **5 minutes** of `gonomad init` on all three hosts · builds verify reproducibly

---

**Total to v0.1.0: ~20–26 weeks** of focused work, assuming one primary developer and no rework from M0 failures.

---

## MVP scope

The MVP is **M1–M5**, with scope cut hard *inside* those milestones. The exclusion list below exists so scope creep has to argue against a written line.

### In

Pairing · device management · revocation · capability grants · hash-chained audit · iroh LAN→direct→relay ladder with a visible status chip · up to 4 terminals (ConPTY) · accessory bar · tabs · scrollback · `file:line` links · file tree · editor (**one tab**) · CAS save · undo/redo · go-to-line · content search · fuzzy file open · replace with dry-run · git status/stage/commit/push/pull/branch-switch/diff · adapter framework with all six manifests at L0 · **Claude Code at L2** with approval cards · ntfy notifications · in-app inbox · reconnect · offline cache reads · offline write queue · **Windows host only** · **`arm64-v8a` only** · **one workspace root**

### Explicitly NOT in the MVP

Multiple editor tabs · multi-workspace switching · LSP/diagnostics · plugin system · voice · iOS · iPad · desktop client · Docker or Kubernetes panels · SSH-to-remote-server · PR review · CI/CD monitoring · Wear OS · WebSocket fallback transport · Tailscale/Cloudflare Tier 3 · macOS/Linux hosts · conflict *editing* (view-and-choose only) · upload/download UI (API only) · themes beyond light/dark · terminal colour customisation · remote debugging · local LLM management · rebase/cherry-pick/interactive git · blame · stash UI (API only) · agent transcript search

### MVP success criteria

1. A developer pairs a phone and makes a **real commit from a train**, on cellular, with no router configuration.
2. An AI agent's approval arrives as a notification and is safely approved from a lock-screen unlock.
3. A dropped connection loses **no work and no session**.
4. All latency budgets met on a mid-range device over LTE.
5. An external security reviewer finds **no pre-authentication surface**.

---

## Definition of done, per milestone

Every milestone requires all of:

- [ ] Unit tests for new logic; property tests for anything parsing untrusted input
- [ ] Docs updated — `ARCHITECTURE.md` if a decision changed, `docs/` if behaviour did
- [ ] Performance budgets met (§14.1) and green in CI
- [ ] `cargo deny check` + `cargo audit` clean
- [ ] `clippy -D warnings` + `rustfmt` + `ktlint` clean
- [ ] Manual smoke test on a **physical** Android device over **cellular**, not just Wi-Fi or an emulator
- [ ] **Security review required for M1 and M5** — the two milestones that add attack surface

Additionally, every PR should be small enough to review in one sitting. The checklist items above are sized to be roughly one PR each.

---

## Performance budgets

Enforced in CI. A regression is a build failure, not a ticket — without enforcement these decay into aspirations within a quarter.

| Path | Target | Ceiling |
|---|---|---|
| Keystroke → echo (LAN) | 20 ms | 50 ms |
| Keystroke → echo (relay, 60 ms RTT) | 80 ms | 150 ms |
| Editor keystroke → glyph (local buffer) | 8 ms | 16 ms |
| Cold open → last session visible | 400 ms | 1 s |
| File open (< 100 KB) | 80 ms | 250 ms |
| Directory expand (cached) | 16 ms | 50 ms |
| Search first result | 150 ms | 500 ms |
| Reconnect after network change | 300 ms | 1.5 s |

| Resource | Target |
|---|---|
| Daemon idle memory / CPU | < 25 MB · < 0.1% |
| Daemon per PTY (10k scrollback) | < 2 MB |
| Phone memory | < 150 MB |
| Phone battery — active / idle-connected | < 4%/h · < 1%/h |
| Bandwidth — active terminal / idle | < 5 KB/s · < 100 B/s |

---

## Top risks

Full table in `ARCHITECTURE.md` §19. The ones that will actually bite:

| Risk | Mitigation |
|---|---|
| **Push notifications structurally conflict with "no cloud account."** Android will not keep a socket alive indefinitely, and FCM needs a Google project. | A three-tier ladder with **always-encrypted opaque payloads**, documented in the README as a product limitation rather than discovered by users. Metadata leakage (that *a* notification happened, when, roughly how big) cannot be hidden and is stated plainly. §24.1 |
| **OEM battery killers** (Xiaomi, Samsung, OnePlus, Huawei) will silently drop connections and the reports will be unreproducible on a Pixel. | Foreground service, exemption prompt, per-OEM in-app guidance keyed on `Build.MANUFACTURER`, kill detection. Engineered in M2, not patched later. §24.2 |
| **Scope is enormous.** | The written not-in-MVP list above. |
| **Prompt-injected agent gets a destructive action approved** on a small screen by a habituated tap. | True-diff rendering (never the agent's summary), destructiveness classification, biometric over the diff digest, no auto-approve ever. §7.5 |
| **Stolen unlocked phone → workstation compromise** via `~/.ssh/id_ed25519`. | Secret denylist, capability scoping, workspace roots, hardware presence key, instant remote revoke. §3.6 |
| **Adapter regexes are fragile**; vendors change output. | Prefer L2 structured protocols; L0 always works; golden transcript tests fail CI; manifests are user-editable so a break is user-fixable. |
| **Secrets leak via terminal output** (`env`, `cat .env`) into scrollback and disk. | Best-effort redaction with audited tap-to-reveal, scrollback hygiene that actually deletes the on-disk buffer, never cached to the phone. Documented as best-effort. §24.5 |
| **Compose Canvas terminal is real graphics work.** | M0 spike before committing; documented fallback. |
| **iroh is young** (1.0, June 2026). | Abstracted behind the `Transport` trait; Tier 3 fallbacks exist; wire stability guaranteed at 1.0. |

---

## Post-MVP

Ordered by value-to-effort, not by excitement. Detail in `ARCHITECTURE.md` §22.

**v0.2–v0.4** — macOS/Linux hosts (unblocks contributors) · multiple editor tabs · multi-workspace · multiple laptops · conflict editing · interactive git (rebase, cherry-pick, blame) · **LSP proxy for real diagnostics** (largest single editor quality jump, and the reason the editor is CM6) · upload/download UI · camera-to-repo · WebSocket + Tier 3 transports

**v0.5–v0.8** — **WASM plugin system** (Component Model, sandboxed, explicit capability grants — WASM so a plugin cannot escalate past the policy layer) · Docker panel · local LLM management · AI review mode · PR review · CI/CD monitoring · project dashboards · **voice** (highest value precisely when a phone is the only device) · iOS/iPad via a SwiftUI view layer over the same Rust core · Wear OS approvals

**v1.0+** — Compose Desktop client · SSH-to-remote through the daemon · Kubernetes panel · remote debugging (DAP proxy) · collaborative sessions (the point at which a CRDT finally earns its cost — for the **editor buffer only**, never the filesystem)

---

## Getting started (once M1 lands)

```bash
cargo install gonomad          # or download a signed release
gonomad init                   # generate identity, print recovery phrase
gonomad workspace add .        # declare a project root
gonomad pair                   # 120s QR — scan it, confirm the 6 digits
```

No account. No port forwarding. No reverse proxy. No DNS. No certificates.
