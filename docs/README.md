# GoNomad documentation

> [!WARNING]
> **GoNomad is pre-alpha.** Nothing described here is usable yet. Documents in
> this directory describe a system that is being built, and each says clearly
> which parts exist. See the [status section of the README](../README.md#status-pre-alpha)
> and the roadmap in [`plan.md`](../plan.md).

---

## Where to start

**If you have never seen this project**, read in this order:

1. [`../README.md`](../README.md) — what GoNomad is, what it deliberately is
   not, why it exists, and its current state. Ten minutes.
2. [`glossary.md`](./glossary.md) — the vocabulary. GoNomad borrows terms from
   terminals, cryptography, NAT traversal, and Android, and the design
   documents assume all of them. Skim it now, return to it as needed.
3. [`../ARCHITECTURE.md`](../ARCHITECTURE.md) §1 and §2 — the product vision
   and the system topology. The rest of that document is reference material;
   these two sections are the argument.

**If you are evaluating whether to trust it** (once there is something to
trust): [`../SECURITY.md`](../SECURITY.md), then
[`threat-model.md`](./threat-model.md), then the "Known limitations" section of
the README. Read the out-of-scope statement before anything else — it is short
and it determines whether GoNomad is the right tool for your situation.

**If you want to contribute**: [`../CONTRIBUTING.md`](../CONTRIBUTING.md), then
[`ci.md`](./ci.md) so you can reproduce every gate locally before you push,
then [`../plan.md`](../plan.md) to find work that is actually unblocked, and
`ARCHITECTURE.md` §17 for where things live.

**If you want to run the daemon**: you cannot yet.
[`deployment.md`](./deployment.md) describes the intended model so it can be
reviewed and argued with before it is built.

---

## What each document is for

| Document | Purpose | Status |
|---|---|---|
| [`glossary.md`](./glossary.md) | Every term the other documents assume: PTY, ConPTY, VT grid, CAS write, capability grant, presence key, SAS, PAKE, ALPN, `NodeId`, relay, hole punching, FST index, L0/L1/L2, DCO | Current |
| [`ci.md`](./ci.md) | Every check that can fail a pull request, what it gates, and the exact command to reproduce it locally | Current |
| [`threat-model.md`](./threat-model.md) | The T1–T10 adversaries with capabilities and defences, the explicit out-of-scope statement, and the trust boundaries — what the relay can see, what a compromised phone can do, what the WebView is trusted with | Design, not implemented |
| [`deployment.md`](./deployment.md) | How the daemon will be installed, configured, and run: `gonomad init`, `~/.gonomad/config.toml`, autostart, the loopback control socket, firewall expectations, and uninstall | Forward-looking; nothing here works yet |

## Documents outside this directory

| Document | Purpose |
|---|---|
| [`../ARCHITECTURE.md`](../ARCHITECTURE.md) | The canonical design document and the *why* behind every decision. Referenced by section number throughout the project; when a document here says "see §3.6", it means a section of this file |
| [`../plan.md`](../plan.md) | The execution roadmap: milestones M0–M6, exit criteria, MVP scope with an explicit exclusion list, performance budgets, and the top risks |
| [`../SECURITY.md`](../SECURITY.md) | Supported versions, the private disclosure process, response expectations, safe harbour, and the known limitations you must understand before trusting the tool |
| [`../CONTRIBUTING.md`](../CONTRIBUTING.md) | Prerequisites, build and lint commands, where lints are configured, the quality bar, testing expectations, commit conventions, and the DCO |
| [`../CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md) | Contributor Covenant 2.1, and how to report a violation |

## Planned but not yet written

`ARCHITECTURE.md` §17 and the M6 checklist in `plan.md` call for several more
documents. They do not exist, and this index does not link to them until they
do:

| Document | Will cover |
|---|---|
| `protocol.md` | Frame layout, the CBOR schema, stream topology, version negotiation, and the error enum — enough to write a third-party client |
| `adapters.md` | Writing an AI agent manifest: the TOML format, detection regexes, approval extraction, and golden transcript tests |

If you write one of these, add it to the table above in the same pull request.

---

## Conventions used in these documents

- **Section references** like "§3.6" always mean a section of
  [`../ARCHITECTURE.md`](../ARCHITECTURE.md) unless another file is named.
- **Milestone references** like "M3" always mean a milestone in
  [`../plan.md`](../plan.md).
- Documents here summarise and cross-link rather than duplicating
  `ARCHITECTURE.md`. Where you want the full argument for a decision, the
  section number is the pointer. Duplicated prose drifts; a reference does not.
- Anything not yet implemented is labelled as such, in the present tense, at
  the point where a reader would otherwise assume it works.
