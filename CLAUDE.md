# CLAUDE.md — AI Assistant Guide for ha-airlock

The entry point for AI assistants working on **ha-airlock**. It is
deliberately short: it states each rule once and names the guard that
enforces it, or says "reviewed" where no guard exists yet. Design intent
lives in [`CONCEPT.md`](./CONCEPT.md) until a `SPECIFICATION.md` and ADRs
replace it; implementation detail lives in the code.

The rules below are taken over from
[go-fabric](https://github.com/SukramJ/go-fabric/blob/main/CLAUDE.md) and
[openccu-loom](https://github.com/SukramJ/openccu-loom/blob/main/CLAUDE.md)
on 2026-11-12 and cut to what applies here. This repository is a skeleton:
where a rule names a guard that is not built yet, it says so, and the guard
is built with the first code it protects.

---

## Project Overview

**ha-airlock** is an MCP server that makes Home Assistant — Core, the
Supervisor and the installed Apps — available to an AI assistant, with
transparency and security ahead of feature breadth. It runs as a Home
Assistant App: one container beside Core.

- **Language**: Go 1.27+ · module `github.com/SukramJ/ha-airlock`
- **License**: Apache-2.0; contributions come under [`CLA.md`](./CLA.md).
- **Deployment**: one static binary (`CGO_ENABLED=0`). No CGo.
- **State of the code**: `cmd/ha-airlock` prints its version, runs the
  reachability probe (`ha-airlock probe`, `notes/phase1-probe.md`) and
  verifies an audit log (`ha-airlock audit verify`). The audit log exists as
  a package (`internal/audit`); nothing records into it yet, and nothing of
  the tool chain is implemented.

Every tool call passes one chain, in this order:

```
Auth → Profile → Policy → (Approval) → Execution → Redaction → Audit
```

---

## Commands

`make help` lists everything.

```sh
make build     # go build ./...
make test      # go test -count=1 ./...
make race      # go test -race (needs CGO_ENABLED=1)
make lint      # gofumpt check + golangci-lint + go mod tidy -diff + go mod verify
make fmt       # gofumpt -w .
make vuln      # govulncheck ./...
make ci        # build vet test lint — everything the pipeline's merge path runs
make setup     # install the pinned gofumpt / golangci-lint, plus govulncheck
```

`golangci-lint` is **v2**; a v1 binary rejects this repo's config. The lint
tools are pinned to the same versions in the `Makefile` and in
`.github/workflows/ci.yml` — bump both in one commit, with the findings
fixed in it.

---

## Critical Rules

Non-negotiable. Each is followed by its guard, or by "reviewed".

### Licensing and build

- **License header** on every Go file:
  `// SPDX-License-Identifier: Apache-2.0` + `// Copyright (C) 2026 SukramJ.`
  Guard: `TestLicenseHeaderOnEveryGoFile` (`internal/repoguard`).
- **No CGo.** `CGO_ENABLED=0` at all times; only the race-enabled test run
  turns it on. If you think you need it, raise an ADR.
- **Every dependency is a decision, not a convenience.** The target is the
  Go standard library plus an MCP SDK (`CONCEPT.md` §7) — a small, readable
  dependency set is a security property of this project, not a preference.
  A new direct dependency, and a direct-dependency version bump (dependabot's
  included), gets a `CHANGELOG.md` entry under `### Changed`. MIT /
  Apache-2.0 / BSD are fine; **GPL / LGPL / MPL / AGPL — stop and discuss.**
  Reviewed.
- **No code loaded at run time.** No plugin loading, no self-update that
  fetches code, no `pip`/`npm`-style install on start. Reviewed.

### Security invariants

These are the product. A change that weakens one is not a refactoring.
All are "reviewed" until the code exists; each gets a guard with the code
that implements it.

- **One enforcement point.** Every tool call passes the whole chain above.
  No tool reaches Home Assistant around the policy, and no result leaves
  around redaction and audit.
- **The MCP client is untrusted.** Never rely on the client to confirm,
  refuse or filter. A check that only works when the model cooperates is not
  a check.
- **Static tool catalogue.** Every tool is declared at compile time with its
  risk tier and the Home Assistant endpoints it touches. No dynamic tools,
  no generic pass-through to an arbitrary API path or service.
- **The Never list is not policy-configurable** (`CONCEPT.md` §4): shell or
  code execution, user and token management, `secrets.yaml`,
  `.storage/auth*`, installing Apps from third-party sources.
- **Approval is out-of-band and bound to the arguments.** The approval text
  is rendered by the server from the structured arguments, never from text
  the model supplied; the approval is tied to the hash of the exact
  arguments and expires.
- **Redaction before output, audit for every call** — refusals included.
  The audit log is append-only and hash-chained.
- **Data from Home Assistant is untrusted input** for the model: entity
  names, log lines and notification texts can carry injection payloads.
- **Never log or return a credential.** Tokens, passwords and config-entry
  secrets are redacted at the boundary, and never written to the audit log.

### Home Assistant source is the authority

How Home Assistant behaves is read from its source, not recalled and not
inferred from a response.

| Source | Local path | Role |
| --- | --- | --- |
| [home-assistant/core](https://github.com/home-assistant/core) | `../core/` | WebSocket and REST API, auth, context, registries |
| [home-assistant/frontend](https://github.com/home-assistant/frontend) | `../frontend/` | how the UI calls the API — a caller that works |
| Supervisor | not checked out | App permissions, the Supervisor API. Check it out before deciding anything that rests on it |
| [ha-mcp](https://github.com/homeassistant-ai/ha-mcp) | `../../GitHub-Ext/ha-mcp/` | functional reference for *what* is useful. MIT. Not a gold standard, not a dependency, and its trust model is the one this project rejects |

- **Cite `path:line` and the commit** for every Home Assistant fact that
  enters a comment, the concept, an ADR or a brief.
- **Only documented APIs.** A tool built on an internal that Home Assistant
  may change silently needs an ADR.
- **An existing caller is the specification.** Before composing a WebSocket
  command or a REST call, read how Core's own tests or the frontend send it —
  field names, required keys, auth — and align every parameter at once.

### A verification without a negative control measures nothing

A check meant to *confirm* something is only sound once it produces a
**different** result when the cause is absent. Before reporting something as
verified, state what result the check would have produced had the claim been
false. If you cannot name that result, the finding is **unverified** — say so
in those words. It is a legitimate outcome; a false "verified" is not.

The limit of that rule: **a negative control validates the mechanism, never
the inputs.** When a check needs a value the source does not explicitly
carry — a field's meaning, a unit, an order, an ID mapping — extend the
source until it carries the value, or report the measurement as **not
performable** and name what is missing. Substituting a plausible convention
is guessing.

**Report what is measured separately from what is inferred.** `CONCEPT.md`
§9 is the pattern: source for every claim, everything else labelled
unverified.

### Wiring

A test that constructs the collaboration itself proves only that the
collaboration *can* happen, never that the running server *makes* it happen.

- **Wiring is pinned through the composition root** (`cmd/ha-airlock`),
  never at the setter: a test builds through the real constructor and
  asserts the *effect*. For this project that means above all: a test proves
  that a tool registered the production way cannot be called without the
  policy, the redaction and the audit step running.
- **Declared and enforced must be the same set.** Every tool in the
  catalogue has a policy tier, and every tier the policy knows is exercised
  by a test — an undeclared tool or an unexercised tier is a defect.
- **An event nobody consumes is a dead feature that looks identical to a
  live one.** A comment naming a consumer is a hypothesis; write the check.

### Writes to the owner's Home Assistant need explicit approval

The owner's Home Assistant instance runs real, in-use devices. **Reads are
free. Writes need explicit approval, and the owner names the target** — a
self-chosen "just another switch" can be a device that must not be cycled.
No sanctioned test target is named yet; ask before the first write, and
record the answer here.

---

## Repository Structure

```
ha-airlock/
├── CONCEPT.md  CLAUDE.md  CHANGELOG.md  Makefile
├── config.yaml  Dockerfile  repository.yaml  — the Home Assistant App: Supervisor config, image, App repository
├── cmd/ha-airlock/      — the server (composition root)
├── internal/
│   ├── audit/           — the audit log: hash-chained JSON lines, verification
│   ├── build/           — version
│   ├── probe/           — reachability probe (Supervisor proxy, Core directly)
│   └── repoguard/       — repository-wide guards (licence header)
├── docs/                — PUBLISHED documentation only
└── notes/               — engineering working docs, NEVER published
```

**`docs/` vs `notes/` is a hard boundary.** `docs/` is for whoever installs
or evaluates the server, every behavioural claim checkable against the code;
ADRs go under `docs/adr/`. Briefs, audits and test plans go under `notes/`.
Repository documents are English.

---

## Code Quality & Standards

- **Formatting**: `gofumpt`; `goimports` grouping stdlib → third-party →
  this module.
- **Context**: `ctx context.Context` first on every I/O method; never ignore
  `ctx.Done()`.
- **Errors**: wrap with `fmt.Errorf("…: %w", err)`; match with `errors.Is` /
  `errors.As`. No bare `panic` outside `main()` and test helpers.
- **Concurrency**: every goroutine has a documented lifecycle and a way to
  stop. No package-level mutable state.
- **`any` needs a justifying comment** (usually "wire-decoded JSON before
  type-dispatch").
- **Logging**: `log/slog`, through the component's logger — never
  `slog.Default().<method>` inline.
- **Comments** offer durable value to a future reader — the *why*, not the
  task that requested the change. No phase tags, audit IDs or date stamps in
  `//` comments. Markdown is where that metadata belongs.

---

## Testing

- **Test names describe what is tested**, never a coverage push or a phase.
- **Bug fixing is test-first** — failing reproducer, then fix, then verify.
- **Behaviour-governing config needs one end-to-end test per value**, driven
  through the real path the value governs. For this project: every policy
  decision (allow, deny, approval) per tier.
- **A guard is accepted by its bite proof**, not by a green run: the named
  production line removed, the test observed red with its message, the line
  restored, green again.
- **Never cite your own unverified wiring.** When a slice depends on an
  earlier slice's seam, its first test crosses that seam.

---

## Git Workflow

- `main` is protected. Branches: `feature/<desc>`, `fix/<desc>`,
  `claude/<desc>`.
- Conventional commits, scopes along package boundaries.
- Every PR passes `make ci`; `make race` before a release.
- Commits are signed off (`git commit -s`).
- User-visible changes get a `CHANGELOG.md` entry under `[Unreleased]`.
- Never push `--force` to `main`.
- **Push, pull request and tag are the session's own calls.** An
  implementing agent works locally and reports; the owner's session reads
  the diff, runs the gate, pushes and opens the pull request; the owner
  merges.

---

## The architecture standard

Set by the owner for the go-fabric family on 2026-10-20 (in the owner's
words: "hervorragende Architektur, zukunftsweisend, innovativ,
herausragend"). Taken over here on 2026-11-12.

- **Outstanding, not adequate.** Every layer is the best design we can
  state, coherent with the others: one shape, no convenience seam.
- **Forward-looking and innovative.** A decision is weighed against where
  Home Assistant and MCP are going, not only against today's need.
- **Better than others, better than before, the right cut.** Every concept
  and architectural ADR carries an explicit section answering three
  questions: better than the comparison targets? better than the state
  before? is the split right? A concept without that section is not
  finished. (`CONCEPT.md` §8.)
- **The check is stated, not assumed.** A recommendation says whether it is
  the best architecture and why. When the owner's choice is not the best
  architecture in the assistant's judgement, the assistant says so with its
  reasons before implementing; the owner decides, the reasons are on record.
  A scope boundary that is a decision (no CGo, the Never list, Supervisor
  required) is kept unless the owner reopens it.
- **Questions to the owner are a wizard, never a list.** Every open decision
  is put one step at a time (`AskUserQuestion`, the independent ones in one
  call): the options, the recommendation first and marked as such, and in
  one or two sentences why. A report never ends with a bare list of
  questions.

---

## Which model does which work

A statement that lands in this repo is cited later as fact, so the work that
produces such statements gets the strongest model, and the work a guard
checks may use a cheaper one.

| Work | Model |
| --- | --- |
| Analysis, planning, audits; anything written into `CONCEPT.md`, an ADR or a comment that names a consumer, a caller or a Home Assistant behaviour; *which* guard gets built and its bite line; the security paths — auth, policy, approval, redaction, audit, the tool catalogue's tier declarations, the composition root; every write to the owner's Home Assistant | **Fable** (the default for this repo) |
| Implementation of a finished plan with guards behind it: a further read tool once the pattern exists, a CHANGELOG entry for a finished diff | **Opus** |
| Review of a pull request, split: the code review — correctness, concurrency, error paths, tests — is **Opus**; on top **Fable** reads every new Home Assistant citation against the source and every line touching the security paths of the first row | **Opus**, then **Fable** |
| Work a test or generator checks immediately: `gofumpt`, table cases on an existing pattern, a version bump; search and first reading of a source tree whose result a stronger model reads again | **Sonnet** |
| Mechanical inventories whose answer is a list the caller can re-grep | **Haiku** |

Sonnet never writes a claim about wiring or Home Assistant behaviour into
the repo and never touches the security paths. Haiku returns lists, never
verdicts. When in doubt about which row a task is in, it is in the first.

## Sub-Agent Delegation

**Delegate what a gate can prove; keep what only a reader can accept.**
Locating is delegable; reading is not. Never delegate the security paths of
the table above, or *which* guard gets built.

- No sub-agent runs `make ci` or a repo-wide lint; the full gate runs once,
  in the main conversation, at the end of the slice.
- No two writing agents in the same package.
- Every brief carries: the files and one style reference; the acceptance
  command the agent runs itself; the invariants it touches; **stop
  conditions** (new dependency, a security path, an ADR-shaped decision — a
  stop is a successful outcome); a report format of ≤ 250 words.
- **A report is a claim.** Read the diff, run the gate yourself.

No agent definitions exist under `.claude/agents/` yet; port openccu-loom's
(`impl`, `guard`, `sweep`, `hunt`) with the first implementation slice.

## Token use

Set by the owner on 2026-10-14 ("Wichtig ist mir eine effiziente Nutzung der
Token"), taken over from go-fabric.

- **Read slices, not files.** `sed -n a,bp`, `grep -n` with a tight pattern;
  a whole file only when the task is the file. Never re-read what is already
  in context.
- **Delegate first reads.** A source tree's inventory (Core, the frontend,
  the Supervisor, ha-mcp) is a cheap read with `file:line` for every fact;
  every load-bearing fact is verified before it enters the repo — the
  agent's result is a map, never a citation.
- **Logs by their summary.** Open a log only on failure, with `grep` for
  `FAIL`, `DATA RACE`, `_test.go:` — never `cat`.
- **One turn, every independent call.**
- **Short artefacts.** Status messages to the owner are short, outcome
  first, in German.
- **Skip what cannot have changed** — and say what was skipped and why.
- **Edit by script** when several replacements hit several files; a
  generated file is regenerated, never patched.

## Interaction Protocol

1. **Describe the approach before coding** — files, approach, trade-offs;
   wait for approval. Trivial edits may proceed directly.
2. **Clarify ambiguous requirements** — as a wizard, before guessing.
3. **Suggest edge cases and tests after implementation.**
4. **Learn from corrections** — find the root cause.

---

## Implementation Policy

Completion checklist per change:

- [ ] `make ci` passes.
- [ ] Tests updated; a new guard has its bite proof.
- [ ] `CHANGELOG.md` entry for user-visible changes.
- [ ] `CONCEPT.md` (later `SPECIFICATION.md`) updated if a goal, a non-goal
      or a decision moved; ADR written for any architectural shift.
- [ ] Every Home Assistant fact cited with `path:line` and commit.
- [ ] No CGo, no copyleft dependency, licence header on every new `.go` file.
- [ ] No security invariant weakened — or the change says which, and why.
