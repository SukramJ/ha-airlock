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
- **State of the code**: `ha-airlock serve` is the server and what the
  App's container runs: it provisions its own Home Assistant user, serves
  the consent page through Ingress and, behind the owner's HTTPS reverse
  proxy, the OAuth 2.1 authorization server and the MCP endpoint. Every
  tool call passes `internal/gate`. The catalogue holds fifteen read-only
  tools (R0), six control tools (R1) and twenty-four tools that change
  configuration (R2, the eight helper domains only); `docs/tools.md` is generated
  from it. R1 acts only on entities carrying the owner's label and, by
  default, after an approval in the sidebar page (ADR 0005). R2 is off
  until the policy file opens a kind, never runs without an approval, and
  is recorded in the journal of changes first (ADR 0006). The sidebar page
  shows the audit log and the changes, with undo. Not built: the other
  kinds of R2, any tier above R2. Other
  commands: `probe`, `provision`, `audit verify`.

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
The sanctioned test target, named by the owner on 2026-11-13, is the
helper `input_boolean.ha_airlock_test`: it controls no device and carries
the label `airlock`. Switching it is approved; every other write still
needs to be asked for.

---

## Repository Structure

```
ha-airlock/
├── CONCEPT.md  CLAUDE.md  CHANGELOG.md  Makefile
├── config.yaml  Dockerfile  repository.yaml  — the Home Assistant App: Supervisor config, image, App repository
├── cmd/ha-airlock/      — the server (composition root)
├── internal/
│   ├── approval/        — tool calls waiting for an administrator: bound to client, tool and arguments, single use
│   ├── audit/           — the audit log: hash-chained JSON lines, verification
│   ├── build/           — version
│   ├── catalog/         — the static tool catalogue: every tool, its tier, its endpoints
│   ├── changes/         — the journal of configuration changes: the state before and after, kept for undo (ADR 0006)
│   ├── gate/            — the one enforcement point: identity, policy, tool, redaction, audit
│   ├── halt/            — the kill switch: one persistent flag the gate obeys
│   ├── hacore/          — client for Core's WebSocket API (hacoretest: its stand-in for tests)
│   ├── mcpserver/       — the catalogue over MCP; every call goes to the gate
│   ├── oauth/           — the authorization server (ADR 0004) and the consent page
│   ├── policy/          — default-deny decisions per profile and tier
│   ├── probe/           — reachability probe (Supervisor proxy and its identity, Core directly)
│   ├── provision/       — the App's own Core user: creation, credential, access to Core (provisiontest: stand-in Home Assistant)
│   ├── redact/          — removes credentials and locations before anything leaves
│   ├── supervisor/      — what the Supervisor tells the App (Core's address)
│   └── repoguard/       — repository-wide guards (licence header)
├── docs/                — PUBLISHED documentation only
├── notes/               — engineering working docs, NEVER published
└── vendor/              — third-party code, written by `go mod vendor` only, never edited
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

Re-cut by the owner on 2026-11-15, mirrored from go-fabric #529 and
openccu-loom #1108 (in the owner's words: "Wichtig ist, dass die Qualität
hoch ist, aber Fable gezielt für die Dinge eingesetzt wird, die es wirklich
besser kann"). The bar is unchanged: a statement that lands in this repo is
cited later as fact, so it comes from the strongest model. But the strongest
model does only the part that needs it: reading the reference and judging.
The writing, the mechanics and the code review are Opus.

| Work | Model |
| --- | --- |
| **Coordination** of a slice: starting agents, integrating, guards, pull requests, status. Every write to the owner's Home Assistant is the coordinating session's own call, never an agent's ([Writes to the owner's Home Assistant need explicit approval](#writes-to-the-owners-home-assistant-need-explicit-approval)) | **Opus**, in a fresh session per slice (the state is in the notes and the memory, never in a long context) |
| **Planning and decisions:** the slice plan; the decision briefs behind the owner's wizard, with the architecture reasoning ([the architecture standard](#the-architecture-standard)); *which* guard gets built and its bite line; the verdict where Core, the frontend, the Supervisor and ha-mcp contradict each other | **Fable**, as a targeted agent |
| **Reading the reference and judging:** what Home Assistant Core, the frontend or the Supervisor do at the pinned source, and what this repo's own wiring does (who consumes an event, who calls a seam) — for `CONCEPT.md`, an ADR and every comment that names a consumer, a caller or a Home Assistant behaviour; the adversarial read of the `hunt` agent | **Fable** gives the verdict with the lines as a short fact note; **Opus** writes the entry or the comment in the file's form; **Fable** reads the finished text once against its note. Every reference statement comes from Fable |
| **Implementation**, also on the security paths — auth, policy, approval, redaction, audit, the tool catalogue's tier declarations, the composition root; test ports; CHANGELOG and docs; rebases and merge conflicts | **Opus** (the `impl` default; also what fast mode runs on) — with the Fable read of the next row before it merges where it touches a security path or mirrors a reference |
| **Review** of a slice's pull request | **Opus** does the code review — correctness, concurrency, error paths, tests. **Fable** reads on top, bounded: behaviour against Core, the frontend and the Supervisor at the pin, the security paths of the row above, and every finding of high or medium severity for confirmation before it reaches an implementer |
| **Citations** | **Opus** checks every range (the file, the lines, the construct the sentence names). **Fable** reads every citation that is the reason for behaviour ("as Core does", "the frontend sends"), every doubtful one and a sample of the rest |
| Work a test or generator checks immediately: `gofumpt`, table cases on an existing pattern, a version bump, regenerating `docs/tools.md`; search and first reading of a source tree whose result a stronger model reads again | **Sonnet** |
| Mechanical inventories whose answer is a list the caller can re-grep | **Haiku** |

Sonnet never writes a claim about wiring or Home Assistant behaviour into
the repo. Opus does not either: it writes what Fable's fact note states.
Haiku returns lists, never verdicts. When in doubt whether a statement is a
reference fact, it is one.

## Sub-Agent Delegation

The main conversation coordinates: integration, guards, sub-agent steering,
final verification, and push / pull request / tag. Planning, guard
specifications and the reading of Home Assistant's source come from Fable
(the planning and reading rows of
[Which model does which work](#which-model-does-which-work)) and reach the
coordinator as a plan or a fact note.

**Delegate what a gate can prove; keep what only a reader can accept.**
Locating is delegable; reading is not. Never delegate to an agent the
security paths of the table above: those are implemented in the
coordinating session, and the agents' stop conditions under
`.claude/agents/` keep them out. *Which* guard gets built is Fable's.

- No sub-agent runs `make ci` or a repo-wide lint; the full gate runs once,
  in the main conversation, at the end of the slice.
- No two writing agents in the same package.
- Every brief carries: the files and one style reference; the acceptance
  command the agent runs itself; the invariants it touches; **stop
  conditions** (new dependency, a security path, an ADR-shaped decision — a
  stop is a successful outcome); a report format of ≤ 250 words.
- **A report is a claim.** Read the diff, run the gate yourself.

The agent definitions are under `.claude/agents/`: `impl` (Opus,
implementation of a finished plan), `guard` (Opus, tests from a guard
specification, with bite proof), `sweep` (Haiku, read-only inventories)
and `hunt` (Fable, read-only defect hunt). Their stop conditions are the
security paths of the table above.

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
- **The strongest model for the part that needs it.** Set by the owner on
  2026-11-15. Fable reads references, judges and plans (the table above);
  it does not coordinate, format, write prose or run mechanics. A Fable
  agent's brief is bounded: the lines to read, the question to answer, a
  fact note back.
- **Few turns in a long session.** A coordinator waits for several agents
  at once and integrates them together; a status message carries new
  information or is not sent; a slice starts in a fresh session.
- **The assistant says when to clear the context.** Set by the owner on
  2026-11-15. It does not wait to be asked: it proposes a fresh session
  when a slice or a pull request is merged; when the context has been
  summarised once and the work that remains is of another kind; or when
  what it still needs fits in a short hand-over and the turns are mostly
  waiting for agents or pipelines. It does NOT propose one while agents of
  the session are running or a decision of the owner is open. The proposal
  comes with the hand-over already written — the state, the open points
  with where each goes, the next step, the lessons — into the memory file
  and the notes (never only into the chat), and with the exact way to go
  on: `/clear`, the model to switch to (`/model`), and the first message
  to send, which names the files to read.
- **The pipeline's guards before the pull request, not after.** The local
  guard set is `make ci`, which runs what CI's merge path runs
  (`.github/workflows/ci.yml`). A red pipeline costs a round of
  coordinator turns.

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
