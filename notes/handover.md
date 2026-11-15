# Hand-over

The state a fresh session starts from. Rewritten at each hand-over, never
appended to; the history is in git.

## 2026-11-15, evening — ADR 0006 step 2 in progress

**State.** `main` at #39 (the undo of `input_number.ha_airlock_number_test`
measured and recorded in ADR 0006 *Measured*; the helper is gone from the
instance). Work in progress on the pushed branch
**`feature/registry-changes`** — no pull request yet. The App on the
owner's instance is unchanged (`0.8.0-dev`, policy file in
`/addon_configs/816cd011_ha_airlock`: local R0 allow, R1 approval, R2
approval, `helper` change approval).

**The plan** is `notes/adr0006-step2-registries.md`: Fable's fact note
(Core `3f8160ce7ff`, frontend `0d31ae5624e`, every fact with `path:line`),
the slice plan (B.0–B.7) and the owner's decisions of 2026-11-15 at its
top: no `area_delete` (D1; D2/D3 fall away), the undo of `label_create`
only while nothing carries the label (D4), `picture` only `null` or a
local path plus an R0 `floor_list` (D5), declared endpoints enforced in
their own slice right after this one (D6).

**Done on the branch.**

1. Commit `28b4a49` — gate (security path, done in the coordinating
   session): `catalog.Kind.Carrier()` (helper/entity → entity, area →
   area, label → none, the rest undeclared), `Change.Entity` renamed
   `Change.Holder`; the gate releases and labels by carrier
   (`release`, `holds`, `label`, `area` in `internal/gate/gate.go`);
   kind `label`: the control label is never the object, no creation while
   the control label is missing, no undo of what is now the control label
   (`ErrControlLabel`); the label step reads Home Assistant's answer
   (CHANGELOG *Fixed*). Tests `internal/gate/carrier_test.go`; the
   stand-in `home` in `gate_test.go` knows areas, the label registry and
   answers registry updates as Core does. Bite proofs done for all eight
   gate guards and for the carrier guard in `TestEveryToolIsFullyDeclared`
   (script: remove the line, observe red with message, restore).
2. Commit after it — `internal/catalog/registries.go`, **written, builds,
   not wired and not tested**: `registry` (area, label) with `list`,
   `create`, `update`, `planUpdate`, `state` (sets sorted, id and
   timestamps dropped), `unassigned`; `floorList`; `entityUpdate` with
   `entityState`, `areaExists`, `planEntityUpdate`. `registryTools()` is
   **not yet appended in `catalog.All()`**, so `golangci-lint` reports the
   functions as unused (and two `exhaustive` switches on `Carrier`). The
   input schemas were checked to be valid JSON.

**Next steps, in order.**

1. Read `registries.go` once against the plan (B.2) before building on
   it — it was written fast at the end of a session. Known point:
   `exhaustive` wants a `default` in the `Carrier` switches of
   `create()`/`update()`.
2. Append `registryTools()` in `catalog.All()`; catalogue tests per tool
   (B.5: plan from arguments, nothing written before Apply, the exact
   message, refusal of every undeclared key and of `null` where not
   nullable, `Revert` of each, unknown floor/area refused, undo of a
   creation refused while something refers to it, sets hashed
   order-independently); extend
   `TestChangeToolsAreExactlyTheDeclaredOnesAndChangeHelpers`
   (`helpers_test.go:41`).
3. Guards of B.6 with bite proofs, above all: no tool message carries
   `labels`, `new_entity_id`, `disabled_by`, `hidden_by`, and no Plan
   sends `config/label_registry/delete` (only the undo of `label_create`
   does, by D4).
4. Wiring tests through `cmd/ha-airlock` (`serve_test.go:714` is the
   pattern): `area`, `label`, `entity` each parked → approved → written →
   journalled → undone, and each not opened (`kind_denied`); `area` with
   `release: label` against `all`; `entity` unreleased.
5. `go run ./cmd/ha-airlock tools > docs/tools.md`; CHANGELOG *Added*;
   tool counts in `CLAUDE.md` (today 15 R0, 6 R1, 24 R2 → +3 R0
   `area_list`, `label_list`, `floor_list`, +5 R2); ADR 0006 amended for
   D1–D5 and the fact note's A.4; Fable reads the ADR text once against
   the fact note; `make ci`; pull request with auto-merge.
6. Measurement on the owner's instance with objects the owner names, the
   policy file opened for `area`, `label`, `entity`.
7. Then D6: declared endpoints enforced by the gate (own slice).

**Other open points.** ADR 0006 *Unverified*: undo of an update and of a
deletion, and a refused undo, on a running system; the state of an
`input_text` in the password mode is still readable through the
state-reading tools. Not built: the sidebar page showing the policy in
force; `remote` profile redaction; audit log rotation; repair of a torn
audit line; moving the sidebar page out of `internal/oauth`. The owner:
revoke the first token pasted in chat (not confirmed).

**How to work with the instance.** Writes need the owner's approval and a
target the owner names (`CLAUDE.md`). A parked call waits five minutes; the
owner sees messages only after a turn ends, so: park the call, end the
turn, the owner approves and answers, repeat within two minutes. The
tools reach the server through `claude mcp` (`ha-airlock` at
`https://airlock.toonlan.de/mcp`). Reads beside ha-airlock use an admin
token kept outside the repository, on the machine of the earlier sessions
(Core at `172.18.4.22:8123`; the App log through Core's proxy
`/api/hassio/addons/816cd011_ha_airlock/logs`). **On another machine
that token is not there**: the owner provides one, kept outside the
repository.

**Lessons.**

- Check the instance before trusting a reported action: the first "Undo
  pressed" had not reached it; the App log (a refused undo logs `WARN
  undo`) and a registry read told the difference.
- A bite script that replaces a line can leave a variable unused and fail
  to compile; read the output, a "RED" without a test message is not a
  bite.
- In zsh a `$LIST` does not split into words in a `for` loop; use an
  explicit list or an array.
- Check `make ci`'s exit status directly; `gofumpt -w` before the gate.
- Home Assistant stores a validated configuration (defaults, coerced
  numbers, sets without order): compare against what was read back, never
  against what was sent.
