# Hand-over

The state a fresh session starts from. Rewritten at each hand-over, never
appended to; the history is in git.

## 2026-11-15, night — ADR 0006 step 2 built, pull request open

**State.** `main` at #39. Branch **`feature/registry-changes`**: the
registry tools are wired (`catalog.All()`), tested and documented — steps
1–5 of the earlier plan are done; the pull request is open with
auto-merge. The App on the owner's instance is unchanged (`0.8.0-dev`,
policy file in `/addon_configs/816cd011_ha_airlock`: local R0 allow, R1
approval, R2 approval, `helper` change approval). Catalogue: 18 R0, 6 R1,
29 R2.

**Done.** `registries.go` read against B.2 (fixed: `default` in the
`Carrier` switches; label creation declares `config/area_registry/list`
for its undo; the undo of `area_update` / `entity_update` checks again
that the floor / area exists). Catalogue tests
`internal/catalog/registries_test.go`, wiring tests
`cmd/ha-airlock/registries_test.go` (each kind parked → approved →
written → journalled → undone, `area_create` labelled by the gate; each
kind `kind_denied`; unlabelled area and entity refused; control label
refused; label creation without the control label refused; area with
`release: all` parked). `provisiontest.Home.CoreMessages` records message
bodies. Bite proofs observed red for: Revert key allow-lists (area,
entity), emptiness check, set sort, floor reference (plan and undo), and
through the running server for the gate's control-label, label-existence
and area-release checks. ADR 0006 amended for D1–D5 and A.4; Fable read
it against the fact note, its three citation findings are fixed.

**Next steps, in order.**

1. After the merge: measurement on the owner's instance with objects the
   owner names, the policy file opened for `area`, `label`, `entity`
   (ask the owner for the objects first — wizard).
2. D6: declared endpoints enforced by the gate (own slice).

**From Fable's security read (LOW, recorded, not fixed).** The undo of
an `entity_update` can be refused by Core (device entity with an own area
and no own name, name set then undone to `null`); the undo does not
re-check an entity's release (now a *Known weakness* in ADR 0006).
Unverified: the control label deleted between the gate's existence check
and the creation (a race; needs a stand-in test).

**This machine.** The lint tools are in `$(go env GOPATH)/bin`, which is
not on `PATH`; `export PATH="$(go env GOPATH)/bin:$PATH"` before `make ci`.

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
