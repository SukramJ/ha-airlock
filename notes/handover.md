# Hand-over

The state a fresh session starts from. Rewritten at each hand-over, never
appended to; the history is in git.

## 2026-11-15, evening — registry tools measured on the instance

**State.** `main` at #40. The App on the owner's instance runs 0.8.0-dev
rebuilt from #40 (53 tools), policy file in
`/addon_configs/816cd011_ha_airlock`: local R0 allow, R1 approval, R2
approval; `helper`, `area`, `label`, `entity` with `change: approval`.
The measurement of ADR 0006 step 2 is done and recorded in ADR 0006
*Measured* (branch `docs/registry-measured`): entity rename, area
create/rename, label create/recolour, each undone; nothing of the test
objects is left on the instance.

**Next steps, in order.**

1. Bump `version` in `config.yaml` with every merge that changes code
   the instance runs: with `0.8.0-dev` unchanged, "Rebuild" built the
   old checkout until the owner reloaded the App store. Own small PR.
2. Log a refused form on the sidebar page (`internal/oauth/consent.go`
   `checked`): two undo presses so far had no effect and left no log
   line; the cause is not established (ADR 0006 *Unverified*).
3. D6: declared endpoints enforced by the gate (own slice).

**From Fable's security read (LOW, recorded, not fixed).** The undo of
an `entity_update` can be refused by Core (device entity with an own area
and no own name, name set then undone to `null`); the undo does not
re-check an entity's release (now a *Known weakness* in ADR 0006).
Unverified: the control label deleted between the gate's existence check
and the creation (a race; needs a stand-in test).

**This machine.** The lint tools are in `$(go env GOPATH)/bin`, which is
not on `PATH`; `export PATH="$(go env GOPATH)/bin:$PATH"` before `make ci`.

**Other open points.** ADR 0006 *Unverified*: undo of a deletion and a
refused undo on a running system; the state of an
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

- After a reconnect the MCP client knows a new catalogue only through
  `/mcp` → Reconnect; a server added mid-session needs a new session.
- Read the tool list as the check that the App runs the merged code;
  the version string does not change between merges.

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
