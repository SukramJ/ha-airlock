# Hand-over

The state a fresh session starts from. Rewritten at each hand-over, never
appended to; the history is in git.

## 2026-11-15

**State.** `main` at #37. The App runs as `0.8.0-dev` on the owner's
instance with the policy file in `/addon_configs/816cd011_ha_airlock`
(local: R0 allow, R1 approval, R2 approval, `helper` change approval).
Catalogue: 15 R0, 6 R1, 24 R2 (eight helper domains). ADR 0006 step 1 is
built and measured on the instance, including the undo of a creation;
step 2 is built for the helper domains (#36), not yet for areas, labels
and the entity registry.

**Open, and where each goes.**

1. Done 2026-11-15: the undo of `input_number.ha_airlock_number_test` is
   measured and recorded in ADR 0006 *Measured*.
2. ADR 0006 step 2, rest: areas, labels, the entity registry. Plan and the
   reading of Core's WebSocket commands are Fable's (a fact note with
   `path:line` at Core `3f8160ce7ff`); the implementation follows the
   `helperDomain` pattern and is Opus's.
3. ADR 0006 *Unverified*: undo of an update and of a deletion, and a
   refused undo, on a running system; the state of an `input_text` in the
   password mode is still readable through the state-reading tools.
4. Not built: the sidebar page showing the policy in force; `remote`
   profile redaction; audit log rotation; repair of a torn audit line;
   moving the sidebar page out of `internal/oauth`.
5. The owner: revoke the first token pasted in chat (not confirmed).

**Next step.** Item 2, starting with a Fable fact note on Core's area and label commands.

**How to work with the instance.** Writes need the owner's approval and a
target the owner names (`CLAUDE.md`). A parked call waits five minutes; the
owner sees messages only after a turn ends, so: park the call, end the
turn, the owner approves and answers, repeat within two minutes. The
tools reach the server through `claude mcp` (`ha-airlock` at
`https://airlock.toonlan.de/mcp`); reads beside ha-airlock use an admin
token kept outside the repository.

**Lessons.**

- In zsh a `$LIST` does not split into words in a `for` loop; use an
  explicit list or an array.
- `codespell` in the Python repositories reads the owner's German quote as
  misspellings; the repositories' `--ignore-words-list` takes the word.
- Check `make ci`'s exit status directly; `gofumpt -w` before the gate.
- Home Assistant stores a helper's validated configuration (defaults,
  coerced numbers): compare against what was read back, never against what
  was sent.
