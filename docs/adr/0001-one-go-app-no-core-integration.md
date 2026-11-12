# ADR 0001 — One Go App, no integration inside Core

Status: accepted, 2026-11-12 (owner decision).

## Context

`CONCEPT.md` §8 chose one Go App for auth, policy, approval, redaction and
audit, and kept a hybrid — the Go App plus a small custom integration — as
the fallback in case out-of-band approval needed code inside Core. Phase 0
was to settle that.

Read at Supervisor `98a2322` and Core `3f8160ce7ff`:

- For an Ingress request the Supervisor sets `X-Remote-User-Id` after
  dropping any client-supplied copy (`supervisor/api/ingress.py:400-418`).
  The App's own UI therefore knows which Home Assistant user confirms.
- The event an actionable notification raises can be subscribed to by an
  admin connection, without code in Core
  (`homeassistant/components/websocket_api/commands.py:199-205`).
- Repairs issues, the one native dialog that would have needed Core code,
  cannot be created over the API at all
  (`homeassistant/components/repairs/websocket_api.py:31-33`).

## Decision

ha-airlock is one Go App. No custom integration is written, and the hybrid
is no longer a fallback. Approval lives in the Ingress UI (ADR 0002).

## Consequences

- One component, one language, one process boundary between the guard and
  Home Assistant.
- No native Home Assistant entities or dialogs for ha-airlock. What the
  owner sees inside Home Assistant is the Ingress panel, logbook entries and
  notifications.
- It runs only where a Supervisor exists.

## Better than others, better than before, the right cut

**Better than the comparison targets?** Core's `mcp_server` and a custom
integration both run inside Core's process; a fault or an injected call
there is already inside what the guard protects. ha-mcp runs outside but
trusts its client. This cut is outside and does not.

**Better than before?** The concept carried an open fallback; the fallback
is closed on evidence.

**Is the cut right?** Yes, as far as it was measured. Nothing in the
approval path needs Core code. What stays unmeasured is listed in
`CONCEPT.md` §9 and concerns the Core identity, not the cut.
