# ADR 0003 — A dedicated Core user, reached directly

Status: accepted, 2026-11-12 (owner decision, confirmed by measurement).

## Context

An App can reach Core in two ways.

Through the Supervisor's proxy, the request arrives in Core as the system
user "Supervisor", an admin that every App using the proxy shares
(`supervisor/api/proxy.py:160-164`, Supervisor `98a2322`; Core
`homeassistant/components/hassio/__init__.py:228-240`, Core `3f8160ce7ff`).
Nothing Home Assistant records then tells ha-airlock's calls from another
App's.

Directly, with a credential of a user of its own. Measured on the owner's
instance (Home Assistant OS 18.4, Supervisor 2026.11.0, Core 2026.11.1):

- From inside the App container, Core answers under `homeassistant` and the
  port the Supervisor reports, with 401 to a request without a credential.
  The probe of `notes/phase1-probe.md` logged all three checks `ok`.
- A call made with the token of a dedicated admin user carries that user's
  id as `context_user_id` in the logbook; entries from other sources in the
  same window carry none.

Not measured: a request with that token sent from inside the container. The
two measurements above were taken from different places, the token one from
the local network.

## Decision

ha-airlock acts in Core as a Home Assistant user of its own and connects to
Core directly. The Supervisor proxy carries no tool call. It is used once,
to provision that user (`CONCEPT.md` §3), and the App keeps the
`homeassistant_api` permission for that purpose only.

The user is an admin: the diagnostic commands of R0 and the event
subscriptions require one.

## Consequences

- Home Assistant's own records — logbook, contexts — attribute every action
  to ha-airlock, independently of ha-airlock's audit log.
- The App holds a credential for an admin user and must store it outside
  the App options, where the Supervisor and backups would expose it.
- Core's address is read from the Supervisor (`/core/info`) at start, never
  assumed.
- If Core serves HTTPS, its certificate will not name `homeassistant`. How
  the connection is verified then is open; the owner's instance serves
  plain HTTP on the internal network.

## Better than others, better than before, the right cut

**Better than the comparison targets?** Core's `mcp_server` acts as the
calling user, which attributes well but gives the server no identity of its
own. An App on the proxy is indistinguishable from every other App. A
dedicated user gives both a server identity and attribution.

**Better than before?** The concept named a dedicated user without knowing
whether the container could reach Core. It can.

**Is the cut right?** Yes: one identity for everything ha-airlock does in
Core, one use of the proxy that ends when the user exists. The admin group
is broader than any single tier needs; the limit on what a client can do is
the policy and the static catalogue, not Home Assistant's permissions.
