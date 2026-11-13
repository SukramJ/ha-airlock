# ADR 0005 — An action waits for approval and is repeated; entities are released by a label

Status: accepted, 2026-11-13 (owner decisions). Implemented with the first
tools of tier R1.

## Context

ADR 0002 decided where an approval is given: in the Ingress UI, by the Home
Assistant user the Supervisor names. It left open what the tool call does
meanwhile, what an approval covers, and which entities a tool may act on at
all.

Owner decisions of 2026-11-13:

- A call that needs approval answers at once; it does not block.
- Entities are released for control with a Home Assistant label.
- In the `local` profile every R1 call needs approval until the owner
  relaxes that in the policy.

What Home Assistant provides (Core at `3f8160ce7ff`):

- `call_service` takes `domain`, `service` and an optional `target`
  (`homeassistant/components/websocket_api/commands.py:315-340`) and runs
  the service as the connection's user.
- `config/entity_registry/get` returns one entity's registry entry or the
  error `not_found` (`homeassistant/components/config/entity_registry.py:97-123`);
  the entry carries `labels`, `name` and `original_name`
  (`homeassistant/helpers/entity_registry.py:428-488`). `labels` holds
  label ids, not label names.

## Decision

**A call that needs approval is parked and answered at once.** The answer
says, in its first words, that nothing ran, and asks for the call to be
repeated with the same arguments after the owner approved. The answer is
not an MCP error. It does not name the request.

**An approval is for one call.** It is bound to the SHA-256 over the client,
the tool and the arguments as a JSON value — key order and spacing do not
matter, every other difference does. The first repetition after the
approval runs and uses the approval up. A request waits five minutes; an
approval must be used within two minutes; a denial is remembered for two
minutes, so that repeating a denied call does not ask the owner again at
once. One client can have five requests waiting.

**The owner is shown what the server wrote.** The line that describes the
action comes from the tool's declaration and from identifiers of a checked
shape; the entity's name comes from Home Assistant's registry; the
arguments are shown after redaction. Nothing on the page is text the
client chose freely.

**Tools above R0 state their action.** A tool of tier R1 or higher
declares a function that turns arguments into a summary and the entities
it acts on. A tool above R0 without it is refused by the gate, and a test
fails for the catalogue.

**An entity is released by a label, and the gate checks it.** Before a
call is parked and again before it runs, the gate reads each entity's
registry entry and lets the call on only if the entry carries the label
whose id the policy names (`control_label`, `airlock` if the file names
none). No label, no such entity and no answer are the same refusal, and
the client is not told which. The check does not depend on the policy's
decision: `allow` skips the approval, never the release.

**The first R1 tools are fixed pairs of domain and service.**
`light`, `switch` and `input_boolean`, each with `turn_on` and `turn_off`,
on one entity of that domain, with no service data. Lock, alarm and cover
have no tool.

**Decisions are audit records, and take effect only as such.** Approval,
denial and expiry are records with the administrator's user id. An
approval that cannot be recorded is not given.

**Requests live in memory.** A restart forgets what waits and what was
approved and not yet run.

## Consequences

- The model must repeat a call. A client or model that does not do so
  never runs an action; none runs by accident.
- While something waits, ha-airlock keeps one persistent notification in
  Home Assistant, the notice ADR 0002 describes: it says that an action
  waits and names neither the action nor the application. It is taken
  away when nothing waits any more; an expiry is noticed within about
  twenty seconds.
- Who may assign labels in Home Assistant decides what can be controlled.
  Today that is every administrator. A future tool that changes labels
  would be a tool that widens its own reach, and must be treated as such.
- An approval says nothing about the state of the entity at the moment
  the call runs, up to two minutes later.
- `CONCEPT.md` §4 named `local` R1 as allowed. The default is stricter
  now; the policy can restore the concept's value.

## Better than others, better than before, the right cut

**Better than the comparison targets?** As `CONCEPT.md` §8 records,
ha-mcp declares the MCP client a trusted principal, and Core's
`mcp_server` has no approval step: its choice is one read-only switch and
an admin check. Here the confirmation is given by an identified
administrator in another channel, for exactly one call, and the release
of an entity is a second, independent condition.

**Better than before?** Before this, ha-airlock could not act at all.
The concept's sentence "bound to the hash of the exact arguments and
expires" is now a mechanism with tests for each half.

**Is the cut right?** The store of waiting requests is its own package
and knows neither tools nor Home Assistant. The gate remains the one
place that decides: release, approval and execution are steps of the same
function, in an order a test pins. The release check sits in the gate and
not in the tools, so that a new tool cannot forget it. Blocking until the
decision would have been simpler for the model and was rejected by the
owner because the clients' time limits for a tool call are unmeasured.

## Known weakness

The owner approves a sentence. "Turn on switch.pump" is exact, and still
only as good as the owner's knowledge of what that switch does. The page
shows the entity's name beside its id; it does not show its state.

## Measured

On the owner's instance (Core 2026.11.1), 2026-11-13, with an
administrator's token over Core's WebSocket API:

- A label created with the name `airlock` got the id `airlock`.
- `config/entity_registry/get` for the test helper returned
  `labels: ["airlock"]`, `name: null` and `original_name`; for an entity
  that does not exist it returned the error `not_found`.
- `call_service` with `domain`, `service` and
  `target: {"entity_id": ["input_boolean.ha_airlock_test"]}` — the shape
  the tools send — switched the helper on and off; the state was read
  back after each call.
- `get_services` lists `turn_on` and `turn_off` for `light`, `switch` and
  `input_boolean`.

## Unverified

- That MCP clients show the text of a parked call to the model in a way
  that makes it repeat the call. No client has been connected yet.
- The whole path on a running system: a call over MCP, the approval in
  the sidebar page, the service called by ha-airlock's own user. The
  measurements above were made beside ha-airlock, not through it.
- How Home Assistant derives a label's id from a name other than the one
  measured. The policy compares ids.
- `light` and `switch` on a real device. Only the helper was switched.
