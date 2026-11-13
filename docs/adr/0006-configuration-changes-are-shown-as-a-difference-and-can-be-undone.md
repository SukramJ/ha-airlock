# ADR 0006 — A configuration change is shown as a difference, bound to the state it was shown against, and can be undone

Status: proposed, 2026-11-13. The owner decided five points, named at the
end of *Context*; everything else is the assistant's proposal and waits
for the owner's reading. Nothing of it is built. Every part is to be measured on a running Home Assistant before the next
part is built on it; a measurement that contradicts this record amends it.

## Context

`CONCEPT.md` §4 names tier R2: automations, scripts, scenes, helpers,
dashboards, areas and labels, in the local profile with "approval with
diff", blocked in the remote profile. §5 asks for a snapshot before every
R2 write, with undo. ADR 0005 built the approval for a single service
call. A configuration change differs from that in four ways.

**It replaces something.** The owner has to see what is there now and
what will be there, not one line.

**What is there can change between the approval and the run.** An
approval for "replace A by B" is not an approval for "replace A′ by B".

**Some configuration acts.** An automation, a script or a scene is a
service call that happens later, without a call through ha-airlock and
without an approval. The action name and the target of such a call can
each be a template (`homeassistant/helpers/config_validation.py:1527-1543`
and `:1360-1364`, Core `3f8160ce7ff`), so what it will call cannot always
be read from the configuration. A helper or an area calls nothing.

**Some configuration decides what ha-airlock itself allows.** An entity
is released for control by a label (ADR 0005), and
`config/entity_registry/update` sets `labels`, `name`, `new_entity_id`,
`disabled_by` and `hidden_by`
(`homeassistant/components/config/entity_registry.py:153-193`). A tool
that passes these on would let a client release entities for itself, or
give a lock the name of a lamp before asking the owner to switch "the
lamp".

How Core takes configuration, all read at Core `3f8160ce7ff`:

- Automations, scripts and scenes are written over HTTP only:
  `/api/config/{automation|script|scene}/config/{key}` with GET, POST and
  DELETE, each for an administrator
  (`homeassistant/components/config/view.py:44`, `:85-157`). POST
  validates, writes the whole item into `automations.yaml`,
  `scripts.yaml` or `scenes.yaml`, and reloads
  (`components/config/automation.py:19-49`, `script.py:23-44`,
  `scene.py:28-48`). DELETE removes the item and its registry entry. Only
  items in those files are reachable; an automation written by hand in
  another file is not.
- Helpers are written over the WebSocket API:
  `{domain}/create`, `/update`, `/delete`, each for an administrator,
  `/list` for any user (`homeassistant/helpers/collection.py:600-659`).
  An update of an `input_boolean` replaces the whole item
  (`components/input_boolean/__init__.py:84-87`).
- Areas and labels: `config/area_registry/…` and
  `config/label_registry/…`, create, update and delete for an
  administrator (`components/config/area_registry.py:42-123`,
  `label_registry.py:72-135`).
- A dashboard's content is replaced as a whole by `lovelace/config/save`
  (`components/lovelace/websocket.py:149-155`).
- The frontend is the caller of record for each of these
  (`src/data/automation.ts:408-429`, `scene.ts:158-167`,
  `script.ts:319-331`, `input_boolean.ts:19-43`,
  `area/area_registry.ts:41-65`, `label/label_registry.ts:63-90`,
  frontend `0eec83448a`).

The owner decided on 2026-11-13: one record for all of R2; undo by a
button in the sidebar page; deleting from the start, with approval; a
kind of configuration can be switched off as a whole and can be released
as a whole; these switches are set in the policy file first. The
assistant had recommended a first record for configuration that does not
act, and a second one for automations after that was measured. The
recommendation survives as the order of building, below.

## Decision

### Every change

**R2 never runs without an approval.** The policy can deny R2 or ask for
approval. A policy file that allows R2 outright is refused when it is
loaded. The remote profile's default stays deny.

**A tool of tier R2 states its change.** Beside the action of ADR 0005 it
declares a function that, from the arguments and from what Home Assistant
holds now, returns: the kind of object, its identifier, the state before
(absent for a creation) and the state after (absent for a deletion). The
server reads the state before; the client never supplies it. A tool of
tier R2 without this function is refused by the gate, and a test fails for
the catalogue.

**The owner is shown the difference.** The approval page shows the kind,
the identifier, the name Home Assistant has for the object now, and
before and after, field by field for flat objects and line by line for
nested ones. All of it is rendered as text. For a creation every value is
the client's; the page says so. The one-line summary names kind and
identifier and never a name the client chose.

**The approval is bound to the state before.** The key of ADR 0005 —
client, tool, arguments — is extended by the SHA-256 of the state before.
Before a change runs, the gate reads the object again. If it differs from
what the owner was shown, the change does not run, the approval is used
up, and the client is told to call again; the owner is then shown the new
difference.

**A change is recorded with both states, and an administrator can undo
it.** Before the write the gate stores before and after in a journal of
changes in the App's data directory; without that record the write does
not happen. The audit record of the call carries the hashes of both
states, not the states. The sidebar page lists the changes, newest first,
each with **Undo**. An undo writes the state before back. It is offered
only while the object still equals the state after; otherwise the page
shows that it has changed since and offers nothing. An undo is an audit
record with the administrator's user id. No tool undoes anything: a
client that wants a change back asks for the opposite change and waits
for an approval like for any other. The journal keeps the last 200
changes.

**The journal holds the states as they are.** A restored state has to be
the real one, so it is not redacted on disk. It stays in the App's data
directory, is shown to administrators only, and does not enter the audit
log. What a client reads of a configuration passes redaction like every
result.

**A deletion is offered only where an undo can restore what was
deleted.** Where deleting takes away more than the object itself, and the
journal could not put that back, there is no tool for it.

**Objects are released the way entities are.** An existing object can be
changed or deleted only if it carries the label of ADR 0005: on its
registry entry for helpers, automations, scripts and scenes, on the area
for an area. The gate checks it before a change is parked and again
before it runs.

**The policy has two switches per kind.** The kinds are: helpers, areas,
labels, the entity registry, scenes, scripts, automations, dashboards.
For each kind and profile the policy file says

- whether the kind can be changed at all: `deny` or `approval`. A kind
  set to `deny` has no tool that runs, whatever the tier says;
- which existing objects of the kind are released: `label`, the rule
  above and the default, or `all`. With `all`, a change to any object of
  the kind can be put before the owner; it still needs the approval, and
  the journal still records it.

`all` releases the objects of a kind, never what they act on. The
entities an automation, a script or a scene targets are released one by
one, by the label, whatever the switch says; otherwise an automation
would be the way to switch a lock that carries no label. For the same
reason the entity registry has no `all`: its objects are the entities.

The switches live in the policy file. The sidebar page shows what is in
force and does not change it; a page that writes the policy is a later
decision.

**What ha-airlock created, it labels.** After a creation ran, the server
puts the release label on the new object, so that the client can correct
its own work — with an approval each time. The approval page for a
creation says that the object will carry the label and what that allows.
This is the only place where a label is written, and the client has no
say in it.

**Reading is R0.** Tools that read one automation, script, scene or the
helpers of a domain are read-only tools like the others and redacted like
them. They are not limited to released objects.

### Never, whatever the policy says

- No tool takes a label from the client or changes the `labels` of an
  entity, a device or an area.
- No tool changes, renames or deletes the release label itself.
- No tool sets `new_entity_id`, `disabled_by` or `hidden_by`.
- No tool adds, changes or removes a dashboard resource: that is code
  the browser loads.
- No tool writes an automation or script that uses a blueprint: what it
  does is not in the difference the owner sees.

### Configuration that does not act

- **Helpers** — `input_boolean`, `input_number`, `input_text`,
  `input_select`, `input_datetime`, `input_button`, `counter`, `timer`:
  create, update, delete, with the fields of each domain's storage schema.
  A deletion stores the helper's registry entry with it; the undo creates
  the helper again and restores name, area and the release label.
- **Areas**: create and update of name, icon, floor, aliases and picture.
  Delete only for an area nothing is assigned to; the entities and devices
  of an area lose their assignment when it goes, and the journal does not
  hold those.
- **Labels**: create and update of name, colour, icon and description,
  except for the release label. No delete: every assignment of the label
  goes with it and cannot be restored from the journal. This is narrower
  than the owner's "deleting from the start", for this reason.
- **Entity registry**: name, icon and area of a released entity. Nothing
  else.

### Configuration that acts

For automations, scripts and scenes the approval is necessary and not
sufficient. Before a change is parked, the server checks its content, and
refuses what it cannot read:

- **Only the action types the check knows.** Core's table of action types
  is `ACTIONS_MAP` (`homeassistant/helpers/config_validation.py:2125-2147`).
  Accepted are: a service call, delay, wait for a template, wait for a
  trigger, condition, choose, if, repeat, parallel, sequence, variables,
  stop. Refused are: firing an event, a device action, activating a scene
  by its own key, setting a conversation response, and every key the check
  does not know.
- **One action key per step.** Core resolves a step with several action
  keys by the table's order (`config_validation.py:2152-2162`). The check
  refuses such a step instead of resolving it a second way.
- **The action name is written out.** `domain.service` as a literal; no
  template, no `service_template`.
- **The target is entities, written out.** Literal entity ids, in
  `target.entity_id` or `entity_id`; no template, no `all`, no device,
  area, floor or label as target.
- **Every targeted entity is released.** The same label check as for a
  direct call, when the change is parked and when it runs.
- **Some services are never written.** Fixed in the code, not in the
  policy: `shell_command.*`, `python_script.*`, `pyscript.*`,
  `command_line.*`, `hassio.*`, `backup.*`, and `homeassistant.restart`,
  `homeassistant.stop` and the `homeassistant.reload_*` services. These
  are code execution or tier R3.
- **Service data, conditions and triggers may hold templates.** A
  template reads; it does not call.
- **A scene** names only released entities.

The check is a floor under the owner's decision, not a replacement for
it: an automation that passes can still do something the owner does not
want.

Automations, scripts and scenes are written with their whole
configuration, over the HTTP endpoints named above, as the App's own
user. The connection to Core therefore gets a second kind of call beside
WebSocket commands, and a tool declares such an endpoint the way it
declares a command.

### Dashboards

One dashboard's content is replaced as a whole, with the difference shown
line by line. A dashboard has no label; where the other kinds say
`label`, the policy file names the dashboards that can be changed, by
their URL path, and names none by default. `all` releases every
dashboard. No tool creates or deletes a dashboard.

### Order of building

1. The change itself — declaration, difference, binding to the state
   before, journal, undo — with the helpers of one domain.
2. The other helper domains; areas, labels, the entity registry.
3. Scenes.
4. Automations and scripts, with the content check.
5. Dashboards.

Each step is measured on the owner's instance with an object the owner
names, before the next begins.

## Consequences

- The gate grows a step between release and approval: read the state
  before, build the difference. It grows a second one before the run:
  read again, compare, write the journal.
- The approval store carries a difference beside the summary. A
  difference can be large; the page and the store bound it, and a change
  above the bound is refused, not cut.
- A new store, the journal of changes, holds unredacted configuration on
  disk.
- The sidebar page gains a list of changes and one more form that writes.
- The catalogue grows by several tools per kind of object. The tools of
  one kind differ in data, not in code.
- A client cannot write an automation that targets an area or uses a
  template for its target. Such automations are common in hand-written
  configuration; here they are refused, and the refusal says why.
- An automation keeps running after its entities lost the label. The
  check is made when the automation is written, not when it fires.

## Better than others, better than before, the right cut

**Better than the comparison targets?** `CONCEPT.md` §8 records that
ha-mcp treats the client as trusted and that Core's `mcp_server` has no
approval step. ha-mcp's documentation, read for this record at `aab8f38f`,
describes switches for single tools and for groups of tools, and an
optional approval of held calls that is off by default
(`homeassistant-addon/DOCS.md:313-336`, `:366-380`); its code was not
read, and what either does with configuration is unverified here. The
two switches per kind above take up what ha-mcp's group switches give the
owner, and add the release of single objects, which its documentation
does not describe. What can be said without the comparison: a
difference rendered by the server, an approval that does not survive a
change of the object, and an undo the client cannot reach are each a
property of this design, and none depends on the model behaving.

**Better than before?** Before this, ha-airlock cannot change
configuration. ADR 0005's approval would not carry it: its key does not
know the state before, and its page has one line.

**Is the cut right?** The change — before, after, binding, journal — is
one mechanism in the gate, and a kind of object is a declaration, so a new
kind cannot skip a step. The content check for acting configuration is
its own unit with Core's table of action types as its specification; it
is the part most likely to be wrong, and the part a test can pin action
type by action type. Undo sits with the page and not in the catalogue,
which keeps the rule that a client changes nothing without an approval
free of exceptions. Whether one record for all of R2 was the right cut is
open: the sections on acting configuration and on dashboards are decided
before anything below them was measured.

## Known weakness

- **The difference is only as good as its reader.** A long automation is
  approved by an owner who reads it or does not.
- **A released name can be changed.** The entity registry tool lets a
  client propose a new name for a released entity. The approval page of a
  later call shows that name beside the entity id. The id does not change,
  and the rename itself needed an approval that showed both names.
- **The refused services are a list.** A service that executes code and
  is not on it — from a custom integration, for example — passes the
  check, and only the owner's reading stands against it.
- **Templates in service data can carry information out**: a
  notification whose text is a template can send any state to wherever the
  notification goes.
- **Undo restores configuration, not history.** What an automation did
  while it existed is done.
- **The journal is a file.** Whoever can write the App's data directory
  can change what an undo would restore; the same holds for the policy
  file.

## Unverified

Nothing in this record is measured. In particular:

- That the HTTP configuration endpoints are a documented interface. The
  frontend uses them; `CLAUDE.md` asks for an ADR where a tool rests on an
  interface Home Assistant may change without notice, and this record is
  that ADR. Their request and response shapes are read from
  `components/config/view.py`, not observed.
- What `async_validate_config_item` accepts and refuses for automations
  and scripts; it was not read.
- Which identifier a helper, an area or an automation gets when it is
  created again after a deletion, and so whether an undo of a deletion
  gives back the same entity id.
- What a reload after a write does to automations that are running.
- That the check's reading of an action is the reading Core makes, for
  every action type. The check is to be written against Core's schemas
  and tested per type; until then this is an intention.
- Update semantics of the helper domains other than `input_boolean`.
- The size of real configurations and of their differences on the
  owner's instance.
