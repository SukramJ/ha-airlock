# ADR 0006 step 2, rest (areas, labels, entity registry) — fact note and slice plan

Read-only work, 2026-11-15. Nothing was run against a Home Assistant; every
statement below is **read from source**, not observed.

**The owner's decisions, 2026-11-15** (on B.8, each as recommended):
D1 — no `area_delete` in this slice; the undo of an `area_create` deletes
an area checked empty. D2 and D3 fall away with D1. D4 — the undo of a
`label_create` only while no entity, device or area carries the label.
D5 — `picture` is `null` or a path beginning with one `/`; `floor_list`
as an R0 tool. D6 — declared endpoints are enforced in a slice of their
own directly after this one; until then the guard of B.6's first row.

- `C:` = `../core` at `3f8160ce7ff382c467aa249d28a1b0e9b2fc2c19`
- `F:` = `../frontend` at `0d31ae5624ec3c54eebfbb22d5874f5a706453ac`
- `R:` = this repo, branch `docs/adr-0006-undo-measured` at `5ed7575`

Core at this commit validates WebSocket messages with **`probatio`**, not
`voluptuous` (`C:homeassistant/components/config/area_registry.py:5`). The
schema constructs have the same names (`Required`, `Optional`, `Any`).

---

## Part A — fact note

### A.0 Common to all three

| Fact | Source |
| --- | --- |
| A dict schema is extended from `{Required("id"): positive_int}`; no `extra` option is passed, so unknown keys are refused | `C:components/websocket_api/decorators.py:151-152`, `messages.py:36-38`. That probatio's default refuses extra keys is **not established** (library not read) |
| Schema failure → error code `invalid_format` | `C:components/websocket_api/connection.py:378-379`, `const.py:36` |
| Not an admin → `Unauthorized` → code `unauthorized` | `decorators.py:64-65`, `connection.py:375-376`, `const.py:44` |
| Any exception the handler does not catch (a `KeyError`) → code `unknown_error` | `connection.py:319-327`, `:367`, `const.py:43` |
| ha-airlock's own user is in `system-admin` | `R:internal/provision/provision.go:39` |

### A.1 Area registry

Commands registered: list, create, delete, update, reorder — **there is no
get for one area** (`C:components/config/area_registry.py:15-19`).

| Command | Schema | Admin | Result |
| --- | --- | --- | --- |
| `config/area_registry/list` (`:24`) | none | **no** | list of entries (`:34-37`) |
| `config/area_registry/create` (`:42`) | `name: str` **required**; optional `aliases: list`, `floor_id: str`, `icon: str`, `labels: [str]`, `picture: str\|None`, `humidity_entity_id: str\|None`, `temperature_entity_id: str\|None` (`:43-50`). **`floor_id` and `icon` do not accept `null` on create** | yes (`:53`) | the entry (`:82`) |
| `config/area_registry/update` (`:111`) | `area_id: str` **required**; optional `name: str` (not nullable), `aliases: list`, `floor_id`, `icon`, `picture`, `humidity_entity_id`, `temperature_entity_id` each `str\|None`, `labels: [str]` (`:112-120`) | yes (`:123`) | the entry (`:152`) |
| `config/area_registry/delete` (`:87`) | `area_id: str` | yes (`:91`) | the string `"success"` (`:106`) |

- **Entry shape** (list, create, update): `aliases`, `area_id`, `floor_id`,
  `humidity_entity_id`, `icon`, `labels`, `name`, `picture`,
  `temperature_entity_id`, `created_at`, `modified_at` (timestamps as
  floats) — `C:helpers/area_registry.py:88-104`.
- **`aliases` and `labels` are Python sets**, sent as `list(set)`
  (`:77,82`, `:92,97`). The source defines no order. Whether the order is
  the same after a restart of Home Assistant is **not established**. A
  hash over the raw list is therefore not a stable identity.
- Aliases are stripped and empty ones dropped by the handler
  (`components/config/area_registry.py:67-71`, `:137-141`).
- **`labels` on create/update replaces the whole set, and label ids that
  do not exist are dropped silently** (`:73-75`, `:143-145`,
  `helpers/label_registry.py:274-281`).
- **Omitted keys are left unchanged** on update: every parameter defaults
  to `UNDEFINED` and only defined, differing values are applied
  (`helpers/area_registry.py:381-410`, `:426-430`). `modified_at` changes
  on every effective update (`:432`).
- **Identifier:** `area_id`. It is **never taken from the caller** (no
  such key in the create schema). It is `slugify(name)`; if taken, `_2`,
  `_3`, … (`helpers/area_registry.py:271-273`, `:307`,
  `helpers/normalized_name_base_registry.py:70-77`). `slugify` delegates to
  the third-party `unicode_slug.slugify`, `"unknown"` for an empty slug
  (`C:homeassistant/util/__init__.py:39-44`); **what that library does
  with a given name is not established**. A rename does not change the id
  (`async_update` never touches `id`).
  → An undo of a deletion gets the old id back **only if** the slug of the
  area's *current* name equals the old id and nothing took it meanwhile.
  This answers the ADR's open point in "Unverified".
- **Errors.** Duplicate name on create → `invalid_info`, "The name X (x)
  is already in use" (`helpers/area_registry.py:291-294`,
  `components/…:79-80`). The comparison is case-folded with spaces
  removed (`normalized_name_base_registry.py:27-30`). Duplicate name on
  update → `invalid_info` (`normalized_name_base_registry.py:48-59`,
  `registry.py:48-54`, `components/…:149-150`). Unknown `area_id` on
  delete → `invalid_info` "Area ID doesn't exist" (`:103-104`). Unknown
  `area_id` on **update** → `KeyError` at `helpers/area_registry.py:396`,
  not caught (`components/…:147-150` catches `ValueError` only) →
  `unknown_error`.
- **`floor_id` is not validated**, neither on create nor on update: it is
  stored as given (`helpers/area_registry.py:302-312`, `:398-410`; the only
  validation in either path is of the temperature and humidity entities,
  `:296-300`, `:412-424`). Floors that exist are in
  `config/floor_registry/list`, key `floor_id`
  (`C:components/config/floor_registry.py:27`, `:158-168`).
- **`picture` is any string** (`components/…:49`, `:119`); nothing checks
  that it is a local path.
- **Delete** clears the area from every device, child device and entity
  first, then removes it (`helpers/area_registry.py:329-334`;
  `helpers/device_registry.py:4804-4809`;
  `helpers/entity_registry.py:2752-2755`). It also clears it from
  **deleted** devices and entities, which Home Assistant keeps to restore
  them later (`device_registry.py:4810-4816`, `entity_registry.py:2756-2760`).
- **Establishing "nothing is assigned":**
  - `config/entity_registry/list` — no admin needed; each item has
    `area_id` (`C:components/config/entity_registry.py:38-63`,
    `helpers/entity_registry.py:403-404`). An entity that takes its area
    from its device has `area_id: null` itself.
  - `config/device_registry/list` — returns devices **and child devices**
    in one list, each with `area_id`
    (`C:components/config/device_registry.py:77`, `:93-99`;
    `helpers/device_registry.py:758`, `:897`).
  - **Not visible through either list:** the deleted devices and entities
    above. Whether another command exposes them is **not established**
    (not searched).
  - Not in any registry: area ids used in automations, scripts, scenes,
    dashboards. Not established, not searchable with these commands.
- Areas have an owner-set order (`config/area_registry/reorder`,
  `components/…:155-176`). That a re-created area goes to the end is
  **inferred** from the dict insert at `helpers/area_registry.py:314`,
  not read further.

**Frontend** (`F:src/data/area/area_registry.ts`): create sends
`{type, ...values}` (`:45-48`), update `{type, area_id, ...updates}`
(`:55-59`), delete `{type, area_id}` (`:62-65`); list is
`config/area_registry/list` (`F:src/data/ws-area_registry.ts:9`). The
dialog sends `name` trimmed, and for `picture`, `icon`, `floor_id` the
value, or — when empty — **`undefined` on create and `null` on update**
(`F:src/panels/config/areas/dialog-area-registry-detail.ts:543-551`).
This agrees with Core's create schema refusing `null`.

**Core ↔ frontend:** the same dialog sends `labels: this._labels || null`
(`:548`); Core's `labels: [str]` does not accept `null`
(`components/…:117`). `_labels` is initialised to an array in both
branches (`:123`, `:132`), so the `null` is not reached on the paths read.
Not relevant to ha-airlock, which never sends `labels` for a client.

### A.2 Label registry

| Command | Schema | Admin | Result |
| --- | --- | --- | --- |
| `config/label_registry/list` (`C:components/config/label_registry.py:55`) | none | **no** | list of entries (`:64-67`) |
| `config/label_registry/create` (`:72`) | `name: str` **required**; optional `color: Any(color_hex, In(theme colours), None)`, `description: str\|None`, `icon: Any(cv.icon, None)` (`:73-78`) | yes (`:81`) | the entry (`:98`) |
| `config/label_registry/update` (`:125`) | `label_id: str` **required**; optional `color`, `description`, `icon` as above, `name: str` (`:126-132`) | yes (`:135`) | the entry (`:152`) |
| `config/label_registry/delete` (`:103`) | `label_id: str` | yes (`:107`) | `null` (`:120`) |

- **Entry shape:** `color`, `created_at`, `description`, `icon`,
  `label_id`, `name`, `modified_at` (`:155-166`).
- `color_hex` is `^#[0-9A-F]{6}$`, case-insensitive, returned unchanged
  (`C:helpers/config_validation.py:461-471`). The theme colours are the 26
  names at `components/config/label_registry.py:13-40`. `cv.icon` accepts
  any string containing `:` (`config_validation.py:451-458`).
- **Identifier:** `label_id`, generated exactly like an area id
  (`helpers/label_registry.py:130-132`, `:154`); never from the caller.
  **A rename keeps the `label_id`** (`:193-212` replaces `name` only).
- Omitted keys unchanged (`:187-208`).
- **Errors.** Duplicate name on create → `invalid_info` (`:145-148`,
  `components/…:95-96`); on update → `invalid_info` (same base-class check
  as areas). Unknown id on delete → `invalid_info` "Label ID doesn't
  exist" (`:117-118`). Unknown id on update → `KeyError` at
  `helpers/label_registry.py:193` → `unknown_error`.
- **Delete** fires `label_registry_updated/remove`; the entity, device and
  area registries each listen and take the label off everything, deleted
  entities and devices included (`helpers/entity_registry.py:2681-2691`,
  `:2883-2890`; `device_registry.py:4819`, `:5188-5195`;
  `area_registry.py:543-553`). This is what the ADR's "No delete" rests on.
- **How a label sits on an entity:** `labels: set[str]` of **label ids**
  on the registry entry, sent as `list(set)`
  (`helpers/entity_registry.py:416`). The policy's control label is a
  label id, compared with those ids (`R:internal/policy/policy.go:122-124`,
  `R:internal/gate/gate.go:565-567`).

**Frontend** (`F:src/data/label/label_registry.ts`): list `:27`, create
`{type, ...values}` `:67-70`, update `{type, label_id, ...updates}`
`:77-81`, delete `:87-90`. Values: `name` trimmed, `icon` and
`description` trimmed-or-`null`
(`F:src/panels/config/labels/dialog-label-detail.ts:208-211`). No
disagreement with Core found.

### A.3 Entity registry

- `config/entity_registry/list` — no admin; items are `as_partial_dict`:
  `area_id`, `categories`, `config_entry_id`, `config_subentry_id`,
  `created_at`, `device_id`, `disabled_by`, `entity_category`,
  `entity_id`, `hidden_by`, `icon`, `id`, `labels`, `modified_at`, `name`,
  `next_name_part`, `options`, `original_name`, `platform`,
  `translation_key`, `unique_id`
  (`C:components/config/entity_registry.py:38-63`,
  `helpers/entity_registry.py:393-425`).
- `config/entity_registry/get` — `entity_id`; no admin; `not_found` if
  absent; result is `extended_dict` = the above plus `aliases`,
  `capabilities`, `device_class`, `original_device_class`,
  `original_icon` (`components/…:97-123`, `helpers/…:427-440`).
- **`config/entity_registry/update`** — admin (`components/…:153`).
  `entity_id` required; optional `aliases: [str|None]`,
  `area_id: str|None`, `categories`, `device_class: str|None`,
  `icon: str|None`, `labels: [str]`, `name: str|None`,
  `new_entity_id: str`, `disabled_by: None|"user"`,
  `hidden_by: None|"user"`, `options_domain` + `options` (`:156-196`).
  - Only keys present in the message are applied (`:219-229`); nothing is
    changed for an omitted key (`helpers/…:2085-2116`).
  - `null` removes the value: comment at `:159`; `name: null` leaves the
    entity with its original name (`helpers/…:330-336`).
  - `labels` replaces the whole set; unknown ids dropped silently
    (`:242-244`).
  - **`area_id` is not checked against the area registry**
    (`helpers/…:2085-2132`; `_validate_item` has no area parameter,
    `:1255-1269`).
  - **Result:** `{"entity_entry": extended_dict}`, plus `require_restart`
    or `reload_delay` only when the entity went from disabled to enabled
    (`:283-293`).
  - **Errors:** unknown entity → `not_found` (`:211-215`); `ValueError` →
    `invalid_info` (`:263-267`).
- **A rule of this Core commit that the ADR does not know.** An entity
  that belongs to a device and has no name of its own (`name` is `null`
  or `""` and no original name; `helpers/…:330-336`, `:1347-1353`) cannot
  have an area of its own: an update that changes `area_id` or `name` and
  leaves it in that state raises "An entity without a name of its own
  cannot have an area of its own, set the area on its device instead"
  → `invalid_info` (`helpers/…:2197-2215`). Whether the owner's Core
  2026.11.1 has this rule is **not established** (the pin is not that
  release).
- **`name: ""` is a value, not "no name".** The frontend sends `""` for a
  device's main entity (`F:src/panels/config/entities/entity-registry-settings-editor.ts:1906-1910`)
  and otherwise the trimmed name or `null` (`:1912-1913`); `icon` trimmed
  or `null` (`:1325`); `area_id` the id or `null` (`:1895-1900`).

**Frontend** (`F:src/data/entity/entity_registry.ts`): update is
`{type, entity_id, ...updates}` (`:286-295`); the keys it knows are
`name`, `icon`, `device_class`, `area_id`, `disabled_by`, `hidden_by`,
`new_entity_id`, `options_domain`, `options`, `aliases` (`:195-217`).
Result type `{entity_entry, reload_delay?, require_restart?}` (`:81-85`),
as Core sends it. **Note:** the settings editor always sends `labels` and
`new_entity_id` with an update (`…settings-editor.ts:1327-1328`);
ha-airlock must not copy that.

### A.4 Where the ADR as written and Core differ

1. **Undo of an area deletion does not give the id back in general**
   (A.1). Everything that names the area by id — which no registry
   lists — breaks without a trace. The ADR's rule "a deletion is offered
   only where an undo can restore what was deleted" is not met by
   "nothing is assigned" alone.
2. **An area holds more than the five fields the ADR lists:** `labels`,
   `temperature_entity_id`, `humidity_entity_id`, its place in the order,
   `created_at`. A deletion takes them too.
3. **"Nothing is assigned" is not fully readable** (deleted devices and
   entities).
4. **"What ha-airlock created, it labels" fails silently** when the
   control label does not exist in the label registry: Core drops the
   unknown id and answers success. `R:internal/gate/gate.go:506-512`
   discards the answer, so today's helper path would not notice either.
5. **"No tool changes the release label":** Core has no notion of it. A
   rename keeps the id, so the release keeps working, but the label the
   owner looks for has another name. And **`label_create` can create the
   release label itself** when it does not exist yet: a name whose slug is
   the control label's id gets that id.
6. **Entity registry, area:** refused by Core for a device's main entity
   (A.3). The ADR's "name, icon and area of a released entity" holds only
   for entities with a name of their own or without a device.
7. **Core validates neither `floor_id` nor an entity's `area_id`.** The
   server has to, or the owner approves a reference to nothing.
8. **`picture` can be any URL.** A client could propose a remote address;
   every browser that shows the area then fetches it. The ADR lists the
   field without a bound.

---

## Part B — slice plan

### B.0 What exists and fits

- The kinds `area`, `label`, `entity` exist (`R:internal/catalog/catalog.go:42-44`),
  and the policy already parses them with the ADR's rules: `entity` only
  `release: label`, `label` no `release` and always `all`
  (`R:internal/policy/policy.go:233-246`). **No new policy kind; not an
  owner decision.**
- `Tool.Plan / Revert`, `Change.Before/After/Apply/Left`, the journal and
  `Undo` carry all three families unchanged in shape.
- What does **not** fit: the gate assumes the release label sits on an
  **entity**. `plan.Entity` is required for every non-creation
  (`gate.go:322`), read through `config/entity_registry/get`
  (`gate.go:342`, `:552-581`), and a creation and an undone deletion are
  labelled as entities (`gate.go:400`, `:473-474`, `:490-514`). An area
  carries the label itself; a label carries none.

### B.1 Tools

Names on the existing `<object>_<verb>` pattern.

| Tool | Tier | Kind | Core commands |
| --- | --- | --- | --- |
| `area_list` | R0 | — | `config/area_registry/list` |
| `area_create` | R2 | `area` | `…/list`, `config/floor_registry/list`, `…/create`, `…/update` (label of the new area, by the gate) |
| `area_update` | R2 | `area` | `…/list`, `config/floor_registry/list`, `…/update` |
| `area_delete` | R2 | `area` | `…/list`, `config/entity_registry/list`, `config/device_registry/list`, `…/delete` |
| `label_list` | R0 | — | `config/label_registry/list` |
| `label_create` | R2 | `label` | `config/label_registry/list`, `…/create` |
| `label_update` | R2 | `label` | `config/label_registry/list`, `…/update` |
| `entity_update` | R2 | `entity` | `config/entity_registry/get`, `config/area_registry/list`, `config/entity_registry/update` |

Reading entities stays with `entities_list` (`R:internal/catalog/entities.go:26`).
`floor_list` (R0) is not in the ADR; without it a client cannot know a
floor id — see decision D5.

**Semantics: partial update**, as Core's commands are (unlike the helper
tools, which replace). `After` = `Before` with the given fields replaced;
`null` clears where Core's update schema allows `None`.

### B.2 State, plan, way back, read-back

One new file per family: `internal/catalog/areas.go`, `labels.go`,
`entity_registry.go`. A shared `registryState` helper sorts set-valued
fields and drops `created_at` / `modified_at` and the id before anything
is hashed (A.1: sets have no order; `modified_at` moves on every write).

**Area** — object = `area_id`; state = `name`, `icon`, `floor_id`,
`aliases` (sorted), `picture`, **and** `labels` (sorted),
`temperature_entity_id`, `humidity_entity_id`: the last three are shown
and bound, never taken from the client.

| Tool | Plan | Apply | Left | Revert |
| --- | --- | --- | --- | --- |
| create | check fields; `floor_id` must be in the floor list | create, **omitting** absent/`null` keys (A.1) | list, pick by returned `area_id` | `planDelete` — with the emptiness check |
| update | read list; refuse unknown id; merge | update with **only** the client's five fields, never `labels` | list | update with the five fields of the journal's `before`, `null`s included |
| delete | read list; refuse unless no entity and no device names the area | delete | nil | create from the journal's `before` (D2, D3); refuse if an area of that name exists |

**Label** — object = `label_id`; state = `name`, `color`, `icon`,
`description`.

| Tool | Plan | Left | Revert |
| --- | --- | --- | --- |
| create | check fields | list, by returned `label_id` | D4 |
| update | read list; refuse unknown id; merge | list | update with the four fields of `before` |

**Entity** — object = entity id; state = `name`, `icon`, `area_id`,
read with `config/entity_registry/get`.

| Tool | Plan | Left | Revert |
| --- | --- | --- | --- |
| update | get; `area_id` must be in the area list or `null`; `name` a non-empty string or `null`, **never `""`** (A.3) | get | update with the three fields of `before` |

The message holds `entity_id` and of `name`, `icon`, `area_id` only what
changes. Core's refusal for a device's main entity (A.4.6) is passed on;
the journal marks the change failed, as for any failed write
(`gate.go:392-396`).

### B.3 Release and the release-label rules — in the gate

None of this may sit in the catalogue alone: the catalogue cannot import
the policy (the policy imports the catalogue), so it does not know which
label is the control label. That is the right way round — the gate holds
the rule, the tool holds the data.

1. **Where the label sits is declared per kind.** Replace
   `Change.Entity string` by a carrier: entity, area, or none. A table in
   the catalogue says which carrier a kind has (`helper`, `entity` →
   entity; `area` → area; `label` → none); the gate refuses a plan whose
   carrier is not its kind's (extends `gate.go:322`).
2. `released` (`gate.go:552`) reads an area's `labels` from
   `config/area_registry/list` for an area carrier; unchanged for
   entities. Checked before parking and before running, as today.
3. `label` (`gate.go:490`) writes the control label on an area with
   `config/area_registry/update`, `labels` = what the area has + the
   control label. **Both branches read the answer and report "could not be
   set" when the label is not in it** (A.4.4 — this also repairs the
   helper path).
4. **Kind `label`, fixed in the gate, not in the policy:**
   - a plan whose object is the control label is refused before anything
     is parked (`decision: release_label`);
   - a **creation** is refused unless the control label exists in
     `config/label_registry/list`. If it exists, Core cannot hand its id
     to a new label (`normalized_name_base_registry.py:72-77`); no slug is
     computed on our side;
   - **`Undo`** refuses a change of kind `label` whose object is the
     control label *now* — the owner may have pointed `control_label` at
     a label ha-airlock created.
5. No label step after a label creation.

### B.4 Stand-ins

- `internal/gate/gate_test.go` `home`: areas with labels
  (`config/area_registry/list`, `…/update`), `config/label_registry/list`.
- `internal/catalog`: a `registryHome` beside `helperHome`
  (`helpers_test.go:60`) for areas, floors, labels, devices, entities;
  records every message with its body.
- `internal/provision/provisiontest.Home`: canned results suffice
  (`CoreResults`, `CoreThen`); **add the bodies** of received commands
  (today only the types, `home.go:169`) so a wiring test can assert what
  was written.
- `hacoretest`: nothing.

### B.5 Tests

Catalogue (per tool): plan from arguments; write only on Apply; exact
message sent; refusal of every undeclared key; `Revert` for each;
unknown floor / area refused; delete refused while a device, a child
device or an entity names the area; sets hashed order-independently.
Extend `TestChangeToolsAreExactlyTheDeclaredOnesAndChangeHelpers`
(`helpers_test.go:41`) to expect each kind's tools.

Gate (`change_test.go`): area without the label refused, with `release:
all` parked; label on the created area; control label refused for
update, for create-when-absent and for undo; carrier/kind mismatch
refused.

Wiring, through `cmd/ha-airlock` (`serve_test.go:714` is the pattern) —
one per kind and decision: `area`, `label`, `entity` each with
`change: approval` (parked → approved → written → journalled → undone) and
each not opened (`kind_denied`); `area` additionally `release: label`
against `all`; `entity` unreleased.

### B.6 Guards, each with its bite line

| Guard | Bites when this line goes |
| --- | --- |
| No tool message carries `labels`, `new_entity_id`, `disabled_by`, `hidden_by`; no tool sends `config/label_registry/delete` — every R2 tool applied against the recording stand-in | the key allow-list in `entity_update`'s Apply / the field list in `area_update`'s Apply |
| The control label is not changed through the running server (wiring) | the gate's object-is-control-label refusal |
| A label is not created while the control label is missing | the gate's existence check |
| An area is released by its own label | the area branch of `released` |
| A created area carries the label, and its absence is reported | the answer check in `label` |
| An area in use is not deleted — also not by an undo of its creation | the emptiness check in `planDelete` |
| A state with reordered `aliases` has the same hash | the sort in `registryState` |
| Every kind with a tool has a declared carrier | the kind's row in the carrier table |

### B.7 Order

1. Gate: carrier, `released`/`label` for areas, answer check, label rules
   — with the gate's stand-in tool, before any catalogue tool (security
   path: coordinating session).
2. `entity_registry.go` — needs no gate change beyond step 1's rename;
   smallest, proves the partial-update shape.
3. `labels.go`.
4. `areas.go` — last: it has the delete and the open decisions.
5. Wiring tests, guards with bite proofs.
6. `go run ./cmd/ha-airlock tools > docs/tools.md`
   (`cmd/ha-airlock/main_test.go:248-261` fails otherwise); `CHANGELOG.md`
   `[Unreleased]` → Added; `CLAUDE.md` tool counts; ADR 0006 amended for
   D1–D4 and A.4; `make ci`.
7. Measurement on the owner's instance with objects the owner names (the
   ADR's rule; every write is the coordinator's call).

### B.8 Decisions for the owner

- **D1 — area deletion at all.** Options: (a) build it, the approval page
  saying that the id may not come back and that references in
  automations and dashboards are not checked; (b) **leave `area_delete`
  out of this slice** — *recommended*: A.4.1–3 mean the ADR's own rule for
  deletions is not met, and an area costs the owner one click to delete;
  (c) only for an area whose present name gives its id again — needs
  Core's slug rule rebuilt on our side, which is guessing.
  With (b), the undo of an `area_create` still deletes — an area nobody
  used yet, checked empty.
- **D2 — if D1 is (a): what the undo restores.** *Recommended:* all eight
  fields from the journal, `temperature_entity_id` and
  `humidity_entity_id` included; the order and `created_at` are lost and
  the page says so.
- **D3 — labels of a re-created area.** The ADR says the label step is
  "the only place where a label is written". *Recommended:* the undo's
  create carries the labels the journal holds (server-read, not the
  client's), and the ADR sentence is narrowed to "no label is ever taken
  from the client". Otherwise only the control label comes back.
- **D4 — undo of a `label_create`.** It is a label deletion, which the ADR
  refuses as a tool. *Recommended:* allowed only while no entity, device
  or area carries the label (the three lists), else refused with that
  reason — the same rule as for an area. Alternative: no undo.
- **D5 — `picture`.** *Recommended:* `null` or a path beginning with one
  `/`; no remote address (A.4.8). And `floor_list` as an R0 tool, so that
  a floor can be named at all.
- **D6 — declared endpoints enforced.** The better architecture is a gate
  that hands a tool a connection which sends only the commands the tool
  declares; `Endpoints` are free text today
  (`catalog.go:72-74`). *Recommended:* its own slice directly after this
  one, with B.6's first guard standing in until then. Saying so because
  this slice adds the first tools where one wrong key (`labels`) is a way
  around the release.

Is this the best architecture? For the release: yes — one carrier
declaration per kind keeps "a kind is a declaration" true, where a
second label check inside the area tools would be a convenience seam. For
endpoints: no, not until D6.
