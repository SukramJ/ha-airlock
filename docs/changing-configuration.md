# Letting an application change configuration

An approved application can ask to create, change or delete toggle helpers
(`input_boolean`). Nothing else of Home Assistant's configuration can be
changed through ha-airlock today. A change never runs without your
approval, and you approve it looking at what is there now beside what is
asked for.

This is off until you switch it on.

## Switch it on

In `/data/policy.json`, the `local` profile needs tier `R2` set to
`approval`, and the kind `helper` opened:

```json
{
  "version": 1,
  "profiles": { "local": { "R0": "allow", "R1": "approval", "R2": "approval" } },
  "configuration": { "local": { "helper": { "change": "approval" } } }
}
```

- `"R2": "allow"` is refused when the file is read: configuration is not
  changed without an approval, whatever the file says.
- A kind that is not named under `configuration` is denied.
  `"change": "deny"` says the same in so many words.
- The file is read when ha-airlock starts.

## Which helpers can be changed

An existing helper can be changed or deleted only if its entity carries
the label that releases entities for control (`airlock`, unless the policy
names another; see `docs/approving-actions.md`). With

```json
"helper": { "change": "approval", "release": "all" }
```

every helper created in Home Assistant's user interface can be changed,
labelled or not. Each change still needs your approval.

A helper that ha-airlock created is given the label by ha-airlock, so the
application can ask to correct it. The approval page says so before you
approve the creation. Because the label is also what releases an entity
for switching, an application can then ask to switch that helper as well.

Helpers written in YAML cannot be changed.

## Approve a change

The call returns at once, saying that nothing ran. Open ha-airlock in Home
Assistant. Under **Actions waiting for your approval** the change has a
table:

| Field | Now | After |
| --- | --- | --- |
| icon | `"mdi:account"` | |
| name | `"Guest mode"` | `"Visitors"` |

- **Now** was read from Home Assistant by ha-airlock, not sent by the
  application. For a creation the column is empty, and every value under
  **After** is the application's.
- A change replaces the helper's stored configuration: a field with
  nothing under **After** is removed.
- Rows that differ are marked.
- The line in bold names the kind of change and the entity. It never
  contains a name the application chose.

The approval is for replacing exactly what **Now** shows. If the helper is
changed by someone else before the application repeats its call, the
change does not run: the application's next call waits again, and you are
shown the new difference.

## What is recorded

- Every call is in the audit log. For a change that ran, the record names
  the entry in the journal of changes and carries the hashes of the
  configuration before and after, not the configuration.
- The journal of changes, `/data/changes.json`, holds the configuration
  before and after for the last 200 changes, unredacted, so that a change
  can be taken back. A change is written there before it is sent to Home
  Assistant; if that fails, the change is not made.

## Not there yet

- Taking a change back from the sidebar page. The journal is written; the
  page does not show it yet.
- Every other kind of configuration, and the other helper domains.
- ADR 0006 describes the whole design and what is still unverified.
