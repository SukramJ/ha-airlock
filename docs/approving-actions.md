# Letting an application switch something

ha-airlock can turn lights, switches and toggle helpers on and off for an
application you approved. Two things must be true for every single call:
you released the entity, and — unless you changed the policy — you approve
the call.

## Release an entity

Give the entity the label **airlock** in Home Assistant (Settings →
Devices & services → Entities → the entity → Labels). ha-airlock compares
the label's id; for a label you name `airlock` in a fresh installation
that is expected to be `airlock`, and the audit log tells you when it is
not: a refused call is recorded with "does not carry the label".

An entity without the label cannot be switched, whatever the policy says.
The application is told that the entity is not released; it is not told
whether the entity exists.

Another label id can be set in `/data/policy.json`:

```json
{"version": 1, "profiles": {"local": {"R0": "allow", "R1": "approval"}}, "control_label": "ai_may_switch"}
```

## Approve a call

When an application asks to switch a released entity, the call does not
run. The application is told to ask you, and to repeat the call after you
approved.

Open ha-airlock in Home Assistant. Under **Actions waiting for your
approval** you see one box per call:

- the action in one line, for example "Turn on light.desk" — written by
  ha-airlock from the call, not by the application;
- the entity's id and the name Home Assistant shows for it;
- the application that asks, and the tool and arguments it sent.

**Approve** lets exactly this call run once, when the application repeats
it within two minutes. **Deny** refuses it. A call you do not decide
within five minutes expires. Nothing tells you that a call is waiting;
you have to open the page.

What can be switched: entities of the domains `light`, `switch` and
`input_boolean`, with `turn_on` and `turn_off`. There is no tool for
locks, alarm panels or covers. The full list is in `docs/tools.md`.

## Without asking each time

In `/data/policy.json`, `"R1": "allow"` for the `local` profile lets an
approved application switch released entities without asking. The label
is still required. `"R1": "deny"`, or leaving `R1` out, switches
controlling off.

## What is recorded

Every call, waiting, refused or run, is in the audit log, and so is every
approval, denial and expiry, with the Home Assistant user who decided.
The kill switch on the same page stops approved calls as well.
