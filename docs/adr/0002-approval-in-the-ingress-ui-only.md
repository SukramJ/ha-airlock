# ADR 0002 — Approval is given in the Ingress UI only

Status: accepted, 2026-11-12 (owner decision).

## Context

`CONCEPT.md` §5 allowed the owner to confirm a parked action "in the Ingress
UI or by push notification". Read at Core `3f8160ce7ff`:

- Core does not define the event an actionable notification raises. The
  companion app sends it through the generic `fire_event` webhook, which
  fires any event type with any data
  (`homeassistant/components/mobile_app/webhook.py:304-321`).
- The event's context is the user who registered the device
  (`homeassistant/components/mobile_app/helpers.py:128-130`).

So an approval read from that event would be authenticated by a device
registration alone: any registered companion app could fire it, with
content of its choosing. The text of the action would also travel through
the push service.

For an Ingress request the Supervisor sets the user id itself
(`supervisor/api/ingress.py:400-418`, Supervisor `98a2322`).

## Decision

An approval is given in the Ingress UI and nowhere else. A push
notification only announces that an approval is waiting and links to the
UI. It carries no action button, and it does not carry the action's text
or arguments.

## Consequences

- The approval path contains no event that a third party can raise.
- The approver is the Home Assistant user the Supervisor names, not a
  device.
- Confirming costs the owner one tap more than a notification button would.
- ha-airlock does not need to subscribe to notification events at all.

## Better than others, better than before, the right cut

**Better than the comparison targets?** Home Assistant's own confirmable-
notification blueprint trusts the event; that is adequate for an automation
the owner wrote, not for an approval that stands between a manipulated model
and a door lock.

**Better than before?** The concept offered two approval channels of
unequal strength; the weaker one is now a notice.

**Is the cut right?** Yes. Notification is delivery, approval is
authorisation; they no longer share a channel.
