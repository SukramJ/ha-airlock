# ha-airlock — Concept

Status: concept, 2026-11-12. Nothing described here is implemented yet.
This document carries the design intent until a `SPECIFICATION.md` and ADRs
under `docs/adr/` replace it section by section.

## 1. Purpose

ha-airlock is a Model Context Protocol (MCP) server that makes Home Assistant
— Core, the Supervisor and the installed Apps — available to an AI assistant.
Its two governing properties are **transparency** and **security**; feature
breadth comes third.

The motivation is distrust: an MCP server for Home Assistant reaches as deep
into a home as an administrator does, so the owner must be able to read what
it can do, see what it did, and stop what it is about to do.

## 2. Guiding idea

The server is a gateway with exactly one enforcement point. Every tool call
passes the same chain, in this order:

```
Auth → Profile → Policy → (Approval) → Execution → Redaction → Audit
```

**The MCP client is untrusted.** The model behind it can be manipulated by
prompt injection through anything it reads — an entity name, a log line, a
web page. The server therefore stays safe on its own; it never relies on the
client to ask for confirmation or to refuse a request.

## 3. Decisions taken

Owner decisions of 2026-11-12:

| Topic | Decision |
| --- | --- |
| Architecture | A Go App: one container beside Home Assistant Core, one static binary, the only place where auth, policy and audit are enforced |
| Access | Local and remote clients, each with its own profile |
| Write scope | Device control, configuration, system and Apps, files / YAML — each switchable per policy |
| Diagnosis | Analysing problems with Home Assistant comprehensively is a first-class goal |
| Approval | Out-of-band, inside Home Assistant — never through the model's channel |
| Name | `ha-airlock`, without a `go-` prefix: an end-user product installed as an App, like `openccu-loom` |

```
MCP client
    │  OAuth 2.1 / Streamable HTTP
    ▼
┌──────────────────────────┐
│ ha-airlock (container)   │
│  Auth → Policy → Audit   │
│  Tools (static catalogue)│
│  Ingress UI              │
└──────┬──────────┬────────┘
       │ WS/REST  │ Supervisor API
       ▼          ▼
   HA Core     Supervisor (Apps,
               backups, updates)
```

## 4. Function scope by risk tier

| Tier | Content | Local profile | Remote profile |
| --- | --- | --- | --- |
| **R0 Read & diagnose** | States, registries, history and statistics, logbook, automation traces, Core / Supervisor / host / App logs, repairs, config check, integration state and diagnostics, Supervisor resolution centre, hardware and network, a time-limited event capture | allowed, redacted | allowed, redacted harder, no raw logs |
| **R1 Control** | Service calls on released entities | allowed; lock, alarm, garage door with approval | allowlist only, sensitive domains blocked |
| **R2 Configuration** | Automations, scripts, scenes, helpers, dashboards, areas and labels | approval with diff | blocked |
| **R3 System & Apps** | Start / stop / configure Apps, backups, updates, Core restart | approval | blocked |
| **R4 Files / YAML** | Read and write below `/config` behind a path allowlist | approval with diff and config check | blocked |
| **Never** | Shell or code execution, user and token management, `secrets.yaml`, `.storage/auth*`, installing Apps from third-party repositories or HACS | — | — |

The two profile columns are starting values. Everything can be narrowed in
the policy file; nothing in the **Never** row can be enabled by policy.

Diagnosis is the reason R0 is broad. It is also where the most sensitive data
leaves the house (section 6, redaction).

## 5. Security

- **Default-deny policy** in one readable file: per profile the tiers,
  domains, entities (for example through a Home Assistant label) and quantity
  limits.
- **Approval outside the model's channel.** A risky action is parked; the
  owner confirms it in the Ingress UI or by push notification. The approval
  is bound to the hash of the exact arguments and expires.
- **The approval text comes from the server.** It is rendered from the
  structured arguments, never from text the model supplied — a manipulated
  model would otherwise describe a dangerous action as harmless.
- **Results are marked as untrusted.** Entity names, log lines and
  notification texts can carry injection payloads.
- **Auth:** OAuth 2.1 with PKCE and one identity per client; no secret-URL
  model. The local listener binds to Ingress / loopback only, Host and Origin
  validation on. The remote endpoint is a separate listener with its own
  profile.
- **Kill switch** in the UI, and rate limits per client.
- **Static tool catalogue.** No dynamic tools, no generic "call any API".
- **Reversibility.** A snapshot before every R2 / R4 write, with undo; a Home
  Assistant backup before an R3 update.

## 6. Transparency

- **Audit log:** append-only, hash-chained JSONL. Per call: client, tool,
  arguments, policy decision, approver, before / after diff, result,
  duration. Refusals are logged too.
- **Ingress UI** in the Home Assistant sidebar: live activity, pending
  approvals, diffs, the active policy, undo.
- **Mirrored into Home Assistant:** logbook entries, and a dedicated Home
  Assistant user so actions are attributed (section 9 has what is verified
  about this).
- **Self-description:** every tool declares its tier and the Home Assistant
  endpoints it touches. The documentation is generated from that
  declaration, and an `explain_policy` tool shows a client what it may do.
- **Redaction before output:** tokens, passwords, config-entry data,
  coordinates and similar values are removed before a result leaves the
  server. This is the price of diagnostic depth — logs and diagnostics
  contain secrets, and the reader is a cloud-hosted model.

## 7. The criterion weighted highest besides transparency and security

**Verifiability through smallness.** The motivation is distrust, so the code
must be small enough for its owner to read:

- Go standard library plus an MCP SDK; dependencies vendored.
- Reproducible build, signed image, no code loaded at run time.
- About thirty clearly cut tools rather than as many as possible.

Second: only documented Home Assistant APIs, so a Home Assistant update does
not break behaviour silently.

## 8. Better than others, better than before, the right cut

**Better than the comparison targets?**

- *ha-mcp* (the functional reference, section 9): it declares the
  authenticated MCP client a trusted principal and prompt injection the
  client's responsibility. ha-airlock inverts that premise, and everything in
  sections 5 and 6 follows from the inversion. It is also deliberately
  smaller.
- *Home Assistant's own `mcp_server` integration:* it exists in Core
  (section 9). What it exposes was not read for this concept, so no
  comparison is claimed here. **Open:** read it before phase 1 and record the
  comparison in this section.

**Better than before?** Greenfield — there is no earlier state.

**Is the cut right?** One Go App holds auth, policy, approval, redaction and
audit. The alternative cuts were weighed and not chosen:

- A custom integration inside Core has no process boundary between the guard
  and what it guards.
- A hybrid (Go App plus a small integration for native entities and approval
  dialogs) costs a second component in a second language to maintain and to
  audit. It remains the fallback if phase 0 shows that out-of-band approval
  needs code inside Core.

The accepted limit of this cut: it runs only where a Supervisor exists (Home
Assistant OS / Supervised).

## 9. Measured and unverified

**Measured — ha-mcp**, local checkout at `aab8f38f` (2026-07-18), MIT:

- `src/ha_mcp/tools/*.py` totals 59,577 lines (`wc -l`).
- A grep over `src/` found 89 distinct `ha_*` names. This is a heuristic, not
  a verified tool count.
- `SECURITY.md`: the MCP client is a trusted principal; `python_transform`
  expressions are "trusted code from a trusted client"; the HTTP entry points
  bind to `0.0.0.0` by default; Host / Origin validation is off by default;
  the OAuth token carries the Home Assistant long-lived access token signed
  but not encrypted.
- `tools_filesystem.py`, `tools_hacs.py` and `tools_code.py` exist; only the
  file names were read, not the code.

**Measured — Home Assistant Core**, local checkout at `3f8160ce7ff`
(2026-11-09), paths below `homeassistant/components/`:

- A WebSocket connection builds its context from the authenticated user:
  `websocket_api/connection.py:124-126` (`Context(user_id=self.user.id)`),
  used by `call_service` at `websocket_api/commands.py:331`. A dedicated
  user therefore gives calls their own `user_id`.
- The Supervisor's system user is created in the admin group
  (`hassio/__init__.py:228-230`,
  `async_create_system_user(HASSIO_USER_NAME, group_ids=[GROUP_ID_ADMIN])`).
- The diagnostic commands R0 needs exist as WebSocket types:
  `system_log/list` (`system_log/__init__.py:318`), `repairs/list_issues`
  (`repairs/websocket_api.py:90`), `trace/list` and `trace/get`
  (`trace/websocket_api.py:86`, `:52`), `config_entries/get`
  (`config/config_entries.py:668`), `logbook/get_events`
  (`logbook/websocket_api.py:455`), `recorder/statistics_during_period`
  (`recorder/websocket_api.py:289`), `diagnostics/list`
  (`diagnostics/__init__.py:124`), `config/entity_registry/list`
  (`config/entity_registry.py:39`), `validate_config`
  (`websocket_api/commands.py:1374`).
- REST: `/api/config/core/check_config` (`config/core.py:29`),
  `/api/diagnostics/{d_type}/{d_id}` (`diagnostics/__init__.py:250`), the
  error-log view (`api/__init__.py:530`).
- The logbook has a `log` service (`logbook/services.py:18`).
- Core ships an `mcp_server` integration ("Model Context Protocol",
  depending on `http` and `conversation`: `mcp_server/manifest.json:3`, `:7`).

**Unverified** — from general knowledge, to be settled in phase 0:

- Which Supervisor role an App needs for logs, backups and App control, and
  which Core user an App's Supervisor-issued token acts as. The Supervisor
  source is not checked out locally.
- Whether a dedicated user's actions appear in the logbook attributed to that
  user in a form the owner finds readable. The context carries the
  `user_id` (measured above); the rendering was not checked.
- Whether out-of-band approval by push notification works without code
  inside Core. A grep for `notification_action` in
  `homeassistant/components/mobile_app/` found nothing, so the event an
  actionable notification raises is not yet located.
- The maturity of the Go MCP SDK for OAuth 2.1.
- Whether Home Assistant's diagnostics downloads are already redacted by the
  integrations that produce them. ha-airlock redacts regardless.

## 10. Phases

0. **Verification spike.** Settle every item of the *Unverified* list
   against the owner's instance and the Supervisor source; read Core's
   `mcp_server`. The result decides between the Go App alone and the hybrid.
1. **R0** with audit, redaction and the Ingress UI — the diagnostic benefit
   without any write risk.
2. **R1** with the approval mechanism.
3. **R2** with snapshot and undo.
4. **R3**, then **R4**.
5. The **remote listener** with OAuth, last.
