# ha-airlock — Concept

Status: concept, 2026-11-12. Implemented so far: the chain of section 2 for
one read tool, the authorization server, the audit log and the App's own
user. `CLAUDE.md` states the current extent.
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
| Access | Clients authenticate with OAuth 2.1 against an authorization server inside the App, behind the owner's HTTPS reverse proxy. Each approved client gets one of two profiles, local or remote, assigned by the owner at approval ([ADR 0004](docs/adr/0004-the-authorization-server-lives-in-the-app.md)) |
| Write scope | Device control, configuration, system and Apps, files / YAML — each switchable per policy |
| Diagnosis | Analysing problems with Home Assistant comprehensively is a first-class goal |
| Approval | Out-of-band, inside Home Assistant — never through the model's channel. Given in the Ingress UI only; a push notification is a notice ([ADR 0002](docs/adr/0002-approval-in-the-ingress-ui-only.md)) |
| Cut | One Go App, no integration inside Core ([ADR 0001](docs/adr/0001-one-go-app-no-core-integration.md)) |
| Core identity | A dedicated Home Assistant user with its own token, connected to Core directly, so that actions are attributable. The Supervisor proxy is not used for Core calls ([ADR 0003](docs/adr/0003-a-dedicated-core-user-reached-directly.md)) |
| Provisioning | The App creates that user and obtains its credential itself on first start; the owner neither creates a user nor copies a token. The step is announced in Home Assistant and is the first record of the audit log |
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
       │ own user │ App token
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

As built, the default for R1 in the local profile is stricter than this
table: every call needs approval, and the tools cover `light`, `switch`
and `input_boolean` only (ADR 0005). The policy file can set the table's
value.

For R2, ADR 0006 decides what "approval with diff" and the snapshot of
section 5 mean, what of R2 no policy can enable, and that undo is given
by an administrator in the sidebar page. None of it is built.

A profile is assigned to a client when the owner approves it; the server
does not derive it from where a request comes from. The two profile columns
are starting values. Everything can be narrowed in
the policy file; nothing in the **Never** row can be enabled by policy.

The **Never** row governs what a client can reach: no tool creates, changes
or deletes a user or a token. The App provisioning its own user on first
start (section 3) is not a tool and takes no arguments from a client; it
creates exactly one user, its own, and nothing in the catalogue can invoke
it.

Diagnosis is the reason R0 is broad. It is also where the most sensitive data
leaves the house (section 6, redaction).

## 5. Security

- **Default-deny policy** in one readable file: per profile the tiers,
  domains, entities (for example through a Home Assistant label) and quantity
  limits.
- **Approval outside the model's channel.** A risky action is parked; the
  owner confirms it in the Ingress UI, as the Home Assistant user the
  Supervisor names. A push notification announces the waiting approval and
  carries neither a button nor the action's text. The approval is bound to
  the hash of the exact arguments and expires.
- **The approval text comes from the server.** It is rendered from the
  structured arguments, never from text the model supplied — a manipulated
  model would otherwise describe a dangerous action as harmless.
- **Results are marked as untrusted.** Entity names, log lines and
  notification texts can carry injection payloads.
- **Auth:** OAuth 2.1 with PKCE and one identity per client; no secret-URL
  model. The authorization server is part of the App; a client is admitted
  only after an administrator approved it in the Ingress UI. One listener,
  on a port that is closed after installation, reached through the owner's
  HTTPS reverse proxy, with the Host header checked against the configured
  public URL (ADR 0004).
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
- *Home Assistant's own `mcp_server` integration* (read for phase 0,
  section 9): it serves Home Assistant's LLM APIs over MCP. Its admin-only
  "Home Assistant" API already reads Core and Supervisor logs and calls any
  action, so ha-airlock is not the only way to diagnose over MCP, and R0
  overlaps with it. What it does not have is what this concept is about: no
  approval step, no audit log beyond a debug line, no redaction, no tiered
  policy — the choice is one read-only switch and an admin check — and no
  Supervisor access beyond logs. It runs inside Core, without a process
  boundary between the guard and what it guards.

**Better than before?** Greenfield — there is no earlier state.

**Is the cut right?** One Go App holds auth, policy, approval, redaction and
audit. The alternative cuts were weighed and not chosen:

- A custom integration inside Core has no process boundary between the guard
  and what it guards.
- A hybrid (Go App plus a small integration for native entities and approval
  dialogs) costs a second component in a second language to maintain and to
  audit. Phase 0 showed that approval needs no code inside Core, so it is no
  longer a fallback (ADR 0001).

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

**Measured in phase 0 — Supervisor**, local checkout at `98a2322`
(2026-11-12), paths below `supervisor/`:

- An App declares one of five roles: `default`, `homeassistant`, `backup`,
  `manager`, `admin` (`const.py:485-491`). The role → path map is
  `role_access` (`api/middleware/security.py:123-173`); it applies only when
  the App also has `hassio_api` (`security.py:452-453`).
- `/supervisor/logs`, `/host/logs` and another App's `/addons/{app}/logs`
  (`api/__init__.py:645`, `:278`, `:789`) are matched only by the `manager`
  and `admin` patterns, as are App start / stop / options
  (`api/__init__.py:776-779`). `backup` covers `/backups.*` only. `manager`
  is therefore the smallest role for the R0 and R3 scope, and it is broad:
  it also opens `/store.*`, `/docker/.+`, `/os/…` and `/security/.+`. It
  costs one point of the App's security rating (`apps/utils.py:76-77`).
- The Core proxy is gated by `homeassistant_api`, not by the role
  (`api/proxy.py:127-149`, WebSocket `:383-388`). The App's own
  `Authorization` header is not forwarded (`proxy.py:160-164`); the request
  reaches Core under the Supervisor's identity. WebSocket frames whose type
  starts with `supervisor/` or `hassio/` are refused (`proxy.py:50`).
- That identity is Core's system user "Supervisor", an admin (Core
  `hassio/__init__.py:228-240`), authenticated by the Unix socket (Core
  `http/auth.py:189-211`). Every App that uses the proxy acts as this one
  user, so calls through the proxy are not attributable to ha-airlock in
  Home Assistant's own records.
- For an Ingress request the Supervisor sets `X-Remote-User-Id`, and name,
  display name and groups when present, after dropping client-supplied
  copies (`api/ingress.py:400-418`). The Ingress UI therefore learns who
  approves without a login of its own.

**Measured in phase 0 — Home Assistant Core** at `3f8160ce7ff`, frontend at
`b1164739c3` (2026-11-11):

- *Actionable notifications.* Core does not define
  `mobile_app_notification_action`; its only occurrence is a blueprint
  (`script/blueprints/confirmable_notification.yaml:75`). The companion app
  raises it through the generic `fire_event` webhook, which fires any event
  type with any data under the context of the user who registered the
  device (`mobile_app/webhook.py:304-321`, `mobile_app/helpers.py:128-130`).
  Subscribing needs an admin: the event is not in `SUBSCRIBE_ALLOWLIST`
  (`websocket_api/commands.py:199-205`, `auth/permissions/events.py:30-50`).
  Push approval therefore needs no code inside Core, but the answer arrives
  as an event any registered device can fire with any content.
- Repairs issues cannot be created over the API; the WebSocket commands are
  get, ignore and list (`repairs/websocket_api.py:31-33`).
- *Logbook attribution.* An entry carries `context_user_id`
  (`logbook/processor.py:435-436`), and `logbook.log` passes the caller's
  context on (`logbook/services.py:54`). The frontend resolves the id to a
  name from person entities, and from the user list only for an admin
  viewer (frontend `src/panels/logbook/ha-logbook.ts:536-558`).
- *`mcp_server`.* Four views, among them `/api/mcp` and
  `/api/mcp/{api_id}` (`mcp_server/http.py:68`, `:86-91`, `:404`); Home
  Assistant's own auth (`helpers/http.py:136`), no OAuth of its own. A new
  entry serves all LLM APIs, requires an admin and is not read-only
  (`mcp_server/config_flow.py:116-123`). Tool calls run under the calling
  user's context (`helpers/http.py:142-147`, `mcp_server/http.py:180-186`).
  The admin-only "Home Assistant" API (`llm/__init__.py:181-184`) offers
  `homeassistant__call_action`, which calls any action
  (`homeassistant/llm.py:557`, `:622-627`), `system_log__get_logs`
  (`system_log/llm.py:298`) and `hassio__get_logs` (`hassio/llm.py:45`).
  The only record of a call is a debug log line (`mcp_server/server.py:221`).
- *Diagnostics are not redacted centrally.* The download view passes the
  integration's `data` through (`diagnostics/__init__.py:217-223`);
  redaction is the integration's choice. 140 of 428
  `components/*/diagnostics.py` files do not contain the string "redact"
  (a text grep, not a proof that they leak);
  `airgradient/diagnostics.py:16` returns its data as is.

**Measured in phase 0 — Go MCP SDK**, `modelcontextprotocol/go-sdk` at
`328036e` (2026-11-10), latest release `v1.8.0` (2026-09-04):

- Streamable HTTP with DNS-rebinding protection on loopback
  (`mcp/streamable.go:386-391`), typed tools (`mcp.AddTool`,
  `mcp/server.go:628`) and a middleware around every incoming method
  (`AddReceivingMiddleware`, `mcp/server.go:2087`).
- OAuth as a resource server only: bearer-token middleware
  (`auth/auth.go:97`) and RFC 9728 metadata (`auth/auth.go:197`). It
  contains no authorization server — a grep for endpoint registrations in
  `auth/` and `oauthex/` found client-side metadata types only.
- Eight direct dependencies (`go.mod`), among them `golang-jwt/jwt`,
  `golang.org/x/oauth2` and `golang.org/x/tools`. "Standard library plus an
  MCP SDK" (section 7) is this set, not one module.
- Licence: Apache-2.0 for new contributions, MIT for existing code
  (`README.md:170`).
- It builds without CGo: `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build`
  over `mcp`, `auth`, `oauthex` and `jsonrpc` ended with exit status 0.

- *Provisioning a user without code inside Core.* An admin connection can
  create a user (`config/auth/create`, `config/auth.py:84-102`) and give it
  a username and password (`config/auth_provider/homeassistant/create`,
  `config/auth_provider_homeassistant.py:31-39`). A long-lived token is
  created for the connection's own user only
  (`auth/__init__.py:637-656`), so through the proxy it would belong to
  the Supervisor user, not to the new one. The new user's credential
  therefore has to come from a login as that user (`/auth/login_flow`,
  `auth/login_flow.py:339`). The Supervisor proxy refuses only WebSocket
  types starting with `supervisor/` or `hassio/` (Supervisor
  `api/proxy.py:50`), so it lets the two `config/…` commands through.

**Measured in phase 0 — the owner's instance**, Core 2026.11.1,
2026-11-12, over the REST API from the local network:

- A `logbook.log` call made with a long-lived token of a dedicated admin
  user (no person entity) produced a logbook entry whose `context_user_id`
  is that user's id, as `auth/current_user` reports it for the same token.
  The same call with the owner's token carried the owner's id. Every other
  entry read in the same window, 171 and 199 of them, carried none — the id
  comes from the call, not from a default.

- *The reachability probe*, run as an App on Home Assistant OS 18.4 with
  Supervisor 2026.11.0 (amd64): the Supervisor accepted `config.yaml` and
  built the image; from inside the container `/core/info` answered 200 with
  port and scheme, Core through the proxy answered 200, and Core directly,
  without a credential, answered 401. The App and its repository were
  removed afterwards.

- *Provisioning*, run as an App on the same instance: the Supervisor
  proxy passed `config/auth/list`, `config/auth/create` and
  `config/auth_provider/homeassistant/create`; Core accepted the client id
  `http://homeassistant:8123/` and the login of a `local_only` user from
  the App network; the App's data directory was writable as root. The user
  list then held one user `ha-airlock` (admin, local only, one
  `homeassistant` credential), the logbook an entry carrying that user's id
  as `context_user_id`, and Home Assistant a notification
  `ha_airlock_provisioned`. A second start logged `created=false` and the
  user list still held one such user. Before that, with a hand-made user
  of the same name present, the App had stopped without creating anything.

- *The server as an App*, same instance, App version 0.1.0-dev: the
  Supervisor took the new configuration as an update (sidebar page, port
  8443 unpublished, start with Home Assistant) and kept the data
  directory; the server reused its credential and logged that the public
  listener stays closed without `public_url`. Through Ingress with a
  session the consent page answered 200; without a session, and with
  forged user headers but no session, the Supervisor answered 401. Whether
  the App's own port refuses another peer could not be tried from outside:
  the port is not published.
- *The five tools' commands* — `system_log/list`, `repairs/list_issues`,
  `config_entries/get` with a domain, `trace/list` for automations,
  `logbook/get_events` with a period and with entity ids — were accepted
  by that Core with the parameters the tools send; `trace/list` with a
  domain the tool refuses was refused by Core as well.
- *The entity tools' commands*, on that Core (2026.11.1, 2026-11-13):
  `config/entity_registry/list` returned 7,211 entries and `get_states`
  4,921 states in 2.6 MiB; every entry carried the fields the tools read
  (`homeassistant/helpers/entity_registry.py:393-425` and
  `homeassistant/components/websocket_api/commands.py:418-430` at
  `3f8160ce7ff`). What was measured for the control tools is in ADR 0005.

**Unverified:**

- How the logbook panel shows a dedicated user's entry to the owner. The
  entry carries the id (measured above) and the frontend code resolves it
  for an admin viewer; the panel itself was not looked at.
- The payload of the notification-action event. The companion app builds
  it, and its source was not read.
- Which authorization server the remote listener uses. The SDK does not
  provide one, and the specification revision in force was read only as a
  draft page.

## 10. Phases

0. **Verification spike.** The source reading is done and decided the cut
   (ADR 0001, ADR 0002); the probe on the owner's instance decided the Core
   identity (ADR 0003). What remains of section 9's *Unverified* list is
   settled by the code that first needs it.
1. **R0** with audit, redaction and the Ingress UI — the diagnostic benefit
   without any write risk.
2. **R1** with the approval mechanism.
3. **R2** with snapshot and undo.
4. **R3**, then **R4**.
5. The **remote profile** opened up for use from outside the home, last.
