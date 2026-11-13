# Changelog

All notable changes to ha-airlock are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- The concept (`CONCEPT.md`), the assistant guide (`CLAUDE.md`), and the
  repository skeleton: module, build and lint gates, licence-header guard.
- The read-out of phase 0 in `CONCEPT.md` §8 and §9, and the first two
  decision records: one Go App without an integration inside Core
  (ADR 0001), approval in the Ingress UI only (ADR 0002).
- `CONCEPT.md`: the App provisions its own Home Assistant user on first
  start, the scope of the Never list is stated against that, and the
  attribution of a dedicated user's calls is measured on a running system.
- `ha-airlock probe` and the packaging as a Home Assistant App
  (`config.yaml`, `Dockerfile`): run inside the App container, it reports
  whether Core is reachable through the Supervisor proxy and directly. It
  only reads.
- ADR 0003: ha-airlock acts in Core as a user of its own and connects
  directly; the probe showed that an App container reaches Core.
- The audit log (`internal/audit`): append-only JSON lines chained by
  SHA-256, and `ha-airlock audit verify FILE` to check a log. Nothing
  records into it yet. See `docs/audit-log.md`.
- `internal/hacore`: a client for Core's WebSocket API, and a fourth check
  of `ha-airlock probe` that reports which Home Assistant user the
  Supervisor proxy acts as.
- `ha-airlock provision` (`internal/provision`): on the first start the App
  creates its own Home Assistant user through the Supervisor proxy, logs
  in as it once and keeps the refresh token; the password is not stored.
  The creation is the first record of the audit log and is announced in
  the logbook and as a notification. A user of that name that the App did
  not create is never taken over. The App's container now runs this
  command. See `docs/own-user.md`.
- ADR 0004: the OAuth 2.1 authorization server is part of the App, clients
  are approved in the Ingress UI, and a profile is assigned per client.
  `CONCEPT.md` §3, §4, §5 and §10 follow. Not implemented yet.
- `CONCEPT.md` §9: provisioning measured on a running Home Assistant.
- The MCP server (`ha-airlock serve`), which the App's container now runs:
  - `internal/catalog`: the static tool catalogue, with a first tool,
    `system_log_list`.
  - `internal/policy`: default-deny per profile and tier, from an optional
    `policy.json`.
  - `internal/redact`: credentials and coordinates are removed from every
    result and from what the audit log keeps.
  - `internal/gate`: the one enforcement point — identity, policy, tool,
    redaction, audit record. A call that cannot be recorded returns
    nothing.
  - `internal/oauth`: the authorization server of ADR 0004 — clients
    identified by a metadata document, approved by an administrator in the
    Ingress page after comparing a code, PKCE, opaque tokens stored as
    hashes, rotating refresh tokens.
  - `internal/mcpserver`: the catalogue over MCP, Streamable HTTP.
  See `docs/connecting-a-client.md`.
- Four more read-only tools: `repairs_list_issues`, `config_entries_list`,
  `trace_list`, `logbook_events`.
- `ha-airlock tools` prints the list of tools from the catalogue;
  `docs/tools.md` is its output, and a test fails when they differ.
- The kill switch (`internal/halt`): one button in the sidebar page makes
  the gate refuse every tool call until it is released; the state survives
  a restart.
- A limit of tool calls per minute and client, 60 for the `local` profile
  and 30 for `remote`, adjustable with `limits` in `policy.json`.
- The audit log in Home Assistant: the ha-airlock page links to a view of
  the records, newest first, for administrators. Opening it checks the
  whole chain and compares the end of the file with the last line the
  server wrote, so lines cut off the end are reported while the server
  runs. See `docs/audit-log.md`.

### Changed

- The minimum Go version is 1.27.4, which fixes GO-2026-6859 in `net/http`.
- New dependency: `github.com/gorilla/websocket` v1.5.3 (BSD-2-Clause, no
  dependencies of its own), for Core's WebSocket API. The first module
  besides the standard library.
- The App's container runs as root, because the Supervisor creates the
  App's data directory as root.
- Dependencies are vendored: `vendor/` holds the third-party code the
  build uses, `make lint` fails when it differs from `go.mod`, and the
  image build fetches nothing.
- New dependency: `github.com/modelcontextprotocol/go-sdk` v1.8.0 with
  seven transitive modules (`google/jsonschema-go`, `segmentio/asm`,
  `segmentio/encoding`, `yosida95/uritemplate`, `golang.org/x/oauth2`,
  `x/sync`, `x/sys`, `x/time`), all MIT or BSD-3-Clause. `vendor/` grows to
  about 64,000 lines of Go.
- The App is a service now: it starts with Home Assistant, has a page in
  the sidebar and declares port 8443, unpublished by default.
- The App's version is 0.1.0-dev, so that an installed App takes over the
  new configuration (sidebar page, port, options) as an update.
