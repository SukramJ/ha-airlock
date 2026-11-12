# Phase 1, first slice — the reachability probe

What it settles: the two items of `CONCEPT.md` §9 *Unverified* that the Core
identity and the provisioning of the App's own user rest on — whether an App
container reaches Core directly, and whether the Supervisor proxy answers.

## What the probe does

`ha-airlock probe`, run once by the container, makes three GET requests and
logs one line each:

| Check | Request | Expected |
| --- | --- | --- |
| supervisor: core info | `http://supervisor/core/info` with the App's token | 200, carrying Core's port and scheme |
| core through the supervisor proxy | `http://supervisor/core/api/config` with the App's token | 200 |
| core directly, without a credential | `http(s)://homeassistant:<port>/api/` without any header | 401 |

Core's port is read from the first answer, never assumed. If that answer is
missing, the third check is logged as `not performable`. The Supervisor
token is sent to the Supervisor only.

Where the inputs come from, Supervisor at `98a2322`:

- the names `supervisor` and `homeassistant` — `supervisor/plugins/dns.py:419-428`;
  `homeassistant` resolves to the Docker network gateway
- `SUPERVISOR_TOKEN` — `supervisor/docker/const.py:168`, set at
  `supervisor/docker/app.py:246-248`
- the bearer form of the token — `supervisor/api/utils.py:108-110`
- `port` and `ssl` in `/core/info` — `supervisor/api/homeassistant.py:110-111`
- `/core/info` under the default role — `supervisor/api/middleware/security.py:124-128`
- the proxy gated by `homeassistant_api` — `supervisor/api/proxy.py:127-149`

## Installing it as a local App

The Supervisor builds a local App from its directory
(`supervisor/apps/build.py:152-158`), so the directory must hold
`config.yaml`, `Dockerfile`, `go.mod`, `cmd/` and `internal/`.

1. Copy the repository into the `addons/local/ha-airlock` folder of the
   Home Assistant host (Samba share `addons`, or SSH).
2. Settings → Apps → App store → reload; "ha-airlock" appears under the
   local Apps. Install it. The build pulls the Go image and takes a while.
3. Start it. It exits after a few seconds; read the result in its log.
4. Uninstall it afterwards. It keeps no state.

The probe changes nothing in Home Assistant. Installing and removing the
App is the only write, and the owner performs it.

## Reading the result

- All three `outcome=ok`: the dedicated-user path is open; the ADR for the
  Core identity can be written.
- Direct check `unreachable`: Core does not accept connections from the
  App network under that name and port. The Core identity decision is
  reopened.
- Direct check `unexpected` with a TLS detail: Core serves HTTPS under a
  certificate that does not name `homeassistant`. A finding, not a failure
  of the probe.

## What was checked before the first installation

- The image builds from the `Dockerfile` (Docker 29.5.2, arm64) and is
  3.4 MB; it runs as `nonroot`.
- Without `SUPERVISOR_TOKEN` the container logs the reason and exits with
  status 2. With a token and no Supervisor in reach, the two Supervisor
  checks are `unreachable`, the direct check is `not performable`, and it
  exits with status 1.
- `config.yaml`: every key and value was read against the Supervisor's
  schema (`supervisor/apps/validate.py:459-469`, `:523-525`; slug pattern
  `supervisor/apps/const.py:58`). The schema itself was not executed on the
  file, so acceptance by the Supervisor is still shown only by installing.
