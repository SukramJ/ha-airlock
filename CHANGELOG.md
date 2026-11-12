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

### Changed

- The minimum Go version is 1.27.4, which fixes GO-2026-6859 in `net/http`.
