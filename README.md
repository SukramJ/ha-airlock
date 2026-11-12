# ha-airlock

An MCP server for Home Assistant that puts **transparency and security**
ahead of feature breadth. It makes Home Assistant — Core, the Supervisor and
the installed Apps — available to an AI assistant, and treats that assistant
as untrusted: every tool call passes one chain.

```
Auth → Profile → Policy → (Approval) → Execution → Redaction → Audit
```

> **Status: concept.** Nothing is implemented yet. The repository holds the
> design ([`CONCEPT.md`](./CONCEPT.md)) and a build skeleton.

## What it is meant to do

- **Diagnose** Home Assistant comprehensively: states, logs, traces,
  repairs, integration diagnostics — redacted before they leave the house.
- **Control** released entities, **configure** automations and dashboards,
  **operate** Apps, backups and updates — each tier switchable per policy.
- **Ask first.** Risky actions are approved out-of-band inside Home
  Assistant, never through the model's own channel.
- **Show everything.** An append-only, hash-chained audit log and a UI in
  the Home Assistant sidebar.
- **Stay small.** One static Go binary with a dependency set small enough to
  read.

## Development

```sh
make setup   # pinned lint tooling
make ci      # build, vet, test, lint
```

Go 1.27+, no CGo. [`CLAUDE.md`](./CLAUDE.md) has the rules that govern
changes.

## Licence

Apache-2.0, see [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE).
Contributions come under [`CLA.md`](./CLA.md).

ha-airlock is an independent project, not affiliated with or endorsed by
Home Assistant, the Open Home Foundation or Nabu Casa.

---

<sub>☕ Like this project? [GitHub Sponsors](https://github.com/sponsors/SukramJ) · [Ko-fi](https://ko-fi.com/sukramj) · [Buy Me a Coffee](https://buymeacoffee.com/sukramj)</sub>
