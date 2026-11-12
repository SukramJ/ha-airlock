# Security Policy

ha-airlock is at the concept stage; there is no released version to
support yet.

## Reporting a vulnerability

Do not file a public issue. Use GitHub's private vulnerability reporting:
<https://github.com/SukramJ/ha-airlock/security/advisories/new>.

## Threat model

The design's premise is in [`CONCEPT.md`](./CONCEPT.md) §2 and §5: the MCP
client is **untrusted**. A report that shows a client reaching Home
Assistant around the policy, a result leaving unredacted or unaudited, or an
approval being obtained or forged through the model's channel is in scope by
definition.
