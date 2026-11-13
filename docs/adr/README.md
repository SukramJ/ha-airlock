# Architecture Decision Records

One file per decision, `NNNN-short-title.md`, numbered in the order the
decisions were taken. A landed ADR is not edited; a decision that moves gets
a new ADR that supersedes the old one.

Every architectural ADR carries the section the architecture standard
requires (`CLAUDE.md`): better than the comparison targets, better than the
state before, and whether the cut is right.

- [0001 — One Go App, no integration inside Core](0001-one-go-app-no-core-integration.md)
- [0002 — Approval is given in the Ingress UI only](0002-approval-in-the-ingress-ui-only.md)
- [0003 — A dedicated Core user, reached directly](0003-a-dedicated-core-user-reached-directly.md)
- [0004 — The authorization server lives in the App; consent is given in the Ingress UI](0004-the-authorization-server-lives-in-the-app.md)
- [0005 — An action waits for approval and is repeated; entities are released by a label](0005-actions-wait-for-approval-and-entities-are-released-by-label.md)

Decisions without an ADR yet are recorded in
[`CONCEPT.md`](https://github.com/SukramJ/ha-airlock/blob/main/CONCEPT.md) §3.
