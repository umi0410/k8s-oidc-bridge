# Architecture Decision Records

This directory holds the **rationale** behind non-obvious decisions and lessons learned the hard way.
Code comments stay concise and point here; they do not restate the "why".

## How to use

- Add a record by copying [`0000-template.md`](./0000-template.md), numbering it sequentially.
- Set a status: `Proposed`, `Accepted`, or `Superseded by NNNN`.
- Keep each record short: the decision, the context that forced it, and the consequences.
- When an Issue or PR touches a decided topic, link the ADR instead of re-arguing it.

## Index

| ADR | Title | Status |
|---|---|---|
| [0001](./0001-rustls-ring-backend.md) | rustls uses the ring backend | Accepted |
| [0002](./0002-serviceaccount-based-injection.md) | ServiceAccount-based injection contract | Accepted |
| [0003](./0003-claim-based-sts-no-rolearn.md) | Claim-based STS omits RoleArn | Accepted |
