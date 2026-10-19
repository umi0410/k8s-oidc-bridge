# CLAUDE.md

Guidance for Claude Code and human contributors working in this repository. Keep this file in
sync with how the code actually works — if a rule here stops matching reality, fix one of them.

## What this is

**k8s-oidc-bridge** exchanges a pod's Kubernetes ServiceAccount token for a token from an upstream
OIDC provider, auto-renews it, and injects it transparently into the pod as a web-identity token.
It is a thin *exchange plane* — not an identity provider, secrets manager, or policy engine. See
[`README.md`](./README.md) for the problem statement, architecture diagram, and comparison.

## Repository layout

| Path | Responsibility |
|---|---|
| `crates/common` | Pure, I/O-free logic: CRD types, provider config + `$secret:key` resolver, renew/backoff math, projection, status transitions, pod-binding selection. Fully unit-tested. Ships the `crdgen` binary. |
| `crates/controller` | Reconcile loop, exchange drivers, projection `Secret` writer, leader election, metrics/events. |
| `crates/webhook` | `axum` mutating-admission server + pure JSON-patch builder. |
| `charts/k8s-oidc-bridge` | Helm chart (controller + webhook + CRD). |
| `examples/` | End-to-end `TokenBinding` + provider recipes. |
| `docs/adr/` | Architecture Decision Records — the home for rationale and hard-won lessons. |

## Golden rules

1. **Code and comments are in English.**
2. **Every code change ships unit tests.** No exceptions. If you change behavior, add or adjust the
   tests in the same change. Prefer moving decision logic into `crates/common` so it is pure and
   trivially unit-testable; keep kube/HTTP I/O thin at the edges.
3. **TLS uses the rustls `ring` backend only.** Never introduce `aws-lc-sys`. See
   [`docs/adr/0001-rustls-ring-backend.md`](./docs/adr/0001-rustls-ring-backend.md).
4. **Regenerate the CRD after changing the `TokenBinding` spec** — never hand-edit the generated file:
   ```sh
   cargo run -p oidc-bridge-common --bin crdgen > charts/k8s-oidc-bridge/crds/tokenbindings.yaml
   ```
5. **Images are distroless nonroot** — deployments must set `runAsUser`/`runAsGroup` `65532`.
6. **`serviceaccounts/token` (TokenRequest) is a cluster-takeover primitive** — keep it scoped to
   named ServiceAccounts (`rbac.serviceAccountNames`) by default; never widen it casually.

## Comments and documentation

- Comments state **intent and gotchas specific to this code** — concise, as a human would write them.
- **Do not record trial-and-error, superseded approaches, or decision history in comments.** Describe
  the current design on its own terms.
- When a decision needs a "why", write an ADR and point to it from a one-line comment
  (`// ring backend only — see docs/adr/0001`). Do not inline the rationale.
- Tutorial-style explanation belongs in `README.md` / `docs/`, not in code.

## Decision records (ADR)

- Significant or non-obvious decisions, and lessons learned the hard way, go in `docs/adr/` — not in
  code comments, and not only in a PR description.
- Copy [`docs/adr/0000-template.md`](./docs/adr/0000-template.md), number sequentially, set a status
  (`Proposed` / `Accepted` / `Superseded by NNNN`).
- **GitHub Issues and PRs should briefly summarize the relevant ADR and link to it**, rather than
  restating the full rationale.

## Development workflow

Write or adjust the unit test alongside the change, then verify locally before pushing:

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
helm lint charts/k8s-oidc-bridge
# if the TokenBinding spec changed, regenerate and commit the CRD (golden rule 4)
```

CI (`.github/workflows/ci.yml`) runs the same on every push/PR; the container image is built and
pushed only on a push to `main`.

## Architecture conventions

- **Pure core, thin edges.** Put branching/validation/derivation in `common` with unit tests; keep
  `controller`/`webhook` as thin wiring around it.
- **Immutability.** Return new values; do not mutate inputs in place.
- **Many small, focused files** over large ones.
- **Exchange drivers** are a discriminated union on `type` in `common::config`. Add one by extending
  the enum plus a module in `controller::exchange`, with unit tests for the request/response shape.
- **The injection contract is load-bearing** across webhook and controller (namespace opt-in +
  ServiceAccount-based resolution + per-pod opt-out; webhook stamps a marker label and the resolved
  binding annotation so the controller can watch/list and fan out). Read
  [`docs/adr/0002-serviceaccount-based-injection.md`](./docs/adr/0002-serviceaccount-based-injection.md)
  before changing it.

## Error handling and security

- Handle errors explicitly; never silently swallow. Log/error messages are in English.
- No secrets in code, comments, or logs. Where a token must be observed in logs, log its SHA-256
  hash, never the token itself.
- Validate external input (admission requests, provider config, token responses) at the boundary.

## PR / Issue conventions

- Conventional commits: `feat` / `fix` / `docs` / `refactor` / `test` / `chore` / `ci`.
- PRs: describe the change, link any relevant ADR, include a short test plan, and keep CI green.
- Issues: if the topic was already decided, link the ADR instead of re-opening the rationale.
