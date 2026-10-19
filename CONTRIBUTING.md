# Contributing

Issues and PRs are welcome. This file covers the build/test workflow and project conventions;
[`CLAUDE.md`](./CLAUDE.md) holds the full working agreement (it applies to human and AI contributors
alike).

## Build & develop

```sh
cargo build
cargo test --workspace
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
helm lint charts/k8s-oidc-bridge
```

Regenerate the CRD after changing the `TokenBinding` spec (never hand-edit the generated file):

```sh
cargo run -p oidc-bridge-common --bin crdgen > charts/k8s-oidc-bridge/crds/tokenbindings.yaml
```

CI runs the same checks on every push/PR; the container image is built only on a push to `main`.

## Project layout

| Crate | Responsibility |
|---|---|
| `crates/common` | `TokenBinding` CRD (`bridge.oidc.io`), provider config + `$<secret>:<key>` resolver, exchange-driver union, renew/backoff math, status transitions, pod-binding selection. Pure, unit-tested. Ships `crdgen`. |
| `crates/controller` | reconcile loop, TokenRequest minting, exchange drivers, projection `Secret` writer, leader election, metrics/events. |
| `crates/webhook` | `axum` mutating-admission server + pure JSON-patch builder. |

TLS uses the **ring** rustls backend (no `aws-lc-sys`), so builds are portable and need no
cmake/clang or native cross toolchains ([ADR 0001](./docs/adr/0001-rustls-ring-backend.md)).

## Conventions

- **Code and comments are in English.**
- **Every code change ships unit tests.** Prefer pushing decision logic into `crates/common` so it is
  pure and trivially unit-testable; keep kube/HTTP I/O thin at the edges.
- Comments state intent and gotchas, concisely. **Don't record trial-and-error or decision history in
  comments** — write an [ADR](./docs/adr) and reference it from a one-line comment.
- Conventional commits (`feat` / `fix` / `docs` / `refactor` / `test` / `chore` / `ci`).

## Decisions and discussion

- Significant or non-obvious decisions, and lessons learned the hard way, go in
  [`docs/adr/`](./docs/adr) — not only in a PR description.
- **Issues and PRs should briefly summarize the relevant ADR and link to it** rather than restating
  the full rationale.

## Opening a PR

Describe the change, link any relevant ADR, include a short test plan, and keep CI green.
