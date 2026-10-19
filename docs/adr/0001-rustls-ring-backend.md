# 0001. rustls uses the ring backend

- **Status:** Accepted
- **Date:** 2026-10-19

## Context

rustls can be backed by either `aws-lc-rs` (default) or `ring`. With `aws-lc-rs`, the `aws-lc-sys`
C/assembly build segfaults (`cc1` SIGSEGV) under emulated builds — QEMU and Rosetta — which breaks
portable and cross-architecture image builds. It also drags in a native toolchain (cmake/clang).

## Decision

Pin rustls (and every crate that selects a rustls backend, e.g. `kube`, `axum-server`) to the
**`ring`** backend, and keep `aws-lc-sys` out of the dependency tree entirely
(`cargo tree -i aws-lc-sys` must be empty). Install the process-wide `CryptoProvider` explicitly at
startup (`rustls::crypto::ring::default_provider().install_default()`).

## Consequences

- Builds are portable and need no cmake/clang or native cross toolchains.
- Adding a dependency that pulls `aws-lc-sys` transitively will reintroduce the segfault — audit new
  TLS-touching dependencies and keep the explicit `ring` feature selection.
