# syntax=docker/dockerfile:1
#
# k8s-oidc-bridge container image. Both the controller and webhook **binaries go into one image**,
# selected via the container `command` (the Helm chart is written on that assumption).
#
# Multi-arch: buildkit runs this Dockerfile per TARGETPLATFORM (via QEMU when needed),
# so the below is an architecture-neutral native `cargo build`. No separate cross setup required.

FROM rust:1-bookworm AS builder
# The rustls backend is ring-only (aws-lc-sys removed), so extra build tools like cmake/perl/clang
# are not needed. ring builds with just cc (included in the base image).
WORKDIR /app
COPY . .
# Cap compilation parallelism to keep peak build memory low on memory-constrained builders.
ENV CARGO_BUILD_JOBS=2 CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
# Registry/target cache mounts speed up rebuilds. The output binaries are copied from the cache to /out.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    mkdir -p /out \
    && cargo build --release --locked \
        --bin oidc-bridge-controller --bin oidc-bridge-webhook \
    && cp target/release/oidc-bridge-controller \
          target/release/oidc-bridge-webhook /out/

# Small runtime: distroless(cc) for glibc dynamically-linked binaries, nonroot.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /out/oidc-bridge-controller /usr/local/bin/oidc-bridge-controller
COPY --from=builder /out/oidc-bridge-webhook /usr/local/bin/oidc-bridge-webhook
USER nonroot
# Default is the controller. The chart gives webhook pods oidc-bridge-webhook via command.
ENTRYPOINT []
CMD ["oidc-bridge-controller"]
