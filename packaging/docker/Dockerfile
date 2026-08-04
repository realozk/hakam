# syntax=docker/dockerfile:1
#
# Hakam core container (no UI). Builds the eBPF object and the userspace node
# from source, then ships a minimal runtime image.
#
#   docker build -f packaging/docker/Dockerfile -t hakam:latest .   (from repo root)
#   ./packaging/docker/run.sh                                        (privileged, host net)
#
# eBPF runs against the HOST kernel, so the container must run --privileged with
# --network host (see run.sh). The image is just a delivery vehicle for the
# kernel programs + the controller.

# ── builder ──────────────────────────────────────────────────────────────────
FROM rust:1-bookworm AS builder

# Native build deps. bpf-linker links against the rust toolchain's bundled LLVM;
# these cover its build and the usual native crates.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config libelf-dev clang llvm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# rust-toolchain.toml pins nightly + rust-src; rustup installs it on first use.
# bpf-linker is required to compile to bpfel-unknown-none. THIS is the slow,
# environment-sensitive step (~10 min — it builds LLVM bindings). If a build
# fails, it is almost always here; pin a known-good version with
# `cargo install bpf-linker --version <X>` to match your toolchain's LLVM.
RUN cargo install bpf-linker

# Portable eBPF bytecode + release controller binary.
RUN cargo xtask build-ebpf \
 && cargo build -p hakam-node --features linux --release

# ── runtime ──────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

# iproute2 gives the entrypoint `ip`/`tc`/`ss` to clear stale hooks and build the
# loopback demo net. netcat/curl/python3/awk let the bundled attack + benign
# scripts run *inside* the container, so a reviewer needs nothing but Docker.
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 ca-certificates netcat-openbsd curl python3 gawk \
    && rm -rf /var/lib/apt/lists/*

# The demo scripts call `sudo`; inside a root container there is no sudo package
# and none is needed. This shim makes them run unmodified.
RUN printf '#!/bin/sh\nexec "$@"\n' > /usr/local/bin/sudo && chmod +x /usr/local/bin/sudo

COPY --from=builder /src/target/release/hakam-node /usr/local/bin/hakam-node
COPY --from=builder /src/target/bpfel-unknown-none/release/hakam-ebpf /usr/local/lib/hakam/hakam-ebpf
COPY packaging/docker/entrypoint.sh /usr/local/bin/hakam-entrypoint
# Self-contained review harness. Everything a reviewer runs lives in one
# directory, because demo-cycle.sh and attack-on-demand.sh resolve their helpers
# relative to their own location ($SCRIPT_DIR) — split them across paths and they
# won't find seclist-attack.sh or target-listener.py. Driven by HAKAM_DEMO=1;
# see packaging/docker/REVIEW.md.
COPY scripts/setup-demo.sh scripts/seclist-attack.sh scripts/benign-traffic.sh \
     scripts/demo-cycle.sh scripts/attack-on-demand.sh scripts/target-listener.py \
     /opt/hakam/scripts/
RUN chmod +x /usr/local/bin/hakam-entrypoint /opt/hakam/scripts/*.sh /opt/hakam/scripts/*.py

ENV HAKAM_IFACE=eth0 \
    HAKAM_MODE=skb \
    HAKAM_BIND=0.0.0.0 \
    HAKAM_BPF_PATH=/usr/local/lib/hakam/hakam-ebpf

EXPOSE 8080
# docker stop sends SIGINT so the node detaches its hooks cleanly.
STOPSIGNAL SIGINT
ENTRYPOINT ["/usr/local/bin/hakam-entrypoint"]
