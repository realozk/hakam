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

# iproute2 gives the entrypoint `ip`/`tc` to clear stale hooks.
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/hakam-node /usr/local/bin/hakam-node
COPY --from=builder /src/target/bpfel-unknown-none/release/hakam-ebpf /usr/local/lib/hakam/hakam-ebpf
COPY packaging/docker/entrypoint.sh /usr/local/bin/hakam-entrypoint
RUN chmod +x /usr/local/bin/hakam-entrypoint

ENV HAKAM_IFACE=eth0 \
    HAKAM_MODE=skb \
    HAKAM_BIND=0.0.0.0 \
    HAKAM_BPF_PATH=/usr/local/lib/hakam/hakam-ebpf

EXPOSE 8080
# docker stop sends SIGINT so the node detaches its hooks cleanly.
STOPSIGNAL SIGINT
ENTRYPOINT ["/usr/local/bin/hakam-entrypoint"]
