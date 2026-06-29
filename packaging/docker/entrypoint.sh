#!/usr/bin/env bash
# Container entrypoint: clear any stale hook, then exec the node headless as PID 1
# so `docker stop` (SIGINT) reaches it and it detaches cleanly.
set -euo pipefail

ip link set dev "${HAKAM_IFACE}" xdp off 2>/dev/null || true
tc qdisc del dev "${HAKAM_IFACE}" clsact 2>/dev/null || true

exec hakam-node \
    --iface "${HAKAM_IFACE}" \
    --mode "${HAKAM_MODE}" \
    --bind "${HAKAM_BIND}" \
    --bpf-path "${HAKAM_BPF_PATH}"
