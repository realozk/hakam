#!/usr/bin/env bash
# Container entrypoint: clear any stale hook, then exec the node headless as PID 1
# so `docker stop` (SIGINT) reaches it and it detaches cleanly.
set -euo pipefail

# The sys_enter_connect tracepoint (per-process attribution) resolves its id via
# tracefs, which containers don't inherit from the host. We run privileged, so
# mount it ourselves; try the modern path first, then the legacy debugfs one.
if [[ ! -e /sys/kernel/tracing/events ]]; then
    mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null \
        || mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null \
        || echo "[hakam] tracefs unavailable — process attribution will be disabled"
fi

# Review/demo mode (HAKAM_DEMO=1): stand up the self-contained test network —
# dummy0 + IP aliases + a no-op target listener on 10.99.0.10:80 — and pin XDP to
# `lo`. Local-to-local attack traffic between the aliases is routed through
# loopback, not dummy0, so `lo` is where the datapath must attach. Lets a reviewer
# see a live block on ONE box, no external target, no second VM. See REVIEW.md.
if [[ "${HAKAM_DEMO:-0}" == "1" ]]; then
    echo "[hakam] demo mode — building loopback test network on 10.99.0.0/16"
    /opt/hakam/scripts/setup-demo.sh || echo "[hakam] setup-demo reported warnings (continuing)"
    HAKAM_IFACE=lo
fi

ip link set dev "${HAKAM_IFACE}" xdp off 2>/dev/null || true
tc qdisc del dev "${HAKAM_IFACE}" clsact 2>/dev/null || true

exec hakam-node \
    --iface "${HAKAM_IFACE}" \
    --mode "${HAKAM_MODE}" \
    --bind "${HAKAM_BIND}" \
    --bpf-path "${HAKAM_BPF_PATH}"
