#!/usr/bin/env bash
# bench-teardown.sh — undoes scripts/bench-setup.sh.
#
# Removes phbench0 (which deletes both ends of the veth pair) and the
# phbench-gen netns. Idempotent.
#
#   ./scripts/bench-teardown.sh

set -uo pipefail

NETNS="${NETNS:-phbench-gen}"
HOST_IF="${HOST_IF:-phbench0}"

GRN=$'\033[0;32m'; YLW=$'\033[1;33m'; CYN=$'\033[0;36m'
DIM=$'\033[2m'  ; BLD=$'\033[1m'  ; RED=$'\033[0;31m'; RST=$'\033[0m'

ok()   { printf "  ${GRN}✓${RST} %s\n"  "$1"; }
warn() { printf "  ${YLW}!${RST} %s\n"  "$1"; }
info() { printf "  ${CYN}·${RST} %s\n"  "$1"; }

if [[ $EUID -ne 0 ]]; then
    info "re-execing under sudo…"
    exec sudo -E "$0" "$@"
fi

echo
echo "  ${BLD}hakam benchmark rig teardown${RST}"

# Detaching XDP first is polite — hakam-node should already be stopped by
# the operator before running this, but if not, this prevents the link delete
# from leaving stale BPF state behind.
if ip link show "$HOST_IF" &>/dev/null; then
    ip link set dev "$HOST_IF" xdp off 2>/dev/null && ok "detached any XDP from ${HOST_IF}" || true
    tc qdisc del dev "$HOST_IF" clsact 2>/dev/null && ok "removed clsact qdisc from ${HOST_IF}" || true
    ip link del "$HOST_IF" 2>/dev/null \
        && ok "deleted veth ${HOST_IF} (peer auto-removed)" \
        || warn "could not delete ${HOST_IF}"
else
    info "${HOST_IF} already absent"
fi

if ip netns list | grep -q "^${NETNS}\b"; then
    ip netns del "$NETNS" \
        && ok "deleted netns ${NETNS}" \
        || warn "could not delete netns ${NETNS}"
else
    info "netns ${NETNS} already absent"
fi

echo
ok "teardown complete"
echo
