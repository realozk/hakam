#!/usr/bin/env bash
# bench-setup.sh — provisions the Hakam benchmark rig.
#
# Creates a veth pair across a network namespace so we can hit Hakam's XDP
# hook with traffic that traverses the kernel network stack (closer to a real
# NIC than dummy0, and supports native-mode XDP).
#
# Topology after run:
#
#       netns phbench-gen                          root ns
#     ┌──────────────────────┐                   ┌────────────────────────┐
#     │ phbench-gen          │ ── veth tunnel ── │ phbench0               │
#     │ 10.200.0.2/24        │                   │ 10.200.0.1/24          │
#     │ (load generator)     │                   │ (Hakam attaches here)│
#     └──────────────────────┘                   └────────────────────────┘
#
# Idempotent: safe to re-run.
#   ./scripts/bench-setup.sh

set -uo pipefail

NETNS="${NETNS:-phbench-gen}"
HOST_IF="${HOST_IF:-phbench0}"
NS_IF="${NS_IF:-phbench-gen}"
SUBNET="${SUBNET:-10.200.0}"
HOST_IP="${HOST_IP:-${SUBNET}.1}"
NS_IP="${NS_IP:-${SUBNET}.2}"
PREFIX="${PREFIX:-24}"

GRN=$'\033[0;32m'; YLW=$'\033[1;33m'; CYN=$'\033[0;36m'
DIM=$'\033[2m'  ; BLD=$'\033[1m'  ; RED=$'\033[0;31m'; RST=$'\033[0m'

ok()   { printf "  ${GRN}✓${RST} %s\n"  "$1"; }
warn() { printf "  ${YLW}!${RST} %s\n"  "$1"; }
info() { printf "  ${CYN}·${RST} %s\n"  "$1"; }
die()  { printf "  ${RED}✗${RST} %s\n"  "$1" >&2; exit 1; }

need_root() {
    if [[ $EUID -ne 0 ]]; then
        info "re-execing under sudo…"
        exec sudo -E "$0" "$@"
    fi
}
need_root "$@"

echo
echo "  ${BLD}hakam benchmark rig bootstrap${RST}"
echo "  ${DIM}netns=${NETNS}  host_if=${HOST_IF}  ns_if=${NS_IF}  subnet=${SUBNET}.0/${PREFIX}${RST}"
echo

# ── netns ───────────────────────────────────────────────────────────────────
if ip netns list | grep -q "^${NETNS}\b"; then
    info "netns ${NETNS} already exists"
else
    ip netns add "$NETNS" || die "ip netns add ${NETNS} failed"
    ok "created netns ${NETNS}"
fi

# ── veth pair ───────────────────────────────────────────────────────────────
# Creating the pair sets up phbench0 in root ns and phbench-gen as a peer; we
# then move the peer into the netns. If phbench0 already exists from a prior
# run we leave it alone.
if ip link show "$HOST_IF" &>/dev/null; then
    info "interface ${HOST_IF} already exists — assuming pair is set up"
else
    ip link add "$HOST_IF" type veth peer name "$NS_IF" \
        || die "ip link add veth pair failed"
    ok "created veth pair ${HOST_IF} ↔ ${NS_IF}"

    # Move the peer end into the netns.
    ip link set "$NS_IF" netns "$NETNS" \
        || die "could not move ${NS_IF} into netns ${NETNS}"
    ok "moved ${NS_IF} into netns ${NETNS}"
fi

# ── addresses + UP ──────────────────────────────────────────────────────────
if ip addr show dev "$HOST_IF" 2>/dev/null | grep -q "inet ${HOST_IP}/"; then
    info "${HOST_IF} already has ${HOST_IP}/${PREFIX}"
else
    ip addr add "${HOST_IP}/${PREFIX}" dev "$HOST_IF" \
        && ok "assigned ${HOST_IP}/${PREFIX} to ${HOST_IF}" \
        || warn "could not assign ${HOST_IP} (already in use?)"
fi
ip link set "$HOST_IF" up && ok "${HOST_IF} is up"

ip netns exec "$NETNS" ip link set lo up
if ip netns exec "$NETNS" ip addr show dev "$NS_IF" 2>/dev/null | grep -q "inet ${NS_IP}/"; then
    info "${NS_IF} (in netns) already has ${NS_IP}/${PREFIX}"
else
    ip netns exec "$NETNS" ip addr add "${NS_IP}/${PREFIX}" dev "$NS_IF" \
        && ok "assigned ${NS_IP}/${PREFIX} to ${NS_IF} (in netns)" \
        || warn "could not assign ${NS_IP} (already in use?)"
fi
ip netns exec "$NETNS" ip link set "$NS_IF" up && ok "${NS_IF} is up (in netns)"

# Loose rp_filter — same reason as setup-demo.sh: we send from spoofed-looking
# sources during DPI tests, the kernel must accept them.
sysctl -wq "net.ipv4.conf.${HOST_IF}.rp_filter=2" >/dev/null || true
ip netns exec "$NETNS" sysctl -wq "net.ipv4.conf.${NS_IF}.rp_filter=2" >/dev/null || true
ok "rp_filter set to loose on both ends"

# ── XDP capability check ────────────────────────────────────────────────────
# veth supports native-mode (driver) XDP since kernel 5.15. Anything below and
# we have to fall back to SKB. Print the verdict so the operator knows.
KVER=$(uname -r | awk -F'[.-]' '{ printf "%d.%02d\n", $1, $2 }')
if awk "BEGIN { exit !($KVER >= 5.15) }"; then
    ok "kernel $(uname -r) supports native XDP on veth"
    echo
    echo "  ${BLD}next:${RST} attach hakam in driver mode for the credible bench:"
    echo "    ${CYN}cargo xtask run --iface ${HOST_IF} --mode drv${RST}"
else
    warn "kernel $(uname -r) is older than 5.15 — driver-mode XDP not guaranteed on veth"
    echo
    echo "  ${BLD}next:${RST} attach hakam in SKB mode (still better than dummy0):"
    echo "    ${CYN}cargo xtask run --iface ${HOST_IF} --mode skb${RST}"
fi

echo "  then in another terminal:"
echo "    ${CYN}./scripts/bench-run.sh -w clean    -l baseline-clean   ${RST}${DIM}# before launching hakam${RST}"
echo "    ${CYN}./scripts/bench-run.sh -w clean    -l hakam-clean   ${RST}${DIM}# with hakam attached${RST}"
echo "    ${CYN}./scripts/bench-run.sh -w flood    -l hakam-flood   ${RST}${DIM}# rate-limit + drop-path${RST}"
echo "    ${CYN}./scripts/bench-run.sh -w dpi      -l hakam-dpi     ${RST}${DIM}# DPI loop${RST}"
echo "  teardown when done:"
echo "    ${CYN}./scripts/bench-teardown.sh${RST}"
echo
