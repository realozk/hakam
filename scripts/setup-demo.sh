#!/usr/bin/env bash
# setup-demo.sh — one-shot bootstrap for the Hakam demo network.
#
# Idempotent: safe to run multiple times. Creates dummy0 if missing, brings it
# up, and adds every IP alias used by the playbook + the demo-cycle source pool.
#
# Run once per VM boot before starting hakam-node:
#   ./scripts/setup-demo.sh

set -uo pipefail

IFACE="${IFACE:-dummy0}"

# Roles
TARGETS=( "10.99.0.10" )                                 # database
WORKSTATIONS=( "10.99.1.10" "10.99.2.10" )               # PC#1 sales / PC#2 engineering

# 18 rotating attack sources across two subnets — used by seclist-attack.sh and
# demo-cycle.sh. We pre-create them so `nc -s <ip>` always succeeds.
ROTATING=()
for i in 11 12 13 14 15 16 17 18 19; do ROTATING+=("10.99.1.$i"); done
for i in 11 12 13 14 15 16 17 18 19; do ROTATING+=("10.99.2.$i"); done

# 10 benign sources on a separate subnet — used by benign-traffic.sh.
# Kept distinct from the attack pool so a blocked attacker never silences a
# benign sender (they are never in the same blocklist entry).
BENIGN_POOL=()
for i in 10 11 12 13 14 15 16 17 18 19; do BENIGN_POOL+=("10.99.3.$i"); done

ALL_IPS=( "${TARGETS[@]}" "${WORKSTATIONS[@]}" "${ROTATING[@]}" "${BENIGN_POOL[@]}" )

# ── Colours ────────────────────────────────────────────────────────────────
GRN=$'\033[0;32m'; YLW=$'\033[1;33m'; CYN=$'\033[0;36m'
DIM=$'\033[2m'  ; BLD=$'\033[1m'  ; RST=$'\033[0m'

ok()   { printf "  ${GRN}✓${RST} %s\n"  "$1"; }
warn() { printf "  ${YLW}!${RST} %s\n"  "$1"; }
info() { printf "  ${CYN}·${RST} %s\n"  "$1"; }

echo
echo "  ${BLD}hakam demo network bootstrap${RST}"
echo "  ${DIM}interface: ${IFACE}${RST}"
echo

# Create the dummy interface if missing.
if ip link show "$IFACE" &>/dev/null; then
    info "dummy interface ${IFACE} already exists"
else
    sudo ip link add "$IFACE" type dummy 2>/dev/null \
        && ok "created dummy interface ${IFACE}" \
        || warn "could not create ${IFACE} (kernel module dummy might be missing)"
fi

# Bring it up.
sudo ip link set "$IFACE" up 2>/dev/null && ok "${IFACE} is up"

# Add every IP we'll need. Errors are tolerated since the alias may already
# exist from a previous run — we just want the end state, not the diff.
added=0
skipped=0
for ip in "${ALL_IPS[@]}"; do
    if ip addr show dev "$IFACE" 2>/dev/null | grep -q "inet $ip/"; then
        skipped=$((skipped + 1))
    else
        if sudo ip addr add "$ip/24" dev "$IFACE" 2>/dev/null; then
            added=$((added + 1))
        fi
    fi
done

ok "${added} new IP aliases added, ${skipped} already present (${#ALL_IPS[@]} total)"

# Start a no-op TCP listener on 10.99.0.10:80. Without it, the attacker
# nc(1) calls get a TCP RST before they can transmit the HTTP payload, so
# XDP only ever sees SYN packets — and the DPI signature engine sees nothing
# to match. With this listener, the handshake completes and the HTTP request
# actually flows across the wire (lo, because both endpoints are local).
LISTENER_HOST="10.99.0.10"
LISTENER_PORT="80"
LISTENER_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/target-listener.py"

if ss -tln 2>/dev/null | awk '{print $4}' | grep -qx "${LISTENER_HOST}:${LISTENER_PORT}"; then
    info "no-op listener already running on ${LISTENER_HOST}:${LISTENER_PORT}"
elif [[ ! -x "$LISTENER_SCRIPT" ]]; then
    warn "target-listener.py not found at $LISTENER_SCRIPT — attacks will get RST'd and DPI will see nothing"
elif ! command -v python3 >/dev/null; then
    warn "python3 not installed — cannot start no-op listener; attacks will get RST'd"
else
    sudo nohup python3 "$LISTENER_SCRIPT" --host "$LISTENER_HOST" --port "$LISTENER_PORT" \
        >/tmp/hakam-target-listener.log 2>&1 &
    disown 2>/dev/null || true
    # Give it a moment to bind before declaring success.
    for _ in 1 2 3 4 5; do
        sleep 0.2
        if ss -tln 2>/dev/null | awk '{print $4}' | grep -qx "${LISTENER_HOST}:${LISTENER_PORT}"; then
            ok "started no-op TCP listener on ${LISTENER_HOST}:${LISTENER_PORT} (log: /tmp/hakam-target-listener.log)"
            break
        fi
    done
    if ! ss -tln 2>/dev/null | awk '{print $4}' | grep -qx "${LISTENER_HOST}:${LISTENER_PORT}"; then
        warn "no-op listener did not come up — see /tmp/hakam-target-listener.log"
    fi
fi

# Sanity check — make sure rp_filter doesn't drop our spoofed-source packets.
# Loose mode (=2) accepts packets if the source matches any local route.
RPF=$(sysctl -n "net.ipv4.conf.${IFACE}.rp_filter" 2>/dev/null || echo "?")
if [[ "$RPF" == "1" ]]; then
    sudo sysctl -w "net.ipv4.conf.${IFACE}.rp_filter=2" >/dev/null 2>&1 \
        && ok "set rp_filter=loose on ${IFACE}" \
        || warn "could not relax rp_filter on ${IFACE}"
else
    info "rp_filter on ${IFACE} = ${RPF} (no change needed)"
fi

echo
echo "  ${BLD}ready.${RST} now run:"
echo "    ${CYN}cargo xtask run --iface lo --mode skb${RST}"
echo "  ${DIM}(XDP binds to lo — local-to-local packets between ${IFACE} IP aliases${RST}"
echo "  ${DIM} are routed by the kernel through loopback, not through ${IFACE}.)${RST}"
echo "  then in a second terminal:"
echo "    ${CYN}./scripts/demo-cycle.sh${RST}"
echo
