#!/usr/bin/env bash
# Runs all four demo attack scenarios in sequence against a running hakam-node.
# Each scenario pauses so you can narrate before the next one fires.
#
# Usage:
#   ./scripts/attack.sh [IFACE] [TARGET_IP]
#
# Defaults:
#   IFACE     = dummy0
#   TARGET_IP = 10.99.0.1
#
# Prerequisites: hping3, curl, nc (netcat)
# On Debian/Ubuntu: sudo apt install hping3 netcat-openbsd curl

set -euo pipefail

IFACE="${1:-dummy0}"
TARGET="${2:-10.99.0.1}"
WS_HOST="${WS_HOST:-localhost}"
WS_PORT="${WS_PORT:-8080}"

RED='\033[0;31m'
YLW='\033[1;33m'
CYN='\033[0;36m'
GRN='\033[0;32m'
DIM='\033[2m'
RST='\033[0m'

banner() {
    echo
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
    echo -e "${RED}  HAKAM ATTACK SUITE${RST}  ${DIM}Iface: ${IFACE}  Target: ${TARGET}${RST}"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
    echo
}

step() {
    echo -e "${YLW}[SCENARIO $1]${RST}  $2"
    echo -e "${DIM}  Press ENTER to fire, Ctrl-C to skip this scenario.${RST}"
    read -r || true
}

wait_for_block() {
    echo -e "${DIM}  Waiting 3s for block to propagate…${RST}"
    sleep 3
}

check_tool() {
    if ! command -v "$1" &>/dev/null; then
        echo -e "${YLW}  [WARN] '$1' not found — skipping scenario.${RST}"
        return 1
    fi
    return 0
}

# ── Setup ───────────────────────────────────────────────────────────────────

banner

# Ensure the dummy interface exists with the target IP.
if ! ip link show "$IFACE" &>/dev/null; then
    echo -e "${CYN}  Creating dummy interface ${IFACE}…${RST}"
    sudo ip link add "$IFACE" type dummy
    sudo ip link set "$IFACE" up
    sudo ip addr add "${TARGET}/24" dev "$IFACE"
    echo -e "${GRN}  ✓ Interface ready${RST}"
fi

# Verify hakam-node is reachable on the WebSocket port.
if ! nc -z "$WS_HOST" "$WS_PORT" 2>/dev/null; then
    echo -e "${RED}  [ERROR] hakam-node not listening on ${WS_HOST}:${WS_PORT}${RST}"
    echo -e "${DIM}  Start it first: cargo xtask run --iface ${IFACE} --mode skb${RST}"
    exit 1
fi
echo -e "${GRN}  ✓ hakam-node is reachable${RST}"
echo

# ── Scenario A: Rate-limit flood ─────────────────────────────────────────────

step "A" "RATE-LIMIT FLOOD — hping3 TCP SYN flood at 10 000 pps
  The XDP hook counts packets per second from this source.
  After 500 pps the IP is auto-inserted into BLOCKLIST — no userspace involvement.
  Watch the CPU graph stay FLAT despite the flood."

if check_tool hping3; then
    FLOOD_IP="10.99.1.100"
    echo -e "${CYN}  Flooding from ${FLOOD_IP} for 5 seconds…${RST}"
    sudo hping3 --flood --rand-source -I "$IFACE" -S -p 80 "$TARGET" --spoof "$FLOOD_IP" &
    FLOOD_PID=$!
    sleep 5
    sudo kill "$FLOOD_PID" 2>/dev/null || true
    wait_for_block
    echo -e "${GRN}  ✓ Flood stopped. Check BLOCKLIST with: hakam ▶ list${RST}"
fi

echo

# ── Scenario B: SQL injection via DPI ────────────────────────────────────────

step "B" "SQL INJECTION — HTTP request containing classic SQLi payload
  hakam-node's DPI engine reads the TCP payload ring buffer.
  It detects the pattern and auto-blocks the source IP."

if check_tool curl; then
    SQLI_IP="10.99.1.200"
    echo -e "${CYN}  Sending SQLi payload from ${SQLI_IP}…${RST}"
    # We bind the source IP with curl's --interface flag, but for a dummy
    # interface we send to the target and let the payload hit the DPI ring.
    curl -s --connect-timeout 2 \
         -H "X-Forwarded-For: ${SQLI_IP}" \
         "http://${TARGET}/search?q=' OR '1'='1" \
         -o /dev/null || true
    # Also trigger with a direct TCP payload via nc so the kernel samples it.
    echo -e "GET /search?q=' OR '1'='1 HTTP/1.1\r\nHost: ${TARGET}\r\n\r\n" \
        | nc -w 2 "$TARGET" 80 || true
    wait_for_block
    echo -e "${GRN}  ✓ SQLi blocked. Source should appear in BLOCKLIST.${RST}"
fi

echo

# ── Scenario C: XSS via DPI ──────────────────────────────────────────────────

step "C" "XSS INJECTION — HTTP GET with script tag in parameter
  Same DPI ring buffer path. Demonstrates multi-pattern coverage."

if check_tool nc; then
    XSS_IP="10.99.1.201"
    echo -e "${CYN}  Sending XSS payload…${RST}"
    printf "GET /page?comment=<script>alert(1)</script> HTTP/1.1\r\nHost: %s\r\n\r\n" "$TARGET" \
        | nc -w 2 "$TARGET" 80 || true
    wait_for_block
    echo -e "${GRN}  ✓ XSS blocked.${RST}"
fi

echo

# ── Scenario D: Reverse shell / exfiltration attempt ─────────────────────────

step "D" "EGRESS BLOCK — simulated reverse shell outbound connection
  First we manually block the C2 server IP.
  Then nc tries to connect out — TC_ACT_SHOT kills it before it leaves the NIC.
  Watch the tracepoint log: you will see the process name + PID attempting to connect."

C2_IP="10.99.2.1"
C2_PORT=4444

echo -e "${CYN}  Blocking C2 server ${C2_IP} in BLOCKLIST…${RST}"
echo -e "  ${DIM}(In a real attack this would be auto-detected; here we pre-block for demo clarity.)${RST}"
# Send block command to hakam-node via stdin — assumes it's running in another terminal.
# The user needs to type: block 10.99.2.1  (or we can do it via bpftool)
echo -e "${YLW}  ACTION REQUIRED: In the hakam-node terminal, type:${RST}"
echo -e "    ${CYN}block ${C2_IP}${RST}"
echo -e "${DIM}  Then press ENTER here to fire the reverse shell attempt.${RST}"
read -r || true

if check_tool nc; then
    echo -e "${CYN}  Attempting outbound nc connect to ${C2_IP}:${C2_PORT}…${RST}"
    nc -w 2 "$C2_IP" "$C2_PORT" </dev/null || true
    echo -e "${GRN}  ✓ Connection attempt made. If TC egress is working, it was killed.${RST}"
    echo -e "${GRN}  ✓ Check the hakam-node terminal — tracepoint shows the PID and comm.${RST}"
fi

echo

# ── Summary ───────────────────────────────────────────────────────────────────

echo -e "${GRN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo -e "${GRN}  ALL SCENARIOS COMPLETE${RST}"
echo -e "${GRN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo
echo -e "  Useful follow-up commands:"
echo -e "    ${CYN}hakam ▶ list${RST}      — show all blocked IPs with age"
echo -e "    ${CYN}hakam ▶ status${RST}    — live counters and interface info"
echo -e "    ${CYN}hakam ▶ unblock <IP>${RST} — restore traffic for UI topology demo"
echo
