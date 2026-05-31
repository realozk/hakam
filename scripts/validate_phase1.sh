#!/usr/bin/env bash
#
# scripts/validate_phase1.sh — Hakam Phase 1 acceptance suite.
#
# Builds the eBPF, launches hakam-node, fires five probes that exercise the
# new code paths from docs/arsenal_roadmap.md Phase 1 and docs/core_hardening.md B2,
# then verifies each produced the expected telemetry over the WebSocket bus.
#
#   1.  eBPF build (BPF verifier go/no-go)
#   2.  Regression — classic single-segment SQLi + XSS still block
#   3.  URL decoding (Phase 1 #2) — %20 + form-encoded `+`
#   4.  Split-segment reassembly (Phase 1 #1)
#   5.  Tracepoint CIDR scope (B2) — in-scope CONNECT surfaces, out-of-scope filtered
#
# Pass: exit 0, every section shows green checkmarks.
# Fail: exit 1, the failing probe's telemetry is dumped, logs preserved
#       under /tmp/hakam-validate-*.log for inspection.
#
# Requires: cargo, nc, websocat, jq, sudo.
# Network:  scripts/setup-demo.sh must have run (binds 10.99.x.y aliases on dummy0).

set -uo pipefail
# Deliberately no -e — some probes expect connect() failures.

# ── config (override via env) ────────────────────────────────────────────────
TARGET_IP="${TARGET_IP:-10.99.0.10}"
TARGET_PORT="${TARGET_PORT:-80}"
MONITOR_PREFIX="${MONITOR_PREFIX:-10.99.0.0/16}"
OUT_OF_SCOPE_IP="${OUT_OF_SCOPE_IP:-127.0.0.1}"
OUT_OF_SCOPE_PORT="${OUT_OF_SCOPE_PORT:-9}"
IFACE="${IFACE:-lo}"
WS_URL="${WS_URL:-ws://127.0.0.1:8080/ws}"

BPF_PATH="target/bpfel-unknown-none/release/hakam-ebpf"
NODE_BIN="target/release/hakam-node"

WS_LOG="$(mktemp /tmp/hakam-validate-ws.XXXXXX.log)"
NODE_LOG="$(mktemp /tmp/hakam-validate-node.XXXXXX.log)"
BUILD_LOG="$(mktemp /tmp/hakam-validate-build.XXXXXX.log)"

# ── colour helpers ───────────────────────────────────────────────────────────
if [ -t 1 ]; then
    BOLD=$(tput bold); RED=$(tput setaf 1); GRN=$(tput setaf 2); YEL=$(tput setaf 3)
    BLU=$(tput setaf 4); GRY=$(tput setaf 8); RST=$(tput sgr0)
else
    BOLD=""; RED=""; GRN=""; YEL=""; BLU=""; GRY=""; RST=""
fi

section() { printf "\n${BOLD}${BLU}── %s ──${RST}\n" "$1"; }
pass()    { printf "  ${GRN}✓${RST} %s\n" "$1"; }
fail()    { printf "  ${RED}✗${RST} %s\n" "$1"; fails=$((fails + 1)); }
info()    { printf "    ${GRY}· %s${RST}\n" "$1"; }
warn()    { printf "  ${YEL}!${RST} %s\n" "$1"; }

fails=0
NODE_PID=""
WS_PID=""

cleanup() {
    [ -n "$WS_PID" ]   && sudo kill "$WS_PID"   2>/dev/null || true
    if [ -n "$NODE_PID" ]; then
        sudo kill -INT "$NODE_PID" 2>/dev/null || true
        sleep 1
        sudo kill -KILL "$NODE_PID" 2>/dev/null || true
    fi
    # Detach anything we left attached, just in case the SIGINT cleanup
    # in hakam-node didn't fire (e.g. on an early-exit panic path).
    sudo ip link set dev "$IFACE" xdp off 2>/dev/null || true
    sudo tc qdisc del dev "$IFACE" clsact 2>/dev/null || true

    if [ "$fails" -eq 0 ]; then
        rm -f "$WS_LOG" "$NODE_LOG" "$BUILD_LOG"
    else
        printf "\n${YEL}logs preserved:${RST}\n"
        printf "  build : %s\n" "$BUILD_LOG"
        printf "  node  : %s\n" "$NODE_LOG"
        printf "  ws    : %s\n" "$WS_LOG"
    fi
}
trap cleanup EXIT

# ── prerequisites ────────────────────────────────────────────────────────────
require() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf "${RED}error:${RST} '%s' not found; install it first.\n" "$1" >&2
        exit 2
    fi
}

require cargo
require nc
require websocat
require jq

if ! sudo -n true 2>/dev/null; then
    printf "${RED}error:${RST} script needs passwordless sudo for cargo xtask run / kill.\n" >&2
    exit 2
fi

# Probe IPs from the demo aliasing pool must be present.
need_ips=(10.99.1.11 10.99.1.12 10.99.1.13 10.99.1.14 10.99.1.15)
for ip in "${need_ips[@]}"; do
    if ! ip addr show | grep -q "$ip"; then
        printf "${RED}error:${RST} %s not bound on any interface — run ./scripts/setup-demo.sh first.\n" "$ip" >&2
        exit 2
    fi
done

# Pre-clean any stale state from a previous run.
sudo ip link set dev "$IFACE" xdp off 2>/dev/null || true
sudo tc qdisc del dev "$IFACE" clsact 2>/dev/null || true

# ── 1. eBPF build (verifier go/no-go) ────────────────────────────────────────
section "1. eBPF build (verifier go/no-go)"
if cargo xtask build-ebpf > "$BUILD_LOG" 2>&1; then
    pass "eBPF compiled and accepted by toolchain"
    info "$(tail -1 "$BUILD_LOG")"
else
    fail "build failed — likely a verifier rejection"
    tail -20 "$BUILD_LOG" | sed 's/^/        /'
    exit 1
fi

if ! cargo build --features linux --release > /dev/null 2>&1; then
    fail "hakam-node release build failed — rerun manually for the error"
    exit 1
fi
pass "hakam-node release binary built"

# ── 2. Launch hakam-node + capture telemetry ─────────────────────────────────
section "2. Launch + telemetry"

sudo "$NODE_BIN" \
    --iface "$IFACE" \
    --mode skb \
    --bpf-path "$BPF_PATH" \
    --bind 127.0.0.1 \
    --monitor-prefix "$MONITOR_PREFIX" \
    > "$NODE_LOG" 2>&1 &
NODE_PID=$!

# wait up to 10s for "Kernel datapath active"
for _ in $(seq 1 20); do
    if grep -q "Kernel datapath active" "$NODE_LOG" 2>/dev/null; then break; fi
    sleep 0.5
done

if grep -q "Kernel datapath active" "$NODE_LOG"; then
    pass "hakam-node attached XDP / TC / tracepoint to $IFACE"
else
    fail "hakam-node did not announce 'Kernel datapath active' within 10s"
    tail -20 "$NODE_LOG" | sed 's/^/        /'
    exit 1
fi

if grep -q "tracepoint scope" "$NODE_LOG"; then
    pass "B2 banner present (MONITOR_CFG populated)"
else
    fail "B2 banner 'tracepoint scope →' missing from startup output"
fi

websocat -t "$WS_URL" > "$WS_LOG" 2>&1 &
WS_PID=$!
sleep 1

# need a METRICS event to confirm the pipe is live
sleep 2
if grep -q '"type":"METRICS"' "$WS_LOG"; then
    pass "telemetry pipe up (METRICS observed on WS)"
else
    fail "no METRICS event after 2s — telemetry pipe is down"
    exit 1
fi

# ── helpers for probe verification ───────────────────────────────────────────
fire_payload() {
    # $1 = src IP, $2 = raw HTTP payload (already \r\n-terminated)
    printf "%s" "$2" | nc -s "$1" -w 1 "$TARGET_IP" "$TARGET_PORT" 2>/dev/null || true
}

# Returns 0 if a BLOCK with given source + category landed since $1 lines ago.
saw_block() {
    local since="$1" src="$2" cat="$3"
    tail -n +"$((since + 1))" "$WS_LOG" \
        | grep '"type":"BLOCK"' \
        | jq -r --arg s "$src" --arg c "$cat" \
            'select(.source == $s and .category == $c) | .source' 2>/dev/null \
        | grep -q .
}

saw_connect_for() {
    local since="$1" dst="$2"
    tail -n +"$((since + 1))" "$WS_LOG" \
        | grep '"type":"CONNECT"' \
        | jq -r --arg d "$dst" 'select(.dst == $d) | .dst' 2>/dev/null \
        | grep -q .
}

expect_block() {
    local label="$1" src="$2" cat="$3" payload="$4"
    local before; before=$(wc -l < "$WS_LOG")
    fire_payload "$src" "$payload"
    sleep 1
    if saw_block "$before" "$src" "$cat"; then
        pass "$label — BLOCK from $src ($cat)"
    else
        fail "$label — expected BLOCK from $src ($cat) but none seen"
        info "new BLOCK frames in window:"
        tail -n +"$((before + 1))" "$WS_LOG" | grep '"type":"BLOCK"' | head -3 | sed 's/^/        /'
    fi
}

# ── 3. Regression baseline ───────────────────────────────────────────────────
section "3. Regression baseline (existing matches still fire)"

expect_block "classic SQLi" "10.99.1.11" "SQLi" \
    "$(printf 'GET /?q=UNION SELECT 1 HTTP/1.1\r\nHost: %s\r\n\r\n' "$TARGET_IP")"

expect_block "classic XSS" "10.99.1.12" "XSS" \
    "$(printf 'GET /?x=<script>alert(1)</script> HTTP/1.1\r\nHost: %s\r\n\r\n' "$TARGET_IP")"

# ── 4. URL decoding (Phase 1 #2) ─────────────────────────────────────────────
section "4. URL decoding (Phase 1 #2)"

expect_block "%20 URL-encoded SQLi" "10.99.1.13" "SQLi" \
    "$(printf 'GET /?q=UNION%%20SELECT%%201 HTTP/1.1\r\nHost: %s\r\n\r\n' "$TARGET_IP")"

expect_block "+ form-encoded SQLi" "10.99.1.14" "SQLi" \
    "$(printf 'GET /?q=UNION+SELECT+1 HTTP/1.1\r\nHost: %s\r\n\r\n' "$TARGET_IP")"

# ── 5. Split-segment reassembly (Phase 1 #1) ─────────────────────────────────
section "5. Split-segment reassembly (Phase 1 #1)"

src="10.99.1.15"
before=$(wc -l < "$WS_LOG")
{
    printf 'GET /?q=UNI'
    sleep 0.2
    printf 'ON SELECT 1 HTTP/1.1\r\nHost: %s\r\n\r\n' "$TARGET_IP"
} | nc -s "$src" -w 2 "$TARGET_IP" "$TARGET_PORT" 2>/dev/null || true
sleep 2

if saw_block "$before" "$src" "SQLi"; then
    pass "split UNION/SELECT — BLOCK from $src (reassembled view matched)"
elif tail -n +"$((before + 1))" "$WS_LOG" | grep -q '"type":"BLOCK"'; then
    fail "BLOCK fired but not for $src/SQLi — possibly an unrelated block"
else
    fail "no BLOCK — either the reassembler isn't engaging, or the kernel coalesced the two writes into one segment"
    info "to confirm whether the split actually happened, in another terminal run:"
    info "  sudo tcpdump -i $IFACE -n 'host $src'"
    info "then re-fire the probe — two PSH,ACK packets = real split; one = Nagle coalesced"
fi

# ── 6. Tracepoint CIDR scope (B2) ────────────────────────────────────────────
section "6. Tracepoint CIDR scope (B2 — MONITOR_CFG)"

# In-scope: connect to TARGET_IP should produce a CONNECT event.
before=$(wc -l < "$WS_LOG")
printf 'GET / HTTP/1.0\r\n\r\n' | nc -w 1 "$TARGET_IP" "$TARGET_PORT" 2>/dev/null || true
sleep 1
if saw_connect_for "$before" "$TARGET_IP"; then
    pass "in-scope dst $TARGET_IP — CONNECT surfaced"
else
    fail "in-scope dst $TARGET_IP — expected CONNECT but tracepoint did not fire"
fi

# Out-of-scope: connect to OUT_OF_SCOPE_IP should NOT produce a CONNECT event.
before=$(wc -l < "$WS_LOG")
nc -w 1 "$OUT_OF_SCOPE_IP" "$OUT_OF_SCOPE_PORT" 2>/dev/null </dev/null || true
sleep 1
if saw_connect_for "$before" "$OUT_OF_SCOPE_IP"; then
    fail "out-of-scope dst $OUT_OF_SCOPE_IP — CONNECT leaked through the MONITOR_CFG filter"
    info "expected the kernel filter to drop the event before reserving a ring slot"
else
    pass "out-of-scope dst $OUT_OF_SCOPE_IP — filtered by MONITOR_CFG (no CONNECT)"
fi

# ── summary ──────────────────────────────────────────────────────────────────
section "summary"

if [ "$fails" -eq 0 ]; then
    printf "\n  ${GRN}${BOLD}all Phase 1 probes passed.${RST}\n"
    printf "  ${GRY}hakam-node is verified end-to-end; ready for Phase 2 work.${RST}\n\n"
    exit 0
else
    printf "\n  ${RED}${BOLD}%d probe(s) failed.${RST}\n" "$fails"
    printf "  ${YEL}inspect the preserved logs above and re-run individual probes manually.${RST}\n\n"
    exit 1
fi
