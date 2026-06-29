#!/usr/bin/env bash
#
# scripts/validate_phase1.sh — Hakam Phase 1 acceptance suite.
#
# Builds the eBPF, launches hakam-node, fires probes that exercise the new
# code paths from docs/arsenal_roadmap.md Phase 1 and docs/core_hardening.md B2,
# then verifies each produced the expected telemetry over the WebSocket bus.
#
#   1.  eBPF build (BPF verifier go/no-go)
#   2.  Launch hakam-node + confirm WS server is sending METRICS
#   3.  Regression — classic single-segment SQLi + XSS still block
#   4.  URL decoding (Phase 1 #2) — %20 + form-encoded `+`
#   5.  Split-segment reassembly (Phase 1 #1)
#   6.  Tracepoint CIDR scope (B2) — in-scope CONNECT surfaces, out-of-scope filtered
#
# Pass: exit 0, every section shows green checkmarks.
# Fail: exit 1, the failing section's diagnostic is printed and the
#       hakam-node log is preserved at /tmp/hakam-validate-node.*.log.
#
# Requires: cargo, nc, websocat, jq (≥ 1.6 for --unbuffered), sudo.
# Network:  scripts/setup-demo.sh must have run (binds 10.99.x.y aliases).
#
# Design notes — why the script is shaped the way it is:
#   * Every websocat invocation is **foreground** inside `$(...)` so it
#     inherits the script's TTY stdin (which never EOFs) — bash backgrounds
#     point child stdin at /dev/null, which trips websocat's --exit-on-eof
#     before the first frame arrives. (Matches scripts/smoke.sh's pattern.)
#   * Each probe pre-schedules its trigger 500 ms in the future via
#     `( sleep 0.5; fire ) &` so websocat has time to subscribe to the
#     broadcast before the kernel event we want to observe is emitted.
#   * `jq --unbuffered | head -1` short-circuits the pipeline on the first
#     matching frame — websocat gets SIGPIPE and exits cleanly.

set -uo pipefail
# Deliberately no -e — nc / connect() probes expect failures.

# ── config (override via env) ────────────────────────────────────────────────
TARGET_IP="${TARGET_IP:-10.99.0.10}"
TARGET_PORT="${TARGET_PORT:-80}"
MONITOR_PREFIX="${MONITOR_PREFIX:-10.99.0.0/16}"
OUT_OF_SCOPE_IP="${OUT_OF_SCOPE_IP:-127.0.0.1}"
OUT_OF_SCOPE_PORT="${OUT_OF_SCOPE_PORT:-9}"
IFACE="${IFACE:-lo}"
WS_HOST="${WS_HOST:-127.0.0.1}"
WS_PORT="${WS_PORT:-8080}"
WS_URL="${WS_URL:-ws://${WS_HOST}:${WS_PORT}/ws}"

BPF_PATH="target/bpfel-unknown-none/release/hakam-ebpf"
NODE_BIN="target/release/hakam-node"

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

cleanup() {
    if [ -n "$NODE_PID" ]; then
        sudo kill -INT "$NODE_PID" 2>/dev/null || true
        sleep 1
        sudo kill -KILL "$NODE_PID" 2>/dev/null || true
    fi
    # Kill the `sleep infinity` we spawned to keep hakam-node's stdin open,
    # plus any orphaned trigger subshells from a probe that's still racing.
    pkill -P $$ 2>/dev/null || true
    # Detach anything left attached if hakam-node didn't get its SIGINT cleanly.
    sudo ip link set dev "$IFACE" xdp off 2>/dev/null || true
    sudo tc qdisc del dev "$IFACE" clsact 2>/dev/null || true

    if [ "$fails" -eq 0 ]; then
        rm -f "$NODE_LOG" "$BUILD_LOG"
    else
        printf "\n${YEL}logs preserved:${RST}\n"
        printf "  build : %s\n" "$BUILD_LOG"
        printf "  node  : %s\n" "$NODE_LOG"
    fi
}
trap cleanup EXIT
# Ctrl-C should abort the whole script, not just the current probe's websocat.
# Bash by default only delivers SIGINT to the foreground command of the
# current job; without this trap the next `expect_block` starts immediately.
trap 'printf "\n${YEL}interrupted${RST}\n"; exit 130' INT

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
require awk

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

# Kill any stale hakam-node from a previous run or a manual `cargo xtask run`
# in another terminal — otherwise it holds port 8080 and our launch can't bind.
if pgrep -x hakam-node >/dev/null 2>&1; then
    warn "another hakam-node is running; stopping it before launching ours"
    sudo pkill -INT -x hakam-node 2>/dev/null || true
    sleep 1
    sudo pkill -KILL -x hakam-node 2>/dev/null || true
fi

# Pre-clean any stale state from a previous run.
sudo ip link set dev "$IFACE" xdp off 2>/dev/null || true
sudo tc qdisc del dev "$IFACE" clsact 2>/dev/null || true

# Warn if there's no TCP listener at the target — probes that fire HTTP at it
# will get RST before sending the payload, so no DPI match will ever happen.
if ! nc -z -w 1 "$TARGET_IP" "$TARGET_PORT" 2>/dev/null; then
    warn "nothing is listening on ${TARGET_IP}:${TARGET_PORT} — probes will fire but no DPI match will trigger"
    warn "start a quick sink before running this script:"
    warn "  while true; do nc -l -s $TARGET_IP -p $TARGET_PORT >/dev/null; done &"
    warn "or use the demo's target listener if you have one"
fi

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

# ── 2. Launch + telemetry ────────────────────────────────────────────────────
section "2. Launch + telemetry"

# Keep hakam-node's stdin open — see header notes for the rationale.
sudo "$NODE_BIN" \
    --iface "$IFACE" \
    --mode skb \
    --bpf-path "$BPF_PATH" \
    --bind "$WS_HOST" \
    --ws-port "$WS_PORT" \
    --monitor-prefix "$MONITOR_PREFIX" \
    < <(sleep infinity) \
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

# Wait for the TCP socket to actually accept before subscribing — the WS
# server is spawned async after the synchronous banners print.
ws_ready=0
for _ in $(seq 1 20); do
    if nc -z "$WS_HOST" "$WS_PORT" 2>/dev/null; then ws_ready=1; break; fi
    sleep 0.5
done
if [ "$ws_ready" -eq 0 ]; then
    fail "WS server never accepted on ${WS_HOST}:${WS_PORT} within 10s"
    info "last 10 lines of node log:"
    tail -10 "$NODE_LOG" | sed 's/^/        /'
    exit 1
fi
pass "WS server accepting on ${WS_HOST}:${WS_PORT}"

# Foreground websocat with two safety belts:
#   * </dev/null — prevents websocat blocking on a TTY stdin read that
#     SIGTERM can't unwind (the kernel keeps the read pending across signals).
#   * timeout -k 2 5 — sends SIGTERM at 5 s, escalates to SIGKILL 2 s later
#     if websocat hasn't exited (SIGKILL is uninterruptible).
# Pipe to awk closes on the first METRICS, websocat gets SIGPIPE and exits.
metrics_line=$(timeout -k 2 5 websocat --no-close "$WS_URL" </dev/null 2>/dev/null \
    | awk '/"type":"METRICS"/{print; exit}')

if [ -n "$metrics_line" ]; then
    pass "telemetry pipe up (METRICS observed on WS)"
else
    fail "no METRICS event after 5s — telemetry pipe is down"
    info "first 20 node-log lines:"
    head -20 "$NODE_LOG" | sed 's/^/        /'
    exit 1
fi

# ── probe helpers ────────────────────────────────────────────────────────────
fire_payload() {
    # $1 = src IP, $2 = raw HTTP payload (already \r\n-terminated)
    printf "%s" "$2" | nc -s "$1" -w 1 "$TARGET_IP" "$TARGET_PORT" 2>/dev/null || true
}

# Subscribe to WS, schedule a payload fire 500ms later, return the first
# matching BLOCK's .source field (empty string if no match within `timeout_s`).
wait_for_block() {
    local timeout_s="$1" src="$2" cat="$3" payload="$4"
    ( sleep 0.5; fire_payload "$src" "$payload" ) &
    local trigger_pid=$!
    # </dev/null + timeout -k 2 — see the METRICS check above for why.
    timeout -k 2 "$timeout_s" websocat --no-close "$WS_URL" </dev/null 2>/dev/null \
        | jq -r --unbuffered --arg s "$src" --arg c "$cat" \
            'select(.type == "BLOCK" and .source == $s and .category == $c) | .source' \
        | head -1
    # Wait ONLY for the trigger subshell — bare `wait` would also block on
    # NODE_PID, which is still alive for the rest of the script.
    wait "$trigger_pid" 2>/dev/null
}

# Wrapper around wait_for_block that prints pass/fail.
expect_block() {
    local label="$1" src="$2" cat="$3" payload="$4"
    local match
    match=$(wait_for_block 5 "$src" "$cat" "$payload")
    if [ -n "$match" ]; then
        pass "$label — BLOCK from $src ($cat)"
    else
        fail "$label — expected BLOCK from $src ($cat) but none seen within 5s"
    fi
}

# Subscribe and listen for any CONNECT event with the given dst; returns the
# first match's .dst (or empty after timeout).
wait_for_connect() {
    local timeout_s="$1" dst="$2" trigger_func="$3"
    ( sleep 0.5; "$trigger_func" ) &
    local trigger_pid=$!
    timeout -k 2 "$timeout_s" websocat --no-close "$WS_URL" </dev/null 2>/dev/null \
        | jq -r --unbuffered --arg d "$dst" \
            'select(.type == "CONNECT" and .dst == $d) | .dst' \
        | head -1
    wait "$trigger_pid" 2>/dev/null
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

split_src="10.99.1.15"

fire_split() {
    {
        printf 'GET /?q=UNI'
        sleep 0.2
        printf 'ON SELECT 1 HTTP/1.1\r\nHost: %s\r\n\r\n' "$TARGET_IP"
    } | nc -s "$split_src" -w 2 "$TARGET_IP" "$TARGET_PORT" 2>/dev/null || true
}

( sleep 0.5; fire_split ) &
split_trigger_pid=$!
split_match=$(timeout -k 2 6 websocat --no-close "$WS_URL" </dev/null 2>/dev/null \
    | jq -r --unbuffered --arg s "$split_src" \
        'select(.type == "BLOCK" and .source == $s and .category == "SQLi") | .source' \
    | head -1)
wait "$split_trigger_pid" 2>/dev/null

if [ -n "$split_match" ]; then
    pass "split UNION/SELECT — BLOCK from $split_src (reassembled view matched)"
else
    fail "no BLOCK for $split_src — reassembler not engaging, or kernel coalesced both writes into one segment"
    info "to tell them apart, in another terminal run:"
    info "  sudo tcpdump -i $IFACE -n 'host $split_src'"
    info "then re-fire — two PSH,ACK packets = real split; one = Nagle coalesced"
fi

# ── 6. Tracepoint CIDR scope (B2) ────────────────────────────────────────────
section "6. Tracepoint CIDR scope (B2 — MONITOR_CFG)"

fire_in_scope()  { printf 'GET / HTTP/1.0\r\n\r\n' | nc -w 1 "$TARGET_IP" "$TARGET_PORT" 2>/dev/null || true; }
fire_out_scope() { nc -w 1 "$OUT_OF_SCOPE_IP" "$OUT_OF_SCOPE_PORT" 2>/dev/null </dev/null || true; }

in_match=$(wait_for_connect 3 "$TARGET_IP" fire_in_scope)
if [ -n "$in_match" ]; then
    pass "in-scope dst $TARGET_IP — CONNECT surfaced"
else
    fail "in-scope dst $TARGET_IP — expected CONNECT but tracepoint did not fire"
fi

out_match=$(wait_for_connect 3 "$OUT_OF_SCOPE_IP" fire_out_scope)
if [ -z "$out_match" ]; then
    pass "out-of-scope dst $OUT_OF_SCOPE_IP — filtered by MONITOR_CFG (no CONNECT)"
else
    fail "out-of-scope dst $OUT_OF_SCOPE_IP — CONNECT leaked through the MONITOR_CFG filter"
    info "expected the kernel filter to drop the event before reserving a ring slot"
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
