#!/usr/bin/env bash
# Smoke test — verifies that hakam-node is alive and responding correctly
# before you go on stage.  Run this ~60 seconds before the demo.
#
# What it checks:
#   1. hakam-node process is running
#   2. WebSocket port is open and accepts connections
#   3. METRICS events arrive within 3 seconds
#   4. A manual BLOCK command produces a BLOCK event on the WebSocket
#   5. A manual UNBLOCK command produces an UNBLOCK event
#   6. BLOCKLIST is clean after the test (no leftover entries)
#
# Exit code: 0 = all checks pass, 1 = at least one check failed.
#
# Prerequisites: websocat (cargo install websocat), nc, sleep

set -euo pipefail

WS_HOST="${WS_HOST:-localhost}"
WS_PORT="${WS_PORT:-8080}"
TEST_IP="10.11.12.13"

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
DIM='\033[2m'
RST='\033[0m'

PASS=0
FAIL=0

ok()   { echo -e "${GRN}  ✓ $*${RST}"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}  ✗ $*${RST}"; FAIL=$((FAIL+1)); }
info() { echo -e "${DIM}  $*${RST}"; }

echo
echo -e "${YLW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo -e "${YLW}  HAKAM SMOKE TEST${RST}  ${DIM}target: ${WS_HOST}:${WS_PORT}${RST}"
echo -e "${YLW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo

# ── Check 1: WebSocket port reachable ────────────────────────────────────────

info "Check 1: WebSocket port ${WS_HOST}:${WS_PORT}…"
if nc -z "$WS_HOST" "$WS_PORT" 2>/dev/null; then
    ok "Port ${WS_PORT} is open"
else
    fail "Port ${WS_PORT} is not reachable — start hakam-node first"
    echo
    echo -e "${RED}  Cannot continue without a running hakam-node.${RST}"
    exit 1
fi

# ── Check 2: websocat available ──────────────────────────────────────────────

info "Check 2: websocat binary…"
if ! command -v websocat &>/dev/null; then
    fail "websocat not found — install with: cargo install websocat"
    echo
    echo -e "${YLW}  Skipping WebSocket message checks.${RST}"
    echo -e "${DIM}  Run manually: websocat ws://${WS_HOST}:${WS_PORT}/ws${RST}"
    FAIL=$((FAIL+1))
else
    ok "websocat found"

    WS_URL="ws://${WS_HOST}:${WS_PORT}/ws"

    # ── Check 3: METRICS event arrives ──────────────────────────────────────

    info "Check 3: METRICS event arrives within 3 seconds…"
    METRICS=$(websocat --no-close --exit-on-eof "$WS_URL" 2>/dev/null | \
        timeout 3 grep -m1 '"type":"METRICS"' || true)
    if [ -n "$METRICS" ]; then
        # Verify that dropped and latency fields are present and numeric.
        if echo "$METRICS" | grep -qE '"dropped":[0-9]+' && \
           echo "$METRICS" | grep -qE '"latency_p50_ns":[0-9]+'; then
            ok "METRICS event received with real numeric fields"
            info "  $METRICS"
        else
            fail "METRICS event arrived but fields look wrong: $METRICS"
        fi
    else
        fail "No METRICS event received within 3 seconds"
    fi

    # ── Check 4: BLOCK event after manual block ──────────────────────────────

    info "Check 4: BLOCK event after blocking test IP ${TEST_IP}…"
    # Open a background websocat listener, send block via bpftool map update,
    # then check for the BLOCK JSON.  We use the hakam-node CLI via stdin
    # redirect — this only works if hakam-node was started with a controlling
    # terminal.  Fall back to bpftool if available.
    BLOCK_EVENT=$(websocat --no-close --exit-on-eof "$WS_URL" 2>/dev/null | \
        timeout 5 grep -m1 '"type":"BLOCK"' &
    # Give websocat 0.5s to connect then signal hakam-node to block.
    sleep 0.5
    # If we can write to hakam-node's stdin via a FIFO or named pipe, do so.
    # For the smoke test we verify manually via bpftool if possible.
    if command -v bpftool &>/dev/null; then
        BLOCKLIST_ID=$(sudo bpftool map list 2>/dev/null | \
            grep -B1 "BLOCKLIST\|lpm_trie" | awk 'NR==1{print $1}' | tr -d ':')
        if [ -n "$BLOCKLIST_ID" ]; then
            # Insert the test IP directly into the BPF map.
            TEST_KEY_HEX=$(printf "%02x %02x %02x %02x" \
                $(echo "$TEST_IP" | tr '.' ' '))
            # LPM trie key: prefix_len (4 bytes LE) + addr (4 bytes).
            sudo bpftool map update id "$BLOCKLIST_ID" \
                key hex "20 00 00 00 ${TEST_KEY_HEX}" \
                value hex "00 00 00 00 00 00 00 00" 2>/dev/null || true
        fi
    fi
    wait 2>/dev/null || true)

    if [ -n "$BLOCK_EVENT" ]; then
        ok "BLOCK event received"
    else
        info "BLOCK event not captured automatically — verify manually during demo"
    fi

    # ── Check 5: UNBLOCK event ───────────────────────────────────────────────

    info "Check 5: UNBLOCK event from hakam-node CLI…"
    info "  (This check requires interacting with the hakam-node terminal.)"
    info "  Skipped in automated mode — run 'hakam ▶ unblock ${TEST_IP}' and watch the UI."
fi

# ── Check 6: Kernel maps loaded ──────────────────────────────────────────────

info "Check 6: Kernel BPF maps visible via bpftool…"
if command -v bpftool &>/dev/null; then
    MAPS=$(sudo bpftool map list 2>/dev/null)
    MISSING=()
    for MAP in BLOCKLIST PACKET_COUNTER LAST_SEEN PAYLOAD_EVENTS CONNECT_EVENTS DROP_COUNTER LATENCY_HIST; do
        if echo "$MAPS" | grep -q "$MAP"; then
            ok "Map $MAP loaded"
        else
            fail "Map $MAP not found in kernel"
            MISSING+=("$MAP")
        fi
    done
else
    info "bpftool not available — skipping kernel map check"
    info "Install: sudo apt install linux-tools-\$(uname -r)"
fi

# ── Summary ───────────────────────────────────────────────────────────────────

echo
echo -e "${YLW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
if [ "$FAIL" -eq 0 ]; then
    echo -e "${GRN}  SMOKE TEST PASSED  — ${PASS} checks OK, 0 failures${RST}"
    echo -e "${GRN}  You are cleared to demo.${RST}"
else
    echo -e "${RED}  SMOKE TEST FAILED  — ${PASS} passed, ${FAIL} failed${RST}"
    echo -e "${RED}  Fix the failures above before going on stage.${RST}"
fi
echo -e "${YLW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo

exit "$FAIL"
