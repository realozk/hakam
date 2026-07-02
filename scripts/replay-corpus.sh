#!/usr/bin/env bash
# Replay the in-repo attack PCAP corpus against a running hakam-node and confirm
# each capture is blocked — a "clone → replay → watch it block" demo in seconds.
#
# Usage:
#   1. Start hakam-node on an interface (fresh, so the blocklist is empty):
#        cargo xtask run --iface lo --mode skb   # run as your user, no sudo prefix
#        # (xtask sudoes only the binary launch; it prompts for your password)
#        # or a packaged deploy: sudo systemctl start hakam   /   docker run …
#   2. Replay the corpus:
#        ./scripts/replay-corpus.sh
#
# Requires: tcpreplay, websocat, and a running hakam-node with its telemetry
# WebSocket on :8080. Replays onto $IFACE (default lo) — match the node's iface.
#
# Each capture carries its attack in one HTTP request from a fixed source IP; the
# expected block source + category are pinned below so the run is a real assertion.

set -uo pipefail

IFACE="${IFACE:-lo}"
WS_HOST="${WS_HOST:-127.0.0.1}"
WS_PORT="${WS_PORT:-8080}"
WS_URL="ws://${WS_HOST}:${WS_PORT}/ws"
CORPUS="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/corpus/pcaps"

GRN=$'\033[0;32m'; RED=$'\033[0;31m'; YEL=$'\033[1;33m'; DIM=$'\033[2m'; RST=$'\033[0m'

# pcap basename → "expected_source expected_category"
ORDER=(sqli-union xss-script path-traversal cmd-injection)
declare -A EXPECT=(
    [sqli-union]="10.99.2.11 SQLi"
    [xss-script]="10.99.2.12 XSS"
    [path-traversal]="10.99.2.13 LFI"
    [cmd-injection]="10.99.2.14 LFI"
)

command -v tcpreplay >/dev/null || { echo "${RED}tcpreplay not found — sudo apt install tcpreplay${RST}"; exit 1; }
command -v websocat  >/dev/null || { echo "${RED}websocat not found — cargo install websocat${RST}"; exit 1; }
if ! nc -z "$WS_HOST" "$WS_PORT" 2>/dev/null; then
    echo "${RED}hakam-node WebSocket not reachable on ${WS_HOST}:${WS_PORT}.${RST}"
    echo "  Start it first (see this script's header), then re-run."
    exit 1
fi

echo
echo "  ${YEL}▸ Replaying attack corpus against hakam-node (iface=${IFACE})${RST}"
echo "  ${DIM}────────────────────────────────────────────────────────────${RST}"

pass=0; fail=0
for name in "${ORDER[@]}"; do
    pcap="$CORPUS/$name.pcap"
    read -r src cat <<<"${EXPECT[$name]}"
    [ -f "$pcap" ] || { echo "  ${RED}✗ $name — pcap missing${RST}"; fail=$((fail+1)); continue; }

    # Watch the WS for the expected BLOCK while we replay.
    match=$(
        ( sleep 0.6; sudo tcpreplay -i "$IFACE" "$pcap" >/dev/null 2>&1 ) &
        timeout 5 websocat --no-close "$WS_URL" </dev/null 2>/dev/null \
            | grep -m1 -oE "\"type\":\"BLOCK\"[^}]*\"source\":\"$src\"[^}]*\"category\":\"$cat\""
    )
    if [ -n "$match" ]; then
        echo "  ${GRN}✓ $name${RST}  ${DIM}→ BLOCK $src / $cat${RST}"
        pass=$((pass+1))
    else
        echo "  ${RED}✗ $name${RST}  ${DIM}(no BLOCK for $src/$cat — already blocked? restart hakam-node)${RST}"
        fail=$((fail+1))
    fi
done

echo "  ${DIM}────────────────────────────────────────────────────────────${RST}"
if [ "$fail" -eq 0 ]; then
    echo "  ${GRN}all ${pass} captures blocked${RST}"; echo; exit 0
else
    echo "  ${RED}${fail} failed${RST}, ${GRN}${pass} passed${RST}"; echo; exit 1
fi
