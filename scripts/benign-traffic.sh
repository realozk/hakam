#!/usr/bin/env bash
# benign-traffic.sh — fires legitimate HTTP requests to demonstrate Hakam's
# zero false-positive rate during the demo.
#
# Uses a dedicated source pool (10.99.3.x) that never overlaps with the attack
# pool (10.99.1.x / 10.99.2.x), so a blocked attacker never silences real users.
#
# Usage:
#   ./scripts/benign-traffic.sh                  # 20 requests, 400ms apart
#   ./scripts/benign-traffic.sh -n 50            # 50 requests
#   ./scripts/benign-traffic.sh -c               # continuous (Ctrl-C to stop)
#   ./scripts/benign-traffic.sh -d 500           # 500ms between requests
#   ./scripts/benign-traffic.sh -t 10.99.0.10:80

set -uo pipefail

TARGET_IP="${TARGET_IP:-10.99.0.10}"
TARGET_PORT="${TARGET_PORT:-80}"

# Dedicated benign source pool — setup-demo.sh adds these as dummy0 aliases.
SOURCES=()
for i in 10 11 12 13 14 15 16 17 18 19; do SOURCES+=("10.99.3.$i"); done

DELAY_MS=400
COUNT=20
CONTINUOUS=0

GRN=$'\033[0;32m'; CYN=$'\033[0;36m'; DIM=$'\033[2m'; BLD=$'\033[1m'; RST=$'\033[0m'

usage() {
    cat <<EOF
hakam benign-traffic — legitimate HTTP traffic to prove zero false positives

  -n N         requests to send (default ${COUNT})
  -c           continuous mode (Ctrl-C to stop)
  -d MS        delay between requests in ms (default ${DELAY_MS})
  -t IP:PORT   target (default ${TARGET_IP}:${TARGET_PORT})
  -h           help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -n)       COUNT="$2"; shift 2 ;;
        -c)       CONTINUOUS=1; shift ;;
        -d)       DELAY_MS="$2"; shift 2 ;;
        -t)       TARGET_IP="${2%%:*}"; TARGET_PORT="${2##*:}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown arg: $1" >&2; usage >&2; exit 2 ;;
    esac
done

# Clean paths — none match any Hakam signature pattern.
PATHS=(
    "/"
    "/home"
    "/products"
    "/products/42"
    "/api/v1/users?page=1&limit=10"
    "/api/v1/orders?status=pending"
    "/health"
    "/metrics"
    "/about"
    "/contact"
    "/blog/post/1"
    "/search?q=laptops"
    "/dashboard"
    "/profile?id=7"
    "/settings"
    "/checkout?step=1"
    "/api/v1/items?category=electronics&sort=price"
    "/favicon.ico"
    "/robots.txt"
    "/sitemap.xml"
    "/api/v1/auth/session"
    "/cart"
    "/wishlist"
    "/api/v1/recommendations?user=42"
)

UAS=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15"
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
    "curl/8.4.0"
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148"
)

fire_benign() {
    local path src ua
    path="${PATHS[$RANDOM % ${#PATHS[@]}]}"
    src="${SOURCES[$RANDOM % ${#SOURCES[@]}]}"
    ua="${UAS[$RANDOM % ${#UAS[@]}]}"

    printf "  ${DIM}[%(%H:%M:%S)T]${RST}  ${GRN}%-10s${RST}  ${DIM}%s →${RST} ${CYN}%s${RST}\n" \
        -1 "benign" "$src" "${TARGET_IP}:${TARGET_PORT}"
    printf "    ${DIM}%s${RST}\n" "$path"

    {
        printf 'GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\n\r\n' \
            "$path" "$TARGET_IP" "$ua"
    } | nc -s "$src" -w 1 "$TARGET_IP" "$TARGET_PORT" >/dev/null 2>&1 &
}

echo
echo "  ${GRN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo "  ${GRN}  HAKAM BENIGN TRAFFIC${RST}    ${DIM}target ${TARGET_IP}:${TARGET_PORT} · ${#SOURCES[@]} source IPs${RST}"
echo "  ${GRN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
[[ $CONTINUOUS -eq 1 ]] && echo "  ${DIM}mode:${RST}   ${BLD}continuous${RST} ${DIM}(Ctrl-C to stop)${RST}"
[[ $CONTINUOUS -eq 0 ]] && echo "  ${DIM}mode:${RST}   ${BLD}${COUNT}${RST} requests, ${BLD}${DELAY_MS}${RST}ms apart"
echo

trap 'echo; echo "  ${GRN}stopped — sent $SENT benign requests${RST}"; exit 0' INT

SENT=0
SLEEP_SECS=$(awk -v ms="$DELAY_MS" 'BEGIN{printf "%.3f", ms/1000}')

while true; do
    fire_benign
    SENT=$((SENT + 1))
    [[ $CONTINUOUS -eq 0 && $SENT -ge $COUNT ]] && break
    sleep "$SLEEP_SECS"
done

echo
echo "  ${GRN}━━ done ━━${RST}  sent ${BLD}${SENT}${RST} benign requests · run ${BLD}stats${RST} in hakam-node to see benign_passed"
echo
