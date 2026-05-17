#!/usr/bin/env bash
# evasion-test.sh — fires 30 payload mutations through a running Hakam instance
# and reports HIT (blocked) or MISS (evaded) for each one.
#
# Mutations span 10 techniques: case folding, URL encoding, SQL comment injection,
# whitespace variants, null byte, payload offset, HTTP method, plus encoding,
# unicode, and post-body position.
#
# Requirements:
#   - hakam-node running (cargo xtask run --iface lo --mode skb)
#   - dummy0 up with aliases from setup-demo.sh
#   - websocat (cargo install websocat)
#
# Usage:
#   ./scripts/evasion-test.sh
#   TARGET=10.99.0.10 WS_PORT=8080 ./scripts/evasion-test.sh

set -uo pipefail

TARGET="${TARGET:-10.99.0.10}"
PORT="${PORT:-80}"
WS_HOST="${WS_HOST:-localhost}"
WS_PORT="${WS_PORT:-8080}"
IFACE="${IFACE:-lo}"

RED=$'\033[0;31m'; BRED=$'\033[1;31m'
GRN=$'\033[0;32m'; YLW=$'\033[1;33m'; CYN=$'\033[0;36m'
DIM=$'\033[2m'  ; BLD=$'\033[1m'  ; RST=$'\033[0m'

# ── Prerequisites ──────────────────────────────────────────────────────────
if ! command -v websocat >/dev/null; then
    echo "  ${RED}error${RST} websocat not found — install with: cargo install websocat" >&2
    exit 1
fi
if ! (echo > /dev/tcp/"${WS_HOST}"/"${WS_PORT}") 2>/dev/null; then
    echo "  ${RED}error${RST} hakam-node not reachable on ${WS_HOST}:${WS_PORT}" >&2
    echo "  ${DIM}start it first: cargo xtask run --iface lo --mode skb${RST}" >&2
    exit 1
fi

# ── Evasion source pool — 30 unique IPs, one per test ─────────────────────
# Added transiently; removed on exit so they don't pollute the demo network.
POOL=()
for i in $(seq 1 30); do POOL+=("10.99.4.$i"); done

setup_pool() {
    local added=0
    for ip in "${POOL[@]}"; do
        sudo ip addr add "$ip/24" dev "$IFACE" 2>/dev/null && added=$((added+1)) || true
    done
    echo "  ${DIM}evasion pool: ${added} IPs added to ${IFACE}${RST}"
}

teardown_pool() {
    for ip in "${POOL[@]}"; do
        sudo ip addr del "$ip/24" dev "$IFACE" 2>/dev/null || true
    done
}

trap teardown_pool EXIT

# ── Detection ─────────────────────────────────────────────────────────────
# Fires a mutation from $src and returns HIT or MISS based on whether a BLOCK
# event containing $src arrives on the WebSocket within 2.5 seconds.
fire_and_detect() {
    local src="$1" method="$2" path="$3"
    local tmpf
    tmpf=$(mktemp)

    # Listen for a BLOCK event mentioning this source IP.
    timeout 2.5 websocat "ws://${WS_HOST}:${WS_PORT}/ws" 2>/dev/null \
        | grep --line-buffered '"BLOCK"' \
        | grep -m1 -F "\"${src}\"" >> "$tmpf" &
    local pid=$!

    sleep 0.15  # give listener time to connect and handshake

    # Send the HTTP request from the evasion source IP.
    {
        printf '%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: hakam-evasion-test/1.0\r\n\r\n' \
            "$method" "$path" "$TARGET"
    } | nc -s "$src" -w 1 "$TARGET" "$PORT" >/dev/null 2>&1 || true

    wait "$pid" 2>/dev/null || true

    local result="MISS"
    [[ -s "$tmpf" ]] && result="HIT"
    rm -f "$tmpf"
    echo "$result"
}

# ── Test runner ────────────────────────────────────────────────────────────
HITS=0; MISSES=0; UNEXPECTED=0; N=0

run() {
    local expected="$1" technique="$2" label="$3" method="$4" path="$5"
    N=$((N+1))
    local src="${POOL[$((N-1))]}"

    local result
    result=$(fire_and_detect "$src" "$method" "$path")

    local rcol="$GRN"
    [[ "$result" == "MISS" ]] && rcol="$YLW"

    local marker
    if [[ "$result" == "$expected" ]]; then
        marker="${DIM}✓${RST}"
        [[ "$result" == "HIT"  ]] && HITS=$((HITS+1))
        [[ "$result" == "MISS" ]] && MISSES=$((MISSES+1))
    else
        marker="${RED}✗ UNEXPECTED${RST}"
        UNEXPECTED=$((UNEXPECTED+1))
    fi

    printf "  %2d  ${rcol}%-4s${RST}  %-22s  %-45s  %s\n" \
        "$N" "$result" "$technique" "$label" "$marker"
}

# ── Banner ────────────────────────────────────────────────────────────────
echo
echo "  ${BRED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo "  ${BRED}  HAKAM EVASION TEST${RST}    ${DIM}target ${TARGET}:${PORT} · ws://localhost:${WS_PORT}${RST}"
echo "  ${BRED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo
printf "  %2s  %-4s  %-22s  %-45s  %s\n" "#" "RSLT" "TECHNIQUE" "MUTATION" "EXPECTED"
printf "  %s\n" "$(printf '─%.0s' {1..90})"

setup_pool
echo

# ── 30 mutations ──────────────────────────────────────────────────────────

# ── Technique 1: Case folding — Hakam CATCHES these ─────────────────────
run HIT  "case fold"      "lowercase union select"        GET "/?x=union select 1,2 from users"
run HIT  "case fold"      "mixed case UnIoN SeLeCt"       GET "/?x=UnIoN SeLeCt 1,2"
run HIT  "case fold"      "lowercase <script>"            GET "/?x=<script>alert(1)"
run HIT  "case fold"      "mixed case <sCrIpT>"           GET "/?x=<sCrIpT>alert(1)"
run HIT  "case fold"      "lowercase javascript:"         GET "/?x=javascript:alert(1)"
run HIT  "case fold"      "lowercase ' or '1'='1"         GET "/?x=' or '1'='1"
run HIT  "case fold"      "lowercase ;whoami"             GET "/?cmd=;whoami"

# ── Technique 2: LFI URL encoding — Hakam CATCHES these (sigs included) ─
run HIT  "URL-enc LFI"   "..%2F path traversal"          GET "/..%2F..%2Fetc%2Fpasswd"
run HIT  "URL-enc LFI"   "%2E%2E%2F traversal"           GET "/%2E%2E%2Fetc%2Fpasswd"
run HIT  "URL-enc LFI"   "%252E%252E double-encoded"     GET "/%252E%252Eetc/passwd"

# ── Technique 3: SQLi URL encoding — Hakam MISSES these ─────────────────
run MISS "URL encode"    "UNION%20SELECT (space encoded)" GET "/?x=UNION%20SELECT%201"
run MISS "URL encode"    "%27%20OR%20%27 (full encode)"  GET "/?x=%27%20OR%20%271%27%3D%271"
run MISS "URL encode"    "%3Cscript%3E (tag encoded)"    GET "/?x=%3Cscript%3Ealert(1)"
run MISS "URL encode"    "UNION%2520SELECT (dbl-encode)"  GET "/?x=UNION%2520SELECT"

# ── Technique 4: SQL comment injection ────────────────────────────────────
run MISS "SQL comment"   "UNION/**/SELECT"               GET "/?x=UNION/**/SELECT 1"
run MISS "SQL comment"   "UN/*x*/ION SELECT (split)"     GET "/?x=UN/*x*/ION SELECT 1"
run MISS "SQL comment"   "' OR/**/1=1--"                 GET "/?x=' OR/**/1=1--"

# ── Technique 5: Whitespace variants ──────────────────────────────────────
run MISS "whitespace"    "UNION<TAB>SELECT"              GET $'/?x=UNION\tSELECT 1'
run MISS "whitespace"    "UNION<LF>SELECT"               GET $'/?x=UNION\nSELECT 1'
run MISS "whitespace"    "UNION  SELECT (double space)"  GET "/?x=UNION  SELECT 1"

# ── Technique 6: Null byte injection ──────────────────────────────────────
run MISS "null byte"     "UNION<NUL>SELECT"              GET $'/?x=UNION\x00SELECT'
run MISS "null byte"     "<SCR<NUL>IPT>"                 GET $'/?x=<SCR\x00IPT>alert(1)'

# ── Technique 7: Payload offset beyond 64-byte capture window ─────────────
# Path: GET + / + 59 a's pushes ?x= to byte 64 — attack outside window.
run MISS "payload offset" "attack at byte 65 (past cap)" GET "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?x=UNION SELECT"

# ── Technique 8: Non-standard HTTP methods ────────────────────────────────
run MISS "HTTP method"   "PROPFIND with SQLi"            PROPFIND "/?x=UNION SELECT 1"
run MISS "HTTP method"   "MKCOL with XSS"                MKCOL    "/?x=<script>alert(1)"

# ── Technique 9: Plus-encoding & other substitutions ──────────────────────
run MISS "plus encode"   "UNION+SELECT (plus as space)"  GET "/?x=UNION+SELECT+1"
run MISS "plus encode"   "%2B (encoded plus in value)"   GET "/?x=UNION%2BSELECT%2B1"

# ── Technique 10: Unicode & entity encoding ───────────────────────────────
# Fullwidth UNION (ｕｎｉｏｎ) — not ASCII, to_ascii_uppercase() leaves unchanged.
run MISS "unicode"       "fullwidth ｕｎｉｏｎ ｓｅｌｅｃｔ" GET "/?x=$(printf '\xef\xbc\x95\xef\xbc\xae\xef\xbc\xa9\xef\xbc\xaf\xef\xbc\xae \xef\xbc\xb3\xef\xbc\xa5\xef\xbc\xac\xef\xbc\xa5\xef\xbc\xa3\xef\xbc\xb4')"
run MISS "HTML entity"   "&#85;NION SELECT (U encoded)"  GET "/?x=&#85;NION SELECT 1"
run MISS "hex SQL"       "0x554e494f4e hex literal"      GET "/?x=0x554e494f4e2053454c454354"

# ── Summary ───────────────────────────────────────────────────────────────
echo
echo "  ${BLD}━━ summary ━━${RST}"
echo "    ${GRN}${HITS} blocked (HIT)${RST}   ${YLW}${MISSES} evaded (MISS)${RST}   ${RED}${UNEXPECTED} unexpected${RST}"
echo
if [[ $UNEXPECTED -gt 0 ]]; then
    echo "  ${RED}${BLD}${UNEXPECTED} result(s) differed from expected — review above.${RST}"
else
    echo "  ${DIM}all results matched expected — table in docs/evasion.md is accurate.${RST}"
fi
echo
echo "  ${DIM}commit output: cat docs/evasion.md for the Q&A-ready table.${RST}"
echo
