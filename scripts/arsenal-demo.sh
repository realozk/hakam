#!/usr/bin/env bash
# arsenal-demo.sh — the Black Hat Arsenal pitch, in three acts.
#
# demo-cycle.sh is the ambient attract-loop that keeps the HUD alive on the
# booth screen. THIS script is the 3-minute pitch you run when a reviewer stops
# walking and gives you their attention. It tells the one story no other
# open-source eBPF firewall can tell — the layered host firewall:
#
#   ACT I   · THE WIRE     — XDP drops the attack in the driver, pre-stack.
#   ACT II  · THE IDENTITY — the block NAMES the originating PID + process.
#   ACT III · THE SYSCALL  — BPF-LSM denies the outbound connect() itself:
#                            the packet is never created — all from one
#                            self-contained host agent, no CNI, no control plane.
#   FINALE  · THE PROOF    — live kernel counters: drops, sub-µs latency,
#                            active conntrack flows, zero false positives.
#
# The pitch, in one sentence:
#   "XDP guards the wire, BPF-LSM guards the syscall, per-flow conntrack ties
#    them together with process identity — three layers, one eBPF firewall."
#
# ── Run order (all on the VM) ───────────────────────────────────────────────
#   ./scripts/setup-demo.sh                    # once per boot
#   cargo xtask run --iface lo --mode skb      # terminal 1 (the console)
#       ^ run as your normal user, NOT with a sudo prefix — xtask builds as you
#         and sudoes only the binary launch itself (it prompts for your password).
#   ./scripts/arsenal-demo.sh                  # terminal 2 (this pitch)
#
# Acts I/II are fully driven here. Act III (the live EPERM) needs ONE line typed
# in the Hakam console (`policy-block <ip>`) — that keystroke IS the demo: you
# are arming the kernel to forbid an exfil path live.
#
# ── Booth attract mode (the unattended screen that hooks passers-by) ─────────
# Run with --loop: the pitch repeats forever, hands-free, driving a steady
# attack stream so the HUD never sits idle — THREATS_NEUTRALIZED climbs, the
# topology pulses, the EVENT_LOG streams BLOCKs with per-process attribution,
# the ATTACK_TIMELINE fills. It never touches kernel policy (nothing to leave
# half-armed between cycles), so Act III degrades to a narration slate — unless
# you pre-armed an exfil IP via `policy-block $LSM_DST` before walking away, in
# which case it shows the live EPERM too.
#
# Flags:
#   --loop        unattended booth attract loop: --auto + repeat + livelier traffic.
#   --auto        hands-free single pass (timed pauses) for screen-recording #16.
#   --fast        halve every pause. Good for a rushed booth window.
#   -h, --help    this help.

set -uo pipefail

# ── Config ──────────────────────────────────────────────────────────────────
TARGET="${TARGET:-10.99.0.10}"          # the "database" the attacker hits / exfils to
PORT="${PORT:-80}"
WS_HOST="${WS_HOST:-localhost}"
WS_PORT="${WS_PORT:-8080}"
WS_URL="ws://${WS_HOST}:${WS_PORT}/ws"

# Framed source identities (must be real dummy0 aliases from setup-demo.sh).
WIRE_SRC="${WIRE_SRC:-10.99.2.17}"      # ACT I  — compromised host on the wire
ID_SRC="${ID_SRC:-10.99.1.13}"          # ACT II — the marquee "SQLi from 10.99.1.13"
# ACT III — the exfil/C2 destination a local process tries to reach. Defaults to
# TARGET (has a listener → clean baseline). For --loop you can point it at a
# dedicated IP and pre-arm `policy-block $LSM_DST` so the booth shows live EPERM
# without ever policy-blocking TARGET (which would break Acts I/II next cycle).
LSM_DST="${LSM_DST:-$TARGET}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECLIST="${SCRIPT_DIR}/seclist-attack.sh"
SERVER_CMD_FILE="/tmp/hakam-server.cmd"

AUTO=0
LOOP=0
PACE=1.0

# ── CLI ─────────────────────────────────────────────────────────────────────
# Print the leading comment block (lines 2 .. just before `set -uo`) as help.
usage() { sed -n '2,/^set -uo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        --loop) LOOP=1; AUTO=1; shift ;;
        --auto) AUTO=1; shift ;;
        --fast) PACE=0.5; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown arg: $1" >&2; usage >&2; exit 2 ;;
    esac
done

# ── Colours ─────────────────────────────────────────────────────────────────
RED=$'\033[0;31m'; BRED=$'\033[1;31m'
YLW=$'\033[1;33m'; CYN=$'\033[0;36m'
GRN=$'\033[0;32m'; MAG=$'\033[0;35m'
BLU=$'\033[0;34m'; DIM=$'\033[2m'
BLD=$'\033[1m'  ; RST=$'\033[0m'

# ── Small helpers ───────────────────────────────────────────────────────────
nap() { sleep "$(awk -v a="$1" -v p="$PACE" 'BEGIN{printf "%.2f", a*p}')"; }

# Presenter gate: ENTER to advance. In --auto, just wait `${1:-5}` scaled secs.
beat() {
    local secs="${1:-5}"
    echo
    if [[ $AUTO -eq 1 ]]; then
        printf "  ${DIM}… continuing in %ss${RST}\n" "$(awk -v a="$secs" -v p="$PACE" 'BEGIN{printf "%.0f", a*p}')"
        nap "$secs"
    else
        printf "  ${DIM}▸ press ${BLD}ENTER${RST}${DIM} for the next beat…${RST} "
        read -r _ 2>/dev/null || true
    fi
}

act_banner() {
    local n="$1" title="$2" sub="$3" color="$4"
    echo
    echo "  ${color}╔══════════════════════════════════════════════════════════════════════╗${RST}"
    printf "  ${color}║  ${BLD}ACT %-4s %-58s${RST}${color}║${RST}\n" "$n" "$title"
    printf "  ${color}║  ${RST}${DIM}%-66s${RST}  ${color}║${RST}\n" "$sub"
    echo "  ${color}╚══════════════════════════════════════════════════════════════════════╝${RST}"
    echo
}

say()  { echo "  ${DIM}$1${RST}"; }
punch(){ echo "  ${BLD}$1${RST}"; }

clear_blocklist() { printf 'c\n' >> "$SERVER_CMD_FILE" 2>/dev/null || true; }

# ── Live WS proof overlay (best-effort) ─────────────────────────────────────
HAVE_WS=0
WS_LOG=""
WS_PID=""
command -v websocat >/dev/null 2>&1 && HAVE_WS=1

ws_start() {
    [[ $HAVE_WS -eq 1 ]] || return 0
    WS_LOG="$(mktemp -t hakam-arsenal.XXXXXX)"
    websocat --no-close --exit-on-eof "$WS_URL" >"$WS_LOG" 2>/dev/null &
    WS_PID=$!
    sleep 0.4   # let the subscription attach before the first attack fires
}

json_str() { sed -n 's/.*"'"$1"'":"\([^"]*\)".*/\1/p' <<<"$2" | tail -n1; }
json_num() { sed -n 's/.*"'"$1"'":\([0-9][0-9]*\).*/\1/p'   <<<"$2" | tail -n1; }

# Pull the freshest BLOCK off the WS feed and render it. Echoes the pid/comm
# when the block carried per-process attribution. With a $1 source-IP filter,
# picks the newest BLOCK from that source specifically — so a background booth
# burst can't steal the narrated line's identity.
show_last_block() {
    local want_src="${1:-}"
    if [[ $HAVE_WS -eq 0 ]]; then
        say "(install websocat for the live overlay — for now watch the Hakam console / HUD)"
        return 0
    fi
    local line src cat sev act pid comm
    local tries=0
    while (( tries < 12 )); do
        if [[ -n "$want_src" ]]; then
            line=$(grep '"type":"BLOCK"' "$WS_LOG" 2>/dev/null | grep "\"source\":\"${want_src}\"" | tail -n1)
        else
            line=$(grep '"type":"BLOCK"' "$WS_LOG" 2>/dev/null | tail -n1)
        fi
        [[ -n "$line" ]] && break
        sleep 0.25; ((tries++))
    done
    if [[ -z "$line" ]]; then
        say "(no BLOCK observed on the feed yet — check the console)"
        return 0
    fi
    src=$(json_str source "$line");   cat=$(json_str category "$line")
    sev=$(json_str severity "$line"); act=$(json_str action "$line")
    pid=$(json_num pid "$line");      comm=$(json_str comm "$line")
    echo
    printf "  ${BRED}▼ BLOCK${RST}  ${BLD}%s${RST}  ${YLW}[%s]${RST}  ${DIM}%s${RST}  ${RED}→ %s${RST}\n" \
        "${src:-?}" "${cat:-?}" "${sev:-?}" "${act:-?}"
    if [[ -n "$pid" && -n "$comm" ]]; then
        printf "  ${MAG}   └─ origin: PID %s / %s${RST}\n" "$pid" "$comm"
    fi
    echo
    # Hand the extracted values back for the narration line.
    LAST_SRC="$src"; LAST_CAT="$cat"; LAST_PID="$pid"; LAST_COMM="$comm"
}

# Fire exactly one attack of category $1 from source IP $2.
# NOTE: SOURCES is passed as a *scalar* env var, not a bash array — an array
# command-prefix does not survive execve into the seclist child process, so it
# would be silently ignored and seclist would pick a random source instead.
# seclist reads it as ${SOURCES[$RANDOM % ${#SOURCES[@]}]}, which resolves a
# scalar to index 0, so a single-IP override lands exactly.
fire_one() {
    local cat="$1" src="$2"
    SOURCES="$src" "$SECLIST" -k "$cat" -n 1 -d 0 -t "${TARGET}:${PORT}" >/dev/null 2>&1 || true
}

# Booth liveliness: fire a short background firehose (seclist's own rotating
# 20-IP pool) so the HUD keeps animating during the narration. Only in auto/loop
# modes — presenter mode stays a clean, readable terminal. Runs detached so it
# never delays a beat.
booth_burst() {
    [[ $AUTO -eq 1 ]] || return 0
    "$SECLIST" -n "${1:-14}" -d 250 -t "${TARGET}:${PORT}" >/dev/null 2>&1 &
}

# Attempt a TCP connect to a destination (default TARGET). Prints timing. Returns:
#   0 = connected   2 = denied (EPERM, "operation not permitted")   1 = other
probe_connect() {
    local dst="${1:-$TARGET}"
    local t0 t1 ms err rc
    t0=$(date +%s%N)
    if command -v curl >/dev/null 2>&1; then
        err=$(curl -sS -o /dev/null --max-time 3 "http://${dst}:${PORT}/" 2>&1); rc=$?
    else
        err=$(nc -w 3 -v "$dst" "$PORT" </dev/null 2>&1); rc=$?
    fi
    t1=$(date +%s%N)
    ms=$(( (t1 - t0) / 1000000 ))
    if grep -qi "not permitted\|operation not permitted\|EPERM" <<<"$err"; then
        printf "  ${BRED}✗ connect() DENIED${RST}  ${DIM}(%s ms)${RST}  ${RED}%s${RST}\n" \
            "$ms" "$(tr -d '\r' <<<"$err" | tail -n1 | head -c 70)"
        return 2
    elif [[ $rc -eq 0 ]]; then
        printf "  ${GRN}✓ connect() OK${RST}         ${DIM}(%s ms) — traffic flows normally${RST}\n" "$ms"
        return 0
    else
        printf "  ${YLW}• connect() failed${RST}     ${DIM}(%s ms, rc=%s) %s${RST}\n" \
            "$ms" "$rc" "$(tr -d '\r' <<<"$err" | tail -n1 | head -c 60)"
        return 1
    fi
}

cleanup() {
    [[ -n "$WS_PID" ]] && kill "$WS_PID" 2>/dev/null
    [[ -n "$WS_LOG" && -f "$WS_LOG" ]] && rm -f "$WS_LOG"
}
trap 'cleanup; echo; echo "  ${YLW}pitch ended.${RST}"; exit 0' INT TERM
trap cleanup EXIT

# ── Preflight ───────────────────────────────────────────────────────────────
preflight() {
    local blockers=0
    echo
    echo "  ${BLD}preflight${RST}"
    if nc -z "$WS_HOST" "$WS_PORT" 2>/dev/null; then
        echo "  ${GRN}✓${RST} hakam-node telemetry reachable on ${WS_HOST}:${WS_PORT}"
    else
        echo "  ${BRED}✗${RST} hakam-node not reachable on ${WS_HOST}:${WS_PORT} — start it first"
        blockers=$((blockers+1))
    fi
    if ip addr show 2>/dev/null | grep -q "inet ${TARGET}/"; then
        echo "  ${GRN}✓${RST} target alias ${TARGET} is up"
    else
        echo "  ${YLW}!${RST} ${TARGET} not found — run ./scripts/setup-demo.sh"
    fi
    if [[ $HAVE_WS -eq 1 ]]; then
        echo "  ${GRN}✓${RST} websocat present — live BLOCK overlay enabled"
    else
        echo "  ${YLW}!${RST} websocat missing — overlay off (cargo install websocat). Console/HUD still shows everything."
    fi
    [[ -x "$SECLIST" ]] || { echo "  ${BRED}✗${RST} ${SECLIST} missing"; blockers=$((blockers+1)); }
    if [[ $blockers -gt 0 ]]; then
        echo
        echo "  ${BRED}${blockers} blocker(s) — fix the above and re-run.${RST}"
        exit 1
    fi
}

# ── Intro ───────────────────────────────────────────────────────────────────
intro() {
    echo
    echo "  ${BRED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
    echo "  ${BRED}${BLD}  HAKAM${RST}${BRED} — the layered host firewall, in three acts${RST}"
    echo "  ${BRED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
    echo
    echo "  ${DIM}Every eBPF firewall drops packets. Hakam does three things at once:${RST}"
    echo "    ${GRN}1.${RST} ${BLD}XDP${RST}     drops the attack ${BLD}in the driver${RST}, before the network stack."
    echo "    ${MAG}2.${RST} ${BLD}Identity${RST} the same drop ${BLD}names the process${RST} that sent it."
    echo "    ${BRED}3.${RST} ${BLD}BPF-LSM${RST}  denies the outbound ${BLD}connect() syscall itself${RST} —"
    echo "               ${DIM}the packet is never created. No other OSS eBPF firewall does this.${RST}"
    echo
    say "target ${TARGET}:${PORT}  ·  telemetry ${WS_URL}"
    [[ $AUTO -eq 1 ]] && say "auto mode — hands-free pacing" || say "presenter mode — ENTER advances each beat"
}

# ── ACT I · THE WIRE ────────────────────────────────────────────────────────
act_one() {
    act_banner "I" "THE WIRE" "XDP drops the attack in the driver — before the kernel parses it" "$GRN"
    clear_blocklist; nap 0.6
    say "A compromised host at ${BLD}${WIRE_SRC}${RST}${DIM} fires a SQL-injection at the database."
    say "There is no userspace proxy in this path. The verdict happens in the NIC driver."
    nap 0.4
    fire_one "SQLi" "$WIRE_SRC"
    show_last_block "$WIRE_SRC"
    punch "That drop cost a few hundred nanoseconds and never touched the network stack."
    booth_burst
    beat 6
}

# ── ACT II · THE IDENTITY ───────────────────────────────────────────────────
act_two() {
    act_banner "II" "THE IDENTITY" "the block names the originating PID + process — not just an IP" "$MAG"
    clear_blocklist; nap 0.6
    say "A firewall that only logs an IP tells you ${BLD}where${RST}${DIM}. Hakam tells you ${BLD}who${RST}${DIM}."
    say "The sys_enter_connect tracepoint records every outbound connect(); when the"
    say "DPI path blocks a flow, per-flow conntrack ties the drop back to the process."
    nap 0.4
    fire_one "SQLi" "$ID_SRC"
    show_last_block "$ID_SRC"
    if [[ -n "${LAST_PID:-}" && -n "${LAST_COMM:-}" ]]; then
        punch "\"blocked ${LAST_CAT:-SQLi} from ${LAST_SRC:-$ID_SRC}, originating PID ${LAST_PID} / ${LAST_COMM}\""
        say "That sentence is the whole pitch. Falco can log the syscall; Cilium can drop the"
        say "packet. Naming the process on the same drop, at line rate, is the differentiator."
    else
        punch "The BLOCK carries PID + comm — see the ${BLD}origin:${RST}${BLD} line in the Hakam console / HUD.${RST}"
        say "(No attribution on the overlay this run — the tracepoint may be CIDR-scoped away"
        say " from ${ID_SRC}, or websocat is off. The console still prints the origin line.)"
    fi
    booth_burst
    beat 7
}

# ── ACT III · THE SYSCALL ───────────────────────────────────────────────────
act_three() {
    act_banner "III" "THE SYSCALL" "BPF-LSM denies the connect() itself — zero packets created" "$BRED"
    say "Now the host is the threat: something on it is trying to beacon out / exfiltrate."
    say "Layers 1-2 kill packets on the wire. Layer 3 kills the ${BLD}syscall${RST}${DIM}."
    echo

    # Loop/booth mode is unattended: never prompt, never toggle kernel policy
    # (a policy-block left armed would break Acts I/II next cycle). Just probe
    # $LSM_DST once — if the operator pre-armed it, show the live EPERM; else
    # narrate the third layer as a slate and move on.
    if [[ $LOOP -eq 1 ]]; then
        probe_connect "$LSM_DST"; local rc=$?
        echo
        if [[ $rc -eq 2 ]]; then
            punch "EPERM — connect() to ${LSM_DST} denied in ~0 ms, before a packet exists."
            say "The exfil connection never forms. TC egress would only drop it AFTER the"
            say "syscall succeeded — the LSM hook denies it DURING the syscall."
        else
            say "Syscall-layer egress denial is live: a CONNECT_POLICY entry makes the LSM"
            say "socket_connect hook return -EPERM, so the connection never forms — the"
            say "packet is never created. (Arm it with ${CYN}policy-block ${LSM_DST}${RST}${DIM} to show it here.)"
        fi
        beat 5
        return
    fi

    # Presenter / single-pass: drive the live EPERM. This may leave $LSM_DST
    # policy-blocked at the end — fine for a one-shot, and we remind you to undo it.
    punch "Baseline — the connection is currently allowed:"
    probe_connect "$LSM_DST" || true
    beat 3

    echo
    punch "Arm the kernel. In the ${BLD}Hakam console${RST}${BLD}, type:${RST}"
    echo "      ${CYN}policy-block ${LSM_DST}${RST}"
    echo
    if [[ $AUTO -eq 1 ]]; then
        say "auto mode: polling up to 20s for the LSM policy to arm…"
    else
        say "Type it, then press ENTER here."
        read -r _ 2>/dev/null || true
    fi

    # Poll until the connect starts returning EPERM (presenter armed the policy).
    # probe_connect returns 2 specifically for "operation not permitted".
    local armed=0 i rc
    for ((i=0; i<40; i++)); do
        probe_connect "$LSM_DST" >/dev/null 2>&1; rc=$?
        if [[ $rc -eq 2 ]]; then armed=1; break; fi
        sleep 0.5
    done

    echo
    punch "Same connection, one rule later:"
    probe_connect "$LSM_DST" || true
    echo
    if [[ $armed -eq 1 ]]; then
        punch "EPERM — returned in ~0 ms, before connect() ever built a packet."
        say "TC egress would have dropped the packet AFTER the syscall succeeded. The LSM"
        say "hook denies it DURING the syscall. The exfil connection simply never forms."
    else
        say "If that still connected: the LSM hook isn't enforcing — the kernel likely lacks"
        say "CONFIG_BPF_LSM=y or 'bpf' in /sys/kernel/security/lsm (Hakam degrades to"
        say "observe-only and says so at startup). The XDP + attribution story stands regardless."
    fi
    echo
    say "Restore it — in the console: ${CYN}policy-unblock ${LSM_DST}${RST}"
    beat 6
}

# ── FINALE · THE PROOF ──────────────────────────────────────────────────────
finale() {
    act_banner "IV" "THE PROOF" "live kernel counters — nothing here is fabricated" "$CYN"
    # The "type stats" call-to-action is for a live presenter; skip it in the
    # unattended booth loop where the HUD itself is the proof on screen.
    if [[ $LOOP -eq 0 ]]; then
        say "In the ${BLD}Hakam console${RST}${DIM}, type ${CYN}stats${RST}${DIM}. Narrate four numbers:"
        echo
        echo "    ${BLD}active flows${RST}      ${DIM}— live eBPF conntrack table (kernel, not userspace)${RST}"
        echo "    ${BLD}kernel drops${RST}      ${DIM}— every XDP_DROP / TC_ACT_SHOT this session${RST}"
        echo "    ${BLD}drop latency p50/p99${RST} ${DIM}— sub-microsecond, measured in-kernel${RST}"
        echo "    ${BLD}benign passed${RST}     ${DIM}— legitimate traffic, zero false positives${RST}"
        echo
        say "For a side terminal that proves the HUD isn't lying:"
        echo "      ${CYN}./scripts/bpftrace-overlay.sh drops${RST}   ${DIM}(reads the counters straight from the kernel)${RST}"
        echo
    fi
    echo "  ${BRED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
    echo "  ${BLD}  XDP guards the wire. BPF-LSM guards the syscall. Conntrack ties them${RST}"
    echo "  ${BLD}  together with process identity. Three layers, one eBPF firewall.${RST}"
    echo "  ${BRED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
    echo
}

# ── Main ────────────────────────────────────────────────────────────────────
preflight
intro
beat 5
ws_start

if [[ $LOOP -eq 1 ]]; then
    # Unattended booth attract loop. Repeats until Ctrl-C; the HUD stays alive.
    cycle=0
    while true; do
        cycle=$((cycle + 1))
        echo
        echo "  ${DIM}── attract cycle ${cycle} ──${RST}"
        clear_blocklist   # fresh sources each cycle so blocks keep re-firing
        act_one
        act_two
        act_three
        finale
        nap 4
    done
else
    act_one
    act_two
    act_three
    finale
fi
