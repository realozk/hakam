#!/usr/bin/env bash
# demo-cycle.sh — narrated end-to-end auto-test cycle for the Hakam HUD.
#
# Continuous benign HTTP traffic runs in the background for the whole cycle
# (started once at entry, killed on Ctrl-C). Phases differ only in *attack
# intensity* — the threat level climbs gradually NOMINAL → SEVERE and then
# decays, the way an operator would actually watch an incident unfold:
#
#   PHASE 0  ·  CALM             (15 s)   benign only — clean baseline
#   PHASE 1  ·  PROBING          (40 s)   sparse recon — first anomalies
#   PHASE 2  ·  INVESTIGATION    (48 s)   mixed families ~1/6s
#   PHASE 3  ·  ESCALATION       (40 s)   full family spread ~1/3s
#   PHASE 4  ·  PEAK             (25 s)   sustained ~1.7/s mixed-vector
#   PHASE 5  ·  CONTAINMENT      (30 s)   trickle stragglers, level decays
#   PHASE 6  ·  RECOVERY         (30 s)   no attacks — return to NOMINAL
#
# Total cycle ≈ 228 s (~3 min 50 s). Loops indefinitely; Ctrl-C to stop.
#
# ── Presenter controls ─────────────────────────────────────────────────────
# While the cycle is running, the following keys are live (no Enter needed):
#
#   space    pause / resume                  (countdown freezes; no packets fire)
#   n / N    skip to the next phase
#   r / R    restart the current phase
#   0 … 5    jump to phase N (forward or backward, takes effect immediately)
#   q / Q    quit cleanly
#   ?        re-print the keymap
#
# Flags:
#   --manual          wait for ENTER before starting each phase
#   --start-at N      begin the first cycle at phase N (0–5)
#   -h, --help        this help
#
# Source IPs rotate through the 18-IP demo pool created by setup-demo.sh, so
# the kernel BLOCKLIST never starves the attack stream.

set -uo pipefail

# ── CLI args ───────────────────────────────────────────────────────────────
MANUAL=0
START_AT=0

usage() {
    cat <<'EOF'
hakam demo-cycle — narrated 6-phase auto-test cycle

  --manual          wait for ENTER before starting each phase
  --start-at N      begin the first cycle at phase N (0–5)
  -h, --help        this help

Live keypresses while running:
  space  pause/resume    n  next phase    r  restart phase
  0-6    jump to phase   q  quit          ?  show keymap
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --manual)    MANUAL=1; shift ;;
        --start-at)  START_AT="$2"; shift 2 ;;
        -h|--help)   usage; exit 0 ;;
        *)           echo "unknown arg: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if ! [[ "$START_AT" =~ ^[0-6]$ ]]; then
    echo "--start-at must be 0..6 (got '${START_AT}')" >&2
    exit 2
fi

TARGET="${TARGET:-10.99.0.10}"
PORT="${PORT:-80}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECLIST="${SCRIPT_DIR}/seclist-attack.sh"
BENIGN="${SCRIPT_DIR}/benign-traffic.sh"

# ── Colours ────────────────────────────────────────────────────────────────
RED=$'\033[0;31m'; BRED=$'\033[1;31m'
YLW=$'\033[1;33m'; CYN=$'\033[0;36m'
GRN=$'\033[0;32m'; MAG=$'\033[0;35m'
BLU=$'\033[0;34m'; DIM=$'\033[2m'
BLD=$'\033[1m'  ; RST=$'\033[0m'

# ── Runtime state ──────────────────────────────────────────────────────────
CYCLE=0
PAUSED=0
SKIP_PHASE=0
RESTART_PHASE=0
JUMP_TO=-1
INTERACTIVE=0
[[ -t 0 ]] && INTERACTIVE=1

# ── Source pool used by every fire_*() call ────────────────────────────────
build_source_pool() {
    local pool=()
    local i
    for i in 11 12 13 14 15 16 17 18 19; do pool+=("10.99.1.$i"); done
    for i in 11 12 13 14 15 16 17 18 19; do pool+=("10.99.2.$i"); done
    printf '%s\n' "${pool[@]}"
}

# ── Pretty narration ───────────────────────────────────────────────────────
phase_banner() {
    local n="$1" name="$2" desc="$3" duration="$4" color="$5"
    echo
    echo "  ${color}┌──────────────────────────────────────────────────────────────────────┐${RST}"
    printf "  ${color}│ %-15s ${BLD}%-22s${RST}${color}              %ss   │${RST}\n" "PHASE $n" "$name" "$duration"
    echo "  ${color}└──────────────────────────────────────────────────────────────────────┘${RST}"
    echo "  ${DIM}$desc${RST}"
    echo
}

print_keymap() {
    echo
    echo "  ${BLD}controls${RST}  ${DIM}space=pause · n=next · r=restart · 0-6=jump · q=quit · ?=help${RST}"
    echo
}

# ── Keypress handling ──────────────────────────────────────────────────────
# handle_key() inspects a single character and updates global state.
# poll_keys() waits for $1 seconds while polling stdin every 100 ms; it returns
# 1 if any state-changing key was pressed (skip / restart / jump), 0 otherwise.
# When PAUSED is set, the elapsed deadline is bumped forward so the wait
# effectively freezes — no packets fire while paused.
handle_key() {
    local k="$1"
    case "$k" in
        ' ')
            PAUSED=$((1 - PAUSED))
            if [[ $PAUSED -eq 1 ]]; then
                printf "\r%-72s\r" " "
                echo "  ${YLW}⏸  paused${RST}  ${DIM}(space to resume)${RST}"
            else
                echo "  ${GRN}▶  resumed${RST}"
            fi
            ;;
        n|N) SKIP_PHASE=1 ;;
        r|R) RESTART_PHASE=1 ;;
        [0-6])
            JUMP_TO="$k"
            SKIP_PHASE=1
            echo "  ${CYN}⇥  jump to phase ${k}${RST}"
            ;;
        q|Q)
            echo
            echo "  ${YLW}quit requested — exiting after $CYCLE complete cycle(s).${RST}"
            exit 0
            ;;
        '?') print_keymap ;;
    esac
}

# UI → script command channel. hakam-node appends single-char commands to
# this file when the browser sends a {"type":"DEMO_CMD","action":"..."} WS
# message. We drain + truncate it on every poll tick so commands fire in the
# same path as terminal keypresses.
CMD_FILE="/tmp/hakam-demo.cmd"

# Script → server command channel (the other direction). hakam-node's
# server_cmd_task polls this file every 500 ms and acts on lines it
# recognises (currently: `c` to clear the BLOCKLIST). We use it at the start
# of every cycle so the next round's attacks don't get silently XDP_DROPped
# at entry because their source IPs are still TTL'd from the previous cycle.
SERVER_CMD_FILE="/tmp/hakam-server.cmd"
clear_blocklist() {
    printf 'c\n' >> "$SERVER_CMD_FILE" 2>/dev/null || true
}
poll_cmd_file() {
    [[ -s "$CMD_FILE" ]] || return 0
    local content
    content=$(cat "$CMD_FILE" 2>/dev/null)
    : > "$CMD_FILE" 2>/dev/null
    [[ -z "$content" ]] && return 0
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        handle_key "$line"
    done <<< "$content"
}

poll_keys() {
    local total="$1"
    if [[ $INTERACTIVE -eq 0 ]]; then
        # Even in non-interactive mode (e.g. nohup), still honour UI commands.
        local end_ns
        end_ns=$(( $(date +%s%N) + $(awk -v t="$total" 'BEGIN { printf "%d", t * 1000000000 }') ))
        while [[ $(date +%s%N) -lt $end_ns ]]; do
            poll_cmd_file
            if [[ $SKIP_PHASE -eq 1 || $RESTART_PHASE -eq 1 ]]; then
                return 1
            fi
            sleep 0.1
        done
        return 0
    fi

    # Compute deadline in ns. date +%s%N is GNU-only but jammy / orbstack ship it.
    local end_ns
    end_ns=$(( $(date +%s%N) + $(awk -v t="$total" 'BEGIN { printf "%d", t * 1000000000 }') ))

    local k
    while [[ $(date +%s%N) -lt $end_ns ]]; do
        k=""
        if read -t 0.1 -n 1 -s k 2>/dev/null; then
            handle_key "$k"
        fi
        # UI → script commands arrive via the file channel; check every tick.
        poll_cmd_file
        # Pause is sticky — stay here until the user resumes or quits.
        while [[ $PAUSED -eq 1 ]]; do
            local pk=""
            if read -t 0.5 -n 1 -s pk 2>/dev/null; then
                handle_key "$pk"
            fi
            poll_cmd_file
            # Push the deadline out by the pause window so the timer resumes
            # where the operator left it instead of jumping ahead.
            end_ns=$(( end_ns + 500000000 ))
        done
        if [[ $SKIP_PHASE -eq 1 || $RESTART_PHASE -eq 1 ]]; then
            return 1
        fi
    done
    return 0
}

countdown_to_next() {
    local secs="$1" label="$2"
    local i
    for ((i = secs; i > 0; i--)); do
        printf "\r  ${DIM}%s · %ds${RST}     " "$label" "$i"
        if ! poll_keys 1; then
            printf "\r%-72s\r" " "
            return 1
        fi
    done
    printf "\r%-72s\r" " "
    return 0
}

# ── Attack primitives ──────────────────────────────────────────────────────
# Note: fire_burst and fire_random invoke seclist-attack.sh which sleeps
# internally; key presses during a burst are queued and applied at the next
# countdown / sleep boundary. The longest uninterruptible window is PEAK's
# 100-shot burst (~18 s).
fire_one() {
    local cat="$1"
    local pool
    mapfile -t pool < <(build_source_pool)
    local src="${pool[$RANDOM % ${#pool[@]}]}"

    SOURCES=("$src") "$SECLIST" -k "$cat" -n 1 -d 0 \
        -t "${TARGET}:${PORT}" 2>/dev/null \
        | grep -E "^\s+\[" || true
}

fire_burst() {
    local cat="$1" n="$2" delay_ms="${3:-200}"
    "$SECLIST" -k "$cat" -n "$n" -d "$delay_ms" -t "${TARGET}:${PORT}" 2>/dev/null \
        | grep -E "^\s+\[" || true
}

fire_random() {
    local n="$1" delay_ms="${2:-150}"
    "$SECLIST" -n "$n" -d "$delay_ms" -t "${TARGET}:${PORT}" 2>/dev/null \
        | grep -E "^\s+\[" || true
}

# Persistent benign background generator. Started once at cycle entry and
# killed at cycle exit (or Ctrl-C). Keeps a steady stream of legitimate
# traffic flowing through the HUD for the entire cycle so attacks land *on
# top of* real traffic — the way operators actually see them.
BENIGN_BG_PID=""
start_benign_background() {
    [[ -x "$BENIGN" ]] || return 0
    [[ -n "$BENIGN_BG_PID" ]] && return 0  # already running
    # ~4 requests/s continuous (-d 250) for the whole cycle, output discarded.
    # Fast enough that the LIVE_TRAFFIC sparkline and benign particles always
    # have movement, slow enough not to swamp the rate-limiter.
    "$BENIGN" -c -d 250 -t "${TARGET}:${PORT}" >/dev/null 2>&1 &
    BENIGN_BG_PID=$!
    disown 2>/dev/null || true
}
stop_benign_background() {
    [[ -n "$BENIGN_BG_PID" ]] || return 0
    kill "$BENIGN_BG_PID" 2>/dev/null || true
    BENIGN_BG_PID=""
}
trap 'stop_benign_background; echo; echo "  ${YLW}stopped after $CYCLE complete cycle(s).${RST}"; exit 0' INT

# ── Phases ─────────────────────────────────────────────────────────────────
# Pacing philosophy: every phase has continuous benign traffic running in the
# background. Phases differ only in *attack intensity*. Threat level rises
# gradually (NOMINAL → ELEVATED → GUARDED → HIGH → SEVERE) over ~3 minutes,
# then decays back. No hard spikes — the operator can read every transition.
#
# Each phase function returns early if poll_keys signals an abort (skip /
# restart / jump). run_phase() is the wrapper that reacts to RESTART_PHASE.

phase_0_calm() {
    phase_banner "0" "CALM" \
        "operating baseline — benign traffic only, threat level NOMINAL" \
        "15" "$DIM$BLU"
    # 15 s of clean baseline. With the LIVE_TRAFFIC bar + node benign pulses
    # the operator can see the system is working even without intercepts.
    countdown_to_next 15 "monitoring" || return
}

phase_1_probing() {
    phase_banner "1" "PROBING" \
        "first anomalies — sparse recon hits, single intercepts every ~10s" \
        "40" "$CYN"
    # 4 low-severity hits over 40 s. Reads as "something curious is poking around."
    local cats=( "Recon" "Recon" "SQLi" "Recon" )
    local cat
    for cat in "${cats[@]}"; do
        fire_one "$cat"
        if ! poll_keys 10 ; then return; fi
    done
}

phase_2_investigation() {
    phase_banner "2" "INVESTIGATION" \
        "mixed reconnaissance — varied families, ~one intercept every 6 s" \
        "48" "$YLW"
    # 8 varied hits over 48 s.
    local cats=( "Recon" "SQLi" "XSS" "LFI" "SSRF" "Recon" "NoSQLi" "XXE" )
    local cat
    for cat in "${cats[@]}"; do
        fire_one "$cat"
        if ! poll_keys 6 ; then return; fi
    done
}

phase_3_escalation() {
    phase_banner "3" "ESCALATION" \
        "attacker fans out — full family spread, ~one intercept every 3 s" \
        "40" "$MAG"
    # ~13 hits over 40 s — every attack family represented.
    local cats=( "SQLi" "XSS" "RCE" "LFI" "SSRF" "XXE" "Log4Shell" "NoSQLi" "SSTI" "WebShell" "CVE" "SQLi" "RCE" )
    local cat
    for cat in "${cats[@]}"; do
        fire_one "$cat"
        if ! poll_keys 3 ; then return; fi
    done
}

phase_4_peak() {
    phase_banner "4" "PEAK" \
        "sustained pressure — 40 mixed-vector shots, threat level peaks SEVERE" \
        "25" "$BRED"
    # 40 random shots over ~24 s = ~1.7/s. Less intense than the old 100-shot
    # 18-s firehose so the eye can still follow individual intercepts.
    fire_random 40 600
    if ! poll_keys 1 ; then return; fi
}

phase_5_containment() {
    phase_banner "5" "CONTAINMENT" \
        "attacker rate collapses — sources auto-blocked, rate decays" \
        "30" "$YLW"
    # 3 final stragglers, then quiet. The HUD's threat-level decay shows here.
    fire_one "SQLi"
    if ! poll_keys 10 ; then return; fi
    fire_one "Recon"
    if ! poll_keys 10 ; then return; fi
    fire_one "RCE"
    if ! poll_keys 10 ; then return; fi
}

phase_6_recovery() {
    phase_banner "6" "RECOVERY" \
        "no attacks — benign continues, threat level returns to NOMINAL" \
        "30" "$GRN"
    countdown_to_next 30 "decaying" || return
}

# ── Phase orchestrator ─────────────────────────────────────────────────────
# run_phase honours the MANUAL flag (wait for ENTER before each phase) and
# loops the body when RESTART_PHASE is set.
run_phase() {
    local n="$1"
    local fn="$2"

    if [[ $MANUAL -eq 1 && $INTERACTIVE -eq 1 ]]; then
        echo "  ${DIM}── press ENTER to start phase ${n} ──${RST}"
        local _line
        if ! IFS= read -r _line 2>/dev/null; then
            : # EOF on stdin — fall through and run the phase
        fi
    fi

    while true; do
        SKIP_PHASE=0
        RESTART_PHASE=0
        $fn
        if [[ $RESTART_PHASE -eq 1 ]]; then
            echo "  ${YLW}↻ restarting phase ${n}…${RST}"
            continue
        fi
        break
    done
}

# ── Banner ────────────────────────────────────────────────────────────────
intro_banner() {
    echo
    echo "  ${BRED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
    echo "  ${BRED}  HAKAM DEMO CYCLE${RST}    ${DIM}narrated auto-test for the HUD${RST}"
    echo "  ${BRED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
    echo "  ${DIM}target ${TARGET}:${PORT}  ·  source pool $(build_source_pool | wc -l | tr -d ' ') IPs${RST}"
    if [[ $INTERACTIVE -eq 1 ]]; then
        echo "  ${DIM}controls live · press ${BLD}?${RST}${DIM} for the keymap · Ctrl-C to stop${RST}"
    else
        echo "  ${DIM}stdin not a tty — keypress controls disabled. Ctrl-C to stop.${RST}"
    fi
    [[ $MANUAL   -eq 1 ]] && echo "  ${YLW}manual mode${RST}    ${DIM}each phase waits for ENTER${RST}"
    [[ $START_AT -gt 0 ]] && echo "  ${YLW}start-at ${START_AT}${RST}    ${DIM}first cycle skips earlier phases${RST}"
    echo
}

# ── Pre-flight ─────────────────────────────────────────────────────────────
if [[ ! -x "$SECLIST" ]]; then
    echo "  ${BRED}error${RST} ${SECLIST} not found or not executable" >&2
    exit 1
fi
if [[ ! -x "$BENIGN" ]]; then
    echo "  ${YLW}warning${RST}  ${BENIGN} not found — benign traffic disabled" >&2
fi
if ! ip link show dummy0 &>/dev/null; then
    echo "  ${YLW}warning${RST}  dummy0 not found — run ./scripts/setup-demo.sh first" >&2
fi

intro_banner
print_keymap

# Start the steady benign traffic that runs for the whole cycle.
start_benign_background

# Apply --start-at to the first cycle only.
if [[ $START_AT -gt 0 ]]; then
    JUMP_TO=$START_AT
fi

# Clear the blocklist before the very first cycle too — if hakam-node
# carries state from a previous run, this gives every demo a fresh start.
clear_blocklist

# ── Main loop ──────────────────────────────────────────────────────────────
while true; do
    CYCLE=$((CYCLE + 1))
    echo
    echo "  ${BLD}── cycle $CYCLE ──${RST}"
    # Fresh start every cycle: tell hakam-node to drop all entries so the
    # next round's attacks generate new BLOCK events instead of being
    # silently re-dropped by the BLOCKLIST hot path.
    [[ $CYCLE -gt 1 ]] && clear_blocklist

    n=0
    if [[ $JUMP_TO -ge 0 ]]; then
        n=$JUMP_TO
        JUMP_TO=-1
    fi

    while [[ $n -le 6 ]]; do
        case "$n" in
            0) run_phase 0 phase_0_calm ;;
            1) run_phase 1 phase_1_probing ;;
            2) run_phase 2 phase_2_investigation ;;
            3) run_phase 3 phase_3_escalation ;;
            4) run_phase 4 phase_4_peak ;;
            5) run_phase 5 phase_5_containment ;;
            6) run_phase 6 phase_6_recovery ;;
        esac

        if [[ $JUMP_TO -ge 0 ]]; then
            n=$JUMP_TO
            JUMP_TO=-1
        else
            n=$((n + 1))
        fi
    done
done
