#!/usr/bin/env bash
# Live bpftrace overlay — runs raw kernel counters in a side terminal during the demo.
# Every number shown here is read directly from the kernel, proving the UI is not lying.
#
# Usage: ./scripts/bpftrace-overlay.sh [mode]
#
# Modes:
#   drops    — count XDP_DROP events per second (default)
#   latency  — histogram of XDP program run time in nanoseconds
#   connects — trace every outbound connect() with PID and comm
#   all      — print instructions for running all three in separate panes

set -euo pipefail

MODE="${1:-drops}"

RED='\033[0;31m'
CYN='\033[0;36m'
YLW='\033[1;33m'
RST='\033[0m'

check_bpftrace() {
    if ! command -v bpftrace &>/dev/null; then
        echo -e "${RED}bpftrace not found.${RST}"
        echo "Install: sudo apt install bpftrace"
        echo "Or from source: https://github.com/bpftrace/bpftrace"
        exit 1
    fi
}

case "$MODE" in

# ── drops: XDP drop rate per second ──────────────────────────────────────────
drops)
    check_bpftrace
    echo -e "${YLW}  HAKAM OVERLAY — XDP drop counter (per second)${RST}"
    echo -e "${CYN}  Source: kernel tracepoint xdp:xdp_exception + bpf_prog events${RST}"
    echo -e "  Press Ctrl-C to stop."
    echo
    sudo bpftrace -e '
tracepoint:xdp:xdp_exception
{
    @drops = count();
}

interval:s:1
{
    printf("drops/s: %lld\n", @drops);
    clear(@drops);
}
'
    ;;

# ── latency: XDP program execution time histogram ────────────────────────────
latency)
    check_bpftrace
    echo -e "${YLW}  HAKAM OVERLAY — XDP program execution latency${RST}"
    echo -e "${CYN}  Source: kprobe on xdp_do_redirect / bpf_prog_run${RST}"
    echo -e "  Press Ctrl-C to stop and print histogram."
    echo
    # bpf_prog_run_xdp is the internal kernel function called for each XDP program.
    # The histogram shows how long the XDP program takes end-to-end in nanoseconds.
    sudo bpftrace -e '
kprobe:bpf_prog_run_xdp
{
    @start[tid] = nsecs;
}

kretprobe:bpf_prog_run_xdp
/@start[tid]/
{
    @latency_ns = hist(nsecs - @start[tid]);
    delete(@start[tid]);
}

END
{
    print(@latency_ns);
}
'
    ;;

# ── connects: outbound connect() with process info ───────────────────────────
connects)
    check_bpftrace
    echo -e "${YLW}  HAKAM OVERLAY — outbound connect() by process${RST}"
    echo -e "${CYN}  Source: tracepoint syscalls:sys_enter_connect${RST}"
    echo -e "  Every outbound IPv4 TCP/UDP connection attempt is logged here."
    echo
    sudo bpftrace -e '
tracepoint:syscalls:sys_enter_connect
{
    $sa = (struct sockaddr *)args->uservaddr;
    if ($sa->sa_family == 2) {   /* AF_INET */
        $sin = (struct sockaddr_in *)args->uservaddr;
        $ip  = ntop($sin->sin_addr.s_addr);
        $port = (($sin->sin_port & 0xff) << 8) | (($sin->sin_port >> 8) & 0xff);
        printf("%-20s  PID %-7d  →  %s:%d\n", comm, pid, $ip, $port);
    }
}
'
    ;;

# ── all: instructions for running all three ──────────────────────────────────
all)
    echo -e "${YLW}  Open three separate terminals and run one command in each:${RST}"
    echo
    echo -e "  Terminal 1 — drop counter:"
    echo -e "    ${CYN}sudo ./scripts/bpftrace-overlay.sh drops${RST}"
    echo
    echo -e "  Terminal 2 — latency histogram:"
    echo -e "    ${CYN}sudo ./scripts/bpftrace-overlay.sh latency${RST}"
    echo
    echo -e "  Terminal 3 — process-aware connect log:"
    echo -e "    ${CYN}sudo ./scripts/bpftrace-overlay.sh connects${RST}"
    echo
    echo -e "  Or use tmux split panes:"
    echo -e "    ${CYN}tmux new-session \\; \\"
    echo -e "      split-window -h 'sudo ./scripts/bpftrace-overlay.sh drops' \\; \\"
    echo -e "      split-window -v 'sudo ./scripts/bpftrace-overlay.sh connects'${RST}"
    echo
    ;;

*)
    echo "Usage: $0 [drops|latency|connects|all]"
    exit 1
    ;;
esac
