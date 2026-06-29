#!/usr/bin/env bash
# preflight.sh — pre-stage health check for a Hakam demo.
#
# Run this on the Mac ~60 seconds before going on stage. It walks every
# moving part — Mac tools, VM tools, kernel modules, build artifacts, ports,
# Mac↔VM reachability — and emits a single PASS/FAIL verdict.
#
# Exit code:
#   0  → every check that matters is green
#   1  → at least one blocker failed
#
# Output:
#   ✓ green    PASS
#   !  yellow  WARN  (cosmetic; does not affect exit code)
#   ✗ red      FAIL  (blocker)

set -uo pipefail

VM_NAME="${VM_NAME:-hakam}"
VM_PROJECT_PATH="${VM_PROJECT_PATH:-/Users/omaralzhrani/hakam}"
WS_PORT="${WS_PORT:-8080}"

# ── Colours ────────────────────────────────────────────────────────────────
GRN=$'\033[0;32m'; YLW=$'\033[1;33m'; CYN=$'\033[0;36m'
DIM=$'\033[2m'  ; BLD=$'\033[1m'  ; RED=$'\033[0;31m'
BRED=$'\033[1;31m'; RST=$'\033[0m'

PASS=0
WARN=0
FAIL=0

ok()   { printf "  ${GRN}✓${RST} %s\n"  "$1";          PASS=$((PASS+1)); }
warn() { printf "  ${YLW}!${RST} %s ${DIM}%s${RST}\n" "$1" "${2-}"; WARN=$((WARN+1)); }
fail() { printf "  ${RED}✗${RST} %s ${DIM}%s${RST}\n" "$1" "${2-}"; FAIL=$((FAIL+1)); }
hdr()  { echo;  printf "  ${BLD}%s${RST}\n" "$1"; printf "  ${DIM}%s${RST}\n" "$(printf '─%.0s' {1..68})"; }
fix()  { printf "    ${DIM}fix:${RST} ${CYN}%s${RST}\n" "$1"; }

orb_run() {
    # Wraps `orb -m VM_NAME bash -lc <cmd>`. Returns the command's exit code.
    orb -m "$VM_NAME" bash -lc "$1"
}

orb_ok() {
    # Convenience: runs a check command in the VM, swallows output.
    orb_run "$1" >/dev/null 2>&1
}

# ── Banner ─────────────────────────────────────────────────────────────────
echo
echo "  ${BRED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo "  ${BRED}  HAKAM PREFLIGHT${RST}    ${DIM}health check before going on stage${RST}"
echo "  ${BRED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo "  ${DIM}vm=${VM_NAME}  project=${VM_PROJECT_PATH}  ws=:${WS_PORT}${RST}"

# ── Mac side ───────────────────────────────────────────────────────────────
hdr "Mac · tooling"

if command -v orb >/dev/null; then
    ok "orb CLI present"
else
    fail "orb CLI missing" "OrbStack not installed?"
    fix "install OrbStack — https://orbstack.dev"
    echo
    echo "  ${RED}cannot continue without orb — VM-side checks blocked${RST}"
    exit 1
fi

if command -v node >/dev/null; then
    ok "node $(node --version)"
else
    fail "node missing"
    fix "brew install node"
fi

if command -v npm >/dev/null; then
    ok "npm $(npm --version)"
else
    fail "npm missing"
    fix "brew install node  # ships npm"
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -d "${REPO_ROOT}/hakam-ui/node_modules" ]]; then
    ok "hakam-ui/node_modules present"
else
    fail "hakam-ui dependencies not installed"
    fix "cd hakam-ui && npm install"
fi

# ── Mac → VM reachability ──────────────────────────────────────────────────
hdr "Mac · VM reachability"

if orb list 2>/dev/null | awk '{print $1}' | grep -qx "$VM_NAME"; then
    ok "VM '${VM_NAME}' is registered with OrbStack"
else
    fail "VM '${VM_NAME}' not registered" "no machine by that name"
    fix "orb create ubuntu ${VM_NAME}"
fi

VM_STATE=$(orb list 2>/dev/null | awk -v vm="$VM_NAME" '$1==vm{print $2}')
if [[ "$VM_STATE" == "running" ]]; then
    ok "VM '${VM_NAME}' is running"
else
    fail "VM '${VM_NAME}' is not running" "(state: ${VM_STATE:-unknown})"
    fix "orb start ${VM_NAME}"
    echo
    echo "  ${RED}cannot continue without a running VM — remaining checks blocked${RST}"
    summary_and_exit() {
        echo
        echo "  ${BLD}── summary ──${RST}"
        echo "    ${GRN}${PASS} pass${RST}  ${YLW}${WARN} warn${RST}  ${RED}${FAIL} fail${RST}"
        exit 1
    }
    summary_and_exit
fi

# Tests pure stdin echo through orb — confirms the VM accepts commands.
if orb_ok 'echo ok'; then
    ok "orb -m ${VM_NAME} accepts commands"
else
    fail "orb -m ${VM_NAME} command path broken"
    fix "orb restart ${VM_NAME}"
fi

# ── VM side ────────────────────────────────────────────────────────────────
hdr "VM · toolchain"

if orb_ok 'command -v cargo'; then
    ok "cargo present in VM ($(orb_run 'cargo --version' 2>/dev/null))"
else
    fail "cargo missing in VM"
    fix "in VM: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
fi

if orb_ok 'rustup toolchain list | grep -q nightly'; then
    ok "rust nightly toolchain installed"
else
    fail "rust nightly missing in VM"
    fix "in VM: rustup toolchain install nightly --component rust-src"
fi

if orb_ok 'command -v bpf-linker'; then
    ok "bpf-linker installed"
else
    fail "bpf-linker missing in VM"
    fix "in VM: cargo install bpf-linker  # ~10 minutes to compile"
fi

if orb_ok 'command -v websocat'; then
    ok "websocat installed (bench latency capture available)"
else
    warn "websocat not installed" "bench latency numbers won't capture"
    fix "in VM: cargo install websocat"
fi

# ── VM kernel + interfaces ─────────────────────────────────────────────────
hdr "VM · kernel + interfaces"

if orb_ok '[ -d /sys/module/dummy ] || modprobe -n -v dummy 2>/dev/null'; then
    ok "dummy kernel module available"
else
    fail "dummy kernel module not loadable"
    fix "in VM: sudo apt install linux-modules-extra-$(uname -r)"
fi

# BPF-LSM availability (Arsenal roadmap Phase 2 #6). The socket_connect hook
# only enforces if 'bpf' is in the kernel's active LSM list (needs
# CONFIG_BPF_LSM=y *and* 'bpf' in the lsm= cmdline). WARN, not FAIL: attach_lsm
# degrades to observe-only when this is missing, so the demo still runs — but
# the headline `connect()` → EPERM moment won't fire, and you want to know that
# before the stage, not during it.
if orb_ok "grep -qw bpf /sys/kernel/security/lsm"; then
    ok "BPF-LSM active (socket_connect enforcement available)"
else
    warn "BPF-LSM not in active LSM list" "connect() enforcement runs observe-only → EPERM demo won't fire"
    fix "in VM: add 'lsm=...,bpf' to kernel cmdline (needs CONFIG_BPF_LSM=y) and reboot"
fi

if orb_ok 'ip link show dummy0'; then
    # dummy interfaces report `state UNKNOWN` even when up — check the UP flag
    # in the angle-bracket flags (<…,UP,LOWER_UP>), not the state field.
    if orb_ok "ip link show dummy0 | grep -qw UP"; then
        ok "dummy0 interface up"
    else
        warn "dummy0 exists but is DOWN"
        fix "in VM: ./scripts/setup-demo.sh"
    fi
else
    fail "dummy0 interface missing"
    fix "in VM: ./scripts/setup-demo.sh"
fi

# 18 rotating IPs needed by demo-cycle.sh's source pool.
if orb_ok "ip addr show dummy0 2>/dev/null | grep -c 'inet 10.99' | awk '{ exit !(\$1 >= 31) }'"; then
    ok "demo IP aliases on dummy0 (≥31: attack pool + benign pool)"
else
    warn "demo IP aliases incomplete" "source pool will be small"
    fix "in VM: ./scripts/setup-demo.sh"
fi

# Target listener on 10.99.0.10:80. THE silent-failure footgun: without it the
# attacker nc(1) calls get RST'd before sending the HTTP payload, so XDP sees
# only SYNs and the HUD stays empty even though every other check is green.
if orb_ok "ss -tln | grep -q '10[.]99[.]0[.]10:80'"; then
    ok "target listener up on 10.99.0.10:80 (attacks can transmit payload)"
else
    warn "no target listener on 10.99.0.10:80" "attacks get RST'd → HUD stays empty"
    fix "in VM: ./scripts/setup-demo.sh"
fi

# ── VM build artifacts ─────────────────────────────────────────────────────
hdr "VM · build artifacts"

if orb_ok "[ -f ${VM_PROJECT_PATH}/target/bpfel-unknown-none/release/hakam-ebpf ]"; then
    ok "hakam-ebpf ELF built"
else
    warn "hakam-ebpf ELF not built yet"
    fix "in VM: cargo xtask build-ebpf  # run once after a clone"
fi

if orb_ok "[ -x ${VM_PROJECT_PATH}/target/debug/hakam-node ]"; then
    ok "hakam-node binary built"
else
    warn "hakam-node binary not built yet"
    fix "in VM: cargo xtask run --iface lo --mode skb  # builds + launches"
fi

# Auto-generated by xtask on a 'run', but useful to flag if it's missing
# right now — saves a confusing 'permission denied' later.
if orb_ok "[ -r ${VM_PROJECT_PATH} ]"; then
    ok "Mac home auto-mounted in VM"
else
    fail "VM cannot read ${VM_PROJECT_PATH}"
    fix "OrbStack auto-mount may have lapsed — orb restart ${VM_NAME}"
fi

# ── Port + listening state ─────────────────────────────────────────────────
hdr "VM · port ${WS_PORT}"

if orb_ok "ss -tln | awk '\$4 ~ /:${WS_PORT}$/ { exit 0 } END { exit 1 }'"; then
    LISTENER=$(orb_run "ss -tlnp 2>/dev/null | awk -v p=':${WS_PORT}\$' '\$4 ~ p { print \$NF }'" 2>/dev/null | head -1)
    if [[ -n "$LISTENER" ]] && echo "$LISTENER" | grep -qi 'hakam-node'; then
        ok "port ${WS_PORT} held by hakam-node ${DIM}($LISTENER)${RST}"
    else
        warn "port ${WS_PORT} is in use by an unknown process" "${LISTENER}"
        fix "in VM: sudo ss -tlnp | grep ${WS_PORT}  # find + stop the squatter"
    fi
else
    ok "port ${WS_PORT} is free (hakam-node not running yet)"
fi

# ── Mac → VM port reachability (skip if hakam isn't listening) ───────────
hdr "Mac → VM · websocket dial"

VM_IP=$(orb_run "ip route get 1.1.1.1 2>/dev/null | awk '/src/{for(i=1;i<=NF;i++)if(\$i==\"src\")print \$(i+1)}'" 2>/dev/null | head -1)
if [[ -z "$VM_IP" ]]; then
    warn "could not detect VM IP" "remote browser will need to read it from start_guide.md"
else
    ok "VM IP detected: ${VM_IP}"
    if (echo > /dev/tcp/${VM_IP}/${WS_PORT}) 2>/dev/null; then
        ok "Mac can reach ${VM_IP}:${WS_PORT}"
    else
        # If hakam isn't running this is expected; we already logged port state above.
        warn "Mac cannot reach ${VM_IP}:${WS_PORT}" "(only matters once hakam-node is running)"
    fi

    # mDNS name fallback used by start_guide.md.
    if (echo > /dev/tcp/${VM_NAME}.orb.local/${WS_PORT}) 2>/dev/null; then
        ok "${VM_NAME}.orb.local resolves and is reachable on ${WS_PORT}"
    else
        warn "${VM_NAME}.orb.local not reachable" "use ${VM_IP}:${WS_PORT} as fallback"
    fi
fi

# ── Summary ────────────────────────────────────────────────────────────────
echo
echo "  ${BLD}━━ summary ━━${RST}"
echo "    ${GRN}${PASS} pass${RST}   ${YLW}${WARN} warn${RST}   ${RED}${FAIL} fail${RST}"
echo

if [[ $FAIL -eq 0 ]]; then
    if [[ $WARN -eq 0 ]]; then
        echo "  ${GRN}${BLD}all clear — you're stage-ready.${RST}"
    else
        echo "  ${YLW}${BLD}clear with cosmetic warnings — read above before going on stage.${RST}"
    fi
    exit 0
else
    echo "  ${RED}${BLD}${FAIL} blocker(s) — do NOT go on stage until fixed.${RST}"
    exit 1
fi
