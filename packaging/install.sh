#!/usr/bin/env bash
# Build Hakam (core only — no UI) and install it as a systemd service.
#
#   ./packaging/install.sh
#
# Then set your interface and start it:
#   sudo nano /etc/hakam/hakam.env     # set HAKAM_IFACE
#   sudo systemctl enable --now hakam
#   journalctl -u hakam -f             # watch it run
#
# Requirements: Rust nightly + bpf-linker (to compile the eBPF object), root via
# sudo (to install + load BPF), and a kernel with BPF-LSM for enforcement
# (`grep -w bpf /sys/kernel/security/lsm`). Without BPF-LSM the LSM hook degrades
# to observe-only; everything else still runs.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BIN_DST=/usr/local/bin/hakam-node
ELF_DST=/usr/local/lib/hakam/hakam-ebpf
UNIT_DST=/etc/systemd/system/hakam.service
ENV_DST=/etc/hakam/hakam.env

echo "▸ Building eBPF object (cargo xtask build-ebpf)…"
cargo xtask build-ebpf
ELF_SRC="$REPO_ROOT/target/bpfel-unknown-none/release/hakam-ebpf"
[ -f "$ELF_SRC" ] || { echo "✗ eBPF object not found at $ELF_SRC" >&2; exit 1; }

echo "▸ Building hakam-node (release)…"
cargo build -p hakam-node --features linux --release
BIN_SRC="$REPO_ROOT/target/release/hakam-node"
[ -x "$BIN_SRC" ] || { echo "✗ hakam-node binary not found at $BIN_SRC" >&2; exit 1; }

echo "▸ Installing (needs sudo)…"
sudo install -Dm755 "$BIN_SRC" "$BIN_DST"
sudo install -Dm644 "$ELF_SRC" "$ELF_DST"
sudo install -Dm644 "$REPO_ROOT/packaging/systemd/hakam.service" "$UNIT_DST"

# Preserve an existing env file (don't clobber the operator's interface choice).
if [ -f "$ENV_DST" ]; then
    echo "  · keeping existing $ENV_DST"
else
    sudo install -Dm644 "$REPO_ROOT/packaging/systemd/hakam.env" "$ENV_DST"
    echo "  · installed default $ENV_DST"
fi

sudo systemctl daemon-reload

echo
echo "✓ Installed. Next:"
echo "    sudo nano $ENV_DST        # set HAKAM_IFACE to your NIC (ip -br link)"
echo "    sudo systemctl enable --now hakam"
echo "    journalctl -u hakam -f"
echo
echo "  Optional UI (not required — the core logs everything): point hakam-ui at"
echo "  ws://<this-host>:8080/ws. See README."
