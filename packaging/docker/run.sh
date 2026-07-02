#!/usr/bin/env bash
# Run the Hakam core container.
#
# eBPF attaches to the HOST kernel and interfaces, so this needs --privileged and
# --network host. Set HAKAM_IFACE to a real host NIC (see `ip -br link`).
#
#   HAKAM_IFACE=eth0 ./packaging/docker/run.sh
#
# The telemetry WebSocket is then on ws://<host>:8080/ws (host networking).
set -euo pipefail

# --name hakam so the second terminal can `docker exec hakam …` to fire attacks.
# HAKAM_DEMO=1 builds the self-contained loopback test net (see REVIEW.md).
exec docker run --rm -it \
    --name hakam \
    --privileged \
    --network host \
    -v /sys/kernel/btf:/sys/kernel/btf:ro \
    -e HAKAM_IFACE="${HAKAM_IFACE:-eth0}" \
    -e HAKAM_MODE="${HAKAM_MODE:-skb}" \
    -e HAKAM_BIND="${HAKAM_BIND:-0.0.0.0}" \
    -e HAKAM_DEMO="${HAKAM_DEMO:-0}" \
    hakam:latest
