# Deploying Hakam (core)

Two ways to run the **core** firewall on a Linux box. Neither needs the UI — the
node logs everything of value to the console / journal (armed hooks, `INTERCEPT`
lines, blocks). The UI is an optional dashboard you can attach later.

> **Requirements (both paths):** Linux ≥ 5.7, root, and — for `connect()`
> *enforcement* — BPF-LSM enabled (`grep -w bpf /sys/kernel/security/lsm`).
> Without BPF-LSM the LSM hook degrades to observe-only; XDP/TC/DPI/conntrack all
> still run. Build needs Rust nightly + `bpf-linker`.

## Option A — systemd (bare metal / VM)  ✅ validated

```bash
./packaging/install.sh                       # build + install binary, eBPF object, unit
sudo nano /etc/hakam/hakam.env               # set HAKAM_IFACE (see: ip -br link)
sudo systemctl enable --now hakam
journalctl -u hakam -f                        # watch it
sudo systemctl stop hakam                      # clean detach (SIGINT)
```

Config lives in `/etc/hakam/hakam.env` (interface, XDP mode, bind address). The
service runs headless and detaches every hook on stop.

## Option B — container  ✅ validated

> **Reviewing, not deploying?** See [`docker/REVIEW.md`](docker/REVIEW.md) — a
> prebuilt-image path (no source build) with a one-flag self-contained demo:
> `sudo HAKAM_DEMO=1 ./run.sh`, then fire attacks from a second terminal. Build
> the shippable tarball with [`docker/save-image.sh`](docker/save-image.sh).

```bash
docker build -f packaging/docker/Dockerfile -t hakam:latest .   # from repo root
HAKAM_IFACE=eth0 ./packaging/docker/run.sh                       # production: real NIC
```

The container build compiles the eBPF object from source, so it pulls a Rust
toolchain and `bpf-linker` (the slow step — ~10–15 min). The run is
`--privileged --network host` because eBPF attaches to the **host** kernel and
interfaces; the telemetry WebSocket is then on `ws://<host>:8080/ws`.
`docker stop` sends SIGINT, so hooks detach cleanly.

Validated end-to-end (Docker 29, kernel 6.x): `docker run` arms XDP + TC +
BPF-LSM headless and serves telemetry; a SQLi fired at a target was dropped by
the container's datapath (`BLOCK … XDP_DROP`); `docker stop` exited 0 with all
hooks detached.

## Optional — the UI (not required)

`hakam-ui` is a separate dashboard that just subscribes to the telemetry
WebSocket. To use it, run the core (either option above), then point the UI at
`ws://<host>:8080/ws`. See `hakam-ui/README.md`. Skip it entirely and you still
get the full picture from `journalctl -u hakam -f` or the interactive CLI.

## Verifying it's up

```bash
# the kernel programs are loaded:
sudo bpftool prog show | grep -E 'xdp|lsm|classifier'   # if bpftool installed
# telemetry is live:
websocat ws://localhost:8080/ws | head -1               # one METRICS line
```
