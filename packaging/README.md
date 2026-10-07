# Running Hakam as a service or container

These workflows run the Linux firewall controller and compiled eBPF object.
Use the interactive CLI for foreground operation and the journal for systemd.

Use a Linux host or VM with kernel 5.15 or newer as the development baseline,
root access, and eBPF support. BPF-LSM connection enforcement additionally needs
`CONFIG_BPF_LSM=y` and `bpf` in `/sys/kernel/security/lsm`. If that hook cannot
attach, startup reports the failure and the remaining hooks can continue.

## systemd

From the repository root, with the source-build dependencies installed:

```bash
./packaging/install.sh
sudo nano /etc/hakam/hakam.env
sudo systemctl enable --now hakam
journalctl -u hakam -f
```

Set `HAKAM_IFACE` to the interface you intend to filter; use `ip -br link` to
inspect available interfaces. The environment file also configures XDP mode and
telemetry bind address. Review the service's logs to confirm actual hook status.

Stop with:

```bash
sudo systemctl stop hakam
```

The service uses SIGINT for shutdown. Inspect the service unit and environment
file in [systemd/](systemd/) before changing deployment settings.

## Docker

From the repository root:

```bash
docker build -f packaging/docker/Dockerfile -t hakam:latest .
sudo HAKAM_IFACE=eth0 ./packaging/docker/run.sh
```

Replace `eth0` with your selected interface. The image compiles Rust and eBPF
inside the container build. Runtime uses `--privileged --network host` to attach
to the host kernel and interfaces. Stop with `docker stop hakam`.

For an isolated local traffic demo, use
[the Docker walkthrough](docker/REVIEW.md). [save-image.sh](docker/save-image.sh)
exports a built image for transfer; no downloadable prebuilt image is included.

## Telemetry

The source node defaults to `ws://127.0.0.1:8080/ws`. The Docker runner binds
to `0.0.0.0` by default; set `HAKAM_BIND=127.0.0.1` for local access. Use
`websocat` to inspect events. Remote access can use an SSH-forwarded port. The
WebSocket accepts demo commands as well as serving telemetry; keep access
limited to a trusted network.

To inspect loaded programs and telemetry, with the optional tools installed:

```bash
sudo bpftool prog show
websocat ws://127.0.0.1:8080/ws
```

Check startup logs for failures and test traffic on the selected interface.
A running process or open WebSocket alone does not confirm every hook is active.
