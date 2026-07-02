# Reviewing Hakam — one Linux box, three commands, no build

This is the fastest way to watch Hakam block a real attack at the kernel edge.
No source build, no UI, no second machine.

> ### ⚠️ Read this first: you need a real Linux kernel
> Hakam is an **eBPF/XDP** tool — its programs load into the Linux kernel, like
> every eBPF tool (Cilium, Falco, bpftrace). **Docker Desktop on macOS/Windows
> will not work** — it runs a stripped LinuxKit VM without XDP/BPF-LSM and
> without real host networking. That's not a Hakam limitation; it's the
> category. If you're on a Mac or Windows laptop, spin up one Linux VM or cloud
> instance first — see [Testing from a Mac or Windows laptop](#testing-from-a-mac-or-windows-laptop) below. It takes ~2 minutes.

## What you need

- **One Linux host** — bare metal, a VM, or a cloud instance. Kernel **≥ 5.8**.
- **Docker**, and **root** (eBPF/XDP attaches to the host kernel).
- The arch of the tarball you load must match the host: `hakam-amd64.tar.gz` for
  `x86_64`, `hakam-arm64.tar.gz` for `aarch64`. Both are shipped.
- That's it. The image carries the datapath, the controller, and a bundled
  attack + benign traffic harness.

## 1 · Load the prebuilt image (no compile)

```bash
gunzip -c hakam-amd64.tar.gz | docker load     # or hakam-arm64.tar.gz on aarch64
```

## 2 · Arm Hakam + stand up a self-contained target

```bash
sudo HAKAM_DEMO=1 ./run.sh
```

`HAKAM_DEMO=1` builds a loopback test network (`dummy0` + IP aliases + a no-op
target on `10.99.0.10:80`) and attaches XDP/TC/BPF-LSM/conntrack to `lo`. You
now have the **interactive Hakam CLI** live in this terminal. Useful commands:
`stats`, `list`, `status`, `help`, `quit`.

## 3 · Fire attacks and watch them drop

In a **second terminal**:

```bash
docker exec -it hakam /opt/hakam/scripts/seclist-attack.sh -k SQLi -n 5
```

Back in terminal 1 you'll see `▼ INTERCEPT` lines naming the signature and the
source IP, and each attacker gets pushed into the kernel blocklist. Type `stats`
in the CLI for drop counts, sub-µs latency, and active flows; `list` shows the
live blocklist.

Try other families or the full firehose:

```bash
docker exec -it hakam /opt/hakam/scripts/seclist-attack.sh -l          # list families
docker exec -it hakam /opt/hakam/scripts/seclist-attack.sh -n 50       # 50 random shots
docker exec -it hakam /opt/hakam/scripts/seclist-attack.sh -k XSS -n 20
```

## Prove zero false positives

```bash
docker exec -it hakam /opt/hakam/scripts/benign-traffic.sh -n 20
```

Clean requests from a separate `10.99.3.x` pool. `stats` shows `benign passed`
climbing with **no blocks** for that pool.

## Stop (detaches every kernel hook cleanly)

```bash
docker stop hakam          # or Ctrl-C, or type `quit` in the CLI
```

`docker stop` sends `SIGINT`; the node detaches XDP/TC/LSM before exiting.

## Testing from a Mac or Windows laptop

You don't need a Linux machine of your own — you need Linux *somewhere*. Pick one:

**Cloud instance (easiest, matches the amd64 image):**

```bash
# Launch any Ubuntu 22.04+ x86_64 instance (EC2 t3.small, DigitalOcean, GCP…),
# then on the box:
curl -fsSL https://get.docker.com | sh              # if Docker isn't preinstalled
# scp the tarball up (or wget it), then follow steps 1–3 above.
```

Cloud instances are `x86_64`, so `hakam-amd64.tar.gz` loads with no arch fuss.

**Local Linux VM:**

- **macOS:** [Multipass](https://multipass.run) (`multipass launch --name hakam --cpus 2 --memory 2G 22.04`) or UTM/VirtualBox/VMware/Parallels.
- **Windows:** VirtualBox/VMware/Hyper-V. (WSL2 *may* work — it's a real kernel —
  but its default build often lacks XDP/BPF-LSM, so a full VM is the safe bet.)

> **Apple Silicon Macs:** a *local* Linux VM there is `arm64`, so load
> `hakam-arm64.tar.gz`. Simpler still: use an `amd64` cloud instance and the
> default `hakam-amd64.tar.gz`.

## Honest notes for the reviewer

- **BPF-LSM `connect()` enforcement** (the EPERM-before-the-packet story) needs
  the kernel booted with BPF-LSM enabled: `grep -w bpf /sys/kernel/security/lsm`.
  Without it, that one hook degrades to observe-only — XDP/TC/DPI/conntrack all
  still run and still block. Nothing hard-fails.
- **SKB (generic) XDP** is used here so it runs on any interface. Native-mode
  driver XDP on a physical NIC is a separate benchmark, not this demo.
- Both `hakam-amd64.tar.gz` and `hakam-arm64.tar.gz` are shipped — load the one
  matching your host (`uname -m`: `x86_64` → amd64, `aarch64` → arm64).

## Optional — the dashboard

Everything above is CLI-only. If you want the visual HUD, the node also serves
telemetry at `ws://<host>:8080/ws`; point `hakam-ui` at it. Not required to
evaluate the core.
