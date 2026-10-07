# Setup guide

This guide runs Hakam on a Linux host or VM with an interactive CLI and a local
demo target. For the container workflow, use the
[Docker walkthrough](packaging/docker/REVIEW.md).

## Requirements

- Linux 5.15 or newer as the development baseline, with eBPF, XDP, TC, and kernel BTF support.
- Root access through `sudo` to attach kernel programs and create the demo network.
- Rust nightly with `rust-src`, LLVM/Clang, and `bpf-linker`.
- Python 3, `iproute2`, and netcat for the demo scripts.

BPF-LSM connection enforcement requires `CONFIG_BPF_LSM=y` and `bpf` in the
active LSM list. Check with:

```bash
cat /sys/kernel/security/lsm
```

If the LSM hook cannot attach, Hakam reports the reason and continues with the
remaining hooks. Verify startup output for the capabilities actually available.

## 1. Install and build on Linux

On an Ubuntu or Debian host with Rust installed:

```bash
sudo apt-get update
sudo apt-get install -y llvm clang libelf-dev pkg-config python3 iproute2 netcat-openbsd
rustup toolchain install nightly --component rust-src
cargo install bpf-linker --locked

git clone https://github.com/realozk/hakam.git
cd hakam
cargo xtask build-ebpf
```

The workspace selects nightly through `rust-toolchain.toml`. The BPF target is
built from `rust-src`; a separate `rustup target add bpfel-unknown-none` step is
not required. The first linker build can take several minutes.

## 2. Start the local demo

In the first Linux terminal, from the repository root:

```bash
./scripts/setup-demo.sh
cargo xtask run --iface lo --mode skb
```

Keep this terminal open. `setup-demo.sh` creates `dummy0`, assigns demo addresses,
relaxes reverse-path filtering on that interface, and starts a no-op TCP listener
on `10.99.0.10:80`. The listener accepts test traffic; it is not a database or
vulnerable application.

Hakam attaches to `lo` because traffic between the local address aliases travels
through loopback. `dummy0` holds the addresses. Generic (`skb`) XDP mode is used
for this demo; it does not demonstrate native driver-mode performance.

The node builds and loads the eBPF object, attaches its hooks, and serves
WebSocket telemetry at `ws://127.0.0.1:8080/ws` by default.

## 3. Generate traffic

In a second Linux terminal, from the repository root:

```bash
./scripts/demo-cycle.sh
```

The cycle runs for roughly four minutes and repeats. Benign traffic continues
in the background while attack requests come from a separate address pool.

| Phase | Duration | Traffic |
|---|---:|---|
| 0: Calm | 15 s | Benign baseline |
| 1: Probing | 40 s | Sparse probes |
| 2: Investigation | 48 s | Mixed attack families |
| 3: Escalation | 40 s | More frequent mixed requests |
| 4: Peak | 25 s | Sustained attack requests |
| 5: Containment | 30 s | A few remaining requests |
| 6: Recovery | 30 s | Benign traffic only |

Controls: `space` pauses, `n` advances, `r` restarts the current phase, `0`–`6`
jumps to a phase, `q` exits, and `?` shows help. `--manual` waits for Enter between
phases; `--start-at N` selects the starting phase.

To send a smaller sample:

```bash
./scripts/seclist-attack.sh -l
./scripts/seclist-attack.sh -k SQLi -n 5
./scripts/benign-traffic.sh -n 20
```

A detection reports a signature match and attempts to install a source block for
subsequent traffic. It does not prove the initial request was prevented or the target was
compromised. See [limitations](README.md#limitations).

## CLI commands

| Command | Purpose |
|---|---|
| `block <IP[/prefix]>` | Add an ingress/egress packet block |
| `unblock <IP[/prefix]>` | Remove a packet block |
| `list` | Show packet blocks and their ages |
| `policy-block <IP[/prefix]>` | Deny new IPv4 connections to a destination through BPF-LSM |
| `policy-unblock <IP[/prefix]>` | Remove a connection-policy entry |
| `policy-list` | List connection-policy entries |
| `status` | Show configuration and counters |
| `rules` | Show signature families and counts |
| `stats` | Show drops, histogram estimates, detections, and flows |
| `clear` | Clear the packet blocklist |
| `help` | Show available commands |
| `quit` | Shut down and detach the node's hooks |

Packet blocks use a 120-second age threshold with a periodic userspace sweep.
Connection-policy entries are separate; remove them with `policy-unblock`.

## Optional telemetry inspection

With `websocat` installed, a third Linux terminal can display the JSON event feed:

```bash
websocat ws://127.0.0.1:8080/ws
```

For SSH access, forward the default loopback port with
`ssh -L 8080:127.0.0.1:8080 user@host`. The WebSocket also accepts demo-control
messages; keep it on loopback or a trusted network. It is not a replacement for
the interactive CLI's policy commands.

## Troubleshooting

| Symptom | Check |
|---|---|
| Connections appear without detections | Check the target listener with `ss -tln`; run `setup-demo.sh` again if `10.99.0.10:80` is missing. |
| XDP cannot attach | Confirm `lo` is up and use `--mode skb` for the local demo. Inspect the reported verifier or attach error. |
| LSM hook is unavailable | Check kernel BTF, `CONFIG_BPF_LSM`, and the active LSM list. Other hooks may still be active. |
| A previously detected source stops producing events | It may already be blocked. Use `clear` before repeating the scenario. |
| `nc -s 10.99.1.x` cannot bind | Run `setup-demo.sh` to restore the address aliases. |
| `cargo xtask` is unavailable | Run from the repository root and ensure Rust is installed. |

`./scripts/smoke.sh` checks a running node and requires `websocat` and netcat.
`./scripts/preflight.sh` is an additional check for the macOS/OrbStack workflow;
it is not a general Linux installer.

## Optional macOS / OrbStack workflow

The kernel programs must run inside Linux. If you use OrbStack, create a Linux
machine named `hakam` and enter it with `orb -m hakam`. Clone this repository in
the guest, or use an existing shared checkout at its actual mounted path. No
particular macOS username or home directory is required.

Run the node and traffic scripts in Linux terminals. The macOS host needs no
Node.js or frontend tooling. For the optional OrbStack preflight, set
`VM_PROJECT_PATH` if the guest checkout is not at `~/hakam`.

## Stop the demo

Stop `demo-cycle.sh` with `q` or Ctrl-C, then enter `quit` in the Hakam CLI.
The setup script's target listener and address aliases are separate resources
and may remain after the node stops. Use an isolated VM for repeatable demos.

To prepare a recording, see the [recording guide](demo/README.md).
