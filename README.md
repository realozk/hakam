# Hakam

![Hakam banner](banner.gif)

[![CI](https://github.com/realozk/hakam/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/realozk/hakam/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**A Linux host firewall built with Rust and eBPF.**

Hakam combines inbound packet filtering, outbound connection policy, and process
connection telemetry on a single host. Kernel programs enforce the rules; a Rust
controller inspects sampled HTTP traffic, manages blocklists, and exposes an
interactive CLI and WebSocket telemetry.

This repository is a research and demonstration project. It includes the kernel
programs, controller, reproducible terminal demos, packet captures, and
benchmark results. Start with the [setup guide](start_guide.md) to try it, or the
[architecture reference](docs/architecture.md) to understand the implementation.

## What it does

| Component | Purpose |
|---|---|
| XDP ingress | Drops IPv4 packets from blocked sources and applies a per-source, per-CPU rate limit. |
| TC egress | Drops IPv4 packets to destinations in the packet blocklist on the attached interface. |
| BPF-LSM | Denies new IPv4 `connect()` calls to destinations in a separate connection policy, when the kernel supports BPF-LSM. |
| Connect tracepoint | Reports local connection attempts with PID, process name, destination, and port. |
| Signature inspection | Matches sampled HTTP request bytes against 202 patterns across 13 attack families. |

The controller runs as `hakam-node` and loads a separate compiled eBPF object.
Use the interactive CLI for manual operation, or systemd logs for a service.
A richer terminal interface is planned; the current version uses a line-based CLI.

## How it works

```text
Inbound IPv4 packet
  → XDP: blocklist lookup and rate limit
  → sample eligible TCP payloads → userspace HTTP signature matcher
  → attempt to add matching source to BLOCKLIST
  → subsequent ingress packets dropped by XDP

Outbound IPv4 packet
  → TC egress: destination lookup in BLOCKLIST

Local IPv4 connect()
  → BPF-LSM: destination lookup in CONNECT_POLICY → allow or EPERM
  → connect tracepoint: process connection telemetry

Kernel maps and events → hakam-node → interactive CLI / service logs / WebSocket
```

Signature detection is asynchronous: the sampled packet can reach the application
before userspace installs a block. A connection policy already installed in the
LSM map can deny a new connection at `connect()`. These are different enforcement
paths; detecting a signature does not guarantee that the initial request was
prevented.

## Quick start

Use a Linux host or VM with kernel 5.15 or newer as the development baseline,
root access, and eBPF support. Kernel version alone is insufficient: BPF-LSM
connection enforcement also requires `CONFIG_BPF_LSM=y` and `bpf` in
`/sys/kernel/security/lsm`. If the LSM hook is unavailable, the node reports the
failure and continues with the other hooks.

### Docker demo

The image build includes the Rust and LLVM toolchain. Run these commands on the
Linux host where Hakam will attach; Docker Desktop on macOS or Windows is not
the supported demo environment.

```bash
git clone https://github.com/realozk/hakam.git
cd hakam
docker build -f packaging/docker/Dockerfile -t hakam:latest .

# Terminal 1: start the firewall and local demo target
sudo HAKAM_DEMO=1 ./packaging/docker/run.sh

# Terminal 2: generate the demo traffic
docker exec -it hakam /opt/hakam/scripts/demo-cycle.sh
```

In terminal 1, use `stats`, `list`, and `help` to inspect results. Stop with
`docker stop hakam`. The container uses privileged access and host networking
because its eBPF programs attach to the host kernel.

See the [Docker walkthrough](packaging/docker/REVIEW.md) for individual scenarios
and the [packaging guide](packaging/README.md) for systemd installation.

### Build from source

On Linux, install Rust, LLVM/Clang, and the eBPF linker, then start the demo:

```bash
git clone https://github.com/realozk/hakam.git
cd hakam
rustup toolchain install nightly --component rust-src
cargo install bpf-linker --locked
./scripts/setup-demo.sh
cargo xtask run --iface lo --mode skb
```

In another terminal on Linux:

```bash
./scripts/demo-cycle.sh
```

Use `stats`, `list`, `rules`, and `help` in the node console. See the
[setup guide](start_guide.md) for CLI commands and troubleshooting.

## Signature coverage

The matcher uses case-insensitive ASCII substring matching with Aho-Corasick,
followed by a single URL-decoding pass if the raw scan misses.

| Family | Example patterns |
|---|---|
| SQLi | `UNION SELECT`, `DROP TABLE`, `WAITFOR DELAY` |
| XSS | `<SCRIPT`, `JAVASCRIPT:`, `ONERROR=` |
| RCE | `;WHOAMI`, `BASH -C` |
| LFI | `../`, `..%2F`, `/ETC/PASSWD` |
| SSRF | `FILE://`, `DICT://`, `GOPHER://` |
| Log4Shell | `${JNDI:` |
| Other families | XXE, NoSQLi, SSTI, WebShell, Recon, CVE, Deserial |

These are signature families, not a guarantee of complete vulnerability coverage.
The [evasion analysis](docs/evasion.md) records specific matches and misses.

## Performance

The [benchmark harness](bench/README.md) compares runs with and without Hakam on
a Linux VM using a network namespace and `veth` pair. Raw measurements are in
[bench/results](bench/results/). Results from this topology do not establish
physical-NIC throughput or application response latency.

The CLI's `stats` command reports XDP blocklist-drop latency from the kernel's
`LATENCY_HIST` map. Percentiles are estimates from log2 histogram buckets, not
exact timings. The existing WebSocket benchmark captures are header-only, so
they do not provide a saved latency series. Record the host, kernel, interface
mode, workload, and measurement window when reporting new results.

## Limitations

- **IPv4 coverage.** IPv6 filtering and general protocol inspection are outside the current implementation.
- **Limited payload visibility.** Only eligible TCP segments with at least 64 available payload bytes are sampled, and only their first 64 bytes are inspected. The per-flow sample buffer is capped at 256 bytes and 4,096 flows.
- **Partial reassembly.** Samples are sorted by TCP sequence number and duplicate sequences are ignored. Missing bytes, overlaps, conflicting retransmissions, and sequence wraparound are not fully reconstructed or validated.
- **HTTP and plaintext scope.** The matcher requires a recognized HTTP request method. It does not decrypt TLS traffic or parse full requests.
- **Encoding gaps.** Recursive URL decoding, Unicode normalization, SQL comment removal, and flexible whitespace matching are not implemented.
- **Reactive signature blocking.** Initial sampled traffic can reach the application before a block is installed. The DPI path reports detections without checking map-insertion success. Process attribution is based on local connection observations and is not guaranteed for every block.
- **Fixed capacity and rate policy.** The packet blocklist holds 1,024 entries. The 500-packet/s rate threshold applies independently per CPU and can block legitimate high-rate sources.
- **Userspace expiry.** Packet blocks are removed by a periodic userspace sweep after the configured 120-second age; expiry is not a kernel-enforced deadline. Connection-policy entries use separate manual commands.

Hakam should be evaluated against your own traffic and kernel configuration
before use beyond an isolated test environment.

## Repository guide

| Directory | Contents |
|---|---|
| [hakam-common](hakam-common/) | Shared kernel/userspace types |
| [hakam-ebpf](hakam-ebpf/) | XDP, TC, LSM, tracepoint, and flow maps |
| [hakam-node](hakam-node/) | Controller, signature matcher, CLI, and telemetry |
| [xtask](xtask/) | Build and launch commands |
| [scripts](docs/scripts.md) | Demo, validation, replay, and benchmark tools |
| [corpus](corpus/README.md) | Replayable attack packet captures |
| [bench](bench/README.md) | Benchmark methodology and raw results |
| [packaging](packaging/README.md) | Docker and systemd deployment files |

## Documentation

- [Setup and troubleshooting](start_guide.md)
- [Architecture](docs/architecture.md)
- [Runtime flow](docs/runtime_flow.md)
- [Codebase reference](docs/codebase.md)
- [Signature evasion analysis](docs/evasion.md)
- [Script reference](docs/scripts.md)
- [Proposed v2 architecture](docs/v2-architecture-plan.md) — design proposal; planned capabilities are not current features
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## License

Hakam is licensed under the [MIT License](LICENSE).
