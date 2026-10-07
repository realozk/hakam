# Docker demo walkthrough

Build and run Hakam on one Linux host, then send requests to a bundled local
test listener. The interactive CLI displays detections, counters, and policy
controls.

## Requirements

- A Linux host or VM with kernel 5.15 or newer as the development baseline and eBPF support.
- Docker and root access on that host.
- Enough memory and disk space to compile the Rust toolchain and LLVM linker dependencies.
- BPF-LSM enabled for `connect()` policy enforcement; check `/sys/kernel/security/lsm` for `bpf`.

Run the image on the Linux host where the hooks will attach. Docker Desktop on
macOS or Windows is not the supported demo environment. From either platform,
use a Linux VM or remote Linux host and run the following commands there.

The container uses privileged access and host networking. The demo setup creates
network aliases and a listener on the host's network namespace; use an isolated
VM for evaluation.

## 1. Build

```bash
git clone https://github.com/realozk/hakam.git
cd hakam
docker build -f packaging/docker/Dockerfile -t hakam:latest .
```

Rust, LLVM, and `bpf-linker` are installed inside the image build. The first build
can take several minutes. Review the Docker build output if a toolchain step fails.

## 2. Start the node and local target

```bash
sudo HAKAM_DEMO=1 ./packaging/docker/run.sh
```

Demo mode creates `dummy0` address aliases and a no-op TCP target at
`10.99.0.10:80`. XDP and TC attach to `lo`, where local alias traffic travels.
This uses generic (`skb`) XDP. BPF-LSM and the connect tracepoint are attempted
separately; startup output identifies attachment failures.

Keep this terminal open for the CLI. Use `help`, `status`, `list`, and `stats`.

## 3. Send traffic

In another terminal:

```bash
docker exec -it hakam /opt/hakam/scripts/demo-cycle.sh
```

The seven-phase cycle takes roughly four minutes and repeats. Watch for
`INTERCEPT` events in the node console. Stop the cycle with Ctrl-C or `q`.

For individual families:

```bash
docker exec -it hakam /opt/hakam/scripts/seclist-attack.sh -l
docker exec -it hakam /opt/hakam/scripts/seclist-attack.sh -k SQLi -n 5
docker exec -it hakam /opt/hakam/scripts/seclist-attack.sh -k XSS -n 5
```

A signature match attempts to add the source to the kernel packet blocklist.
Confirm actual block/drop state: the DPI path does not check insertion success. Later packets
from that source are dropped. The initial sampled request can reach the listener
before the block is installed. Clear the packet blocklist with `clear` when
repeating a scenario.

## 4. Check a benign sample

```bash
docker exec -it hakam /opt/hakam/scripts/benign-traffic.sh -n 20
```

This uses a separate source pool (`10.99.3.x`). Inspect the results and blocklist
for that pool. Passing this sample does not establish a zero false-positive rate
for other traffic or workloads.

## Optional: individual attack and evasion controls

Run the command watcher in a second terminal:

```bash
docker exec -it hakam /opt/hakam/scripts/attack-on-demand.sh
```

Then write a command from a third terminal:

```bash
docker exec hakam sh -c 'echo a > /tmp/hakam-demo.cmd'
docker exec hakam sh -c 'echo e > /tmp/hakam-demo.cmd'
```

`a` sends a signature example. `e` sends a double-URL-encoded example that the
single-pass decoder can miss. Arrival at the no-op listener demonstrates a
coverage gap, not application compromise. See [evasion analysis](../../docs/evasion.md).

Run one traffic driver at a time: `attack-on-demand.sh` and `demo-cycle.sh` share
a command file.

## Stop

```bash
docker stop hakam
```

The container sends SIGINT so the node can shut down its hooks. The demo aliases
and listener are setup resources; verify or reset the test VM before the next run.

## Telemetry

The Docker runner binds telemetry to `0.0.0.0` by default. Set
`HAKAM_BIND=127.0.0.1` to restrict it to the host. With `websocat` installed:

```bash
websocat ws://127.0.0.1:8080/ws
```

For remote inspection, forward port 8080 over SSH. Keep access within a trusted
network; this endpoint accepts demo commands as well as serving telemetry.
