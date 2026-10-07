# Script reference

Run scripts from the repository root on Linux unless noted. Demo scripts target
an isolated local network; inspect defaults before selecting a different target.

## Local demonstration

| Script | Purpose | Requirements / notes |
|---|---|---|
| `setup-demo.sh` | Creates `dummy0`, address aliases, and the no-op target at `10.99.0.10:80` | `sudo`, `iproute2`, Python 3; modifies interface reverse-path filtering |
| `demo-cycle.sh` | Repeating seven-phase traffic sequence with background benign requests | Run after setup and node startup; roughly four minutes per cycle |
| `seclist-attack.sh` | Sends signature examples by family from rotating source addresses | netcat; `-l` lists available families |
| `benign-traffic.sh` | Sends a bounded set of clean HTTP examples from `10.99.3.x` | Sample results do not establish a general false-positive rate |
| `attack-on-demand.sh` | Watches `/tmp/hakam-demo.cmd` for attack/evasion commands | Run one driver at a time; shares the file with `demo-cycle.sh` |
| `arsenal-demo.sh` | Presenter-paced packet, process-observation, and connection-policy scenarios | Some steps require CLI input; optional `websocat` overlay |
| `attack.sh` | Earlier multi-scenario driver | Uses its own interface/target defaults; requires `hping3`, curl, and netcat |
| `target-listener.py` | Accepts demo TCP requests | No-op target; does not execute the request payload |

Typical order:

```bash
./scripts/setup-demo.sh
cargo xtask run --iface lo --mode skb
# In another Linux terminal:
./scripts/demo-cycle.sh
```

The aliases reside on `dummy0`, but local alias traffic passes through `lo`.
See [the setup guide](../start_guide.md) for CLI commands and troubleshooting.

### Cycle controls

```bash
./scripts/demo-cycle.sh --manual
./scripts/demo-cycle.sh --start-at 3
```

`space` pauses, `n` advances, `r` restarts a phase, `0`–`6` selects a phase,
`q` exits, and `?` displays help. The phase names and durations are in the
[setup guide](../start_guide.md#3-generate-traffic).

### Selected traffic samples

```bash
./scripts/seclist-attack.sh -l
./scripts/seclist-attack.sh -k SQLi -n 5
./scripts/seclist-attack.sh -n 100 -d 500
./scripts/benign-traffic.sh -n 20
```

Use `-t 10.99.0.10:80` to set the target for either traffic generator. A signature
match creates a source block; clear existing blocks before repeating a test.

### Presenter-paced sequence

```bash
./scripts/arsenal-demo.sh
./scripts/arsenal-demo.sh --auto
./scripts/arsenal-demo.sh --fast
```

This sequence demonstrates signature detection, optional heuristic process
correlation, a manually armed LSM destination rule, and CLI counters. It does
not establish universal attack prevention or zero false positives. Use startup
logs to verify that LSM enforcement is available before its scenario.

## Health and validation

| Script | Purpose | Requirements / scope |
|---|---|---|
| `smoke.sh` | Checks a running node, WebSocket events, and block/unblock behavior | `websocat`, netcat; may change test block state |
| `preflight.sh` | Checks the macOS/OrbStack demo workflow | Run on macOS; defaults to an OrbStack machine named `hakam` |
| `validate_phase1.sh` | Builds/loads the node and exercises signatures, decoding, reassembly, and tracepoint scope | Linux, Cargo, netcat, `websocat`, `jq`, passwordless sudo, demo setup |
| `evasion-test.sh` | Sends 30 mutations and reports observed hits/misses | Linux, running node, `dummy0`, `websocat`; creates temporary source aliases |
| `replay-corpus.sh` | Replays the four PCAP fixtures and checks expected detection categories | Linux, `tcpreplay`, `websocat`, running node, empty packet blocklist |

Examples:

```bash
./scripts/smoke.sh
WS_HOST=localhost WS_PORT=8080 ./scripts/smoke.sh
./scripts/evasion-test.sh
./scripts/replay-corpus.sh
```

See [evasion.md](evasion.md) for expected matcher outcomes and
[corpus/README.md](../corpus/README.md) for replay details. Live packet boundaries
can affect results; a userspace test is distinct from a kernel load/traffic check.

## Benchmarking

| Script | Purpose |
|---|---|
| `bench-setup.sh` | Creates a `veth` pair and `phbench-gen` network namespace |
| `bench-run.sh` | Runs `clean`, `flood`, or `dpi` traffic and writes CSV measurements |
| `bench-teardown.sh` | Removes the benchmark namespace and interfaces |

```bash
./scripts/bench-setup.sh
./scripts/bench-run.sh -w flood -l baseline-flood -d 60
# Start Hakam on phbench0 separately, then repeat:
./scripts/bench-run.sh -w flood -l hakam-flood -d 60
./scripts/bench-teardown.sh
```

Keep baseline and Hakam conditions comparable. A `clean` run can trigger the
rate policy, so verify no blocks before calling it a PASS-path measurement.
The [benchmark guide](../bench/README.md) explains topology, output, and known
WebSocket capture failures.

## Additional observability

```bash
./scripts/bpftrace-overlay.sh drops
./scripts/bpftrace-overlay.sh latency
./scripts/bpftrace-overlay.sh connects
./scripts/bpftrace-overlay.sh all
```

Requires `bpftrace` and suitable kernel probe access. The overlay observes kernel
activity; its program runtime histogram is a different measurement from the
node's blocklist-drop histogram. Treat probe availability as kernel-dependent.
