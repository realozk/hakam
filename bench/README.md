# Benchmark guide

The harness compares traffic with and without Hakam using a Linux network
namespace and a `veth` pair. It records host CPU utilization and interface
counters, and attempts to capture node metrics over WebSocket. Existing results
are in [results/](results/).

## Measurement scope

| Measurement | Source | Interpretation |
|---|---|---|
| Host CPU utilization | `/proc/stat` | Whole-host activity, including the generator; not isolated controller CPU |
| Packet/byte rates | `/proc/net/dev` on `phbench0` | Interface counters over the run window |
| XDP blocklist-drop latency | Node `stats`, from `LATENCY_HIST` | Log2-bucket percentile estimates for one drop branch |
| WebSocket metrics | Optional `.ws.csv` capture | Usable only when data rows are present |

This topology does not establish physical-NIC line rate, hardware offload,
application request latency, or complete PASS-path overhead. Driver-mode XDP on
`veth` is a software-interface measurement. Generic (`skb`) mode is a different
path and must be labeled separately.

The latency histogram excludes PASS verdicts, TC drops, signature processing,
and the initial rate-limit rejection. Historical live readings of 48 ns p50 and
96 ns p99 were reported in earlier documentation, but the checked-in WebSocket
files do not preserve a latency series to independently reproduce those figures.
Record new readings with their test environment and window.

## Topology

```text
Network namespace: phbench-gen        Host namespace
  phbench-gen: 10.200.0.2 ── veth ── phbench0: 10.200.0.1
  Python traffic generator             Hakam attaches here
```

`bench-setup.sh` creates the namespace, links, addresses, and loose reverse-path
filter settings. `bench-teardown.sh` removes the namespace and links. Defaults
can be changed through `NETNS`, `HOST_IF`, `NS_IF`, `HOST_IP`, `NS_IP`, and other
variables defined in the setup script.

## Reproduce a comparison

Run on Linux with Python 3, Bash, `iproute2`, `timeout`, and sudo access.
`websocat` is optional for metric capture.

```bash
./scripts/bench-setup.sh

# Baseline: Hakam must be stopped
./scripts/bench-run.sh -w flood -l baseline-flood -d 60

# In another terminal, start Hakam on the benchmark interface
cargo xtask run --iface phbench0 --mode drv

# With Hakam running
./scripts/bench-run.sh -w flood -l hakam-flood -d 60
```

If driver mode is unsupported, select `--mode skb` and state that mode in the
results. Stop the node with `quit`, then remove the topology:

```bash
./scripts/bench-teardown.sh
```

Repeat each condition at least three times, report the median and variation,
and record the host hardware/VM allocation, kernel, checkout, XDP mode, and
background workload. Confirm attachment state separately: `hakam_listening`
checks the telemetry port, not the actual kernel hooks.

## Workloads

| Workload | Generator | Caveats |
|---|---|---|
| `clean` | Repeated TCP connection attempts and benign HTTP requests to port 80 | Can exceed the fixed rate threshold and become a drop workload. A listener is needed to transmit the HTTP payload. |
| `flood` | UDP sends from `10.200.0.2` to port 9999 | Exercises rate limiting and subsequent blocklist drops; baseline also includes normal closed-port handling. |
| `dpi` | Repeated TCP attempts with a rotating list of attack payloads, roughly 20/s | Needs a working listener and sufficient sampled bytes. The current generator uses one source; a source block prevents later inspection. |

Neither the setup script nor the runner starts an HTTP listener on benchmark
port 80. Without one, TCP connection failure can prevent payload delivery, so a
run labeled `dpi` alone does not prove the matcher was exercised. Verify payload
samples and detection counters when collecting DPI results. Clear the packet
blocklist between conditions.

## Output

Files are written under `bench/results/`:

- `<label>-<UTC timestamp>.csv`: summary rows with `metric,value,unit` columns.
- `<label>-<UTC timestamp>.ws.csv`: attempted WebSocket sampling, when available.

Summary fields include duration, interface, telemetry-port detection, host CPU,
packet/byte rates, and WebSocket sample counts. Check `ws_samples` before using
any `ws_*` summary values. A header-only file or zero samples is missing telemetry,
not a zero-latency measurement.

Compare explicitly selected runs rather than silently choosing unrelated files:

```bash
python3 - baseline.csv hakam.csv <<'PYTHON'
import csv, sys

def load(path):
    with open(path) as handle:
        return {row['metric']: row['value'] for row in csv.DictReader(handle)}

baseline, hakam = map(load, sys.argv[1:])
for metric in ('host_cpu_pct', 'rx_pps'):
    before, after = float(baseline[metric]), float(hakam[metric])
    print(f'{metric}: baseline={before:.2f}, hakam={after:.2f}, delta={after-before:+.2f}')
PYTHON
```

Replace the filenames with two results from the same workload and comparable
conditions. A different received packet rate can change CPU utilization, so
compare offered load and delivered rate alongside CPU.

## Known issues / future work

- Existing checked-in WebSocket captures are header-only. Validate the sampler before publishing new latency or drop-counter series; `/proc` measurements are collected separately.
- No real-NIC benchmark, PASS-path timing, or application response-time measurement is included.
- Clean and DPI workloads require validation of listener state, payload delivery, sampling, and block state before their labels can be used as evidence of the intended path.
- The Python generator and VM networking constrain throughput. No universal packet-rate ceiling or hardware-independent latency claim follows from these results.
