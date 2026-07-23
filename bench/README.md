# Hakam — Benchmark rig

> **What this is.** A reproducible measurement harness for Hakam's overhead. Sets up a `veth`-pair / `netns` topology that supports native-mode XDP (closer to a real NIC than `dummy0`), runs three workloads (PASS path, DROP path, DPI loop), and emits CSV.
>
> **Why a veth pair.** `dummy0` doesn't go through the full kernel network stack on the receive side — XDP attaches in *generic/SKB mode only*, which is the slow path. veth supports native-mode XDP since kernel 5.15. We can't do native NIC offload (HW mode) inside a VM, but veth + DRV mode is the closest credible thing.

---

## What this measures (and what it doesn't)

**Measures honestly:**
- CPU% delta on the host with vs. without Hakam attached, under identical packet load.
- Kernel-side pps the rig sustains (rx counters on `phbench0`).
- Hakam's XDP_DROP latency (`p50`/`p99`) read straight from the `LATENCY_HIST` per-CPU map. **Read it live from the running node with the `stats` command** — that's the reliable source (e.g. p50 48 ns, p99 96 ns over 41.5M drops). The harness also tries to sample it over the WS feed into `<label>.ws.csv`, but that capture is currently unreliable (see Known issues) — prefer `stats`.
- Hakam's drop counter delta over the run window.

**Does NOT measure (and why):**
- Real-NIC line-rate sustained throughput. We're inside a VM. The pps ceiling here is the cost of `python3 → netns → veth → kernel → veth → kernel`, not Hakam. Treat absolute pps as environment-dependent — what matters is the **delta** between baseline and hakam passes.
- Hardware offload (XDP HW mode). Requires a SmartNIC; not our target deployment for the talk.
- Application-level latency. We don't run a real HTTP server on port 80 — packets reach XDP and that's the boundary we care about.

---

## Reproduction — under 10 commands

Run on the Linux VM (the repo mounts at `~/hakam`):

```bash
cd ~/hakam

# 1. Provision the rig (idempotent)
./scripts/bench-setup.sh

# 2. Baseline pass — hakam is NOT running
./scripts/bench-run.sh -w clean -l baseline-clean -d 60

# 3. Start hakam in another terminal in driver mode if your kernel supports it
#    cargo xtask run --iface phbench0 --mode drv
#    (fall back to --mode skb on older kernels)

# 4. Hakam-attached passes
./scripts/bench-run.sh -w clean -l hakam-clean -d 60   # PASS path overhead
./scripts/bench-run.sh -w flood -l hakam-flood -d 60   # rate-limit + DROP path
./scripts/bench-run.sh -w dpi   -l hakam-dpi   -d 60   # DPI loop

# 5. Stop hakam (`quit` at the prompt)

# 6. Tear down the rig
./scripts/bench-teardown.sh
```

Results land in `bench/results/<label>-<UTC-timestamp>.csv`.

---

## Workloads

| `-w` | What it sends | What it stresses on Hakam |
|---|---|---|
| `clean`  | Short TCP conns to `${HOST_IP}:80` with benign HTTP `GET /healthz?ts=…` requests | Pure XDP_PASS path. No DPI hits. No blocks. Measures the cost of "kernel ran XDP and let the packet through." |
| `flood`  | Tight UDP send loop at ~5k pps from `${NS_IP}` to `${HOST_IP}:9999` | Triggers the in-kernel rate limiter (>500 pps from one IP → auto-block). After ~1 s every packet hits the BLOCKLIST and goes through the DROP hot path. Best signal for pps overhead under sustained drop load. |
| `dpi`    | HTTP requests carrying SQLi/XSS/Log4Shell/LFI/RCE payloads at ~20 shots/s | Exercises `dpi_task`: `is_http_request` → uppercase → `contains()` over ~210 signatures → BLOCKLIST insert → BLOCK telemetry. Stresses the userspace pipeline. |

---

## Output format

### Summary CSV (`<label>-<ts>.csv`)
One row per metric. Easy to grep, easy to diff:

```
metric,value,unit
label,hakam-clean,
workload,clean,
ts_utc,20260509-014530Z,
duration,60.012,s
host_iface,phbench0,
hakam_listening,1,bool
host_cpu_pct,11.32,%
rx_pkts,12480,pkts
tx_pkts,12480,pkts
rx_pps,207.96,pps
tx_pps,207.96,pps
rx_bps,1234567,bps
ws_samples,57,n
ws_p50_ns_avg,68,ns
ws_p99_ns_avg,192,ns
ws_p99_ns_max,256,ns
ws_dropped_max,5821,pkts
ws_dropped_delta,4127,pkts
```

(Numbers above are illustrative — real values come from your run.)

### Raw WS samples (`<label>-<ts>.ws.csv`)
One row per second of WS METRICS (only emitted when `hakam_listening=1` and `websocat` is installed):

```
ts_ms,cpu,latency_p50_ns,latency_p99_ns,dropped,rx_bps,tx_bps,mem_kb
1748400000123,8.4,42,128,4321,5132,144,18752
1748400001147,11.2,68,192,4523,5188,148,18752
…
```

---

## Diffing two runs

Two clean ways:

**One-liner — side-by-side metrics:**
```bash
paste -d',' \
  <(awk -F, 'NR>1{print $1","$2}' bench/results/baseline-clean-*.csv) \
  <(awk -F, 'NR>1{print $2}'      bench/results/hakam-clean-*.csv)
```

**Quick overhead computation:**
```bash
python3 - <<'PY'
import csv, glob, sys
def load(p):
    with open(p) as f: return {r['metric']: r['value'] for r in csv.DictReader(f)}
b = load(sorted(glob.glob('bench/results/baseline-clean-*.csv'))[-1])
p = load(sorted(glob.glob('bench/results/hakam-clean-*.csv'))[-1])
print(f"CPU% baseline={b['host_cpu_pct']}  hakam={p['host_cpu_pct']}  Δ={float(p['host_cpu_pct'])-float(b['host_cpu_pct']):+.2f}")
print(f"pps baseline={b['rx_pps']}  hakam={p['rx_pps']}  Δ={float(p['rx_pps'])-float(b['rx_pps']):+.2f}")
PY
```

---

## Optional dependencies

Already on the VM (Ubuntu Jammy + OrbStack):
- `python3`
- `iproute2` (`ip`, `tc`)
- `bash`

**Strongly recommended — install `websocat` once before benching:**
```bash
cargo install websocat
```
Without it, the bench still records CPU% and pps from `/proc/stat` and `/proc/net/dev`. Latency and the drop counter are **not** lost regardless of websocat — read them any time from the running node with the `stats` command, which queries the `LATENCY_HIST` map and drop counter directly. `stats` is in fact the recommended way to get latency (see Known issues about the WS-feed capture).

Optional, only if you need a faster pps generator than the bundled Python one:
```bash
sudo apt install hping3 iperf3
```

---

## Topology layout

```
   netns: phbench-gen                          root ns
 ┌──────────────────────┐                   ┌────────────────────────┐
 │ phbench-gen          │ ── veth tunnel ── │ phbench0               │
 │ 10.200.0.2/24        │                   │ 10.200.0.1/24          │
 │ (load generator)     │                   │ (Hakam attaches)     │
 └──────────────────────┘                   └────────────────────────┘
```

`bench-setup.sh`:
1. `ip netns add phbench-gen`
2. `ip link add phbench0 type veth peer name phbench-gen`
3. moves the peer end into the netns
4. assigns `10.200.0.1/24` to `phbench0`, `10.200.0.2/24` to the peer
5. brings both up + `lo` in the netns
6. sets `rp_filter=2` on both (so spoofed-source DPI tests aren't dropped)

Override any of these via env: `NETNS`, `HOST_IF`, `NS_IF`, `SUBNET`, `HOST_IP`, `NS_IP`, `PREFIX`.

---

## Repeating-yourself checklist

Before recording numbers for a slide:

1. Run each workload **3 times per condition** and report the median, not a single shot.
2. Same VM state (no other heavy processes, same CPU governor).
3. `hakam_listening` column must be `0` for the baseline rows and `1` for the hakam rows. If it's the wrong value, the run is invalid.
4. For latency, read `drop latency p50`/`p99` from the node's `stats` command after a flood — that's the authoritative source. The harness's `ws_samples` column should ideally track your `-d` value (1 sample/s), but the WS-feed capture is currently unreliable (often `ws_samples=0`); don't block on it — CPU%/pps in the summary CSV are unaffected.
5. **Reset the blocklist between hakam workloads.** Once `10.200.0.2` is auto-blocked (which happens within ~1 s of the first hakam run because the workload exceeds 500 pps), every subsequent run just exercises the BLOCKLIST hot path and not the rate-limit or DPI paths. Either type `clear` at the `hakam@kernel ▸` prompt between workloads, or wait 120 s for the TTL to drain.
6. Commit results under `bench/results/`. The `.gitkeep` is there so the directory survives a clean clone.

---

## Known issues / future work

- **WS-feed latency capture is unreliable.** The harness samples `<label>.ws.csv` by piping `websocat` → a JSON picker, but in practice the client connects and receives zero `METRICS` frames (`ws_samples=0`), so the `.ws.csv` files come back header-only. This is a harness-plumbing quirk, not a Hakam defect — the kernel `LATENCY_HIST` map is populated correctly and is read straight from the running node via the `stats` command (p50 48 ns / p99 96 ns over 41.5M drops). **Use `stats` for latency; treat the `.ws.csv` path as best-effort.** CPU%/pps in the summary CSV are captured independently and are unaffected.
- **No native pktgen integration.** The Python flooders top out around 5–10k pps inside an arm64 VM. For real wire-rate numbers we need pktgen on a Linux host with a real NIC — out of scope for the demo machine but a natural Phase 2.5 follow-up.
- **No latency on PASS path.** `LATENCY_HIST` only times the DROP branch (see `hakam-ebpf/src/main.rs:81`). To get PASS-path overhead we'd need to time both branches in eBPF. The current bench just compares CPU% and pps deltas, which is the right measurement for "what cost does Hakam add to a clean packet."
- **No latency-injection control.** We don't yet have a way to assert "hakam adds ≤ 1 µs to a clean packet" — that would need a tx-side timestamp and an rx-side timestamp on the same NIC, which is hard inside a VM.
