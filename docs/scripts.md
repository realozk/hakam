# Hakam — Scripts Reference

All scripts live in `scripts/`. Run them from the repo root inside the VM unless noted otherwise.

---

## Demo — run order on stage

### `setup-demo.sh`
**Run once per VM boot, before anything else.**

Creates `dummy0` if it doesn't exist, brings it up, and adds every IP alias the demo needs:
- `10.99.0.10` — target (database)
- `10.99.1.10`, `10.99.2.10` — workstations PC#1 / PC#2
- `10.99.1.11–19`, `10.99.2.11–19` — 18 rotating attack sources
- `10.99.3.10–19` — 10 benign sources (separate pool so blocked attackers never silence real users)

Also relaxes `rp_filter` on `dummy0` so spoofed-source packets aren't silently dropped.

```bash
./scripts/setup-demo.sh
```

---

### `demo-cycle.sh`
**The main demo driver.** Loops through 6 phases (~113 s per cycle) that take the threat level from NOMINAL → SEVERE → back, exercising every visual on the HUD. Blends benign traffic into every phase (5:1 benign:attack ratio during calm phases, 1:1 during PEAK).

| Phase | Name | Duration | What fires |
|------:|------|:--------:|-----------|
| 0 | BASELINE | 12 s | 6 benign requests — calm metrics |
| 1 | FIRST CONTACT | 12 s | 1 SQLi + 1 XSS, 10 benign |
| 2 | RECON SWEEP | 10 s | 8 Recon bursts, 40 benign (5:1) |
| 3 | MULTI-VECTOR | 24 s | 1 shot per family (11 families), 55 benign |
| 4 | PEAK ASSAULT | 20 s | 100 random attacks at 6/s, 100 benign (1:1) |
| 5 | COOLDOWN | 35 s | No attacks, 5 benign — threat level decays |

**Live controls** (no Enter needed):

| Key | Action |
|-----|--------|
| `space` | Pause / resume |
| `n` | Skip to next phase |
| `r` | Restart current phase |
| `0`–`5` | Jump to phase N |
| `q` | Quit |
| `?` | Show keymap |

**Flags:**

```bash
./scripts/demo-cycle.sh                # auto loop
./scripts/demo-cycle.sh --manual       # wait for ENTER before each phase
./scripts/demo-cycle.sh --start-at 3  # begin at phase 3
```

---

### `attack.sh`
**Legacy four-scenario attack script.** Runs SQLi, SYN flood, LFI, and RCE scenarios in sequence, pausing between each so you can narrate. Predates `demo-cycle.sh` — use `demo-cycle.sh` for the polished 6-phase story; use this for quick ad-hoc testing.

```bash
./scripts/attack.sh [IFACE] [TARGET_IP]
# defaults: dummy0  10.99.0.1
```

Prerequisites: `hping3`, `curl`, `nc`.

---

### `seclist-attack.sh`
**Randomised attack payload firehose.** Self-contained corpus of ~200 payloads across 12 attack families (SQLi, XSS, RCE, LFI, SSRF, XXE, Log4Shell, NoSQLi, SSTI, WebShell, Recon, CVE). Called internally by `demo-cycle.sh`; also useful standalone for testing new signatures or running evasion experiments.

```bash
./scripts/seclist-attack.sh                  # 30 random shots
./scripts/seclist-attack.sh -n 100           # 100 shots
./scripts/seclist-attack.sh -c               # continuous (Ctrl-C to stop)
./scripts/seclist-attack.sh -k SQLi          # one family only
./scripts/seclist-attack.sh -k XSS -n 50    # 50 XSS payloads
./scripts/seclist-attack.sh -l               # list categories + payload counts
./scripts/seclist-attack.sh -d 500           # 500ms between shots
./scripts/seclist-attack.sh -t 10.99.0.10:80
```

---

### `benign-traffic.sh`
**Legitimate HTTP traffic generator.** Proves Hakam's zero false-positive rate by sending clean GET requests from a dedicated benign pool (`10.99.3.x`) that never overlaps with the attack pool. Called silently in the background by `demo-cycle.sh`; run standalone to test or demonstrate the `benign_passed` counter in `stats`.

24 clean paths (e.g. `/products`, `/api/v1/users?page=1`, `/health`) across 5 realistic user agents (Chrome, Safari, Firefox, curl, Safari mobile).

```bash
./scripts/benign-traffic.sh              # 20 requests, 400ms apart
./scripts/benign-traffic.sh -n 50       # 50 requests
./scripts/benign-traffic.sh -c          # continuous
./scripts/benign-traffic.sh -d 200      # 200ms between requests
./scripts/benign-traffic.sh -t 10.99.0.10:80
```

After running, check hakam-node: `stats` → `benign passed` should be non-zero with no blocks for `10.99.3.x`.

---

---

### `evasion-test.sh`
**Runs 30 payload mutations through a live Hakam instance and reports HIT or MISS for each.** Used to populate `docs/evasion.md` and verify the table is still accurate after signature changes. Not needed during demos — run it in the VM before a talk to confirm nothing regressed.

Spawns transient source IPs on `10.99.4.x` (one per test, removed on exit) so each mutation gets a fresh, unblocked source.

```bash
./scripts/evasion-test.sh
# env overrides:
TARGET=10.99.0.10 WS_PORT=8080 ./scripts/evasion-test.sh
```

Prerequisites: `websocat` (`cargo install websocat`), `hakam-node` running, `dummy0` up.

---

## Health checks

### `preflight.sh`
**Run on the Mac ~60 s before going on stage.** Walks 16 checks across Mac tooling, VM reachability, kernel modules, build artifacts, and port state. Emits a single PASS / FAIL verdict with colour-coded results and fix hints for every failure.

```bash
./scripts/preflight.sh
# env overrides:
VM_NAME=hakam ./scripts/preflight.sh
WS_PORT=8080    ./scripts/preflight.sh
```

Exit code `0` = stage-ready. Exit code `1` = at least one blocker.

---

### `smoke.sh`
**Post-boot sanity check for hakam-node.** Verifies the process is alive, the WebSocket accepts connections, METRICS events arrive within 3 s, BLOCK/UNBLOCK round-trips work, and the blocklist is clean after the test. Faster than `preflight.sh`; run this after `cargo xtask run` to confirm the binary is healthy before running the full preflight.

```bash
./scripts/smoke.sh
# env overrides:
WS_HOST=localhost WS_PORT=8080 ./scripts/smoke.sh
```

Prerequisites: `websocat` (`cargo install websocat`), `nc`.

---

## Benchmark

### `bench-setup.sh`
**Provisions the benchmark rig.** Creates a `veth` pair across a network namespace (`phbench-gen`) so traffic traverses the real kernel network stack — much closer to a real NIC than `dummy0`, and supports native-mode XDP. Idempotent.

```
netns phbench-gen           root ns
  phbench-gen (10.200.0.2)  ──veth──  phbench0 (10.200.0.1)
  (load generator)                    (Hakam attaches here)
```

```bash
sudo ./scripts/bench-setup.sh
```

---

### `bench-run.sh`
**Runs one benchmark workload and writes a CSV row.** Run twice — once with hakam-node down (baseline) and once with it attached to `phbench0`. Diffing the two gives Hakam's overhead.

| Workload | What it measures |
|----------|-----------------|
| `clean` | Short TCP HTTP GETs, no signature hits — PASS path overhead |
| `flood` | UDP flood from netns — rate-limit + drop path |
| `dpi` | HTTP with SQLi payloads — DPI loop overhead |

Outputs go to `bench/results/<label>-<ts>.csv` (summary) and `bench/results/<label>-<ts>.ws.csv` (raw WebSocket samples).

```bash
./scripts/bench-run.sh -w clean -l baseline-clean
./scripts/bench-run.sh -w clean -l hakam-clean
./scripts/bench-run.sh -w flood -l hakam-flood -d 90
./scripts/bench-run.sh -w dpi   -l hakam-dpi
```

See `bench/README.md` for the full reproduction procedure.

---

### `bench-teardown.sh`
**Undoes `bench-setup.sh`.** Removes `phbench0` (deletes both veth ends) and the `phbench-gen` netns. Idempotent.

```bash
sudo ./scripts/bench-teardown.sh
```

---

## Observability

### `bpftrace-overlay.sh`
**Live kernel counters in a side terminal.** Every number shown here is read directly from the kernel — useful on stage to prove the HUD is not fabricating data.

| Mode | What it shows |
|------|--------------|
| `drops` | XDP_DROP events per second (default) |
| `latency` | Histogram of XDP program run time in nanoseconds |
| `connects` | Every outbound `connect()` with PID and comm |
| `all` | Instructions for running all three in separate panes |

```bash
./scripts/bpftrace-overlay.sh           # drop counter
./scripts/bpftrace-overlay.sh latency
./scripts/bpftrace-overlay.sh connects
./scripts/bpftrace-overlay.sh all
```

Prerequisites: `bpftrace` installed in the VM.

---

## Quick-reference order for a live demo

```
# VM — once per boot
./scripts/setup-demo.sh
cargo xtask run --iface lo --mode skb

# Mac — 60 s before stage
./scripts/preflight.sh

# VM — in a second terminal, when you're ready
./scripts/demo-cycle.sh

# VM — optional side terminal (proves HUD isn't lying)
./scripts/bpftrace-overlay.sh drops
```
