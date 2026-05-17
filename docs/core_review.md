# Hakam — Core Arsenal-Readiness Review

> Snapshot of the code path that has to survive a 30-minute Arsenal slot. Scope: kernel program, userspace controller, signatures, build, demo scripts. UI / docs / naming are out of scope here — handle separately.

**Verdict: Arsenal-ready.** The functional path runs end-to-end. The known weaknesses are honest and documented in code. No blockers.

---

## What runs, what's measured

| Layer | LOC | What it does | State |
|-------|----:|-------------|:-----:|
| `hakam-ebpf/src/main.rs` | 310 | XDP ingress + TC egress + `sys_enter_connect` tracepoint, 7 maps (BLOCKLIST LPM, PACKET_COUNTER, LAST_SEEN, PAYLOAD_EVENTS ring, CONNECT_EVENTS ring, DROP_COUNTER per-CPU, LATENCY_HIST per-CPU log2) | ✅ |
| `hakam-node/src/main.rs` | 1338 | 6 async tasks (WS server, metrics ticker, DPI loop, connect loop, TTL sweep, CLI), 9 CLI commands, 5 telemetry event types | ✅ |
| `hakam-common/src/lib.rs` | 150 | Shared `PayloadEvent`, `ConnectEvent`, `Ipv4Addr`, `PAYLOAD_LEN=64` | ✅ |
| `hakam-node/src/signatures.rs` | — | 203 patterns across 12 families, all uppercased for case-insensitive match | ✅ |
| `xtask/src/main.rs` | 218 | `build-ebpf`, `run`, `check`, `test` — clears stale XDP/TC, auto-detects iface | ✅ |
| 11 demo / bench / evasion scripts | — | `setup-demo`, `demo-cycle`, `attack`, `seclist-attack`, `benign-traffic`, `preflight`, `smoke`, `bench-{setup,run,teardown}`, `bpftrace-overlay`, `evasion-test` | ✅ |

**Build status (VM, `orb -m hakam`):**
- `cargo xtask check` → clean
- `cargo xtask test` → 11/11 passing
- `cargo xtask build-ebpf` → ELF produced (one benign LLVM lib warning, non-fatal)

---

## What is genuinely Arsenal-grade

### 1. Kernel/userspace boundary is honest and defensible
- Pattern matching is in **userspace** (the verifier won't take loops + string libs in BPF). The kernel ships the **drop**, the **rate limit**, the **LPM lookup**, and the **payload sample feed**. This is the right answer when a reviewer asks "where does the regex run."
- Every raw pointer deref goes through `ptr_at<T>` with an explicit bounds check (`start + offset + sizeof(T) <= end`). The verifier accepts the program; no `invalid mem access` warnings.
- No unbounded loops, no heap, no reachable panics. Panic handler is `loop {}` — provably unreachable under release + `panic = "abort"`.

### 2. Instrumentation is real, not mocked
- CPU%: actual delta of idle/total from `/proc/stat`
- Drop counter: actual sum of per-CPU `DROP_COUNTER` map
- Latency p50/p99: actual reduction over the per-CPU 64-bucket log2 histogram (`LATENCY_HIST`)
- Bandwidth: actual deltas from `/proc/net/dev`
- RSS: actual `VmRSS` from `/proc/self/status`
- A reviewer with `bpftool map dump name BLOCKLIST` sees the same entries the CLI shows.

### 3. The 6 async tasks have correct shutdown semantics
- All maps are wrapped in `Arc<Mutex<...>>`, no panics on concurrent access
- WebSocket `broadcast::error::RecvError::Lagged` is logged, not fatal
- Ctrl-C drops `_link_xdp`, `_link_tc`, `_link_tp` — aya auto-detaches the kernel programs. No leaks after a clean exit.
- The CLI runs on `task::spawn_blocking`, never starves the async runtime.

### 4. The demo is presenter-controlled
`demo-cycle.sh` accepts `space` (pause), `n` (next), `r` (restart), `0-5` (jump), `q` (quit), `?` (help) — no fixed wall-clock surprises during Q&A.

### 5. The evasion story is honest
30 mutations recorded in `docs/evasion.md`, 10 HIT / 20 MISS, every result derived from a one-line code path explanation. Q&A answer is rehearsed at ~25 seconds.

### 6. Benchmark is reproducible
veth + netns rig (`bench-setup.sh`) supports native-mode XDP inside a VM. Three workloads (`clean`, `flood`, `dpi`), CSV output under `bench/results/`. A reviewer can re-run from a fresh clone in <10 commands.

---

## Known weaknesses (in priority order)

### Low-risk for Arsenal

| # | Issue | Where | Why it's OK for stage |
|--:|------|-------|----------------------|
| 1 | `PACKET_COUNTER` is a regular `HashMap`, not per-CPU — rate limit is racy across CPUs (worst case `RATE_LIMIT × num_cpus` before block fires) | `hakam-ebpf/src/main.rs:49` | Already commented honestly in the code. On a demo VM with low core count this is invisible. A reviewer who notices will be impressed by the honest comment. |
| 2 | DPI loop is O(signatures × payload) — ~13K `contains()` per matched packet at peak | `hakam-node/src/main.rs:698` | Bottleneck is the kernel→userspace transfer, not the match. Real production would use Aho-Corasick; not an Arsenal blocker. |
| 3 | `sys_enter_connect` tracepoint is **system-wide** | `hakam-ebpf/src/main.rs:179` | Worth one sentence on stage: "every connect() in the VM". On a demo VM, traffic is yours. |
| 4 | WebSocket has no auth — `0.0.0.0:8080/ws` is open | `hakam-node/src/main.rs:464` | Required so a remote Mac browser can connect. Mention on stage that production would TLS+token this. |
| 5 | `hakam-node` requires the BPF ELF at a relative path | `hakam-node/src/main.rs:176` | `xtask run` always launches from the workspace root, so the relative path resolves. Acceptable. |

### Pre-stage owed (already tracked in `blackhat_readiness_plan.md`)

| # | Item | Status |
|--:|------|:------:|
| 1 | `demo/hakam-hud.thumbnail.png` referenced in README is missing | Owed — Phase 4 recordings |
| 2 | `demo/hakam-cycle.cast` (asciinema fallback) | Owed — Phase 4 recordings |
| 3 | `demo/hakam-hud.mp4` (OBS fallback) | Owed — Phase 4 recordings |

User has indicated these wait for the UI redesign — correct call.

### Not required for Arsenal (would be nice)

| # | Item | Effort |
|--:|------|:------:|
| 1 | GitHub Actions running `cargo xtask check` + `cargo xtask test` on push | 30 min |
| 2 | One-line `cargo xtask smoke` that auto-runs `scripts/smoke.sh` end-to-end | 20 min |
| 3 | DPI metric on the WS feed (`benign_passed`, `total_http_seen`) — currently only in CLI `stats` | 15 min |

---

## End-to-end functional path (verified)

```
1. cargo xtask run --iface lo --mode skb
   → builds eBPF + hakam-node, clears stale hooks, launches with sudo

2. hakam-node banner prints
   → ◉ XDP armed on [lo] · mode=SKB
   → ◉ TC armed on [lo]
   → ◉ tracepoint armed
   → ◉ telemetry ws://0.0.0.0:8080/ws
   → ◉ reachable at ws://192.168.139.X:8080/ws

3. Browser connects to http://localhost:5173 → HUD shows METRICS

4. ./scripts/demo-cycle.sh
   → phase banners, fire_one() / fire_burst() / fire_random()
   → fire_benign() in background, hits 10.99.0.10:80 from 10.99.3.x

5. eBPF XDP hook samples payload → PAYLOAD_EVENTS ring buffer

6. hakam-node dpi_task reads ring → uppercases → matches signature
   → INTERCEPT printed in CLI
   → BLOCKLIST.insert(src_ip, now_ns)
   → BLOCK telemetry sent on WS
   → HUD shows block

7. Subsequent packets from src_ip → BLOCKLIST hit → XDP_DROP
   → DROP_COUNTER increments
   → LATENCY_HIST bucket increments
   → metrics_ticker reports drop count + p50/p99 every 1s

8. After 120s → ttl_sweep_task removes entry
   → UNBLOCK telemetry on WS
   → HUD shows unblock

9. Manual `block 10.99.1.11` in CLI → same path
   `unblock 10.99.1.11` → same path
   `clear` → removes everything, broadcasts UNBLOCK for each

10. Ctrl-C → shutdown_tx fires → aya detaches XDP/TC/tracepoint
    → "Hakam-Node terminated. Ghost mode: OFF."
```

Every node in this chain is exercised in the demo cycle. Every numeric claim on the HUD comes from a real kernel counter.

---

## What to do next (your call)

The user noted UI / docs / naming are next. Suggested order:

1. **UI redesign first** — affects the screenshot, affects the demo cast, blocks Phase 4 recording.
2. **Naming pass** — if the project name changes, that propagates into README, banner ASCII art, crate names (`hakam-*`), telemetry JSON `type` fields, signature category labels.
3. **Docs polish** — `start_guide.md`, `docs/*.md`, `README.md`. All currently consistent with `hakam-*` naming, will need search-and-replace if renamed.
4. **Phase 4 recordings** — last, after UI + naming are settled.

The core does not need touching for any of those.
