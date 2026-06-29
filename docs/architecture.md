# Hakam — Architecture

> **One-page reference.** Where every claim in the README and on stage is grounded.
> Read time: ~90 seconds.

---

## 1 · The honest one-liner

> *Hakam is a kernel-resident packet filter (XDP + TC + tracepoint) that samples the first 64 B of every TCP segment into a userspace ring buffer, where a 203-signature Aho-Corasick matcher runs over a per-flow reassembly buffer. On a hit, userspace pushes the source IP into a kernel LPM trie, after which all further traffic from that IP drops at the driver edge.*

The string match itself is **userspace**. Nothing else makes sense under the eBPF verifier — no string library, no unbounded loops, no regex engine. What's *kernel-resident* is the **drop**, the **rate limit**, the **CIDR blocklist lookup**, and the **payload sample feed**. That's the right answer to *"where does the regex run."*

---

## 2 · Kernel / userspace boundary

```
                ┌──────────────────────────────────────────────────────────────┐
                │  KERNEL  (hakam-ebpf,  no_std,  ≤310 LOC)                   │
                │                                                              │
   ingress  →   │   XDP hook  ──┬──► BLOCKLIST (LpmTrie<u32,u64>) ──► DROP      │
   (NIC)        │               │                                              │
                │               ├──► RATE LIMIT (HashMap, 500 pps/IP/window)    │
                │               │       overflow → BLOCKLIST + DROP             │
                │               │                                              │
                │               └──► sample first 64 B of TCP payload ──┐      │
                │                                                       ▼      │
                │   PAYLOAD_EVENTS RingBuf  (1 MiB)  ───────────────────┐      │
                │                                                       │      │
   egress   →   │   TC classifier ─► BLOCKLIST lookup ─► TC_ACT_SHOT    │      │
                │                                                       │      │
   syscalls →   │   tracepoint sys_enter_connect ─► CONNECT_EVENTS RB   │      │
                │                                                       │      │
                │   maps: DROP_COUNTER, LATENCY_HIST (per-CPU log2 buckets)    │
                └─────────────────────────────────┬─────────────────────┘      │
                                                  │ ring buffers                │
                                                  ▼                             │
                ┌──────────────────────────────────────────────────────────────┐
                │  USERSPACE  (hakam-node, tokio, ~1.3k LOC)                  │
                │                                                              │
                │   payload_task : pull RB → reassembler.ingest(4-tuple) →    │
                │                  HTTP method gate → Aho-Corasick scan →      │
                │                  fallback URL-decoded scan; on hit:          │
                │                    1. insert src_addr into BLOCKLIST (LPM)   │
                │                    2. reassembler.forget(flow)               │
                │                    3. broadcast BLOCK json on telemetry      │
                │                    4. update DpiStats counters               │
                │                                                              │
                │   metrics_ticker (1 s) : drop_counter sum, p50/p99 from      │
                │                          LATENCY_HIST, /proc/{stat,net/dev,  │
                │                          self/status} → broadcast METRICS    │
                │                                                              │
                │   connect_task : drain CONNECT_EVENTS → broadcast CONNECT    │
                │                                                              │
                │   ttl_sweep_task (30 s) : evict BLOCKLIST entries older      │
                │                           than BLOCK_TTL_SECS (120 s)        │
                │                                                              │
                │   ws_server   : warp on ${--bind}:${--ws-port}/ws fan-out   │
                │                 via tokio::broadcast (cap 512) to N HUDs;    │
                │                 default 127.0.0.1:8080 (demo uses 0.0.0.0)   │
                │                                                              │
                │   stdin CLI   : block / unblock / list / status / rules /    │
                │                 stats / clear / help / quit                  │
                └──────────────────────────────────────────────────────────────┘
```

---

## 3 · What each hook does (5-line table)

| Hook | Program type | Decides | Forwards | Notes |
|------|--------------|---------|----------|-------|
| **XDP ingress** | `xdp` | `XDP_DROP` if src in BLOCKLIST or rate ≥ 500 pps; else `XDP_PASS` | First 64 B of TCP payload + full 4-tuple (src/dst addr, src/dst port) via `PAYLOAD_EVENTS` ring | Latency timed only on DROP path |
| **TC egress** | `classifier` | `TC_ACT_SHOT` if dst in BLOCKLIST; else `TC_ACT_OK` | — | Stops outbound exfil to a known-bad CIDR |
| **Tracepoint** | `tracepoint sys_enter_connect` | always returns 0 (observe-only); skips events outside `MONITOR_CFG` CIDR before reserving a ring slot | PID + `comm` + dst sockaddr via `CONNECT_EVENTS` | Surfaces *which process* is talking out — IPv4 only |

---

## 4 · Data flow on attack

1. Packet arrives → XDP. Not in BLOCKLIST, not rate-limited → `XDP_PASS`. First 64 B of TCP payload + full 4-tuple (`src_addr`, `dst_addr`, `src_port`, `dst_port`) pushed to `PAYLOAD_EVENTS`.
2. `payload_task` pulls from the ring, constructs a `FlowKey`, and calls `Reassembler::ingest`. The per-flow buffer (default 256 B cap, 30 s TTL) accumulates segments from the same 4-tuple **in TCP sequence order** (Phase 2 #7) — out-of-order delivery is reordered and retransmits are deduped, using the `seq` the kernel stamps on each event. Separately, XDP records every TCP segment into the kernel `CONNTRACK` flow table (`seq_next`/`last_ts`/`packets`/`dir`), whose live size is surfaced as `active_flows`.
3. Match runs on the **reassembled view**, not just this segment. First, the HTTP method gate (`GET ` / `POST ` / `PUT ` / `HEAD ` / `DELETE ` / `OPTIONS ` / `PATCH ` / `CONNECT ` / `TRACE `). Then the Aho-Corasick automaton over all 203 signatures (case-insensitive on raw bytes). If that misses, a single-pass URL-decoded view (`%XX` → byte, `+` → space) is scanned as a fallback — so `UNION%20SELECT` and `UNION+SELECT` both hit.
4. On hit: userspace inserts `(src_addr, /32, boot_time_ns)` into the kernel `BLOCKLIST` LpmTrie via aya, calls `Reassembler::forget(flow)` so the same connection can be re-inspected (HTTP keep-alive), broadcasts `BLOCK` JSON to every WS subscriber, and increments `DpiStats`.
5. Every subsequent packet from that IP hits the BLOCKLIST branch in XDP and is dropped *before* IP routing.
6. After 120 s, `ttl_sweep_task` removes the entry and broadcasts `UNBLOCK`.

**On the packet path, detection is reactive, not preventive** — the first attacking *flow* always passes through to the host (one segment for a single-shot attack; up to a few segments while the reassembler waits for enough bytes). The follow-up flood is what gets stopped at the driver edge. This is intentional (keeps the kernel program verifier-safe) but it's the honest answer when someone asks "did the first SQLi reach the app."

**On the `connect()` syscall path, the BPF-LSM `socket_connect` hook (Phase 2 #6) is preventive** — a destination in `CONNECT_POLICY` makes the originating `connect(2)` return `-EPERM`, so the connection never forms and no packet is ever created. Honest scope: this covers `connect()`-based IPv4 flows only. Connectionless UDP (`sendto` without `connect`) and the packet path above stay reactive — TC egress is the catch-all there. The policy is destination-keyed (deny anyone from reaching a listed dst), not task-keyed; per-process *attribution* on a block is a separate mechanism (#8).

---

## 5 · Telemetry shapes

All JSON, line-delimited over WS at `:8080/ws`, broadcast to all subscribers via `tokio::broadcast<String>` (cap 512, lagging clients drop messages):

| `type`     | Fields |
|------------|--------|
| `METRICS`  | `cpu`, `latency_p50_ns`, `latency_p99_ns`, `dropped`, `rx_bps`, `tx_bps`, `mem_kb` |
| `BLOCK`    | `source`, `target`, `payload?`, `action`, `category?`, `severity?` |
| `UNBLOCK`  | `source` |
| `CONNECT`  | `pid`, `comm`, `dst`, `port` |
| `EVENT`    | `message`, `level` |

The HUD (`hakam-ui`) subscribes and renders. It does not push anything back — strictly read-only.

---

## 6 · Maps inventory

| Map | Type | Capacity | Purpose |
|-----|------|---------:|---------|
| `BLOCKLIST` | `LpmTrie<u32,u64>` | 1024 | Drop decision, supports CIDR. Value = boot-time ns of insert (TTL). |
| `PACKET_COUNTER` | `LruPerCpuHashMap<u32,u64>` | 1024 | Per-IP packet count in current 1-second window; LRU eviction prevents new-attacker starvation past 1024 unique sources. |
| `LAST_SEEN` | `LruPerCpuHashMap<u32,u32>` | 1024 | Per-IP last window-second; rolls counter on change. |
| `PAYLOAD_EVENTS` | `RingBuf` | 1 MiB | TCP payload samples + 4-tuple → DPI. |
| `CONNECT_EVENTS` | `RingBuf` | 512 KiB | Outbound `connect()` events. |
| `CONNTRACK` | `LruHashMap<FlowKey,FlowState>` | 65536 | Phase 2 #7 flow table — `seq_next`/`last_ts`/`packets`/`dir` per 4-tuple. LRU eviction; count surfaced as `active_flows`. |
| `CONNECT_POLICY` | `LpmTrie<u32,u64>` | 1024 | Phase 2 #6 — destinations denied at the `socket_connect` LSM hook. |
| `DROP_COUNTER` | `PerCpuArray<u64>` | 1 | Total drops, summed in userspace. |
| `LATENCY_HIST` | `PerCpuArray<u64>` | 64 | log2-bucketed XDP_DROP latency. |
| `RING_OVERFLOW` | `PerCpuArray<u64>` | 1 | Counter of samples we couldn't enqueue (ring full) — surfaced in CLI `stats`. |
| `MONITOR_CFG` | `Array<u64>` | 1 | Optional CIDR scope for the connect tracepoint. High 32 = network, low 32 = mask. Cell = 0 → monitor all. |

`BLOCKLIST` capacity is **1024 entries** — a real concern at scale, not at demo scale. Worth calling out if asked.

---

## 7 · Honest limits

The full evasion table (30 mutations, hit/miss verified by `cargo test --test dpi_matcher`) lives in [`evasion.md`](evasion.md). Headline gaps:

- **No regex.** Aho-Corasick substring matching with ASCII case-folding plus a single-pass URL-decode fallback. **Recursive decoding (e.g. `%2520`) is not unwound**, by design — it amplifies false-positive surface on legitimate URLs.
- **First packet always passes.** Detection is reactive (see §4). Slow-and-low scanners that send one payload per source IP from a wide pool are a worst case.
- **64-byte sample window per segment.** Reassembly stitches segments from the same 4-tuple into a 256-byte buffer **in TCP sequence order** (Phase 2 #7), so the split-segment evasion is closed for both in-order *and* out-of-order delivery, and retransmits are deduped. The residual gap is the sample window itself: a single oversized segment still truncates at 64 B, and a payload split across a segment Hakam never sampled (sub-64-byte segments aren't sampled) leaves a hole.
- **Per-CPU rate limit.** The `RATE_LIMIT = 500 pps` is per-CPU per-IP because of the way HashMap lookups work in eBPF, so the worst-case effective limit is `500 × num_cpus`. Fine at demo scale, not a hard guarantee on bigger boxes.
- **IPv4 only.** No IPv6 path in any of the three programs.
- **`dummy0` SKB-mode** in the demo. Native-mode XDP on a real NIC has not been benchmarked yet — that's Arsenal Phase 3 (driver-mode + perf rewrite).
- **Blocklist capped at 1024 entries.** A determined attacker with >1024 source IPs would saturate the trie before the 120 s TTL drains it.

---

## 8 · Test coverage

**56 passing tests across 5 targets** (cross-platform — no Linux required):

| Target | Count | Pins |
|--------|------:|------|
| `hakam-common` lib | 10 | `Ipv4Addr` byte order, std interop, `PayloadEvent` layout (16 + `PAYLOAD_LEN` bytes), `ConnectEvent` layout. |
| `hakam-node` lib · `signatures` | 4 | Uppercase / non-empty / ≤ `PAYLOAD_LEN` / `CATEGORIES`-in-sync invariants. |
| `hakam-node` lib · `reassembly` | 10 | Concatenation, flow isolation, `forget`, GC eviction, buffer cap, flow cap, retransmit dedupe, out-of-order reassembly. |
| `hakam-node` lib · `monitor` | 5 | CIDR packing for `MONITOR_CFG` across /0, /16, /24, /32 and the monitor-all sentinel. |
| `hakam-node` `tests/dpi_matcher.rs` | 25 | One test per row of [`evasion.md`](evasion.md) + smoke + HTTP-gate coverage. |
| `hakam-node` `tests/reassembly.rs` | 5 | End-to-end split-segment attacks (in-order + reordered); benign + attacker flow isolation; keep-alive `forget`. |
| `hakam-node` `tests/unit_tests.rs` | 11 | Byte order, mock blocklist, command tokenisation, IP parsing, capacity. |

What's still missing:
- `hakam-ebpf` — **no tests.** No verifier-safe test harness wired up. Validation is `cargo xtask build-ebpf` + manual smoke under `cargo xtask run`.
- **No live integration test** loads the eBPF program, fires a packet, and asserts XDP_DROP. Manual smoke via `scripts/smoke.sh` and `scripts/demo-cycle.sh`.
