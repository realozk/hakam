# Hakam — Architecture

> **One-page reference.** Where every claim in the README and on stage is grounded.
> Read time: ~90 seconds.

---

## 1 · The honest one-liner

> *Hakam is a kernel-resident packet filter (XDP + TC + tracepoint) that samples raw TCP payload bytes into a userspace ring buffer, where a ~210-pattern HTTP-anchored matcher runs. On a hit, userspace pushes the source IP into a kernel LPM trie, after which all further traffic from that IP drops at the driver edge.*

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
                │   dpi_task     : pull RB → check HTTP method prefix →        │
                │                  uppercase → contains() ~210 needles →       │
                │                  if hit:                                     │
                │                    1. insert src_addr into BLOCKLIST (LPM)   │
                │                    2. broadcast BLOCK json on telemetry      │
                │                    3. update DpiStats counters               │
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
                │   ws_server   : warp ws://0.0.0.0:8080/ws  fan-out via       │
                │                 tokio::broadcast (cap 512) to N HUDs         │
                │                                                              │
                │   stdin CLI   : block / unblock / list / status / rules /    │
                │                 stats / clear / help / quit                  │
                └──────────────────────────────────────────────────────────────┘
```

---

## 3 · What each hook does (5-line table)

| Hook | Program type | Decides | Forwards | Notes |
|------|--------------|---------|----------|-------|
| **XDP ingress** | `xdp` | `XDP_DROP` if src in BLOCKLIST or rate ≥ 500 pps; else `XDP_PASS` | First 64 B of TCP payload via `PAYLOAD_EVENTS` ring | Latency timed only on DROP path |
| **TC egress** | `classifier` | `TC_ACT_SHOT` if dst in BLOCKLIST; else `TC_ACT_OK` | — | Stops outbound exfil to a known-bad CIDR |
| **Tracepoint** | `tracepoint sys_enter_connect` | always returns 0 (observe-only) | PID + `comm` + dst sockaddr via `CONNECT_EVENTS` | Surfaces *which process* is talking out — IPv4 only |

---

## 4 · Data flow on attack

1. Packet arrives → XDP. Not in BLOCKLIST, not rate-limited → `XDP_PASS`. First 64 B of TCP payload pushed to `PAYLOAD_EVENTS`.
2. `dpi_task` pulls from the ring. Skips anything that isn't a known HTTP verb prefix (`GET `, `POST `, `PUT `, `HEAD `, `DELETE `, `OPTIONS `, `PATCH `, `CONNECT `, `TRACE `).
3. Uppercases the buffer, scans the 210 substrings (`signatures::SIGNATURES`). First hit wins.
4. Userspace inserts `(src_addr, /32, boot_time_ns)` into the kernel `BLOCKLIST` LpmTrie via aya, broadcasts `BLOCK` JSON to every WS subscriber, increments `DpiStats`.
5. Every subsequent packet from that IP hits the BLOCKLIST branch in XDP and is dropped *before* IP routing.
6. After 120 s, `ttl_sweep_task` removes the entry and broadcasts `UNBLOCK`.

**Detection is reactive, not preventive** — the first attacking packet always passes through to the host. The follow-up flood is what gets stopped at the driver edge. This is intentional (keeps the kernel program verifier-safe) but it's the honest answer when someone asks "did the first SQLi reach the app."

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
| `PACKET_COUNTER` | `HashMap<u32,u64>` | 1024 | Per-IP packet count in current 1-second window |
| `LAST_SEEN` | `HashMap<u32,u32>` | 1024 | Per-IP last window-second; rolls counter on change |
| `PAYLOAD_EVENTS` | `RingBuf` | 1 MiB | TCP payload samples → DPI |
| `CONNECT_EVENTS` | `RingBuf` | 512 KiB | Outbound `connect()` events |
| `DROP_COUNTER` | `PerCpuArray<u64>` | 1 | Total drops, summed in userspace |
| `LATENCY_HIST` | `PerCpuArray<u64>` | 64 | log2-bucketed XDP_DROP latency |

`BLOCKLIST` capacity is **1024 entries** — a real concern at scale, not at demo scale. Worth calling out if asked.

---

## 7 · Honest limits

- **No regex.** Substring `contains()` only. URL-decoded variants exist for some paths but no decode pass is run before matching. **Most encoding/casing evasions will get through.** (Phase 6 of the readiness plan turns this into a slide.)
- **First packet always passes.** Detection is reactive (see §4). Slow-and-low scanners that send one payload per source IP from a wide pool are a worst case.
- **64-byte payload window.** A signature whose discriminator sits past byte 64 of the TCP segment is invisible. Most HTTP method+path attacks fit; deep body inspection does not.
- **Per-CPU rate limit.** The `RATE_LIMIT = 500 pps` is per-CPU per-IP because of the way HashMap lookups work in eBPF, so the worst-case effective limit is `500 × num_cpus`. Fine at demo scale, not a hard guarantee on bigger boxes.
- **IPv4 only.** No IPv6 path in any of the three programs.
- **`dummy0` SKB-mode** in the demo. Native-mode XDP on a real NIC has not been benchmarked yet — that's Phase 2.
- **Blocklist capped at 1024 entries.** A determined attacker with >1024 source IPs would saturate the trie before the 120 s TTL drains it.

---

## 8 · Test coverage (today)

- `hakam-common/src/lib.rs` — 9 unit tests (octet round-trip, byte order, std conversions, layout).
- `hakam-node/tests/unit_tests.rs` — 8 unit tests (key byte order, mock blocklist, command tokenization, IP parsing, capacity).
- `hakam-ebpf` — **no tests.** No verifier-safe test harness wired up.
- **No integration test** loads the eBPF program, fires a real packet, and asserts XDP_DROP. Manual smoke-testing only via `scripts/smoke.sh` and `scripts/demo-cycle.sh`.
- **No DPI signature regression test.** Adding a needle that breaks the corpus would not be caught by `cargo test`.

Closing this gap is part of Phase 1's followup. The minimum credible additions:
1. A signature unit test that runs each `seclist-attack.sh` payload through `is_http_request` + uppercase + `contains()` and asserts a HIT for its declared family.
2. An integration test (`#[ignore]` by default) that spins hakam-node on a `veth` pair and asserts a BLOCK telemetry message after a single SQLi shot.

---

## 9 · Build-blocker found during this audit

The working copy of `hakam-node/src/main.rs` had a stray `you` token at line 1278 that prevented compilation. Fixed in this session — the file now matches the structure that landed in the last commit. Worth a `cargo check --features linux` on the VM before the next demo.
