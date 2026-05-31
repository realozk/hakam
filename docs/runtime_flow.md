# Hakam — Runtime Flow

> **What this is.** The order things happen at runtime: what loads first, where every packet goes, how an attack becomes a BLOCK, how a BLOCK becomes a red node on the HUD, when blocks expire, and what shutdown looks like.
>
> **What this is not.** A file-by-file reference (that's `codebase.md`) or a high-level architecture diagram (that's `architecture.md`).
>
> **Reading this with the code.** Function names like `dpi_task` map to `hakam-node/src/main.rs`; symbols like `BLOCKLIST` are eBPF maps in `hakam-ebpf/src/main.rs`. `codebase.md` §9 has the file-to-symbol cross-reference.

---

## 0 · The cast of moving parts

Before the flows, here's every component that does something at runtime:

| Thing | Lives in | Purpose | When it runs |
|------|----|---------|----|
| **XDP program** | kernel | Drop / pass / sample on ingress | Every ingress packet on the NIC |
| **TC classifier** | kernel | Drop on egress for blocked dst | Every egress packet |
| **Tracepoint** | kernel | Observe `connect()` syscalls (optionally CIDR-scoped) | Every IPv4 outbound connect |
| **`BLOCKLIST`** | kernel map (LpmTrie) | CIDR-aware drop set | Read by XDP+TC, written by userspace |
| **`PAYLOAD_EVENTS`** | kernel map (RingBuf, 1 MiB) | TCP payload + 4-tuple → userspace | Written by XDP, drained by `payload_task` |
| **`CONNECT_EVENTS`** | kernel map (RingBuf, 512 KiB) | connect() events → userspace | Written by tracepoint, drained by `connect_task` |
| **`DROP_COUNTER`** | kernel map (PerCpu) | Total drops | Written by XDP+TC, read by `metrics::ticker` |
| **`LATENCY_HIST`** | kernel map (PerCpu, 64 buckets) | Drop-path latency | Written by XDP, read by `metrics::ticker` |
| **`RING_OVERFLOW`** | kernel map (PerCpu, 1 cell) | Counter of payload samples we couldn't enqueue (ring full) | Written by XDP, read by `metrics::ticker` + CLI `stats` |
| **`MONITOR_CFG`** | kernel map (Array, 1 cell) | Optional CIDR scope for the tracepoint (high32=network, low32=mask) | Read by tracepoint, written once at startup if `--monitor-prefix` set |
| **`PACKET_COUNTER`/`LAST_SEEN`** | kernel maps (LruPerCpuHashMap) | 1-s sliding rate window with LRU eviction | Written + read by XDP only |
| **`Reassembler`** | userspace (`hakam-node`/`reassembly.rs`) | Per-4-tuple TCP segment buffer (256 B / 30 s / 4096 flows) | Owned by `payload_task`; ingested per sample, GC'd every 1024 events |
| **`payload_task`** | userspace tokio task | Reassemble per flow → matcher → BLOCK on hit | Continuous |
| **`connect_task`** | userspace tokio task | Format and broadcast connect events | Continuous |
| **`metrics::ticker`** | userspace tokio task | Build `METRICS` JSON | Every 1 s |
| **`maintenance::ttl_sweep_task`** | userspace tokio task | Expire BLOCKLIST entries | Every 30 s |
| **`maintenance::server_cmd_task`** | userspace tokio task | Apply back-channel `DEMO_CMD` frames from the HUD | Continuous |
| **`telemetry::run_ws_server`** | userspace tokio task | Fan out telemetry to HUDs | On every WS subscribe |
| **CLI stdin loop** | userspace blocking task | Parse `block`/`list`/`stats`/etc. | On every keystroke |
| **`tokio::broadcast<String>` (cap 512)** | userspace channel | Telemetry bus — every task writes, every WS client reads | Continuous |
| **HUD `useHakamData()`** | browser | Open WS, parse JSON, derive UI state | On mount, then on every message |
| **`scripts/demo-cycle.sh`** | bash | Drive the 6-phase narrated attack stream | Manual launch |

---

## 1 · Boot sequence — the one minute after `cargo xtask run`

```
T+0 s   xtask                  → cargo build hakam-ebpf (nightly + bpf-linker)
T+5 s   xtask                  → cargo build hakam-node --features linux
T+10 s  xtask                  → sudo ip link set IFACE xdp off    (cleanup)
                              → sudo tc qdisc del dev IFACE clsact (cleanup)
                              → exec sudo hakam-node --iface … --bpf-path …
T+11 s  hakam-node main()    → Args::parse, env_logger, banner
                              → Ebpf::load_file(bpf_path)
                              → attach_xdp (load + attach IFACE, mode)
                              → attach_tc  (qdisc_add_clsact tolerates EEXIST, then load + Egress attach)
                              → attach_tracepoint (load + attach "syscalls"/"sys_enter_connect")
                              → take_map for BLOCKLIST, DROP_COUNTER, LATENCY_HIST,
                                RING_OVERFLOW, PAYLOAD_EVENTS, CONNECT_EVENTS
                              → if --monitor-prefix: take_map MONITOR_CFG,
                                write pack_monitor_cfg(network, prefix_len) to cell 0
                              → broadcast::channel(512)         ← telemetry bus
                              → spawn telemetry::run_ws_server  (binds args.bind:8080)
                              → spawn metrics::ticker           (1 Hz)
                              → spawn dpi::payload_task         (drains PAYLOAD_EVENTS, owns Reassembler)
                              → spawn dpi::connect_task         (drains CONNECT_EVENTS)
                              → spawn maintenance::ttl_sweep_task   (30 s)
                              → spawn maintenance::server_cmd_task  (HUD back-channel)
                              → spawn ctrl-C listener
                              → spawn_blocking stdin CLI loop
                              → tokio::select! { CLI exits ‖ shutdown signal }
T+11 s  Banner prints:
          ◉ XDP                armed on [IFACE] mode=SKB (generic)
          ◉ TC                 armed on [IFACE] — outbound exfiltration killed at the NIC
          ◉ tracepoint         armed — process-aware outbound connect() monitoring
          ◉ tracepoint scope   → 10.99.0.0/16  (only if --monitor-prefix given)
          ◉ telemetry          ws on ${--bind}:${--ws-port}/ws
                               (default 127.0.0.1:8080; demo uses --bind 0.0.0.0)
        ← demo is now live.
```

Anything that fails between T+11 s steps (`xdp_prog.load()`, `attach()`, `take_map`) panics with an `anyhow::Context` message — useful pre-flight diagnostics. Successful boot ends at the `hakam@kernel ▸` prompt.

---

## 2 · Per-packet ingress path — XDP

Every packet that enters the NIC bound to hakam-node walks this path. **No allocation, no syscalls, no userspace transitions** — pure verifier-checked eBPF, runs before the rest of the kernel network stack.

```
                              packet arrives on NIC
                                       │
                                       ▼
                       ┌────────────────────────────────┐
                       │ XDP program: hakam_ebpf      │
                       │ t0 = bpf_ktime_get_ns()        │
                       └───────────┬────────────────────┘
                                   │
                       ┌───────────▼────────────┐
                       │ EthHdr.ether_type IPv4?│  no → XDP_PASS
                       └───────────┬────────────┘
                                   │ yes
                       ┌───────────▼────────────────────────────┐
                       │ Lookup BLOCKLIST[(/32, src_addr)]      │
                       └───────────┬────────────────────────────┘
                                   │
                       hit ────────┴────────► increment_drop_counter
                                              record_latency(now-t0)
                                              return XDP_DROP
                                   │ miss
                                   ▼
                       ┌────────────────────────────────────────┐
                       │ Rate-limit window check                │
                       │   sec = now_ns / 1e9                   │
                       │   if LAST_SEEN[src] != sec:            │
                       │     LAST_SEEN[src] = sec               │
                       │     PACKET_COUNTER[src] = 0            │
                       │   PACKET_COUNTER[src] += 1             │
                       │   if count > 500:                      │
                       │     BLOCKLIST.insert(src/32, now_ns)   │
                       │     return XDP_DROP                    │
                       └───────────┬────────────────────────────┘
                                   │ under limit
                                   ▼
                       ┌────────────────────────────────────────┐
                       │ proto == TCP ?                          │
                       └───────────┬────────────────────────────┘
                          no       │ yes
                       XDP_PASS    ▼
                       ┌────────────────────────────────────────┐
                       │ sample_payload(src_addr, dst_addr):    │
                       │ verify tcp_hdr_start+13 ≤ data_end,    │
                       │ read TCP src_port + dst_port,          │
                       │ parse data offset → tcp_hdr_len,       │
                       │ copy first 64 B of TCP payload + the   │
                       │ 4-tuple into a reserved slot in        │
                       │ PAYLOAD_EVENTS RingBuf, .submit()      │
                       │ (RING_OVERFLOW++ if reserve fails)     │
                       └───────────┬────────────────────────────┘
                                   ▼
                              return XDP_PASS
```

**Hot-path cost.** A blocked-IP drop is one LPM lookup + one PerCpu increment + one ktime read. A clean packet is one LPM miss + one LRU HashMap upsert + one LRU HashMap increment + (if TCP) one bounds-checked memcpy of 64 B + four 2/4-byte tuple reads + one ring-buffer reserve. No locks, no allocation, no syscall. The verifier guarantees this can't loop or stall the NIC.

**Why latency only times the DROP path.** XDP_PASS means we let the packet through — the cost we want to advertise is the cost we add to a *drop*, because the pass case is what unloaded XDP would do anyway. So `record_latency(now − t0)` is gated by `if ret == XDP_DROP` (`hakam-ebpf/src/main.rs:81`).

---

## 3 · Per-packet egress path — TC

```
        userland sends packet on IFACE
                  │
                  ▼
       ┌────────────────────────────────────────┐
       │ TC clsact egress: hakam_egress       │
       │   ethertype IPv4?                      │ no → TC_ACT_OK
       │   load dst_addr at offset 30           │
       │   BLOCKLIST.get(/32, dst_addr)?        │
       └────────────┬───────────────────────────┘
                    │ hit                miss │
                    ▼                         ▼
            increment_drop_counter        TC_ACT_OK
            return TC_ACT_SHOT
```

This is the **outbound exfiltration kill** path — same blocklist, opposite direction. If a compromised host inside the network tries to reach a known-bad IP, the packet dies before leaving the NIC. The kernel never asks userspace.

---

## 4 · Tracepoint path — `sys_enter_connect`

```
        any process calls connect() syscall
                       │
                       ▼
       ┌──────────────────────────────────────────┐
       │ tracepoint: hakam_connect              │
       │   read uservaddr ptr at TP offset 24     │
       │   bpf_probe_read_user → SockaddrIn       │
       │   sa.sin_family == AF_INET ?             │ no → return 0
       │   MONITOR_CFG[0]:                        │
       │     mask != 0 && (sin_addr & mask)       │
       │       != network ?                       │ yes → return 0
       │   pid  = bpf_get_current_pid_tgid >> 32  │
       │   comm = bpf_get_current_comm()          │
       └──────────────────┬───────────────────────┘
                          ▼
       ┌──────────────────────────────────────────┐
       │ CONNECT_EVENTS.reserve::<ConnectEvent>() │
       │   { pid, comm, dst_addr, dst_port }      │
       │ .submit()                                │
       └──────────────────┬───────────────────────┘
                          ▼
                    return 0  (observe-only)
```

This program **never blocks** anything — it's pure observation. It exists so the HUD can answer *"which process tried to call out, and where to?"* — useful when an outbound block fires (TC kills the packet, tracepoint identifies the culprit by name + PID). The `MONITOR_CFG` filter keeps the demo console free of DNS / apt / systemd-resolved noise; default cell value 0 leaves it system-wide.

---

## 5 · Attack lifecycle — from first byte to red node on the HUD

This is the canonical story to walk an audience through. I'll describe it in 8 steps with timing in the same wall-clock so it makes intuitive sense.

```
Wall-clock   Where                    What happens
──────────── ──────────────────────── ────────────────────────────────────────
t = 0 ms     attacker (10.99.1.13)    fires:  GET /search?q=' OR '1'='1 HTTP/1.1
                                              Host: 10.99.0.10
                                              \r\n\r\n
                                              via nc -s 10.99.1.13 ...
t ~ 0.1 ms   NIC → XDP                IPv4 ✓, src not in BLOCKLIST, count = 1
                                       (under 500), TCP ✓ → sample_payload()
                                       writes 64 B of "GET /search?q=' OR '1…"
                                       plus the full 4-tuple (10.99.1.13:eph
                                       → 10.99.0.10:80) to PAYLOAD_EVENTS,
                                       returns XDP_PASS. (The first packet
                                       REACHES the host — this is the honest
                                       "reactive, not preventive" answer.)
t ~ 0.2 ms   userspace payload_task   AsyncFd wakes, drains the ring entry.
                                       key = FlowKey::from_event(event)
                                       view = reassembler.ingest(key, payload, now_ns)
                                         → first segment of this flow, view =
                                           "GET /search?q=' OR '1'='1…"
                                       signatures::is_http_request(view) → true
                                       signatures::match_payload(view):
                                         → AC scan on raw bytes (case-insensitive)
                                         → "' OR '" matches at position N.
                                         → category=SQLi, action=XDP_DROP,
                                           severity=critical.
t ~ 0.3 ms   userspace payload_task   reassembler.forget(&key) — drop the flow
                                       so HTTP keep-alive can reuse the tuple.
                                       1. blocklist.lock().insert(
                                            (32, src=10.99.1.13), boot_ns)
                                         → updates the kernel map directly.
                                       2. DpiStats.total_detections += 1
                                          DpiStats.by_category["SQLi"] += 1
                                       3. tx.send(block_json(
                                            "10.99.1.13","Edge Proxy",
                                            "' OR '","XDP_DROP","SQLi","critical"))
                                       4. tx.send(event_json(
                                            "SQLi (critical) — pattern '\' OR \'' …",
                                            "critical"))
                                       Console pretty-prints "▼ INTERCEPT [SQLi]…"
t ~ 0.4 ms   tokio::broadcast → WS    All connected WS clients receive both
             → handle_ws_client       JSON messages.
t ~ 5 ms     browser ws.onmessage     Switch on data.type:
             useHakamData()           BLOCK branch:
                                         fromRole = roleForIp("10.99.1.13") = "pc1"
                                         pulseActive("pc1") (1.2 s amber pulse)
                                         threatState.nodes.pc1 = {active:true,
                                                                   blocked:true, …}
                                         threatState.edge = {from:pc1, to:firewall,
                                                              category:SQLi, blocked:true}
                                         lastBlockTick = Date.now()
                                         attackWindowRef.push(now)
                                         recomputeThreatLevel(now) → maybe steps to 4
                                         recentAttacks.unshift(...).slice(0,50)
                                         familyCounts.SQLi = (prev??0) + 1
                                         logs.unshift(... "SQLi (critical) blocked…")
                                         splash = {category:SQLi, …}
                                         setTimeout(splash=null, 1700)
                                         setTimeout(showCard=false, 4500)
                                       EVENT branch (same broadcast frame):
                                         logs.unshift("SQLi (critical) — pattern …")
t = 5–~50 ms React rerenders          InterceptSplash slides in from the top-right
                                       for critical/high severity, auto-clears 1.7 s.
                                       TopologyMap: pc1 turns red, the pc1↔firewall
                                       edge becomes dashed-red with × marker, a
                                       one-shot ring fires on pc1, and a particle
                                       flies pc1 → firewall and dies.
                                       HakamStatus: family bar for SQLi grows; the
                                       THREATS_NEUTRALIZED counter ticks up; the
                                       attack-pattern heatmap cell for SQLi heats.
                                       EventLog prepends a red row; AttackTimeline
                                       paints a new color-coded tick at NOW.
                                       Header now-playing chip swaps to
                                       "▶ SQLi · UNION SELECT · 10.99.1.13".
t > 50 ms    attacker keeps shooting  Every subsequent packet from 10.99.1.13:
                                         XDP → BLOCKLIST hit → XDP_DROP.
                                         drop counter increments per-CPU.
                                         No userspace involvement at all —
                                         the kernel handles it inline.
                                       metrics_ticker (1 Hz) sums DROP_COUNTER
                                       across CPUs and broadcasts METRICS.
                                       HUD ticks "kernel drops" counter up.
t = 120 s    ttl_sweep_task           At the next 30-s sweep tick after the
                                       insert, the entry's age exceeds 120 s.
                                       blocklist.remove(key); broadcasts
                                       UNBLOCK + EVENT "Block TTL expired …".
                                       HUD clears blocked state for pc1.
                                       Source can attack again. Cycle repeats.
```

**The single most-asked question — "did the first packet reach the host?"** — yes. Detection is reactive. The kernel can't do regex; it samples bytes and asks userspace, and by the time userspace has decided, the packet is already past XDP. *Every subsequent packet from that source* dies at the driver edge. This is the right answer; trying to claim otherwise gets caught.

---

## 6 · Block lifecycle — insert / drop / sweep / unblock

There are three ways an entry lands in `BLOCKLIST`:

1. **Auto-block from DPI.** `dpi_task` inserts after a signature hit (see §5).
2. **Auto-block from rate-limit.** XDP itself inserts when `PACKET_COUNTER[src] > 500` in a 1-s window. No userspace round-trip.
3. **Manual `block <IP[/prefix]>` CLI.** stdin loop calls `parse_cidr`, `lpm_key`, `blocklist.lock().insert()`, broadcasts `BLOCK` JSON with `category="Manual"`.

After insert, the source IP gets dropped at XDP for *every subsequent ingress packet* until either:

- **TTL expiry.** Every 30 s, `ttl_sweep_task` walks the trie. If `now − insert_ns > 120 s`, it removes the key and broadcasts `UNBLOCK` + an `EVENT`.
- **Manual `unblock <IP[/prefix]>`.** CLI calls `blocklist.lock().remove()`, broadcasts `UNBLOCK`.
- **Manual `clear`.** CLI iterates the trie, removes every key, broadcasts an UNBLOCK per removed entry, then a single info `EVENT`.

```
                        ┌─── DPI hit (dpi_task)        ─┐
        sources of      ├─── rate-limit overflow (XDP)  │
        BLOCKLIST       ├─── manual `block` CLI          │
        inserts         │                                │
                                                          ▼
                                          BLOCKLIST  (LpmTrie<u32, u64>)
                                                          │
                              ┌───────────────────────────┼────────────────┐
                              │                           │                │
                              ▼                           ▼                ▼
              XDP hot path (every packet)   TC hot path (egress)   ttl_sweep_task
              "src in BLOCKLIST?            "dst in BLOCKLIST?      every 30 s:
               yes → XDP_DROP"               yes → TC_ACT_SHOT"     remove if age>120s

                              │                           │                │
                              └─────── drops counted ─────┘                │
                                       in DROP_COUNTER                     │
                                                                            ▼
                                                              tx.send(unblock_json)
                                                              + event_json
```

**The blocklist is the single source of truth for "is this IP killed."** Both kernel hot paths read it; userspace only writes to it. There is no second-tier ACL anywhere.

---

## 7 · Telemetry bus — how a kernel event reaches every HUD

```
                                  ┌────────────────────────────────────┐
                                  │ tokio::broadcast::Sender<String>   │  cap 512
                                  └────────────────┬───────────────────┘
              writers (everything fans in)         │
        ┌───────────────────────────────┬──────────┼──────────────────────┐
        │                               │          │                      │
   metrics_ticker            dpi_task  connect_task   stdin CLI loop
   1 × METRICS / s             BLOCK   CONNECT   BLOCK / UNBLOCK / EVENT
                              EVENT
                                                  │
                                                  ▼
                          ┌──────────────────────────────────────────┐
                          │  tokio::broadcast::Receiver per WS client │  one each
                          └──────────────────────────┬────────────────┘
                                                     ▼
                                  warp WS sender → on the wire
                                                     ▼
                                  HUD.useHakamData onmessage
                                                     ▼
                                       React state update
```

- **Cap 512 messages.** A WS client that lags will receive a `RecvError::Lagged(n)` log warning; the message is dropped for that client. `dpi_task` and friends keep moving.
- **No backpressure to the kernel.** Even if all WS clients disconnect, the broadcast channel still drains (no subscribers means each `tx.send` returns the count `0`). The kernel never stalls.
- **All messages are line-delimited JSON.** Five `type` values: `METRICS`, `BLOCK`, `UNBLOCK`, `CONNECT`, `EVENT`. The HUD switches on the type and updates a different piece of state for each.

---

## 8 · HUD lifecycle

### 8a. Mount

```
index.html → main.tsx (createRoot)
           → <App />
                ↓
            useHakamData()
                ↓
   ┌────────────────────────────────────────────┐
   │ initial state:                              │
   │   logs = [{ "Connecting to Hakam…" }]     │
   │   metrics = zeros, history arrays of 60     │
   │   threatState = idle                        │
   │   threatLevel = 5 (NOMINAL)                 │
   │ recomputeThreatLevel interval (1.5 s)       │
   │ open WebSocket(VITE_HAKAM_WS_URL          │
   │                || ws://localhost:8080/ws)   │
   └────────────────────────────────────────────┘
```

Children render against the initial state — the topology shows all-quiet, hero stats are zero, the kernel-link chip says `reconnecting` until the first non-zero CPU sample arrives.

### 8b. Steady state

For every WS frame, `useHakamData` runs the switch in §7's diagram and produces new state. React rerenders the affected components:

| WS message | Components that re-render |
|------------|---------------------------|
| `METRICS` | `<HakamStatus>` tiles + sparkline, header status chip stays `KERNEL_LINK` |
| `BLOCK` | `<TopologyMap>` (pulse + ring), `<EventLog>` (new row), `<AttackTimeline>` (new tick), `<HakamStatus>` (counter / family bar / heatmap), `<InterceptSplash>` mounts for critical/high, header now-playing chip updates, `<ThreatLevel>` segment in HakamStatus may step |
| `UNBLOCK` | `<TopologyMap>` clears node + edge, `<EventLog>` scrolls a new info line |
| `CONNECT` | `<TopologyMap>` pulses the dst node, `<EventLog>` appends, `<HakamStatus>` live-traffic bar updates |
| `EVENT` | `<EventLog>` appends |
| `SCENARIO` | Header scenario chip updates |

### 8c. Reconnect

`ws.onclose` schedules `connectWS()` via `scheduleReconnect()`. The retry delay starts at `INITIAL_RECONNECT_MS` (3 s) and doubles on each failure up to `MAX_RECONNECT_MS` (60 s) — prevents a reconnect storm when the VM is briefly unreachable. The delay resets on the next successful `onopen`.

While disconnected:
- `wsConnected = false` flips the header chip to **RECONNECTING** (red, pulsing dot) immediately — no longer inferred from stale metric history.
- The 1.5 s `recomputeThreatLevel` interval keeps draining `attackWindowRef`, so the threat level decays to NOMINAL even with no kernel link.
- All other component state is preserved.

When the new socket opens, `ws.onopen` sets `wsConnected = true`, resets the backoff, prepends a `── Kernel WebSocket connected ──` info line, and the chip flips back to **KERNEL_LINK**.

Separately, if the socket is open but no inbound events for `STALE_THRESHOLD_MS` (30 s), `isStale = true` and the chip turns amber **STALE_FEED** — catches the "hakam-node is up but the demo generator crashed" case.

### 8d. Threat level

Independent of WS state. Driven by `attackWindowRef` (the rolling 30 s of BLOCK timestamps) and the 1.5 s recompute interval:

- 0 attacks in 30 s → 5 NOMINAL
- 1–2 → 4 ELEVATED
- 3–5 → 3 GUARDED
- 6–11 → 2 HIGH
- ≥12 → 1 SEVERE

This is what makes the demo's COOLDOWN phase visibly "decay" the level on screen — no new attacks land, the window drains, the level steps back down every 1.5 s.

---

## 9 · Demo cycle lifecycle (`scripts/demo-cycle.sh`)

The cycle is a pure attack driver — it knows nothing about hakam-node, only about the network. It fires HTTP requests through `nc` from rotating source IPs and lets the kernel + HUD do the rest. One full cycle = ~113 s.

```
cycle N starts
  │
  ├── PHASE 0  BASELINE (12 s)          countdown_to_next 12 "settling"
  │                                     └─ no traffic. HUD shows calm.
  │
  ├── PHASE 1  FIRST CONTACT (12 s)     fire_one "SQLi" (single shot from one IP)
  │                                      countdown 8
  │                                      fire_one "XSS"
  │                                      countdown 4
  │                                     └─ 2 BLOCK frames over 12 s.
  │                                        HakamStatus family bars show 2.
  │
  ├── PHASE 2  RECON SWEEP (10 s)       fire_burst "Recon" 8 800
  │                                     └─ 8 low-severity blocks over 8 s.
  │                                        ThreatLevel may step to ELEVATED.
  │
  ├── PHASE 3  MULTI-VECTOR (24 s)      11 categories, one shot each at 1.7 s spacing
  │                                     └─ 11 BLOCK frames. HakamStatus family
  │                                        bars race; PEAK bar wins by count.
  │
  ├── PHASE 4  PEAK ASSAULT (20 s)      fire_random 100 180   (100 shots, 180 ms apart)
  │                                     └─ HUD floods. ThreatLevel → SEVERE.
  │                                        Kernel autoblocks IPs as their per-IP
  │                                        rate exceeds 500/s; further packets
  │                                        from those IPs drop at XDP without
  │                                        userspace involvement.
  │
  └── PHASE 5  COOLDOWN (35 s)          no traffic.
                                        └─ HUD's 30-s rolling window empties.
                                           ThreatLevel decays 1 → 4 → 5.
                                           ttl_sweep_task starts removing the
                                           oldest blocks at the 30-s mark.

then loops (cycle N+1).
```

The narration banner (`phase_banner` + `countdown_to_next`) prints in the VM terminal so the operator (and the audience) can read the phase name + remaining seconds.

---

## 10 · Shutdown sequence

When the operator types `quit` (or `q`/`exit`) at the `hakam@kernel ▸` prompt:

1. The CLI loop hits `break;` → the `spawn_blocking` task finishes → its `Result` returns Ok.
2. `tokio::select!` notices the CLI future resolved → `main()` falls through.
3. As `main()` returns:
   - `_link_xdp` drops → XDP detached from the interface.
   - `_link_tc` drops → TC clsact filter detached.
   - `_link_tp` drops (if Some) → tracepoint detached.
   - The eBPF object drops → all maps are released.
   - All tokio tasks are dropped (the runtime shuts down).
4. The `Hakam going dark` line prints. Process exits 0.

If the operator hits **Ctrl-C** instead, the dedicated `tokio::signal::ctrl_c` task fires the oneshot, the `select!` short-circuits the CLI task, and we go through the same drop sequence.

If the process is killed with SIGKILL or panics, the kernel keeps the XDP hook + clsact qdisc attached. **The next `cargo xtask run` cleans both** before re-attaching (`xtask/src/main.rs:160` and `:165`). That's why re-running it is always safe.

---

## 11 · End-to-end picture

Putting all of §2 through §9 together for one BLOCK:

```
   nc shoots a SQLi
      │
      ▼
   NIC ── XDP hakam_ebpf ──► PAYLOAD_EVENTS RingBuf  (sample + 4-tuple)
      │            │                       │
      │            │                       ▼
      │            │            tokio  payload_task: reassembler.ingest(flow)
      │            │                       → HTTP gate → AC match (case-fold)
      │            │                       → on miss: URL-decoded AC match
      │            │                       → hit → reassembler.forget(flow)
      │            │                       │
      │            │              ┌────────┴────────┬──────────┐
      │            │              ▼                 ▼          ▼
      │            │         BLOCKLIST           DpiStats   tokio::broadcast<String>
      │            │         insert(/32,                       BLOCK + EVENT
      │            │         boot_ns)                              │
      │            │              │                                │
      ▼            ▼              ▼                                ▼
   2nd packet  XDP_PASS        every later                  WS server fan-out
   from same   on first         packet from                       │
   src         shot             src dies in XDP                   ▼
                                                          HUD useHakamData
                                                          → topology red
                                                          → splash plate
                                                          → event log card
                                                          → family bar +1
                                                          → threats counter +1
                                                          → maybe threat level step
   ── 30 s tick ─────────────────────────────────────────────────────────────
                                ttl_sweep_task scans BLOCKLIST
                                no entries old enough yet → continue
   ── 120 s after the insert ────────────────────────────────────────────────
                                ttl_sweep_task removes the entry
                                broadcasts UNBLOCK + EVENT
                                HUD clears the red node, edge restores,
                                source can attack again.
```

That's the whole lifecycle. Every other moving part — manual `block`, the 200+ signatures, the threat-level decay, the 1 Hz METRICS ticker — is a variation on this same shape.
