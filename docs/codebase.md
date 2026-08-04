# Hakam — Codebase Reference

> **What this is.** A file-by-file walkthrough of the entire repo. Every directory, every source file, every key function — what it does, where it lives, what depends on it.
>
> **What this is not.** A runtime / data-flow narrative — that lives in `runtime_flow.md`. Read that one if you want to know "what happens when a packet hits the NIC." Read this one if you want to know "what's in `signatures.rs` and which other files use it."
>
> **Companion docs.** `architecture.md` (1-page bird's-eye view), `runtime_flow.md` (boot + packet path).

---

## 0 · Top-level layout

```
hakam/
├── Cargo.toml              ← workspace manifest (Rust)
├── Cargo.lock
├── rust-toolchain.toml     ← pins the toolchain (nightly for eBPF crate)
├── .cargo/config.toml      ← target/linker config for the eBPF target
├── .github/workflows/      ← CI: userspace build+test, eBPF build
├── README.md               ← project overview, performance, limitations
├── start_guide.md          ← 3-terminal demo runbook
├── CONTRIBUTING.md · SECURITY.md · LICENSE
│
├── hakam-common/           ← Rust crate — shared types (kernel + userspace)
├── hakam-ebpf/             ← Rust crate — kernel eBPF programs
├── hakam-node/             ← Rust crate — userspace controller
├── hakam-ui/               ← React/Vite HUD (+ Tauri shell, optional)
├── xtask/                  ← Rust crate — build automation (cargo xtask …)
│
├── scripts/                ← bash demo + ops scripts
├── bench/                  ← benchmark rig and raw CSV results
├── corpus/                 ← replayable attack pcaps
├── packaging/              ← Docker image, systemd unit, install script
├── demo/                   ← screencast fallback (recording SOP)
└── docs/                   ← this folder (architecture, codebase, runtime_flow)
```

Workspace members: `hakam-common`, `hakam-ebpf`, `hakam-node`, `xtask`. `hakam-ebpf` is **excluded from default `cargo build`** — it builds for `bpfel-unknown-none` via xtask. The Tauri sub-project under `hakam-ui/src-tauri` is workspace-`exclude`d as well.

---

## 1 · Workspace plumbing

### `Cargo.toml` (workspace root)
- Declares 4 workspace members; default-members excludes `hakam-ebpf`.
- Profile overrides: **`[profile.dev]` is set to `opt-level = 3`, `lto = true`, `panic = "abort"`** — so dev builds compile slowly but run like release. This matters because eBPF link-time work is heavy.

### `rust-toolchain.toml`
- Pins the toolchain. The eBPF crate needs nightly + `rust-src`.

### `.cargo/config.toml`
- Linker / target overrides for the BPF target.

---

## 2 · `hakam-common/` — shared types

**Single file: `src/lib.rs`**. Compiles `no_std` for the kernel, `std` for everything else (gated by the `std` feature).

### Public surface
| Item | What it is | Used by |
|------|------------|---------|
| `PAYLOAD_LEN: usize = 64` | Bytes sampled from each TCP segment | kernel + userspace DPI |
| `struct PayloadEvent { src_addr, dst_addr, src_port, dst_port, payload_len, payload[64] }` | RingBuf entry kernel→userspace; full 4-tuple lets userspace reassemble per flow. Wire byte order on every field copied from packet headers. | both sides |
| `struct ConnectEvent { pid, comm[16], dst_addr, dst_port, _pad }` | Tracepoint event for outbound `connect()` | both sides |
| `struct Ipv4Addr(pub u32)` | Tiny newtype (big-endian internal) with `from_octets`, `to_octets`, `as_raw` | userspace key generation |

### Non-public
- `mod std_impls` (feature-gated) — `From<std::net::Ipv4Addr>` round-trips and a `Display` impl.
- `mod tests` — 10 unit tests covering octet round-trip, big-endian raw value, equality, std conversion, mock map, `ConnectEvent` layout (28 B / align 4), and `PayloadEvent` layout (16 + `PAYLOAD_LEN` = 80 B / align 4).

### Why this file matters
Both the kernel program and the userspace consumer must agree on the byte layout of `PayloadEvent` and `ConnectEvent`. Any field added here without rebuilding both crates is a silent corruption bug. The 4-tuple fields in `PayloadEvent` are what `hakam-node/src/reassembly.rs` keys its per-flow buffer on.

---

## 3 · `hakam-ebpf/` — kernel programs

`no_std` + `no_main`. Split across five files under `src/`:

- `main.rs` — entry points, map declarations, constants, panic handler.
- `xdp.rs` — `try_xdp` / `sample_payload` (ingress drop + payload sample).
- `tc.rs` — `try_tc` (egress drop on blocked dst).
- `tracepoint.rs` — `try_connect` (CIDR-scoped `sys_enter_connect` observer).
- `helpers.rs` — verifier-safe `ptr_at`, `increment_drop_counter`, `record_latency`.

### Crate-level
- `Cargo.toml` declares `aya-ebpf`, `aya-log-ebpf`, `network-types` as deps.
- `panic_handler` is a tight infinite loop — kernel-side panics are fatal anyway, the verifier will reject anything that can panic.

### Constants
| Name | Value | Purpose |
|------|------:|---------|
| `RATE_LIMIT` | `500` | Packets-per-second per source IP before auto-block |
| `TC_ACT_OK` / `TC_ACT_SHOT` | `0` / `2` | TC return codes |
| `AF_INET` | `2` | Filter tracepoint to IPv4 only |
| `TP_OFF_USERVADDR` | `24` | Byte offset of `uservaddr` in `sys_enter_connect` tracepoint args |

### Maps (declared in `main.rs`)
| Symbol | Type | Capacity | Purpose |
|--------|------|---------:|---------|
| `BLOCKLIST` | `LpmTrie<u32, u64>` | 1024 | CIDR-aware drop set; value = boot-time ns of insert |
| `PACKET_COUNTER` | `LruPerCpuHashMap<u32, u64>` | 1024 | Per-IP packets in current 1-s window. LRU eviction prevents new-attacker starvation past 1024 unique sources. |
| `LAST_SEEN` | `LruPerCpuHashMap<u32, u32>` | 1024 | Per-IP last-seen window-second; rolls counter |
| `PAYLOAD_EVENTS` | `RingBuf` | 1 MiB | Sampled TCP payloads + 4-tuple → userspace |
| `CONNECT_EVENTS` | `RingBuf` | 512 KiB | Outbound `connect()` events → userspace |
| `DROP_COUNTER` | `PerCpuArray<u64>` | 1 | Total drops; userspace sums across CPUs |
| `LATENCY_HIST` | `PerCpuArray<u64>` | 64 | log2-bucketed XDP_DROP latency |
| `RING_OVERFLOW` | `PerCpuArray<u64>` | 1 | Counter of samples dropped because `PAYLOAD_EVENTS` was full; surfaced in CLI `stats`. |
| `MONITOR_CFG` | `Array<u64>` | 1 | Optional CIDR scope for `try_connect`. High 32 = network, low 32 = mask. Cell = 0 → monitor all. Set by `--monitor-prefix` flag. |

### Programs

#### `hakam_ebpf` (XDP — entry in `main.rs`, body in `xdp.rs`)
- Entry: `pub fn hakam_ebpf(ctx: XdpContext) -> u32`.
- Times itself with `bpf_ktime_get_ns()` *only on the DROP path* via `record_latency()` (the line `if ret == xdp_action::XDP_DROP` gates this).
- Delegates to `xdp::try_xdp()`:
  1. Parse Eth → IPv4. Non-IPv4 = `XDP_PASS`. Captures both `src_addr` and `dst_addr` from the IP header.
  2. **BLOCKLIST hit → `increment_drop_counter()` + `XDP_DROP`** (hot path).
  3. Sliding-1-s rate limit: if window rolled, reset counter; if count > 500, insert into BLOCKLIST and DROP.
  4. If TCP, call `sample_payload(ctx, src_addr, dst_addr)` to forward bytes + 4-tuple to userspace via `PAYLOAD_EVENTS`.
  5. Return `XDP_PASS`.

#### `hakam_egress` (TC classifier — body in `tc.rs`)
- Entry: `pub fn hakam_egress(ctx: TcContext) -> i32`.
- Reads ethertype + dst IP via `ctx.load()`.
- If dst in BLOCKLIST → `TC_ACT_SHOT`. Else `TC_ACT_OK`.
- This is the **outbound exfiltration kill** path.

#### `hakam_connect` (tracepoint `sys_enter_connect` — body in `tracepoint.rs`)
- Entry: `pub fn hakam_connect(ctx: TracePointContext) -> i32`.
- Reads `uservaddr` pointer at offset `TP_OFF_USERVADDR` (24), `bpf_probe_read_user`s a `SockaddrIn`, filters to `AF_INET`.
- **`MONITOR_CFG` filter:** if the map cell's low 32 bits (mask) are non-zero, drop events whose `sa.sin_addr & mask != network`. Default cell value 0 → monitor all. Set from userspace by `--monitor-prefix`.
- Fills `ConnectEvent { pid, comm, dst_addr, dst_port }` and submits via `CONNECT_EVENTS`.
- Always returns 0 — observe-only, never blocks.

### Helpers
- `xdp::sample_payload(ctx, src_addr, dst_addr)` — verifier-safe bounds check (`tcp_hdr_start + 13`), reads TCP src/dst port, parses TCP data offset, copies first `PAYLOAD_LEN` bytes plus the 4-tuple into a reserved RingBuf slot.
- `helpers::increment_drop_counter()` — `+=1` on per-CPU drop counter.
- `helpers::record_latency(delta_ns)` — `floor(log2(delta))` bucketing, clamped to 63.
- `helpers::ptr_at<T>(ctx, offset)` — verifier-safe pointer cast with bounds check (used by all packet parsing).

### What it does NOT do
- No string match. No regex. No allocation. No loops over user data. The eBPF verifier wouldn't allow any of this.

---

## 4 · `hakam-node/` — userspace controller

Split into a **library crate** (cross-platform) and a **binary crate** (Linux-only).

The library half (`src/lib.rs` + `signatures.rs` + `reassembly.rs` + `monitor.rs`) compiles on macOS, has 16 inline tests, and is exercised by 40 integration tests across `tests/`. The binary half (`src/main.rs` + `cli.rs` + `dpi.rs` + `maintenance.rs` + `metrics.rs` + `telemetry.rs`) is feature-gated `#[cfg(feature = "linux")]` — default Cargo build on macOS produces a stub that prints "requires Linux".

### `Cargo.toml`
- Mandatory deps (always-on, lib + tests use them): `anyhow`, `env_logger`, `colored`, `aho-corasick`, `percent-encoding`, `hakam-common`.
- Linux-only deps under `features.linux`: `aya`, `aya-log`, `tokio`, `clap`, `log`, `warp`, `serde`, `serde_json`, `futures-util`, `libc`.
- `features.default = []` → must opt in with `--features linux` to build the bin.

### `src/lib.rs` — library entry
Re-exports the three platform-independent modules: `monitor`, `reassembly`, `signatures`. Anything that does not link `aya` / `libc` lives here so it gets `cargo test` coverage on any host.

### `src/signatures.rs` — DPI signature corpus + matcher
- `pub struct Sig { pattern, category, action, severity }` — all `&'static str`.
- `const fn sig(...)` — constructor used to build the table at compile time.
- `pub const SIGNATURES: &[Sig]` — the corpus. **202 entries** across 13 families: SQLi (~30), XSS (~30), LFI (~20), RCE (~30), SSRF (~15), XXE (~10), Log4Shell (~7), Deserial (3), NoSQLi (~10), SSTI (~10), WebShell (~10), Recon (~15), CVE (~10).
- `pub const CATEGORIES: &[&str]` — display order for the CLI / HUD.
- `pub fn category_counts() -> Vec<(&str, usize)>` — used by the `rules` CLI command.
- `pub fn is_http_request(payload: &[u8]) -> bool` — checks startswith for the 9 HTTP verbs. The gate that decides whether a payload reaches the matcher.
- `pub fn matcher() -> &'static AhoCorasick` — Aho-Corasick automaton over the corpus, built once via `OnceLock`. `ascii_case_insensitive(true)` so it scans raw payload bytes with no allocation.
- `pub fn match_payload(payload: &[u8]) -> Option<&'static Sig>` — the single matcher entrypoint. Gate → AC scan on raw bytes → fallback AC scan on URL-decoded bytes. Returns the first hit.
- `fn url_decoded(payload: &[u8]) -> Option<Vec<u8>>` — single-pass `%XX` → byte plus `+` → space; returns `None` if no `%` or `+` present so the caller skips allocation.
- 4 inline invariant tests pinning uppercase / non-empty / ≤ `PAYLOAD_LEN` / category-table sync.

**Patterns are uppercase substrings by convention.** Runtime matching is case-folded inside the Aho-Corasick automaton — a lowercase corpus entry would still match, but the test fails the build to keep the corpus visually uniform.

### `src/reassembly.rs` — userspace TCP segment buffer
- `pub struct FlowKey { src_addr, dst_addr, src_port, dst_port }` + `FlowKey::from_event(&PayloadEvent)` constructor.
- `pub struct Reassembler` (private fields). API: `new(max_buf, ttl_ns, max_flows)`, `with_defaults()`, `ingest(key, payload, now_ns) -> Option<&[u8]>`, `forget(&key)`, `gc(now_ns) -> usize`, `flow_count()`, `dropped_full_buf()`, `dropped_at_cap()`.
- Defaults: `DEFAULT_MAX_FLOW_BUF = 256` B, `DEFAULT_FLOW_TTL_NS = 30 s`, `DEFAULT_MAX_FLOWS = 4096`.
- `FlowState` is deliberately laid out so the Phase 2 #7 eBPF conntrack can add `seq_next` / `dir` fields without rewriting the reassembly logic.
- 7 inline tests + 4 integration tests in `tests/reassembly.rs` covering split-segment attacks end-to-end.

### `src/monitor.rs` — `MONITOR_CFG` packer
- `pub fn pack_monitor_cfg(network: Ipv4Addr, prefix_len: u32) -> u64` — packs an IPv4 prefix into the `u64` cell layout the kernel filter expects (high 32 = network in wire-byte order, low 32 = mask).
- 5 inline tests covering /0 (monitor-all sentinel), /16, /24, /32.

### `src/main.rs` — Linux runtime entry point

Loads the eBPF ELF, attaches XDP / TC / tracepoint, takes every map, populates `MONITOR_CFG` from `--monitor-prefix`, spawns the async tasks, runs the stdin CLI loop, handles Ctrl-C cleanup. Delegates everything else to the sibling modules.

Boot order:
1. `Args::parse()`, `env_logger` init, `cli::print_banner()`.
2. Canonicalize the BPF ELF path; `Ebpf::load_file`.
3. `attach_xdp` → `attach_tc` → `attach_tracepoint`.
4. `bpf.take_map(...)` for `BLOCKLIST`, `DROP_COUNTER`, `LATENCY_HIST`, `RING_OVERFLOW`, `PAYLOAD_EVENTS`, `CONNECT_EVENTS`. If `--monitor-prefix` set, also take `MONITOR_CFG` and write `pack_monitor_cfg(network, prefix_len)` to cell 0.
5. `broadcast::channel::<String>(512)` — telemetry bus.
6. Spawn tasks: `telemetry::run_ws_server`, `metrics::ticker`, `dpi::payload_task`, `dpi::connect_task`, `maintenance::ttl_sweep_task`, `maintenance::server_cmd_task`.
7. Spawn ctrl-C listener (sends `()` on a oneshot to the main `select!`).
8. Spawn `task::spawn_blocking` for the stdin CLI (so it never blocks tokio).
9. `tokio::select!` on the CLI task and the shutdown signal.

### `src/cli.rs` — CLI args, banner, stdin command loop

- `struct Args { iface, bpf_path, mode, log_level, ws_port, bind, monitor_prefix }` (clap derive). `--monitor-prefix 10.99.0.0/16` scopes the connect tracepoint via `MONITOR_CFG`.
- `parse_xdp_flags(s)` — accepts `skb` (default) / `drv` / `hw` / `default`.
- `parse_cidr(s)` — accepts `1.2.3.4` or `10.0.0.0/24`. Zeros host bits beyond the prefix.
- `lpm_key(ip, prefix)` → `aya::maps::lpm_trie::Key<u32>`; `format_lpm_key(&key)` — pretty-print.
- `print_banner`, `print_attached`, `print_prompt`, `print_block_deployed`, `print_unblock`, `print_error`, `print_help` — colored terminal output via the `colored` crate.
- `struct CliCtx { blocklist, telemetry, stats, drop_counter, latency_hist, ring_overflow, iface, bpf_path }` — what the stdin loop holds onto.
- `run_stdin_loop(ctx)` — the command match:
  - `block <IP[/prefix]>` — parse_cidr → LPM insert → broadcast BLOCK + EVENT.
  - `unblock <IP[/prefix]>` — LPM remove → broadcast UNBLOCK + EVENT.
  - `list` — iterate BLOCKLIST, format with age + TTL remaining.
  - `status` — interface, BPF ELF, hooks, rate limit, TTL, signatures, blocklist size.
  - `rules` / `sigs` / `signatures` — bar chart of `category_counts()`.
  - `stats` — kernel drops, p50/p99 ns, DPI total, per-family breakdown, ring overflows.
  - `clear` — drop every BLOCKLIST entry, broadcast UNBLOCK for each.
  - `help` / `?` — print the command reference.
  - `quit` / `exit` / `q` — break out of the CLI loop, drop links → all hooks detach.

### `src/dpi.rs` — payload + connect ring-buffer consumers

- `struct DpiStats { total_http_seen, total_detections, by_category }` — drives the `stats` CLI command.
- `pub async fn payload_task(ring, blocklist, tx, stats)` — **the core DPI loop.**
  - Owns a local `Reassembler::with_defaults()` and an `events_seen` counter; runs `reassembler.gc(now_ns)` every `REASSEMBLY_GC_INTERVAL` (1024 events).
  - Per event: build `FlowKey::from_event`, `reassembler.ingest(key, payload, now_ns)`, `signatures::is_http_request(view)` gate, then `signatures::match_payload(view)`. On hit: `reassembler.forget(&key)`, insert into BLOCKLIST, update `DpiStats`, broadcast BLOCK + critical EVENT, pretty-print to console.
- `pub async fn connect_task(ring, tx)` — drains `CONNECT_EVENTS`, formats PID + comm + dst, prints to console, broadcasts CONNECT JSON.
- `severity_paint(sev)` — returns a colored string for terminal.

### `src/maintenance.rs` — periodic blocklist housekeeping

- `BLOCK_TTL_SECS = 120` constant.
- `ttl_sweep_task(blocklist, tx)` — every 30 s, iterates `BLOCKLIST`, removes entries whose age exceeds `BLOCK_TTL_SECS`, broadcasts `UNBLOCK` + an `EVENT`.
- `server_cmd_task(blocklist, tx)` — listens for back-channel `DEMO_CMD` frames from the HUD over the WS.

### `src/metrics.rs` — system + kernel metrics

- `boot_time_ns()` — `clock_gettime(CLOCK_BOOTTIME)`. Same reference clock as `bpf_ktime_get_ns()` in the kernel, so timestamps round-trip.
- `read_latency_percentiles(hist)` — sums per-CPU `LATENCY_HIST` buckets, returns `(p50_ns, p99_ns)`. Bucket midpoint is `2^n * 1.5`.
- `ticker(tx, drop_counter, latency_hist, ring_overflow, iface)` — 1 Hz task. Reads `DROP_COUNTER` (sum across CPUs), latency percentiles, `RING_OVERFLOW` sum, `/proc/stat` (CPU%), `/proc/net/dev` (rx/tx bytes), `/proc/self/status` (RSS). Emits one `METRICS` JSON per tick.

### `src/telemetry.rs` — JSON builders + WS server

- `json_escape(s)` — minimal JSON escaper for the WS payloads.
- `metrics_json(...)`, `event_json(message, level)`, `block_json(source, target, payload, action, category, severity)`, `unblock_json(source)`, `connect_json(pid, comm, dst, port)` — the five telemetry shapes the HUD knows about (plus `SCENARIO` which the HUD emits for self-driven demo cycles).
- `Sender = broadcast::Sender<String>` — telemetry bus type alias used everywhere.
- `run_ws_server(tx, port, bind)` — `warp` server on `${bind}:${port}/ws`. Each connecting client gets a `tokio::broadcast::Receiver` and a fan-out task in `handle_ws_client`.

### `tests/unit_tests.rs` — 11 cross-platform unit tests
Byte-order conversion, mock blocklist insert/remove, distinct keys for distinct IPs, loopback key value, `HakamIp` matches std, command tokenization (block / unblock / no-arg), invalid-IP rejection, valid-IP acceptance, mock-map capacity at 1024. Does not load eBPF, attach hooks, or fire packets.

### `tests/dpi_matcher.rs` — 25 end-to-end matcher tests
One `#[test]` per row of [`evasion.md`](evasion.md): HIT rows enforce the guarantees we make on stage; MISS rows lock down the documented gaps so a regression that secretly closes them shows up in CI (and so the docs stay honest as the matcher evolves). Plus HTTP-gate coverage, smoke coverage, and a "every declared category has a matchable signature" round-trip.

### `tests/reassembly.rs` — 4 end-to-end reassembly tests
The split-segment evasion scenarios: `split_union_select_caught_after_segment_two`, `split_across_three_segments`, `parallel_flows_match_independently`, `forget_after_match_lets_same_flow_be_reinspected`.

---

## 5 · `xtask/` — build automation

**Single file: `src/main.rs`** (235 LOC). Invoked as `cargo xtask <subcommand>`.

### Subcommands
- **`build-ebpf [--release]`** → `build_ebpf()`. Spawns `cargo +nightly build -Z build-std=core --target bpfel-unknown-none --package hakam-ebpf --release` from the workspace root. Prints the resulting ELF path.
- **`run [--release] [--iface NAME] [--mode MODE]`** → `run()`. Sequence:
  1. Build the eBPF ELF (`build_ebpf`).
  2. Build hakam-node (`cargo build --features linux` ± `--release`).
  3. `auto_detect_iface()` if `--iface` not given (parses `ip route get 1.1.1.1`, falls back to `eth0`).
  4. **Pre-clean stale state**: `sudo ip link set dev IFACE xdp off`, `sudo tc qdisc del dev IFACE clsact`. Both ignored if they fail.
  5. `sudo target/<profile>/hakam-node --iface … --mode … --bpf-path …`.
- **`check`** → `cargo check --workspace --exclude hakam-ebpf`.
- **`test`** → `cargo test --workspace --exclude hakam-ebpf`.

### Helpers
- `auto_detect_iface()` — runs `ip route get 1.1.1.1` and pulls the `dev` token.
- `workspace_root()` — `manifest_dir.parent()`.

The pre-clean step in `run` is the reason "re-running `cargo xtask run` after a crash always works" — stale XDP hooks and clsact qdiscs are wiped before re-attach.

---

## 6 · `hakam-ui/` — React HUD

Vite + React 19 + TypeScript + Tailwind. Optional Tauri shell (desktop wrapper) under `src-tauri/`, not used by the demo (we use `npm run dev` → browser).

### Top-level
- `package.json` — deps: `framer-motion`, `lucide-react`, `clsx`, `tailwind-merge`, `react`, `react-dom`. Dev deps: `vite`, `tailwindcss`, `typescript`. Tauri deps present but optional.
- `vite.config.ts`, `tsconfig*.json`, `tailwind.config.js`, `postcss.config.js` — standard.
- `index.html` — single `<div id="root">` mount point.

### `src/main.tsx` (9 LOC)
- React 19 `createRoot` mounts `<App />` inside `<StrictMode>`.

### `src/App.tsx` (591 LOC)
- Uses `useHakamData()` to get every piece of state.
- `useIsMobile()` watches `matchMedia('(max-width: 900px)')` and early-returns `<MobileView />` on narrow viewports.
- **Header:** Hakam badge, scenario chip, **now-playing chip** (NowPlaying subcomponent at bottom of file — surfaces the latest BLOCK family/pattern/IP within a 5 s freshness window), tri-state status (`KERNEL_LINK` / `STALE_FEED` / `RECONNECTING`).
- **Main:** CSS Grid (`status / topology / timeline`) — `<Panel>` chrome wraps `<HakamStatus>`, `<TopologyMap>`, `<AttackTimeline>`. The grid is fully responsive (no `vw`/`vh` math).
- **Floating box:** `<EventLog>` bottom-right above the timeline, with a `FULL` button that opens a fullscreen modal.
- **Footer:** COMPARE / SOUND / FULLSCREEN / KEYS buttons.
- **Overlays:** `<InterceptSplash>` top-right on every BLOCK; `<KeyboardOverlay>` on `?`; `<SplitView>` on `V`.
- Computes:
  - `connected` = `wsConnected && !isStale` — derived from the explicit WS health flags (no longer inferred from frozen metric history).
  - `anyBlocked` — any node `blocked: true` in `threatState.nodes`.
  - `threatsBlocked` — sum of `familyCounts`.
  - `detectionRate` — BLOCK timestamps in last 30 s, ticked every second.

### `src/utils/websocket.ts` (532 LOC) — **the brain**

This is where every piece of UI state derives from. App.tsx exposes the result via `useHakamData()`.

**Type exports (used everywhere):**
- `LogLevel`, `Severity`, `LogEntry` — log-line shape.
- `AttackFamily` (literal union of 14 strings) and `FAMILY_COLOR` — per-family hex.
- `NodeRole` ∈ `attacker | pc1 | pc2 | db | firewall`. `NodeState`, `NodesState`, `NODE_META`.
- `roleForIp(ip)` — `10.99.0.x` → db, `10.99.1.x` → pc1, `10.99.2.x` → pc2, else attacker.
- `AttackEdge` — directed lit-edge for the topology overlay.
- `ThreatState { nodes, edge, showCard }`.
- `RecentAttack` — feeds the timeline + the now-playing chip.
- `ThreatLevel` 1–5, `THREAT_LEVEL_META` (DEFCON-style labels: SEVERE/HIGH/GUARDED/ELEVATED/NOMINAL).
- `GlobalMetrics` — every number on the hero panel.
- `FamilyCounts` — partial map family → count.

**Connection health constants:**
- `INITIAL_RECONNECT_MS = 3000`, `MAX_RECONNECT_MS = 60000` — exponential backoff bounds.
- `STALE_THRESHOLD_MS = 30000` — flips `isStale` when the socket is open but no events arrive for this long.

**`useHakamData()`** — the single React hook the rest of the UI consumes.
1. State: `logs`, `metrics`, `threatState`, `recentAttacks`, `familyCounts`, `threatLevel`, `splash`, `lastBlockTick`, `lastBenignTick`, `scenario`, `benignRate`, plus connection-health flags **`wsConnected`** and **`isStale`**.
2. Rolling windows: `attackWindowRef` (30 s of BLOCK timestamps → threat level), `benignWindowRef` (30 s of HTTP CONNECT timestamps → `benignRate`).
3. A 1.5-s interval decays threat level, the benign rate, and flips `isStale = true` when `Date.now() - lastEventAtRef > STALE_THRESHOLD_MS`.
4. `useEffect` opens `WebSocket(VITE_HAKAM_WS_URL || ws://localhost:8080/ws)`. **Exponential reconnect backoff** (3 s → 6 → 12 → 24 → 48 → 60 cap) via `scheduleReconnect`; resets to 3 s on successful `onopen`.
5. `onmessage` updates `lastEventAtRef`, clears `isStale`, then switches on `data.type`:
   - **METRICS** — derives `cpuHistory`, `rxHistory`, `pps` (rough: `rx_bps / 90`), `kernelMemory` (KB→MB), `ringOverflows`.
   - **CONNECT** — only HTTP-targeted (port 80 / 443) connects count toward `benignRate`; pulses the dst node `lastBenignAt`; appends a log line.
   - **EVENT** — generic message line.
   - **BLOCK** — pulses source node, sets `blocked` + `lastBlockedAt`, sets `threatState.edge`, bumps `lastBlockTick`, prepends to `recentAttacks` (cap 200), increments `familyCounts[category]`, prepends a critical log (cap 200); fires `splash` only for `critical` / `high` severity (auto-clears in 1.7 s); edge clears 2.5 s after the last hit.
   - **SCENARIO** — drives the scenario chip in the header.
   - **UNBLOCK** — clears `blocked` on the matching role.
6. `sendDemoCommand(action)` — back-channel WS frame `{ type: 'DEMO_CMD', action }`. No-op when not OPEN.
7. Cleanup on unmount: clear pending reconnect timer, close WS, clear all timers.

### `src/components/`

| File | LOC | Purpose | Reads from |
|------|----:|---------|------------|
| `Panel.tsx` | 36 | Static panel chrome — labeled header (`label` / `tag` / optional `actions`) with a flex-1 scrollable body. Used by every grid cell. | (none — pure layout) |
| `HakamStatus.tsx` | 684 | Hero panel: connection status header, big `THREATS_NEUTRALIZED` counter, static facts strip, live-traffic split bar with sparkline, threat-level meter, 3 metric tiles (CPU / drop-lat / throughput), family bars with MITRE ATT&CK IDs, system-state grid, process telemetry rows, attack-pattern heatmap (families × 30 s buckets, last 6 min). | `metrics`, `threatsBlocked`, `familyCounts`, `detectionRate`, `benignRate`, `logs`, `recentAttacks` |
| `TopologyMap.tsx` | 606 | Network graph: 5 nodes (`attacker`, `firewall`, `pc1`, `pc2`, `db`), 4 edges, time-decayed visual states (hot 0–3 s / warm 3–13 s / cool), one-shot intercept ring per new BLOCK (re-mounted on `lastBlockedAt` change), radar sweep around firewall during in-flight attacks, severed-edge × marker on blocked links, attacker-IP history list, zone legend (auto-fades 10 s). Pure SVG + framer-motion. | `threatState`, `blockTick`, `benignTick` |
| `AttackTimeline.tsx` | 252 | Bottom strip — aggregate readouts left (intercepts / rate / last / active families), color-coded ticks right, hover tooltip with family / severity / source / pattern. | `events`, `startedAt` |
| `EventLog.tsx` | 111 | Persistent event feed with `ALL / BLOCKS / CONNECTS` filter tabs, severity-tinted rows. Truncated to 200 lines by the WS layer; shown in a 420×270 floating box and a fullscreen modal. | `logs` |
| `InterceptSplash.tsx` | 122 | Top-right card on `critical` / `high` BLOCK only — family stripe + family/severity, source IP + pattern. Tween in/out (180/220 ms), auto-clears 1.7 s. | `splash` |
| `KeyboardOverlay.tsx` | 153 | Overlay shown on `?`. Documents the demo (Space / N / R / Q / 0–6) and UI (F / M / V / Esc) shortcuts. | `open`, `onClose` |
| `MobileView.tsx` | 179 | Single-column fallback for ≤900 px viewports. HAKAM brand, live `THREATS_NEUTRALIZED` counter, 3-bullet "how it works", last 5 intercepts, "best on desktop" hint. | `threatsBlocked`, `recentAttacks`, `wsConnected`, `isStale` |
| `SplitView.tsx` | 380 | Modal opened with `V` — side-by-side comparison: Hakam-protected (left) vs simulated unprotected (right). Right side projects each blocked event as a "breach"; the delta is the "so what" answer. | `threatsBlocked`, `familyCounts`, `detectionRate`, `peakRate`, `threatLevel` |

### `src-tauri/`
Optional Tauri desktop wrapper — `tauri.conf.json`, `Cargo.toml`, `build.rs`, `src/`. Not used by the demo. Workspace excluded.

---

## 7 · `scripts/` — bash demo + ops

| Script | LOC | Purpose |
|--------|----:|---------|
| `setup-demo.sh` | 83 | **Idempotent network bootstrap.** Creates `dummy0`, brings it up, adds 21 IP aliases (1 DB target, 2 workstations, 18 rotating sources), relaxes `rp_filter` to `2` (loose). Safe to re-run. |
| `demo-cycle.sh` | 183 | **6-phase narrated auto-cycle (~113 s).** Phases: BASELINE / FIRST CONTACT / RECON / MULTI-VECTOR / PEAK ASSAULT / COOLDOWN. Loops until Ctrl-C. Internally calls `seclist-attack.sh` per phase. |
| `seclist-attack.sh` | 379 | **187-payload firehose.** Inline corpus across 12 families. Flags: `-n N` count, `-c` continuous, `-k CAT` filter, `-d MS` delay, `-t IP:PORT`, `-l` list categories. Source IPs rotate through the 18-IP pool unless `SOURCES=()` is exported. |
| `attack.sh` | 176 | Older interactive 4-scenario walker — pauses for ENTER between scenarios, narrates each. Largely superseded by `demo-cycle.sh`. |
| `smoke.sh` | 160 | **Pre-stage health check.** Verifies (1) WS port open, (2) websocat installed, (3) METRICS arrives in ≤3 s, (4) manual `block` produces a BLOCK on the wire, (5) `unblock` produces UNBLOCK, (6) BLOCKLIST clean afterwards. Exit 0/1. Recommended to run ~60 s before going on stage. |
| `bpftrace-overlay.sh` | 128 | **Live kernel telemetry overlay.** Three modes: `drops` (XDP_DROP/s), `latency` (XDP run-time histogram), `connects` (every outbound `connect()` PID + comm). Useful during a demo to prove the HUD's numbers come from the kernel. |

### Cross-script conventions
- All have ANSI color helpers and a banner block.
- `setup-demo.sh` is the only one that needs sudo and `ip` tool. The rest only need a working dummy0 + `nc`.
- `seclist-attack.sh` accepts an external `SOURCES=("a.b.c.d" …)` to override the rotation pool — `demo-cycle.sh` uses this to pin a single source per shot when needed.
- All scripts assume target = `10.99.0.10:80` unless `-t` is passed.

---

## 8 · `docs/`

- `architecture.md` — 1-page bird's-eye summary (kernel/userspace boundary, hooks, maps, honest limits, test status).
- `codebase.md` — this file.
- `runtime_flow.md` — boot sequence + per-packet path + attack lifecycle + HUD lifecycle.

---

## 9 · Cross-reference index — "where does X live?"

| If you want to change… | Edit this |
|------|----|
| The DPI string corpus | `hakam-node/src/signatures.rs` `SIGNATURES` |
| The matcher pipeline (gate / AC / URL decode) | `hakam-node/src/signatures.rs` `match_payload`, `matcher`, `url_decoded` |
| What action is taken on a hit (drop / log / etc) | `hakam-node/src/dpi.rs` `payload_task` |
| Per-flow buffer caps (256 B, 30 s TTL, 4096 flows) | `hakam-node/src/reassembly.rs` `DEFAULT_MAX_FLOW_BUF` / `DEFAULT_FLOW_TTL_NS` / `DEFAULT_MAX_FLOWS` |
| Reassembly GC interval (every 1024 events) | `hakam-node/src/dpi.rs` constant `REASSEMBLY_GC_INTERVAL` |
| The auto-block rate threshold (500 pps) | `hakam-ebpf/src/main.rs` constant `RATE_LIMIT` |
| The block TTL (120 s) | `hakam-node/src/maintenance.rs` constant `BLOCK_TTL_SECS` |
| Payload sample window (64 B) | `hakam-common/src/lib.rs` constant `PAYLOAD_LEN` |
| Telemetry JSON shape | `hakam-node/src/telemetry.rs` `*_json(...)` builders |
| WS bind address (default `127.0.0.1`) | `hakam-node/src/cli.rs` `Args::bind` |
| Tracepoint CIDR scope | `hakam-node/src/cli.rs` `Args::monitor_prefix` + `hakam-ebpf/src/main.rs` map `MONITOR_CFG` |
| WS reconnect / parse logic | `hakam-ui/src/utils/websocket.ts` `useHakamData()` |
| Hero panel layout | `hakam-ui/src/components/HakamStatus.tsx` |
| Topology positions / edges | `hakam-ui/src/components/TopologyMap.tsx` `POS` and `EDGES` |
| Demo cycle phase timing | `scripts/demo-cycle.sh` `phase_*()` |
| Demo source-IP pool | `scripts/setup-demo.sh` and `scripts/seclist-attack.sh` `SOURCES=()` |
| Build / launch sequence | `xtask/src/main.rs` |
