# Hakam — Core Hardening Sessions

> Working checklist. Each item is a focused, scoped change with paste-ready code. Mark done as you ship. Full reasoning lives in [`docs/core_review.md`](core_review.md).

| Session | Goal | Items | Total effort |
|--------:|------|------:|:------------:|
| **1** | Eliminate every weakness called out in the core review — turn each "yes that's a gap" into a "yes that's a design choice with a defensible answer" | 4 | ~45 min |
| **2** | Upgrade Arsenal-grade → Briefings-grade — real perf claims + test coverage + scoped instrumentation | 4 | ~1 hr |

**Status legend:** ✅ done · ⬜ pending

---

## Session 1 — Arsenal hardening (~45 min)

### ✅ A1 · Per-CPU rate-limit counter — DONE
**Commit:** `8922004` · **Effort:** 15 min

**Problem:** `PACKET_COUNTER` was a regular `HashMap<u32, u64>`. The `*ptr += 1` increment was racy across CPUs — four CPUs could all read 499 and write 500, letting the block fire at 2000 packets instead of 500.

**Fix applied:**
```rust
// hakam-ebpf/src/main.rs
static PACKET_COUNTER: PerCpuHashMap<u32, u64> = PerCpuHashMap::<u32, u64>::with_max_entries(1024, 0);
static LAST_SEEN:      PerCpuHashMap<u32, u32> = PerCpuHashMap::<u32, u32>::with_max_entries(1024, 0);
```

**On-stage answer:** *"Per-CPU counter by design. A real attacker flow hashes to one RX queue → one CPU → 500 pps. Distributed flow hits 500 × num_cpus worst case, which we accept."*

---

### ✅ A2 · WebSocket bind default → localhost — DONE
**Effort:** 10 min

**Problem:** WS binds to `0.0.0.0:8080/ws` unconditionally — anyone on the network can read every block event, every `CONNECT` event with PID/comm, every metric.

**Fix:**
```rust
// hakam-node/src/main.rs — Args
#[arg(long, default_value = "127.0.0.1")]
bind: std::net::IpAddr,
```

```rust
// hakam-node/src/main.rs — run_ws_server
let addr: std::net::SocketAddr = (args.bind, port).into();
```

Update the banner print and `start_guide.md` to use `--bind 0.0.0.0` for the demo.

**On-stage answer:** *"Localhost by default. WebSocket is read-only telemetry — no commands flow this way. For the demo we explicitly bind to 0.0.0.0 because the Mac browser needs to reach it; production would use SSH tunnel or a reverse proxy with auth."*

---

### ✅ A3 · LRU eviction on counter maps — DONE
**Effort:** 10 min

**Problem:** `PACKET_COUNTER` and `LAST_SEEN` are bounded at 1024 entries. Once full, the 1025th unique IP gets **no rate-limit enforcement at all**. A flood from 2000 random source IPs walks past the gate.

**Fix:**
```rust
// hakam-ebpf/src/main.rs
use aya_ebpf::maps::LruPerCpuHashMap;

static PACKET_COUNTER: LruPerCpuHashMap<u32, u64> = LruPerCpuHashMap::<u32, u64>::with_max_entries(1024, 0);
static LAST_SEEN:      LruPerCpuHashMap<u32, u32> = LruPerCpuHashMap::<u32, u32>::with_max_entries(1024, 0);
```

Same API — `get`, `insert`, `get_ptr_mut` all unchanged. Kernel auto-evicts the oldest entry on capacity hit.

**On-stage answer:** *"LRU-evicted. Old entries auto-purge, so high-churn source pools never starve enforcement on new attackers."*

---

### ✅ A4 · Ring buffer overflow counter — DONE
**Commit:** `8922004` · **Effort:** 10 min

**Problem:** When `PAYLOAD_EVENTS.reserve()` returned `None` (ring full), the sample was silently dropped — no counter, no signal, no way to know DPI was falling behind.

**Fix applied:**
```rust
// hakam-ebpf/src/main.rs
#[map]
static RING_OVERFLOW: PerCpuArray<u64> = PerCpuArray::<u64>::with_max_entries(1, 0);

// in sample_payload:
None => {
    unsafe { if let Some(p) = RING_OVERFLOW.get_ptr_mut(0) { *p += 1; } }
    return;
}
```

Userspace pulls the map, sums across CPUs, surfaces in:
- `stats` CLI command (green when 0, red when > 0)
- `metrics_json` → `"ring_overflows":N` field for the HUD

**On-stage answer:** *"`stats` shows ring overflows — was zero just now. If it's not zero, we know exactly how many TCP payloads we failed to inspect."*

---

## Session 2 — Briefings upgrade (~1 hr)

### ⬜ B1 · Aho-Corasick DPI matcher
**Effort:** 30 min · **Real perf win**

**Problem:** DPI loop scans 203 signatures sequentially per packet: O(signatures × text × pattern). At demo rate invisible, at line rate 200× slower than necessary. "I'd use Aho-Corasick" is the first reflex of any DPI reviewer.

**Fix:**
```toml
# hakam-node/Cargo.toml
aho-corasick = "1"
```

```rust
// hakam-node/src/signatures.rs (add at bottom)
use aho_corasick::AhoCorasick;
use std::sync::OnceLock;

pub fn matcher() -> &'static AhoCorasick {
    static M: OnceLock<AhoCorasick> = OnceLock::new();
    M.get_or_init(|| {
        AhoCorasick::new(SIGNATURES.iter().map(|s| s.pattern))
            .expect("signatures compile into Aho-Corasick automaton")
    })
}
```

```rust
// hakam-node/src/main.rs — dpi_task, replace the for-loop
if let Some(m) = signatures::matcher().find(&upper) {
    let sig = &signatures::SIGNATURES[m.pattern().as_usize()];
    // … existing block + telemetry code, unchanged
}
```

The `aho-corasick` crate is already a transitive dep via `regex`. No new vendor surface.

**On-stage answer:** *"Aho-Corasick automaton built once at startup. Single-pass match for all 203 patterns. Scales to thousands of signatures without a perf cliff."*

---

### ⬜ B2 · Tracepoint scoped to monitored CIDR
**Effort:** 15 min

**Problem:** `sys_enter_connect` fires for **every connect() on the system** — DNS lookups, apt, systemd-resolved all clutter the `CONNECT` event stream.

**Fix:**
```rust
// hakam-ebpf/src/main.rs
use aya_ebpf::maps::Array;

#[map]
static MONITOR_CFG: Array<u64> = Array::<u64>::with_max_entries(1, 0);
// Layout: high 32 bits = network (big-endian), low 32 bits = mask. 0 = monitor all.

// in try_connect, after the sa_family check:
if let Some(cfg) = MONITOR_CFG.get(0) {
    let network = (cfg >> 32) as u32;
    let mask    = *cfg as u32;
    if mask != 0 && (sa.sin_addr & mask) != network {
        return Ok(0);
    }
}
```

Userspace sets `MONITOR_CFG[0]` from a new `--monitor-prefix 10.99.0.0/16` flag. Empty / unset = monitor everything (current behavior).

**On-stage answer:** *"Userspace pushes the monitored prefix into a config map; we filter in kernel before reserving a ring slot. Default is the demo subnet; you can scope it tighter or open it up."*

---

### ⬜ B3 · Unit tests for the DPI signature matcher
**Effort:** 30 min

**Problem:** `hakam-node/tests/unit_tests.rs` covers 11 cases — all about CIDR parsing. The actual security claim (signature matching, evasion table) has zero test coverage. A typo in `signatures.rs` could go undetected.

**Fix:**
```rust
// hakam-node/src/signatures.rs — extract the matcher as a pure function
pub fn is_http_request(payload: &str) -> bool { /* move from main.rs */ }

pub fn match_payload(payload: &str) -> Option<&'static Sig> {
    if !is_http_request(payload) { return None; }
    let upper = payload.to_ascii_uppercase();
    SIGNATURES.iter().find(|sig| upper.contains(sig.pattern))
}
```

```rust
// hakam-node/tests/dpi_matcher.rs — new file
use hakam_node::signatures::match_payload;

#[test] fn catches_lowercase_sqli() {
    assert!(match_payload("GET /?x=union select 1 HTTP/1.1").is_some());
}
#[test] fn misses_url_encoded_space() {
    assert!(match_payload("GET /?x=UNION%20SELECT HTTP/1.1").is_none());
}
#[test] fn requires_http_method() {
    assert!(match_payload("UNION SELECT 1").is_none());
}
#[test] fn case_insensitive_xss() {
    assert!(match_payload("GET /?x=<sCrIpT> HTTP/1.1").is_some());
}
#[test] fn lfi_url_encoded_caught() {
    assert!(match_payload("GET /..%2Fetc%2Fpasswd HTTP/1.1").is_some());
    assert!(match_payload("GET /%2E%2E%2Fetc HTTP/1.1").is_some());
}
#[test] fn rce_lowercase_caught() {
    assert!(match_payload("GET /?cmd=;whoami HTTP/1.1").is_some());
}
```

**Note:** requires `hakam-node` to expose `signatures` as a `pub mod` or move the matcher to a `lib.rs`. Small refactor — 10 min of the 30.

**On-stage answer:** *"The evasion table in `docs/evasion.md` is enforced by `cargo test`. Anyone who edits signatures and breaks coverage gets a red CI run before the change lands."*

---

### ⬜ B4 · Const assertion: all signatures uppercase
**Effort:** 5 min

**Problem:** Matching does `upper.contains(sig.pattern)`. If someone adds a signature with a lowercase letter, it'll **never match** — silently. Footgun.

**Fix:**
```rust
// hakam-node/src/signatures.rs
#[cfg(test)]
#[test]
fn all_signatures_uppercase() {
    for sig in SIGNATURES {
        assert_eq!(
            sig.pattern, sig.pattern.to_ascii_uppercase(),
            "signature '{}' has lowercase chars — will never match", sig.pattern
        );
    }
}
```

**On-stage answer:** *"All 203 signatures are verified uppercase by a test that runs in CI. Lowercase patterns can't sneak in."*

---

## What you say on stage after both sessions

Pick any question a Black Hat reviewer might fire. Compare today vs. after:

| Question | Today | After Session 1 | After Session 2 |
|----------|-------|----------------|-----------------|
| Race in your rate-limit counter? | "Yeah, per-CPU approximate" | "Per-CPU by design" | same |
| WS auth? | "It's open" | "Localhost-only, demo binds 0.0.0.0 explicitly" | same |
| What if I flood with 2000 random IPs? | "Map exhausts at 1024" | "LRU-evicted" | same |
| Are you dropping samples under load? | "I don't know" | "`stats` shows 0 ring overflows" | same |
| DPI is O(N×M)? | "Yes" | same | "Aho-Corasick, single pass" |
| Test coverage on the matcher? | "Only CIDR parsing" | same | "`cargo test` enforces evasion table" |
| Tracepoint sees everything? | "Yes, system-wide" | same | "Scoped to a CIDR via kernel config map" |

---

## Tracking

| Session | Item | Status | Commit |
|--------:|------|:------:|--------|
| 1 | A1 — per-CPU rate-limit | ✅ done | `8922004` |
| 1 | A2 — WS bind localhost | ✅ done | next commit |
| 1 | A3 — LRU eviction | ✅ done | next commit |
| 1 | A4 — ring overflow counter | ✅ done | `8922004` |
| 2 | B1 — Aho-Corasick | ✅ done | (case-insensitive, drops per-packet uppercase copy) |
| 2 | B2 — tracepoint scope | ⬜ pending | — |
| 2 | B3 — DPI matcher tests | ✅ done | hakam-node lib + tests/dpi_matcher.rs (25 tests) |
| 2 | B4 — uppercase assertion | ✅ done | + length and category-table invariants |

**Progress: 7 of 8 (only B2 — tracepoint scope — remains in Session 2).**

Update this table as you ship each item.
