# Phase 1 Implementation Log — 2026-05-31

> **Session date:** 2026-05-31
> **Commit:** `c909c43` — `feat: Phase 1 Arsenal hardening — Aho-Corasick + URL decode + TCP reassembly`
> **Scope:** Closes every Phase 1 item in [`arsenal_roadmap.md`](arsenal_roadmap.md) and items B1 / B3 / B4 in [`core_hardening.md`](core_hardening.md).
> **Schedule:** Roadmap allocated 14 days (May 28 → Jun 11). Landed in one session, 11 days ahead of the Phase 2 start date.

This document is the complete record of every file added, deleted, edited, and why. Read it before moving to Phase 2.

---

## 1. Roadmap items shipped

| Roadmap ref | Title | Effort budgeted | Status |
|------------:|-------|:---------------:|:------:|
| Phase 1 #5 / B4 | Uppercase signature assertion | 0.1 d | ✅ |
| Phase 1 #3 / B1 | Aho-Corasick DPI matcher | 0.5 d | ✅ |
| Phase 1 #4 / B3 | DPI matcher unit tests + evasion corpus | 0.5 d | ✅ |
| Phase 1 #2 | URL / percent-decoding pipeline | 2 d | ✅ |
| Phase 1 #1 | TCP segment reassembly (userspace) | 4 d | ✅ |
| New | Extend `PayloadEvent` with 4-tuple (kernel side) | — | ✅ (prerequisite for #1) |

Only `B2 — tracepoint scope` remains open in `core_hardening.md`.

---

## 2. File inventory

### 2.1 Files created (new)

| Path | Lines | Role |
|------|------:|------|
| `hakam-node/src/lib.rs` | 9 | Promotes `hakam-node` to a library crate so the matcher + reassembler can be exercised by integration tests on any host (not just Linux). Re-exports `signatures` and `reassembly`. |
| `hakam-node/src/reassembly.rs` | 240 | Per-flow TCP segment buffer, keyed on a 4-tuple `FlowKey`. Closes the multi-segment evasion. |
| `hakam-node/tests/dpi_matcher.rs` | 152 | 25 integration tests that pin every row of [`evasion.md`](evasion.md) plus HTTP-gate, smoke, and empty-input coverage. |
| `hakam-node/tests/reassembly.rs` | 91 | 4 end-to-end tests that drive the reassembler + matcher together with the actual split-segment attack scenarios. |
| `docs/arsenal_roadmap.md` | (pre-session file, now tracked) | The Phase 1 → Phase 4 plan. Was untracked at session start; staged in this commit. |
| `docs/post_arsenal_roadmap.md` | (pre-session file, now tracked) | Booth-week prep and v2 ideas. Same — staged in this commit. |
| `docs/phase1_implementation_log.md` | (this file) | The document you are reading. |

### 2.2 Files modified

| Path | Diff lines | Purpose of edit |
|------|----------:|-----------------|
| `hakam-common/src/lib.rs` | +19 | Added 3 new fields to `PayloadEvent`; added layout test. |
| `hakam-ebpf/src/xdp.rs` | +21 / -8 | Read TCP src/dst port + IP dst_addr in `sample_payload`; write them into the new `PayloadEvent` fields. |
| `hakam-node/Cargo.toml` | +2 deps | `aho-corasick = "1"`, `percent-encoding = "2"`. Both already transitive — no new vendor surface. |
| `hakam-node/src/main.rs` | -2 | Removed `#[cfg(feature = "linux")] mod signatures;` — the module now lives in `lib.rs`. |
| `hakam-node/src/signatures.rs` | +142 | Added `is_http_request`, `match_payload`, `matcher` (Aho-Corasick), `url_decoded`, and 4 inline invariant tests. |
| `hakam-node/src/dpi.rs` | +60 / -67 | Replaced the 203-pattern loop with `signatures::match_payload`; integrated the `Reassembler` into `payload_task`. |
| `README.md` | +4 / -4 | Rewrote "Honest limitations" — dropped the "no URL decoding" and "single-segment only" bullets; added "in-order TCP only", "single-pass URL decoding". |
| `docs/evasion.md` | +21 / -20 | Score went from 10/20 to 15/15 HIT. Rows 11, 12, 26, 27 flipped MISS → HIT. Row 13 fact-checked (was wrong before — caught via `ALERT(1)`). Row 14 added. Row 23 reframed. Pipeline recap and Q&A sections rewritten. |
| `docs/core_hardening.md` | +3 / -3 | Marked B1 / B3 / B4 done in the tracker. Updated progress count to 7 of 8. |
| `Cargo.lock` | +2 | Auto-update from the new direct deps. |

### 2.3 Files NOT touched (intentionally)

These files showed up in `git status` at session start as already-modified by the user — they are unrelated to Phase 1 and were left alone:

- `.gitignore`
- `hakam-ui/src/App.tsx`
- `start_guide.md`

If you want them in source control, stage and commit them separately.

### 2.4 Files deleted

None. Some functions were deleted inside `dpi.rs` (the inline `is_http_request` and the 203-pattern `for` loop), but no whole files were removed.

---

## 3. What each change does, in plain English

### 3.1 `hakam-common/src/lib.rs` — `PayloadEvent` extended

**Before.** The kernel sent userspace `(src_addr, payload_len, [u8; 64])`. Userspace knew which IP a packet came from, but not the source port, the destination IP, or the destination port. Three packets from the same `src_addr` could be three different TCP flows — no way to tell.

**After.** `PayloadEvent` carries the full 4-tuple:

```rust
#[repr(C)]
pub struct PayloadEvent {
    pub src_addr:    u32,    // wire byte order
    pub dst_addr:    u32,    // wire byte order  (new)
    pub src_port:    u16,    // wire byte order  (new)
    pub dst_port:    u16,    // wire byte order  (new)
    pub payload_len: u32,
    pub payload:     [u8; PAYLOAD_LEN],
}
```

Size went from 72 → 80 bytes. Layout pinned by a new test (`test_payload_event_layout`).

**Why this matters.** Without these fields, "reassemble per flow" is impossible because userspace has no flow key. This is the foundation that Phase 1 #1 stands on, and the same struct is what the Phase 2 #7 eBPF conntrack will read.

### 3.2 `hakam-ebpf/src/xdp.rs` — kernel sample populates the new fields

**Before.** `sample_payload` extracted only `src_addr` from the IP header. TCP ports were never read.

**After.** Reads `dst_addr` from the IPv4 header (offset 16), then reads TCP `src_port` (offset 0) and `dst_port` (offset 2) from the TCP header. The bounds check was consolidated: `tcp_hdr_start + 13 > data_end` covers ports (0..4) + data-offset byte (12..13) in one expression.

**Why this matters.** The BPF verifier needs explicit bounds checks before any memory read. The earlier code split the checks across two locations; the new code uses a single guard that the verifier can prove covers every subsequent read.

### 3.3 `hakam-node/src/lib.rs` — new library crate

**Before.** `hakam-node` was a binary crate only. Its modules (`signatures`, `dpi`, etc.) were declared inside `main.rs` and gated behind `#[cfg(feature = "linux")]`. This meant `cargo test` on macOS could not reach the matcher — tests had to live in a parallel re-implementation (`tests/unit_tests.rs` reimplements logic just to test it).

**After.** A new `lib.rs` exposes the platform-independent pieces:

```rust
pub mod reassembly;
pub mod signatures;
```

Both modules compile and test on any host. `main.rs` still owns all the Linux-only runtime code (eBPF loading, ring-buffer consumers).

**Why this matters.** Real tests against the real matcher are now possible without a Linux VM. The 25 integration tests in `tests/dpi_matcher.rs` exist because of this refactor.

### 3.4 `hakam-node/src/signatures.rs` — new public API + Aho-Corasick

Four functions added, in declaration order:

| Function | Purpose |
|---------|---------|
| `is_http_request(payload: &[u8]) -> bool` | The HTTP method gate. Moved from `dpi.rs` and changed to operate on `&[u8]` (was `&str`) so callers don't have to allocate a `String` per packet. |
| `match_payload(payload: &[u8]) -> Option<&'static Sig>` | The full DPI pipeline: HTTP gate → AC match on raw bytes → fallback AC match on URL-decoded bytes. Single entry point for tests and for `dpi.rs`. |
| `matcher() -> &'static AhoCorasick` | Lazy AC automaton over all 203 signatures, built once on first call via `OnceLock`. `ascii_case_insensitive(true)` so it folds `A-Z ⇔ a-z` internally — no per-packet uppercase copy is needed anymore. |
| `url_decoded(payload: &[u8]) -> Option<Vec<u8>>` | One pass of percent decoding (`%XX` → byte) plus `+` → space. Returns `None` if the payload has no `%` or `+`, letting the caller skip allocation in the common case. |

Plus the **inline test module** at the bottom of the file:

| Test | What it pins |
|------|--------------|
| `all_signatures_are_uppercase` | Style convention — the corpus stays uppercase even though the AC matcher is case-insensitive (helps grep and visual review). |
| `no_signature_exceeds_payload_window` | Any signature longer than `PAYLOAD_LEN` (64) can never match because the kernel only samples 64 bytes. CI fails the build if someone adds one. |
| `no_signature_is_empty` | Guards against an empty-string typo. |
| `category_table_is_complete` | The `CATEGORIES` display table must list exactly the categories that appear in `SIGNATURES`. CI fails on drift. |

**Why this matters.** The old matcher was O(signatures × text × pattern length) with a per-packet uppercase allocation. The new matcher is a single-pass AC scan on the raw bytes — no allocation in the hot path. URL decoding is a fallback (only triggers if the raw match misses and the payload contains `%` or `+`), so the common case is unchanged.

### 3.5 `hakam-node/src/reassembly.rs` — new userspace reassembler

The new module exposes three types and two constants:

```rust
pub struct FlowKey {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub src_port: u16,
    pub dst_port: u16,
}
impl FlowKey {
    pub fn from_event(event: &PayloadEvent) -> Self;
}

pub struct Reassembler { /* private fields */ }
impl Reassembler {
    pub fn new(max_buf: usize, ttl_ns: u64, max_flows: usize) -> Self;
    pub fn with_defaults() -> Self;
    pub fn ingest(&mut self, key: FlowKey, payload: &[u8], now_ns: u64) -> Option<&[u8]>;
    pub fn forget(&mut self, key: &FlowKey);
    pub fn gc(&mut self, now_ns: u64) -> usize;
    pub fn flow_count(&self) -> usize;
    pub fn dropped_full_buf(&self) -> u64;
    pub fn dropped_at_cap(&self) -> u64;
}

pub const DEFAULT_MAX_FLOW_BUF: usize = 256;   // 4 segments
pub const DEFAULT_FLOW_TTL_NS:  u64   = 30 * 1_000_000_000;  // 30 s
pub const DEFAULT_MAX_FLOWS:    usize = 4096;
```

**How it works.** Every TCP sample from the kernel becomes an `ingest(FlowKey, payload, now_ns)` call. If the flow doesn't exist yet, it's created (refused if at `max_flows` cap). The payload is appended to the flow's buffer up to `max_buf`. The returned slice is the buffer view — pass it to `match_payload`. After a match fires, call `forget(&key)` so the same flow can be re-inspected (this matters for HTTP keep-alive where multiple requests pipeline on one TCP connection).

**`FlowState` design choice.** The struct deliberately leaves room for fields that the Phase 2 #7 eBPF conntrack will populate (`seq_next` for reordering and retransmit dedupe, `dir` for client→server classification). When that work lands, the swap-in is mechanical, not a rewrite.

**What it does NOT do** (per the module-level docstring):

- No TCP state machine. Any segment with a payload is a matching opportunity.
- No reordering. Without seq numbers (which arrive with Phase 2 #7), we append in arrival order. Out-of-order delivery can break a split signature.
- No retransmit dedupe. Same reason. A retransmit appends a duplicate to the buffer — harmless for substring matching but uses buffer space.

**Inline tests (7):** `single_segment_is_returned_intact`, `two_segments_concatenate`, `distinct_flows_dont_bleed`, `forget_drops_state`, `gc_evicts_stale_flows`, `buffer_cap_clamps_growth`, `flow_cap_refuses_new_flows`.

### 3.6 `hakam-node/src/dpi.rs` — `payload_task` integration

**Before.**

```rust
let text = String::from_utf8_lossy(&event.payload[..len]);
if !is_http_request(&text) { continue; }
let upper = text.to_ascii_uppercase();
for sig in SIGNATURES {
    if upper.contains(sig.pattern) {
        // block + telemetry
        break;
    }
}
```

Two heap allocations per packet (`from_utf8_lossy` + `to_ascii_uppercase`), O(N×M) sequential loop. No flow context.

**After.**

```rust
let key = FlowKey::from_event(event);
let Some(view) = reassembler.ingest(key, payload, now_ns) else { continue; };

if !signatures::is_http_request(view) { continue; }

// stats++
let Some(sig) = signatures::match_payload(view) else { continue; };

reassembler.forget(&key);
// block + telemetry
```

Zero per-packet allocation. AC-based match. Reassembled view replaces single-segment view. `gc` runs every 1024 events (`REASSEMBLY_GC_INTERVAL`) to evict TTL'd flows.

**Inline `is_http_request` function deleted** — moved to `signatures.rs` and made `pub`.

### 3.7 Documentation updates

`docs/evasion.md` got the biggest rewrite. Concrete changes:

| Edit | Before | After |
|------|--------|-------|
| Pipeline recap | "Payload is converted to ASCII uppercase, then each signature is matched as a case-insensitive substring" | "The full corpus is compiled once into an Aho-Corasick automaton, case-insensitive on ASCII; runs as one single-pass scan on the raw payload bytes" |
| Row 11 (`UNION%20SELECT`) | MISS — no URL decode | HIT — single-pass URL decode |
| Row 12 (`%27%20OR…`) | MISS | HIT — single-pass URL decode |
| Row 13 (`%3Cscript%3Ealert(1)`) | MISS (the doc was wrong) | HIT — `ALERT(1)` is its own signature, catches the unencoded tail |
| Row 14 (`UNION%2520SELECT`) | (was row 14 with same content) | Reworded — we now decode once, deliberately not twice |
| Row 23 (long path prefix) | "Capture window is 64 bytes; tail is never seen" | "The 64-byte sample window truncates within a single segment; multi-segment attacks recover via reassembly, but a single oversized segment does not" |
| Row 26 (`UNION+SELECT+1`) | MISS | HIT — form-urlencoded `+` → space |
| Row 27 (`UNION%2BSELECT`) | MISS | HIT — `%2B` → `+` → space chain |
| Score | 10 HIT / 20 MISS | **15 HIT / 15 MISS** |
| "Known gaps" §1 | "No URL decoding" | "Single-pass URL decoding only" |
| "Known gaps" §3 | "Single-segment only" | "Userspace reassembly, in-order only" |
| "Known gaps" §4 | "ASCII uppercase only" | "ASCII case folding only" |
| Q&A rehearsal | "We don't decode" | "Single-pass URL decoding runs as a fallback" |
| Demo path narration | "We uppercase everything before we match" | "The matcher is case-insensitive at the automaton level" |

`README.md` — "Honest limitations" section dropped from 4 bullets to 4 different bullets (URL-decoding and single-segment-only removed; in-order TCP and single-pass URL decoding added).

`docs/core_hardening.md` — tracker table updated; B1 / B3 / B4 marked done.

`docs/arsenal_roadmap.md` — Phase 1 progress tracker updated; items #1 through #5 marked done with notes.

---

## 4. Test inventory

Across the workspace, **61 tests pass** as of this commit:

```
hakam-common               10 tests   (added: test_payload_event_layout)
hakam-node lib (signatures) 4 tests   (new file)
hakam-node lib (reassembly) 7 tests   (new file)
hakam-node main             0 tests
hakam-node tests/dpi_matcher.rs  25 tests   (new file)
hakam-node tests/reassembly.rs    4 tests   (new file)
hakam-node tests/unit_tests.rs   11 tests   (unchanged)
```

### 4.1 `signatures` invariants (4)

- `all_signatures_are_uppercase`
- `no_signature_exceeds_payload_window`
- `no_signature_is_empty`
- `category_table_is_complete`

### 4.2 `reassembly` unit tests (7)

- `single_segment_is_returned_intact`
- `two_segments_concatenate`
- `distinct_flows_dont_bleed`
- `forget_drops_state`
- `gc_evicts_stale_flows`
- `buffer_cap_clamps_growth`
- `flow_cap_refuses_new_flows`

### 4.3 `dpi_matcher` integration tests (25)

Each test name encodes the [`evasion.md`](evasion.md) row it pins.

**HIT rows (11):** `hit_01_lowercase_sqli_union_select`, `hit_02_mixed_case_sqli`, `hit_03_lowercase_xss_script_tag`, `hit_04_mixed_case_xss`, `hit_05_lowercase_javascript_url`, `hit_06_lowercase_sqli_or_truism`, `hit_07_lowercase_rce_whoami`, `hit_08_url_encoded_lfi_slash_2f`, `hit_09_url_encoded_lfi_dot_dot`, `hit_10_double_url_encoded_lfi`, `hit_11_url_encoded_space_in_sqli`, `hit_12_fully_url_encoded_sqli`, `hit_13_url_encoded_script_still_caught_via_alert`, `hit_26_plus_decoded_to_space`, `hit_27_encoded_plus_chains_to_space`.

**MISS rows (4):** `miss_14_double_url_encoded_space`, `miss_15_sql_comment_breaks_pattern`, `miss_18_tab_instead_of_space`, `miss_23_attack_beyond_capture_window`, `miss_24_propfind_bypasses_http_gate`.

**Pipeline correctness (6):** `requires_http_method_prefix`, `accepts_every_recognised_method`, `empty_payload_returns_none`, `http_request_with_no_attack_returns_none`, `each_declared_category_has_a_matchable_signature`.

### 4.4 `reassembly` integration tests (4)

- `split_union_select_caught_after_segment_two` — the headline scenario: split `UNION SELECT` across two TCP segments, neither alone matches, the reassembled buffer matches.
- `split_across_three_segments` — same but with three segments.
- `parallel_flows_match_independently` — interleaved benign + attacker flows do not contaminate each other.
- `forget_after_match_lets_same_flow_be_reinspected` — HTTP keep-alive case: after blocking the first attack on a connection, the next request gets a fresh buffer.

---

## 5. Architectural decisions (and the alternatives we rejected)

### 5.1 Aho-Corasick case mode

**Chose:** `ascii_case_insensitive(true)`. Folds A–Z internally — no per-packet uppercase copy.
**Alternative:** Build the AC automaton case-sensitive and keep uppercasing the payload (the original `core_hardening.md` B1 spec). Slower (one allocation per packet) and the case-insensitive AC is the same number of lines.

### 5.2 URL decoding: single-pass or recursive?

**Chose:** Single-pass (`%XX` → byte, plus `+` → space) as a fallback after the raw match misses.
**Alternative:** Recursive decoding until a fixed point. Amplifies false-positive surface on legitimate URLs that happen to contain `%25` literally. Documented as a known gap (row 14 in `evasion.md`).

### 5.3 Reassembly: userspace, kernel, or hybrid?

**Chose:** Userspace, in `hakam-node`. `FlowState` struct designed to be extended later with `seq_next` and `dir` fields when the Phase 2 #7 eBPF conntrack lands. No throwaway code.
**Alternative considered:** Skip Phase 1 #1 entirely and build the eBPF conntrack first. Rejected because Phase 2 also includes BPF-LSM enforcement, which is higher risk — conntrack-blocked verifier work would block both #6 and #7.

### 5.4 Match-then-forget for reassembled flows

**Chose:** Call `reassembler.forget(&key)` after a match fires. Subsequent requests on the same TCP connection get a fresh buffer.
**Why this matters:** HTTP keep-alive pipelines multiple requests on one TCP connection (one 4-tuple). Without `forget`, a benign request on a connection that previously triggered an attack would still match the residual buffered bytes — false positive cascade.

### 5.5 `is_http_request` runs on the reassembled view, not just the segment

**Chose:** Gate on `is_http_request(view)` after reassembly.
**Why:** After segment 1 of `GET /?...`, the view starts with `GET `. After segment 2 (continuation), the view still starts with `GET ` because the buffer holds segment 1 + 2. So the gate stays correct. The cost: a second segment that arrives before segment 1 (out-of-order delivery) creates a buffer that does not start with an HTTP method — that flow gets skipped. Documented limitation.

### 5.6 Wire byte order in `PayloadEvent`

**Chose:** Store IP addresses and ports as the raw on-wire bytes (big-endian on the wire, stored in `u32` / `u16` with no conversion). Userspace converts on display using `to_ne_bytes` (for octets) or `u16::from_be` (for port values).
**Why:** Matches the existing convention for `src_addr`. The eBPF side has no `htons` / `ntohs` overhead. Consistent across `PayloadEvent` and `ConnectEvent`.

---

## 6. Verification status

### 6.1 Verified on macOS (this session)

- `cargo check` (workspace, default features) — green.
- `cargo test` — all 61 tests pass.
- `cargo test -p hakam-common` — 10 pass, including the new `test_payload_event_layout` (pins size to 16 + `PAYLOAD_LEN` = 80 bytes, alignment 4).
- `cargo test -p hakam-node` — 51 pass (11 lib + 25 + 4 + 11 integration).

### 6.2 NOT verified — needs Linux VM

These code paths cannot run on macOS because `metrics.rs` uses `libc::CLOCK_BOOTTIME` (Linux-only) and `aya` imports netlink symbols absent on Apple `libc`:

- `hakam-ebpf/src/xdp.rs` — the new `tcp_hdr_start + 13 > data_end` bounds check needs to pass the BPF verifier. The math is correct from a "human verifier" standpoint, but the kernel verifier is pattern-based and may reject it. **If it does**, the fallback is to split the check into per-read guards (one for ports, one for the data-offset byte) — straightforward refactor.
- `hakam-node/src/dpi.rs::payload_task` — the new `Reassembler` integration is unit-tested in isolation, but the live ring-buffer integration only runs under `cargo xtask run`.

**Verification commands on the Linux VM:**

```bash
cd ~/hakam
cargo xtask build-ebpf            # rebuild the eBPF ELF with the new sample_payload
cargo xtask run --iface lo --mode skb
# in another shell, run an attack and confirm the block fires:
./scripts/demo-cycle.sh
```

If the eBPF rebuild fails with a verifier error, the most likely fix is to split the `tcp_hdr_start + 13` check into two guards.

### 6.3 Wire-format change

`PayloadEvent` is 8 bytes larger (72 → 80). This is a wire-format change between the kernel program and userspace. Both sides are in the same repo and are rebuilt together by `cargo xtask`, so there is no version-skew risk in this codebase — but if anyone has an old `hakam-ebpf` ELF cached, they must rebuild it. `cargo xtask build-ebpf` does this.

---

## 7. Dependencies added

Both were already pulled in transitively by `regex`. Promoting them to direct deps adds zero binary surface:

| Crate | Version | Used for |
|-------|---------|---------|
| `aho-corasick` | 1 | The `AhoCorasick` automaton used by `signatures::matcher()`. |
| `percent-encoding` | 2 | `percent_decode` used by `signatures::url_decoded`. |

Recorded in `hakam-node/Cargo.toml` under the always-on dependency block (not gated behind the `linux` feature), so the lib + tests can use them on any host.

---

## 8. What is NOT in this commit

These are deliberate non-goals — listed so they're not surprises later.

- **B2 — tracepoint scope** (Session 2, `core_hardening.md`). 15 minutes of work, easy bonus before Phase 2 starts.
- **eBPF conntrack** — that's Phase 2 #7. The `FlowState` struct is laid out so the conntrack work plugs in without rewriting reassembly.
- **TCP sequence-number aware reassembly** — depends on Phase 2 #7.
- **AF_XDP / zero-copy data path**, **CO-RE / BTF portability**, **TLS SNI extraction**, **per-rule action tiers**, **YAML hot-reload**, **Prometheus `/metrics`** — all in `post_arsenal_roadmap.md` §2.
- **`docs/architecture.md`, `docs/codebase.md`, `docs/runtime_flow.md`** — these contain references to the old single-segment, no-URL-decode pipeline. They are NOT updated in this commit. Worth a docs-sweep pass before submission.

---

## 9. Suggested next steps, in order

1. **Validate on Linux** (1 hour). Run the verification commands in §6.2. If verifier complains, fix the bounds check.
2. **Ship B2** (15 minutes). Tracepoint scope from `core_hardening.md`.
3. **Docs sweep** (2 hours). Update `architecture.md`, `codebase.md`, `runtime_flow.md` for the new pipeline.
4. **Start Phase 2 prep** (write Q&A answers from `arsenal_roadmap.md` §Phase 2). Don't write code yet — Phase 2 nominally starts 2026-06-11, you're 11 days early.

When you're ready to start Phase 2, the next items are the headline features:

- **#6 BPF-LSM `socket_connect` enforcement** (7 d)
- **#7 Tight-scope eBPF conntrack** (10 d) — the `FlowState` extension hook lives in `hakam-node/src/reassembly.rs::FlowState`.
- **#8 Per-process attribution in BLOCK events** (4 d)

---

## 10. Glossary of files touched

| Path | Type | Status after this commit |
|------|------|-------------------------|
| `Cargo.lock` | Lockfile | Modified (auto) |
| `README.md` | Public docs | Modified (limitations rewritten) |
| `docs/arsenal_roadmap.md` | Plan | New (tracked); tracker updated |
| `docs/core_hardening.md` | Plan | Modified (B1/B3/B4 marked done) |
| `docs/evasion.md` | Public docs | Modified (score 15/15; rows + recap + Q&A refreshed) |
| `docs/phase1_implementation_log.md` | This file | New |
| `docs/post_arsenal_roadmap.md` | Plan | New (tracked) |
| `hakam-common/src/lib.rs` | Shared types | Modified (PayloadEvent + layout test) |
| `hakam-ebpf/src/xdp.rs` | Kernel BPF | Modified (sample_payload populates 4-tuple) |
| `hakam-node/Cargo.toml` | Manifest | Modified (+2 deps) |
| `hakam-node/src/dpi.rs` | Binary | Modified (Reassembler + match_payload integration) |
| `hakam-node/src/lib.rs` | Library | New |
| `hakam-node/src/main.rs` | Binary | Modified (-1 module decl) |
| `hakam-node/src/reassembly.rs` | Library | New |
| `hakam-node/src/signatures.rs` | Library | Modified (matcher + match_payload + url_decoded + tests) |
| `hakam-node/tests/dpi_matcher.rs` | Integration tests | New (25 tests) |
| `hakam-node/tests/reassembly.rs` | Integration tests | New (4 tests) |
