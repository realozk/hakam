# Phase 2 #7 — Tight-scope eBPF conntrack · implementation plan

> Roadmap item: *"Tight-scope eBPF conntrack — flow table keyed on 4-tuple,
> holds `seq_next` + `dir` + `last_ts`. No TCP state machine."* Budget: **10 d**.
> Status as of 2026-06-29: **not started** (#6 and #8 done). This is the last
> Phase 2 headline feature and the biggest verifier risk in the plan.

## 1 · What this buys us (and the exit criteria it must hit)

From the roadmap, #7 must deliver:

1. **A kernel flow table** keyed on the 4-tuple, holding `seq_next`, `dir`,
   `last_ts`. → *the defensible-novelty centerpiece: "per-flow conntrack ties
   XDP and LSM together."*
2. **Seq-aware reassembly** — userspace orders/dedupes segments by TCP sequence
   instead of arrival order. → closes the two documented gaps in
   `reassembly.rs`: out-of-order delivery and retransmit buffer waste.
3. **Per-flow visibility/limits** — flow-granular state instead of per-IP only.
4. **`stats` shows N active flows** held in the conntrack table.
5. **Foundation for microsegmentation** — the flow key + dir is what any future
   east-west policy would gate on.

Exit-criteria line from Phase 2: *"Conntrack table holds N active flows visible
in `stats`."* That's the concrete acceptance gate.

## 2 · What exists today (the seams we build on)

| Piece | File | Today |
|---|---|---|
| XDP fast path | `hakam-ebpf/src/xdp.rs` | reads 4-tuple + 64 B payload; **does not read TCP seq**; rate-limits **per-IP** via `PACKET_COUNTER`/`LAST_SEEN` (per-CPU LRU keyed on `src_addr`) |
| Ring event | `hakam-common/src/lib.rs` `PayloadEvent` | `src/dst addr+port`, `payload_len`, `payload[64]`. **No seq field.** |
| Reassembler | `hakam-node/src/reassembly.rs` | per-flow `HashMap<FlowKey, FlowState{buf,last_seen_ns}>`, **appends in arrival order**, no seq/dir/dedupe. Comment already reserves `seq_next`/`dir` for #7. |
| Map idiom | `main.rs` | `LruPerCpuHashMap` already used — kernel auto-evicts oldest on cap. The eviction-policy Q&A answer is already "LRU". |

The seams are clean: XDP already computes the 4-tuple and ships an event per
TCP segment. We add a seq read, a kernel flow map, and a `seq` field on the
event. Userspace reassembly grows seq ordering. Nothing gets rewritten.

## 3 · Design

### 3.1 Kernel flow table

```rust
// hakam-common (shared, #[repr(C)], POD — used as BPF map key/value)
#[repr(C)] #[derive(Clone, Copy)]
pub struct FlowKey {            // 12 bytes, on-wire byte order (no host conv)
    pub src_addr: u32,
    pub dst_addr: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

#[repr(C)] #[derive(Clone, Copy)]
pub struct FlowState {          // small, linear-write POD
    pub seq_next:  u32,         // next expected seq = last seq + payload_len
    pub last_ts:   u64,         // bpf_ktime_get_ns of most recent segment
    pub packets:   u32,         // per-flow counter (rate-limit / stats)
    pub dir:       u8,          // 0 = initiator→responder (first seen), 1 = reverse
    pub _pad:      [u8; 3],
}
```

```rust
// hakam-ebpf/src/main.rs
#[map]
pub static CONNTRACK: LruHashMap<FlowKey, FlowState> =
    LruHashMap::with_max_entries(65_536, 0);
```

**Map type = `LruHashMap` (BPF_MAP_TYPE_LRU_HASH).** This is the deliberate
answer to the *"1M flows = 1M entries, what's the eviction policy"* Q&A: the
kernel evicts the least-recently-used flow on capacity pressure, so the table is
self-bounding. 65 536 entries is generous for a demo box and keeps worst-case
memory modest (~`65536 * (12+24)` ≈ 2.3 MB).

### 3.2 XDP changes (`xdp.rs`)

In `sample_payload`, after reading ports and data-offset, also:
- read **TCP seq** (`u32` at `tcp_hdr_start + 4`),
- compute **on-wire payload length** from the IP total-length field
  (`ip.total_len - ip_hdr_len - tcp_hdr_len`), not the capped 64-byte view.

Then a new `conntrack::observe(key, seq, wire_len, now)` that:
- **first sight** → insert `FlowState{ seq_next: seq+wire_len, last_ts: now, packets: 1, dir: 0 }`.
- **seen before** → update `last_ts`, `packets += 1`; classify the segment:
  - `seq + wire_len <= seq_next` → **retransmit/duplicate**
  - `seq == seq_next` → **in-order** (advance `seq_next`)
  - `seq > seq_next` → **gap / out-of-order**
- write the classification into a new `flags: u8` on `PayloadEvent` so userspace
  knows without re-deriving.

This stays verifier-linear: one map lookup, a handful of field compares/writes,
no loops, no unbounded memory.

### 3.3 Wire event change (`PayloadEvent`)

Add two fields (bump the layout test):
```rust
pub seq:   u32,   // TCP sequence of this segment (on-wire)
pub flags: u8,    // 0=in-order, 1=retransmit, 2=gap   (+ _pad)
```

### 3.4 Userspace reassembly changes (`reassembly.rs`)

`FlowState` grows `seq_next: Option<u32>`. `ingest` gains a `seq`/`flags` arg:
- **retransmit** (`flags==1` or `seq+len <= seq_next`) → drop, bump a
  `dropped_retransmit` counter. *Closes the "retransmit eats buffer" gap.*
- **in-order** → append, advance `seq_next`. (today's behaviour, now provably
  in-order.)
- **gap / out-of-order** → **minimum viable**: hold in a small per-flow
  `BTreeMap<seq, Vec<u8>>` pending-buffer; splice contiguous runs into `buf`
  when the gap fills. *Closes the "out-of-order breaks split signature" gap.*
  **Cut line if it runs long:** skip the pending-buffer, append anyway and just
  record `out_of_order_seen` — we still ship in-order + dedupe, which is the
  bulk of the win, and document the residual in `docs/evasion.md`.

### 3.5 `stats` surface

Add to the `stats` command / METRICS: `active_flows` (CONNTRACK entry count via
map iteration — periodic, not per-packet), plus `dropped_retransmit` and
`out_of_order_seen` from the reassembler. `active_flows` is the literal exit
criterion.

## 4 · Verifier-safety strategy and the degrade ladder

The risk register's mitigation is the spec, not a fallback to improvise. Build
in this order and stop at the first rung that lands cleanly:

1. **Full**: `FlowState{ seq_next, last_ts, packets, dir }` + in-XDP seq
   classification + userspace pending-buffer reordering.
2. **If the verifier balks at seq math in XDP**: drop the in-XDP classification —
   XDP only stamps `seq` onto the event and bumps `last_ts`/`packets`. **All**
   seq logic (dedupe + ordering) moves to userspace, which has no verifier.
   Kernel `FlowState` keeps just `last_ts + dir + packets`.
3. **If the flow struct itself trips complexity limits**: shrink `FlowState` to
   `{ last_ts, packets }`, drop `dir`. The flow table still exists (satisfies
   "N active flows in stats" + per-flow counters); reassembly is fully
   userspace from `PayloadEvent.seq`.

Every rung still ships a working demo and an honest story. Rung 2 is the most
likely landing spot and is completely fine — the kernel owns the flow identity
and counters; userspace owns the byte ordering.

## 5 · Per-flow rate limiting — decision, not default-swap

The roadmap says *"per-flow rate limit instead of per-IP."* **Recommendation:
do not replace the working per-IP limiter — add per-flow on top.** Rationale:

- Per-flow-only rate limiting is *weaker* against the obvious attack: one source
  opening many short flows, each staying under the per-flow budget. The per-IP
  limiter is what actually stops a flood and it already works.
- Regressing a working DoS guard to chase a roadmap phrasing is the wrong trade
  three weeks from feature freeze.

So: keep per-IP enforcement; use the new per-flow `packets` counter for
**visibility** (`stats`) and an *optional* per-flow cap behind a flag. State
this explicitly in the Q&A prep — it's a stronger, more honest answer than
"we replaced it."

## 6 · Tightening #8 attribution (stretch — likely follow-on, not core #7)

#8 correlates BLOCK→PID by **dst-keyed, most-recent-wins** because the
`sys_enter_connect` tracepoint fires *before* the kernel assigns the ephemeral
source port — `ConnectEvent` has no `src_port`. The conntrack table sees the
real 4-tuple (from XDP packets), but bridging the PID (dst-only) to the flow
(full 4-tuple) needs a second correlation step. **Treat as a stretch goal**: if
rungs 1–3 land with time to spare, add dst+pid → flow correlation so a BLOCK can
name the exact source port. If not, #8's current dst-keyed attribution stands
and is already a strong demo moment. Do **not** let this expand #7's scope.

## 7 · Implementation sequence (10-day budget)

| Day | Step | Gate |
|--:|------|------|
| 1 | `FlowKey`/`FlowState` in `hakam-common`; `CONNTRACK` LruHashMap; layout tests | `cargo test` layout |
| 2 | XDP reads seq + wire payload len; `conntrack::observe` insert/update | eBPF verifier loads (`cargo xtask build-ebpf` + attach) |
| 3 | In-XDP seq classification → `PayloadEvent.seq`/`flags`; bump layout test | verifier still loads; **if not → degrade rung 2** |
| 4–5 | Userspace `ingest(seq, flags)`: retransmit dedupe + in-order advance; counters | unit tests: dedupe, in-order, gap |
| 6–7 | Out-of-order pending-buffer (§3.4); splice on gap-fill | unit tests: split signature delivered reversed still matches; **cut line if slipping** |
| 8 | `stats`/METRICS: `active_flows`, `dropped_retransmit`, `out_of_order_seen` | exit criterion visible in CLI + HUD |
| 9 | VM validation: real split/reordered/retransmit traffic; map-fill behaviour under load | end-to-end on hakam VM |
| 10 | Docs: `architecture.md` §4 conntrack note, `evasion.md` residuals, roadmap tracker → ✅; Q&A prep update (eviction, per-flow decision) | clean tree, tracker flipped |

## 8 · Tests to add

- **`hakam-common`**: `FlowKey`/`FlowState`/new `PayloadEvent` layout + size/align.
- **`reassembly.rs` units**: retransmit dropped; in-order append; two segments
  delivered out-of-order still produce a buffer the matcher hits; cap/TTL
  unaffected.
- **eBPF**: verifier-load gate in CI (already planned as Phase 3 #13) covers the
  conntrack program.
- **VM e2e**: `scripts/` probe that splits `UNION SELECT` across reordered
  segments and asserts a BLOCK — the reviewer-facing proof.

## 9 · Risks specific to #7

| Risk | Mitigation |
|---|---|
| Verifier rejects per-flow struct / seq math | The §4 degrade ladder — pre-decided, not improvised. Rung 2 is fine. |
| Out-of-order reordering eats >2 days | §3.4 cut line: ship in-order + dedupe only, document residual. |
| LRU evicts a hot flow mid-reassembly | 65 536 entries is far above demo concurrency; userspace reassembler has its own TTL and is the authoritative buffer regardless. |
| Scope creep into #8 src-port tightening | §6 — explicitly a stretch/follow-on, hard-fenced. |
| Per-IP regression from "per-flow rate limit" | §5 — keep per-IP, add per-flow as visibility/optional. |

## 10 · Definition of done

- `CONNTRACK` LruHashMap loads in the verifier and populates from XDP.
- `stats` / HUD shows `active_flows`.
- A signature split across **out-of-order** segments is caught (or, at the cut
  line, in-order + retransmit-dedupe is caught and the residual is documented).
- Per-IP rate limiting unchanged; per-flow counter visible.
- `architecture.md`, `evasion.md`, roadmap tracker, and Q&A prep updated.
- Validated end-to-end on the hakam VM.
