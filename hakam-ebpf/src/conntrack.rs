//! Tight-scope connection tracking in the kernel.
//!
//! Per-flow state keyed on the 4-tuple, updated from the XDP fast path. There is
//! **no TCP state machine**: any TCP segment carrying a payload updates the flow.
//! The table is an LRU hash, so a flood of unique flows evicts the coldest
//! entries rather than failing inserts or growing without bound.
//!
//! Verifier discipline: `observe` does exactly one map lookup, then a handful of
//! field writes — no loops, no unbounded memory. Keep this function linear. If
//! it ever trips the verifier's complexity limit, the degrade path in
//! `docs/dev/phase2_7_conntrack_plan.md` §4 moves the sequence logic to
//! userspace and shrinks `FlowState`.

use aya_ebpf::helpers::bpf_ktime_get_ns;
use hakam_common::{FlowKey, FlowState, FLOW_GAP, FLOW_IN_ORDER, FLOW_RETRANSMIT};

use crate::CONNTRACK;

/// Record one TCP segment against its flow and classify it.
///
/// `seq` and `wire_len` are **host order** (the caller converts `seq` from the
/// on-wire big-endian value and derives `wire_len` from the IP/TCP header
/// lengths). Returns the segment's classification (`FLOW_*`) relative to the
/// flow's expected next sequence, computed *before* this segment advances it.
/// The caller stamps the returned flag onto the ring event so userspace — which
/// only sees sampled segments — gets the kernel's authoritative ordering view.
///
/// TCP sequence space is mod 2^32; comparisons use a wrapping subtraction cast
/// to `i32` so wraparound is handled correctly. No TCP state machine — first
/// sighting is in-order by definition.
#[inline(always)]
pub fn observe(key: &FlowKey, seq: u32, wire_len: u32) -> u8 {
    let now = unsafe { bpf_ktime_get_ns() };
    let new_end = seq.wrapping_add(wire_len);

    if let Some(st) = CONNTRACK.get_ptr_mut(key) {
        let prev = unsafe { (*st).seq_next };
        let flag = match seq.wrapping_sub(prev) as i32 {
            0 => FLOW_IN_ORDER,
            d if d < 0 => FLOW_RETRANSMIT, // seq is behind expected
            _ => FLOW_GAP,                 // seq is ahead — a hole precedes it
        };
        unsafe {
            (*st).last_ts = now;
            (*st).packets = (*st).packets.wrapping_add(1);
            // Only ever advance seq_next forward (to the furthest byte seen) —
            // a retransmit must not drag the expected pointer backward.
            if (new_end.wrapping_sub(prev) as i32) > 0 {
                (*st).seq_next = new_end;
            }
        }
        return flag;
    }

    let st = FlowState {
        last_ts: now,
        seq_next: new_end,
        packets: 1,
        dir: 0,
        _pad: [0; 7],
    };
    // Best-effort: a full table just means the LRU evicts something. A failed
    // insert is never allowed to disturb the packet's XDP verdict.
    let _ = CONNTRACK.insert(key, &st, 0);
    FLOW_IN_ORDER
}
