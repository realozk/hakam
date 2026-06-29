//! Tight-scope eBPF conntrack (Arsenal roadmap Phase 2 #7).
//!
//! Per-flow state keyed on the 4-tuple, updated from the XDP fast path. There is
//! **no TCP state machine**: any TCP segment carrying a payload updates the flow.
//!
//! Verifier discipline: `observe` does exactly one map lookup, then a handful of
//! field writes — no loops, no unbounded memory. If this ever trips the
//! verifier's complexity limit, the degrade ladder in
//! `docs/phase2_7_conntrack_plan.md` §4 moves the seq logic to userspace and
//! shrinks `FlowState`. Keep this function linear.

use aya_ebpf::helpers::bpf_ktime_get_ns;
use hakam_common::{FlowKey, FlowState};

use crate::CONNTRACK;

/// Record one TCP segment against its flow.
///
/// `seq` and `wire_len` are **host order** (the caller converts `seq` from the
/// on-wire big-endian value and derives `wire_len` from the IP/TCP header
/// lengths). On a first sighting we insert; otherwise we advance `seq_next` and
/// bump the per-flow counter. This step only *populates* the table — classifying
/// a segment as in-order / retransmit / gap and stamping the ring event is the
/// next step (`seq-on-the-wire`).
#[inline(always)]
pub fn observe(key: &FlowKey, seq: u32, wire_len: u32) {
    let now = unsafe { bpf_ktime_get_ns() };

    if let Some(st) = unsafe { CONNTRACK.get_ptr_mut(key) } {
        unsafe {
            (*st).last_ts = now;
            (*st).packets = (*st).packets.wrapping_add(1);
            // Wrapping add: TCP sequence space is mod 2^32 by definition.
            (*st).seq_next = seq.wrapping_add(wire_len);
        }
        return;
    }

    let st = FlowState {
        last_ts: now,
        seq_next: seq.wrapping_add(wire_len),
        packets: 1,
        dir: 0,
        _pad: [0; 7],
    };
    // Best-effort: a full table just means the LRU evicts something. A failed
    // insert is never allowed to disturb the packet's XDP verdict.
    let _ = CONNTRACK.insert(key, &st, 0);
}
