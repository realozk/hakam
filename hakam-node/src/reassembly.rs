//! Per-flow TCP segment buffering.
//!
//! The eBPF program samples the first `PAYLOAD_LEN` bytes of every TCP
//! segment and ships them up the ring buffer. Each sample on its own is a
//! one-shot window — an attacker who splits `UNION SELECT` across two
//! segments evades every signature.
//!
//! The `Reassembler` here closes that gap in userspace. Samples from the
//! same 4-tuple get concatenated into a per-flow buffer; the matcher runs
//! against the accumulated view.
//!
//! What this does with the kernel's conntrack data:
//!   * Sequence-ordered reassembly. Every sampled segment carries its TCP
//!     sequence number (stamped by the kernel). We keep each flow's segments in
//!     a map keyed by sequence and build the matched view in sequence order, so
//!     segments that arrive out of order — including the classic "send the
//!     second half first" evasion — are reassembled correctly. This supersedes
//!     the kernel's coarse in-order/retransmit/gap flag for *byte placement*:
//!     the flag can't tell a late-arriving earlier segment from a true
//!     retransmit (both sit behind the expected sequence), but the sequence
//!     number can.
//!   * Retransmit dedupe. A segment whose sequence we already hold is a
//!     duplicate and is dropped (sampled payloads are a fixed width, so an
//!     identical sequence means identical bytes).
//!   * Gap awareness. The kernel's `FLOW_GAP` flag feeds an out-of-order
//!     counter for stats; byte placement is sequence-driven regardless.
//!
//! What we deliberately do NOT do:
//!   * No TCP state machine. We do not track SYN/ACK/FIN — any TCP segment
//!     with a payload is considered an opportunity to match.
//!   * No sequence-wraparound handling. Segments are ordered by raw u32
//!     sequence; a flow whose window straddles the 2^32 wrap would order
//!     once-scrambled. Documented rather than handled: it requires the wrap to
//!     land inside a single flow's ≤256-byte buffer window.

use std::collections::{BTreeMap, HashMap};

use hakam_common::{PayloadEvent, FLOW_GAP};

/// 4-tuple identifying a TCP flow. All fields hold the on-wire bytes as
/// loaded from the packet headers — no host-order conversion. Two events
/// from the same flow always produce the same `FlowKey`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

impl FlowKey {
    pub fn from_event(event: &PayloadEvent) -> Self {
        Self {
            src_addr: event.src_addr,
            dst_addr: event.dst_addr,
            src_port: event.src_port,
            dst_port: event.dst_port,
        }
    }
}

/// Per-flow segment store plus housekeeping.
///
/// `frags` holds each sampled segment's bytes keyed by its TCP sequence number;
/// `view` is those fragments concatenated in sequence order (rebuilt on every
/// ingest and handed to the matcher). `buffered` is the summed fragment length,
/// capped at `max_buf`. `max_seq` is the highest sequence seen, used to detect
/// out-of-order arrivals. `last_seen_ns` drives TTL eviction.
struct FlowState {
    frags: BTreeMap<u32, Vec<u8>>,
    view: Vec<u8>,
    buffered: usize,
    max_seq: Option<u32>,
    last_seen_ns: u64,
}

// Wrapping signed sequence comparisons (TCP sequence space is mod 2^32).
#[inline]
fn seq_gt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

/// Default cap on bytes buffered per flow. Four PAYLOAD_LEN segments is
/// enough to defeat the common "split across two segments" evasion while
/// keeping the worst-case memory at `max_flows * MAX_FLOW_BUF` bytes.
pub const DEFAULT_MAX_FLOW_BUF: usize = hakam_common::PAYLOAD_LEN * 4;

/// Default TTL: 30s of silence and we drop the flow.
pub const DEFAULT_FLOW_TTL_NS: u64 = 30 * 1_000_000_000;

/// Default cap on concurrent flows. At max we refuse new flows rather than
/// evict — premature eviction would defeat reassembly for the freshest
/// attackers. The GC sweeps TTL'd flows to make room.
pub const DEFAULT_MAX_FLOWS: usize = 4096;

pub struct Reassembler {
    flows: HashMap<FlowKey, FlowState>,
    max_buf: usize,
    ttl_ns: u64,
    max_flows: usize,
    dropped_full_buf: u64,
    dropped_at_cap: u64,
    dropped_retransmit: u64,
    out_of_order_seen: u64,
}

impl Reassembler {
    pub fn new(max_buf: usize, ttl_ns: u64, max_flows: usize) -> Self {
        Self {
            flows: HashMap::new(),
            max_buf,
            ttl_ns,
            max_flows,
            dropped_full_buf: 0,
            dropped_at_cap: 0,
            dropped_retransmit: 0,
            out_of_order_seen: 0,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_MAX_FLOW_BUF, DEFAULT_FLOW_TTL_NS, DEFAULT_MAX_FLOWS)
    }

    /// Store `payload` for the flow at sequence `seq` (creating the flow if
    /// absent) and return the sequence-ordered reassembled view to feed the
    /// matcher. `flags` is the kernel's classification, used only for the
    /// out-of-order stat — byte placement is driven entirely by `seq`.
    ///
    /// Returns `None` only if the flow could not be created (flow table at cap).
    /// A duplicate or a buffer-full flow returns the existing view unchanged;
    /// the hot path treats `None` the same as "no match this segment".
    pub fn ingest(
        &mut self,
        key: FlowKey,
        payload: &[u8],
        seq: u32,
        flags: u8,
        now_ns: u64,
    ) -> Option<&[u8]> {
        if !self.flows.contains_key(&key) {
            if self.flows.len() >= self.max_flows {
                self.dropped_at_cap += 1;
                return None;
            }
            self.flows.insert(key, FlowState {
                frags: BTreeMap::new(),
                view: Vec::new(),
                buffered: 0,
                max_seq: None,
                last_seen_ns: now_ns,
            });
        }

        // Duplicate: we already hold a fragment at this sequence. Sampled
        // payloads are a fixed width, so an identical sequence means identical
        // bytes — drop it. (Counters are bumped here, before the &mut borrow.)
        if self.flows.get(&key).is_some_and(|s| s.frags.contains_key(&seq)) {
            self.dropped_retransmit += 1;
            return self.flows.get(&key).map(|s| s.view.as_slice());
        }

        // Kernel says this landed ahead of its expected sequence — a stats hint.
        if flags == FLOW_GAP {
            self.out_of_order_seen += 1;
        }

        let buffered = self.flows.get(&key).map_or(0, |s| s.buffered);
        let room = self.max_buf.saturating_sub(buffered);
        if room == 0 {
            self.dropped_full_buf += 1;
            return self.flows.get(&key).map(|s| s.view.as_slice());
        }
        let take = payload.len().min(room);

        let state = self.flows.get_mut(&key).expect("just inserted/exists");
        state.last_seen_ns = now_ns;
        state.frags.insert(seq, payload[..take].to_vec());
        state.buffered += take;
        state.max_seq = Some(match state.max_seq {
            Some(m) if seq_gt(m, seq) => m,
            _ => seq,
        });
        // Rebuild the matched view in sequence order. `buffered` ≤ max_buf (256
        // by default), so this concatenation is trivially cheap.
        state.view.clear();
        for frag in state.frags.values() {
            state.view.extend_from_slice(frag);
        }
        Some(&state.view)
    }

    /// Drop the flow's buffered state. Call after a match fires so the same
    /// flow doesn't keep re-matching on every subsequent segment.
    pub fn forget(&mut self, key: &FlowKey) {
        self.flows.remove(key);
    }

    /// Evict flows whose `last_seen_ns` is older than `ttl_ns`.
    pub fn gc(&mut self, now_ns: u64) -> usize {
        let before = self.flows.len();
        self.flows
            .retain(|_, state| now_ns.saturating_sub(state.last_seen_ns) < self.ttl_ns);
        before - self.flows.len()
    }

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    pub fn dropped_full_buf(&self) -> u64 {
        self.dropped_full_buf
    }

    pub fn dropped_at_cap(&self) -> u64 {
        self.dropped_at_cap
    }

    pub fn dropped_retransmit(&self) -> u64 {
        self.dropped_retransmit
    }

    pub fn out_of_order_seen(&self) -> u64 {
        self.out_of_order_seen
    }
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hakam_common::{FLOW_IN_ORDER, FLOW_RETRANSMIT};

    fn k(src_port: u16) -> FlowKey {
        FlowKey {
            src_addr: 0x0a000001,
            dst_addr: 0x0a000002,
            src_port,
            dst_port: 80,
        }
    }

    #[test]
    fn single_segment_is_returned_intact() {
        let mut r = Reassembler::with_defaults();
        let view = r.ingest(k(40000), b"hello", 0, FLOW_IN_ORDER, 0).unwrap();
        assert_eq!(view, b"hello");
    }

    #[test]
    fn two_segments_concatenate() {
        let mut r = Reassembler::with_defaults();
        let _ = r.ingest(k(40000), b"GET /?x=UNI", 0, FLOW_IN_ORDER, 100);
        let view = r.ingest(k(40000), b"ON SELECT 1 HTTP/1.1", 11, FLOW_IN_ORDER, 200).unwrap();
        assert!(
            std::str::from_utf8(view).unwrap().contains("UNION SELECT"),
            "expected reassembled view to contain UNION SELECT, got: {:?}",
            std::str::from_utf8(view).unwrap(),
        );
    }

    #[test]
    fn distinct_flows_dont_bleed() {
        let mut r = Reassembler::with_defaults();
        let _ = r.ingest(k(40000), b"AAAA", 0, FLOW_IN_ORDER, 0);
        let _ = r.ingest(k(40001), b"BBBB", 0, FLOW_IN_ORDER, 0);
        let view_a: Vec<u8> = r.ingest(k(40000), b"AAAA", 4, FLOW_IN_ORDER, 0).unwrap().to_vec();
        let view_b: Vec<u8> = r.ingest(k(40001), b"BBBB", 4, FLOW_IN_ORDER, 0).unwrap().to_vec();
        assert_eq!(view_a, b"AAAAAAAA");
        assert_eq!(view_b, b"BBBBBBBB");
    }

    #[test]
    fn forget_drops_state() {
        let mut r = Reassembler::with_defaults();
        let _ = r.ingest(k(40000), b"xxx", 0, FLOW_IN_ORDER, 0);
        assert_eq!(r.flow_count(), 1);
        r.forget(&k(40000));
        assert_eq!(r.flow_count(), 0);
    }

    #[test]
    fn gc_evicts_stale_flows() {
        // 1s TTL. Old flow at t=0, fresh flow at t=1.5s, gc at t=2s.
        // Old: age 2s ≥ 1s → evicted. Fresh: age 0.5s < 1s → kept.
        let mut r = Reassembler::new(64, 1_000_000_000, 16);
        let _ = r.ingest(k(40000), b"old", 0, FLOW_IN_ORDER, 0);
        let _ = r.ingest(k(40001), b"new", 0, FLOW_IN_ORDER, 1_500_000_000);
        let evicted = r.gc(2_000_000_000);
        assert_eq!(evicted, 1, "stale flow should have been evicted");
        assert_eq!(r.flow_count(), 1);
    }

    #[test]
    fn buffer_cap_clamps_growth() {
        let mut r = Reassembler::new(8, DEFAULT_FLOW_TTL_NS, 16);
        let _ = r.ingest(k(40000), b"AAAAAAAA", 0, FLOW_IN_ORDER, 0); // exactly at cap
        let view = r.ingest(k(40000), b"BBBB", 8, FLOW_IN_ORDER, 0).unwrap();
        assert_eq!(view.len(), 8, "buffer must not grow past the cap");
        assert_eq!(view, b"AAAAAAAA");
        assert_eq!(r.dropped_full_buf(), 1);
    }

    #[test]
    fn flow_cap_refuses_new_flows() {
        let mut r = Reassembler::new(64, DEFAULT_FLOW_TTL_NS, 2);
        let _ = r.ingest(k(40000), b"a", 0, FLOW_IN_ORDER, 0);
        let _ = r.ingest(k(40001), b"b", 0, FLOW_IN_ORDER, 0);
        let result = r.ingest(k(40002), b"c", 0, FLOW_IN_ORDER, 0);
        assert!(result.is_none(), "third flow must be refused at cap");
        assert_eq!(r.dropped_at_cap(), 1);
    }

    #[test]
    fn retransmit_is_dropped() {
        let mut r = Reassembler::with_defaults();
        let _ = r.ingest(k(40000), b"AAAA", 0, FLOW_IN_ORDER, 0);
        // Same bytes re-presented as a kernel-flagged retransmit: buffer unchanged.
        let view = r.ingest(k(40000), b"AAAA", 0, FLOW_RETRANSMIT, 1).unwrap();
        assert_eq!(view, b"AAAA", "retransmit must not be appended");
        assert_eq!(r.dropped_retransmit(), 1);
    }

    #[test]
    fn gap_segment_is_counted_and_placed_by_seq() {
        let mut r = Reassembler::with_defaults();
        let _ = r.ingest(k(40000), b"GET ", 0, FLOW_IN_ORDER, 0);
        // Kernel-flagged gap: counted as out-of-order; placed by sequence.
        let view = r.ingest(k(40000), b"/x", 100, FLOW_GAP, 1).unwrap();
        assert_eq!(view, b"GET /x");
        assert_eq!(r.out_of_order_seen(), 1);
    }

    #[test]
    fn out_of_order_segments_reassemble_in_seq_order() {
        let mut r = Reassembler::with_defaults();
        // The second half (seq 11) arrives before the first half (seq 0). The
        // kernel, seeing the later-but-lower segment, mislabels it RETRANSMIT —
        // sequence ordering must still place it first and recover the attack.
        let _ = r.ingest(k(40000), b"ON SELECT 1 HTTP/1.1", 11, FLOW_IN_ORDER, 0);
        let view = r.ingest(k(40000), b"GET /?x=UNI", 0, FLOW_RETRANSMIT, 1).unwrap();
        assert!(
            std::str::from_utf8(view).unwrap().contains("UNION SELECT"),
            "reordered view must contain UNION SELECT, got: {:?}",
            std::str::from_utf8(view).unwrap(),
        );
    }
}
