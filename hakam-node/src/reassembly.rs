//! Per-flow TCP segment buffering.
//!
//! The eBPF program samples the first `PAYLOAD_LEN` bytes of every TCP
//! segment and ships them up the ring buffer. Each sample on its own is a
//! one-shot window — an attacker who splits `UNION SELECT` across two
//! segments evades every signature.
//!
//! The `Reassembler` here closes that gap in userspace. Samples from the
//! same 4-tuple get concatenated into a per-flow buffer; the matcher runs
//! against the accumulated view. The state struct deliberately leaves room
//! for fields a future eBPF conntrack (Arsenal roadmap Phase 2 #7) will
//! populate — `seq_next` for retransmit dedupe and ordering, `dir` for
//! client→server vs server→client classification.
//!
//! What this does with Phase 2 #7 conntrack data:
//!   * Retransmit dedupe. The kernel flags a segment whose bytes it has already
//!     seen (`FLOW_RETRANSMIT`); we drop it instead of padding the buffer. We
//!     trust the kernel flag because the kernel sees every segment while we see
//!     only the sampled subset.
//!   * Gap awareness. A segment arriving ahead of the expected sequence
//!     (`FLOW_GAP`) is counted; the reorder step buffers it. Until then we still
//!     append it so no real attack bytes are ever dropped.
//!
//! What we deliberately do NOT do:
//!   * No TCP state machine. We do not track SYN/ACK/FIN — any TCP segment
//!     with a payload is considered an opportunity to match.

use std::collections::HashMap;

use hakam_common::{PayloadEvent, FLOW_GAP, FLOW_RETRANSMIT};

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

/// Per-flow buffered bytes plus housekeeping.
///
/// `last_seen_ns` is the boot-time nanosecond timestamp of the most recent
/// segment we ingested for this flow; the GC uses it for TTL eviction.
struct FlowState {
    buf: Vec<u8>,
    last_seen_ns: u64,
    /// Sequence end (host order) of the last segment we appended, or `None`
    /// until the first one establishes it. The reorder step uses this to know
    /// where the contiguous buffer ends; set on every appended segment.
    seq_next: Option<u32>,
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

    /// Append `payload` to the flow's buffer (creating the flow if absent)
    /// and return the buffer view to feed the matcher.
    ///
    /// Returns `None` if the flow could not be created (table at cap) or if
    /// the existing buffer is full and the segment is discarded. The hot
    /// path treats `None` the same as "no match this segment".
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
            self.flows.insert(
                key,
                FlowState {
                    buf: Vec::with_capacity(payload.len()),
                    last_seen_ns: now_ns,
                    seq_next: None,
                },
            );
        }

        // Retransmit: the kernel conntrack already accounted for these bytes
        // earlier in the flow. Drop the duplicate — appending it only pads the
        // buffer (substring matching doesn't need it) and burns the per-flow
        // cap. We trust the kernel flag: it tracks the full segment stream,
        // while userspace sees only sampled segments and couldn't decide this.
        if flags == FLOW_RETRANSMIT {
            self.dropped_retransmit += 1;
            return self.flows.get(&key).map(|s| s.buf.as_slice());
        }

        // Gap: a hole precedes this segment in sequence space. Until the reorder
        // step lands we still append (never drop real attack bytes) but count it
        // so the out-of-order rate is visible in stats.
        if flags == FLOW_GAP {
            self.out_of_order_seen += 1;
        }

        let state = self.flows.get_mut(&key).expect("just inserted/exists");
        state.last_seen_ns = now_ns;

        let room = self.max_buf.saturating_sub(state.buf.len());
        if room == 0 {
            self.dropped_full_buf += 1;
            return Some(&state.buf);
        }
        let take = payload.len().min(room);
        state.buf.extend_from_slice(&payload[..take]);
        state.seq_next = Some(seq.wrapping_add(payload.len() as u32));
        Some(&state.buf)
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
    use hakam_common::FLOW_IN_ORDER;

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
    fn gap_segment_is_counted_but_kept() {
        let mut r = Reassembler::with_defaults();
        let _ = r.ingest(k(40000), b"GET ", 0, FLOW_IN_ORDER, 0);
        // Ahead-of-expected segment: counted as out-of-order, still appended so
        // no real attack bytes are lost before the reorder step lands.
        let view = r.ingest(k(40000), b"/x", 100, FLOW_GAP, 1).unwrap();
        assert_eq!(view, b"GET /x", "gap bytes are still appended (no data loss)");
        assert_eq!(r.out_of_order_seen(), 1);
    }
}
