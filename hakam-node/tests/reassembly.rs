//! End-to-end tests for the reassembler + matcher pipeline.
//!
//! These exercise the exact code path the live `payload_task` runs through
//! for split-segment attacks — buffer two halves of a payload, then run the
//! matcher against the reassembled view. Every segment here is in-order, so it
//! carries `FLOW_IN_ORDER`; the dedupe/gap behaviour is unit-tested in
//! `src/reassembly.rs`.

use hakam_common::{FLOW_IN_ORDER, FLOW_RETRANSMIT};
use hakam_node::reassembly::{FlowKey, Reassembler};
use hakam_node::signatures::match_payload;

fn key(src_port: u16) -> FlowKey {
    FlowKey {
        src_addr: 0x0a630101, // 10.99.1.1
        dst_addr: 0x0a63000a, // 10.99.0.10
        src_port,
        dst_port: 0x5000, // 80 in network byte order (don't care here)
    }
}

#[test]
fn split_union_select_caught_after_segment_two() {
    let mut r = Reassembler::with_defaults();
    let k = key(40000);

    // Segment 1: HTTP method present, attack starts but doesn't complete.
    let v1: Vec<u8> = r.ingest(k, b"GET /?q=UNI", 0, FLOW_IN_ORDER, 100).unwrap().to_vec();
    assert!(
        match_payload(&v1).is_none(),
        "first segment alone must not match — that's the evasion we're closing",
    );

    // Segment 2 lands; reassembled view now contains the full UNION SELECT.
    let v2: Vec<u8> = r.ingest(k, b"ON SELECT 1 HTTP/1.1", 11, FLOW_IN_ORDER, 200).unwrap().to_vec();
    let sig = match_payload(&v2).expect("reassembled buffer must match SQLi");
    assert_eq!(sig.category, "SQLi");
}

#[test]
fn split_across_three_segments() {
    let mut r = Reassembler::with_defaults();
    let k = key(40001);

    let _ = r.ingest(k, b"GET /?q=", 0, FLOW_IN_ORDER, 0);
    let _ = r.ingest(k, b"UN", 8, FLOW_IN_ORDER, 0);
    let v: Vec<u8> = r.ingest(k, b"ION SELECT 1 HTTP/1.1", 10, FLOW_IN_ORDER, 0).unwrap().to_vec();
    let sig = match_payload(&v).expect("three-segment reassembly must match");
    assert_eq!(sig.category, "SQLi");
}

#[test]
fn reordered_split_still_matches() {
    // The classic evasion: send the second half of the attack first, the first
    // half second. The kernel mislabels the late earlier segment as a
    // retransmit (it sits behind the expected sequence), but userspace orders
    // by sequence number and recovers the intact payload.
    let mut r = Reassembler::with_defaults();
    let k = key(40010);

    let _ = r.ingest(k, b"ON SELECT 1 HTTP/1.1", 11, FLOW_IN_ORDER, 0);
    let v: Vec<u8> = r
        .ingest(k, b"GET /?q=UNI", 0, FLOW_RETRANSMIT, 0)
        .unwrap()
        .to_vec();
    let sig = match_payload(&v).expect("reordered reassembly must match SQLi");
    assert_eq!(sig.category, "SQLi");
}

#[test]
fn parallel_flows_match_independently() {
    let mut r = Reassembler::with_defaults();
    let k_attacker = key(40002);
    let k_benign = key(40003);

    let _ = r.ingest(k_attacker, b"GET /?q=UNI", 0, FLOW_IN_ORDER, 0);
    let benign_view: Vec<u8> = r
        .ingest(k_benign, b"GET /index.html HTTP/1.1\r\n", 0, FLOW_IN_ORDER, 0)
        .unwrap()
        .to_vec();
    let attacker_view: Vec<u8> = r
        .ingest(k_attacker, b"ON SELECT 1 HTTP/1.1", 11, FLOW_IN_ORDER, 0)
        .unwrap()
        .to_vec();

    assert!(
        match_payload(&benign_view).is_none(),
        "benign flow must not match",
    );
    assert_eq!(
        match_payload(&attacker_view).map(|s| s.category),
        Some("SQLi"),
        "attacker flow must match independently",
    );
}

#[test]
fn forget_after_match_lets_same_flow_be_reinspected() {
    // Real HTTP keep-alive pipelines several requests on one connection.
    // After we block the first attack we shouldn't poison the flow forever —
    // the next request on the same 4-tuple must get a fresh buffer.
    let mut r = Reassembler::with_defaults();
    let k = key(40004);

    let v1: Vec<u8> = r
        .ingest(k, b"GET /?q=UNION SELECT 1 HTTP/1.1", 0, FLOW_IN_ORDER, 0)
        .unwrap()
        .to_vec();
    assert!(match_payload(&v1).is_some());
    r.forget(&k);

    let v2: Vec<u8> = r
        .ingest(k, b"GET /benign HTTP/1.1\r\n", 0, FLOW_IN_ORDER, 0)
        .unwrap()
        .to_vec();
    assert!(
        match_payload(&v2).is_none(),
        "after forget, the next request must match against only its own bytes",
    );
}
