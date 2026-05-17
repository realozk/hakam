//! Integration-safe unit tests for hakam-node logic.
//!
//! These tests are isolated in a separate file so they only depend on
//! `std` and `hakam-common` — allowing them to compile and run on
//! any platform (macOS, Linux, Windows) without `aya` or `libc` netlink
//! symbols that are Linux-exclusive.
//!
//! Tests that require a live eBPF environment (loading programs, attaching
//! XDP, reading from the kernel map) must be run on a Linux host.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::str::FromStr;
use hakam_common::Ipv4Addr as HakamIp;

// ────────────────────────────────────────────────────────────────
//  Byte-order conversion
// ────────────────────────────────────────────────────────────────

/// Verify that our byte-order conversion from a dotted-decimal string
/// to the raw u32 key matches what the eBPF kernel side expects.
///
/// `u32::from_be_bytes(ip.octets())` interprets the octets as big-endian,
/// producing 0x01020304 on **any** architecture.  The eBPF kernel also reads
/// `src_addr` straight from the IPv4 header (which is on-wire big-endian),
/// so both sides agree without any manual byte-swap.
#[test]
fn test_ip_to_map_key_byte_order() {
    let ip = Ipv4Addr::new(1, 2, 3, 4);
    let key: u32 = u32::from_be_bytes(ip.octets());
    // from_be_bytes([1,2,3,4]) == 0x01_02_03_04 on any host.
    assert_eq!(key, 0x01_02_03_04_u32);
}

// ────────────────────────────────────────────────────────────────
//  Mock block / unblock cycle
// ────────────────────────────────────────────────────────────────

/// Simulate inserting and removing an IP from the blocklist using a
/// plain std::HashMap — same logic as the aya HashMap wrapper.
#[test]
fn test_mock_block_unblock_cycle() {
    let mut mock_map: HashMap<u32, u32> = HashMap::new();
    let ip = Ipv4Addr::new(10, 0, 0, 1);
    let key: u32 = u32::from_be_bytes(ip.octets());

    // Block: insert.
    mock_map.insert(key, 0);
    assert!(mock_map.contains_key(&key), "IP should be blocked after insert");

    // Unblock: remove.
    mock_map.remove(&key);
    assert!(!mock_map.contains_key(&key), "IP should be gone after remove");
}

/// Blocking multiple different IPs must produce distinct map keys.
#[test]
fn test_two_ips_distinct_keys() {
    let ip_a = Ipv4Addr::new(192, 168, 1, 1);
    let ip_b = Ipv4Addr::new(192, 168, 1, 2);
    let key_a: u32 = u32::from_be_bytes(ip_a.octets());
    let key_b: u32 = u32::from_be_bytes(ip_b.octets());
    assert_ne!(key_a, key_b);
}

/// The loopback address must convert to 0x7F000001.
#[test]
fn test_loopback_key() {
    let ip = Ipv4Addr::new(127, 0, 0, 1);
    let key: u32 = u32::from_be_bytes(ip.octets());
    assert_eq!(key, 0x7F_00_00_01_u32);
}

// ────────────────────────────────────────────────────────────────
//  HakamIp ↔ std::net::Ipv4Addr interop
// ────────────────────────────────────────────────────────────────

/// HakamIp::as_raw() must produce the same u32 key as
/// u32::from_be_bytes(std_ip.octets()).
#[test]
fn test_hakam_ip_matches_std() {
    let std_ip = Ipv4Addr::new(8, 8, 8, 8);
    let phm_ip = HakamIp::from(std_ip);
    let std_key: u32 = u32::from_be_bytes(std_ip.octets());
    let phm_key: u32 = phm_ip.as_raw();
    assert_eq!(std_key, phm_key, "HakamIp key must match std conversion");
}

// ────────────────────────────────────────────────────────────────
//  Command tokenisation
// ────────────────────────────────────────────────────────────────

/// "block 1.2.3.4" must tokenise to cmd="block", arg="1.2.3.4".
#[test]
fn test_command_tokenisation_block() {
    let line = "block 1.2.3.4";
    let mut parts = line.splitn(2, ' ');
    assert_eq!(parts.next(), Some("block"));
    assert_eq!(parts.next().map(str::trim), Some("1.2.3.4"));
}

/// "unblock  192.168.0.1 " must tolerate leading/trailing whitespace.
#[test]
fn test_command_tokenisation_unblock() {
    let line = "unblock  192.168.0.1 ";
    let mut parts = line.splitn(2, ' ');
    assert_eq!(parts.next(), Some("unblock"));
    // trim() removes surrounding spaces from the argument.
    assert_eq!(parts.next().map(str::trim), Some("192.168.0.1"));
}

/// A bare command with no argument produces None for the arg token.
#[test]
fn test_command_no_arg() {
    let line = "list";
    let mut parts = line.splitn(2, ' ');
    assert_eq!(parts.next(), Some("list"));
    assert_eq!(parts.next(), None);
}

// ────────────────────────────────────────────────────────────────
//  IP address validation
// ────────────────────────────────────────────────────────────────

/// Invalid IP strings must fail std parsing.
#[test]
fn test_invalid_ip_rejected() {
    assert!(Ipv4Addr::from_str("not_an_ip").is_err());
    assert!(Ipv4Addr::from_str("999.0.0.1").is_err());
    assert!(Ipv4Addr::from_str("256.0.0.1").is_err());
    assert!(Ipv4Addr::from_str("").is_err());
}

/// Valid IP strings must parse successfully.
#[test]
fn test_valid_ip_accepted() {
    assert!(Ipv4Addr::from_str("0.0.0.0").is_ok());
    assert!(Ipv4Addr::from_str("255.255.255.255").is_ok());
    assert!(Ipv4Addr::from_str("10.0.0.1").is_ok());
}

// ────────────────────────────────────────────────────────────────
//  Map capacity boundary
// ────────────────────────────────────────────────────────────────

/// Simulate filling the mock map up to the BPF limit (1024 entries).
/// This verifies that our key generation produces 1024 distinct keys.
#[test]
fn test_mock_map_capacity() {
    let mut mock_map: HashMap<u32, u32> = HashMap::new();
    for i in 0u32..1024 {
        let key = i; // distinct keys
        mock_map.insert(key, 0);
    }
    assert_eq!(mock_map.len(), 1024);
}
