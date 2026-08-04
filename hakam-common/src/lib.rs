//! Types shared between the kernel programs and the userspace controller.
//!
//! This crate is the wire contract across the kernel/userspace boundary: every
//! struct here is `#[repr(C)]` and read on one side exactly as it was written on
//! the other. It builds twice — `no_std` for `hakam-ebpf`, and with the `std`
//! feature for `hakam-node` — so nothing here may pull in `std` unconditionally.
//!
//! Two rules govern every struct below, and the layout tests at the bottom of
//! this file enforce them:
//!
//!   * **Byte order is explicit per field.** Most fields carry on-wire (network)
//!     byte order untouched, so kernel and userspace derive identical map keys
//!     with no conversion. `PayloadEvent::seq` is the deliberate exception — the
//!     kernel byte-swaps it so userspace can order segments arithmetically.
//!   * **No implicit padding.** Fields are ordered widest-first and padding is
//!     named explicitly. A BPF map key is hashed over its raw bytes, so an
//!     uninitialised padding hole would silently break lookups.

#![cfg_attr(not(feature = "std"), no_std)]

pub const PAYLOAD_LEN: usize = 64;

/// Conntrack segment classification, computed by the kernel — which sees
/// *every* TCP segment — and carried in `PayloadEvent.flags`.
/// Userspace trusts these rather than re-deriving from its own sequence state,
/// because it only ever sees the *sampled* subset of segments and so cannot
/// compute an authoritative `seq_next` itself.
pub const FLOW_IN_ORDER:   u8 = 0; // seq == flow's expected next sequence
pub const FLOW_RETRANSMIT: u8 = 1; // seq behind expected — bytes already seen
pub const FLOW_GAP:        u8 = 2; // seq ahead of expected — a hole precedes it

/// Sent from the XDP ring buffer to userspace for every sampled TCP payload.
///
/// `src_addr` / `dst_addr` are big-endian (network byte order, copied straight
/// from the IPv4 header). `src_port` / `dst_port` are also big-endian
/// (copied from the TCP header). Userspace converts on display.
///
/// `seq` is the TCP sequence number in **host** order (already byte-swapped by
/// the kernel — unlike the network-order address/port fields) so userspace can
/// order segments with plain arithmetic. `flags` is one of the `FLOW_*` constants.
///
/// The 4-tuple is required for per-flow TCP reassembly — userspace keys its
/// buffer on `(src_addr, src_port, dst_addr, dst_port)`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PayloadEvent {
    pub src_addr:    u32,
    pub dst_addr:    u32,
    pub src_port:    u16,
    pub dst_port:    u16,
    pub payload_len: u32,
    pub seq:         u32,
    pub flags:       u8,
    pub _pad:        [u8; 3],
    pub payload:     [u8; PAYLOAD_LEN],
}

/// Sent from the sys_enter_connect tracepoint for every outbound IPv4 connect().
/// comm is a null-terminated process name (up to 15 chars + null).
/// dst_addr and dst_port are in network byte order, directly from the sockaddr.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectEvent {
    pub pid:      u32,
    pub comm:     [u8; 16],
    pub dst_addr: u32,
    pub dst_port: u16,
    pub _pad:     u16,
}

/// 4-tuple identifying a TCP flow, as used by the kernel conntrack table.
///
/// Used as the kernel `CONNTRACK` LRU-hash map key and, in std builds, as a
/// userspace `HashMap` key. Every field holds the on-wire bytes (network byte
/// order) exactly as loaded from the packet headers — no host-order conversion —
/// so the same flow always produces the same key on both sides. The layout is
/// padding-free (12 bytes, 4-aligned), which matters for a BPF map key: the
/// kernel hashes the raw key bytes, so an uninitialised padding hole would break
/// lookups.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

/// Per-flow conntrack state held in the kernel `CONNTRACK` map value slot.
///
/// Deliberately small and linear to write — no TCP state machine. `seq_next` is
/// the next expected sequence number (last seq + on-wire payload length) used
/// for retransmit/ordering classification; `last_ts` is the boot-time ns of the
/// most recent segment (LRU/TTL); `packets` is a per-flow counter for stats and
/// optional per-flow limiting; `dir` records the first-seen direction
/// (0 = initiator→responder). Field order puts the u64 first so the struct has
/// no internal padding hole (24 bytes, 8-aligned).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FlowState {
    pub last_ts:  u64,
    pub seq_next: u32,
    pub packets:  u32,
    pub dir:      u8,
    pub _pad:     [u8; 7],
}

/// Shared IPv4 newtype that compiles in both no_std (kernel) and std (userspace).
/// Internal u32 is stored in big-endian (network) byte order.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ipv4Addr(pub u32);

impl Ipv4Addr {
    #[inline]
    pub const fn from_octets(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self(u32::from_be_bytes([a, b, c, d]))
    }

    #[inline]
    pub const fn to_octets(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    #[inline]
    pub const fn as_raw(self) -> u32 {
        self.0
    }
}

#[cfg(feature = "std")]
mod std_impls {
    use super::Ipv4Addr;
    use std::net::Ipv4Addr as StdIpv4Addr;

    impl From<StdIpv4Addr> for Ipv4Addr {
        fn from(addr: StdIpv4Addr) -> Self {
            let [a, b, c, d] = addr.octets();
            Self::from_octets(a, b, c, d)
        }
    }

    impl From<Ipv4Addr> for StdIpv4Addr {
        fn from(addr: Ipv4Addr) -> Self {
            let [a, b, c, d] = addr.to_octets();
            StdIpv4Addr::new(a, b, c, d)
        }
    }

    impl core::fmt::Display for Ipv4Addr {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            let [a, b, c, d] = self.to_octets();
            write!(f, "{}.{}.{}.{}", a, b, c, d)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_octets() {
        let addr = Ipv4Addr::from_octets(10, 0, 0, 1);
        assert_eq!(addr.to_octets(), [10, 0, 0, 1]);
    }

    #[test]
    fn test_raw_is_big_endian() {
        let addr = Ipv4Addr::from_octets(1, 2, 3, 4);
        assert_eq!(addr.as_raw(), 0x01_02_03_04_u32);
    }

    #[test]
    fn test_equality() {
        let a = Ipv4Addr::from_octets(192, 168, 1, 1);
        let b = Ipv4Addr::from_octets(192, 168, 1, 1);
        assert_eq!(a, b);
    }

    #[test]
    fn test_inequality() {
        let a = Ipv4Addr::from_octets(10, 0, 0, 1);
        let b = Ipv4Addr::from_octets(10, 0, 0, 2);
        assert_ne!(a, b);
    }

    #[test]
    fn test_loopback() {
        let lo = Ipv4Addr::from_octets(127, 0, 0, 1);
        assert_eq!(lo.to_octets(), [127, 0, 0, 1]);
    }

    #[cfg(feature = "std")]
    mod std_tests {
        use super::super::*;
        use std::net::Ipv4Addr as StdIpv4Addr;

        #[test]
        fn test_std_conversion_roundtrip() {
            let std_addr = StdIpv4Addr::new(172, 16, 0, 1);
            let our_addr = Ipv4Addr::from(std_addr);
            let back: StdIpv4Addr = our_addr.into();
            assert_eq!(std_addr, back);
        }

        #[test]
        fn test_display() {
            let addr = Ipv4Addr::from_octets(8, 8, 8, 8);
            assert_eq!(format!("{}", addr), "8.8.8.8");
        }

        #[test]
        fn test_mock_map_insert_and_lookup() {
            use std::collections::HashMap;
            let mut mock_map: HashMap<u32, u32> = HashMap::new();
            let ip = Ipv4Addr::from(StdIpv4Addr::new(1, 2, 3, 4));
            mock_map.insert(ip.as_raw(), 1_u32);
            assert_eq!(mock_map.get(&ip.as_raw()).copied(), Some(1));
            let other = Ipv4Addr::from(StdIpv4Addr::new(9, 9, 9, 9));
            assert_eq!(mock_map.get(&other.as_raw()).copied(), None);
        }

        #[test]
        fn test_connect_event_layout() {
            use super::super::ConnectEvent;
            assert_eq!(core::mem::size_of::<ConnectEvent>(), 28);
            assert_eq!(core::mem::align_of::<ConnectEvent>(), 4);
        }

        #[test]
        fn test_payload_event_layout() {
            use super::super::{PayloadEvent, PAYLOAD_LEN};
            // 4 (src_addr) + 4 (dst_addr) + 2 (src_port) + 2 (dst_port)
            // + 4 (payload_len) + 4 (seq) + 1 (flags) + 3 (_pad)
            // + PAYLOAD_LEN = 24 + PAYLOAD_LEN.
            assert_eq!(core::mem::size_of::<PayloadEvent>(), 24 + PAYLOAD_LEN);
            assert_eq!(core::mem::align_of::<PayloadEvent>(), 4);
        }

        #[test]
        fn test_flow_key_layout() {
            use super::super::FlowKey;
            // 4 (src_addr) + 4 (dst_addr) + 2 (src_port) + 2 (dst_port) = 12,
            // and it MUST be padding-free — it's a BPF map key, hashed by raw bytes.
            assert_eq!(core::mem::size_of::<FlowKey>(), 12);
            assert_eq!(core::mem::align_of::<FlowKey>(), 4);
        }

        #[test]
        fn test_flow_state_layout() {
            use super::super::FlowState;
            // 8 (last_ts) + 4 (seq_next) + 4 (packets) + 1 (dir) + 7 (_pad) = 24,
            // u64 first → no internal padding hole.
            assert_eq!(core::mem::size_of::<FlowState>(), 24);
            assert_eq!(core::mem::align_of::<FlowState>(), 8);
        }
    }
}
