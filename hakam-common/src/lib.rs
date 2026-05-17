#![cfg_attr(not(feature = "std"), no_std)]

pub const PAYLOAD_LEN: usize = 64;

/// Sent from the XDP ring buffer to userspace for every sampled TCP payload.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PayloadEvent {
    pub src_addr:    u32,
    pub payload_len: u32,
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
    }
}
