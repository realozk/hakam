//! Helpers for the `MONITOR_CFG` eBPF map.
//!
//! The kernel side stores one `u64` cell:
//!   * high 32 bits — network address, in the same byte order as
//!     `sockaddr_in.sin_addr` (wire bytes loaded as a host-endian `u32`).
//!   * low 32 bits — prefix mask, in the same byte order.
//!   * `mask == 0` is the sentinel for "monitor every `connect()`".
//!
//! Keeping the pack logic here (instead of inlined in `main.rs`) lets the
//! cross-platform test suite pin the byte arithmetic, so a future endianness
//! change can't silently break the demo's noise filter.

use std::net::Ipv4Addr;

/// Pack an IPv4 prefix into the `u64` layout the kernel filter expects.
///
/// `prefix_len` is in bits (0..=32). The function does not normalise the
/// network address — pass an IP whose host bits are already zero, which is
/// what `cli::parse_cidr` returns.
pub fn pack_monitor_cfg(network: Ipv4Addr, prefix_len: u32) -> u64 {
    debug_assert!(prefix_len <= 32, "prefix_len {prefix_len} out of range");

    let network_u32 = u32::from_ne_bytes(network.octets());
    let mask_bits = if prefix_len == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix_len)
    };
    let mask_u32 = u32::from_ne_bytes(mask_bits.to_be_bytes());

    ((network_u32 as u64) << 32) | (mask_u32 as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sin_addr_like_kernel(ip: Ipv4Addr) -> u32 {
        // What sockaddr_in.sin_addr looks like once bpf_probe_read_user loads
        // the wire bytes into a u32 on the host. Same byte order as the kernel
        // filter operates on, so the AND check below mirrors production.
        u32::from_ne_bytes(ip.octets())
    }

    fn ip_passes(packed: u64, ip: Ipv4Addr) -> bool {
        let network = (packed >> 32) as u32;
        let mask = packed as u32;
        if mask == 0 {
            return true;
        }
        sin_addr_like_kernel(ip) & mask == network
    }

    #[test]
    fn slash_zero_packs_to_monitor_all_sentinel() {
        let packed = pack_monitor_cfg(Ipv4Addr::UNSPECIFIED, 0);
        assert_eq!(packed as u32, 0, "mask must be 0 → kernel skips the filter");
    }

    #[test]
    fn ip_inside_prefix_passes_filter() {
        let packed = pack_monitor_cfg(Ipv4Addr::new(10, 99, 0, 0), 16);
        assert!(ip_passes(packed, Ipv4Addr::new(10, 99, 5, 42)));
        assert!(ip_passes(packed, Ipv4Addr::new(10, 99, 255, 1)));
    }

    #[test]
    fn ip_outside_prefix_is_filtered() {
        let packed = pack_monitor_cfg(Ipv4Addr::new(10, 99, 0, 0), 16);
        assert!(!ip_passes(packed, Ipv4Addr::new(10, 100, 0, 1)));
        assert!(!ip_passes(packed, Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn slash_24_only_matches_the_one_subnet() {
        let packed = pack_monitor_cfg(Ipv4Addr::new(172, 16, 5, 0), 24);
        assert!(ip_passes(packed, Ipv4Addr::new(172, 16, 5, 99)));
        assert!(!ip_passes(packed, Ipv4Addr::new(172, 16, 6, 1)));
    }

    #[test]
    fn slash_32_matches_only_the_exact_host() {
        let packed = pack_monitor_cfg(Ipv4Addr::new(10, 0, 0, 1), 32);
        assert!(ip_passes(packed, Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!ip_passes(packed, Ipv4Addr::new(10, 0, 0, 2)));
    }
}
