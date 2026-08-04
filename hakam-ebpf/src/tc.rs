//! TC egress: outbound counterpart to the XDP ingress filter.
//!
//! XDP only sees packets arriving at the NIC, so it cannot stop the host from
//! *sending* to a blocked address. This classifier runs on the egress path and
//! matches the same `BLOCKLIST` against the packet's **destination**, which is
//! what turns a block into a bidirectional one — an already-established session
//! to a newly blocked IP stops carrying data in both directions.
//!
//! This is the catch-all layer, not the precise one. It kills packets after the
//! syscall has already succeeded, so the sending process sees a silent black
//! hole rather than an error. The BPF-LSM hook in [`crate::lsm`] is the precise
//! path — it denies `connect()` outright — but only covers connection-oriented
//! flows. Anything the LSM hook can't see (connectionless UDP, sockets that
//! predate the policy) is caught here.
//!
//! Fail-open: an unreadable header returns `TC_ACT_OK`. A parsing bug must
//! never be able to sever the host's own networking.

use aya_ebpf::{maps::lpm_trie::Key, programs::TcContext};
use network_types::eth::EthHdr;

use crate::{helpers::increment_drop_counter, BLOCKLIST, TC_ACT_OK, TC_ACT_SHOT};

// Byte offsets into the packet, from the start of the Ethernet header:
//   12          — EtherType (after the 6-byte dst and 6-byte src MACs).
//   EthHdr::LEN — start of the IPv4 header.
//   ...    + 16 — IPv4 destination address (offset 16 within the IPv4 header:
//                 4 bytes of version/IHL/TOS/total-length, 4 of ID/flags/frag,
//                 4 of TTL/proto/checksum, then 4 of source address).
const OFF_ETHERTYPE: usize = 12;
const OFF_IPV4_DST: usize = EthHdr::LEN + 16;

// EtherType 0x0800 = IPv4. `ctx.load` yields the field in on-wire order, so the
// constant is byte-swapped to match rather than swapping the loaded value.
const ETHERTYPE_IPV4_BE: u16 = 0x0800_u16.to_be();

pub fn run(ctx: TcContext) -> i32 {
    match try_egress(&ctx) {
        Ok(v) => v,
        Err(_) => TC_ACT_OK,
    }
}

#[inline(always)]
fn try_egress(ctx: &TcContext) -> Result<i32, ()> {
    let ether_type: u16 = ctx.load(OFF_ETHERTYPE).map_err(|_| ())?;
    if ether_type != ETHERTYPE_IPV4_BE {
        return Ok(TC_ACT_OK);
    }

    // Network byte order, matching how BLOCKLIST keys are written — no
    // conversion needed for the lookup to line up with the XDP side.
    let dst_addr: u32 = ctx.load(OFF_IPV4_DST).map_err(|_| ())?;

    if BLOCKLIST.get(&Key::new(32u32, dst_addr)).is_some() {
        increment_drop_counter();
        return Ok(TC_ACT_SHOT);
    }

    Ok(TC_ACT_OK)
}
