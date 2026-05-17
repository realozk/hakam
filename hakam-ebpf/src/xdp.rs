use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    maps::lpm_trie::Key,
    programs::XdpContext,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
};
use hakam_common::{PayloadEvent, PAYLOAD_LEN};

use crate::{
    helpers::{increment_drop_counter, ptr_at, record_latency},
    BLOCKLIST, LAST_SEEN, PACKET_COUNTER, PAYLOAD_EVENTS, RATE_LIMIT, RING_OVERFLOW,
};

pub fn run(ctx: XdpContext) -> u32 {
    let t0 = unsafe { bpf_ktime_get_ns() };
    let ret = match try_xdp(&ctx) {
        Ok(r) => r,
        Err(_) => xdp_action::XDP_ABORTED,
    };
    if ret == xdp_action::XDP_DROP {
        record_latency(unsafe { bpf_ktime_get_ns() }.wrapping_sub(t0));
    }
    ret
}

#[inline(always)]
fn try_xdp(ctx: &XdpContext) -> Result<u32, ()> {
    let eth: *const EthHdr = unsafe { ptr_at(ctx, 0)? };

    if unsafe { (*eth).ether_type } != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ipv4: *const Ipv4Hdr = unsafe { ptr_at(ctx, EthHdr::LEN)? };
    let src_addr: u32 = unsafe { (*ipv4).src_addr };

    if BLOCKLIST.get(&Key::new(32u32, src_addr)).is_some() {
        increment_drop_counter();
        return Ok(xdp_action::XDP_DROP);
    }

    // bpf_ktime_get_ns() returns nanoseconds since boot (same clock as CLOCK_BOOTTIME).
    let now_ns: u64 = unsafe { bpf_ktime_get_ns() };
    let now_sec: u32 = (now_ns / 1_000_000_000) as u32;

    let new_window = match unsafe { LAST_SEEN.get(&src_addr) } {
        None => true,
        Some(last) => now_sec.wrapping_sub(*last) >= 1,
    };

    if new_window {
        let _ = LAST_SEEN.insert(&src_addr, &now_sec, 0);
        let _ = PACKET_COUNTER.insert(&src_addr, &0u64, 0);
    }

    let count: u64 = unsafe {
        match PACKET_COUNTER.get_ptr_mut(&src_addr) {
            Some(ptr) => {
                *ptr += 1;
                *ptr
            }
            None => {
                let _ = PACKET_COUNTER.insert(&src_addr, &1u64, 0);
                1
            }
        }
    };

    if count > RATE_LIMIT {
        let _ = BLOCKLIST.insert(&Key::new(32u32, src_addr), &now_ns, 0);
        increment_drop_counter();
        return Ok(xdp_action::XDP_DROP);
    }

    if unsafe { (*ipv4).proto } == IpProto::Tcp {
        sample_payload(ctx, src_addr);
    }

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn sample_payload(ctx: &XdpContext, src_addr: u32) {
    let data = ctx.data();
    let data_end = ctx.data_end();

    let ihl_addr = data + EthHdr::LEN;
    if ihl_addr + 1 > data_end {
        return;
    }
    let ip_hdr_len = (unsafe { *(ihl_addr as *const u8) } & 0x0f) as usize * 4;
    if ip_hdr_len < 20 {
        return;
    }

    let doff_addr = data + EthHdr::LEN + ip_hdr_len + 12;
    if doff_addr + 1 > data_end {
        return;
    }
    let tcp_hdr_len = (unsafe { *(doff_addr as *const u8) } >> 4) as usize * 4;
    if tcp_hdr_len < 20 || tcp_hdr_len > 60 {
        return;
    }

    let payload_start = data + EthHdr::LEN + ip_hdr_len + tcp_hdr_len;
    if payload_start + PAYLOAD_LEN > data_end {
        return;
    }

    let mut entry = match PAYLOAD_EVENTS.reserve::<PayloadEvent>(0) {
        Some(e) => e,
        None => {
            unsafe {
                if let Some(p) = RING_OVERFLOW.get_ptr_mut(0) {
                    *p += 1;
                }
            }
            return;
        }
    };

    let ptr = entry.as_mut_ptr();
    unsafe {
        (*ptr).src_addr = src_addr;
        (*ptr).payload_len = PAYLOAD_LEN as u32;
        core::ptr::copy_nonoverlapping(
            payload_start as *const u8,
            (*ptr).payload.as_mut_ptr(),
            PAYLOAD_LEN,
        );
    }

    entry.submit(0);
}
