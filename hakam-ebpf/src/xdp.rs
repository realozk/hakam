//! XDP ingress: the earliest enforcement point in the stack.
//!
//! This runs at the driver's receive path, before the kernel allocates an
//! `sk_buff` for the packet. A verdict here costs a fraction of what the same
//! decision costs anywhere further up — that is the whole reason the hot path
//! lives in XDP rather than in userspace.
//!
//! Every packet takes the same fixed sequence, cheapest check first:
//!
//!   1. Non-IPv4 → `XDP_PASS` immediately.
//!   2. Source IP in `BLOCKLIST` → `XDP_DROP`.
//!   3. Per-second rate accounting; over `RATE_LIMIT` the source is added to
//!      `BLOCKLIST` and dropped, so subsequent packets exit at step 2.
//!   4. TCP only: record the flow in conntrack and sample the payload for
//!      userspace DPI. Sampling never changes the verdict.
//!
//! Two constraints shape the code below. The verifier requires every packet
//! access to be provably in bounds, which is what `ptr_at` and the explicit
//! `data_end` comparisons in `sample_payload` are for. And nothing here may
//! fail the packet: a parse error returns `XDP_ABORTED` rather than dropping
//! traffic on a bug, and a full ring buffer increments a counter and moves on.

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
use hakam_common::{FlowKey, PayloadEvent, PAYLOAD_LEN};

use crate::{
    conntrack,
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
    let dst_addr: u32 = unsafe { (*ipv4).dst_addr };

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
        sample_payload(ctx, src_addr, dst_addr);
    }

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn sample_payload(ctx: &XdpContext, src_addr: u32, dst_addr: u32) {
    let data = ctx.data();
    let data_end = ctx.data_end();

    let ihl_addr = data + EthHdr::LEN;
    // Need the IHL byte (offset 0) and the total-length field (offset 2..4) to
    // size the on-wire payload for conntrack's seq accounting.
    if ihl_addr + 4 > data_end {
        return;
    }
    let ip_hdr_len = (unsafe { *(ihl_addr as *const u8) } & 0x0f) as usize * 4;
    if ip_hdr_len < 20 {
        return;
    }
    let ip_total_len = u16::from_be(unsafe { *((ihl_addr + 2) as *const u16) }) as usize;

    let tcp_hdr_start = data + EthHdr::LEN + ip_hdr_len;
    // Need the first 13 bytes of the TCP header: ports (0..4) and data offset (12..13).
    if tcp_hdr_start + 13 > data_end {
        return;
    }

    let src_port: u16 = unsafe { *(tcp_hdr_start as *const u16) };
    let dst_port: u16 = unsafe { *((tcp_hdr_start + 2) as *const u16) };

    let tcp_hdr_len = (unsafe { *((tcp_hdr_start + 12) as *const u8) } >> 4) as usize * 4;
    if tcp_hdr_len < 20 || tcp_hdr_len > 60 {
        return;
    }

    // Record the flow in conntrack *before* the 64-byte sampling gate below, so
    // every TCP segment updates the table even when its payload is too short to
    // sample. seq is on-wire big-endian → convert to host order for arithmetic;
    // wire_len is the true on-wire payload size (total − IP hdr − TCP hdr).
    let seq = u32::from_be(unsafe { *((tcp_hdr_start + 4) as *const u32) });
    let wire_len = ip_total_len.saturating_sub(ip_hdr_len + tcp_hdr_len) as u32;
    let flow_flags = conntrack::observe(
        &FlowKey { src_addr, dst_addr, src_port, dst_port },
        seq,
        wire_len,
    );

    let payload_start = tcp_hdr_start + tcp_hdr_len;
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
        (*ptr).dst_addr = dst_addr;
        (*ptr).src_port = src_port;
        (*ptr).dst_port = dst_port;
        (*ptr).payload_len = PAYLOAD_LEN as u32;
        // seq is host order (already byte-swapped above); flags is the kernel's
        // conntrack classification so userspace need not re-derive it.
        (*ptr).seq = seq;
        (*ptr).flags = flow_flags;
        (*ptr)._pad = [0; 3];
        core::ptr::copy_nonoverlapping(
            payload_start as *const u8,
            (*ptr).payload.as_mut_ptr(),
            PAYLOAD_LEN,
        );
    }

    entry.submit(0);
}
