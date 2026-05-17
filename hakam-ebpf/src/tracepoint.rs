use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user},
    programs::TracePointContext,
};
use hakam_common::ConnectEvent;

use crate::{AF_INET, CONNECT_EVENTS, TP_OFF_USERVADDR};

#[repr(C)]
struct SockaddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
}

pub fn run(ctx: TracePointContext) -> i32 {
    match try_connect(&ctx) {
        Ok(r) => r,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_connect(ctx: &TracePointContext) -> Result<i32, ()> {
    let uservaddr_ptr: u64 = unsafe { ctx.read_at(TP_OFF_USERVADDR).map_err(|_| ())? };
    if uservaddr_ptr == 0 {
        return Ok(0);
    }

    let sa: SockaddrIn = unsafe {
        bpf_probe_read_user(uservaddr_ptr as *const SockaddrIn).map_err(|_| ())?
    };

    if sa.sin_family != AF_INET {
        return Ok(0);
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // bpf_get_current_comm returns [i8; 16]; transmute to [u8; 16].
    let comm: [u8; 16] = unsafe {
        let raw = bpf_get_current_comm().map_err(|_| ())?;
        core::mem::transmute(raw)
    };

    let mut entry = match CONNECT_EVENTS.reserve::<ConnectEvent>(0) {
        Some(e) => e,
        None => return Ok(0),
    };

    let ptr = entry.as_mut_ptr();
    unsafe {
        (*ptr).pid = pid;
        (*ptr).comm = comm;
        (*ptr).dst_addr = sa.sin_addr;
        (*ptr).dst_port = sa.sin_port;
        (*ptr)._pad = 0;
    }

    entry.submit(0);
    Ok(0)
}
