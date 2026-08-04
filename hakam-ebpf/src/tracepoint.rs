//! `sys_enter_connect` tracepoint: attributes outbound connections to processes.
//!
//! This is the observability layer, not an enforcement one — it always returns
//! 0 and never blocks anything. Its job is to answer *who*: the packet-level
//! hooks see addresses and ports, but only a syscall-level hook can name the
//! PID and command behind a connection. Userspace joins these events against
//! DPI detections so a block can report the process that caused it.
//!
//! Note this reads with `bpf_probe_read_user`, unlike [`crate::lsm`] which uses
//! the kernel variant. A tracepoint fires on syscall *entry*, while the
//! `sockaddr` is still the caller's own userspace buffer; the LSM hook runs
//! later, after the kernel has copied it inward.
//!
//! Because it is system-wide by default, `MONITOR_CFG` can narrow it to one
//! CIDR — otherwise routine DNS, package-manager, and resolver traffic drowns
//! out anything interesting.

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user},
    programs::TracePointContext,
};
use hakam_common::ConnectEvent;

use crate::{AF_INET, CONNECT_EVENTS, MONITOR_CFG, TP_OFF_USERVADDR};

// Prefix of the userspace `struct sockaddr_in`. Declared separately from the
// LSM hook's identical struct because the two read from different address
// spaces and are intentionally not coupled.
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

    // Optional CIDR scope: drop connect() events outside the monitored prefix
    // before we burn a ring-buffer slot on them. mask == 0 → monitor all.
    if let Some(cfg) = MONITOR_CFG.get(0) {
        let network = (*cfg >> 32) as u32;
        let mask = *cfg as u32;
        if mask != 0 && (sa.sin_addr & mask) != network {
            return Ok(0);
        }
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
