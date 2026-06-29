//! BPF-LSM `socket_connect` enforcement (Arsenal roadmap Phase 2 #6).
//!
//! This hook runs *inside* the connect(2) syscall, last in the LSM chain
//! (after the major MAC modules — SELinux/AppArmor — so any of them returning
//! -EPERM first short-circuits before we are consulted) and before the
//! protocol's own connect. If the
//! destination IP is in CONNECT_POLICY we return -EPERM, which aborts the
//! syscall: the connection never forms and no packet is ever created. That is
//! the distinction from the TC egress drop (which kills the packet on the wire
//! *after* the syscall succeeds) — here the originating process gets an
//! immediate "Operation not permitted".
//!
//! Scope (honest limitations, see docs):
//!   * connect()-based flows only. Connectionless UDP (sendto without connect)
//!     never triggers this hook — TC egress is the catch-all for those.
//!   * IPv4 only. AF_INET6 connects are passed through untouched.
//!
//! Fail-open: any internal read error returns 0 (allow). A parsing bug must
//! never be able to wedge the host's own networking.

use aya_ebpf::{
    helpers::bpf_probe_read_kernel, maps::lpm_trie::Key, programs::LsmContext,
};

use crate::{AF_INET, CONNECT_POLICY};

// Returning a negative errno from an LSM hook denies the operation.
const EPERM: i32 = 1;

// security_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen).
// `address` is a *kernel* copy (move_addr_to_kernel runs before the hook), so we
// read it with bpf_probe_read_kernel, not _user.
#[repr(C)]
struct SockaddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
}

pub fn run(ctx: LsmContext) -> i32 {
    match try_connect(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_connect(ctx: &LsmContext) -> Result<i32, ()> {
    // arg 0 = struct socket *, arg 1 = struct sockaddr *, arg 2 = addrlen.
    let addr_ptr: *const SockaddrIn = unsafe { ctx.arg(1) };
    if addr_ptr.is_null() {
        return Ok(0);
    }

    let sa: SockaddrIn = unsafe { bpf_probe_read_kernel(addr_ptr).map_err(|_| ())? };

    if sa.sin_family != AF_INET {
        return Ok(0);
    }

    // sin_addr is network byte order — the same representation TC egress loads
    // from the packet and userspace writes via lpm_key, so the key matches.
    if CONNECT_POLICY.get(&Key::new(32, sa.sin_addr)).is_some() {
        return Ok(-EPERM);
    }

    Ok(0)
}
