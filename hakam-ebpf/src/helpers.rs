//! Small shared primitives for the kernel programs: drop accounting, latency
//! histogram writes, and the bounds-checked packet-pointer cast every parser
//! goes through.

use aya_ebpf::programs::XdpContext;

use crate::{DROP_COUNTER, LATENCY_HIST};

#[inline(always)]
pub fn increment_drop_counter() {
    unsafe {
        if let Some(ptr) = DROP_COUNTER.get_ptr_mut(0) {
            *ptr += 1;
        }
    }
}

/// Places delta_ns into the floor(log2(delta)) bucket. Bucket index clamped to [0, 63].
#[inline(always)]
pub fn record_latency(delta_ns: u64) {
    let bucket = if delta_ns == 0 {
        0u32
    } else {
        (63 - delta_ns.leading_zeros()).min(63)
    };
    unsafe {
        if let Some(ptr) = LATENCY_HIST.get_ptr_mut(bucket) {
            *ptr += 1;
        }
    }
}

/// Verifier-safe bounds check before casting a raw packet pointer.
#[inline(always)]
pub unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let size = core::mem::size_of::<T>();
    if start + offset + size > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}
