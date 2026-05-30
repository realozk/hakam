//! Platform-independent pieces of `hakam-node`.
//!
//! Anything that does not link against `aya` / `libc` / Linux netlink lives
//! here so it can compile and be tested on any host. The `main.rs` binary
//! contains the Linux-only runtime (eBPF loading, XDP/TC attachment, async
//! ring-buffer consumers).

pub mod reassembly;
pub mod signatures;
