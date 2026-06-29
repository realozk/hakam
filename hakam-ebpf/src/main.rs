#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{classifier, lsm, map, tracepoint, xdp},
    maps::{Array, LpmTrie, LruHashMap, LruPerCpuHashMap, PerCpuArray, RingBuf},
    programs::{LsmContext, TcContext, TracePointContext, XdpContext},
};
use hakam_common::{FlowKey, FlowState};

mod conntrack;
mod helpers;
mod lsm;
mod tc;
mod tracepoint;
mod xdp;

// Packets per second from one IP before it is auto-blocked.
// PACKET_COUNTER is per-CPU, so each CPU enforces RATE_LIMIT independently.
// Real-world flows hash to a single RX queue → one CPU → 500 pps per IP.
// A distributed flow spread across CPUs hits RATE_LIMIT * num_cpus (worst case).
pub const RATE_LIMIT: u64 = 500;

pub const TC_ACT_OK: i32 = 0;
pub const TC_ACT_SHOT: i32 = 2;
pub const AF_INET: u16 = 2;

// Layout of syscalls/sys_enter_connect tracepoint args on x86-64 Linux ≥ 5.4:
//   offset  0 : u16  common_type
//   offset  2 : u8   common_flags
//   offset  3 : u8   common_preempt_count
//   offset  4 : i32  common_pid
//   offset  8 : i32  __syscall_nr
//   offset 12 : u32  <padding>
//   offset 16 : u64  fd
//   offset 24 : u64  uservaddr  ← pointer to sockaddr in user memory
//   offset 32 : i64  addrlen
pub const TP_OFF_USERVADDR: usize = 24;

// Key  : (prefix_len, addr) where addr bytes match host-endian u32 of the IP octets.
// Value: nanosecond boot timestamp of the block insertion; userspace uses it for TTL.
#[map]
pub static BLOCKLIST: LpmTrie<u32, u64> = LpmTrie::<u32, u64>::with_max_entries(1024, 0);

// Outbound connect() policy (Arsenal roadmap Phase 2 #6). Same key convention as
// BLOCKLIST: a destination IP a local process is forbidden to connect() to. The
// LSM socket_connect hook consults this and returns -EPERM on a hit, killing the
// syscall before any packet is created. Userspace-managed via `policy-block`.
#[map]
pub static CONNECT_POLICY: LpmTrie<u32, u64> = LpmTrie::<u32, u64>::with_max_entries(1024, 0);

// Tight-scope eBPF conntrack (Arsenal roadmap Phase 2 #7). Per-flow state keyed
// on the 4-tuple, holding seq_next/last_ts/packets/dir. No TCP state machine —
// any TCP segment with a payload updates the flow. LruHashMap so the kernel
// auto-evicts the least-recently-used flow under capacity pressure (the answer
// to "1M flows = 1M entries, what's the eviction policy"). XDP populates it;
// userspace reads flow_count for `stats`.
#[map]
pub static CONNTRACK: LruHashMap<FlowKey, FlowState> =
    LruHashMap::<FlowKey, FlowState>::with_max_entries(65_536, 0);

// LruPerCpuHashMap: each CPU has its own counter slot for each key (race-free
// without atomics); kernel auto-evicts the oldest entry on capacity hit so a
// flood from >1024 unique source IPs never silently skips rate limiting.
#[map]
pub static PACKET_COUNTER: LruPerCpuHashMap<u32, u64> =
    LruPerCpuHashMap::<u32, u64>::with_max_entries(1024, 0);

// Per-IP last-seen second-of-boot, used to detect 1 s window boundaries.
#[map]
pub static LAST_SEEN: LruPerCpuHashMap<u32, u32> =
    LruPerCpuHashMap::<u32, u32>::with_max_entries(1024, 0);

#[map]
pub static PAYLOAD_EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

#[map]
pub static CONNECT_EVENTS: RingBuf = RingBuf::with_byte_size(1 << 19, 0);

#[map]
pub static DROP_COUNTER: PerCpuArray<u64> = PerCpuArray::<u64>::with_max_entries(1, 0);

// 64 buckets; bucket n covers [2^n, 2^(n+1)) nanoseconds.
// Only XDP_DROP paths are timed; TC drops and rate-limit rejects are not.
#[map]
pub static LATENCY_HIST: PerCpuArray<u64> = PerCpuArray::<u64>::with_max_entries(64, 0);

// Counter for payload samples we couldn't enqueue (ring full). Surfaced in
// userspace `stats` so the operator sees when DPI falls behind line rate.
#[map]
pub static RING_OVERFLOW: PerCpuArray<u64> = PerCpuArray::<u64>::with_max_entries(1, 0);

// Optional CIDR filter for the sys_enter_connect tracepoint. Packed as
//   high 32 bits = network address (same byte order as sockaddr_in.sin_addr)
//   low  32 bits = mask        (same byte order; 0 means "monitor every connect()").
// Default (cell value 0) leaves the tracepoint system-wide; the userspace
// `--monitor-prefix` flag narrows it to e.g. 10.99.0.0/16 to keep the demo
// console free of DNS / apt / systemd-resolved noise.
#[map]
pub static MONITOR_CFG: Array<u64> = Array::<u64>::with_max_entries(1, 0);

#[xdp]
pub fn hakam_ebpf(ctx: XdpContext) -> u32 {
    xdp::run(ctx)
}

#[classifier]
pub fn hakam_egress(ctx: TcContext) -> i32 {
    tc::run(ctx)
}

#[tracepoint]
pub fn hakam_connect(ctx: TracePointContext) -> i32 {
    tracepoint::run(ctx)
}

#[lsm(hook = "socket_connect")]
pub fn hakam_connect_lsm(ctx: LsmContext) -> i32 {
    lsm::run(ctx)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
