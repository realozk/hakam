use std::{sync::Arc, time::Duration};

use aya::maps::{MapData, PerCpuArray};
use tokio::sync::Mutex;

use crate::telemetry::{metrics_json, Sender};

/// Nanoseconds since boot using CLOCK_BOOTTIME — same reference as
/// bpf_ktime_get_ns() in the eBPF programs.
pub fn boot_time_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// Reads the per-CPU LATENCY_HIST map and returns (p50_ns, p99_ns).
/// Each bucket n represents drop latencies in [2^n, 2^(n+1)) nanoseconds.
pub fn read_latency_percentiles(hist: &PerCpuArray<MapData, u64>) -> (u64, u64) {
    let mut totals = [0u64; 64];
    for bucket in 0u32..64 {
        if let Ok(values) = hist.get(&bucket, 0) {
            totals[bucket as usize] = values.iter().sum();
        }
    }

    let total: u64 = totals.iter().sum();
    if total == 0 {
        return (0, 0);
    }

    let p50_target = total / 2;
    let p99_target = total * 99 / 100;
    let mut cumulative = 0u64;
    let mut p50 = 0u64;
    let mut p99 = 0u64;

    for (n, &count) in totals.iter().enumerate() {
        cumulative += count;
        // Bucket midpoint: 2^n * 1.5 (geometric mean of [2^n, 2^(n+1))).
        let mid = if n == 0 { 1u64 } else { 3u64 << (n - 1) };
        if p50 == 0 && cumulative >= p50_target {
            p50 = mid;
        }
        if p99 == 0 && cumulative >= p99_target {
            p99 = mid;
        }
    }

    (p50, p99)
}

pub async fn ticker(
    tx: Sender,
    drop_counter: Arc<Mutex<PerCpuArray<MapData, u64>>>,
    latency_hist: Arc<Mutex<PerCpuArray<MapData, u64>>>,
    ring_overflow: Arc<Mutex<PerCpuArray<MapData, u64>>>,
    iface: String,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    let mut prev_iface = read_iface_bytes(&iface).await.unwrap_or((0, 0));

    loop {
        interval.tick().await;

        let cpu = read_cpu_usage_percent().await.unwrap_or(0.0);

        let dropped: u64 = {
            let map = drop_counter.lock().await;
            map.get(&0u32, 0).map(|v| v.iter().sum()).unwrap_or(0)
        };

        let (p50_ns, p99_ns) = {
            let map = latency_hist.lock().await;
            read_latency_percentiles(&map)
        };

        let ring_overflows: u64 = {
            let map = ring_overflow.lock().await;
            map.get(&0u32, 0).map(|v| v.iter().sum()).unwrap_or(0)
        };

        let (rx_bps, tx_bps) = match read_iface_bytes(&iface).await {
            Some(curr) => {
                let rx = curr.0.saturating_sub(prev_iface.0);
                let tx = curr.1.saturating_sub(prev_iface.1);
                prev_iface = curr;
                (rx, tx)
            }
            None => (0, 0),
        };

        let mem_kb = read_self_rss_kb().await.unwrap_or(0);

        let _ = tx.send(metrics_json(
            cpu, p50_ns, p99_ns, dropped, rx_bps, tx_bps, mem_kb, ring_overflows,
        ));
    }
}

async fn read_cpu_usage_percent() -> Option<f32> {
    use tokio::fs;
    let content = fs::read_to_string("/proc/stat").await.ok()?;
    let line = content.lines().next()?;
    let nums: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|s| s.parse().ok())
        .collect();
    if nums.len() < 4 {
        return None;
    }
    let idle = nums[3];
    let total: u64 = nums.iter().sum();
    if total == 0 {
        return None;
    }
    Some(100.0 - (idle as f32 / total as f32 * 100.0))
}

async fn read_iface_bytes(iface: &str) -> Option<(u64, u64)> {
    use tokio::fs;
    let content = fs::read_to_string("/proc/net/dev").await.ok()?;
    for line in content.lines() {
        let line = line.trim_start();
        if let Some(rest) = line.strip_prefix(&format!("{}:", iface)) {
            let nums: Vec<u64> = rest
                .split_whitespace()
                .filter_map(|s| s.parse().ok())
                .collect();
            // /proc/net/dev field order:
            //   rx_bytes rx_packets rx_errs rx_drop rx_fifo rx_frame rx_compressed rx_multicast
            //   tx_bytes tx_packets tx_errs tx_drop tx_fifo tx_colls tx_carrier tx_compressed
            if nums.len() >= 9 {
                return Some((nums[0], nums[8]));
            }
        }
    }
    None
}

async fn read_self_rss_kb() -> Option<u64> {
    use tokio::fs;
    let content = fs::read_to_string("/proc/self/status").await.ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok());
        }
    }
    None
}
