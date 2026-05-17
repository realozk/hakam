use std::{sync::Arc, time::Duration};

use aya::maps::{lpm_trie::Key, LpmTrie, MapData};
use log::info;
use tokio::sync::Mutex;

use crate::{
    cli::format_lpm_key,
    metrics::boot_time_ns,
    telemetry::{event_json, unblock_json, Sender},
};

pub const BLOCK_TTL_SECS: u64 = 120;

const SERVER_CMD_PATH: &str = "/tmp/hakam-server.cmd";

/// Sweeps the BLOCKLIST every 30s, removing entries older than BLOCK_TTL_SECS.
pub async fn ttl_sweep_task(
    blocklist: Arc<Mutex<LpmTrie<MapData, u32, u64>>>,
    tx: Sender,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));

    loop {
        interval.tick().await;

        let now_ns = boot_time_ns();
        let ttl_ns = BLOCK_TTL_SECS * 1_000_000_000;

        let expired: Vec<Key<u32>> = {
            let map = blocklist.lock().await;
            map.iter()
                .filter_map(|r| r.ok())
                .filter(|(_, ts)| now_ns.saturating_sub(*ts) > ttl_ns)
                .map(|(k, _)| k)
                .collect()
        };

        if expired.is_empty() {
            continue;
        }

        let mut map = blocklist.lock().await;
        for key in &expired {
            let _ = map.remove(key);
            let target = format_lpm_key(key);
            info!("TTL expired: {} removed from BLOCKLIST", target);
            let _ = tx.send(unblock_json(&target));
            let _ = tx.send(event_json(
                &format!("Block TTL expired: {} restored", target),
                "info",
            ));
        }
    }
}

/// Server-side command file watcher. demo-cycle.sh writes single-char commands
/// to /tmp/hakam-server.cmd. Currently supports:
///   `c` / `C`  → clear BLOCKLIST. Used between demo cycles so the next cycle's
///                attacks don't get silently XDP_DROPped because their source
///                IPs are still TTL'd from the previous cycle.
pub async fn server_cmd_task(
    blocklist: Arc<Mutex<LpmTrie<MapData, u32, u64>>>,
    tx: Sender,
) {
    use std::os::unix::fs::PermissionsExt;
    let mut interval = tokio::time::interval(Duration::from_millis(500));

    loop {
        interval.tick().await;

        // Atomic-ish drain: rename before reading to avoid the race where
        // demo-cycle.sh appends between our read and truncate.
        let tmp_path = format!("{}.processing", SERVER_CMD_PATH);
        if std::fs::rename(SERVER_CMD_PATH, &tmp_path).is_err() {
            continue;
        }

        let contents = std::fs::read_to_string(&tmp_path).unwrap_or_default();
        let _ = std::fs::remove_file(&tmp_path);

        for raw_line in contents.lines() {
            let line = raw_line.trim();
            match line {
                "c" | "C" => {
                    let mut map = blocklist.lock().await;
                    let keys: Vec<Key<u32>> = map
                        .iter()
                        .filter_map(|r| r.ok())
                        .map(|(k, _)| k)
                        .collect();
                    let n = keys.len();
                    for k in &keys {
                        let _ = map.remove(k);
                        let _ = tx.send(unblock_json(&format_lpm_key(k)));
                    }
                    drop(map);
                    if n > 0 {
                        info!("BLOCKLIST cleared via server cmd: {} entries removed", n);
                        let _ = tx.send(event_json(
                            &format!("Blocklist cleared by demo-cycle: {} entries", n),
                            "info",
                        ));
                    }
                }
                _ => {}
            }
        }

        // Re-create world-rw so the unprivileged demo-cycle.sh can append.
        if let Ok(f) = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(SERVER_CMD_PATH)
        {
            drop(f);
            let _ = std::fs::set_permissions(
                SERVER_CMD_PATH,
                std::fs::Permissions::from_mode(0o666),
            );
        }
    }
}
