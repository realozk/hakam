use std::{collections::HashMap, net::Ipv4Addr, sync::Arc};

use aya::maps::{lpm_trie::Key, LpmTrie, MapData, RingBuf};
use colored::Colorize;
use hakam_common::{ConnectEvent, PayloadEvent};
use tokio::{io::unix::AsyncFd, sync::Mutex};

use hakam_node::{
    reassembly::{FlowKey, Reassembler},
    signatures,
};

use crate::{
    metrics::boot_time_ns,
    telemetry::{block_json, connect_json, event_json, Sender},
};

// Run the reassembler GC every N payload events. At 64-byte samples this is
// roughly once per 64 KB of inspected traffic — cheap enough to amortise the
// linear scan over the flow table.
const REASSEMBLY_GC_INTERVAL: u64 = 1024;

#[derive(Default)]
pub struct DpiStats {
    pub total_http_seen: u64,
    pub total_detections: u64,
    pub by_category: HashMap<&'static str, u64>,
}

fn severity_paint(sev: &str) -> colored::ColoredString {
    match sev {
        "critical" => sev.to_uppercase().bright_red().bold(),
        "high" => sev.to_uppercase().red().bold(),
        "medium" => sev.to_uppercase().yellow().bold(),
        _ => sev.to_uppercase().bright_black().bold(),
    }
}

pub async fn payload_task(
    mut ring: AsyncFd<RingBuf<MapData>>,
    blocklist: Arc<Mutex<LpmTrie<MapData, u32, u64>>>,
    tx: Sender,
    stats: Arc<Mutex<DpiStats>>,
) {
    let mut reassembler = Reassembler::with_defaults();
    let mut events_seen: u64 = 0;

    loop {
        let mut guard = match ring.readable_mut().await {
            Ok(g) => g,
            Err(_) => continue,
        };

        let rb = guard.get_inner_mut();
        while let Some(bytes) = rb.next() {
            if bytes.len() < core::mem::size_of::<PayloadEvent>() {
                continue;
            }

            let event: &PayloadEvent = unsafe { &*(bytes.as_ptr() as *const PayloadEvent) };
            let len = (event.payload_len as usize).min(hakam_common::PAYLOAD_LEN);
            let payload = &event.payload[..len];

            events_seen = events_seen.wrapping_add(1);
            let now_ns = boot_time_ns();
            if events_seen % REASSEMBLY_GC_INTERVAL == 0 {
                reassembler.gc(now_ns);
            }

            let key = FlowKey::from_event(event);
            let Some(view) = reassembler.ingest(key, payload, now_ns) else {
                continue;
            };

            // Match against the reassembled view, not just this segment —
            // that's the whole point of buffering.
            if !signatures::is_http_request(view) {
                continue;
            }

            {
                let mut s = stats.lock().await;
                s.total_http_seen += 1;
            }

            let Some(sig) = signatures::match_payload(view) else {
                continue;
            };

            // Match fired — drop the flow's buffered state so we don't
            // keep re-matching on subsequent segments of the same flow.
            reassembler.forget(&key);

            let b = event.src_addr.to_ne_bytes();
            let ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
            let ip_str = ip.to_string();

            println!();
            println!(
                "  {}  {}  {}  {}  {}  {}",
                "▼ INTERCEPT".bright_red().bold().on_black(),
                format!("[{}]", sig.category).bright_yellow().bold(),
                severity_paint(sig.severity),
                "FROM".bright_black(),
                ip_str.bright_white().bold(),
                format!("→ {}", sig.action).bright_red(),
            );
            println!(
                "  {}  {}",
                "   └─ pattern:".bright_black(),
                sig.pattern.yellow(),
            );
            println!();

            let trie_key = Key::new(32, u32::from_ne_bytes(ip.octets()));
            let _ = blocklist.lock().await.insert(&trie_key, &now_ns, 0);

            {
                let mut s = stats.lock().await;
                s.total_detections += 1;
                *s.by_category.entry(sig.category).or_insert(0) += 1;
            }

            let _ = tx.send(block_json(
                &ip_str,
                "Edge Proxy",
                Some(sig.pattern),
                sig.action,
                Some(sig.category),
                Some(sig.severity),
            ));
            let _ = tx.send(event_json(
                &format!(
                    "{} ({}) — pattern '{}' from {}",
                    sig.category, sig.severity, sig.pattern, ip_str
                ),
                "critical",
            ));
        }

        guard.clear_ready();
    }
}

pub async fn connect_task(mut ring: AsyncFd<RingBuf<MapData>>, tx: Sender) {
    loop {
        let mut guard = match ring.readable_mut().await {
            Ok(g) => g,
            Err(_) => continue,
        };

        let rb = guard.get_inner_mut();
        while let Some(bytes) = rb.next() {
            if bytes.len() < core::mem::size_of::<ConnectEvent>() {
                continue;
            }

            let ev: &ConnectEvent = unsafe { &*(bytes.as_ptr() as *const ConnectEvent) };

            let comm_end = ev.comm.iter().position(|&b| b == 0).unwrap_or(16);
            let comm = String::from_utf8_lossy(&ev.comm[..comm_end]).into_owned();

            // dst_addr is in network byte order (raw bytes from sockaddr_in).
            let b = ev.dst_addr.to_ne_bytes();
            let dst = format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]);
            let port = u16::from_be(ev.dst_port);

            println!(
                "  {} {} {} {}:{} {}",
                "⚡".bright_blue(),
                format!("[{}]", comm).bright_blue().bold(),
                "→".bright_black(),
                dst.yellow(),
                port,
                format!("(PID {})", ev.pid).bright_black()
            );

            let _ = tx.send(connect_json(ev.pid, &comm, &dst, port));
        }

        guard.clear_ready();
    }
}
