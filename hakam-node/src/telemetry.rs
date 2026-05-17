use std::sync::Arc;

use colored::Colorize;
use futures_util::{SinkExt, StreamExt};
use log::{info, warn};
use tokio::sync::broadcast;
use warp::{ws::Message, Filter};

pub type Sender = broadcast::Sender<String>;

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
}

pub fn metrics_json(
    cpu: f32,
    p50_ns: u64,
    p99_ns: u64,
    dropped: u64,
    rx_bps: u64,
    tx_bps: u64,
    mem_kb: u64,
    ring_overflows: u64,
) -> String {
    format!(
        r#"{{"type":"METRICS","cpu":{:.1},"latency_p50_ns":{},"latency_p99_ns":{},"dropped":{},"rx_bps":{},"tx_bps":{},"mem_kb":{},"ring_overflows":{}}}"#,
        cpu, p50_ns, p99_ns, dropped, rx_bps, tx_bps, mem_kb, ring_overflows
    )
}

pub fn event_json(message: &str, level: &str) -> String {
    format!(
        r#"{{"type":"EVENT","message":"{}","level":"{}"}}"#,
        json_escape(message),
        json_escape(level)
    )
}

pub fn block_json(
    source: &str,
    target: &str,
    payload: Option<&str>,
    action: &str,
    category: Option<&str>,
    severity: Option<&str>,
) -> String {
    let mut s = String::with_capacity(160);
    s.push_str(r#"{"type":"BLOCK","source":""#);
    s.push_str(&json_escape(source));
    s.push_str(r#"","target":""#);
    s.push_str(&json_escape(target));
    s.push_str(r#"","action":""#);
    s.push_str(&json_escape(action));
    s.push('"');
    if let Some(p) = payload {
        s.push_str(r#","payload":""#);
        s.push_str(&json_escape(p));
        s.push('"');
    }
    if let Some(c) = category {
        s.push_str(r#","category":""#);
        s.push_str(&json_escape(c));
        s.push('"');
    }
    if let Some(sev) = severity {
        s.push_str(r#","severity":""#);
        s.push_str(&json_escape(sev));
        s.push('"');
    }
    s.push('}');
    s
}

pub fn unblock_json(source: &str) -> String {
    format!(r#"{{"type":"UNBLOCK","source":"{}"}}"#, json_escape(source))
}

pub fn connect_json(pid: u32, comm: &str, dst: &str, port: u16) -> String {
    format!(
        r#"{{"type":"CONNECT","pid":{},"comm":"{}","dst":"{}","port":{}}}"#,
        pid,
        json_escape(comm),
        json_escape(dst),
        port
    )
}

pub async fn run_ws_server(tx: Sender, port: u16, bind_addr: std::net::IpAddr) {
    let tx = Arc::new(tx);
    let ws_route = warp::path("ws")
        .and(warp::ws())
        .and(warp::any().map(move || Arc::clone(&tx)))
        .map(|ws: warp::ws::Ws, tx: Arc<Sender>| {
            ws.on_upgrade(move |socket| handle_ws_client(socket, tx))
        });

    let addr: std::net::SocketAddr = (bind_addr, port).into();
    info!("Telemetry WebSocket on ws://{}:{}/ws", bind_addr, port);
    println!(
        "  {}  {} {} {}",
        "◉".cyan().bold(),
        "telemetry".cyan().bold(),
        format!("ws://{}:", bind_addr).bright_black(),
        format!("{}/ws", port).bright_white().bold(),
    );
    if let Some(ip) = detect_reachable_ipv4() {
        println!(
            "  {}  {} {}",
            "◉".bright_green().bold(),
            "reachable at".bright_green().bold(),
            format!("ws://{}:{}/ws", ip, port).bright_white().bold(),
        );
    }

    warp::serve(ws_route).run(addr).await;
}

/// `connect()` on a UDP socket doesn't send anything but triggers the routing
/// decision, so `local_addr()` reports the egress IP without new dependencies.
fn detect_reachable_ipv4() -> Option<std::net::Ipv4Addr> {
    use std::net::{IpAddr, UdpSocket};
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("8.8.8.8:53").ok()?;
    match s.local_addr().ok()?.ip() {
        IpAddr::V4(a) if !a.is_loopback() && !a.is_unspecified() => Some(a),
        _ => None,
    }
}

const DEMO_CMD_PATH: &str = "/tmp/hakam-demo.cmd";

fn extract_json_string_field(json: &str, key: &str) -> Option<String> {
    // Matches `"<key>":"<value>"`; rejects embedded quotes (we don't emit them).
    let needle = format!("\"{}\"", key);
    let rest = &json[json.find(&needle)? + needle.len()..];
    let after_colon = rest.trim_start().strip_prefix(':')?;
    let after_quote = after_colon.trim_start().strip_prefix('"')?;
    let end = after_quote.find('"')?;
    Some(after_quote[..end].to_string())
}

/// Append a single-char demo command to /tmp/hakam-demo.cmd. Validated
/// against an allow-list — defense in depth on top of `case` in the script.
fn write_demo_cmd(action: &str) {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    if action.chars().count() != 1 {
        return;
    }
    let c = action.chars().next().unwrap();
    let ok = c == ' '
        || matches!(c, 'n' | 'N' | 'r' | 'R' | 'q' | 'Q')
        || c.is_ascii_digit();
    if !ok {
        return;
    }

    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(DEMO_CMD_PATH)
    {
        let _ = writeln!(f, "{}", c);
    }
    // World-rw so unprivileged demo-cycle.sh can truncate it.
    let _ = std::fs::set_permissions(
        DEMO_CMD_PATH,
        std::fs::Permissions::from_mode(0o666),
    );
}

async fn handle_ws_client(ws: warp::ws::WebSocket, tx: Arc<Sender>) {
    let mut rx = tx.subscribe();
    let (mut ws_tx, mut ws_rx) = ws.split();

    // Inbound: only handles {"type":"DEMO_CMD","action":"<single char>"};
    // everything else (ping, malformed) is silently ignored.
    let inbound = tokio::spawn(async move {
        while let Some(Ok(msg)) = ws_rx.next().await {
            if let Ok(text) = msg.to_str() {
                if !text.contains("\"DEMO_CMD\"") {
                    continue;
                }
                if let Some(action) = extract_json_string_field(text, "action") {
                    write_demo_cmd(&action);
                }
            }
        }
    });

    loop {
        match rx.recv().await {
            Ok(msg) => {
                if ws_tx.send(Message::text(msg)).await.is_err() {
                    break;
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!("WS client lagged, dropped {} messages", n);
            }
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
    inbound.abort();
}
