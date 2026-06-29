use std::{
    io::{self, BufRead, Write},
    net::Ipv4Addr,
    path::PathBuf,
    str::FromStr,
    sync::Arc,
};

use anyhow::Result;
use aya::{
    maps::{lpm_trie::Key, HashMap as AyaHashMap, LpmTrie, MapData, PerCpuArray},
    programs::XdpFlags,
};
use clap::Parser;
use colored::Colorize;
use tokio::sync::Mutex;

use hakam_node::signatures;

use crate::{
    dpi::DpiStats,
    maintenance::BLOCK_TTL_SECS,
    metrics::{boot_time_ns, read_latency_percentiles},
    telemetry::{block_json, event_json, unblock_json, Sender},
};

#[derive(Parser, Debug)]
#[command(
    name = "hakam-node",
    author = "Hakam Security",
    version = env!("CARGO_PKG_VERSION"),
    about = "Kernel-level XDP packet filtering. No rules. No mercy.",
    long_about = None,
)]
pub struct Args {
    #[arg(short, long, default_value = "lo")]
    pub iface: String,

    #[arg(
        short,
        long,
        default_value = "./target/bpfel-unknown-none/release/hakam-ebpf"
    )]
    pub bpf_path: PathBuf,

    #[arg(long, default_value = "skb", value_parser = parse_xdp_flags)]
    pub mode: XdpFlags,

    #[arg(long, default_value = "info", env = "RUST_LOG")]
    pub log_level: String,

    #[arg(long, default_value = "8080")]
    pub ws_port: u16,

    #[arg(long, default_value = "127.0.0.1")]
    pub bind: std::net::IpAddr,

    /// Restrict the sys_enter_connect tracepoint to this IPv4 prefix
    /// (e.g. `10.99.0.0/16`). Omit to monitor every connect() on the host.
    #[arg(long)]
    pub monitor_prefix: Option<String>,
}

fn parse_xdp_flags(s: &str) -> Result<XdpFlags, String> {
    match s.to_lowercase().as_str() {
        "skb" => Ok(XdpFlags::SKB_MODE),
        "drv" => Ok(XdpFlags::DRV_MODE),
        "hw" => Ok(XdpFlags::HW_MODE),
        "default" => Ok(XdpFlags::default()),
        other => Err(format!("unknown XDP mode '{}'; try skb|drv|hw", other)),
    }
}

/// Parses "10.0.0.0/24" or "1.2.3.4" into (network_ip, prefix_len).
/// Host bits beyond prefix_len are zeroed so the stored key is canonical.
pub fn parse_cidr(s: &str) -> Result<(Ipv4Addr, u32), String> {
    if let Some((ip_str, prefix_str)) = s.split_once('/') {
        let ip: Ipv4Addr = Ipv4Addr::from_str(ip_str)
            .map_err(|_| format!("'{}' is not a valid IPv4 address", ip_str))?;
        let prefix: u32 = prefix_str
            .parse()
            .map_err(|_| format!("'{}' is not a valid prefix length", prefix_str))?;
        if prefix > 32 {
            return Err(format!("prefix length {} is out of range (0–32)", prefix));
        }
        let mask = if prefix == 0 { 0u32 } else { !0u32 << (32 - prefix) };
        let addr_be = u32::from(ip) & mask;
        Ok((Ipv4Addr::from(addr_be), prefix))
    } else {
        let ip: Ipv4Addr = Ipv4Addr::from_str(s)
            .map_err(|_| format!("'{}' is not a valid IPv4 address", s))?;
        Ok((ip, 32))
    }
}

/// Builds an LPM trie key. The `data` field holds octets in memory in network
/// byte order; on a little-endian host, `u32::from_ne_bytes(ip.octets())`
/// produces a u32 whose LE memory layout is [a,b,c,d] — what the kernel reads
/// MSB-first for prefix matching.
pub fn lpm_key(ip: Ipv4Addr, prefix_len: u32) -> Key<u32> {
    Key::new(prefix_len, u32::from_ne_bytes(ip.octets()))
}

pub fn format_lpm_key(key: &Key<u32>) -> String {
    let b = key.data().to_ne_bytes();
    let ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
    if key.prefix_len() == 32 {
        ip.to_string()
    } else {
        format!("{}/{}", ip, key.prefix_len())
    }
}

pub fn print_banner() {
    let sig_count = signatures::SIGNATURES.len();
    let cat_count = signatures::CATEGORIES.len();

    println!();
    println!("{}", r#"  ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗"#.bright_red().bold());
    println!("{}", r#"  ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║"#.bright_red().bold());
    println!("{}", r#"  ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║"#.bright_red().bold());
    println!("{}", r#"  ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║"#.red().bold());
    println!("{}", r#"  ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║"#.red().bold());
    println!("{}", r#"  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝"#.red().bold());
    println!();
    println!(
        "  {} {}    {}",
        "HAKAM".bright_red().bold(),
        "// kernel-resident eBPF firewall".bright_black(),
        format!("v{}", env!("CARGO_PKG_VERSION")).bright_black(),
    );
    println!(
        "  {}  {}    {}  {}    {}  {}",
        "engine:".bright_black(),
        "XDP + TC + Tracepoint".cyan(),
        "signatures:".bright_black(),
        format!("{}", sig_count).bright_white().bold(),
        "families:".bright_black(),
        format!("{}", cat_count).bright_white().bold(),
    );
    println!("{}", "  ──────────────────────────────────────────────────────────────────".bright_black());
    println!(
        "  {}   {}",
        "status".bright_black(),
        "[ INITIALISING KERNEL HOOKS ]".yellow().bold()
    );
    println!();
}

pub fn print_attached(iface: &str, mode: &str, bpf_path: &std::path::Path) {
    println!();
    println!(
        "  {}  {} {} {} {}",
        "◉".green().bold(),
        "XDP".green().bold(),
        "armed on".bright_black(),
        format!("[{}]", iface).bright_white().bold(),
        format!("mode={}", mode).bright_black(),
    );
    println!(
        "  {}  {} {}",
        "◉".bright_black(),
        "BPF ELF".bright_black(),
        bpf_path.display().to_string().cyan()
    );
    println!(
        "  {}  {}",
        "◉".bright_black(),
        "Kernel datapath active — all ingress under surveillance.".bright_black()
    );
    println!();
    println!(
        "  {}  {}",
        "type".bright_black(),
        "`help`".bright_white().bold()
    );
    println!(
        "{}",
        "  ──────────────────────────────────────────────────────────────────────────────".bright_black()
    );
    println!();
}

fn print_prompt() {
    print!(
        "  {}{}{} ",
        "hakam".bright_red().bold(),
        "@".bright_black(),
        "kernel ▸".bright_red().bold(),
    );
    let _ = io::stdout().flush();
}

fn print_block_deployed(target: &str) {
    println!();
    println!(
        "  {}  {}  {}",
        "▼ BLOCK".bright_red().bold().on_black(),
        target.bright_white().bold(),
        "→ XDP_DROP".bright_red(),
    );
    println!(
        "  {}  {}",
        "   └─".bright_black(),
        "all matching packets dropped at the driver edge".bright_black(),
    );
    println!();
}

fn print_unblock(target: &str) {
    println!();
    println!(
        "  {}  {}  {}",
        "▲ UNBLOCK".green().bold(),
        target.bright_white().bold(),
        "→ allow".green(),
    );
    println!(
        "  {}  {}",
        "   └─".bright_black(),
        "rule rescinded; traffic flows unimpeded".bright_black(),
    );
    println!();
}

fn print_error(msg: &str) {
    println!("  {} {}", "[ERR]".red().bold(), msg.red());
}

fn print_help() {
    let row = |cmd: &str, desc: &str| {
        println!(
            "    {:<24} {}  {}",
            cmd.bright_white().bold(),
            "·".bright_black(),
            desc.bright_black()
        );
    };

    println!();
    println!("  {}  {}", "▸".cyan().bold(), "command reference".cyan().bold());
    println!("  {}", "──────────────────────────────────────────────────────────────".bright_black());
    row("block <IP[/prefix]>", "drop all packets from/to IP or CIDR range");
    row("unblock <IP[/prefix]>", "restore traffic from/to IP or CIDR range");
    row("policy-block <IP[/prefix]>", "deny local connect() to dest at the LSM (EPERM)");
    row("policy-unblock <IP[/prefix]>", "permit connect() to dest again");
    row("policy-list", "print active connect() egress-policy rules");
    row("list", "print active block rules with age + TTL");
    row("status", "interface, hooks, signature corpus, blocklist");
    row("rules", "show DPI signature families and counts");
    row("stats", "live drops, latency p50/p99, detections per family");
    row("clear", "remove every entry from the blocklist");
    row("help, ?", "show this reference");
    row("quit, exit, q", "detach XDP + TC + tracepoint, exit cleanly");
    println!();
}

pub struct CliCtx {
    pub blocklist: Arc<Mutex<LpmTrie<MapData, u32, u64>>>,
    pub connect_policy: Arc<Mutex<LpmTrie<MapData, u32, u64>>>,
    pub telemetry: Arc<Sender>,
    pub stats: Arc<Mutex<DpiStats>>,
    pub drop_counter: Arc<Mutex<PerCpuArray<MapData, u64>>>,
    pub latency_hist: Arc<Mutex<PerCpuArray<MapData, u64>>>,
    pub ring_overflow: Arc<Mutex<PerCpuArray<MapData, u64>>>,
    pub conntrack: Arc<Mutex<AyaHashMap<MapData, [u8; 12], [u8; 24]>>>,
    pub iface: String,
    pub bpf_path: Arc<PathBuf>,
}

pub fn run_stdin_loop(ctx: CliCtx) -> Result<()> {
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    loop {
        print_prompt();

        let line = match lines.next() {
            Some(Ok(l)) => l,
            Some(Err(e)) => {
                print_error(&format!("stdin read error: {}", e));
                continue;
            }
            None => break,
        };

        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let mut parts = line.splitn(2, ' ');
        let cmd = parts.next().unwrap_or("").to_lowercase();
        let arg = parts.next().map(str::trim);

        match cmd.as_str() {
            "block" => cmd_block(&ctx, arg),
            "unblock" => cmd_unblock(&ctx, arg),
            "policy-block" => cmd_policy_block(&ctx, arg),
            "policy-unblock" => cmd_policy_unblock(&ctx, arg),
            "policy-list" => cmd_policy_list(&ctx),
            "list" => cmd_list(&ctx),
            "status" => cmd_status(&ctx),
            "rules" | "sigs" | "signatures" => cmd_rules(),
            "stats" => cmd_stats(&ctx),
            "clear" => cmd_clear(&ctx),
            "help" | "?" => print_help(),
            "quit" | "exit" | "q" => {
                println!(
                    "\n  {}  {}\n",
                    "◉".green().bold(),
                    "Detaching all hooks. Hakam going dark.".green()
                );
                break;
            }
            other => {
                print_error(&format!("Unknown command '{}'. Type 'help' for usage.", other));
            }
        }
    }
    Ok(())
}

fn cmd_block(ctx: &CliCtx, arg: Option<&str>) {
    let Some(target) = arg else {
        print_error("Usage: block <IP> or block <IP/prefix>");
        return;
    };
    match parse_cidr(target) {
        Err(e) => print_error(&e),
        Ok((ip, prefix)) => {
            let now_ns = boot_time_ns();
            let key = lpm_key(ip, prefix);
            let display = format_lpm_key(&key);
            let mut map = ctx.blocklist.blocking_lock();
            match map.insert(&key, &now_ns, 0) {
                Ok(_) => {
                    print_block_deployed(&display);
                    let _ = ctx.telemetry.send(block_json(
                        &display,
                        "Edge Proxy",
                        None,
                        "XDP_DROP",
                        Some("Manual"),
                        Some("high"),
                        None,
                        None,
                    ));
                    let _ = ctx.telemetry.send(event_json(
                        &format!("Manual block: {} → XDP_DROP", display),
                        "critical",
                    ));
                }
                Err(e) => print_error(&format!("Map insert failed: {}", e)),
            }
        }
    }
}

fn cmd_unblock(ctx: &CliCtx, arg: Option<&str>) {
    let Some(target) = arg else {
        print_error("Usage: unblock <IP> or unblock <IP/prefix>");
        return;
    };
    match parse_cidr(target) {
        Err(e) => print_error(&e),
        Ok((ip, prefix)) => {
            let key = lpm_key(ip, prefix);
            let display = format_lpm_key(&key);
            let mut map = ctx.blocklist.blocking_lock();
            match map.remove(&key) {
                Ok(_) => {
                    print_unblock(&display);
                    let _ = ctx.telemetry.send(unblock_json(&display));
                    let _ = ctx.telemetry.send(event_json(
                        &format!("Block rescinded: {} restored", display),
                        "info",
                    ));
                }
                Err(e) => print_error(&format!("Map remove failed: {}", e)),
            }
        }
    }
}

// ── connect() egress policy (Arsenal roadmap Phase 2 #6) ────────────────────
// These manage CONNECT_POLICY, which the BPF-LSM socket_connect hook consults.
// A listed destination causes a local process's connect() to fail with EPERM —
// the syscall is denied, distinct from the XDP/TC path which drops packets.

fn cmd_policy_block(ctx: &CliCtx, arg: Option<&str>) {
    let Some(target) = arg else {
        print_error("Usage: policy-block <IP> or policy-block <IP/prefix>");
        return;
    };
    match parse_cidr(target) {
        Err(e) => print_error(&e),
        Ok((ip, prefix)) => {
            let now_ns = boot_time_ns();
            let key = lpm_key(ip, prefix);
            let display = format_lpm_key(&key);
            let mut map = ctx.connect_policy.blocking_lock();
            match map.insert(&key, &now_ns, 0) {
                Ok(_) => {
                    println!(
                        "\n  {}  {}  {}\n",
                        "▼ LSM POLICY".bright_red().bold().on_black(),
                        display.bright_white().bold(),
                        "→ connect() denied at syscall".bright_red(),
                    );
                    let _ = ctx.telemetry.send(event_json(
                        &format!("LSM policy: connect() to {} now denied (EPERM)", display),
                        "critical",
                    ));
                }
                Err(e) => print_error(&format!("Policy map insert failed: {}", e)),
            }
        }
    }
}

fn cmd_policy_unblock(ctx: &CliCtx, arg: Option<&str>) {
    let Some(target) = arg else {
        print_error("Usage: policy-unblock <IP> or policy-unblock <IP/prefix>");
        return;
    };
    match parse_cidr(target) {
        Err(e) => print_error(&e),
        Ok((ip, prefix)) => {
            let key = lpm_key(ip, prefix);
            let display = format_lpm_key(&key);
            let mut map = ctx.connect_policy.blocking_lock();
            match map.remove(&key) {
                Ok(_) => {
                    println!(
                        "\n  {}  {}  {}\n",
                        "▲ LSM POLICY".green().bold(),
                        display.bright_white().bold(),
                        "→ connect() permitted again".green(),
                    );
                    let _ = ctx.telemetry.send(event_json(
                        &format!("LSM policy: connect() to {} permitted again", display),
                        "info",
                    ));
                }
                Err(e) => print_error(&format!("Policy map remove failed: {}", e)),
            }
        }
    }
}

fn cmd_policy_list(ctx: &CliCtx) {
    let map = ctx.connect_policy.blocking_lock();
    let entries: Vec<(Key<u32>, u64)> = map.iter().filter_map(|r| r.ok()).collect();
    drop(map);

    println!();
    if entries.is_empty() {
        println!(
            "  {}  {}",
            "▸".bright_black(),
            "connect() policy is empty — no destinations denied".bright_black()
        );
    } else {
        println!(
            "  {}  {}",
            "▸".bright_red().bold(),
            format!("{} destination(s) denied at connect()", entries.len())
                .bright_white()
                .bold(),
        );
        for (key, _) in &entries {
            println!("    {}  {}", "•".bright_red(), format_lpm_key(key).bright_white());
        }
    }
    println!();
}

fn cmd_list(ctx: &CliCtx) {
    let map = ctx.blocklist.blocking_lock();
    let entries: Vec<(Key<u32>, u64)> = map.iter().filter_map(|r| r.ok()).collect();
    drop(map);

    println!();
    if entries.is_empty() {
        println!(
            "  {}  {}",
            "▸".bright_black(),
            "blocklist is empty".bright_black()
        );
    } else {
        let now_ns = boot_time_ns();
        println!(
            "  {}  {}  {}",
            "▸".bright_red().bold(),
            "active blocklist".bright_red().bold(),
            format!("({} entries)", entries.len()).bright_black(),
        );
        println!("  {}", "──────────────────────────────────────────────────────────────".bright_black());
        println!(
            "    {:<22} {:<14} {:>8} {:>8}",
            "TARGET".bright_black(),
            "ACTION".bright_black(),
            "AGE".bright_black(),
            "TTL".bright_black(),
        );
        for (key, insert_ns) in &entries {
            let target = format_lpm_key(key);
            let age_secs = now_ns.saturating_sub(*insert_ns) / 1_000_000_000;
            let ttl_left = BLOCK_TTL_SECS.saturating_sub(age_secs);
            println!(
                "    {:<22} {:<14} {:>7}s {:>7}s",
                target.bright_white().bold(),
                "XDP_DROP".red(),
                age_secs.to_string().yellow(),
                ttl_left.to_string().bright_black(),
            );
        }
    }
    println!();
}

fn cmd_status(ctx: &CliCtx) {
    let map = ctx.blocklist.blocking_lock();
    let count = map.iter().filter(|r| r.is_ok()).count();
    drop(map);

    let row = |k: &str, v: colored::ColoredString| {
        println!(
            "  {}  {:<14} {}  {}",
            "│".bright_black(),
            k.bright_black(),
            "·".bright_black(),
            v
        );
    };

    println!();
    println!("  {}  {}", "▸".green().bold(), "hakam-node status".green().bold());
    println!("  {}", "──────────────────────────────────────────────────────────────".bright_black());
    row("interface", ctx.iface.bright_white().bold());
    row("bpf elf", ctx.bpf_path.display().to_string().cyan());
    row("hooks", "XDP · TC egress · sys_enter_connect tracepoint".cyan());
    row("rate limit", "500 pkt/s per src IP (1 s window)".cyan());
    row("block TTL", format!("{} s", BLOCK_TTL_SECS).cyan());
    row(
        "signatures",
        format!(
            "{} patterns / {} families",
            signatures::SIGNATURES.len(),
            signatures::CATEGORIES.len()
        )
        .cyan(),
    );
    row(
        "blocklist",
        if count == 0 {
            "empty".bright_black()
        } else {
            format!("{} entries", count).bright_red().bold()
        },
    );
    println!();
}

fn cmd_rules() {
    println!();
    println!(
        "  {}  {}  {}",
        "▸".magenta().bold(),
        "DPI signature corpus".magenta().bold(),
        format!("({} patterns)", signatures::SIGNATURES.len()).bright_black(),
    );
    println!("  {}", "──────────────────────────────────────────────────────────────".bright_black());
    for (cat, n) in signatures::category_counts() {
        let bar: String = std::iter::repeat('█').take(n.min(40)).collect();
        println!(
            "    {:<11} {:>3}  {}",
            cat.bright_white().bold(),
            n.to_string().bright_yellow(),
            bar.bright_red(),
        );
    }
    println!();
}

fn cmd_stats(ctx: &CliCtx) {
    let dropped: u64 = {
        let m = ctx.drop_counter.blocking_lock();
        m.get(&0u32, 0).map(|v| v.iter().sum()).unwrap_or(0)
    };
    let (p50, p99) = {
        let m = ctx.latency_hist.blocking_lock();
        read_latency_percentiles(&m)
    };
    let ring_overflows: u64 = {
        let m = ctx.ring_overflow.blocking_lock();
        m.get(&0u32, 0).map(|v| v.iter().sum()).unwrap_or(0)
    };
    // Live kernel conntrack table size — the Phase 2 #7 exit-criterion number.
    let active_flows: u64 = {
        let m = ctx.conntrack.blocking_lock();
        m.keys().filter(|k| k.is_ok()).count() as u64
    };
    let stats = ctx.stats.blocking_lock();

    println!();
    println!("  {}  {}", "▸".bright_yellow().bold(), "live counters".bright_yellow().bold());
    println!("  {}", "──────────────────────────────────────────────────────────────".bright_black());
    println!("    {:<22} {}", "active flows".bright_black(), active_flows.to_string().bright_cyan().bold());
    println!("    {:<22} {}", "kernel drops".bright_black(), dropped.to_string().bright_red().bold());
    println!("    {:<22} {}", "drop latency p50".bright_black(), format!("{} ns", p50).cyan());
    println!("    {:<22} {}", "drop latency p99".bright_black(), format!("{} ns", p99).cyan());
    let benign_passed = stats.total_http_seen.saturating_sub(stats.total_detections);
    println!("    {:<22} {}", "HTTP seen".bright_black(), stats.total_http_seen.to_string().cyan());
    println!("    {:<22} {}", "benign passed".bright_black(), benign_passed.to_string().bright_green().bold());
    println!("    {:<22} {}", "DPI detections".bright_black(), stats.total_detections.to_string().bright_yellow().bold());
    println!("    {:<22} {}", "reassembly flows".bright_black(), stats.reassembly_flows.to_string().cyan());
    println!("    {:<22} {}", "retransmits dropped".bright_black(), stats.retransmit_dropped.to_string().cyan());
    println!("    {:<22} {}", "out-of-order segs".bright_black(), stats.out_of_order.to_string().cyan());
    let overflow_color = if ring_overflows == 0 {
        ring_overflows.to_string().bright_green().bold()
    } else {
        ring_overflows.to_string().bright_red().bold()
    };
    println!("    {:<22} {}", "ring overflows".bright_black(), overflow_color);

    if !stats.by_category.is_empty() {
        println!();
        println!("  {}  {}", "└─".bright_black(), "by family".bright_black());
        let mut rows: Vec<(&&str, &u64)> = stats.by_category.iter().collect();
        rows.sort_by(|a, b| b.1.cmp(a.1));
        for (cat, n) in rows {
            println!(
                "      {:<14} {}",
                cat.bright_white(),
                n.to_string().bright_yellow().bold(),
            );
        }
    }
    println!();
}

fn cmd_clear(ctx: &CliCtx) {
    let mut map = ctx.blocklist.blocking_lock();
    let keys: Vec<Key<u32>> = map.iter().filter_map(|r| r.ok()).map(|(k, _)| k).collect();
    let n = keys.len();
    for k in &keys {
        let _ = map.remove(k);
        let _ = ctx.telemetry.send(unblock_json(&format_lpm_key(k)));
    }
    drop(map);
    println!();
    println!(
        "  {}  {}  {}",
        "◉".green().bold(),
        "BLOCKLIST CLEARED".green().bold(),
        format!("({} entries removed)", n).bright_black()
    );
    let _ = ctx.telemetry.send(event_json(
        &format!("Blocklist cleared: {} entries removed", n),
        "info",
    ));
    println!();
}
