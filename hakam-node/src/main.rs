// hakam-node — userspace controller for the Hakam eBPF firewall.
// Loads hakam-ebpf into the kernel, attaches XDP + TC + tracepoint hooks,
// then runs concurrent telemetry, DPI, connect-event, TTL-sweep, and demo-cmd
// tasks. The CLI stdin loop runs on a blocking thread so it never stalls the
// async runtime.

#[cfg(feature = "linux")]
mod cli;
#[cfg(feature = "linux")]
mod dpi;
#[cfg(feature = "linux")]
mod maintenance;
#[cfg(feature = "linux")]
mod metrics;
#[cfg(feature = "linux")]
mod telemetry;

#[cfg(feature = "linux")]
use std::sync::Arc;

#[cfg(feature = "linux")]
use anyhow::{bail, Context, Result};
#[cfg(feature = "linux")]
use aya::{
    maps::{Array, LpmTrie, PerCpuArray, RingBuf},
    programs::{
        tc::{qdisc_add_clsact, TcAttachType},
        SchedClassifier, TracePoint, Xdp, XdpFlags,
    },
    Ebpf,
};
#[cfg(feature = "linux")]
use aya_log::EbpfLogger;
#[cfg(feature = "linux")]
use clap::Parser;
#[cfg(feature = "linux")]
use colored::Colorize;
#[cfg(feature = "linux")]
use log::{error, info, warn};
#[cfg(feature = "linux")]
use tokio::{
    io::unix::AsyncFd,
    sync::{broadcast, oneshot, Mutex},
    task,
};

#[cfg(feature = "linux")]
use hakam_node::monitor::pack_monitor_cfg;

#[cfg(feature = "linux")]
use crate::{
    cli::{parse_cidr, Args, CliCtx},
    dpi::DpiStats,
};

#[cfg(feature = "linux")]
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    env_logger::Builder::new()
        .filter_level(args.log_level.parse().unwrap_or(log::LevelFilter::Info))
        .format_timestamp(None)
        .format_module_path(false)
        .init();

    cli::print_banner();

    let bpf_path = args.bpf_path.canonicalize().with_context(|| {
        format!(
            "eBPF ELF not found at '{}'\nRun `cargo xtask run` to build and launch.",
            args.bpf_path.display()
        )
    })?;

    let mut bpf = Ebpf::load_file(&bpf_path)
        .with_context(|| format!("Failed to load eBPF ELF from '{}'", bpf_path.display()))?;

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("BPF kernel logger unavailable (non-fatal): {}", e);
    }

    attach_xdp(&mut bpf, &args, &bpf_path)?;
    attach_tc(&mut bpf, &args.iface)?;
    attach_tracepoint(&mut bpf)?;

    println!();

    // ── Take maps from eBPF object for userspace access ────────────────────
    let blocklist: LpmTrie<_, u32, u64> = LpmTrie::try_from(
        bpf.take_map("BLOCKLIST")
            .context("Map 'BLOCKLIST' not found — is hakam-ebpf up to date?")?,
    )
    .context("Failed to interpret 'BLOCKLIST' as LpmTrie<u32, u64>")?;
    let blocklist = Arc::new(Mutex::new(blocklist));

    let drop_counter: PerCpuArray<_, u64> = PerCpuArray::try_from(
        bpf.take_map("DROP_COUNTER").context("Map 'DROP_COUNTER' not found")?,
    )
    .context("Failed to interpret 'DROP_COUNTER' as PerCpuArray<u64>")?;
    let drop_counter = Arc::new(Mutex::new(drop_counter));

    let latency_hist: PerCpuArray<_, u64> = PerCpuArray::try_from(
        bpf.take_map("LATENCY_HIST").context("Map 'LATENCY_HIST' not found")?,
    )
    .context("Failed to interpret 'LATENCY_HIST' as PerCpuArray<u64>")?;
    let latency_hist = Arc::new(Mutex::new(latency_hist));

    let ring_overflow: PerCpuArray<_, u64> = PerCpuArray::try_from(
        bpf.take_map("RING_OVERFLOW")
            .context("Map 'RING_OVERFLOW' not found — rebuild eBPF with cargo xtask build-ebpf")?,
    )
    .context("Failed to interpret 'RING_OVERFLOW' as PerCpuArray<u64>")?;
    let ring_overflow = Arc::new(Mutex::new(ring_overflow));

    let payload_ring: RingBuf<_> = RingBuf::try_from(
        bpf.take_map("PAYLOAD_EVENTS").context("Map 'PAYLOAD_EVENTS' not found")?,
    )
    .context("Failed to interpret 'PAYLOAD_EVENTS' as RingBuf")?;

    let connect_ring: RingBuf<_> = RingBuf::try_from(
        bpf.take_map("CONNECT_EVENTS").context("Map 'CONNECT_EVENTS' not found")?,
    )
    .context("Failed to interpret 'CONNECT_EVENTS' as RingBuf")?;

    if let Some(prefix_str) = args.monitor_prefix.as_deref() {
        let (network, prefix_len) = parse_cidr(prefix_str)
            .map_err(|e| anyhow::anyhow!("--monitor-prefix: {e}"))?;
        let mut monitor_cfg: Array<_, u64> = Array::try_from(
            bpf.take_map("MONITOR_CFG")
                .context("Map 'MONITOR_CFG' not found — rebuild eBPF with cargo xtask build-ebpf")?,
        )
        .context("Failed to interpret 'MONITOR_CFG' as Array<u64>")?;
        monitor_cfg
            .set(0, pack_monitor_cfg(network, prefix_len), 0)
            .context("Failed to write MONITOR_CFG[0]")?;
        info!("Tracepoint scoped to {}/{}", network, prefix_len);
        println!(
            "  {}  {} {} {}",
            "◉".bright_blue().bold(),
            "tracepoint scope".bright_blue().bold(),
            "→".bright_black(),
            format!("{}/{}", network, prefix_len).cyan(),
        );
    }

    // ── Spawn async tasks ──────────────────────────────────────────────────
    let (telemetry_tx, _) = broadcast::channel::<String>(512);
    let telemetry_tx = Arc::new(telemetry_tx);
    let dpi_stats = Arc::new(Mutex::new(DpiStats::default()));

    tokio::spawn({
        let tx = (*telemetry_tx).clone();
        let port = args.ws_port;
        let bind_addr = args.bind;
        async move { telemetry::run_ws_server(tx, port, bind_addr).await }
    });

    tokio::spawn(metrics::ticker(
        (*telemetry_tx).clone(),
        Arc::clone(&drop_counter),
        Arc::clone(&latency_hist),
        Arc::clone(&ring_overflow),
        args.iface.clone(),
    ));

    tokio::spawn(dpi::payload_task(
        AsyncFd::new(payload_ring).context("AsyncFd for PAYLOAD_EVENTS failed")?,
        Arc::clone(&blocklist),
        (*telemetry_tx).clone(),
        Arc::clone(&dpi_stats),
    ));

    tokio::spawn(dpi::connect_task(
        AsyncFd::new(connect_ring).context("AsyncFd for CONNECT_EVENTS failed")?,
        (*telemetry_tx).clone(),
    ));

    tokio::spawn(maintenance::ttl_sweep_task(
        Arc::clone(&blocklist),
        (*telemetry_tx).clone(),
    ));

    tokio::spawn(maintenance::server_cmd_task(
        Arc::clone(&blocklist),
        (*telemetry_tx).clone(),
    ));

    // ── Shutdown listener ──────────────────────────────────────────────────
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        if let Err(e) = tokio::signal::ctrl_c().await {
            error!("Failed to listen for Ctrl-C: {}", e);
            return;
        }
        println!(
            "\n\n  {} {}\n  {} {}",
            "[!]".yellow().bold(),
            "SIGINT — detaching all kernel hooks…".yellow(),
            "◉".green(),
            "Hakam-Node terminated. Ghost mode: OFF.".green().bold()
        );
        println!();
        let _ = shutdown_tx.send(());
    });

    // ── CLI stdin loop ─────────────────────────────────────────────────────
    let ctx = CliCtx {
        blocklist: Arc::clone(&blocklist),
        telemetry: Arc::clone(&telemetry_tx),
        stats: Arc::clone(&dpi_stats),
        drop_counter: Arc::clone(&drop_counter),
        latency_hist: Arc::clone(&latency_hist),
        ring_overflow: Arc::clone(&ring_overflow),
        iface: args.iface.clone(),
        bpf_path: Arc::new(bpf_path),
    };

    let stdin_task = task::spawn_blocking(move || cli::run_stdin_loop(ctx));

    tokio::select! {
        res = stdin_task => {
            if let Ok(Err(e)) = res {
                error!("CLI error: {}", e);
            }
        }
        _ = &mut shutdown_rx => {}
    }

    info!("All hooks detached from '{}'. Goodbye.", &args.iface);
    Ok(())
}

#[cfg(feature = "linux")]
fn attach_xdp(bpf: &mut Ebpf, args: &Args, bpf_path: &std::path::Path) -> Result<()> {
    let xdp_prog: &mut Xdp = bpf
        .program_mut("hakam_ebpf")
        .context("BPF program 'hakam_ebpf' not found — run: cargo xtask build-ebpf")?
        .try_into()
        .context("'hakam_ebpf' is not of type XDP")?;

    xdp_prog.load().context(
        "Failed to load XDP program — are you running as root with CAP_BPF + CAP_NET_ADMIN?",
    )?;

    xdp_prog.attach(&args.iface, args.mode).with_context(|| {
        format!("Failed to attach XDP to '{}' — is the interface UP?", &args.iface)
    })?;

    let mode_str = if args.mode.bits() == XdpFlags::SKB_MODE.bits() {
        "SKB (generic)"
    } else if args.mode.bits() == XdpFlags::DRV_MODE.bits() {
        "Driver"
    } else if args.mode.bits() == XdpFlags::HW_MODE.bits() {
        "Hardware offload"
    } else {
        "Auto"
    };
    cli::print_attached(&args.iface, mode_str, bpf_path);
    info!("XDP program attached to '{}'", &args.iface);
    Ok(())
}

#[cfg(feature = "linux")]
fn attach_tc(bpf: &mut Ebpf, iface: &str) -> Result<()> {
    if let Err(e) = qdisc_add_clsact(iface) {
        let msg = format!("{:?}", e);
        // EEXIST (17) just means the qdisc is already present.
        if !msg.contains("17") && !msg.contains("xist") {
            bail!("qdisc_add_clsact on '{}': {}", iface, e);
        }
        info!("clsact qdisc already present on '{}', reusing.", iface);
    }

    let tc_prog: &mut SchedClassifier = bpf
        .program_mut("hakam_egress")
        .context("BPF program 'hakam_egress' not found — rebuild with cargo xtask build-ebpf")?
        .try_into()
        .context("'hakam_egress' is not of type SchedClassifier")?;

    tc_prog.load().context("Failed to load TC egress program")?;
    tc_prog
        .attach(iface, TcAttachType::Egress)
        .with_context(|| format!("Failed to attach TC egress to '{}'", iface))?;

    info!("TC egress attached to '{}'", iface);
    println!(
        "  {}  {} {} {}",
        "◉".bright_red().bold(),
        "TC".bright_red().bold(),
        "armed on".bright_black(),
        format!("[{}] — outbound exfiltration killed at the NIC", iface).bright_black(),
    );
    Ok(())
}

#[cfg(feature = "linux")]
fn attach_tracepoint(bpf: &mut Ebpf) -> Result<()> {
    let tp_prog: &mut TracePoint = bpf
        .program_mut("hakam_connect")
        .context("BPF program 'hakam_connect' not found — rebuild with cargo xtask build-ebpf")?
        .try_into()
        .context("'hakam_connect' is not of type TracePoint")?;

    tp_prog.load().context("Failed to load tracepoint program")?;

    match tp_prog.attach("syscalls", "sys_enter_connect") {
        Ok(_) => {
            println!(
                "  {}  {} {} {}",
                "◉".bright_blue().bold(),
                "tracepoint".bright_blue().bold(),
                "armed".bright_black(),
                "— process-aware outbound connect() monitoring".bright_black(),
            );
        }
        Err(e) => {
            warn!(
                "sys_enter_connect tracepoint unavailable ({}); process monitoring disabled.",
                e
            );
            println!(
                "  {}  {} {}",
                "◈".yellow(),
                "tracepoint".yellow(),
                "unavailable — process monitoring disabled".bright_black(),
            );
        }
    }
    Ok(())
}

#[cfg(not(feature = "linux"))]
fn main() {
    eprintln!("hakam-node requires Linux and must be built with --features linux.");
    eprintln!("  cargo xtask run");
    std::process::exit(1);
}
