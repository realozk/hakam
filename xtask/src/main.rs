use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name  = "xtask",
    about = "Build automation for hakam-node (aya-rs XDP firewall)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    BuildEbpf {
        #[arg(long)]
        release: bool,
    },

    Run {
        #[arg(long)]
        release: bool,

        #[arg(long)]
        iface: Option<String>,

        #[arg(long, default_value = "skb")]
        mode: String,

        #[arg(long, default_value = "127.0.0.1")]
        bind: String,
    },

    Check,

    Test,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::BuildEbpf { release } => build_ebpf(release),
        Commands::Run { release, iface, mode, bind } => {
            let iface = match iface {
                Some(i) => i,
                None    => auto_detect_iface()?,
            };
            run(release, &iface, &mode, &bind)
        }
        Commands::Check => check(),
        Commands::Test  => test(),
    }
}

fn build_ebpf(release: bool) -> Result<()> {
    let workspace = workspace_root()?;
    eprintln!("[xtask] Building hakam-ebpf (release={}) …", release);

    let mut cargo = Command::new("cargo");
    cargo
        .arg("+nightly")
        .arg("build")
        .arg("-Z")
        .arg("build-std=core")
        .arg("--target")
        .arg("bpfel-unknown-none")
        .arg("--package")
        .arg("hakam-ebpf")
        .arg("--release")
        .current_dir(&workspace);

    let status = cargo
        .status()
        .context("Failed to spawn `cargo build` for hakam-ebpf. Ensure bpf-linker is installed.")?;

    if !status.success() {
        bail!(
            "hakam-ebpf build failed (exit {:?}).\n\
             • Install bpf-linker: cargo install bpf-linker\n\
             • Install nightly:    rustup toolchain install nightly --component rust-src",
            status.code()
        );
    }

    let elf = workspace
        .join("target")
        .join("bpfel-unknown-none")
        .join("release")
        .join("hakam-ebpf");

    eprintln!("[xtask] ✓ eBPF ELF: {}", elf.display());
    Ok(())
}

fn auto_detect_iface() -> Result<String> {
    let output = Command::new("ip")
        .args(["route", "get", "1.1.1.1"])
        .output();

    if let Ok(out) = output {
        let text = String::from_utf8_lossy(&out.stdout);
        let words: Vec<&str> = text.split_whitespace().collect();
        for i in 0..words.len() {
            if words[i] == "dev" {
                if let Some(iface) = words.get(i + 1) {
                    let iface = iface.to_string();
                    eprintln!("[xtask] Auto-detected interface: {}", iface);
                    return Ok(iface);
                }
            }
        }
    }

    eprintln!("[xtask] WARNING: could not auto-detect interface, falling back to eth0");
    eprintln!("[xtask] Tip: run with --iface <name> to specify it explicitly.");
    Ok("eth0".to_string())
}

fn run(release: bool, iface: &str, mode: &str, bind: &str) -> Result<()> {
    build_ebpf(release)?;

    let workspace = workspace_root()?;
    eprintln!("[xtask] Building hakam-node (release={}) …", release);

    let mut cargo = Command::new("cargo");
    cargo
        .arg("build")
        .arg("--package")
        .arg("hakam-node")
        .arg("--features")
        .arg("linux")
        .current_dir(&workspace);

    if release {
        cargo.arg("--release");
    }

    let status = cargo
        .status()
        .context("Failed to spawn `cargo build` for hakam-node")?;

    if !status.success() {
        bail!("hakam-node build failed (exit {:?})", status.code());
    }

    let profile  = if release { "release" } else { "debug" };
    let bin_path = workspace.join("target").join(profile).join("hakam-node");

    let bpf_path = workspace
        .join("target")
        .join("bpfel-unknown-none")
        .join("release")
        .join("hakam-ebpf");

    eprintln!("[xtask] Clearing any stale XDP hook on '{}'…", iface);
    let _ = Command::new("sudo")
        .args(["ip", "link", "set", "dev", iface, "xdp", "off"])
        .status();

    eprintln!("[xtask] Clearing any stale TC clsact qdisc on '{}'…", iface);
    let _ = Command::new("sudo")
        .args(["tc", "qdisc", "del", "dev", iface, "clsact"])
        .status();

    eprintln!(
        "[xtask] Launching hakam-node on '{}' via sudo …\n\
         ─────────────────────────────────────────────────────",
        iface
    );

    let status = Command::new("sudo")
        .arg(&bin_path)
        .arg("--iface")
        .arg(iface)
        .arg("--mode")
        .arg(mode)
        .arg("--bind")
        .arg(bind)
        .arg("--bpf-path")
        .arg(&bpf_path)
        .current_dir(&workspace)
        .status()
        .context("Failed to spawn hakam-node via sudo.")?;

    if !status.success() {
        bail!("hakam-node exited with code {:?}", status.code());
    }

    Ok(())
}

fn check() -> Result<()> {
    let workspace = workspace_root()?;
    eprintln!("[xtask] Running cargo check …");

    let status = Command::new("cargo")
        .args(["check", "--workspace", "--exclude", "hakam-ebpf"])
        .current_dir(&workspace)
        .status()
        .context("Failed to run cargo check")?;

    if !status.success() {
        bail!("cargo check failed");
    }
    eprintln!("[xtask] ✓ cargo check passed");
    Ok(())
}

fn test() -> Result<()> {
    let workspace = workspace_root()?;
    eprintln!("[xtask] Running unit tests …");

    let status = Command::new("cargo")
        .args(["test", "--workspace", "--exclude", "hakam-ebpf"])
        .current_dir(&workspace)
        .status()
        .context("Failed to run cargo test")?;

    if !status.success() {
        bail!("cargo test failed");
    }
    eprintln!("[xtask] ✓ All tests passed");
    Ok(())
}

fn workspace_root() -> Result<PathBuf> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest_dir)
        .parent()
        .map(PathBuf::from)
        .context("xtask Cargo.toml has no parent directory")
}
