# Hakam

**Kernel-resident HTTP threat interceptor built on eBPF.**  
XDP drops attacks before a socket buffer is ever allocated. A userspace DPI engine matches 203 signatures across 12 attack families and auto-blocks attackers in the kernel map. A real-time browser HUD shows every block, live.

![Hakam HUD](demo/hakam-hud.thumbnail.png)
<!-- replace with a real screenshot once demo/hakam-hud.mp4 is recorded -->

---

## How it works

```
  NIC / veth
    │
    ▼
 [XDP hook]  ◄─ hakam-ebpf (kernel, no_std)
    │  • BLOCKLIST lookup (LPM trie)  → XDP_DROP  ← no sk_buff ever allocated
    │  • per-IP rate limit (500 pps)  → auto-block
    │  • sample first 64 B of TCP     → PAYLOAD_EVENTS ring buffer
    │
    ▼  XDP_PASS
  kernel network stack
    │
 [TC egress]  ← blocks reverse shells / exfil on the way OUT
    │
    ▼
 hakam-node  (userspace, tokio)
    • reads PAYLOAD_EVENTS ring buffer
    • 203-pattern HTTP DPI  →  match → push IP into BLOCKLIST map
    • interactive CLI: block / unblock / stats / clear
    • WebSocket server → browser HUD
```

The string match is in **userspace** (verifier won't allow loops + string lib in BPF).  
The **drop** is in the kernel — attacker traffic never reaches the TCP stack after the first hit.

---

## Performance

Measured on a `veth` pair in native-mode XDP (closest to a real NIC inside a VM).  
All numbers are wall-clock deltas — baseline vs. Hakam attached, same workload.

| Workload | Throughput | CPU (no Hakam) | CPU (Hakam) | Overhead |
|----------|:----------:|:----------------:|:-------------:|:--------:|
| Flood (UDP, line rate) | 180 k pps | 4.31 % | 4.58 % | **+0.27 %** |
| DPI (HTTP SQLi payloads) | 15 pps | 0.32 % | 0.37 % | **+0.05 %** |

Drop latency (XDP pre-stack): **~45–50 ns** per packet.  
Raw CSVs: [`bench/results/`](bench/results/) · Reproduce: [`bench/README.md`](bench/README.md)

---

## Signatures

203 patterns across 12 families — all matched case-insensitively against the first 64 bytes of each TCP segment.

| Family | Examples |
|--------|---------|
| SQLi | `UNION SELECT`, `' OR '`, `DROP TABLE`, `WAITFOR DELAY` |
| XSS | `<SCRIPT`, `JAVASCRIPT:`, `ONERROR=`, `<IFRAME` |
| RCE | `;WHOAMI`, `\|/BIN/SH`, `BASH -C`, `$(CAT` |
| LFI | `../`, `..%2F`, `%2E%2E%2F`, `/ETC/PASSWD` |
| SSRF | `FILE://`, `DICT://`, `GOPHER://` |
| Log4Shell | `${JNDI:` |
| + 6 more | XXE, NoSQLi, SSTI, WebShell, Recon, CVE |

---

## Quick start

```bash
# ── VM (Linux) ─────────────────────────────────────────────────────────────
git clone https://github.com/realozk/hakam.git && cd hakam

# One-time: boot the demo network
./scripts/setup-demo.sh          # creates dummy0, adds 31 IP aliases

# Build eBPF + launch hakam-node (requires nightly + bpf-linker)
# XDP attaches to `lo` because local-to-local traffic between dummy0 IP aliases
# routes via loopback in the Linux kernel — that's where the packets actually flow.
cargo xtask run --iface lo --mode skb

# ── Mac (separate terminal) ────────────────────────────────────────────────
cd hakam-ui && npm install && npm run dev
# Open http://localhost:5173 in a browser

# ── Fire attacks (VM, third terminal) ──────────────────────────────────────
./scripts/demo-cycle.sh          # narrated 6-phase cycle, ~113 s per loop
```

Full walkthrough with screenshots and troubleshooting: [`start_guide.md`](start_guide.md)  
Pre-stage health check: `./scripts/preflight.sh`

---

## Known gaps

Hakam is a signature-based inline DPI engine — not a WAF. Honest limitations:

- **No URL decoding** — `UNION%20SELECT` (space encoded) evades SQLi signatures. Exception: common LFI path-traversal encodings (`..%2F`, `%2E%2E%2F`, `%252E%252E`) are explicit signatures.
- **64-byte capture window** — attacks that start after the first 64 bytes of a TCP segment (long path prefix, POST body) are invisible.
- **Single-segment only** — a multi-packet attack split across TCP segment boundaries evades all signatures.
- **ASCII uppercase only** — Unicode homoglyphs and fullwidth characters are not normalised.

Evasion corpus (30 mutations, honest HIT/MISS table): [`docs/evasion.md`](docs/evasion.md)

---

## Repository layout

```
hakam-common/   shared no_std types (PayloadEvent, PAYLOAD_LEN)
hakam-ebpf/     kernel BPF program — XDP + TC + rate limit + ring buffer
hakam-node/     userspace — DPI engine, CLI, WebSocket server
hakam-ui/       browser HUD — React + Tailwind + WebSocket client
xtask/            build automation (cargo xtask run / build-ebpf)
scripts/          demo, bench, preflight, evasion test
docs/             architecture, codebase, evasion analysis, scripts reference
bench/            benchmark rig and raw CSV results
```

---

## Build requirements

**VM (Linux ≥ 5.15):**
```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker          # needs LLVM ≥ 14
```

**Mac:**
```bash
node --version   # ≥ 18
# Rust stable for Tauri — installed automatically via hakam-ui/src-tauri
```

---

## Architecture · Codebase deep-dive · Runtime flow

- [`docs/architecture.md`](docs/architecture.md) — kernel/userspace boundary diagram, map table, hook table
- [`docs/codebase.md`](docs/codebase.md) — per-file walkthrough, eBPF verifier notes
- [`docs/runtime_flow.md`](docs/runtime_flow.md) — packet lifecycle from NIC to block event

---

## License

MIT
