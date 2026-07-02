# Hakam

Hakam is a kernel-level HTTP threat interceptor I built on top of eBPF. The idea is simple: drop attacks before they ever reach the network stack. No socket buffer gets allocated, no userspace overhead — the kernel just kills the packet at the XDP hook and moves on.

A userspace engine running alongside it does the heavy lifting for deep packet inspection — matching 202 signatures across 13 attack families — and when something hits, it pushes the attacker's IP directly into a kernel map to block all future traffic. There's also a browser HUD that shows everything in real time.

![Hakam HUD](demo/hakam-hud.thumbnail.png)

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
    • 202-pattern DPI  →  match → push IP into BLOCKLIST map
    • interactive CLI: block / unblock / stats / clear
    • WebSocket server → browser HUD
```

The string matching happens in **userspace** because the BPF verifier doesn't allow loops or string libraries in kernel programs. But the actual **drop** happens in the kernel — once an attacker is blocked, their traffic never touches the TCP stack again.

---

## Performance

Tested on a `veth` pair in native-mode XDP — the closest you can get to a real NIC inside a VM. Numbers are wall-clock deltas comparing baseline vs. Hakam attached under the same workload.

| Workload | Throughput | CPU (no Hakam) | CPU (Hakam) | Overhead |
|----------|:----------:|:----------------:|:-------------:|:--------:|
| Flood (UDP, line rate) | 180 k pps | 4.31 % | 4.58 % | **+0.27 %** |
| DPI (SQLi payloads) | 15 pps | 0.32 % | 0.37 % | **+0.05 %** |

Drop latency at the XDP layer sits around **~45–50 ns** per packet.  
Raw CSVs: [`bench/results/`](bench/results/) · Reproduce steps: [`bench/README.md`](bench/README.md)

---

## Signatures

202 patterns across 13 families, matched case-insensitively against the first 64 bytes of each TCP segment.

| Family | Examples |
|--------|---------|
| SQLi | `UNION SELECT`, `' OR '`, `DROP TABLE`, `WAITFOR DELAY` |
| XSS | `<SCRIPT`, `JAVASCRIPT:`, `ONERROR=`, `<IFRAME` |
| RCE | `;WHOAMI`, `\|/BIN/SH`, `BASH -C`, `$(CAT` |
| LFI | `../`, `..%2F`, `%2E%2E%2F`, `/ETC/PASSWD` |
| SSRF | `FILE://`, `DICT://`, `GOPHER://` |
| Log4Shell | `${JNDI:` |
| + 7 more | XXE, NoSQLi, SSTI, WebShell, Recon, CVE, Deserial |

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
./scripts/demo-cycle.sh          # narrated 7-phase cycle, ~4 min per loop
```

Full walkthrough with screenshots and troubleshooting: [`start_guide.md`](start_guide.md)  
Pre-stage health check: `./scripts/preflight.sh`

---

## Honest limitations

Hakam is a signature-based inline DPI engine — not a WAF. Here's what it can't do:

- **64-byte capture window per segment** — the eBPF sample is 64 bytes. Reassembly stitches segments together up to 256 bytes per flow, but bytes past that cap on a long flow are still invisible.
- **Sampled-segment reassembly** — userspace reassembles segments in TCP sequence order (the kernel conntrack stamps each sampled segment's `seq`), so out-of-order delivery and retransmits are handled. The residual: only segments ≥64 B are sampled, so a payload split across a sub-64-byte segment leaves a hole, and sequence-number wraparound mid-flow isn't special-cased.
- **ASCII case folding only** — the Aho-Corasick automaton folds A–Z ⇔ a–z, but Unicode homoglyphs and fullwidth characters are not normalised.
- **Single-pass URL decoding** — `%XX` and `+` are decoded once as a fallback (so `UNION%20SELECT` and `UNION+SELECT` both match). Double-encoded payloads like `UNION%2520SELECT` are not recursively decoded.

Full evasion corpus (30 mutations, hit/miss table): [`docs/evasion.md`](docs/evasion.md)

---

## Repository layout

```
hakam-common/   shared no_std types (PayloadEvent, PAYLOAD_LEN)
hakam-ebpf/     kernel BPF program — XDP + TC + rate limit + ring buffer
hakam-node/     userspace — DPI engine, CLI, WebSocket server
hakam-ui/       browser HUD — React + Tailwind + WebSocket client
xtask/          build automation (cargo xtask run / build-ebpf)
scripts/        demo, bench, preflight, evasion test
docs/           architecture, runtime_flow, codebase, evasion, scripts reference
bench/          benchmark rig and raw CSV results
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

## Docs

- [`docs/architecture.md`](docs/architecture.md) — kernel/userspace boundary diagram, map table, hook table
- [`docs/codebase.md`](docs/codebase.md) — per-file walkthrough, eBPF verifier notes
- [`docs/runtime_flow.md`](docs/runtime_flow.md) — packet lifecycle from NIC to block event
