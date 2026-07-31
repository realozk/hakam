# Hakam

[![CI](https://github.com/realozk/hakam/actions/workflows/ci.yml/badge.svg)](https://github.com/realozk/hakam/actions/workflows/ci.yml)
[![eBPF build](https://github.com/realozk/hakam/actions/workflows/ebpf.yml/badge.svg)](https://github.com/realozk/hakam/actions/workflows/ebpf.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **A layered eBPF host firewall in a single Rust binary.** Three kernel enforcement points on one host — packets dropped at the XDP driver hook, outbound connections denied at the `socket_connect` syscall, and every block attributed to the process that opened it.

Hakam is a single-host, single-binary firewall built on eBPF — small enough to read end to end. Getting both packet-level *and* process-level enforcement usually means adopting cluster infrastructure (an orchestrator, agents, a control plane). Hakam takes the opposite trade: three kernel enforcement points on one box.

- **The wire** — an XDP program drops blocklisted sources at the driver hook, before an `sk_buff` is ever allocated, with a per-IP rate limiter behind it.
- **The syscall** — a BPF-LSM hook on `socket_connect` returns `EPERM` on policy-violating outbound connections, so a reverse shell or exfil channel dies at `connect()` before a single packet exists.
- **The process** — a `sys_enter_connect` tracepoint plus a lightweight eBPF conntrack correlate a block back to the originating PID and process name — so you see *who* opened the flow, not just which IP.

A userspace engine closes the loop: it reassembles the TCP segments the kernel samples and matches them against 202 signatures across 13 attack families (Aho-Corasick); on a hit it pushes the attacker's IP straight into the kernel blocklist map. A browser HUD shows drops, latency, and flow state in real time. Signature DPI is a supporting layer, not the headline — see [Honest limitations](#honest-limitations).

![Hakam HUD](https://github.com/realozk/hakam/raw/main/banner.gif)


---

## How it works

```
── kernel · hakam-ebpf (no_std) ───────────────────────────────────

  OUTBOUND  connect() ─►  [BPF-LSM socket_connect]
                            • CONNECT_POLICY (LPM trie) hit → -EPERM
                            • connection never forms — no packet exists
                          [sys_enter_connect tracepoint]
                            • (pid, comm, dst) → process attribution

  INBOUND   NIC / veth ─►  [XDP hook]
                            • BLOCKLIST (LPM trie) → XDP_DROP  ← no sk_buff
                            • per-IP rate limit (500 pps) → auto-block
                            • sample first 64 B of TCP → PAYLOAD_EVENTS ring
                                  │ XDP_PASS
                            kernel network stack
                                  │
                          [TC egress]  ← kills reverse shells / exfil OUT
                                  │
── userspace · hakam-node (tokio) ┼────────────────────────────────
                                  ▼
   • reads PAYLOAD_EVENTS ring buffer
   • reassembles TCP segments in sequence order
   • 202-signature Aho-Corasick DPI  →  match → push IP into BLOCKLIST
   • correlates each block → originating PID (attribution)
   • CLI (block / policy-block / stats)  +  WebSocket → browser HUD
```

String matching runs in **userspace** — the BPF verifier forbids loops and string libraries in kernel programs. But every **enforcement** decision stays in the kernel: the XDP drop, the LSM `EPERM`, the TC egress kill. Once a source is blocked, its traffic never touches the TCP stack again.

---

## Performance

**Drop latency — read straight from the kernel.** The per-CPU `LATENCY_HIST` map times every XDP drop; these numbers are accumulated over **41.5 million** drops under sustained flood, not a self-reported average. Latency is a property of the drop path itself — a single LPM-trie lookup at the driver hook — so it holds regardless of the host it's measured on:

| Percentile | XDP drop latency |
|---|:---:|
| p50 | **48 ns** |
| p99 | **96 ns** |

`LATENCY_HIST` is a log2-bucketed histogram, so these are bucket midpoints: the median drop lands in the 32–64 ns bucket, the 99th percentile in the 64–128 ns bucket. Read live from the running node with the `stats` command. The drop lands at the driver hook — no `sk_buff` is ever allocated for a blocked packet.

**CPU under load** — three 60-second workloads, medians of 3 runs each. Measured on a `veth` pair in **native-mode (driver) XDP** inside a VM, so absolute packet rates are bound by the VM's software path — **read the baseline↔Hakam delta, not the absolute pps.** Methodology and raw CSVs: [`bench/`](bench/README.md).

| Workload | Baseline | Hakam | Reading |
|---|:---:|:---:|---|
| UDP flood | 4.9 % @ 134k pps | 5.6 % @ 166k pps | Hakam sustains *higher* pps at ~the same per-packet CPU (≈3.4 %/100k pps vs 3.7 %) — `XDP_DROP` is cheaper than the kernel's closed-port handling |
| SQLi DPI stream | 0.30 % | 0.22 % | ~18 req/s; the difference is within run-to-run noise |

A single high-rate source isn't shown as a "clean traffic" overhead figure on purpose: it trips Hakam's own 500 pps rate-limiter and auto-blocks itself within a second — real behavior, but not a PASS-path measurement.

**For context, a different tool class.** ModSecurity — an L7 WAF that parses every full request in userspace — publishes ~107k → ~808 req/s once the full OWASP CRS is loaded ([defanator/modsecurity-performance](https://github.com/defanator/modsecurity-performance/wiki)). This is *not* a head-to-head: Hakam samples the first 64 bytes per segment in the kernel instead of parsing whole requests. It's here to frame *where* the cost of inline inspection lives — and why Hakam keeps the enforcement path (drop / deny) in the kernel and the parsing sampled.

Raw CSVs: [`bench/results/`](bench/results/) · Reproduce: [`bench/README.md`](bench/README.md)

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
cargo xtask run --iface lo --mode skb --bind 0.0.0.0   # 0.0.0.0 so a HUD on another host can reach the WS

# ── Mac (separate terminal) ────────────────────────────────────────────────
cd hakam-ui && npm install
VITE_HAKAM_WS_URL=ws://<vm-ip>:8080/ws npm run dev     # point the HUD at the VM — see start_guide.md
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

---

## License

MIT — see [`LICENSE`](LICENSE).
