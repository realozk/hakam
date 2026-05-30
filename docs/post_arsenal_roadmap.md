# Hakam — Post-Arsenal Roadmap

> **Window:** 2026-08-25 (day after submission) → event week (~Dec 2026), then ongoing.
> **Purpose:** Everything that was scoped out of [`arsenal_roadmap.md`](arsenal_roadmap.md) because it doesn't fit 9 weeks, plus booth-week prep and post-event direction.

Two categories live here:

1. **§1 · Booth-week prep** — work that happens *after* submission but *before* the event. Triggered only if Arsenal accepts.
2. **§2 · Bigger architectural ideas** — items that would have been welcome in Arsenal but each take weeks. Deferred to post-event or treated as v2 research directions.

Do not touch §2 before the Arsenal submission lands.

---

## §1 · Booth-week prep (2026-09 → 2026-12)

Triggered if Arsenal accepts; skipped otherwise.

| Block | Work | Effort |
|-------|------|:------:|
| **Sep 2026** | **Live-on-site hosting**: nginx WSS proxy + auth, systemd hardening, log rotation, persistent blocklist across restarts. Stand it up early so you have months of uptime data to point to. | ~5 d |
| **Sep 2026** | **DVWA or Juice Shop swap** for `target-listener.py` — "real SQLi against a real vulnerable app, blocked." 10× the demo of synthetic IP aliases hitting a no-op socket. | ~3 d |
| **Oct 2026** | **Hostile Q&A rehearsal**. Get a kernel networking person to grill you for 60 minutes. Write down every question you can't answer cleanly. Fix the gaps. | ~3 d + reactive |
| **Oct 2026** | **Apples-to-apples ModSec/Coraza bench rig** — the version cut from Arsenal Phase 3. Now you have time to do it right: same vulnerable app, same workload, side-by-side perf + detection rate. | ~5 d |
| **Nov 2026** | **Booth demo runbook**: 5-minute script, idiot-proof, works offline. Backup screencast (the `demo/README.md` fallback). Stickers (~$40) + business cards (~$20). | ~2 d |
| **Dec 2026** | **Event week**: final dry run on day -1. Don't change anything else. Day-of: arrive early, plug in, smile. | — |

---

## §2 · Bigger architectural ideas

Ranked by payoff-per-week. Treat as research / v2 directions, not promises.

### A · AF_XDP + zero-copy userspace data path
**Effort:** 14–21 d · **Payoff:** real, but conditional

Replace the BPF RingBuf sample with AF_XDP redirect into a UMEM ring. Lets you inspect the **full packet** (not just 64 B) in userspace, with zero copy on supported NICs.

**Tradeoff:** you lose XDP_DROP-at-the-edge for redirected flows — the kernel can't drop what userspace has taken. You'd reply with a RST or re-inject. This is a real architectural change, not a feature add.

**io_uring note:** people pair these together in marketing copy, but they're orthogonal. AF_XDP already gives you a userspace ring. io_uring is for socket/file I/O. If anything, io_uring is useful for the *side channels* (log persistence, blocklist snapshot, control socket) — not the packet path.

**When to do it:** when the "64-byte window" line in `docs/evasion.md` becomes a recurring objection in feedback. Not before.

### B · Full eBPF conntrack with TCP state machine
**Effort:** 30–40 d · **Payoff:** big for the microsegmentation story

Upgrade the tight-scope conntrack from Arsenal Phase 2 #7 into a real flow tracker: `SYN_SENT`, `SYN_RECV`, `ESTABLISHED`, `FIN_WAIT_*`, `CLOSED`. NAT awareness. Per-flow rate budgets. Cilium-class.

**Tradeoff:** verifier complexity explodes. Per-flow state means careful map sizing under load (a 1M-flow box needs 1M map entries with eviction policy).

**When to do it:** when policy moves from *"block this IP"* to *"PC1 may initiate to DB but DB may not initiate to PC1."* That's the actual internal-network value prop and it needs real state.

### C · Hardware offload + SmartNIC support
**Effort:** 10–20 d (mostly debugging) · **Payoff:** marginal except for one specific story

Add `XDP_FLAGS_HW_MODE` support on Netronome Agilio or recent Mellanox/NVIDIA ConnectX. The story: *"line rate on 100 GbE with zero host CPU."*

**Tradeoff:** restricted BPF helper set on offload (no ring buffers in some cases, limited map types), and demo reproducibility dies — reviewers don't have these NICs. Only worth doing if you partner with a NIC vendor or have a specific customer demanding it.

**When to do it:** never on the critical path. If a vendor offers hardware, take it; otherwise leave it.

### D · CO-RE / BTF portability
**Effort:** 5–7 d · **Payoff:** small but legitimate

Use aya's CO-RE support so the same eBPF binary loads across kernel versions without rebuild. Today you rebuild per kernel.

**When to do it:** when you have more than one production deploy on different kernels.

### E · TLS SNI extraction (no decryption)
**Effort:** 5–7 d · **Payoff:** medium

Parse the TLS ClientHello in userspace to extract SNI before the connection is fully established. Lets the blocklist work on hostnames, not just IPs. Common in internal-network products.

**When to do it:** when egress policy needs to be hostname-based (most enterprises do).

### F · Per-rule action tiers
**Effort:** 2–3 d · **Payoff:** config sugar

Today every match drops. Add `block` / `log` / `alert` / `rate-limit` tiers per signature.

**When to do it:** when operators ask for it. Don't pre-build.

### G · YAML rule hot-reload
**Effort:** 3–4 d · **Payoff:** config sugar

Externalize signatures to YAML, reload without restart.

**When to do it:** when the signature corpus changes more than monthly. Today it's hardcoded and that's fine.

### H · Prometheus `/metrics` endpoint
**Effort:** 1–2 d · **Payoff:** observability

Replace or augment the WS telemetry feed with standard Prometheus metrics.

**When to do it:** first production deploy where someone wants to point Grafana at it.

---

## What does NOT belong here

- GUI rule editor
- IPv6 (unless it falls out for free during conntrack work)
- Windows / macOS kernel hooks
- "AI-powered" detection — the room will eat you alive
- Clean-architecture refactor — the code is fine
- Vanity HUD features (themes, sound packs, extra animations)

These were cut from the Arsenal plan and they stay cut.

---

## How to use this file

After 2026-08-24 (Arsenal submitted):

1. **If accepted:** run §1 in order through Dec 2026. Don't touch §2 until after the event.
2. **If rejected:** pick one item from §2 to ship by year-end, treat next year's CFP as the next milestone. Skip §1.
3. **Either way:** don't touch §2 before the Arsenal submission lands.
