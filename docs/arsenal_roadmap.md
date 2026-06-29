# Hakam — Black Hat Arsenal Roadmap

> **Submission last chance:** **2026-08-31** · **Event:** ~Dec 2026 (Black Hat Europe)
> **Today:** 2026-06-29 · **Budget:** 9 weeks to feature-complete (target **2026-07-28**), then ~4 weeks buffer to submit by **2026-08-24**.

Submission day is the real deadline, not the event. Anything not shipped by **2026-08-24** is booth-only and does not influence acceptance.

This plan reflects the **internal-network-security-layer pivot** — Hakam is not a WAF, it is a kernel-resident layer for east-west traffic, lateral movement, and host policy enforcement. The HTTP signature engine is now a side feature. The headline is **XDP edge drop + BPF-LSM syscall enforcement + per-process attribution**, with a tight-scope eBPF conntrack tying them together.

Items considered and cut from this plan because they don't fit 9 weeks live in [`post_arsenal_roadmap.md`](post_arsenal_roadmap.md).

---

## What Arsenal selectors actually grade on

1. **Defensible novelty** — what does Hakam do that nf_tables / Cilium / Falco can't?
2. **Honest engineering** — can you survive 30 minutes of hostile Q&A from a kernel networking reviewer?
3. **Reproducible demo** — can the audience walk away and run it in 60 seconds?

The new pitch for criterion 1: *"Layered host firewall — XDP guards the wire, BPF-LSM guards the syscall, per-flow conntrack ties them together with process identity. No other open-source eBPF firewall composes all three."*

---

## Phase 1 · 2026-05-28 → 2026-06-11 · Kill the loud critiques

Close the items from `README.md` "Honest limitations" and the unfinished Session 2 items in `core_hardening.md`.

| # | Item | Why it matters | Effort |
|--:|------|----------------|:------:|
| 1 | **TCP segment reassembly** in userspace (per-flow buffer keyed on 4-tuple, ≥2 segments) | Closes single-segment evasion — the #1 thing a reviewer demos against you on stage | 4 d |
| 2 | **URL / percent-decoding pipeline** before signature match | Closes `UNION%20SELECT` slipping past SQLi | 2 d |
| 3 | **Aho-Corasick matcher** (`core_hardening.md` B1) | Replaces O(N×M) loop; lets you claim line-rate scaling | 0.5 d |
| 4 | **DPI matcher unit tests** + evasion corpus enforced by CI (B3) | "Evasion table enforced by `cargo test`" beats "I tested it manually" | 0.5 d |
| 5 | **Uppercase signature assertion** (B4) | Footgun for future contributors; trivial fix | 0.1 d |

**Exit criteria:** `README.md` "Honest limitations" drops from 4 items to 1 (single-segment + URL decoding both deleted). Aho-Corasick automaton compiles once at startup. `cargo test` enforces the evasion table.

---

## Phase 2 · 2026-06-11 → 2026-07-02 · The new headline features

These three items are why your Arsenal pitch is different from a Cilium demo.

| # | Item | Why it matters | Effort |
|--:|------|----------------|:------:|
| 6 | **BPF-LSM `socket_connect` enforcement** + userspace policy map | Upgrades per-process awareness from *observed* to *enforced*. Answers "did the first packet reach the host" by **preventing the originating syscall**. This is the new headline. | 7 d |
| 7 | **Tight-scope eBPF conntrack** — flow table keyed on 4-tuple, holds `seq_next` + `dir` + `last_ts`. No TCP state machine. | Unlocks segment-ordered reassembly with kernel awareness. Enables per-flow rate limit instead of per-IP. Foundation for any future microsegmentation policy. | 10 d |
| 8 | **Per-process attribution in BLOCK events** — wire `sys_enter_connect` data through to the BLOCK JSON | Every block names PID + comm. The single most quotable demo moment: *"blocked SQLi from 10.99.1.13, originating PID 4827 / curl"* | 4 d |

**Exit criteria:** A blocked SQLi names the originating PID/comm in CLI + HUD. The `socket_connect` LSM hook denies a process from initiating an outbound connect when policy rejects it. Conntrack table holds N active flows visible in `stats`. The "first packet always reaches the host" admission in `docs/architecture.md` §4 is replaced with "first attempted `connect()` is denied at LSM."

**Q&A prep — write the answers by week 4:**
- BPF-LSM kernel cmdline requirements (`CONFIG_BPF_LSM=y`, `lsm=…,bpf` in cmdline)
- LSM hook ordering (after SELinux/AppArmor in the chain — what does that mean for a `-EPERM` return)
- Policy bypass surfaces (CAP_BPF, userspace policy poisoning)
- Conntrack map exhaustion under load (1M flows = 1M entries; what's the eviction policy)
- TCP reassembly edge cases (retransmits, out-of-order delivery)

---

## Phase 3 · 2026-07-02 → 2026-07-16 · Make it run on someone else's box

| # | Item | Why |
|--:|------|-----|
| 9 | **systemd unit + container image** | Pre-req for the 60-second reproducible demo. Also fixes the stdin-exit bug — no TTY = no-op CLI loop. |
| 10 | **Driver-mode XDP on a real NIC** (not SKB on `lo`) | Lets you publish honest perf numbers, not synthetic ones. |
| 11 | **Small in-repo PCAP replay corpus** (3–5 PCAPs from public CVE PoCs) | "Replay our tests in 10 seconds from a clone" beats any synthetic claim. Don't try to do CIC-IDS or full corpora — that's post-Arsenal work. |
| 12 | **README perf table rewrite** with real-NIC numbers + one ModSecurity reference number from their published bench | Skip the full apples-to-apples rig — point to their numbers, show yours alongside. |
| 13 | **GitHub Actions CI** (cargo check, cargo test, eBPF verifier load test) | Signals "maintained project" to anyone who clicks the repo. |
| 14 | **Release tag `v1.0.0`** | Reviewers check the Releases page. |

**Exit criteria:** `docker run` brings the whole stack up on any Linux ≥ 5.7 with BPF-LSM enabled. README perf table has driver-mode XDP numbers from a real NIC. Green CI badge. Tagged release.

**Cut from this phase (live in `post_arsenal_roadmap.md`):** full apples-to-apples ModSec/Coraza rig, DVWA / Juice Shop integration, large public attack corpora.

---

## Phase 4 · 2026-07-16 → 2026-07-28 · Submission package · FEATURE FREEZE

Feature freeze on **2026-07-21**. One week for the submission package, then ~4 weeks of buffer to Aug 24.

| # | Item | Notes |
|--:|------|-------|
| 15 | **Arsenal abstract** (250–500 words) | Write 3 drafts, pick the strongest. Lead with the layered-firewall differentiator, not the architecture. |
| 16 | **Demo video** (3 min, screen recording, no editing tricks) | Show: process attempts outbound `connect()` → LSM denies → HUD shows PID/comm. Then: SQLi from external IP → XDP drops → HUD shows BLOCK with per-process attribution. End with `stats`. |
| 17 | **One-pager PDF** for the program guide | One diagram, three bullets, one perf number. |
| 18 | **Speaker bio + headshot** | 100 words, professional photo. |
| 19 | `CONTRIBUTING.md`, `SECURITY.md`, demo GIF in README | Open-source maturity signal. |
| 20 | **Submit by 2026-08-24** | Buffer week absorbs hiccups (network, browser crash, last-minute typo). |

**Hard rule:** No feature commits after 2026-07-21. Anything you want to add goes on a `booth/` branch and merges only after submission lands.

---

## What is explicitly NOT in this plan

These were considered and cut because they don't fit 9 weeks. They live in [`post_arsenal_roadmap.md`](post_arsenal_roadmap.md):

- **AF_XDP + io_uring data-path rewrite** — redundant with userspace TCP reassembly (Phase 1 #1)
- **Hardware offload / SmartNIC** support — kills demo reproducibility, restricts BPF feature set
- **Full eBPF conntrack with TCP state machine** — tight-scope flow table covers Arsenal needs
- **Apples-to-apples ModSec/Coraza bench rig** — use their published numbers instead
- **DVWA / Juice Shop integration** — synthetic harness is fine for the demo
- **CO-RE / BTF portability** — every reviewer's box is recent enough
- **TLS SNI extraction** — adds DPI complexity for marginal differentiator
- **Per-rule action tiers, YAML hot-reload, Prometheus `/metrics`** — config sugar
- **Booth-week ops** (live hosting, hostile Q&A rehearsal, runbook) — post-submission work

And the no-touch list, same as before:

- No GUI rule editor.
- No IPv6 unless it falls out for free during conntrack work.
- No Windows / macOS kernel hooks.
- No "AI-powered" detection.
- No clean-architecture refactor — the code is fine, ship features.
- No vanity features (themes, sound packs, extra HUD animations).

---

## Risk register

| Risk | Trigger | Mitigation |
|------|---------|------------|
| BPF-LSM unavailable on reviewer kernel | `CONFIG_BPF_LSM` off or `lsm=` doesn't include `bpf` | Document the requirement loudly in README. Ship a kernel-detection check in `scripts/preflight.sh`. Fall back to observe-only mode (tracepoint + log) when LSM unavailable so the demo still works. |
| eBPF conntrack verifier rejects flow state | Per-flow struct + map access pattern triggers verifier complexity limit | Drop the `seq_next` field, keep just `dir + last_ts`. Move reassembly logic entirely to userspace. |
| TCP reassembly eats more than 4 days | Edge cases with retransmits, out-of-order delivery | Time-box at 6 days. If still not landing, ship in-order ≥2 segments only and document the gap in `docs/evasion.md`. |
| BPF-LSM enforcement breaks demo VM's own networking | LSM hook denies hakam-node's own connects, etc. | Allowlist the hakam-node PID in the policy map at startup. Add a smoke test that hakam-node can still reach its WS clients after LSM attaches. |
| Phase 2 slips, can't recover | BPF-LSM or conntrack hits a real wall | Submit a degraded version: per-process attribution alone (Phase 2 #8 without #6 and #7) is still a strong story. Don't sink the submission chasing the full stack. |
| You miss 2026-08-24 | Phase 1 or 2 slipped | Arsenal usually has a second waitlist round in October. Submit anyway; if accepted, finish remaining items between accept date and event. |

---

## Progress tracker

Update this as you ship each item. Phase numbers map to the tables above.

| Phase | Item | Status | Notes |
|------:|------|:------:|-------|
| 1 | 1 — TCP reassembly (userspace) | ✅ | 4-tuple keyed buffer (PayloadEvent extended); FlowState fields seq_next/dir reserved for Phase 2 #7 |
| 1 | 2 — URL decoding | ✅ | single-pass `%XX` + `+`→space; flipped 4 evasion rows MISS→HIT |
| 1 | 3 — Aho-Corasick | ✅ | case-insensitive, zero per-packet allocation |
| 1 | 4 — DPI tests + evasion enforcement | ✅ | tests/dpi_matcher.rs pins every evasion row |
| 1 | 5 — Uppercase assertion | ✅ | + length/empty/category-sync invariants |
| 2 | 6 — BPF-LSM socket_connect | ✅ | LSM `socket_connect` returns -EPERM on a `CONNECT_POLICY` dst hit — `connect()` denied pre-packet. `policy-block/unblock/list` CLI manages the map. Degrades to observe-only when `bpf` absent from active LSM list; preflight WARNs on this. Validated on hakam VM: blocked dst → curl/python/nc all get EPERM (0 ms), non-blocked dst still connects (selective). Limitation: dst-keyed, not task-keyed — per-process *policy* scoping deferred to #7 (attribution already lands via #8). |
| 2 | 7 — Tight eBPF conntrack | ✅ | Kernel `CONNTRACK` LruHashMap<FlowKey,FlowState> (seq_next/last_ts/packets/dir), populated by XDP per TCP segment; verifier passed on **rung 1** — no degrade-ladder needed. Userspace reassembly now **sequence-ordered** (BTreeMap by seq) — closes the out-of-order evasion; retransmit dedupe by seq. `active_flows` surfaced in METRICS/HUD + `stats` (the exit-criterion number). Live-validated on lo: active_flows climbed 0→12 with traffic, single-shot SQLi blocked, forced two-segment split (UNION SELECT spanning the seam) blocked. Decisions: kept **per-IP** rate limit (per-flow added as visibility, not a swap — per-flow-only is weaker vs many-small-flows); seq supersedes the kernel flag for byte placement (the flag mislabels a late earlier segment as a retransmit). Out-of-order correctness covered by integration test (live OOO needs raw packet crafting). |
| 2 | 8 — Per-process attribution in BLOCK | ✅ | connect_task records (dst_addr,dst_port)→(pid,comm); payload_task correlates on a BLOCK and names origin in INTERCEPT line + BLOCK JSON; HUD log shows "origin PID/comm". Verified end-to-end on VM real traffic. Limitation: dst-keyed, most-recent-wins within 120s TTL — #7 conntrack tightens to source-port precision. |
| 3 | 9 — systemd + container | 🟡 | **Partial.** stdin-exit bug fixed (headless mode: no-TTY → datapath stays up, controlled via WS + SIGINT; main-side so it exits cleanly). systemd unit + `install.sh` + `/etc/hakam/hakam.env` — **validated in VM**: `systemctl start`→active/armed/headless/WS, `systemctl stop`→clean detach. Container (`packaging/docker/` multi-stage Dockerfile + entrypoint + run.sh + .dockerignore) **written but not build-tested** (no docker in dev VM); bpf-linker build is the env-sensitive step, flagged in-file. Remaining: actually build-test the image to satisfy the `docker run` exit criterion. |
| 3 | 10 — Driver-mode XDP / real NIC | ⬜ | |
| 3 | 11 — Small PCAP replay corpus | ⬜ | |
| 3 | 12 — README perf rewrite | ⬜ | |
| 3 | 13 — GitHub Actions CI | ⬜ | |
| 3 | 14 — Release tag v1.0.0 | ⬜ | |
| 4 | 15 — Abstract | ⬜ | |
| 4 | 16 — Demo video | ⬜ | |
| 4 | 17 — One-pager | ⬜ | |
| 4 | 18 — Bio + headshot | ⬜ | |
| 4 | 19 — Repo polish | ⬜ | |
| 4 | 20 — **Submit (target 2026-08-24)** | ⬜ | |
