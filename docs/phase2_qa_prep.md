# Hakam — Phase 2 Q&A Preparation

> **Purpose.** Rehearse-ready answers to the five questions a kernel-networking reviewer will ask once Phase 2 (BPF-LSM enforcement + eBPF conntrack + per-process attribution) is in the booth demo. Each section has a 30-second headline answer to deliver on stage, the deeper technical detail to fall back on if the questioner is real, and the follow-ups they will chain into.
> **Audience.** Use this to prep yourself. Do not read from it on stage — internalise it. The headline paragraph is what should come out of your mouth verbatim under pressure.
> **Status.** Drafted 2026-05-31 (before Phase 2 code lands). Revisit and tighten after each Phase 2 milestone — when something here is no longer true, fix this doc in the same commit.
> **Companion docs.** [`arsenal_roadmap.md`](arsenal_roadmap.md) §Phase 2, [`architecture.md`](architecture.md), [`evasion.md`](evasion.md).

The five questions, in the order the roadmap risk register names them:

1. [BPF-LSM kernel cmdline requirements](#1--bpf-lsm-kernel-cmdline-requirements)
2. [LSM hook ordering](#2--lsm-hook-ordering)
3. [Policy bypass surfaces](#3--policy-bypass-surfaces)
4. [Conntrack map exhaustion under load](#4--conntrack-map-exhaustion-under-load)
5. [TCP reassembly edge cases](#5--tcp-reassembly-edge-cases)

Plus an [appendix](#appendix-a--preflight-check-script-outline) with the preflight script we owe the demo by Phase 3.

---

## 1 · BPF-LSM kernel cmdline requirements

> **Q: "What do I need on my kernel to actually run your LSM hook?"**

### 30-second answer

> *"Linux 5.7 or newer with `CONFIG_BPF_LSM=y` in the kernel build, and `bpf` listed in the `lsm=` boot cmdline alongside whatever else is enabled — typically `lockdown,yama,integrity,apparmor,bpf` on Ubuntu, `lockdown,yama,integrity,selinux,bpf` on RHEL family. You can't enable it at runtime — it's an init-time decision. `cat /sys/kernel/security/lsm` after boot confirms it; if `bpf` isn't in that comma-separated list, our enforcement falls back to observe-only and logs why."*

That sentence answers the surface question. Everything below is the follow-up depth.

### Why this matters

BPF-LSM is what makes Phase 2 #6 (`socket_connect` enforcement) different from a regular tracepoint. A tracepoint observes; an LSM hook can return `-EPERM` and the syscall actually fails for the caller. But the kernel will not run our LSM program at all unless the kernel was built with `CONFIG_BPF_LSM` *and* the boot cmdline explicitly enables it.

### What's actually required

| Knob | Required value | Where it lives | How to verify |
|------|----------------|----------------|---------------|
| Kernel version | ≥ 5.7 | `uname -r` | `uname -r` (BPF-LSM merged in 5.7, released June 2020) |
| Build config | `CONFIG_BPF_LSM=y` | Kernel `.config` at build time | `grep BPF_LSM /boot/config-$(uname -r)` or `zcat /proc/config.gz \| grep BPF_LSM` if `CONFIG_IKCONFIG_PROC` is set |
| Boot cmdline | `lsm=...,bpf` (must include `bpf`) | GRUB / boot loader | `cat /proc/cmdline` to see what was passed; `cat /sys/kernel/security/lsm` to see what was loaded |
| Sysfs mount | `securityfs` mounted at `/sys/kernel/security` | usually automatic | `mount \| grep securityfs` |

The `lsm=` cmdline parameter is **the** gate. If `bpf` is absent from the list, the kernel registered BPF as an LSM but disabled it before any program could attach — we get `EPERM` from `bpf(BPF_PROG_LOAD, ...)` with `expected_attach_type` set to an LSM hook.

### Distro defaults in 2026

These shift, so re-check before the booth week — but as of mid-2026:

- **Ubuntu 22.04 / 24.04** — `CONFIG_BPF_LSM=y` is set, but the default cmdline is `lsm=lockdown,yama,integrity,apparmor`. You have to add `,bpf` yourself.
- **Debian 12** — same story.
- **RHEL 9 / Rocky 9 / Alma 9** — `CONFIG_BPF_LSM=y`, default cmdline omits `bpf`, SELinux is enforcing.
- **Fedora 41+** — `bpf` is in the default `lsm=` list. The one distro where this works out of the box.
- **Amazon Linux 2023** — `CONFIG_BPF_LSM=y`, you add `bpf` via `/etc/default/grub`.

### How a user enables it (Ubuntu walkthrough — what we put in our README)

```bash
# 1. Confirm the kernel can run BPF-LSM at all.
grep BPF_LSM /boot/config-$(uname -r)
# Expected: CONFIG_BPF_LSM=y

# 2. Check the current boot's LSM stack.
cat /sys/kernel/security/lsm
# If 'bpf' is not in the list, the kernel won't let us attach.

# 3. Edit GRUB defaults.
sudo sed -i 's/GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 lsm=lockdown,yama,integrity,apparmor,bpf"/' /etc/default/grub
sudo update-grub
sudo reboot

# 4. After reboot, confirm.
cat /sys/kernel/security/lsm
# Should now include ',bpf' at the end.
```

We ship this as `scripts/preflight.sh` (Phase 3 #9 deliverable) so the reviewer doesn't have to write it themselves.

### Fallback behaviour

If `MONITOR_BPF_LSM_AVAILABLE` returns false (we detect it by `cat`-ing `/sys/kernel/security/lsm` at startup), `hakam-node` logs:

```
[warn] BPF-LSM unavailable on this kernel (bpf not in lsm= cmdline).
[warn] socket_connect enforcement disabled; falling back to tracepoint observe-only.
[warn] See docs/phase2_qa_prep.md §1 to enable enforcement.
```

The demo still runs — the tracepoint surfaces PID/comm as before, just without the deny. The headline pitch shifts from *"blocked at the syscall"* to *"identified at the syscall"*. This matters because reviewers will absolutely test on their own laptop with a stock kernel.

### Follow-ups

> **"What about kernel 5.4?"**
> No. BPF-LSM is a 5.7 minimum. We don't backport. Linux 5.4 is the LTS that shipped with Ubuntu 20.04 — if a reviewer is on that, they're on an old box.

> **"Can I add `bpf` to `lsm=` without a reboot?"**
> No. The LSM stack is finalised in `security_init()` during boot. There's no runtime knob — that's by design (an attacker shouldn't be able to swap LSM stacks).

> **"What if `lockdown` is in integrity mode?"**
> Integrity mode blocks `bpf(BPF_PROG_LOAD)` for unsigned programs. We'd need to either sign hakam-ebpf (CAP_SYS_ADMIN + key chain on the kernel keyring) or document "lockdown=integrity is incompatible". We're going to document the second.

> **"What's the minimum kernel for the rest of the stack?"**
> 5.15 for XDP + ring buffers as we use them. So the effective floor for Hakam is 5.15, which subsumes the 5.7 BPF-LSM requirement.

---

## 2 · LSM hook ordering

> **Q: "If I'm running SELinux / AppArmor, what does your BPF-LSM hook do when they've already made a decision?"**

### 30-second answer

> *"LSMs stack — every hook in the chain runs regardless of what the previous one returned. We can deny what they allowed, but we can't override their deny. So in a setup where SELinux says deny, the syscall fails before our program would have a say; in a setup where SELinux says allow, our hook still runs and can return -EPERM. The order is set by the `lsm=` cmdline list; BPF is typically last, which means we see the decision after the major LSMs have weighed in."*

### Why this matters

A reviewer running SELinux-enforcing RHEL will ask whether our hook is dead code on their box. The honest answer is *no, it's strictly additive*. We're not a replacement for SELinux/AppArmor — we're an extra layer that can deny things they allowed.

### How the chain actually runs

The LSM framework iterates **every registered LSM for a given hook**, in registration order (which is the `lsm=` cmdline order). For each hook:

```c
// Simplified — actual code is in security/security.c
for (each LSM in list) {
    rc = LSM->hook(...);
    if (rc < 0) {
        // remember this is a deny, but keep iterating
        deny_rc = rc;
    }
}
return deny_rc;  // first non-zero error
```

The chain does **not** short-circuit on the first deny — every LSM gets to run its bookkeeping (auditd records, AVC cache updates, etc.). The first negative return wins.

This is good for us: even if SELinux says allow, we still get to run and decide. And it means our deny is real — the syscall returns the `-EPERM` we set, after the chain completes.

### What "BPF is typically last" implies

With `lsm=lockdown,yama,integrity,apparmor,bpf`:

1. `lockdown` — pre-boot integrity policy.
2. `yama` — ptrace scope.
3. `integrity` — IMA file appraisal.
4. `apparmor` — path-based MAC. This is the one most likely to interfere on Ubuntu.
5. `bpf` — us.

For `socket_connect` specifically, AppArmor has a per-profile `network` rule. If a profile says `deny network tcp,`, AppArmor returns `-EPERM` before our hook runs — but the LSM framework still calls us, and our return is overridden by the earlier deny. Net effect: our hook gets called for accounting, our deny would have stuck if AppArmor had said allow, but if AppArmor said deny the syscall fails for the AppArmor reason.

For audit purposes (a real concern in regulated environments), this means **our deny will be paired with the AppArmor allow** in the audit log — which is exactly what compliance wants.

### What happens if our hook isn't loaded at all

We never see the syscall. The chain just runs the other LSMs and returns whatever they decide. No safety net, no surprise behaviour — same as before Phase 2.

### Returning `-EPERM` vs other errnos

We return `-EPERM` (Operation not permitted) because it matches what every other LSM uses for "policy deny". Userspace tools (curl, wget, ssh) know how to surface this. Returning something exotic like `-ECONNREFUSED` would make the failure look like a routing problem and confuse operators.

### Follow-ups

> **"Can I see your hook in the audit log?"**
> Yes — kernel ≥ 5.8 supports the `bpf` audit subsystem. Run `auditctl -a always,exit -F arch=b64 -S bpf` and load hakam-ebpf; each LSM program load generates an audit record. We'll add the exact command to the preflight script.

> **"What if I want SELinux to win and you to be observe-only?"**
> Set our policy map to allow everything (sentinel: empty map). The LSM hook still runs, accounting still fires, but every decision is "permit". We can also unload the LSM program entirely with `bpftool prog detach`.

> **"What about Smack or TOMOYO?"**
> Same story — they stack too. We don't have a setup to test against either, so we'll mark them as "should work, untested" in the README.

> **"What's the per-hook cost of having BPF in the chain?"**
> One indirect call per `connect()`. The `socket_connect` hook is not in any packet hot path — it fires once per outbound connection setup. Cost on the order of 100 ns. Not measurable in throughput benchmarks.

---

## 3 · Policy bypass surfaces

> **Q: "Walk me through how I bypass your policy. Be honest."**

### 30-second answer

> *"Three surfaces. First, the `bpf()` syscall — anyone with `CAP_BPF` or `CAP_SYS_ADMIN` can detach our LSM hook with `bpftool prog detach`, period. Second, the policy map is a regular BPF map; CAP_BPF can write to it, so an attacker with that capability can whitelist their own PID. Third, our userspace daemon owns the map handle — kill the daemon, the hook stays attached but the policy stops updating. Mitigations are root-only sysctl `kernel.unprivileged_bpf_disabled=2` to keep the bar at root, plus an AppArmor profile on hakam-node itself to limit what it can do. We don't claim this defends against root; we claim it raises the cost above what a real attacker invests in a host they've only partially compromised."*

### Why this matters

A reviewer who has done any serious red-teaming will ask about bypass within the first three minutes. The wrong answer is to claim there isn't one. The right answer is to enumerate them honestly and explain the threat model that justifies the design anyway.

### The full surface

**Surface 1: BPF program detach.**

```bash
sudo bpftool prog list | grep hakam_lsm
sudo bpftool prog detach <id>
```

This requires `CAP_BPF` (or `CAP_SYS_ADMIN`) and access to `bpftool`. On a default-config Ubuntu, that means root. On a hardened box (`kernel.unprivileged_bpf_disabled=2`), the bar is still root.

**Surface 2: Policy map write.**

```bash
# Inside the policy map, key=PID, value=action
sudo bpftool map update name HAKAM_POLICY key 0x05 0x0E 0x00 0x00 value 0x00
# (whitelists PID 3589)
```

Requires CAP_BPF + knowing the map name + knowing the key/value layout. Surface is identical to Surface 1 in practice — both gated by CAP_BPF.

**Surface 3: Daemon kill.**

```bash
sudo kill -9 $(pgrep hakam-node)
```

This stops policy *updates* but the kernel-side hook keeps running with whatever the map last contained. New processes started after the kill get evaluated against stale policy. The hook can only be detached by Surface 1.

This is actually a *security property*, not a weakness — killing the daemon does not undo enforcement. But it means a static policy is enforced even when our daemon is dead, which can become a denial-of-service if the policy denies more than the operator intended.

**Surface 4: File descriptor leakage.**

BPF program FDs are referenced by file descriptor in the daemon process. If hakam-node forks a child and doesn't `FD_CLOEXEC` the program FDs, the child inherits handles that allow detach without going through `bpftool`. We use `BPF_OBJ_PIN` with O_CLOEXEC and don't fork — surface closed by design but worth a code review in Phase 2.

**Surface 5: Kernel module loading.**

A loaded kernel module can unhook anything. Same bar (root) plus `CAP_SYS_MODULE`. We can't defend against this; it's the same threat model as "attacker has root".

**Surface 6: cgroup escape.**

Our LSM hook fires for *every* process on the host regardless of cgroup. So a container escape doesn't bypass us. (Containers running with their own user namespaces still call into the host kernel; our LSM runs at the kernel layer.)

### Mitigations and what they actually buy you

| Mitigation | Protects against | Cost |
|------------|------------------|------|
| `sysctl kernel.unprivileged_bpf_disabled=2` | non-root bpf() (Surface 1, 2, 4) | None — recommended default for production. |
| AppArmor / SELinux profile on `hakam-node` | Daemon compromise expanding to host (Surface 3) | One profile file. |
| Lock the policy map's file mode (`fchmod` on the pinned BPF object) | Casual `bpftool map update` from a separate root context | None. |
| Pin LSM program + map under `/sys/fs/bpf/hakam/` with `0600` | Confused-deputy daemon overwriting policy | None. |
| Refuse to load if `CONFIG_BPF_UNPRIV_DEFAULT_OFF` is not set | Wrong-distro deployment | One preflight check. |
| Don't expose policy edit over the WS channel | Browser-side compromise editing kernel policy | Design constraint — WS is read-only telemetry. |

The last one is **load-bearing**. The HUD WebSocket is broadcast-only — it never accepts policy commands. Reviewers will ask. The answer is *"the WS is a one-way fire hose; the policy map is mutated only by signed input on the local stdin loop"*.

### What we explicitly don't claim

- **Defence against a root attacker.** Anyone with root owns the kernel, full stop. If your threat model includes a privileged adversary, BPF-LSM is the wrong primitive — you want an out-of-band attestation system.
- **Anti-forensic resistance.** A root attacker can wipe BPF audit records.
- **Resistance to a malicious kernel module.** Out of scope.

What we do claim: the bar to bypass is *root with eBPF tooling knowledge*, not *unprivileged user with curl*. That bar is high enough to matter against the actual common attacker (web-app compromise leading to a low-privilege RCE that pivots to credential theft and lateral movement) — which is the whole point of an internal-network security layer.

### Follow-ups

> **"What about CAP_NET_ADMIN?"**
> Irrelevant. CAP_NET_ADMIN gives you netlink, tc, ifconfig — not bpf(). Our threat model uses CAP_BPF as the bar.

> **"What if I set `kernel.unprivileged_bpf_disabled=0`?"**
> You shouldn't, ever, on a multi-user box — unprivileged BPF has been a CVE source for years (CVE-2020-8835, CVE-2021-3490, CVE-2021-31440, etc.). Our preflight refuses to start if it's set to 0 and the operator hasn't passed `--allow-unprivileged-bpf`.

> **"Can a process spoof its own PID to the LSM hook?"**
> No — `bpf_get_current_pid_tgid()` reads from the current task struct, which the kernel owns. A process cannot lie about its PID to the kernel.

> **"What about `LD_PRELOAD`?"**
> Doesn't help. LSM hooks run in kernel context. LD_PRELOAD intercepts library calls in userspace before the syscall — but the syscall still happens and we still see it.

---

## 4 · Conntrack map exhaustion under load

> **Q: "What happens when 1M concurrent flows hit your conntrack? Where does it break?"**

### 30-second answer

> *"The Phase 2 conntrack is an `LRU_HASH` map sized at load time — default 64k entries which is `64,000 × 32 bytes = ~2 MB`. At capacity the kernel evicts the least-recently-touched flow per CPU, so new flows always get a slot. The trade-off is that under sustained 1M-flow load (well above demo and realistic-enterprise rates), the eviction churn means flows can be dropped from the table mid-life — they keep working at the network layer but our per-flow state resets. We surface the eviction rate via a `STATS` counter; if you see it climbing, raise `--conntrack-size`. The hard ceiling is whatever your kernel will accept (typically 4M entries before the BPF verifier complains about memory)."*

### Why this matters

Map exhaustion is the question every conntrack reviewer asks because nf_conntrack has burned every operator at least once. The right answer references the eviction policy by name (LRU), names the per-entry cost, and gives the operator a knob.

### What we actually use

For the Phase 2 #7 "tight scope" conntrack, the map type is:

```rust
// hakam-ebpf/src/main.rs (planned)
#[map]
pub static FLOW_TABLE: LruHashMap<FlowKey, FlowState> =
    LruHashMap::<FlowKey, FlowState>::with_max_entries(65_536, 0);
```

Key layout (12 bytes): `src_addr (4) + dst_addr (4) + src_port (2) + dst_port (2)`. Wire byte order.

Value layout (20 bytes), per the `FlowState` in `hakam-node/src/reassembly.rs` that the conntrack will populate:

```
seq_next   : u32   (4) — expected next TCP seq
dir        : u8    (1) — 0 = c2s, 1 = s2c
_pad       : u8    (1)
last_ts    : u32   (4) — boot-time seconds of last segment
flags      : u16   (2) — SYN_SENT / ESTABLISHED / FIN_WAIT_*
_pad2      : u16   (2)
bytes_seen : u32   (4)
_reserved  : u32   (2)  (room for what we discover we need)
```

Total: 32 bytes per entry counting alignment. At 64k entries: 2 MB resident, per CPU on a `LruPerCpuHashMap`, total ~`2 MB × num_cpus`. On a 16-core machine that's 32 MB — small compared to nf_conntrack's typical ~256 MB.

### Eviction semantics, in detail

`BPF_MAP_TYPE_LRU_HASH` (and per-CPU variant) maintains an internal LRU list. On insert when the map is at capacity:

1. Kernel walks the LRU list looking for the least-recently-used entry.
2. Evicts it (no userspace notification).
3. Inserts the new entry at MRU position.

This is O(1) amortised. The only failure mode is when the LRU list scan can't find an eviction candidate — happens if every entry was touched in the same RCU window. In that case the insert returns `-E2BIG` and we drop the new flow (kernel netdev counter increments).

Our userspace surfaces this in `stats`:

```
conntrack flows       : 8,432 / 65,536  (12.9%)
conntrack evictions   : 0
conntrack insert fail : 0
```

(All counters live in `PerCpuArray<u64>` cells, summed across CPUs in userspace.)

### What "1M flows" actually looks like

The reviewer's framing assumes a DDoS or a busy CDN. Realistic numbers:

- A small office network: 100–500 concurrent TCP flows.
- A mid-size enterprise LAN: 5k–30k.
- A busy reverse proxy under load: 50k–200k.
- A real DDoS or scanner sweep: 1M+ unique 4-tuples in seconds.

64k entries cover the first three. For the fourth, the operator has two options:

1. **Raise the cap.** `--conntrack-size 1048576` packs the map at 1M entries × 32 bytes × 16 CPUs = ~512 MB. Verifier accepts up to about 4M entries before complaining; we cap at 2M in the CLI parser.
2. **Accept the eviction churn.** LRU means the new flows still get a slot — they just may push our oldest tracked flows out. For Hakam's threat model (we care about *new* outbound connections, not long-lived ones), this is the right trade-off.

### What we *don't* do

- **No per-IP rate limit on conntrack inserts.** The XDP rate limiter (already shipped) acts before conntrack would even fire. If a single IP is doing 500+ pps, it's already on the blocklist and isn't reaching the flow table.
- **No `nf_conntrack` integration.** We don't share state with the kernel's netfilter conntrack. Two reasons: (a) we want to demo on boxes where nf_conntrack isn't loaded; (b) coupling our verifier-checked map to a netfilter subsystem with its own CVE history is a regression in attack surface.
- **No flow timeout knobs.** TCP states have implicit timeouts — ESTABLISHED flows get evicted when LRU pressure hits, which is enough. We're not building a full TCP state machine in BPF.

### Follow-ups

> **"What if my workload is mostly UDP?"**
> Out of scope for Phase 2. The map keys on the 4-tuple regardless of protocol but the state machine assumes TCP. UDP flows would get entries but no useful tracking. We'd need a separate UDP conntrack — post-Arsenal.

> **"How does this compare to Cilium's conntrack?"**
> Cilium uses two LRU maps (`cilium_ct4_global`, `cilium_ct_any4_global`) sized at compile time per node based on policy. Same primitive, same eviction. They size at 1M as a default for K8s clusters. We're smaller because our scope is one host, not a cluster.

> **"What about IPv6?"**
> Out of scope for Phase 2 — the FlowKey is IPv4-only (12 bytes). IPv6 would need a 36-byte key (16+16+2+2). Different map. Post-Arsenal.

> **"Memory budget?"**
> 32 bytes × 64k entries × 16 CPUs = ~32 MB at default. 32 bytes × 1M × 16 CPUs = ~512 MB at max. Operator knob makes the trade-off explicit.

> **"Can I see the per-flow state?"**
> Yes — `bpftool map dump name FLOW_TABLE` walks the entries. We expose a `flows` CLI command that does this prettier.

---

## 5 · TCP reassembly edge cases

> **Q: "What breaks your reassembly?"**

### 30-second answer

> *"Today, in-order TCP delivery is solid — we buffer up to 256 bytes per 4-tuple flow and run the matcher over the reassembled view. Out-of-order delivery breaks us because we don't track TCP sequence numbers yet — the Phase 2 #7 conntrack adds `seq_next` to `FlowState` and at that point we can dedupe retransmits and reorder. Path MTU changes, TCP fast open, TLS-encrypted payloads, and TSO-merged segments all behave correctly today because we operate on whatever the kernel hands XDP — TSO/GRO actually helps us by pre-merging segments before sampling. The honest gap is segment-after-256-bytes — for very long URIs split across more than four segments, the tail is invisible."*

### Why this matters

This is the question the kernel-networking person in the audience will ask, because they've written reassembly code before and know how many ways it can fail. The right answer enumerates the edge cases by name and tells the truth about each.

### Cases we handle correctly today

| Case | Behaviour | Why |
|------|-----------|-----|
| **Single-segment HTTP request** | Match runs on segment 1 | Reassembler creates a flow with that one segment, view = single segment, match. |
| **Two-segment split** (`UNION` then `SELECT`) | Match runs on reassembled view | `tests/reassembly.rs::split_union_select_caught_after_segment_two` pins this. |
| **Three-segment split** | Same, buffer grows to 256 B cap | `split_across_three_segments` test. |
| **Concurrent flows from same source IP** | Each 4-tuple gets its own buffer | `parallel_flows_match_independently` test. |
| **HTTP keep-alive (multiple requests on same connection)** | After a match fires we `forget(flow)`, so the next request matches against only its own bytes | `forget_after_match_lets_same_flow_be_reinspected` test. |
| **TSO / GRO pre-merged segments** | Match runs on whatever the kernel hands us | XDP sees post-GRO merged segments on receive offload; we sample 64 B of the merged buffer. |
| **TCP Fast Open (payload in SYN)** | Sampled normally | We don't care about SYN/ACK flags, just that there's a TCP payload. |
| **Connection RST** | TTL eviction cleans up | 30s TTL on the flow state; an RST just means we won't see more segments, GC takes care of it. |
| **TLS-encrypted payloads** | No match fires | We do not decrypt. Encrypted bytes don't match any signature; the flow eventually GC's. Correct behaviour. |

### Cases we get wrong today (documented, planned for Phase 2 #7)

| Case | Failure mode | Phase 2 #7 fix |
|------|--------------|----------------|
| **Out-of-order delivery** (seg N+1 arrives before seg N) | View buffer is appended in arrival order; the HTTP method gate fails on the second-segment-first view | `seq_next` in FlowState lets us hold seg N+1 in a small reorder slot until seg N lands, then concatenate in correct order. |
| **TCP retransmits** (same seq, later in time) | Buffer gets a duplicate of an earlier payload appended; substring match still fires (harmless) but buffer fills 2× faster | `seq_next` lets us identify retransmits and skip them. |
| **Sequence number wrap** (4 GB into a long-lived flow) | A retransmit dedupe based on raw `seq_next` would misidentify wraps as out-of-order | Wrap detection needs the standard `seq1 - seq2 < 2^31` arithmetic. Documented in the Phase 2 #7 spec. |
| **Long URI past 256 bytes** | Anything beyond byte 256 of the reassembled view is invisible | Raise `DEFAULT_MAX_FLOW_BUF` if needed (memory cost: linear). 256 is the demo default; production might want 1024. |

### Cases the reviewer might think we get wrong but we actually don't

> **"What about TCP segmentation offload? Doesn't your XDP see fragments?"**
> XDP sees what the NIC drivers hand it. On receive, GRO (Generic Receive Offload) merges multiple wire segments into one large skb *before* XDP runs in SKB mode. In driver mode, XDP runs before GRO — but we explicitly enable SKB mode in the demo (`--mode skb`) to get the merged view. So TSO/GRO is feature, not bug. If we go to driver mode in Phase 3 we'll either tolerate the smaller per-call payloads or re-enable GRO via `ethtool -K`.

> **"What about IP fragmentation?"**
> Same answer — the kernel reassembles IP fragments before our XDP hook in SKB mode. We don't see fragments.

> **"What about TCP Fast Open data in SYN?"**
> The SYN carries the data in the payload. XDP samples the payload bytes whether they came in SYN, ACK, or anything else. No special case needed.

> **"What if the attacker pads the request with garbage past 256 bytes?"**
> The attack still has to be in the first 256 bytes of the request to land in the matcher. If they push it past, the request doesn't reach the vulnerable endpoint either (most servers reject 4KB+ URI). Real-world: HTTP server URI limits are usually 4KB (Apache) or 8KB (nginx), and our buffer is 256 B — which means attacks that *would actually work against a real backend* are usually within our window.

### Cases that don't exist for us

- **NAT traversal.** We're a host-level eBPF program; NAT happens at routers. We see the post-NAT addresses on receive — fine.
- **VLAN tagging.** XDP sees the inner packet; the kernel strips VLAN tags before our hook in standard configurations.
- **Encryption.** Out of scope — see the limitations note on TLS above.

### Follow-ups

> **"How do you know your seq_next math is right?"**
> When Phase 2 #7 lands, we'll add unit tests for: in-order N→N+1 (concatenate), reorder N+1→N (hold N+1 until N), retransmit of N (skip), wrap from `0xFFFFFFF0` to `0x00000010` (concatenate, not reorder). The tests live in `hakam-node/tests/reassembly.rs`.

> **"What's the worst case for an attacker to slip past?"**
> A request larger than 256 bytes that places its only attack token in the trailing portion. Mitigations: raise the buffer cap (memory cost), or rely on the upstream server having its own request limit.

> **"Why not just use scapy / Suricata / Zeek for this?"**
> Those operate on a userspace packet capture — totally fine, totally different architecture. Our value prop is that the *drop* happens in the kernel, with no userspace round-trip for already-blocked sources. We reassemble in userspace only because the BPF verifier won't let us do unbounded string operations in kernel.

---

## Appendix A · Preflight check script outline

The Phase 3 #9 deliverable is `scripts/preflight.sh` that verifies the host is Hakam-ready. Below is the planned check list — once the script lands, link it from here.

```bash
#!/usr/bin/env bash
set -eu

fail=0
pass()    { printf "  ✓ %s\n" "$1"; }
warn()    { printf "  ! %s\n" "$1"; }
err()     { printf "  ✗ %s\n" "$1"; fail=$((fail+1)); }

echo "── kernel ────────────────────────────────────────────"
ver=$(uname -r)
maj=$(echo "$ver" | cut -d. -f1)
min=$(echo "$ver" | cut -d. -f2)
if [ "$maj" -gt 5 ] || { [ "$maj" -eq 5 ] && [ "$min" -ge 15 ]; }; then
    pass "kernel $ver (≥ 5.15 required)"
else
    err  "kernel $ver too old; need ≥ 5.15"
fi

echo "── BPF-LSM ───────────────────────────────────────────"
if [ -r /proc/config.gz ]; then
    cfg=$(zcat /proc/config.gz)
elif [ -r /boot/config-"$ver" ]; then
    cfg=$(cat /boot/config-"$ver")
else
    cfg=""
    warn "no kernel config readable; cannot verify CONFIG_BPF_LSM"
fi
echo "$cfg" | grep -q '^CONFIG_BPF_LSM=y' \
    && pass "CONFIG_BPF_LSM=y" \
    || err  "CONFIG_BPF_LSM not set; LSM enforcement unavailable"

if grep -qw bpf /sys/kernel/security/lsm; then
    pass "lsm= cmdline includes bpf"
else
    warn "lsm= cmdline does NOT include bpf — enforcement falls back to observe-only"
    warn "fix: add 'bpf' to GRUB_CMDLINE_LINUX in /etc/default/grub, then update-grub && reboot"
fi

echo "── BPF safety knobs ──────────────────────────────────"
v=$(sysctl -n kernel.unprivileged_bpf_disabled 2>/dev/null || echo 0)
if [ "$v" -ge 1 ]; then
    pass "unprivileged_bpf_disabled = $v"
else
    err  "kernel.unprivileged_bpf_disabled = 0 — set to 2 for production"
fi

echo "── caps and tools ────────────────────────────────────"
[ "$(id -u)" -eq 0 ] && pass "running as root" || err "must run as root"
command -v bpftool >/dev/null && pass "bpftool present" || warn "bpftool missing"

echo
if [ "$fail" -eq 0 ]; then
    echo "ready to launch hakam-node"
    exit 0
else
    echo "$fail blocking issue(s); fix before launch"
    exit 1
fi
```

The exact script will live alongside the demo materials. This appendix exists so the Q&A doc is self-contained even before Phase 3 #9 lands.

---

## Appendix B · References

- **BPF-LSM upstream documentation** — `Documentation/bpf/prog_lsm.rst` in the Linux source. Authoritative on hook semantics, return-value conventions, and what attach types exist.
- **LSM framework** — `security/security.c` and `include/linux/lsm_hooks.h`. The actual iterator that runs the chain.
- **BPF map types** — `Documentation/bpf/maps.rst`. LRU semantics for `BPF_MAP_TYPE_LRU_HASH`.
- **Cilium conntrack design** — their `bpf/lib/conntrack.h` is the canonical reference for sizing and eviction policy in production eBPF conntrack.
- **CVE history for unprivileged BPF** — CVE-2020-8835, CVE-2021-3490, CVE-2021-31440, CVE-2022-23222. We cite these when defending the `unprivileged_bpf_disabled=2` requirement.

---

## Appendix C · Things this doc deliberately does not promise

- This is **prep for hostile Q&A** about Phase 2. It is not a security audit, a threat model document, or a customer-facing claim. None of the answers here should be lifted into marketing copy.
- The "30-second answer" paragraphs are **rehearsal targets**, not exact transcripts. Internalise the structure, deliver in your own voice.
- Numbers in §4 (memory, throughput) are **estimates from spec, not measurements**. When Phase 2 #7 lands and we measure them on the demo box, update those numbers here with a note pointing at the bench rig.
- The bypass enumeration in §3 is the **set we know about as of 2026-05-31**. Any reviewer who shows us a new one — buy them a drink, then add it here.
