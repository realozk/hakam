# Phase 2 pre-start review — 2026-06-29

> Reviewer pass over the working tree before continuing the Arsenal roadmap
> (`docs/arsenal_roadmap.md`). Scope: confirm Phase 1 is genuinely closed, and
> audit the **uncommitted Phase 2 #6 (BPF-LSM `socket_connect`)** work that is
> sitting in the working tree before we start Phase 2 #7 (eBPF conntrack).

## TL;DR

Phase 1 is closed for real — the tracker matches the code. Phase 2 #6 is
~complete in the working tree (`hakam-ebpf/src/lsm.rs`, the `CONNECT_POLICY`
map, `attach_lsm`, and the `policy-block/unblock/list` CLI), uncommitted, and
the roadmap tracker still shows it `⬜`. The engineering is clean. Five issues
must be closed before we layer #7 on top of it.

| # | Issue | Severity | Status |
|--:|-------|:--------:|:------:|
| 1 | LSM enforcement is destination-keyed but labeled "per-process" | **High** (honesty / Q&A) | ✅ fixed |
| 2 | `preflight.sh` has no BPF-LSM kernel-detection check | Medium | ✅ fixed |
| 3 | `architecture.md` §4 still future-tense about #6 | Low (doc) | ✅ fixed |
| 4 | #6 uncommitted + unvalidated in-tree; tracker `⬜` | Medium (process) | ⏳ owner action |
| 5 | No smoke assertion that hakam-node survives LSM attach | Low | ⏳ owner action |
| — | `lsm.rs` header mis-describes LSM chain ordering | Trivial | ✅ fixed |

---

## Issue 1 — "per-process" enforcement is actually a destination blocklist

**Severity: High.** This is the one that loses you criterion 2 (honest
engineering) under hostile Q&A.

### What HEAD does

`CONNECT_POLICY` is an `LpmTrie<u32, u64>` keyed **only on the destination IP**.
`lsm.rs::try_connect` reads the `sockaddr_in`, and if the *destination* is in
the policy it returns `-EPERM`:

```rust
if CONNECT_POLICY.get(&Key::new(32, sa.sin_addr)).is_some() {
    return Ok(-EPERM);
}
```

There is no PID, TGID, UID, or cgroup in the key or the lookup. The hook denies
**any** process that connects to a listed destination. Yet `attach_lsm` prints:

```
LSM armed — socket_connect() egress enforcement (per-process)
```

### Why that's a problem

The Arsenal pitch leans on *per-process* as the differentiator. A kernel
networking reviewer reads "per-process enforcement", looks at the map key, and
says: *"there's no task identity in your policy — this is a destination
blocklist enforced at the syscall layer. The per-process part is your
tracepoint attribution, which runs after the fact and doesn't gate anything."*
That is correct, and once they catch one overstatement they discount the rest
of the demo. The real, defensible per-process story is **attribution** (#8 —
naming the originating PID/comm on a block), which is genuinely strong; the LSM
hook's real strength is **prevention at the syscall** (no packet is ever
created), which is *also* genuinely strong. Neither needs to be dressed up as
the other.

### The fix

Relabel the console line to describe what the hook actually does — deny the
`connect()` syscall before any packet exists — and drop the "(per-process)"
claim from the enforcement line. Per-process stays attached to attribution (#8),
where it's true.

```
LSM armed — socket_connect() syscall-layer egress denial (pre-packet)
```

### Why the fix is better than HEAD

- **Survives Q&A.** The claim now matches the map key. A reviewer who inspects
  the code finds the words and the implementation agree.
- **Keeps both real strengths intact.** "Pre-packet" is the honest, unique
  thing — the connection never forms. That's a *stronger* line than a vague
  "per-process", and it's defensible.
- **Doesn't dilute #8.** Attribution remains the place we say "per-process",
  and it earns it.
- **Cheap.** A one-line string change buys back the credibility a single caught
  overstatement would cost.

> Note: genuinely scoping the *policy* by PID/cgroup (so you can deny one
> process but not another to the same dst) is real work and belongs in #7 or
> post-Arsenal, not bolted on now. Logged, not done.

---

## Issue 2 — `preflight.sh` never checks for BPF-LSM

**Severity: Medium.**

### What HEAD does

`scripts/preflight.sh` walks Mac tooling, VM toolchain, kernel modules,
interfaces, build artifacts, ports, and reachability — but has **no check for
BPF-LSM availability**. The runtime path in `attach_lsm` *does* degrade to
observe-only when `CONFIG_BPF_LSM` is off or `bpf` isn't in the active LSM list,
which is good. But the roadmap risk register explicitly committed to:

> *"Ship a kernel-detection check in `scripts/preflight.sh`."*

…and it isn't there.

### Why that's a problem

The headline feature of the whole Phase 2 pivot is the LSM hook. On a reviewer's
box where `bpf` isn't in `/sys/kernel/security/lsm`, the demo silently runs in
observe-only mode and the single most quotable moment — `connect()` denied with
`EPERM` — never fires. Without a preflight signal you discover this *on stage*,
not 60 seconds before. The preflight script exists precisely to turn silent
stage failures into a pre-stage WARN; this is the most important thing for it to
catch and it's the one thing it doesn't.

### The fix

Add a check in the "VM · kernel + interfaces" section: read
`/sys/kernel/security/lsm` and confirm `bpf` is present. WARN (not FAIL),
because the observe-only fallback means the demo still runs — the operator just
needs to know enforcement is off before going on stage.

### Why the fix is better than HEAD

- **Closes a committed roadmap item.** The risk register promised exactly this.
- **Catches the failure at the right time.** Pre-stage WARN instead of a dead
  demo moment in front of the audience.
- **Matches the runtime contract.** It checks the same condition `attach_lsm`
  falls back on (`bpf` in the active LSM list), so preflight and runtime agree.
- **Correct severity.** WARN, not FAIL — the fallback is real, so it shouldn't
  block a demo that intentionally runs observe-only.

---

## Issue 3 — `architecture.md` §4 is still future-tense about #6

**Severity: Low (doc accuracy).**

### What HEAD does

`docs/architecture.md:89` still reads:

> *"Phase 2 #6 (`BPF-LSM socket_connect`) **will** close this for the
> `connect()` syscall path specifically."*

The roadmap's Phase 2 exit criteria say this admission should be replaced once
#6 lands, with the `connect()`-path scoping kept honest.

### Why that's a problem

The doc now lags the code. A reviewer reading "will close this" alongside a
live `EPERM` demo sees the docs trailing the implementation, which reads as a
project that doesn't keep its own paper trail straight — a small but real ding
on the "maintained project" signal.

### The fix

Rewrite the paragraph to present tense: the packet path remains reactive
(unchanged, still honest), **and** the `connect()` syscall path is now denied
pre-packet at the LSM hook — while explicitly preserving the honest scope
(connect()-based IPv4 flows only; UDP `sendto` and the packet path are still
reactive).

### Why the fix is better than HEAD

- **Doc matches code.** No "will" promising something the tree already does.
- **Keeps the honesty that earns trust.** The reactive-detection admission for
  the packet path stays; we only add the syscall-path prevention where it's
  real.
- **Pre-scoped for Q&A.** Stating "connect()-based IPv4 only, UDP still
  reactive" in the architecture doc means the reviewer's follow-up is already
  answered in writing.

---

## Issue 4 — #6 is uncommitted and unvalidated in-tree

**Severity: Medium (process). Owner action — not auto-fixed.**

### What HEAD does

The entire #6 change set lives only in the working tree (`git status` shows
`hakam-ebpf/src/lsm.rs` untracked and `main.rs`/`cli.rs` modified). It has not
been built or run — eBPF can't compile on macOS, and there's no VM-validation
record. The roadmap tracker still shows #6 as `⬜`.

### Why that's a problem

Starting #7 (the 10-day conntrack) on top of an uncommitted, never-run #6 means
any verifier rejection or self-networking regression from #6 surfaces tangled up
with #7 changes, and you can't cleanly bisect. The `⬜` is at least honest, but
the code being "done but invisible" invites exactly the kind of half-landed
state the feature-freeze discipline is meant to prevent.

### Recommended fix (owner)

1. Apply issues 1–3 (done below).
2. Validate on the VM end-to-end: `policy-block <dst>` → target process's
   `connect()` returns `EPERM` → HUD shows it; confirm observe-only fallback on
   a non-LSM kernel.
3. Commit #6 as its own commit (do **not** push — per standing instruction).
4. Flip the tracker to `✅` with the dst-keyed limitation noted, mirroring the
   honest limitation note already used for #8.

### Why this is better than HEAD

- **Clean bisect boundary** before #7 starts.
- **Verifier reality check** happens in isolation, where a rejection is
  attributable to #6 alone.
- **Tracker tells the truth** — `✅` with a scoped limitation, not a silent
  `⬜` hiding finished code.

---

## Issue 5 — no smoke assertion that hakam-node survives LSM attach

**Severity: Low. Owner action — not auto-fixed.**

### What HEAD does

The risk register feared the LSM hook denying hakam-node's *own* connects and
killing its WS clients, with "allowlist the hakam-node PID" as the mitigation.
With the current **destination-keyed, default-allow** design that fear is
largely moot: hakam-node is only ever denied if you explicitly `policy-block` a
destination it itself needs. There is no PID allowlist, and none is required.
But there's also no test asserting any of this.

### Why that's a (minor) problem

It's a correct-by-design property that isn't pinned by anything. A future change
to the policy default (e.g. a deny-by-default mode, or PID-scoping in #7) could
silently break hakam-node's own networking, and nothing would catch it.

### Recommended fix (owner)

- Add one assertion to `scripts/smoke.sh`: after the LSM program attaches, a WS
  client can still connect to hakam-node. Optionally add a doc line in
  `docs/phase2_qa_prep.md` explaining *why* no PID allowlist is needed
  (default-allow + dst-keying), so the Q&A answer is on paper.

### Why this is better than HEAD

- **Pins a property we currently only reason about.** Cheap insurance against a
  #7 regression.
- **Pre-answers the Q&A.** "Doesn't your own daemon get blocked?" → documented
  no, with the reason.

---

## Minor — `lsm.rs` header mis-describes the LSM chain

**Severity: Trivial.**

### What HEAD does

`hakam-ebpf/src/lsm.rs` header comment says the hook runs *"after the major LSMs
(capability/landlock/yama)"*. BPF-LSM hooks actually run **last** in the chain —
after the major MAC modules including SELinux/AppArmor — and any one of them
returning `-EPERM` first short-circuits before BPF is consulted.

### The fix

Correct the comment to state BPF-LSM runs last (after SELinux/AppArmor), so it
matches the chain-ordering answer already written in `docs/phase2_qa_prep.md`.

### Why the fix is better than HEAD

- **Internally consistent.** Code comment and Q&A prep now tell the same story.
- **Pre-empts the ordering question** with an accurate inline note for the next
  contributor.

---

## Fixes applied in this pass

- `hakam-node/src/main.rs` — relabeled the LSM-armed console line (Issue 1).
- `scripts/preflight.sh` — added BPF-LSM availability WARN check (Issue 2).
- `docs/architecture.md` §4 — present-tense, scoped rewrite (Issue 3).
- `hakam-ebpf/src/lsm.rs` — corrected LSM chain-ordering comment (Minor).

Left for the owner: validate + commit #6 and flip the tracker (Issue 4); add the
post-attach smoke assertion (Issue 5).

## Recommended sequence before Phase 2 #7

1. Eyeball the four applied fixes below.
2. Validate #6 on the VM (enforce + observe-only fallback).
3. Commit #6; flip roadmap tracker to `✅` with the dst-keyed limitation noted.
4. *Then* start #7 — it tightens #8's dst-keyed attribution to source-port
   precision and is the right home for genuine per-flow/per-process policy
   scoping, which retroactively strengthens #6.
