# Hakam v2 — Architecture and Implementation Plan

> Draft design notes. The direction and technical decisions are mine;
> I used AI to expand and organize the explanation.
> Proposals remain subject to implementation and testing.

> **Status:** Design proposal; not yet implemented.
>
> **Scope review:** 2026-10-02. The required proof of concept is narrowed to
> connection-based behavior on one Linux server, one application honeytoken,
> precise temporary containment, and measured operating cost. Detailed socket
> telemetry and Isolation Forest are conditional experiments. Fleet services
> and new packet-rate restrictions are outside this release.
>
> **Purpose:** This document is the source of truth for the proposed Hakam v2
> direction. It defines what Hakam remains, what v2 adds, how the new components
> integrate with the current code, how the system is deployed, how decisions are
> made, and what must be proven before behavioral enforcement is enabled.
>
> **Important:** Descriptions under "Current v1" describe code that exists.
> Descriptions under "Proposed v2" describe planned work. Nothing in the planned
> sections should be presented as an implemented capability until its phase exit
> criteria have passed.

---

## 1. Executive decision

Hakam remains a **per-host Linux eBPF firewall**. It is not becoming a SIEM,
general EDR, switch appliance, TLS proxy, or generic machine-learning platform.

The single v2 improvement is:

> **Add workload-aware behavioral detection so Hakam can identify and
> contain network-visible signs of compromise that do not contain a known
> payload signature.**

The existing signature engine, the new behavioral detectors, and optional
honeytoken events are all evidence sources for one local decision engine. They
are not separate products and they do not receive independent authority to
modify kernel policy.

The project message is therefore a progression, not a pivot:

```text
Hakam v1
  Recognize known malicious traffic and enforce blocks in the kernel.

Hakam v2
  Preserve v1, then add workload-aware evidence for repeated outbound
  beacon-like connections to an unexpected destination, with precise local
  containment and an application honeytoken as another evidence source.
```

Hakam must not claim that it "detects hackers" or "detects every zero-day."
The defensible claim is that it detects and contains specific, measured forms
of network-observable malicious behavior.

---

## 2. Permanent project boundaries

### 2.1 In scope

Hakam is responsible for:

- observing network activity on the protected Linux host;
- applying early packet enforcement through XDP and outbound enforcement hooks;
- associating outbound activity with a process, service, container, or cgroup
  when the kernel provides enough context;
- matching known plaintext attack patterns through the existing DPI path;
- extracting bounded, content-independent flow features;
- turning observations into typed evidence;
- applying explicit evidence rules through one serialized policy engine;
- temporarily denying a remote source or an exact workload/destination;
- explaining every userspace enforcement decision;
- expiring temporary enforcement automatically;
- exposing local operational state through terminal tools and structured logs.

### 2.2 Explicitly out of scope

Hakam v2 is not intended to provide:

- general endpoint malware detection;
- file integrity monitoring;
- memory scanning;
- arbitrary syscall auditing unrelated to network containment;
- user identity or attribution of an IP address to a human;
- full HTTP parsing or WAF compatibility;
- TLS interception or decryption;
- packet capture retention;
- a distributed consensus system;
- peer-to-peer policy sharing between agents;
- a required central control plane;
- a switch/router product mode;
- Windows or macOS enforcement;
- a new graphical product interface;
- automated model retraining on production hosts;
- permanent blocking based solely on one weak anomaly score.

### 2.3 Feature-admission rule

Every proposed feature must answer this question:

> Does it materially improve detection, attribution, decision quality, or local
> containment of a network-visible threat on one Linux host without putting
> expensive work in the packet path?

If the answer is no, it does not belong in the Hakam core.

### 2.4 Release scope and admission gates

| Work | Release decision | Reason / admission condition |
|---|---|---|
| Existing XDP/TC/LSM and signature DPI | Keep | Existing enforcement foundation |
| One evidence/decision/enforcement path | Required | Consistent ownership, expiry, and explanations |
| Connection events with workload/socket identity | Required | Fix attribution and detect payload-independent connection patterns |
| Periodicity plus destination history | Required | One coherent beacon-like scenario; numeric explanations and benign controls |
| One registered application honeytoken | Required | A distinct signal after TLS termination; reuse the same decision path |
| Headless service, rich terminal, structured logs | Required, small | Operate through terminal tools |
| Kernel-enforced expiry and scoped rule ownership | Required before new automatic containment | Prevent indefinite or unrelated blocks |
| Socket byte/packet telemetry | Conditional experiment | Include only if it adds held-out detection value within memory/CPU budgets |
| Isolation Forest | Conditional experiment | Include only if it beats the two explainable baselines at a matched false-alert budget |
| Fanout and transfer/exfiltration detectors | Deferred | Additional threat scenarios and telemetry costs; not required to prove this update |
| New suspect rate restrictions / ingress action DSL | Deferred | More packet-path state without proving the selected detection scenario |
| Fleet collector, policy distribution, central UI | Outside v2 | Separate future design after local acceptance |
| General process investigation / mandatory pidfd enrichment | Outside core | PID metadata is optional; Hakam contains network activity |

The required release does not depend on any conditional experiment succeeding.
Evidence of benefit means additional detections on held-out scenarios at the
same benign alert/containment limit, with measured cost. More features, a higher
anomaly score, or a more dramatic demo are not evidence of benefit.

The first supported target is IPv4 TCP connections created after attachment on
one Linux server with cgroup v2. Persistent sessions predating attachment,
connectionless UDP, IPv6, and container-specific interface/CNI coverage are
explicit limits until separately tested. Process names are explanatory metadata;
the central promise is accurate workload-scoped network decisions.

---

## 3. Fixed product decisions

These decisions are part of the architecture and should not be reopened during
implementation unless new measured evidence invalidates them.

1. **The interface is terminal-based.** The graphical frontend has been removed.
   The current CLI remains available; richer terminal views are proposed v2 work.
   Historical graphical demos require a pre-removal checkout.
2. **The accepted demo is preserved.** A known-good v1 tag or release must be
   created before v2 changes alter runtime behavior.
3. **The primary deployment is one autonomous agent per protected Linux
   server.** Multiple hosts run independently; fleet software is outside v2.
4. **Kernel enforcement never waits for userspace.** Model inference, logging,
   terminal rendering, disk access, and central communication are never part of
   the packet verdict path.
5. **Detectors do not enforce.** They emit evidence. One `DecisionEngine` emits
   verdicts, and one `Enforcer` owns userspace writes to enforcement maps.
6. **The existing kernel flood rule remains an explicit exception.** XDP may
   continue auto-blocking a source that exceeds its fixed emergency rate limit.
    This kernel-autonomous action must expose an auditable reason. It is a
    co-writer of the legacy blocklist and needs explicit ownership semantics
    before that map can safely host v2 decision rules.
7. **Behavioral detection starts in observation mode.** It cannot block until
   its correctness, false-positive behavior, and performance have been measured.
8. **Isolation Forest is a candidate detector, not the product identity.** It
   stays only if it performs better than simpler, explainable baselines.
9. **Honeytokens are supporting evidence.** They are detected by the protected
   application or reverse proxy after TLS termination and reported locally.
10. **Every temporary action expires.** Permanent rules require an explicit
    administrator command or external configuration. New v2 temporary rules
    check expiry in the enforcing hook; userspace cleanup is not the expiry
    mechanism.

---

## 4. Current v1 baseline

This section records what already exists so that v2 can reuse it instead of
silently reimplementing it.

### 4.1 Existing crates and applications

| Path | Current responsibility | v2 treatment |
|---|---|---|
| `hakam-common/` | Shared `no_std` kernel/userspace structs | Extend with versioned observation and policy types; preserve layout tests |
| `hakam-ebpf/` | XDP, TC, tracepoint, LSM, maps, conntrack | Preserve hot path; add workload-aware observation/enforcement incrementally |
| `hakam-node/` | Loader, DPI, CLI, metrics, maintenance, WebSocket; already runs without stdin on a non-TTY | Add independent terminal clients and decision/enforcement ownership |
| Terminal interface | Current line-based CLI | Extend with optional rich terminal views |
| `xtask/` | eBPF and userspace build/run orchestration | Extend for v2 build artifacts and VM validation |
| `scripts/` | Demo, test, attack, benchmark, setup | Keep v1 demo; add v2 lab and acceptance scripts separately |
| `bench/` | Current CPU/pps/drop benchmark results | Add PASS-path, behavior, queue, and model benchmarks |
| `corpus/` | Replayable attack traffic | Preserve; add versioned behavioral scenario metadata |

### 4.2 Existing kernel programs

| Program | Existing job | v2 relationship |
|---|---|---|
| XDP `hakam_ebpf` | IPv4 source block, per-IP rate limit, TCP sampling, conntrack update | Remains the earliest ingress enforcement point |
| TC `hakam_egress` | Drop egress packets whose destination is blocklisted | Remains global destination enforcement; may later be supplemented by workload-specific egress policy |
| Tracepoint `hakam_connect` | Observe IPv4 `connect()` and emit PID/comm/destination | Retained during migration; replaced or supplemented by cgroup-aware connection identity |
| LSM `hakam_connect_lsm` | Deny global destination policy before a connection forms | Preserved for manual/global policy; not sufficient by itself for workload-specific behavior |

### 4.3 Existing maps

| Map | Existing use | Planned v2 action |
|---|---|---|
| `BLOCKLIST` | CIDR-aware IP block with insertion timestamp; XDP and userspace both write | Preserve initially; version expiry/ownership before new automated rules; no new `RESTRICT` action in v2 |
| `CONNECT_POLICY` | Global outbound destination deny list | Preserve for administrator policy and global emergency response |
| `CONNTRACK` | Bounded per-flow packet/sequence state | Preserve; do not overload it with every behavioral feature until benchmarks justify changes |
| `PACKET_COUNTER` / `LAST_SEEN` | Per-IP rate accounting | Preserve the emergency flood guard |
| `PAYLOAD_EVENTS` | Sampled plaintext TCP bytes for DPI | Preserve only for signature DPI; do not use as the behavioral data source |
| `CONNECT_EVENTS` | Process/destination connection observations | Extend or supersede with workload-aware connection events |
| `DROP_COUNTER` / `LATENCY_HIST` | Drop and latency measurements | Preserve; add separate PASS-path benchmark instrumentation rather than permanently timing every PASS |
| `RING_OVERFLOW` | Lost payload sample count | Preserve and add independent counters for new event channels |
| `MONITOR_CFG` | Tracepoint CIDR scoping | Preserve while tracepoint compatibility remains |

### 4.4 Existing userspace flow

The current loader uses `Ebpf::load_file` and requires the compiled eBPF ELF
alongside the userspace executable. "Single binary" here preserves one
userspace executable and no extra service; it is not a claim that the current
artifact is already self-contained. Record the ELF version/checksum with the
release. Embedding it is a packaging choice, not a new detection prerequisite.

Today, `hakam-node/src/dpi.rs` consumes sampled payloads, runs reassembly and
signature matching, then inserts the source address directly into `BLOCKLIST`.
The tracepoint consumer separately stores the most recent process associated
with `(destination address, destination port)`.

V2 changes the ownership without discarding the implementation:

```text
Current:
  DPI match ─────────────► BLOCKLIST insert

V2:
  DPI match ─► Evidence ─► DecisionEngine ─► Verdict ─► Enforcer ─► map update
```

The existing reassembler and signature matcher remain valid detector internals.
Only their output path changes.

### 4.5 Existing limitations that v2 must not hide

- IPv4 only.
- Plaintext signature inspection only; encrypted application content is not
  visible.
- `PAYLOAD_EVENTS` does not represent every packet and is unsuitable as a
  complete behavioral feed.
- Current process attribution is heuristic: the most recent process connecting
  to a destination/port wins.
- Current XDP rate limiting is per CPU.
- The fixed 500-pps source guard is a demo policy, not a safe general server
  default. Legitimate high-rate clients or many users behind one NAT can trigger
  it. Always-on deployment requires an explicit operational rate policy and
  benign offered-load tests; preserving the demo value is not production tuning.
- Current blocklist capacity is bounded.
- `metrics::ticker` currently walks the entire 65,536-entry `CONNTRACK` key
  space once per second to display a flow count. Production v2 must remove this
  default scan even if the new behavioral collector is event-driven.
- The block TTL is currently a userspace sweep every 30 seconds; XDP and TC do
  not check expiry. It cannot guarantee timely expiry if maintenance stalls.
- Userspace `boot_time_ns()` uses `CLOCK_BOOTTIME`, while BPF
  `bpf_ktime_get_ns()` uses `CLOCK_MONOTONIC`. Suspend can therefore distort
  cross-domain ages. V2 must use the same clock on both sides.
- XDP parse failures currently return `XDP_ABORTED`, which drops the packet.
  The proposed observation fail-open rule is a future requirement, not current
  behavior; test and correct this deliberately before production claims.
- The current loader does not establish a documented pin/recovery contract.
  Continuity through daemon death/restart is not an existing guarantee.
- The LSM program does not read the previous BPF-LSM return value. Preserve
  another BPF security program's denial when composing hooks; otherwise a
  Hakam allow/error path may override it. This needs an explicit coexistence
  test, not an assumption that fail-open is always safe.
- Existing latency numbers measure the DROP path, not clean PASS-path overhead.
- The benchmark WebSocket sampler is unreliable.
- Hakam is still a research/demonstration project until deployment hardening and
  broader validation are completed.

---

## 5. Threat model

### 5.1 Threats v2 intends to detect or contain

1. A remote source sends a known malicious plaintext request.
2. A remote source exceeds the emergency packet-rate policy.
3. A compromised local service creates repeated outbound connections that look
   like beaconing.
4. A local workload communicates with destinations or ports that are unusual
   for that workload.
5. Conditional future telemetry may identify transfer/fanout patterns, but
   neither is a required v2 detection claim.
7. An attacker uses a registered decoy credential, endpoint, or object and the
   protected application reports the event.
8. An administrator installs an explicit local ingress or outbound deny rule.

### 5.2 Threats v2 does not claim to solve

- A privileged root attacker who can unload Hakam, modify its binary, or alter
  its policy files.
- Malicious behavior with no network-observable difference from the workload's
  normal behavior.
- Semantic inspection of encrypted content.
- Correct attribution of a NATed remote IP to one human.
- All covert channels.
- Kernel compromise below Hakam's hooks.
- IPv6 attacks until an explicit IPv6 phase is designed and tested.
- Attacks on switches or other machines where no Hakam agent is installed.

### 5.3 Trust boundaries

| Boundary | Trusted input | Untrusted input | Required defense |
|---|---|---|---|
| Network → eBPF | Nothing from packet bytes | All packet fields and lengths | Verifier-safe bounds checks; fail-open parse errors unless policy says otherwise |
| eBPF → userspace ring | Shared struct layout | Event volume and missing events | Version/layout tests, length checks, overflow counters |
| Application → honeytoken socket | Registered local UID/application ID | Event payload and claimed source | Unix credentials, size limits, schema validation, deduplication |
| CLI → control socket | Authorized local admin group | Command arguments | Separate socket permissions, strict parsing, audit log |
| Model file → detector | Explicitly configured model path | All model bytes | Size cap, schema version, checksum, complete validation before activation |
| Policy file → decision engine | Root-owned configuration | Invalid thresholds or actions | Schema validation, semantic validation, atomic reload, retain last valid policy |

---

## 6. Deployment model

### 6.1 Primary mode: autonomous host agent

Install one Hakam agent on every **protected Linux server**, not automatically
on every device in the network.

```text
┌──────────────── Linux server A ────────────────┐
│ application / service / container              │
│                    │                           │
│       cgroup/connect + cgroup skb + LSM        │
│                    │                           │
│              Hakam kernel maps                 │
│                    │                           │
│              hakam-node daemon                 │
│                    │                           │
│          local sockets + structured log        │
└────────────────────────────────────────────────┘

┌──────────────── Linux server B ────────────────┐
│ independent Hakam agent and independent policy │
└────────────────────────────────────────────────┘
```

Every host must continue enforcing local confirmed rules when:

- terminal clients disconnect;
- the CLI and service operate without a graphical frontend;
- the behavioral model is disabled;
- a local log subscriber falls behind.

Observation is asynchronous: the first suspicious connection can reach its
destination before userspace produces a verdict. A connection gate prevents
future connects; it cannot revoke data already sent. Existing-session denial
requires a separately validated packet hook. The demo and docs must identify
which of those two effects is actually enabled.

Deployment configuration names the protected interface and cgroup v2 subtree.
At startup show the network namespace, interface/attach mode, hook coverage,
and selected workload cgroups. One NIC attachment does not imply loopback,
other NICs, every container veth, or every namespace is covered. Select one
reference topology first and test its real route in both directions.

### 6.2 Why the primary mode is not a switch

A switch or gateway can see packets, but it normally cannot reliably identify
the local PID, systemd service, container, or cgroup that caused a connection.
Placing Hakam only at a switch would remove its process-aware differentiator and
turn it into a conventional network firewall.

Gateway mode may be investigated in a separate future document. It is not part
of the v2 proof of concept.

### 6.3 Workstations

The architecture can later support Linux workstations, but the v2 proof of
concept targets servers because:

- services have more stable behavioral baselines;
- cgroups/systemd units provide useful workload identity;
- the deployment surface is smaller;
- workstation software creates much noisier destination behavior;
- Hakam does not provide Windows or macOS enforcement.

### 6.4 Several protected servers

Run the same local agent on each selected Linux server. Each maintains its own
policy, evidence, and enforcement. Communication between agents is unnecessary
for this proof of concept. A collector, event export protocol, remote policy
distribution, or gateway mode needs a separate proposal after local v2 passes;
none is an implementation phase or acceptance dependency here.

---

## 7. Proposed v2 architecture

### 7.1 Logical flow

```text
                              KERNEL DATA PLANE

 ingress packet ─► XDP ─► BLOCK / emergency rate rule / PASS
                       └─► bounded flow counters and DPI sample

 outbound connect ─► cgroup/connect4 and/or BPF-LSM
                       ├─► explicit policy deny
                       └─► workload-aware connection observation

 optional detail ─► cgroup skb ingress/egress (admitted experiment only)
                       └─► capped socket summaries

                                   │
                           maps / bounded events
                                   │
                                   ▼
                           USERSPACE CONTROL PLANE

                     Observation normalization
                                   │
             ┌─────────────────────┼────────────────────┐
             ▼                     ▼                    ▼
      Signature detector    Behavior detectors    Honeytoken input
             │                     │                    │
             └─────────────────────┼────────────────────┘
                                   ▼
                               Evidence
                                   ▼
                      EvidenceStore + DecisionEngine
                                   ▼
                                Verdict
                                   ▼
                               Enforcer
                      ┌────────────┼────────────┐
                      ▼            ▼            ▼
                  BPF maps      Audit log    Local events
```

### 7.2 Component ownership

| Component | Owns | Must not own |
|---|---|---|
| Kernel programs | Immediate packet/syscall verdicts and bounded counters | ML, JSON, logging, policy aggregation |
| Observation normalizer | Conversion from source-specific event to shared type | Blocking decisions |
| Detector | One detection method | Direct map access |
| EvidenceStore | Active evidence and expiry | Packet parsing |
| DecisionEngine | State transitions and verdict creation | Raw BPF file descriptors |
| Enforcer | Validated, idempotent map operations | Risk scoring |
| Audit sink | Durable explanation of decisions | Enforcement authority |
| `hakamctl` | Display and authorized commands | Daemon lifecycle or direct map access |
| Demo telemetry adapter | Optional event stream and demo controls | Production control or required telemetry |

### 7.3 Backpressure rule

Every queue is bounded. On saturation:

1. Network packet handling continues.
2. Existing kernel rules continue.
3. A loss counter increases.
4. Low-priority telemetry is discarded before decision-critical evidence.
5. The daemon raises a visible degraded-health event.
6. The system never blocks a source merely because observation data was lost.

---

## 8. Shared data contracts

The exact Rust layout may change during implementation, but the semantic
contracts below are fixed. Kernel-facing structs remain `#[repr(C)]`, explicit
about padding and byte order, with layout tests in `hakam-common`.

### 8.1 Subject identity

```rust
pub enum Subject {
    RemoteIp {
        addr: std::net::Ipv4Addr,
    },
    Workload {
        cgroup_id: u64,
        workload_generation: u64,
    },
    WorkloadDestination {
        cgroup_id: u64,
        workload_generation: u64,
        dst_addr: std::net::Ipv4Addr,
        dst_port: u16,
        protocol: u8,
    },
    Socket {
        cgroup_id: u64,
        socket_cookie: u64,
    },
    Process {
        cgroup_id: u64,
        tgid: u32,
        start_time_ns: u64,
    },
    Flow {
        cgroup_id: Option<u64>,
        src_addr: std::net::Ipv4Addr,
        dst_addr: std::net::Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
        direction: Direction,
    },
}
```

Rules:

- `RemoteIp` does not mean a person.
- PID/TGID is never an authoritative enforcement key. A `Process` subject exists
  only with start time captured in the original kernel context and verified;
  otherwise the event remains
  attached to its workload/socket and PID/comm are display metadata.
- `Workload` is the preferred enforcement identity for systemd services and
  containers.
- `WorkloadDestination` is the behavior decision subject. Periodic connections
  to destination A cannot corroborate novelty at destination B. Whole-workload
  summaries may start monitoring, but cannot select an arbitrary destination
  for denial.
- All local identities are scoped to the host boot ID and observation epoch.
  A workload registry tracks configured cgroup identity, a retained live cgroup
  reference, and a userspace generation. Recreation at the same path creates a
  new generation and cold baseline. Release checks generation and rule ID;
  numeric IDs and paths are never treated as everlasting identities.
- `Socket` uses the kernel socket cookie as its lifetime identity. The cookie is
  stable for the life of that socket and prevents short-lived PID reuse from
  merging two connections.
- `Flow` is used for correlation and explanation; not every flow should become
  a separate long-lived decision subject.

### 8.2 Observation

```rust
pub struct Observation {
    pub schema_version: u16,
    pub id: u128,
    pub source: ObservationSource,
    pub subject: Subject,
    pub monotonic_ns: u64,
    pub wall_time_ms: Option<u64>,
    pub payload: ObservationPayload,
}
```

`ObservationSource` includes:

- `DpiMatch`;
- `KernelRateLimit`;
- `ConnectAttempt`;
- `FlowWindow`;
- `HoneytokenSocket`;
- `ManualCommand`;
- `PolicyViolation`;
- `HealthSignal`.

Observations are facts. They do not contain enforcement actions.

### 8.3 Evidence

```rust
pub struct Evidence {
    pub schema_version: u16,
    pub id: u128,
    pub observation_ids: Vec<u128>,
    pub subject: Subject,
    pub family: EvidenceFamily,
    pub detector_id: String,
    pub detector_version: String,
    pub strength: EvidenceStrength, // weak | compound-validated | direct
    pub correlation_group: String,  // signals derived from the same observations
    pub complete: bool,
    pub severity: Severity,
    pub observed_ns: u64,
    pub expires_ns: u64,
    pub summary: String,
    pub attributes: BTreeMap<String, String>,
}
```

Evidence families name detector results; they are not a claim of independence:

- `Signature`;
- `BehaviorPeriodicity`;
- `BehaviorDestinationNovelty`;
- `BehaviorFanout`;
- `BehaviorTransferRatio`;
- `BehaviorModel`;
- `Honeytoken`;
- `KernelRateLimit`;
- `ExplicitPolicy`;
- `Manual`.

Repeated evidence updates one bounded `(subject, detector, window)` record.
Periodicity, novelty, and a model using those features belong to the same
behavior correlation group. The model cannot turn the same measurements into
an additional confirmation vote. Distinct registered decoy use or a scoped
signature observation is a different source; combining them still requires
matching subjects and a stated rule.

### 8.4 Verdict

```rust
pub struct Verdict {
    pub id: u128,
    pub subject: Subject,
    pub previous_state: DecisionState,
    pub next_state: DecisionState,
    pub rule_id: String,
    pub action: Action,
    pub evidence_ids: Vec<u128>,
    pub policy_version: String,
    pub created_ns: u64,
    pub expires_ns: Option<u64>,
    pub reason: String,
}
```

### 8.5 Enforcement result

```rust
pub struct EnforcementResult {
    pub verdict_id: u128,
    pub attempted_action: Action,
    pub map_name: Option<String>,
    pub key_summary: String,
    pub success: bool,
    pub changed_existing_rule: bool,
    pub error: Option<String>,
    pub completed_ns: u64,
}
```

The result is audited even when enforcement fails.

A verdict describes requested action. Enter/report actual `Contained` state only
after the enforcer confirms required map updates and the applicable hook is
active for that scope. On failure remain `Suspect` with `enforcement_failed`;
never display a blocked subject merely because a verdict was queued. Partial
multi-map application is audited and rolled back only for matching decision
ownership, without deleting unrelated policy.

---

## 9. Decision engine

### 9.1 States

```text
NORMAL ──────► WATCHING ──────► SUSPECT ──────► CONTAINED
  ▲                │                │                │
  └────────────────┴────────────────┴──── expiry ───┘
```

| State | Meaning | Default traffic action |
|---|---|---|
| `Normal` | No active meaningful evidence | No change |
| `Watching` | Weak or single-source anomaly | No traffic modification |
| `Suspect` | Compound pattern needs review or acceptance validation | Observe and alert |
| `Contained` | Strong evidence or explicit policy | Temporary block/deny |
| `Released` | Previous action expired or was removed | Remove enforcement, retain audit history |

`Released` is an audit transition. The active state becomes `Watching` during a
short cooldown, then `Normal` if no evidence remains.

### 9.2 Explicit rules instead of arbitrary risk arithmetic

The first implementation uses a small deterministic rule table. Uncalibrated
0–100 weights and corroboration bonuses are removed from the required design.
An unusual pattern can be real without being malicious; invented score sums
would conceal that distinction.

| Evidence / condition | Initial state and action |
|---|---|
| New destination alone | `Watching`; retain explanation, allow traffic |
| Repeated timing pattern alone | `Watching`; retain explanation, allow traffic |
| Complete periodic-plus-novel pattern for the same workload/destination | `Suspect`; alert in observe mode |
| Accepted behavior rule after held-out and shadow gates | Short exact workload/destination denial, only when explicitly enabled |
| Registered decoy use with proven source attribution | Short source block only if that token's policy authorizes it |
| Existing DPI detection | Preserve v1 temporary source block during migration |
| Administrator deny | Apply the explicit configured rule |

### 9.3 Compound behavior rule

One candidate rule requires all of the following:

1. The workload is enrolled and its baseline has completed warm-up.
2. Timing is measured for the same IPv4/TCP destination and port, with the
   configured minimum number of distinct attempts and minimum observation span.
3. The timing variation is below a threshold selected on training data.
4. The destination is absent from the accepted workload baseline.
5. The observation window is complete and the workload identity is live.
6. No protected-service exception applies.

This is a compound behavior heuristic, not two independent witnesses. Periodic
health checks and legitimate services contacting new endpoints are required
negative controls. Automatic action stays disabled until this exact rule meets
the declared false-containment and cost targets. A new model score cannot
satisfy a missing clause. Repeated alerts never become a block just by count.

Every rule records its version, evidence requirements, dedupe key, mode, exact
action scope, TTL, and cooldown. State returns to `Normal` after evidence expiry;
release enters a cooldown that requires newly observed qualifying evidence
before another automatic containment. Old evidence cannot renew a block forever.

### 9.4 Hard-evidence overrides

A hard-evidence override may request immediate temporary containment when:

- a registered honeytoken event is accepted from an authorized local producer,
  its deployment/source attribution is verified, and its policy permits action;
- an administrator explicitly requests a block;
- an existing explicit policy is violated;
- the current kernel emergency flood guard fires.

A DPI signature may request immediate temporary containment under the existing
v1 behavior, but it must remain reversible and audited. Signatures are not
described as mathematically zero-false-positive.

### 9.5 Evidence expiry and decay

- Evidence has a fixed expiry timestamp.
- The first implementation should use expiry rather than continuous floating
  point decay so decisions remain deterministic and easy to test.
- On evidence insert and maintenance tick, expire affected records and evaluate
  the subject's explicit rules. Use an expiry heap/timing wheel with a bounded
  tick budget, rather than walking all subjects each tick.
- Model inference never extends an earlier evidence item's lifetime; it creates
  a new evidence item.
- A subject record with no evidence and no active enforcement is removed after
  its audit cooldown.
- Bound subjects, evidence per subject, total evidence, attribute/string length,
  and total retained bytes. Per-subject caps alone do not bound daemon memory
  adequately. Eviction of evidence changes completeness; it does not grant
  enforcement authority.

### 9.6 Determinism and serialization

Run the `DecisionEngine` as one Tokio task consuming a bounded `mpsc` channel.
This serializes transitions without a lock shared by detectors.

Detectors may run concurrently, but they only send `Evidence` messages. The
decision engine assigns transition order when messages arrive. Every message
contains a monotonic timestamp so out-of-order arrivals can be recorded and
handled consistently. One consumer does not guarantee identical outcomes from
different arrival orders: use explicit event-time rules, a bounded lateness
allowance, and reject stale evidence for new action. Replay tests use the recorded
order and must reproduce the same verdicts.

---

## 10. Enforcement design

### 10.1 Enforcer responsibilities

The `Enforcer`:

- validates that the action is compatible with the subject;
- converts typed addresses to the exact kernel byte order;
- performs idempotent map insert/remove operations;
- records insertion and expiry time;
- returns a structured result;
- never invents a stronger action than the verdict;
- never calculates risk scores;
- serializes conflicting updates for the same key;
- reconciles active userspace decisions with kernel maps after startup.

### 10.2 Actions

```rust
pub enum Action {
    None,
    Watch,
    BlockRemoteIp {
        prefix_len: u8,
        ttl_secs: u32,
    },
    DenyGlobalDestination {
        prefix_len: u8,
        ttl_secs: u32,
    },
    DenyWorkloadDestination {
        cgroup_id: u64,
        dst_addr: std::net::Ipv4Addr,
        dst_port: u16,
        protocol: u8, // first release: TCP only, exact port
        ttl_secs: u32,
    },
    Release,
}
```

### 10.3 Temporary rule expiry and writer ownership

Phase 1 keeps the legacy ABI for the existing demo. New automated v2 containment
requires explicit expiry in every hook that enforces that rule. A userspace
cleanup sweep cannot guarantee expiry if the daemon stalls or disappears.

Minimal versioned value for decision-owned deny rules:

```rust
#[repr(C)]
pub struct IpPolicyValue {
    pub inserted_ns: u64,
    pub expires_ns: u64,
    pub reason_id: u64,
    pub rule_id: u64,
}
```

`expires_ns == 0` means administrator-configured permanent deny. Otherwise a
rule applies only while `now_ns < expires_ns`. All timestamps use
`bpf_ktime_get_ns()` and userspace `CLOCK_MONOTONIC`; suspend is excluded on both
sides. Reboot changes the identity epoch, and monotonic deadlines are never
copied into a new boot.

The existing emergency XDP rule writes `BLOCKLIST` too. Calling the userspace
enforcer the sole writer without accommodating this would be incorrect. The
v2 migration must establish exclusive ownership:

- `SOURCE_DENY_V2`: userspace enforcer only; XDP/TC read;
- `FLOOD_BLOCK_V2`: kernel emergency guard writes; XDP/TC read; fixed temporary
  expiry; userspace may inspect it but does not delete/overwrite its decisions;
- workload/destination deny: userspace enforcer only; cgroup hook reads.

Existing global `CONNECT_POLICY` stays administrator-managed. If its command
offers a temporary TTL, version its value too and check the same deadline in
LSM; otherwise reject that TTL as unsupported. Do not display a future expiry
for a hook that only tests key presence.

This candidate adds a policy lookup on unblocked traffic. Its PASS-path cost is
a required benchmark, not something to conceal with a "one lookup" claim. If
the cost fails the budget, the migration remains experimental until an equally
correct measured alternative exists. Do not merge writers into one value to
save a lookup without a race/priority proof. No new rate restriction is added.

Decision/administrator enforcement maps use fixed capacity and never LRU
eviction: pressure must not silently remove an existing confirmed deny. Failed
insertion returns a failed result and visible health state.

The separate flood map is a bounded, best-effort automatic cache; a measured LRU
candidate avoids accumulating expired entries forever when its only writer is
the kernel. Pressure can evict a temporary flood entry, while the existing
per-CPU rate check still runs. Report saturation/insertion pressure and test
the resulting protection under many sources. Never place administrator/DPI/
honeytoken decision rules in this evictable map. The emergency guard drops the
triggering packet when cache insertion fails, but cannot promise durable source
denial at capacity. If a strict non-evicting flood deny is required later, it
needs a proven expiry-reclamation/writer protocol rather than a racy userspace
lookup-then-delete of a kernel-refreshed entry.

For LPM decision maps, reject overlapping prefixes in the v2 policy registry
and leave current rules intact on rejection. An expired specific entry can mask
a still-active broader prefix, so simply checking the first LPM match's expiry
is insufficient with overlapping rules. Dynamic source blocks are `/32` only;
do not install one beneath an existing covering decision deny. More general
prefix precedence needs a separate tested design. Phase 1 retains legacy
semantics; these stricter rules apply to the versioned v2 map.

Userspace uses a bounded expiry index for cleanup. Delayed deletion consumes
capacity but cannot extend kernel denial. Every release verifies rule ownership
and removes only the matching rule, preserving active administrator policy.

### 10.4 Workload-specific outbound policy

The v2 proof of concept should prefer cgroup/workload identity over raw PID for
outbound containment.

Initial exact-match key:

```rust
#[repr(C)]
pub struct WorkloadDestinationKey {
    pub cgroup_id: u64,
    pub dst_addr: u32,
    pub dst_port: u16,  // exact port; no wildcard in the first release
    pub protocol: u8,
    pub _pad: u8,
}
```

The first proof of concept supports exact IPv4/TCP destination and port only.
Its value contains `expires_ns`, `rule_id`, and workload generation where the
verified hook can check it. A zero cgroup ID/cookie is unknown, never root or
"all workloads." CIDR and wildcard-port workload rules are deferred; a hash
lookup does not implement a wildcard just because its key stores zero.

Potential hooks:

- `cgroup/connect4` for denying new IPv4 connections from the affected cgroup;
- `cgroup_skb/egress` for accounting and, if validated, denying packets on an
  already-established flow;
- existing BPF-LSM `socket_connect` for administrator-managed global policy.

Hook return conventions differ: a cgroup connect program returns its documented
allow/deny result, while BPF-LSM uses its own return/error convention and must
propagate a prior nonzero BPF-LSM result. Observation fail-open must never undo
an existing denial from another security program. Test coexistence before
claiming additive enforcement.

The loader enrolls a configured cgroup v2 subtree. Observation may attach at the
parent, but containment should attach to the exact live workload cgroup using
a retained reference. Resolve ancestry deliberately: a parent attachment does
not mean a child socket's ID equals the parent's ID. Packet hooks use socket
ownership, not the current task (which can be a softirq worker). Moving tasks
between cgroups, inherited/passed sockets, and systemd restarts are explicit
tests; uncertain ownership disables automatic action for that subject.

The first guaranteed action is denial of future connects. Existing-flow packet
denial is an admitted extension only after helper availability, established
socket association, expiry, and unrelated-workload isolation pass on the target
kernel. Global IP blocking is never the fallback for unavailable workload
containment. In that case remain in observation mode and report the limitation.

### 10.5 Idempotency

Applying the same verdict twice must not extend its TTL accidentally unless the
policy explicitly says repeated evidence refreshes containment.

Use a userspace enforcement index:

```text
enforcement key → verdict id, map key, inserted time, expiry, action
```

On repeated verdicts:

- identical verdict ID: return the existing result;
- same key and stronger action: replace only if policy permits escalation;
- same key and weaker action: do not downgrade an unexpired administrator rule;
- release: remove only the rule owned by the matching decision lineage.
- store active owners for a key; retiring one automatic owner cannot delete a
  stronger administrator owner. Serialize changes and expiry through the same
  enforcer, and check workload generation before acting.

### 10.6 Process lifetime and recovery contract

Closing terminal clients has no effect on the daemon or its attachments. Daemon
death is a different event. A userspace process alone does not keep every BPF
link/map alive across restart.

The research POC may report `recovery=reattach` with an explicitly measured
coverage gap. It cannot claim continuous enforcement through restart. Unattended
always-on acceptance requires a verified pin/adoption design for the supported
hook types, boot/ABI checks, single-daemon ownership, restart reconciliation, and
clean administrative removal. Pinning a map alone does not preserve its program
attachment. Do not overwrite an unknown attachment or adopt a stale ABI.

On restart, reset behavioral baselines to warm-up unless a separately validated
baseline artifact is supplied. Adopt only known unexpired rules with recoverable
ownership; never convert orphaned rules into permanent ones. Retained temporary
rules must still expire in the kernel without userspace. Record restart gaps
and actual recovery mode in status and audit output. Full evidence persistence
is unnecessary for this release.

---

## 11. Behavioral observation

Required v2 collection is connection-based. For enrolled workloads, consume
bounded `connect4` attempt events, keep per-CPU attempt totals, and calculate
timing/destination history in userspace. It does not require per-packet behavior
counters, sockops state, socket storage, or full-flow reports.

Sections 11.3–11.5 describe an optional detail experiment. Enable it only after
the connection detector demonstrates a specific missed scenario that detail can
improve. Additional hooks stay unattached when this experiment is disabled.

### 11.1 Why `PAYLOAD_EVENTS` cannot be reused

The DPI ring contains only sampled plaintext TCP payloads and intentionally
misses traffic outside its sampling conditions. Basing behavior on that ring
would bias the model toward larger plaintext requests and miss short or
encrypted beacons.

Behavioral features therefore come from connection and flow metadata, not DPI
payload samples.

### 11.2 Workload-aware connection observation

For enrolled workload IPv4/TCP attempts, collect a bounded event containing
the workload identity and a kernel socket cookie:

```rust
#[repr(C)]
pub struct WorkloadConnectEvent {
    pub schema_version: u16,
    pub event_kind: u16,
    pub event_size: u32,
    pub monotonic_ns: u64,
    pub socket_cookie: u64,
    pub cgroup_id: u64,
    pub process_start_ns: u64, // 0 when the hook cannot read it safely
    pub tgid: u32,
    pub pid: u32,
    pub uid: u32,
    pub dst_addr: u32,
    pub dst_port: u16,
    pub protocol: u8,
    pub flags: u8,
    pub comm: [u8; 16],
    pub _pad: [u8; 4],
}
```

An attempt is not a successful connection. Its flags identify observed/denied
status known in this hook; it cannot report a later TCP handshake as successful.
Repeated `connect()` calls on one socket remain distinct attempts. Label any
feature or alert based only on attempts accordingly. Confirmed establishment is
optional sockops evidence after validation, with a distinct event kind.

The kernel socket cookie is the authoritative lifetime identity for the
connection. Linux documents it as stable for the life of the socket and suitable
as a global socket identifier. The cgroup is the authoritative policy identity
for the workload. PID, TGID, UID, and `comm` are attribution metadata.

The exact helper availability must be verified on the minimum supported kernel
and in the pinned Aya version. The current dependency exposes cgroup socket
address, cgroup skb, sockops program types, and the raw socket-cookie helper, but
does not expose every desired socket-storage abstraction through a high-level
map wrapper. Phase 4 begins with the required connection-helper load spike;
socket-storage support belongs to the optional detail spike. The
acceptable outcomes are:

1. use the supported Aya abstraction directly;
2. upgrade Aya in an isolated compatibility change; or
3. implement a narrow, audited wrapper around the required map/helper ABI.

The architecture must not assume a helper works in a hook until that spike loads
successfully on the minimum kernel.

Explicit layout tests cover event version/size, padding initialization, address
and port byte order, and decoding without alignment assumptions. At runtime
wrap events with host boot ID and collector epoch. Cookie or cgroup lookup
failure is a measured unknown identity; it cannot authorize broader action.

The required detector filters to TCP. Although `connect4` can also observe
connected UDP, sockops close/state callbacks do not supply its general lifecycle.
UDP detection needs a separate tested design and is not silently treated as
complete here.

### 11.3 Optional two-tier flow accounting

V2 must not create one global hash entry and one ring event for every packet.
Use two accounting tiers:

1. **Workload aggregate tier** — per-CPU connection-attempt totals for a capped
   enrolled cgroup set. Packet/byte aggregates exist only in an admitted detail
   experiment. Do not multiply per-CPU state by arbitrary remote destinations.
2. **Socket detail tier** — a fixed-capacity cookie-keyed hash is the initial
   memory-bounded candidate. Socket-local `BPF_MAP_TYPE_SK_STORAGE` is an
   alternative only after a provable allocation cap and compatible helpers are
   demonstrated. LRU eviction is an optional telemetry-only fallback; it must
   mark data incomplete and be benchmarked under churn.

Candidate detail value (not required for connection-only v2):

```rust
#[repr(C)]
pub struct SocketTelemetry {
    pub socket_cookie: u64,
    pub counter_generation: u64,
    pub cgroup_id: u64,
    pub opened_ns: u64,
    pub last_seen_ns: u64,
    pub next_report_ns: u64,
    pub packets_out: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub bytes_in: u64,
    pub event_sequence: u64,
    pub dst_addr: u32,
    pub dst_port: u16,
    pub protocol: u8,
    pub _pad: [u8; 9],
}
```

Socket storage ties cleanup to socket lifetime, but it is not inherently bounded:
its map requires `max_entries = 0`. Limiting the number of watched cgroups does
not limit sockets inside a watched cgroup. Do not advertise it as fixed-memory
without a separately verified per-workload/global admission and release quota.
If that quota cannot be proved under close/missed-event races, use the fixed-cap
hash or leave detail disabled. Kernel automatic cleanup also does not eliminate
counter concurrency; section 11.7 still applies.

The cookie-keyed hash inserts with `BPF_NOEXIST` only at admitted lifecycle
points, never per packet. When full, decline detail and report the gap without
dropping traffic. Delete on validated close; bounded low-frequency cleanup may
recover leaked telemetry entries. An expired/re-created telemetry entry starts
a new counter generation and cannot produce a delta against an earlier value.

Kernel values use integers only. Variance, ratios, normalization, and windowing
belong in userspace.

Detailed per-socket packet accounting should be adaptive rather than an equal
cost paid by every workload forever:

```text
Normal workload
  connection attempts + cheap per-CPU attempt totals

Watching/Suspect workload
  enable per-socket ingress/egress counters and rate-limited summaries

Contained/Released workload
  enforce or detach detail collection after cooldown
```

The preferred implementation is to attach the detail cgroup-skb program only to
a watched workload cgroup, with a hard maximum number of watched cgroups. This
keeps the extra per-socket update out of normal workloads. If dynamic attachment
is not reliable in the supported Aya/kernel matrix, the fallback is one small
watched-cgroup flag lookup in the detail hook. That fallback must pass the
PASS-path budget before adoption.

Connection timing and destination history decide whether an admitted detail
experiment is justified. Enrollment, attachment, and detail state creation all
have bounded limits. Starting detail later cannot recover bytes sent earlier;
reset the detail window at activation and mark its prior history unavailable.
Persistent low-rate traffic that never reconnects may produce no trigger. Such
coverage needs a separate experiment and must not be implied by this funnel.

### 11.4 Event-driven collection; no steady-state full-map scan

The original draft proposed periodic userspace snapshots as the initial path.
That is acceptable for a small experiment but not as the production steady-state
design: scanning `N` flows every few seconds creates `O(N)` userspace work even
when most flows are idle.

The v2 steady-state design is event-driven:

1. `cgroup/connect4` emits one connection-attempt event with socket cookie and
   workload identity.
2. In the optional detail experiment, `sockops` emits established/close events
   where the selected kernel supports the required callbacks.
3. Optional cgroup ingress/egress hooks update cumulative integer counters
   without emitting an event for each packet.
4. Target one cumulative summary per active socket/report interval. Only a
   packet crossing the deadline attempts it; idle sockets generate no report.
   This bound holds with a verified atomic deadline claim. The duplicate-tolerant
   fallback has a separate hard event budget and must measure duplicate rate.
5. The summary contains cumulative counters plus `socket_cookie` and a monotonic
   `event_sequence`. Userspace subtracts the last accepted cumulative values; it
   never races the kernel by resetting counters.
6. A close event carries the final cumulative values when available.
7. A later cumulative report can recover total bytes/packets after a lost
   intermediate report. It cannot recover exact timing, intermediate windows,
   lost destinations, or a lost final report. Mark those intervals incomplete;
   never spread a recovered total across missing windows as measured activity.

`next_report_ns` must be claimed with a verifier-supported atomic
compare-and-swap or equivalent one-writer mechanism. Do not use a BPF spin lock
on every packet. If the minimum kernel/toolchain cannot support the atomic claim,
allow bounded duplicate attempts rather than introducing a contended lock.
An atomic sequence gives each emission an ID; two redundant reports can still
have different IDs. Prevent double counting with per-cookie/counter-generation
high-water marks for cumulative fields, plus event-time ordering checks. Do not
assume ID deduplication alone handles two reporters. Concurrent scalar snapshots
are approximate; uncertain ratios/window boundaries cannot authorize action.

This changes the cost model from:

```text
periodic full scan: O(all map entries per interval)
```

to:

```text
optional detail:   O(1) bounded counter update per packet
userspace events:  O(connection churn + active reporting sockets)
idle sockets:      no periodic event
```

`O(1)` expresses bounded algorithmic work, not constant nanoseconds or absence
of contention. Kernel map allocation, shared atomic cache lines, ring producer
reservation, and memory pressure still require scale tests. The core
connection-only collector has no additional per-packet behavior update.

### 11.5 Optional bounded reconciliation

Event-driven observation can lose events under extreme load. Reconciliation is
therefore a safety mechanism, not the primary data path.

- Workload-level cumulative per-CPU counters are read at a low frequency.
- If a fallback enumerable hash/LRU map is used, reconciliation uses
  `BPF_MAP_LOOKUP_BATCH`, not one syscall per key.
- Reconciliation has a strict entry and time budget per tick and yields between
  batches.
- It runs at a much lower frequency than feature windows, initially 60 seconds
  or longer.
- It repairs userspace accounting and health estimates; it does not manufacture
  evidence for an interval whose detailed events were lost.
- Socket-local storage cannot be blindly enumerated without socket references,
  which is another reason lifecycle events carry cumulative values.

No detection decision should require a complete synchronous map dump.

Remove the inherited one-second `CONNTRACK.keys().count()` in production
`metrics::ticker`. Show an observed-flow estimate with an accuracy label, or
omit that gauge. Explicit operator diagnostics may request a time/entry-bounded
count and receive `partial`; opening the rich terminal must not trigger a scan.

### 11.6 PID reuse and short-lived processes

PID reuse is handled by refusing to make PID the enforcement identity:

1. At connect time, the kernel records cgroup ID, socket cookie, PID/TGID, UID,
   `comm`, and monotonic time in the same event.
2. The socket cookie identifies the exact connection for its lifetime.
3. The cgroup identifies the workload to which policy applies.
4. The preferred event includes a task start time read in the same kernel
   context through a verifier-safe, BTF-compatible method. A zero value means
   unavailable.
5. Userspace may immediately open a `pidfd` to stabilize subsequent enrichment,
   but this does not by itself close the race between the kernel event and
   `pidfd_open`. It can enrich an already verified identity; it cannot create
   certainty after the original PID was reused.
6. If kernel start time is unavailable, userspace may compare current cgroup,
   UID, and `comm` for best-effort display, but must mark the process unresolved.
7. Userspace never looks up a later process with the same numeric PID and treats
   it as the original process.
8. A verified process key is `(tgid, start_time_ns)`; an unverified PID is only
   metadata copied from the original event.
9. If a transient process exits, containment targets its workload/destination
   or remote IP, not the dead PID.

Process resolution is optional. Failure to obtain start time does not require
another tracer, a procfs poll loop, or pidfd service; retain the original PID/name
as event metadata. Never attach an unrelated remote IP action to unresolved
local behavior. Release policy on workload removal/recreation, and keep a short
late-event tombstone so an old event cannot warm up a new workload generation.

If process identity is included, document the PID namespace and start-time
field/clock. A TGID identity uses the thread-group leader's start time, not the
current worker thread's start time. Container-local PID display must be labeled
and cannot be joined blindly to host IDs. Failure to prove that mapping leaves
process identity unresolved without weakening workload/socket identity.

This makes rapid process creation/exit a loss of optional process-path detail,
not a misattribution or policy race.

### 11.7 Map concurrency model

Different data classes use different synchronization. A single global mutable
flow value is not the default design.

| Data | Map/storage | Writers | Synchronization |
|---|---|---|---|
| Decision block/deny policy | Non-evicting LPM/hash map | Userspace enforcer | BPF reads only; enforcer serializes same-key changes |
| Emergency flood cache | Dedicated bounded kernel-owned map | XDP emergency guard | Fixed TTL; best-effort retention; no userspace overwrite |
| Global packet/drop metrics | Per-CPU array | Packet hooks | CPU-local increment; userspace sums |
| Workload totals | Per-CPU hash/storage | Cgroup hooks | CPU-local increment; userspace sums |
| Optional socket byte/packet totals | Fixed-cap hash or quota-proven socket storage | Ingress/egress hooks | Aligned atomic add; no per-packet spin lock |
| Optional report deadline/sequence | Admitted detail storage | Packet/lifecycle hooks | Atomic compare-and-swap/increment, or budgeted duplicate-tolerant fallback |
| Evidence/state | Userspace memory | One decision task | Serialized bounded channel; no detector-held global lock |

Rules:

- Do not copy the current v1 `CONNTRACK.get_ptr_mut()` mutation pattern into v2
  behavioral accounting without a concurrency proof. Its unsynchronized field
  writes can lose updates or misclassify sequence state across CPUs. Preserve
  the demo baseline, but do not describe it as proven correct; include it in
  regression/race assessment before deployment claims.
- Do not place a BPF spin lock in the common packet path unless a benchmark and
  correctness test prove it is necessary and within budget.
- Use per-CPU storage for high-frequency aggregate counters where multiplying
  the small workload-level value by CPU count is acceptable.
- Do not use a full per-CPU copy of large per-flow state on high-core machines;
  that trades contention for uncontrolled memory growth.
- Use aligned atomic operations for shared scalar counters. A lifecycle callback
  alone does not prove ingress/egress are quiescent; composite snapshots remain
  approximate until that property is demonstrated. Avoid plain concurrent
  writes to timestamps/deadlines as well as counters.
- Create detailed state at connection establishment, not from arbitrary packets,
  to prevent a spoofed high-cardinality packet stream from forcing allocations.
- Ring-buffer overflow loses an observation, never changes a PASS into a DROP.

### 11.8 Scale and overload behavior

Thousands of active flows must not imply thousands of map lookups from userspace
every feature interval. Core connection events and any optional detailed report
producer each have their own budget. Without detail, the cost driver is new
connection attempts, not the number of idle/established sockets.

Control event rate with:

- no events for idle sockets;
- one target summary per active socket/interval with atomic claims; a hard
  producer budget also covers duplicates;
- a configurable minimum interval;
- per-workload event budgets for detailed reports;
- always-on workload aggregate counters even when detail is sampled;
- adaptive widening of the report interval when queue occupancy crosses a
  threshold;
- explicit `detail_sampled` and `events_lost` fields so the model never mistakes
  missing data for zero traffic.

High connection churn can still exceed a ring buffer. In that case:

- connection/detail events may be sampled or dropped according to documented
  priority;
- per-workload cumulative connect counters continue;
- the behavior detector marks affected windows incomplete;
- incomplete windows cannot authorize behavioral containment, alone or combined;
- the existing kernel emergency rate rule remains available for volumetric
  abuse;
- overload is visible in status, logs, and metrics.

Benchmark concurrent flows and churn separately at 1K, 10K, and the declared
maximum. The important dimensions are active sockets, new connections per
second, packets per second, CPU count, and report interval. At a target of 10,000
active detailed sockets and a 10-second interval, the target summary rate alone
is 1,000/s plus lifecycle events. This arithmetic is an input to the budget,
not a tested throughput guarantee. Include ring reservation costs and record
loss at target and overload rates.

### 11.9 Rolling windows

Use one configured connection-analysis window plus bounded destination history
per enrolled workload. The initial lab candidate is five minutes; slow periods
require a longer explicitly budgeted observation experiment. Extra simultaneous
10-second/60-second/30-minute windows are not required in this release.

Retain at most the configured number of event timestamps for each exact
workload/destination/port and enforce a global byte budget. Compute intervals on
original monotonic event time. Minimum intervals, observation span, and lateness
limit are part of the rule. An interval crossing collector restart, loss, or
sampling-mode change is invalid for timing evidence.

All windows have hard entry caps and TTL eviction. A window also carries data
quality fields: accepted events, cumulative attempt totals, lost-event delta,
sampling mode, collector epoch, and completeness. If losses cannot be assigned
to one workload, mark all overlapping candidate timing windows incomplete.
Per-CPU totals can reveal missing attempts, but cannot reconstruct their
destinations or timing. A clean subsequent full window is required before
behavioral automatic action becomes eligible again.

### 11.10 Feature schema v1

The required connection feature schema includes:

| Feature | Definition |
|---|---|
| `window_ms` | Width of the observation window |
| `connect_count` | Outbound connection attempts in the window |
| `mean_connect_delta_ms` | Mean time between connection attempts |
| `stddev_connect_delta_ms` | Standard deviation of connection intervals |
| `connect_delta_cv` | `stddev / max(mean, epsilon)`; low values indicate periodicity |
| `destination_age_secs` | Time since workload first observed this destination |
| `destination_frequency` | Historical windows containing this destination |
| `workload_connect_baseline_ratio` | Current connection count divided by workload baseline |

An admitted detail experiment gets a different schema containing validated
packet/byte deltas, counter generation, collection start, and coverage. Never
feed absent socket telemetry as zero into a model trained with byte features.
Payload length per packet is not a required behavioral feature.

Rules:

- Every feature has a documented unit.
- Feature order is fixed by `feature_schema_version`.
- Missing values use an explicit validity bitmap, not an undocumented magic
  number.
- Ratios are capped before model inference.
- No feature may contain raw packet payload.
- Adding, removing, or reordering a feature requires a new schema version and a
  new model.

---

## 12. Behavioral detectors

### 12.1 Detector interface

```rust
pub trait Detector: Send {
    fn id(&self) -> &'static str;
    fn version(&self) -> &str;
    fn observe(&mut self, observation: &Observation) -> Vec<Evidence>;
    fn health(&self) -> DetectorHealth;
}
```

The actual implementation may use source-specific typed methods internally to
avoid unnecessary allocations. The public contract remains observation in,
evidence out.

### 12.2 Two required explainable baselines

Before admitting an Isolation Forest comparison, implement:

1. **Periodicity detector**
   - Requires a minimum number of intervals.
   - Uses mean interval and coefficient of variation.
   - Supports configured jitter tolerance.
   - Produces evidence explaining interval count, mean, and variation.

2. **Destination novelty detector**
   - Maintains a bounded per-workload destination history.
   - Applies a warm-up period.
   - Uses accepted IP/port history and operator exceptions. Domain attribution
     would need DNS/proxy evidence and is outside the first detector.

Baseline enrollment is explicit: collect in observe mode, review representative
normal/maintenance activity, and freeze a versioned candidate baseline for
evaluation. A newly seen destination does not instantly become trusted. Baseline
eviction marks history unknown rather than new/malicious. Automatic learning
from unreviewed suspicious activity could normalize an attack; it is deferred.
Workload recreation starts fresh. A 30-minute lab warm-up is a collection
setting, not proof that backups or weekly maintenance are represented.

Fanout and transfer-ratio detectors are deferred. Admit them only with a
separate scenario, necessary collection cost, negative controls, and measured
incremental benefit. The release does not require four detectors.

These detectors provide a measurable baseline and remain useful explanations
even if the Isolation Forest is accepted.

### 12.3 Conditional Isolation Forest role

Isolation Forest consumes only a complete, versioned feature vector. It does
not read packets, maps, sockets, or policy.

Modes:

```text
off       Model not loaded.
observe   Score and log; no automatic action.
assist    Annotates an accepted rule after evaluation; cannot authorize action.
```

There is no separate model `enforce` mode in the first release. A model built
from the periodicity/novelty features shares their correlation group. It cannot
serve as an independent witness to those rules. Keep it only when a held-out
comparison demonstrates extra useful detections at matched benign alert rates,
acceptable detection delay, and an agreed resource budget. Unsupervised training
finds unusual samples; it does not establish that an anomaly is an attack.

### 12.4 Offline training

Training is never part of the production binary.

Proposed directory:

```text
training/
  README.md
  requirements.lock
  collect-schema.json
  train.py
  export_model.py
  evaluate.py
  scenarios/
  fixtures/
```

Training process (conditional model experiment):

1. Run Hakam in feature-logging observation mode.
2. Collect representative benign traffic from more than the demo traffic
   generator.
3. Record dataset metadata: host, workload, time range, feature schema, software
   versions, and known maintenance periods.
4. Split training and evaluation chronologically.
5. Hold out at least one workload or machine when possible.
6. Train candidate Isolation Forest configurations.
7. Evaluate against benign holdout and labeled attack scenarios.
8. Select a threshold on a separate validation split using a declared benign
   false-alert objective; keep the final test set untouched until selection ends.
9. Export the complete inference artifact.
10. Generate golden input/output fixtures for Rust.

Random row splitting is prohibited because adjacent windows from the same flow
would leak nearly identical examples into both training and evaluation.

Purge the maximum feature-window/history overlap at split boundaries. Identify
workloads/baseline versions without including host IDs, PIDs, raw IP integers,
or token IDs as numeric model features. Record seeds and the exact training
dependency versions. Evaluate per workload as well as aggregate totals so one
busy benign service does not hide failures in another.

### 12.5 Model artifact

The exported artifact includes:

- artifact format version;
- feature schema version;
- ordered feature names;
- validity/missing-value behavior;
- normalization or scaling parameters, if used;
- tree nodes, child indexes, leaf sample counts/corrections, and feature-subset
  mappings for each tree;
- expected sample-size normalization constant;
- anomaly score direction;
- selected threshold;
- training dataset identifier;
- training tool version;
- creation timestamp;
- SHA-256 checksum of the canonical artifact payload, excluding its checksum
  field (or stored as an external digest); this detects corruption, not producer
  authenticity, which relies on the root-owned configured artifact;
- golden test vectors and expected scores.

JSON is acceptable for the first auditable proof of concept if startup parsing
is bounded and the file size is capped. A compact binary format is considered
only after correctness is established and startup/size measurements justify it.

### 12.6 Rust inference engine

The custom inference engine:

- loads once at startup or validated reload;
- performs no allocation per tree traversal after model loading;
- uses immutable model memory shared by the detector task;
- checks every node index and feature index during load;
- rejects cycles, excessive depth, NaN, infinity, and invalid thresholds;
- places hard limits on tree count, nodes per tree, and total artifact size;
- returns a score and explanation metadata;
- never panics on an invalid model;
- is tested against Python golden scores within a declared numeric tolerance.

Tree traversal alone is insufficient to reproduce Isolation Forest. For the
pinned scikit-learn version, export leaf path-length corrections and sample-size
normalization, map each tree's feature indexes, match the input `float32`
conversion and branch boundary behavior, and specify score direction. Use
`anomaly_score = -score_samples(X)` consistently (larger means more unusual),
or explicitly reproduce `decision_function` with its learned offset; never mix
their thresholds. Export fixed leaf corrections rather than recomputing an
approximation differently in Rust. Reject missing/non-finite feature vectors in
the first artifact format. Golden fixtures include threshold-neighbor values,
one/two/many-sample leaves, feature subsampling, and boundary scores. Loader and
test correctness determine code size; "under 100 lines" and microsecond latency
are not requirements or assumed guarantees.

If model validation or inference health fails, that detector becomes `disabled`.
The existing firewall and other detectors continue.

---

## 13. Honeytoken design

### 13.1 Role

A honeytoken is a deliberately planted decoy that legitimate execution should
not use. It is a high-confidence application signal, not a packet signature and
not something Hakam injects into arbitrary traffic.

Good candidates:

- an unlinked randomized administration route;
- a decoy API credential that no legitimate service uses;
- a decoy object identifier only when its use can be tied to an actual request
  peer within the protected application's enforcement scope;
- a reserved application token stored where unauthorized discovery is
  meaningful.

Avoid:

- cookies that browsers automatically return;
- normal hidden form fields submitted by legitimate forms;
- one public static token shared by every deployment;
- tokens placed in a response and then treated as malicious when a normal
  browser sends them back;
- relying on XDP DPI to find tokens inside encrypted HTTPS.

### 13.2 Detection location and source trust

The application or reverse proxy detects the token **after TLS termination** and
reports an event to Hakam locally.

Hakam does not need the token secret. It receives a registered token ID and the
context of its use.

The first reference integration is one directly reachable local HTTP application
with a randomized decoy route or credential. Legitimate browsers, forms, health
checks, and authorized scanner traffic are negative controls. A decoy hit is
evidence of unexpected use; it is not mathematical proof of an attacker.

Source attribution is part of the integration contract. Use the transport peer
for a direct application connection. Behind a proxy, accept forwarded addresses
only from configured trusted proxies that sanitize that header. A producer must
never treat arbitrary `X-Forwarded-For` as truth. Moreover, an original client IP
reported behind NAT/proxy may not be visible on the protected host's XDP path;
blocking the proxy would disrupt unrelated clients. Such events alert only
unless enforcement for that same network-visible source is demonstrated. An
application-layer blocking adapter is outside this release.

UID authorization authenticates the producer, not the event's truth. A
compromised producer can lie about token use or source addresses. Use a
dedicated sensor UID, narrow token registration, protected-source exceptions,
and short action TTLs; default newly registered tokens to observation mode.

### 13.3 Local protocol

Recommended endpoint:

```text
/run/hakam/honeytoken.sock
```

Recommended first implementation:

- Unix stream socket owned by `root:hakam-sensors`;
- mode `0660`;
- peer credentials checked by the daemon;
- newline-delimited JSON messages;
- maximum message length, initially 4096 bytes;
- connection and event rate limits per UID;
- read timeout for incomplete messages;
- no response containing policy internals;
- explicit protocol version.

Example message:

```json
{
  "version": 1,
  "event_id": "0195f23e-2e75-7d0b-9910-9e3862f914a4",
  "token_id": "orders-decoy-admin-7f82",
  "application_id": "orders-api",
  "source_ip": "203.0.113.42",
  "observed_unix_ms": 1789912345678,
  "route": "/internal/decoy/7f82"
}
```

Validation:

1. Protocol version supported.
2. Message length within limit.
3. Actual `SO_PEERCRED` UID matches the registered producer for `application_id`.
   Group permissions allow socket access but do not uniquely authenticate an
   application. Peer PID is metadata and is not later resolved as authorization.
4. `token_id` registered in root-owned policy.
5. Source IP syntactically valid.
6. Timestamp inside configured skew window.
7. `event_id` not seen in the deduplication TTL.
8. Source not in a protected infrastructure allowlist requiring manual action.
9. Token policy is enabled, source attribution mode is approved, and the source
   is within the deployment's proven enforcement scope.

An accepted event becomes `Honeytoken` evidence. It does not expose a generic
"block this address" API to the application.

### 13.4 Default response

For a valid registered honeytoken:

- create direct high-severity evidence with producer/source provenance;
- alert by default; request short source containment only for an explicitly
  enabled token policy after its source/scope checks pass;
- default TTL: configurable, initially 120 seconds to match current behavior;
- log token ID, application, source, producer UID, verdict, and enforcement
  result;
- never log the secret token value;
- notify the terminal/event stream;
- preserve an administrator override and allowlist.

### 13.5 Failure behavior

- Socket unavailable: application continues serving traffic and records its own
  alert; Hakam health reports no honeytoken feed.
- Malformed event: reject and audit producer metadata.
- Flooding producer: rate-limit that local producer; do not let it starve kernel
  event consumption.
- Unknown token ID: reject; do not block.
- Duplicate event ID: acknowledge as duplicate; do not extend TTL unless policy
  explicitly permits it.
- Bound both per-UID and total open connections; parse incrementally and enforce
  length/time limits before allocating a full message. Caller-supplied event IDs
  and wall time do not provide authentication. Daemon receive monotonic time
  governs evidence TTL, with a bounded receive-skew check for audit metadata.
- The application submits asynchronously with a bounded local queue/timeout;
  request processing must never wait for Hakam enforcement or socket recovery.

---

## 14. Signature detector integration

The existing signature path remains valuable and should not be rewritten while
building v2.

Implementation changes:

1. `dpi::payload_task` continues draining `PAYLOAD_EVENTS`.
2. `Reassembler` and `signatures::match_payload` stay unchanged initially.
3. On match, `dpi.rs` creates an `Observation::DpiMatch` instead of inserting
   directly into `BLOCKLIST`.
4. `SignatureDetector` converts that observation to evidence.
5. `DecisionEngine` produces the same temporary-block behavior as v1.
6. `Enforcer` writes the map and returns a result.
7. Console and telemetry messages are generated from the observation, evidence,
   verdict, and enforcement result rather than from detector-local printing.

Migration compatibility:

- signature categories and counts remain;
- existing CLI `stats` remains available through `hakamctl stats`;
- existing BLOCK telemetry can be derived from verdict/enforcement events for
  demo mode;
- the reassembly and evasion test suites must pass unchanged;
- block timing may move by only the userspace channel overhead, which must be
  measured and bounded.

---

## 15. Daemon, terminal, logging, and demo UI

### 15.1 Runtime processes

Normal operation:

```text
hakam-node daemon       always-running privileged service
hakamctl top            optional rich read-only terminal
hakamctl logs --follow  optional log viewer
hakamctl ...            authorized control commands
```

Closing a client cannot detach kernel programs or terminate the daemon.

Preserve the single-binary distribution: implement daemon and client subcommands
in `hakam-node`. `hakamctl` is an optional symlink/command alias to that executable,
not another Rust crate or a required service. The client runs without BPF
capabilities and connects to local sockets. A richer terminal is an operator
view; limit refresh frequency and rows, and render snapshots built from existing
daemon state. It never adds background flow scans.

### 15.2 Proposed local endpoints

Use separate permissions for read-only events and administrative commands:

```text
/run/hakam/events.sock       read-only event subscribers
/run/hakam/control.sock      administrator commands
/run/hakam/honeytoken.sock   registered application producers
```

Suggested ownership:

| Socket | Owner/group | Purpose |
|---|---|---|
| `events.sock` | `root:hakam-observers`, `0660` | Status and event subscription |
| `control.sock` | `root:hakam-admins`, `0660` | Block, release, policy reload, shutdown |
| `honeytoken.sock` | `root:hakam-sensors`, `0660` | Evidence submission only |

The service creates `/run/hakam` with restrictive permissions and removes stale
sockets only after verifying their type and ownership.

Its directory must allow traversal for all three configured groups (for example,
root-owned `0755` with each socket `0660`, or explicit directory ACLs); a
root-only `0700` directory would make the group socket permissions ineffective.
Bind clients after the sockets' ownership/modes are set. Readers get typed
status/event requests only, never control-command dispatch on `events.sock`.

### 15.3 Control protocol

Commands are typed and versioned:

```rust
pub enum ControlCommand {
    Status,
    Stats,
    ListDecisions,
    ShowSubject { subject: SubjectSelector },
    BlockRemoteIp { cidr: String, ttl_secs: Option<u32> },
    Release { decision_id: Option<String>, subject: Option<SubjectSelector> },
    DenyDestination { cidr: String, ttl_secs: Option<u32> },
    ReloadPolicy,
    SetBehaviorMode { mode: BehaviorMode },
    Shutdown,
}
```

Every mutating command records peer UID/GID, command, result, and policy effect.

### 15.4 Rich terminal

`hakamctl top` is read-only and displays:

- hook/feature availability;
- current health and degraded components;
- packet/drop rates;
- PASS/DROP benchmark metrics when available;
- ring overflows and queue depth;
- active subjects by state;
- recent evidence and reasons;
- active enforcement with expiry;
- detector modes and model versions;
- top workloads and destinations;
- current policy version.

It must not calculate authoritative risk scores locally. It renders daemon
events and snapshots.

### 15.5 Log terminal

`hakamctl logs --follow` may follow the daemon event socket or structured
journald output. The canonical operational log is structured and useful without
the TUI. Journald is the initial sink; a searchable log database and reliable
export pipeline are outside v2. Logs are durable only under the configured
journald storage policy; state that retention policy explicitly.

Never synchronously write one disk record per packet. Log state transitions,
evidence summaries, enforcement results, health changes, and aggregated
statistics.

### 15.6 Demo telemetry

Default behavior:

- WebSocket demo server disabled;
- demo command backchannel disabled;
- no graphical frontend;
- no graphical-interface requirement for daemon health;

`--demo-mode` behavior:

- enable the existing WebSocket adapter;
- expose compatible telemetry messages for existing terminal demo scripts;
- enable demo commands required by the accepted scripts;
- display a clear `DEMO MODE` banner in daemon logs;
- bind to loopback by default unless the operator explicitly chooses otherwise.

The v1 tag remains the presentation fallback if the v2 compatibility adapter is
not stage-ready.

---

## 16. Configuration

### 16.1 Configuration layers

One root-owned `hakam.toml` is the first release's configuration source for
deployment, limits, detectors, and decision rules. Compiled defaults support
omitted optional fields. CLI overrides select runtime paths/interface or request
an audited mode change; they do not create a second hidden scoring policy.
Environment variables do not silently override security rules. Status shows
effective values, origin, policy version, and checksum.

Proposed locations:

```text
/etc/hakam/hakam.toml
/var/lib/hakam/models/<model-id>.json
/var/lib/hakam/baselines/             explicit reviewed baseline artifacts
/run/hakam/                           runtime sockets only
```

### 16.2 Example policy

```toml
schema_version = 1
policy_version = "v2-lab-001"

[runtime]
interface = "eth0"              # reference topology, not assumed universal
cgroup_root = "/sys/fs/cgroup/hakam-lab.slice"
demo_mode = false

[behavior]
mode = "observe"                 # off | observe | enforce-validated-rules
warmup_seconds = 1800
window_seconds = 300
baseline_path = "/var/lib/hakam/baselines/lab-v1.json"
detail_enabled = false

[decision]
default_block_ttl_seconds = 120
post_release_watch_seconds = 300
validated_rule_version = ""       # set only after documented acceptance

[limits]
observation_queue = 4096
evidence_queue = 4096
event_subscriber_queue = 1024
max_enrolled_workloads = 64
max_active_subjects = 4096
max_evidence_per_subject = 16
max_total_evidence = 8192
max_evidence_bytes = 16777216
max_attribute_bytes = 1024
max_destination_history_entries = 8192
max_retained_connect_times = 65536
max_model_bytes = 16777216
max_honeytoken_message_bytes = 4096
max_sensor_connections = 32

[detectors.periodicity]
enabled = true
minimum_intervals = 5
minimum_observation_seconds = 60
maximum_cv = 0.20
evidence_ttl_seconds = 600

[detectors.destination_novelty]
enabled = true
evidence_ttl_seconds = 300

[detectors.isolation_forest]
enabled = false                    # conditional experiment
mode = "observe"                   # observe | assist; no independent block
model_path = "/var/lib/hakam/models/iforest-v1.json"
evidence_ttl_seconds = 300

[honeytokens]
enabled = true
default_ttl_seconds = 120
allowed_clock_skew_seconds = 30
dedupe_ttl_seconds = 600

[[honeytokens.producers]]
application_id = "orders-api"
uid = 991
token_ids = ["orders-decoy-admin-7f82"]

[[honeytokens.tokens]]
token_id = "orders-decoy-admin-7f82"
mode = "observe"                   # contain only after integration tests
source_attribution = "direct-peer"

[[allowlist.remote]]
cidr = "192.0.2.10/32"
behavior = "manual-review"
reason = "documentation-only management peer example; replace for deployment"
```

Numeric limits and thresholds are lab candidates, not measured defaults. Before
implementation admission, document the reference machine's memory/CPU budget
and calculate the aggregate kernel/userspace allocation implied by these caps.
For per-CPU values use the kernel's possible CPU count, which may exceed online
CPUs. Quotas must include allocator overhead, subscriber queues, event strings,
destination histories, and model memory. Test maximum-capacity behavior.

### 16.3 Validation and reload

- Parse into a new immutable configuration instance.
- Validate schema version and every range.
- Reject unknown enforcement actions.
- Verify detector ranges, mode/rule compatibility, TTL limits, and cooldown.
- Verify referenced detector and model compatibility.
- Log the candidate version and validation result.
- Atomically swap only after complete validation.
- Keep the previous configuration on failure.
- Policy reload does not automatically remove administrator rules unless the
  policy explicitly defines reconciliation behavior.
- One userspace config swap does not atomically update multiple kernel maps.
  Serialize reload and pending verdicts through decision/enforcement ownership;
  reject stale policy epochs for new action, audit each map result, and state
  which existing rules remain until expiry. Newly protected subjects suppress
  pending automatic action and release only decision-owned rules according to
  documented reload semantics.

---

## 17. Proposed repository structure

The exact filenames can evolve, but responsibilities should remain separated:

```text
hakam-common/src/
  lib.rs
  observations.rs        shared kernel/userspace event layouts
  policy_types.rs        map key/value layouts

hakam-ebpf/src/
  main.rs                program and map declarations
  xdp.rs                 ingress fast path
  tc.rs                  existing global egress path
  lsm.rs                 existing global connect policy
  tracepoint.rs          compatibility attribution
  conntrack.rs           existing TCP observation
  cgroup_connect.rs      workload-aware connect observation/deny
  cgroup_skb.rs          optional detail/existing-flow experiment
  behavior_maps.rs       bounded attempt totals; optional detail helpers
  helpers.rs

hakam-node/src/
  main.rs                loader and task wiring only
  config.rs              configuration loading and validation
  observation.rs         normalization and routing
  evidence.rs            evidence types/store
  decision.rs            deterministic state machine
  enforcement.rs         sole userspace BPF policy writer
  audit.rs               structured non-blocking audit events
  health.rs              component health and degradation
  dpi.rs                 existing ring consumer, emits observations
  signatures.rs          existing corpus and matcher
  reassembly.rs          existing flow reassembly
  features/
    mod.rs
    windows.rs           bounded rolling windows
    schema.rs            versioned feature vector
    ingest.rs            cumulative lifecycle/report events and bounded reconciliation
  detectors/
    mod.rs
    signature.rs
    periodicity.rs
    destination.rs
    isolation_forest.rs   only if the model experiment is admitted
  ipc/
    mod.rs
    events.rs            read-only subscribers
    control.rs           administrator commands
    honeytoken.rs        application evidence input
  demo/
    websocket.rs         old telemetry behind demo feature/mode
    commands.rs          old demo command bridge
  terminal/
    mod.rs               client subcommands in the same binary
    main.rs
    client.rs
    top.rs
    logs.rs
    commands.rs

training/                conditional model experiment only
  README.md
  requirements.lock
  train.py
  export_model.py
  evaluate.py
  fixtures/
  scenarios/

docs/
  v2-architecture-plan.md
  v2-threat-model.md       optional extracted document later
  v2-model-card.md         generated/completed for accepted model
```

Do not create all files at once. Each phase introduces only the modules it can
test and use.

---

## 18. Integration mapping from current files

| Current file | Required v2 change |
|---|---|
| `hakam-ebpf/src/main.rs` | Declare new maps/programs only in the phase that attaches them; preserve existing names during migration |
| `hakam-ebpf/src/xdp.rs` | Preserve demo baseline; version expiry and flood-rule ownership before new source containment; benchmark added work |
| `hakam-ebpf/src/tc.rs` | Preserve global destination blocking; add workload path separately rather than complicating this hook immediately |
| `hakam-ebpf/src/tracepoint.rs` | Continue compatibility events until cgroup identity proves complete |
| `hakam-ebpf/src/lsm.rs` | Preserve global `CONNECT_POLICY`; do not mix model scoring into LSM |
| `hakam-ebpf/src/conntrack.rs` | Preserve existing sequence tracking; evaluate separate behavior map before expanding value layout |
| `hakam-common/src/lib.rs` | Split shared types only when useful; add explicit version/layout tests |
| `hakam-node/src/main.rs` | Become loader/task composition; attach optional hooks with explicit capability status |
| `hakam-node/src/dpi.rs` | Emit DPI observations; remove direct map insertion after enforcer is proven |
| `hakam-node/src/signatures.rs` | Preserve matcher; add detector adapter outside corpus |
| `hakam-node/src/reassembly.rs` | No planned semantic change in early phases |
| `hakam-node/src/cli.rs` | Route commands through shared control handlers; later move interactive presentation to `hakamctl` |
| `hakam-node/src/maintenance.rs` | Move rule expiry/reconciliation into decision/enforcement ownership; keep demo command bridge only in demo mode |
| `hakam-node/src/metrics.rs` | Remove default full conntrack scan; add bounded queue/evidence/enforcement health snapshots |
| `hakam-node/src/telemetry.rs` | Retain as demo adapter; production event protocol lives under `ipc/` |
| Terminal interface | Add rich views in the existing executable after IPC contracts pass |
| `xtask/src/main.rs` | Add build/validation support for new crate and hooks without changing v1 tag |

---

## 19. Implementation phases and exit criteria

Each phase has a usable result, a measured admission gate, and a rollback point.
The required path is 0–6 and 8. Phase 7 and socket detail are experiments; their
failure does not prevent the focused v2 proof of concept.

### Phase 0 — Preserve and record v1

- Record the accepted demo commit, kernel, toolchain, topology, and configuration.
- Create a known-good Arsenal tag/release only from the verified state.
- Archive existing Rust/UI/live smoke results and benchmark artifacts.
- Record actual test counts rather than assuming a historical number.
- Freeze UI development except fixes necessary to run the accepted demo.

Exit: the accepted demonstration and rollback are reproducible. Document the
existing scan, clock, parse-error, attribution, and TTL limitations.

### Phase 1 — One decision and enforcement owner in userspace

- Add only observation, evidence, verdict, rule, and enforcement-result contracts.
- Route DPI/manual decisions through the same bounded decision/enforcement path.
- Preserve v1 source-block behavior and explicitly document the kernel flood
  co-writer while the legacy ABI is in use.
- Add rule lineage, deduplication, bounded expiry indexes, and structured results.
- Keep detectors free of map handles.

Exit: existing detections and TTL behavior reproduce the recorded baseline;
duplicate/release/ownership tests pass; channel loss is visible; decision latency
is measured. This phase introduces no new automatic behavior or new kernel hook.

### Phase 2 — Operate without a GUI

- Add client subcommands to the same executable; optional `hakamctl` alias.
- Implement status/stats/top/logs and narrowly authorized local controls.
- Gate WebSocket/demo commands behind explicit demo mode.
- Remove default full-map flow counting from production metrics.
- Match userspace clock to BPF monotonic time; document deliberate suspend
  semantics and migration of legacy timestamps.
- Verify observation parse-error semantics before changing the accepted demo.
- Configure systemd restart and report actual attachment recovery behavior.
- Record that the legacy 500-pps guard is a demo setting; before unattended use,
  select/validate an operational configuration of the existing guard with
  legitimate high-rate/NAT traffic and disclose per-CPU semantics.

Exit: daemon runs with no clients; slow/disconnected terminal clients cannot
stall consumers; permissions/size limits pass; normal metrics never walk the
whole conntrack map; actual clock/parse behavior is tested on Linux.

### Phase 3 — One honeytoken integration in observe mode

- Register one randomized route or credential for one direct local application.
- Implement bounded Unix stream input, peer-UID checks, dedupe, and token policy.
- Document direct/proxy source attribution and enforcement address visibility.
- Submit alerts asynchronously from the application.
- Exercise the same decision path; automatic honeytoken containment waits for
  the expiry/ownership gate in Phase 8.

Exit: normal browser/form/health-check traffic does not trigger the integration;
malformed/unauthorized/unknown/replayed reports cannot request action; spoofed
forwarded headers do not select a victim IP; producer flooding is isolated;
token secrets do not enter logs. Observe-mode evidence is visible in both
terminals.

### Phase 4 — Workload connection identity proof

- Load `cgroup/connect4` on the declared cgroup-v2/kernel/Aya reference target.
- Emit attempt, socket cookie, live workload ID, PID metadata, destination,
  monotonic time, and event header.
- Obtain task start time only if supported safely in the original hook.
- Verify cgroup ancestry, recreation, inherited/passed sockets, and unknown IDs.
- Enroll a capped workload set and compare against legacy tracepoint output.
- Keep detailed sockops/cgroup-skb/storage work outside the required spike.

Exit: two workloads reaching the same destination remain distinct; PID reuse
cannot transfer identity; removed/recreated workloads cannot inherit evidence;
the actual interface/namespace/cgroup coverage is reported; unsupported hooks
leave behavior observe-only. No claim of perfect process attribution is made.

### Phase 5 — Bounded connection features

- Update small per-CPU attempt totals for enrolled workloads.
- Consume attempt events into one configured window and bounded destination
  history per exact workload/destination/port.
- Add global entry/byte limits, late-event policy, quality flags, and cold start.
- Produce opt-in feature logs with a versioned connection-only schema.
- Measure target connection churn, not only packet throughput.

Exit: replayed vectors are reproducible; lost/sampled events invalidate timing
windows; missing history is unknown; no full flow-map scan or behavior packet
hook is required; CPU/memory/queue budgets pass at target and overload rates.

Optional detail spike: only after a demonstrated connection-only gap, prove
helper combinations, exact memory caps, allocation/close races, atomic updates,
summary bounds, and interval completeness. Admit it only with measured detection
benefit and PASS-path cost. Otherwise stop that experiment and retain core v2.

### Phase 6 — Focused behavior detector proof

- Implement periodicity and destination-history evidence for one chosen
  outbound beacon-like connection scenario.
- Enroll/review a representative benign baseline; version and freeze it.
- Evaluate the compound rule against held-out benign workloads, scheduled jobs,
  health checks, updates, and jittered/failed connection controls.
- Keep all behavior observation-only during evaluation.
- Report what the connection detector misses, including persistent sessions.

Exit: the rule explains sample count, duration, interval variation, destination
history, subject, and completeness. Publish alerts per workload-day, detection
delay/misses, and uncertainty. Thresholds are selected on training/validation,
then tested once on the held-out set. Do not add fanout/transfer detectors to
satisfy this gate.

### Phase 7 — Conditional Isolation Forest experiment

- Proceed only with a written comparison objective and budget.
- Lock Python dependencies; separate train, validation, and final test periods.
- Export full scoring semantics and implement bounded Rust inference.
- Test feature mapping, float conversion, leaf corrections, score direction,
  malformed artifacts, and Python/Rust numerical parity.
- Compare at a matched benign alert rate against Phase 6.

Exit if included: reproducible additional detection value, measured inference
cost, and golden-score parity. Otherwise document the result and leave the model
disabled. Model evidence shares the behavior correlation group and never
independently authorizes a block.

### Phase 8 — Scoped temporary containment and acceptance

- Implement versioned expiry values and explicit kernel/userspace writer
  ownership; benchmark any extra policy lookup.
- Deny future IPv4/TCP connects only for the exact live workload/destination/port.
- Add kernel deadline checks, rule lineage, protected-source exceptions, release,
  cooldown, map-full behavior, and an audited behavior-disable command.
- Keep compound behavior observe-only through the declared shadow duration.
- Enable only individually accepted rules/token integrations.
- Test existing-flow denial only if that optional capability was admitted.
- Verify recovery/pinning before claiming unattended enforcement continuity.

Exit: automatic action cannot come from a single weak flag, a model echo of the
same flag, lost observations, stale workload identity, or arbitrary producer
source claims. Expiry works with maintenance paused; another workload retains
connectivity; recurring alerts cannot extend one block forever. Benign
containment and performance meet the targets declared before testing. Each
action has evidence, rule/version, exact scope, deadline, and result.

The release may complete with observe-only behavior if automatic containment
fails its gate, but must be labeled accordingly. A proof of precise containment
can still use an administrator-confirmed lab verdict; that is not evidence that
automatic classification is safe.

### Presentation go/no-go

Use v2 on stage only if its selected scenario and rollback pass. Otherwise run
the accepted v1 demo and explain v2 as measured work in progress. Additional
detectors, a collector, a policy distribution service, and a new GUI are not
tasks needed to finish this update.

---

## 20. Testing strategy

### 20.1 Unit tests

- byte order and struct layout;
- subject equality and PID-reuse handling;
- evidence expiry, global memory quotas, and window deduplication;
- explicit rule clauses, state transitions, and cooldown;
- same-subject correlation and prevention of model double voting;
- action compatibility with subject type;
- idempotent enforcement;
- failed/partial enforcement cannot report successful containment;
- policy parsing and semantic validation;
- local read/control/sensor permission and framing boundaries;
- feature window arithmetic;
- missing feature bitmap;
- periodicity and novelty fixtures;
- model tree traversal and malformed model rejection;
- honeytoken schema and deduplication.

### 20.2 Property and fuzz tests

- no incomplete, stale, unresolved, or single weak evidence authorizes action;
- evidence for one workload/destination never selects an unrelated destination;
- event ordering does not create an impossible state transition;
- arbitrary control/honeytoken bytes do not panic;
- arbitrary model artifacts do not panic or exceed configured bounds;
- repeated release is idempotent;
- TTL arithmetic handles clock wrap/saturation safely;
- CIDR parsing normalizes host bits consistently.

### 20.3 Linux VM integration tests

- load and attach every required hook;
- verifier accepts all BPF programs;
- XDP blocks confirmed remote source;
- global LSM/connect policy returns expected error;
- workload policy affects only the target cgroup;
- unrelated cgroup remains connected;
- existing established-flow behavior is documented and tested;
- feature counters match generated traffic;
- conditional detail: simultaneous ingress/egress keeps scalar counters monotonic
  under multi-CPU stress, while composite snapshots are correctly marked;
- PID churn/reuse never transfers an old socket or workload decision to a new
  process;
- core event deduplication does not collapse distinct attempts on one socket;
- conditional detail: redundant emissions with different sequences do not double
  count bytes; recovered totals do not create fabricated interval timing;
- steady-state feature processing performs no complete flow-map scan;
- any admitted batch reconciliation obeys its entry/time budget under a full map;
- temporary rules expire while userspace maintenance is stopped;
- prefix overlap is rejected without losing the existing deny;
- administrator and kernel flood ownership cannot be erased by automatic release;
- BPF-LSM preserves an earlier security program's denial on its own allow/error
  paths; cgroup connect uses the correct hook return convention;
- mocked/reproduced suspend does not mix BOOTTIME and MONOTONIC deadlines;
- cgroup removal/recreation and late events do not inherit old policy/baselines;
- queue/ring overflow is observable;
- hooks detach/restart cleanly;
- systemd restart matches the declared reattach-gap or verified pin/adopt contract.

### 20.4 Behavioral scenarios

Benign scenarios:

- web/API request traffic;
- DNS resolver activity;
- package updates;
- SSH administration;
- monitoring and metrics exporters;
- periodic health checks;
- backup jobs;
- database connections;
- software deployment;
- idle server periods;
- traffic spikes caused by legitimate load.

Required suspicious lab scenarios:

- regular beacon intervals;
- beacon intervals with configured jitter;
- repeated short outbound connections;
- unusual service-to-destination relationship;
- registered honeytoken use;
- known signature attack;
- combined weak behavior signals.

Persistent low-rate sessions, fanout, and transfer ratios are coverage-gap or
optional experiment fixtures, not required success cases for the core detector.
Also include repeated failing attempts, benign periodic new-endpoint traffic,
baseline history eviction, event loss, authorized scanners, and proxy/NAT decoy
attribution as negative/uncertain controls.

Use isolated lab traffic. The scenario suite should test defensive detection and
containment outcomes rather than become an offensive deployment toolkit.

### 20.5 Regression rule

Record the actual existing cross-platform tests and UI build at the selected
v1 commit; a historical count is not an invariant. Existing guarantees must not
silently disappear. Live eBPF
tests are required in addition to cross-platform Rust tests.

---

## 21. Performance plan

### 21.1 What must be measured

- baseline host without Hakam;
- v1 Hakam;
- v2 kernel hooks with behavior disabled;
- v2 connection feature collection enabled;
- conditional socket detail off/enabled, only if admitted;
- v2 detectors enabled in observe mode;
- v2 model enabled, only if admitted;
- terminal disconnected and connected;
- demo mode disabled and enabled.

Metrics:

- PASS-path p50/p99/p99.9 latency;
- DROP-path p50/p99/p99.9 latency;
- packets per second and throughput;
- system and process CPU;
- resident memory;
- map memory and occupancy;
- ring/event loss;
- userspace queue depth and drops;
- lifecycle/summary event processing latency;
- bounded reconciliation batch duration;
- detector evaluation latency;
- Isolation Forest inference p50/p99/p99.9;
- evidence-to-verdict latency;
- verdict-to-map-update latency.

### 21.2 Performance rules

- No claim of "no latency" without PASS-path measurement.
- No permanent timing instrumentation on every PASS packet merely to measure
  performance; use dedicated benchmark builds or controlled instrumentation.
- Report hardware, kernel, attach mode, traffic generator, packet size, flow
  count, run duration, and number of repetitions.
- Report medians and tail latency, not one best run.
- A VM result demonstrates function, not native-NIC wire-rate capacity.
- Every queue/map capacity is included in the report.
- Benchmark artifacts and scripts are committed with the result.
- Drive comparable offered load in each condition. Distinguish generator limits,
  dropped traffic, throughput, and actual offered PPS/connection churn; a larger
  received-PPS number after dropping traffic does not prove cheaper PASS traffic.
- Keep legitimate sources below the current emergency rate rule, or use a
  separate controlled benchmark configuration and disclose it. Otherwise a
  "clean" load test becomes a DROP test.
- Measure end-to-end legitimate request/connect latency as well as hook timing;
  async analysis still competes for CPU/cache/memory and can affect other tasks.

### 21.3 Merge gate

Before implementation starts, choose and record a reference host and explicit
budgets for:

- allowed PASS-path regression;
- allowed throughput regression;
- maximum daemon CPU at target workload;
- maximum lifecycle/summary event-processing time;
- maximum reconciliation time budget per tick;
- maximum expected ring/queue loss;
- maximum model inference time.

Do not invent a successful number after seeing the result. A phase either meets
the predeclared budget or remains experimental.

Record a performance/evaluation sheet before Phase 4 admission: reference host,
kernel/Aya versions, interface mode, possible CPU count, target workload count,
PPS, connection churn, max active sockets, and test duration. Fill PASS p99/p99.9
regression, throughput regression, daemon CPU/RSS, map bytes, event loss, and
decision delay budgets with explicit values. Add optional detail/model budgets
only when those experiments are admitted. An unfilled budget blocks an acceptance
claim; this document does not supply invented successful measurements.

Similarly predeclare benign workload-days, alert and false-containment limits,
minimum attack repetitions, tolerated misses, and detection-delay limits. Report
denominators and uncertainty. Zero false events in a short demo does not prove a
zero false-positive rate.

---

## 22. Reliability and failure behavior

| Failure | Required behavior |
|---|---|
| Optional model missing/invalid | Disable model; core firewall/detectors continue; report experiment health |
| Feature collector falls behind | Drop bounded observations, increment loss, never delay packets |
| Decision queue full | Preserve confirmed policy; emit degraded health; do not invent blocks |
| Audit sink slow | Bounded buffering and visible loss; preserve decision/result priority; never stall packets |
| Terminal client slow | Disconnect/skip that subscriber |
| Honeytoken producer floods | Per-producer limit and disconnect; kernel consumers keep priority |
| Policy reload invalid | Keep last valid policy |
| Daemon restarts | Systemd restarts; report coverage gap unless pin/adopt continuity has been verified |
| BPF-LSM unavailable | Report downgrade; XDP/TC and available cgroup hooks continue |
| cgroup hooks unavailable | Report capability loss; do not claim workload containment |
| Telemetry map full | Decline detail or measured eviction; invalidate affected data; never alter packet verdict |
| Decision/admin map full | Reject new rule and report failure; never evict existing confirmed policy |
| Flood cache pressure | Best-effort retention is visible; existing per-CPU guard continues; no confirmed rule shares this cache |

Fail-open/fail-closed policy:

- parser/internal observation errors fail open for new traffic unless an
  explicit existing policy says deny;
- explicit administrator deny rules remain fail-closed while installed;
- optional behavioral components fail open;
- confirmed temporary rules remain until their TTL even if the model becomes
  unavailable, provided the enforcing attachment remains live; daemon-crash
  continuity follows the separately declared recovery contract;
- no optional component failure may silently convert `Watch` into `Block`.

Audit/event loss makes investigation incomplete and must be visible. A bounded
nonblocking log channel cannot promise durable delivery of every decision. If
decision lineage cannot be retained even in its reserved bounded buffer, disable
new optional automatic containment until healthy; existing explicit rules and
kernel emergency behavior continue. This avoids an unexplained block while
preserving packet forwarding.

---

## 23. Security hardening

- Run the daemon with the minimum capabilities proven sufficient on supported
  kernels; document when root is still required.
- Root-own binaries, policy, and model artifacts.
- Apply restrictive systemd settings that do not prevent required BPF/cgroup
  operations.
- Separate observer, administrator, and sensor Unix groups.
- Never expose the control or honeytoken protocol over TCP in v2.
- Bound every untrusted string, vector, map, queue, and artifact.
- Avoid logging secrets or full payloads.
- Treat model and policy files as executable security configuration.
- Include policy/model checksums in status and audit output.
- Use monotonic time for TTL and state decisions; wall time is display/audit
  metadata only.
- Make map key byte order explicit and tested.
- Avoid unsafe Rust outside narrow event-layout decoding boundaries.
- Validate event length before casting shared structures.
- Keep demonstration commands unavailable outside explicit demo mode.
- Document every compatibility downgrade at startup and in `hakamctl status`.

---

## 24. Audit event requirements

Every important event has:

- schema version;
- event ID;
- monotonic and wall timestamp;
- host ID;
- subject;
- component/source;
- policy version;
- model version where applicable;
- evidence/verdict/enforcement lineage;
- human-readable summary;
- structured attributes;
- outcome and error.

Required event types:

- daemon start/stop;
- hook attach/downgrade;
- detector enable/disable/health;
- policy/model load or rejection;
- evidence accepted/expired;
- state transition;
- enforcement applied/failed/released;
- manual command accepted/rejected;
- honeytoken accepted/rejected without exposing secret;
- queue/ring/map degradation;

The audit record must make it possible to answer:

1. What was affected?
2. What evidence existed?
3. Which policy/model versions were active?
4. Why did the state change?
5. What map operation was attempted?
6. Did enforcement succeed?
7. When will it expire?
8. Who issued any manual command?

---

## 25. Black Hat Arsenal preservation and v2 demonstration

The accepted demonstration remains a protected artifact.

### 25.1 Presentation fallback

```text
Primary fallback: validated CLI demo from the chosen v1 revision.
Optional addition: v2 terminal demonstration only after its go/no-go gate.
```

### 25.2 V2 demonstration story

If ready, the v2 extension should demonstrate one coherent scenario:

1. Normal service traffic establishes a baseline.
2. A compromised lab workload begins a payload-independent outbound pattern.
3. The rich terminal shows observations without slowing traffic.
4. One weak detector moves the workload to `Watching` only.
5. The same-destination compound rule qualifies and shows its numeric clauses;
   it is labeled a validated heuristic, not independent witnesses.
6. The decision engine explains the transition.
7. An accepted rule (or clearly labeled administrator confirmation) denies future
   connects to that exact destination/port for that workload.
8. Other workloads continue communicating.
9. The rule expires or is released.
10. The benchmark shows the cost with detection disabled/enabled.

Show one separate decoy use reaching the same evidence/decision path only if its
integration passed. Identify whether existing sessions remain allowed; do not
describe a future-connect deny as cutting an established channel. The story
demonstrates improved detection and precise containment rather than feature count.

### 25.3 Claims policy

Allowed only when measured:

- detector scenario coverage;
- false-positive observations on the stated dataset;
- time to detection;
- measured latency/throughput on stated hardware;
- exact hook and kernel support.

Do not claim:

- zero false positives;
- all zero-days;
- all reverse shells;
- production readiness;
- wire-rate performance not tested on a real NIC;
- process attribution when the agent reports degraded/heuristic attribution.

---

## 26. Risks and mitigations

| Risk | Consequence | Mitigation |
|---|---|---|
| Behavioral scope expands into EDR | Project loses identity | Admit only network-detection/containment features |
| Model trained only on demo traffic | Misleadingly low false positives | Collect varied, chronological, multi-workload benign data |
| Per-packet event emission | CPU/ring contention | Socket-local cumulative counters; lifecycle and rate-limited summary events |
| Immediate block from weak anomaly | Legitimate outage | Explicit compound rule acceptance, observe default, TTL, protected-source exceptions |
| PID reuse | Wrong process attribution | Enforce by cgroup/socket cookie; use `(TGID,start time)` only after verification |
| Global destination block | Other services disrupted | Workload-specific connect policy |
| Honeytoken misuse/misconfiguration | False containment | Producer authorization, registry, dedupe, reversible TTL |
| Model/parser bug | Detector outage | Bounded validated artifact; fail model open; base firewall continues |
| Double counting correlated detectors | False confidence and containment | Shared correlation group; model cannot act as another vote |
| Socket storage has no max-entry limit | Memory growth under churn | Fixed-cap hash or proven quotas; detail disabled by default |
| Producer/proxy source is misleading | Innocent client/proxy blocked | Verified direct peer or trusted forwarding plus enforcement scope; observe default |
| Stalled expiry / clock mismatch | Indefinite or premature deny | Kernel deadline checks; same MONOTONIC clock; boot epoch |
| Demo 500-pps policy on a busy server/NAT | Legitimate clients auto-blocked | Explicit operational guard configuration and benign offered-load tests |
| Daemon attachment disappears | Coverage gap | Explicit recovery mode; measured pin/adopt gate for unattended use |
| Terminal work expands beyond operational needs | Security work delayed | Bound terminal scope; reuse daemon state |
| Accepted demo regresses | Event risk | Preserve tag and separate v2 go/no-go |
| Documentation outruns code | False claims | Proposal labels and phase-specific capability matrix |
| New map lookup harms PASS path | Latency regression | Minimal ownership-correct maps; benchmark every added lookup before admission |

---

## 27. Capability reporting

`hakamctl status` must report actual runtime capabilities, not intended design:

```text
Ingress XDP                  active (driver/generic mode shown)
Global TC egress             active
Global connect LSM           active / unavailable
Legacy connect tracepoint    active / unavailable
Workload connect hook        active / unavailable / not built
Workload byte accounting     deferred / experiment / unavailable / not built
Signature detector           active; corpus version/count
Behavior feature collector   off / observe / active / degraded
Explainable detectors        list with versions
Isolation Forest             off / observe / assist / invalid
Honeytoken socket            active / disabled / degraded
Decision policy              version + checksum
Model                        ID + checksum + feature schema
Demo mode                    enabled / disabled
Scope                        interfaces, netns, enrolled cgroups, IPv4/TCP
Recovery                     reattach (measured gap) / pin-adopt (verified)
Containment                  future-connect / existing-flow (verified) / observe
Data quality                 epoch, losses, sampled/incomplete windows
```

Startup and status must never imply a missing optional hook is active.

---

## 28. Definition of done for the focused v2 proof of concept

Required:

1. The accepted v1 demo and rollback are reproducible.
2. The local daemon and both terminal views work independently,
   using the same shipped executable.
3. Existing signature/manual decisions use the shared decision/enforcement path.
4. Workload/socket identity separates two workloads contacting the same endpoint;
   PID churn and cgroup recreation cannot transfer identity, evidence, or policy.
5. Connection features have enforced global memory/entry budgets and explicit
   timing/loss/cold-start semantics.
6. One held-out beacon-like connection scenario gains detection beyond v1, with
   the corresponding benign periodic/new-endpoint controls and measured misses.
7. Alerts and false containment are reported with workload-day denominators,
   uncertainty, and predeclared detection-delay/resource targets.
8. One registered application honeytoken produces evidence with verified producer
   and source scope; unauthorized or misleading reports cannot select a victim.
9. A scoped workload/destination action is demonstrated without affecting another
   workload. Automatic use is permitted only for an individually accepted rule;
   administrator confirmation is labeled as such.
10. Every new temporary rule expires in its enforcing hook with maintenance
    paused; explicit administrator ownership and kernel flood ownership survive
    unrelated release.
11. Single weak flags, duplicated model evidence, incomplete windows, stale
    policy epochs, and unresolved ownership cannot authorize containment.
12. Normal metrics/feature processing never require a complete periodic flow-map
    walk; slow clients and overflow cannot delay packet verdicts.
13. PASS/request/connect latency, throughput, daemon CPU/RSS, and map/queue costs
    meet budgets declared before testing on the stated reference topology.
14. Runtime status states exact hook/interface/cgroup/protocol coverage,
    observation mode, temporary action scope, and actual recovery behavior.
15. Documentation and the demo use implemented-capability labels and state
    limitations, especially first-connection exposure and persistent sessions.

Conditional acceptance:

- If socket detail is included, prove memory admission/release bounds, concurrency,
  cumulative-report correctness, completeness, and extra detection value/cost.
- If Isolation Forest is included, prove exact Python/Rust scoring parity,
  malformed-input rejection, and held-out incremental value at a matched false
  alert budget.
- Before unattended always-on deployment, verify kernel hook/link/map adoption
  through daemon failure and reboot, measured recovery behavior, and benign
  automatic containment over the predeclared shadow duration.

Observation-only classification is a valid research milestone, but does not
claim accepted autonomous behavioral blocking or unattended readiness.

---

## 29. Prerequisites and deferred work

Before acceptance work starts, declare the reference Linux kernel/configuration,
Aya lockfile version, interface mode/topology, workload scope, CPU/memory limits,
traffic/churn target, benign evaluation duration, and false-alert/containment
targets. These are required measurements/decisions, not optional future work.
The helper/load spike confirms the supported matrix. An unsupported hook leaves
that capability explicitly unavailable.

Conditional choices after a written experiment admission:

- socket detail hook, storage type, quota design, and report interval;
- existing-session denial rather than future-connect denial;
- model format/scoring implementation, only if the model comparison is useful.

Outside this release:

- fanout/transfer detectors as additional threat stories;
- wildcard/CIDR workload rules and suspect packet-rate restrictions;
- IPv6 and general UDP lifecycle coverage;
- DNS/domain attribution;
- full evidence persistence and automatic baseline/model retraining;
- fleet export, remote policy distribution, central dashboards, switch mode;
- general process investigation or removal of existing LSM based on this update.

Each extension needs its own detection benefit, costs, test scope, and admission
decision. None is an unfinished task required to deliver the focused v2.

---

## 30. Implementation discipline

The following rules apply during development:

- Preserve unrelated user changes and the accepted demo.
- Implement one phase at a time.
- Do not scaffold unused modules far ahead of tests.
- Keep map ABI changes explicit and versioned.
- Add tests in the same change as each data contract or state transition.
- Measure before optimizing and re-measure after optimization.
- Prefer deterministic rules and integer arithmetic in security decisions.
- Keep training code and production inference separate.
- Never describe a planned capability as implemented.
- Reject a complex detector if a simpler detector performs as well.
- Treat false positives as security failures because they damage availability
  and operator trust.
- Treat silent missed observations and unexplained blocks as correctness bugs.
- Keep a working rollback point before every enforcement change.

---

## 31. References

Primary technical references for implementation review:

- Linux kernel BPF-LSM documentation:
  <https://docs.kernel.org/bpf/prog_lsm.html>
- Linux kernel BPF program and attach-type table:
  <https://docs.kernel.org/bpf/libbpf/program_types.html>
- Linux kernel BPF ring-buffer documentation:
  <https://docs.kernel.org/bpf/ringbuf.html>
- Linux kernel socket-local storage documentation:
  <https://docs.kernel.org/bpf/map_sk_storage.html>
- Linux kernel hash/LRU map documentation:
  <https://docs.kernel.org/bpf/map_hash.html>
- Linux kernel BPF map overview:
  <https://docs.kernel.org/bpf/maps.html>
- Linux kernel eBPF syscall reference, including batch map operations:
  <https://docs.kernel.org/userspace-api/ebpf/syscall.html>
- Linux UAPI definitions for socket cookies and sockops callbacks:
  <https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h>
- Linux `pidfd_open` semantics:
  <https://man7.org/linux/man-pages/man2/pidfd_open.2.html>
- Linux Unix-socket credentials (`SO_PEERCRED`):
  <https://man7.org/linux/man-pages/man7/unix.7.html>
- scikit-learn Isolation Forest scoring and API:
  <https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html>
- scikit-learn scoring implementation (pin the implementation's actual version
  during export; `main` is a review reference, not a reproducibility lock):
  <https://github.com/scikit-learn/scikit-learn/blob/main/sklearn/ensemble/_iforest.py>
- Original Isolation Forest paper, Liu, Ting, and Zhou (ICDM 2008):
  <https://doi.org/10.1109/ICDM.2008.17>

Repository references:

- `README.md`
- `SECURITY.md`
- `docs/architecture.md`
- `docs/runtime_flow.md`
- `docs/codebase.md`
- `docs/evasion.md`
- `bench/README.md`

---

## 32. Short architecture summary

```text
Accepted v1 remains reproducible:
  XDP + TC + LSM + signature DPI + process observation.

Required v2:
  workload-aware connection identity
  + bounded connection timing and destination history
  + one explicit compound behavior rule
  + one registered application honeytoken
  + one serialized decision engine
  + one auditable enforcer
  + kernel expiry and precise future-connect containment
  + headless service and two terminal views in the same executable.

Conditional experiments:
  socket detail / existing-flow denial
  Isolation Forest only with additional measured value.

Outside v2:
  fleet services, new rate restrictions, fanout/transfer detectors,
  GUI development, EDR, switch mode, TLS interception.

Packet work is bounded and benchmarked.
Analysis is asynchronous and local.
Evidence explains actions; actions have ownership and deadlines.
```

---

## 33. Review record — 2026-10-02

The scope pass compared every required feature to the selected workload-aware
network detection story. The code pass checked actual map writers, metrics,
clock/TTL behavior, hooks, loader lifetime, attribution, and current packaging.
The consistency pass checked phase dependencies, acceptance criteria, modes,
configuration, and model/honeytoken assumptions against primary references.

| Finding in the earlier plan/current baseline | Resolution in this plan |
|---|---|
| Four behavior detectors and multiple threat stories were mandatory | Require periodicity/destination history; defer fanout/transfer |
| Collector/export/policy distribution had an implementation phase | Remove from release phases and definition of done |
| Rich terminal implied a second binary/crate | Client subcommands/optional alias in the existing executable |
| Existing external BPF ELF was described as a self-contained binary | State current artifact requirement and record its version/checksum |
| Periodicity, novelty, and model counted as independent evidence | Explicit compound rule and shared correlation group |
| Arbitrary score weights suggested confidence without validation | Remove score sums/bonuses; version measurable rule clauses |
| Evidence for a workload could select the wrong destination | Exact workload-generation/destination/port correlation |
| New collector avoided scans but v1 metrics still scanned each second | Remove the production metrics scan and bound explicit diagnostics |
| Socket storage was described as inherently bounded | Conditional only with proven quotas; fixed-cap hash candidate |
| Cumulative reports implied recovered timing/completeness | Recover totals only; invalidate missing/uncertain timing windows |
| Sequence dedupe implied all redundant reports share an ID | Per-counter-generation high-water accounting and event budgets |
| PID enrichment was treated as solving identity | Kernel event identity; optional process metadata; no PID-only action |
| Cgroup path/ID could outlive its workload instance | Live reference, generation, boot/collector epoch, tombstones |
| Legacy BLOCKLIST has both kernel and userspace writers | Version explicit ownership; measure separate-map lookup cost |
| Kernel-only non-evicting flood map could fill with expired keys | Separate measured best-effort flood cache; no confirmed policy eviction |
| Userspace sweeps implied guaranteed temporary expiry | Kernel deadline checks; bounded cleanup only reclaims capacity |
| BOOTTIME userspace clock mismatched MONOTONIC BPF clock | Same clock and reboot epoch; suspend test |
| Fixed demo source rate could block normal server/NAT traffic | Operational configuration and benign high-rate acceptance gate |
| Expired LPM entries could mask broader policy | Reject overlap for v2; defer general precedence |
| Port zero was called a wildcard in an exact hash key | Exact TCP/port rules only |
| Denying connects sounded like revoking an established channel | Explicit future-connect scope; existing-flow denial conditional |
| Socket cleanup/lifecycle callback implied exact snapshot/zero contention | Atomic scalar discipline, approximate composite data, scale gates |
| Honeytoken credentials implied truth of claimed source | Dedicated producer UID and verified direct/proxy source scope |
| Hidden cookies/forms or NAT/proxy paths could block legitimate clients | Direct-app reference integration and observe default |
| Custom tree traversal omitted full model scoring semantics | Leaf corrections, feature maps, float behavior, score-direction parity |
| Hashing an artifact implied authenticity | Digest integrity only; configured root-owned artifact trust |
| Headless process/pinned map implied restart continuity | Declared recovery mode; link/adoption proof before unattended claims |
| A queued verdict could be displayed as successful containment | Actual state waits for enforcement result and active scope |
| Per-subject limits could still retain excessive global memory | Global entry/byte quotas, possible-CPU memory calculation |
| One Tokio consumer was described as arrival-order independent | Explicit event-time/lateness contract and recorded-order replay |
| Current XDP parse failure was implied to pass traffic | Record actual XDP_ABORTED drop; deliberate tested remediation |
| LSM allow path could ignore an earlier BPF-LSM denial | Propagate prior result and test coexistence |

Review completion is a documentation/design result. No v2 detector, hook,
recovery mechanism, model, or performance target has been implemented or proven
by this edit. Linux verifier/load tests, held-out evaluation, shadow duration,
and real PASS/request/connect measurements remain phase gates. A proof of
concept becomes convincing by passing those gates, not by adding more rows to
the feature list.
