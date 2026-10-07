# Architecture

Hakam has four kernel hooks and a userspace controller. The hooks enforce
IPv4 packet and connection policies. The controller consumes sampled traffic,
updates maps, and publishes telemetry. Operators use the interactive CLI,
service logs, or a WebSocket client.

## Kernel and userspace boundary

```text
KERNEL: hakam-ebpf (no_std)
  XDP ingress ── BLOCKLIST / per-CPU rate counters ── drop or pass
       └── TCP samples and sequence metadata ── PAYLOAD_EVENTS
  TC egress ──── BLOCKLIST destination lookup ────── drop or pass
  BPF-LSM ────── CONNECT_POLICY destination lookup ─ allow or EPERM
  Connect tracepoint ── PID / process / destination ─ CONNECT_EVENTS

USERSPACE: hakam-node
  PAYLOAD_EVENTS → sample reassembly → HTTP gate → signature matcher
       └── match → insert source in BLOCKLIST → detection telemetry
  CONNECT_EVENTS → connection telemetry / heuristic process correlation
  Kernel maps → counters / histogram estimates → periodic metrics
  CLI → map reads and policy changes
  Maintenance → periodic packet-block expiry
  WebSocket → telemetry fan-out and demo commands
```

## Hook responsibilities

| Hook | Program | Scope and action |
|---|---|---|
| XDP ingress | `hakam_ebpf` | IPv4 source lookup in `BLOCKLIST`; per-CPU source rate policy; eligible TCP payload sampling. |
| TC egress | `hakam_egress` | IPv4 destination lookup in `BLOCKLIST` on the attached interface. |
| BPF-LSM `socket_connect` | `hakam_connect_lsm` | Denies new IPv4 `connect()` calls whose destination matches `CONNECT_POLICY`. Requires kernel support. |
| `sys_enter_connect` | `hakam_connect` | Observes local IPv4 connection attempts. Optional CIDR filtering through `MONITOR_CFG`. |

The tracepoint is an observation hook, not an enforcement point. Connectionless
UDP sends do not invoke `socket_connect`; TC applies packet policy on its
attached interface. LSM connection policy is destination-based and is not
restricted to the interface selected for XDP/TC.

The default local demo uses `lo` in generic (`skb`) mode. Native driver-mode XDP
can reject blocked traffic before socket-buffer allocation on a supported
interface; that claim does not apply to the generic-mode demo.

## Signature detection

1. XDP samples the first 64 available payload bytes of eligible TCP segments and records flow/sequence metadata.
2. `payload_task` builds a view keyed by the IPv4 address/port four-tuple. Defaults are 256 sampled bytes per flow, 4,096 flows, and a 30-second idle-age threshold.
3. The HTTP gate checks for a recognized request method. Aho-Corasick scans the view with ASCII case folding, then scans a single URL-decoded view if necessary.
4. A match attempts to install a `/32` source entry in `BLOCKLIST`, releases that flow's sample buffer, and publishes a detection event.
5. Later ingress packets from the source and egress packets to it hit the kernel blocklist.

Detection is asynchronous. The sampled request can reach the application before
the source is blocked. Sample reassembly sorts fragments by raw sequence number
and discards repeated sequence keys; it does not restore missing bytes or provide
full TCP stream validation. Its idle cleanup runs every 1,024 payload events.

## Process attribution

The tracepoint reports PID and process name for local connection attempts.
`dpi.rs` correlates detections using destination address and port, retaining the
most recent observed process within the attribution window. This is a heuristic:
multiple processes contacting the same endpoint can be confused, and remote
inbound traffic has no guaranteed local originating-process attribution.

## Map inventory

Declarations are in [main.rs](../hakam-ebpf/src/main.rs).

| Map | Type / capacity | Purpose |
|---|---|---|
| `BLOCKLIST` | LPM trie / 1,024 entries | IPv4 packet blocks with insertion timestamps |
| `CONNECT_POLICY` | LPM trie / 1,024 entries | Separate outbound connection policy |
| `CONNTRACK` | LRU hash / 65,536 entries | Lightweight flow and sequence observations |
| `PACKET_COUNTER` | LRU per-CPU hash / 1,024 keys | Source packet counts |
| `LAST_SEEN` | LRU per-CPU hash / 1,024 keys | Source rate-window timestamps |
| `PAYLOAD_EVENTS` | Ring buffer / 1 MiB | TCP payload samples |
| `CONNECT_EVENTS` | Ring buffer / 512 KiB | Process connection events |
| `DROP_COUNTER` | Per-CPU array / 1 cell | XDP drop counts |
| `LATENCY_HIST` | Per-CPU array / 64 cells | Log2 blocklist-drop latency histogram |
| `RING_OVERFLOW` | Per-CPU array / 1 cell | Failed payload-ring reservations |
| `MONITOR_CFG` | Array / 1 cell | Optional connect-observation CIDR |

The rate threshold is 500 packets per second per source per CPU; it is not a
host-wide 500-packet/s bound. Blocklist capacity and ring-buffer loss can limit
coverage under load.

Packet-block expiry runs in userspace every 30 seconds with a 120-second age
threshold. It is not a kernel deadline, and insertion/expiry use different clock
sources in the current implementation. Connection-policy entries are managed
separately through `policy-block`, `policy-unblock`, and `policy-list`.

## Telemetry

The default endpoint is `ws://127.0.0.1:8080/ws`. The node uses a bounded Tokio
broadcast channel. Slow consumers can miss events; telemetry is not a persistent
audit log.

| Message | Main fields |
|---|---|
| `METRICS` | CPU, histogram p50/p99 estimates, drops, interface rates, memory, ring overflows, active flows |
| `BLOCK` | Source, target, action, optional payload/category/severity and process correlation |
| `UNBLOCK` | Source |
| `CONNECT` | PID, process name, destination, port |
| `EVENT` | Message and level |

The WebSocket also accepts demo-control input and forwards it to a local command
file. Keep the endpoint on loopback or a trusted network. The CLI reads kernel
counters and policy maps; WebSocket clients can consume events independently.

## Validation and design status

Userspace tests cover shared layouts, signatures, decoding, reassembly, and
helper behavior. Kernel acceptance requires an eBPF build, verifier/load check,
and live traffic exercise on the selected Linux configuration. See
[CONTRIBUTING.md](../CONTRIBUTING.md) and the [script reference](scripts.md).

The [v2 architecture plan](v2-architecture-plan.md) describes proposed work.
Behavioral detection, honeytokens, and workload-scoped containment from that
plan are not implemented capabilities of the current version.
