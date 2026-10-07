# Runtime flow

This reference follows the current node from startup through detection,
telemetry, maintenance, and shutdown. For hook scope and map capacities, see
[architecture.md](architecture.md).

## Startup

`cargo xtask run` builds the eBPF object and Linux controller, then starts the
controller with the selected interface, XDP mode, and telemetry bind address.
The runtime in [main.rs](../hakam-node/src/main.rs):

1. Parses arguments and loads the compiled eBPF object.
2. Attaches XDP ingress and TC egress to the selected interface.
3. Attempts the connect tracepoint and BPF-LSM hook, reporting unavailable optional capabilities.
4. Opens maps and event rings; applies optional `--monitor-prefix` filtering.
5. Starts payload and connect consumers, metrics, maintenance, WebSocket, and CLI tasks.
6. Waits for a shutdown signal or CLI exit.

The compiled BPF object is a separate runtime artifact. A started node does not
imply every optional hook attached successfully; inspect startup output.

## Ingress packet

```text
Packet → XDP
  ├─ blocked IPv4 source → increment drop counter / histogram → XDP_DROP
  ├─ source exceeds per-CPU rate threshold → attempt source block → XDP_DROP
  └─ otherwise
       ├─ eligible TCP segment → flow observation and payload-ring sample
       └─ XDP_PASS
```

The signature engine is not on the synchronous packet-verdict path. A payload
sample does not wait for userspace before the packet passes. Ring reservation
failure increments `RING_OVERFLOW`; the affected sample is unavailable to DPI.

The histogram measures the XDP blocklist-drop branch. It does not measure
signature detection time, TC drops, the initial rate-limit rejection, or
application response latency. Parse errors have their own kernel return path;
consult [xdp.rs](../hakam-ebpf/src/xdp.rs) rather than assuming all errors pass.

## Egress packet and connection policy

TC checks IPv4 destinations against `BLOCKLIST` and returns `TC_ACT_SHOT` on a
match. Otherwise it allows the packet. This acts on the attached interface.

Separately, BPF-LSM checks `CONNECT_POLICY` during an IPv4 `connect()` attempt.
A matching destination returns `EPERM`. This blocks a new connection; it does
not revoke an already-established socket. Unsupported address families and
internal read failures take the current allow path.

The connect tracepoint observes local IPv4 connection attempts and publishes
PID, process name, destination, and port through `CONNECT_EVENTS`. Its optional
CIDR filter narrows observation, not packet or LSM policy.

## Signature detection

[The payload task](../hakam-node/src/dpi.rs) drains samples and performs:

```text
PayloadEvent
  → four-tuple sample buffer, ordered by sequence
  → recognized HTTP-method gate
  → raw case-insensitive Aho-Corasick scan
  → single URL-decoding fallback if raw scan misses
  → match: attempt source /32 insertion in BLOCKLIST
  → forget sample buffer, update counters, publish detection
```

The default sample buffer holds at most 256 bytes per flow across 4,096 flows.
Cleanup runs every 1,024 sampled events using a 30-second idle-age threshold.
Missing bytes are not recovered. Duplicate sequence keys are ignored, without
validating conflicting retransmitted content.

A detection can include process metadata from a destination/port correlation
with recent connect events. The latest process reaching an endpoint can replace
a previous entry, so this metadata is heuristic.

## Packet-block lifecycle

| Action | Effect |
|---|---|
| Signature hit | Userspace attempts a source `/32` insertion in `BLOCKLIST` |
| Rate threshold exceeded | Kernel attempts a source `/32` insertion |
| CLI `block` | Userspace inserts the requested address or CIDR |
| CLI `unblock` / `clear` | Userspace removes selected or all packet entries |
| Maintenance sweep | Every 30 seconds, removes entries beyond the 120-second age threshold |

Once present, a packet block applies to incoming source and outgoing destination
lookups. Kernel enforcement does not test an expiry deadline. Delayed maintenance
can extend a block; kernel and userspace insertion/expiry clocks also differ in
the current version. The separate `CONNECT_POLICY` map is removed through its
policy commands, not this packet-block sweep.

## Telemetry and terminal operation

Tasks publish JSON through a bounded broadcast channel. The WebSocket server
fans messages out to connected clients. Lagging clients can lose messages, and
new clients do not receive a complete historical replay.

The interactive CLI exposes `stats`, `rules`, `list`, and policy commands.
Kernel packet-drop counters differ from signature-detection totals. The
WebSocket exposes structured events for scripts and other clients; it does not
provide persistent history or a complete policy-control API.

Demo-control messages travel in the other direction through the WebSocket and
are written to `/tmp/hakam-demo.cmd`. `demo-cycle.sh` or
`attack-on-demand.sh` consumes those controls. Run one driver at a time.

## Demo sequence

`setup-demo.sh` creates local aliases and a no-op listener. Traffic between the
aliases traverses `lo`, where the demo attaches XDP and TC in generic mode.
`demo-cycle.sh` rotates through seven phases while a separate benign source pool
continues sending requests. See [start_guide.md](../start_guide.md) for timing
and keyboard controls.

The listener does not execute attacks. A signature detection, a dropped packet,
and a successful application exploit are different observations.

## Shutdown

CLI `quit`, Ctrl-C, or the configured service/container stop signal initiates
shutdown. The node exits and releases its owned BPF resources. The launch helper
also attempts to clean stale XDP/TC attachments before starting again.

Demo address aliases, the target listener, and benchmark namespaces are separate
setup resources. Stopping the node does not imply those resources were removed.
After an abnormal exit, inspect attachment state before relying on coverage or
cleanup. The current runtime does not establish uninterrupted enforcement across
controller failure or reboot.
