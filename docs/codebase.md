# Codebase reference

Hakam is a Rust workspace with kernel programs and a userspace controller.
This guide identifies the files to read when investigating a behavior or making
a change. Start with [architecture.md](architecture.md) for the overall design.

## Build configuration

| File | Purpose |
|---|---|
| [Cargo.toml](../Cargo.toml) | Workspace membership and build profiles; excludes eBPF from the default host build |
| [rust-toolchain.toml](../rust-toolchain.toml) | Nightly toolchain and `rust-src` components |
| [.cargo/config.toml](../.cargo/config.toml) | `cargo xtask` alias |
| [xtask/src/main.rs](../xtask/src/main.rs) | eBPF compilation, controller build, interface cleanup, and privileged launch |
| [.github/workflows](../.github/workflows/) | Userspace and eBPF CI builds |

The eBPF target uses `-Z build-std=core` and `bpf-linker`. A normal `cargo build`
does not compile the kernel program; use `cargo xtask build-ebpf`.

## Shared types: hakam-common

[lib.rs](../hakam-common/src/lib.rs) defines addresses, payload/connect events,
flow keys and state, and constants shared across the kernel/userspace boundary.
The crate supports `no_std` for eBPF and a `std` feature for userspace.

Field layout, padding, and byte order are part of the map/ring ABI. Update both
producer and consumer when changing an event. Payload events include address and
port fields, sequence metadata, flags, and the fixed 64-byte sample.

## Kernel programs: hakam-ebpf

| File | Responsibility |
|---|---|
| [main.rs](../hakam-ebpf/src/main.rs) | Maps, capacities, constants, and four program entry points |
| [xdp.rs](../hakam-ebpf/src/xdp.rs) | Ingress parsing, source blocks, per-CPU rate counting, flow observation, payload sampling |
| [tc.rs](../hakam-ebpf/src/tc.rs) | Egress destination filtering against the packet blocklist |
| [lsm.rs](../hakam-ebpf/src/lsm.rs) | IPv4 `socket_connect` destination policy |
| [tracepoint.rs](../hakam-ebpf/src/tracepoint.rs) | Local connection metadata with optional CIDR scope |
| [conntrack.rs](../hakam-ebpf/src/conntrack.rs) | Lightweight sequence/flow state, not a complete TCP state machine |
| [helpers.rs](../hakam-ebpf/src/helpers.rs) | Shared packet-access and drop-metric helpers |

Kernel code must keep accesses bounded and satisfy the verifier. Packet headers
are untrusted input; successful compilation does not prove a safe load on every
kernel. Validate changed hooks with the verifier and live scenarios.

`BLOCKLIST` and `CONNECT_POLICY` are separate LPM tries. The former affects XDP
and TC packets; the latter denies new connections through BPF-LSM. The tracepoint
only observes. See [the map inventory](architecture.md#map-inventory).

## Controller: hakam-node

| File | Responsibility |
|---|---|
| [main.rs](../hakam-node/src/main.rs) | Linux loader, hook attachment, task wiring, and shutdown |
| [lib.rs](../hakam-node/src/lib.rs) | Cross-platform library modules used by tests |
| [signatures.rs](../hakam-node/src/signatures.rs) | Signature corpus, categories, HTTP gate, Aho-Corasick matcher, URL fallback |
| [reassembly.rs](../hakam-node/src/reassembly.rs) | Bounded per-flow sample buffers, sequence sorting, duplicate filtering, and cleanup |
| [dpi.rs](../hakam-node/src/dpi.rs) | Payload/connect ring consumers, map insertion, detection counters, process correlation |
| [cli.rs](../hakam-node/src/cli.rs) | Startup arguments, interactive commands, rule formatting, and console output |
| [metrics.rs](../hakam-node/src/metrics.rs) | `/proc` sampling, kernel counters, and histogram percentile estimates |
| [maintenance.rs](../hakam-node/src/maintenance.rs) | Packet-block age sweep and demo clear-command watcher |
| [monitor.rs](../hakam-node/src/monitor.rs) | Packing the connect-observation CIDR filter |
| [telemetry.rs](../hakam-node/src/telemetry.rs) | JSON messages, WebSocket fan-out, and demo-command handling |

The full runtime requires the `linux` feature. Library tests can exercise
signatures and reassembly without attaching eBPF. The node loads a separate BPF
object whose path is configurable with `--bpf-path`.

The reassembler concatenates retained samples in raw sequence order; it does not
recover gaps or implement complete stream validation. Process correlation is
keyed by destination/port and can be ambiguous. These limits matter when
interpreting a detection; see [runtime_flow.md](runtime_flow.md).

## Tests and operational tools

- [hakam-node/tests](../hakam-node/tests/) covers matcher behavior, reassembly, and helper logic.
- Shared-type and library modules also contain unit tests.
- [scripts](scripts.md) documents Linux smoke, validation, evasion, packet replay, and benchmark tools.
- [corpus](../corpus/README.md) contains four replayable packet captures.
- [bench](../bench/README.md) explains measurements and capture limitations.
- [packaging](../packaging/README.md) contains systemd installation and Docker workflows.

Run checks appropriate to the change as described in
[CONTRIBUTING.md](../CONTRIBUTING.md). Test counts vary as the code changes; use
the current test output rather than a fixed documentation total.

## Proposed work

[v2-architecture-plan.md](v2-architecture-plan.md) is a design proposal with
acceptance gates. It does not describe shipped behavioral detectors, honeytoken
integration, or recovery guarantees.
