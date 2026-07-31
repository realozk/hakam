# Contributing to Hakam

Thanks for taking the time to look at Hakam. It's a single-host, single-binary
eBPF firewall meant to be small enough to **read end to end**, so contributions
that keep it auditable and honest are especially welcome.

## Ways to help

- **Report a bug** — open an issue with your kernel version (`uname -r`), the
  interface/mode you attached with, and the exact command that failed.
- **Improve the docs** — if a step in [`start_guide.md`](start_guide.md) or
  [`packaging/docker/REVIEW.md`](packaging/docker/REVIEW.md) didn't work on your
  setup, that's a real bug worth a PR.
- **Add or fix a signature** — see the corpus in `hakam-node/src/signatures.rs`
  and the evasion notes in [`docs/evasion.md`](docs/evasion.md).
- **Close a known limitation** — the [Honest limitations](README.md#honest-limitations)
  section is the honest to-do list.

## Development setup

Hakam builds and runs on **Linux only** (kernel ≥ 5.15) — eBPF/XDP/BPF-LSM live
in the Linux kernel. macOS/Windows can develop the UI, but the node must run on
a Linux host or VM.

```bash
# Toolchain
rustup toolchain install nightly --component rust-src
cargo install bpf-linker          # needs LLVM ≥ 14; ~10 min to build

# Build the eBPF object + userspace node, then run
cargo xtask build-ebpf
cargo xtask run --iface lo --mode skb --bind 0.0.0.0
```

The browser HUD lives in `hakam-ui/` (React + Vite): `npm install && npm run dev`.

Full walkthrough — VM setup, the demo network, troubleshooting — is in
[`start_guide.md`](start_guide.md). Repo architecture and the kernel/userspace
boundary are in [`docs/architecture.md`](docs/architecture.md) and
[`docs/codebase.md`](docs/codebase.md).

## Before you open a pull request

1. **Run the tests** — `cargo test` (userspace unit + integration tests).
2. **Keep it building** — `cargo build -p hakam-node --features linux` and
   `cargo xtask build-ebpf` both succeed. CI runs these on every PR
   (`.github/workflows/ci.yml`, `.github/workflows/ebpf.yml`).
3. **Match the surrounding style** — no new dependencies without a reason, and
   keep kernel-side code within the eBPF verifier's constraints (no loops, no
   heap, bounded access — see the verifier notes in `docs/codebase.md`).
4. **Be honest about limits** — if a change narrows or widens what Hakam can
   detect or enforce, update the README's limitations and, if relevant,
   `docs/evasion.md`. Overclaiming is the one thing this project won't ship.

## Pull request process

- Branch off `main`, keep the change focused, and describe **what** it does and
  **why** in the PR body.
- Reference the issue it closes, if any.
- Green CI is required before merge.

## License

By contributing, you agree that your contributions are licensed under the
project's [MIT License](LICENSE).
