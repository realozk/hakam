# Contributing to Hakam

Contributions that improve correctness, documentation, and reproducibility are
welcome. Hakam is a Linux eBPF research project; changes should make its behavior
and limitations easy to inspect.

## Report an issue

For bugs, include the kernel version (`uname -r`), interface, XDP mode, exact
command, relevant logs, and steps to reproduce. For telemetry issues, include
the client command and the messages received.

Report security vulnerabilities through the process in [SECURITY.md](SECURITY.md).
For setup problems, identify the step in the [setup guide](start_guide.md) or
[Docker walkthrough](packaging/docker/REVIEW.md) that failed.

## Development setup

Follow the [setup guide](start_guide.md). The kernel programs and full node run
on Linux; userspace library tests can run on other supported platforms.
The workspace uses Rust nightly. Build the eBPF object with:

```bash
cargo xtask build-ebpf
```

## Validate a change

Run checks appropriate to the files changed:

```bash
# Shared types, matcher, reassembly, and userspace tests
cargo test

# Linux controller build (on Linux)
cargo build -p hakam-node --features linux

# Kernel program build
cargo xtask build-ebpf
```

A successful eBPF build does not prove the kernel verifier accepts the program.
For kernel-path changes, load it on the target Linux configuration and exercise
the relevant scenario. See [script reference](docs/scripts.md) for smoke,
validation, and evasion checks.

## Submit a pull request

1. Branch from `main` and keep the change focused.
2. Explain the problem, resulting behavior, and validation performed.
3. Add tests for meaningful logic or ABI changes; describe Linux checks where required.
4. Update documentation when detection coverage, enforcement, configuration, or setup changes.
5. Resolve CI failures before requesting review.

Keep kernel accesses bounded and compatible with the verifier. Document new
dependencies and resource limits. Distinguish observed detections from confirmed
containment, and planned features from implemented behavior.

## License

Contributions are licensed under the project's [MIT License](LICENSE).
