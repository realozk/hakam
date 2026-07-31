# Security Policy

## Scope and intent

Hakam is an **open-source, single-host eBPF firewall** built for research,
learning, and demonstration. It is deliberately auditable and documents its own
limits honestly — see [Honest limitations](README.md#honest-limitations) and the
[evasion corpus](docs/evasion.md). It is **not** a hardened, production WAF, and
its signature DPI is a supporting layer, not a security guarantee. Please keep
that framing in mind when assessing impact.

## Supported versions

| Version            | Supported |
|--------------------|:---------:|
| latest release / `main` | ✅ |
| older tags         | ❌ (please upgrade) |

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Report it privately through GitHub's private vulnerability reporting:

1. Go to the **Security** tab of the repository.
2. Click **Report a vulnerability** and describe the issue.

Please include:

- affected component (kernel program, userspace node, UI, or a script),
- kernel version (`uname -r`) and how Hakam was attached (interface + mode),
- steps to reproduce, and the impact you observed,
- a proof of concept if you have one.

I'll acknowledge your report as soon as I reasonably can and keep you updated on
a fix. Because Hakam is maintained by a single person, please allow reasonable
time before any public disclosure — coordinated disclosure is appreciated.

## What is in scope

- Memory-safety or logic bugs in the userspace node (`hakam-node`) that a remote
  or local input can trigger.
- eBPF programs that can be made to misbehave, crash, or bypass enforcement in a
  way not already documented as a limitation.
- The demo/packaging scripts running with more privilege than they need.

## What is out of scope

- The documented detection limits (64-byte capture window, sampled-segment
  reassembly, ASCII case folding, single-pass URL decoding) — these are known
  and listed in the README on purpose.
- Findings that require an already-privileged local attacker, since Hakam itself
  runs privileged by design (it loads kernel programs).
- Denial of service from unrealistic traffic volumes against the demo network.

Thank you for helping keep Hakam honest and safe to run.
