# Security policy

Hakam is a research and demonstration firewall. Its current coverage and limits
are described in the [README](README.md#limitations) and
[evasion analysis](docs/evasion.md). Signature matching and the demo traffic set
do not establish a security guarantee or production readiness.

## Maintained code

Security fixes are made against `main`. Older revisions may not receive
backported fixes; include the affected commit or tag in your report.

## Report a vulnerability

Use the repository's **Security → Report a vulnerability** option if private
vulnerability reporting is enabled. Do not include exploit details or sensitive
data in a public issue. If that option is unavailable, ask the maintainer to
provide a private reporting channel without publishing the vulnerability.

Include:

- The affected component and commit or version.
- Kernel version and configuration, interface, and attachment mode.
- Reproduction steps and observed impact.
- Relevant logs or a minimal proof of concept, with credentials removed.

Reports are reviewed as maintainer availability permits. This project does not
promise a fixed response deadline or a vulnerability bounty.

## Evaluation scope

Use an isolated Linux host or VM for demonstrations. The container has privileged
access to the host kernel, and the setup scripts change network configuration.
The telemetry WebSocket has demo-control functionality; keep it on loopback or
a trusted network. Report issues involving unintended blocking, policy bypass,
unsafe kernel access, privilege boundaries, or unauthenticated control access.

Documented signature misses remain useful context for reports. New bypasses,
incorrect enforcement, and availability failures should include the traffic and
configuration needed to reproduce them.
