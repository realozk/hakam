# Attack packet captures

Four HTTP-request fixtures recorded on the local demo network, with target
`10.99.0.10:80`. The replay script checks whether each source produces the
expected signature-detection event.

## Replay

On Linux, install `tcpreplay` and `websocat`, then run from the repository root:

```bash
./scripts/setup-demo.sh
cargo xtask run --iface lo --mode skb
# In another terminal, with an empty packet blocklist:
./scripts/replay-corpus.sh
```

Use `clear` in the CLI before repeating a replay. Sources that are already
blocked cannot deliver another payload sample. The script uses `lo` by default;
check its `IFACE`, `WS_HOST`, and `WS_PORT` settings when using another topology.

| Capture | Source | Request class | Expected detection |
|---|---|---|---|
| `pcaps/sqli-union.pcap` | `10.99.2.11` | SQL injection | SQLi: `UNION SELECT` |
| `pcaps/xss-script.pcap` | `10.99.2.12` | Cross-site scripting | XSS: `<script>` |
| `pcaps/path-traversal.pcap` | `10.99.2.13` | Path traversal | LFI: `../` |
| `pcaps/cmd-injection.pcap` | `10.99.2.14` | Command injection | LFI: `/etc/passwd` |

The command-injection request contains `;cat /etc/passwd`; its expected match is
an LFI token. Hakam also has RCE patterns, but this fixture does not demonstrate
complete command-injection coverage. Labels describe the signature that fires.

A `BLOCK` event reports a detection and an attempted blocklist action; the current
DPI path does not check map-insertion success. It does not confirm
that the initial sampled request was prevented, or that an exploit succeeded.
The local listener does not execute the payloads.

## Add or regenerate a fixture

Capture on the demo interface while sending a request from a fresh source:

```bash
sudo tcpdump -i lo -w corpus/pcaps/example.pcap 'host 10.99.2.15 and tcp port 80'
```

Place the expected token within the available 64-byte sample, verify the
observed category, then update this table and `scripts/replay-corpus.sh`.
Document request segmentation if it affects detection.
