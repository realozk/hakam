# Attack PCAP corpus

Small, in-repo packet captures of real attack requests, so a reviewer can
**clone → replay → watch Hakam block them** in seconds — no synthetic harness,
no external corpora to download.

```bash
# 1. run hakam-node on an interface (fresh, empty blocklist):
sudo cargo xtask run --iface lo --mode skb        # or systemctl start hakam / docker run
# 2. replay every capture and assert each is blocked:
./scripts/replay-corpus.sh
```

Each capture is a single HTTP request from a fixed source IP, taken on the demo
network (target `10.99.0.10:80`). `scripts/replay-corpus.sh` replays them with
`tcpreplay` and confirms the expected `BLOCK` arrives on the telemetry feed.

| PCAP | Source | Attack class | **Detected as** | Notes |
|------|--------|--------------|-----------------|-------|
| `sqli-union.pcap` | 10.99.2.11 | SQL injection | **SQLi** (`UNION SELECT`) | classic union-based read |
| `xss-script.pcap` | 10.99.2.12 | Cross-site scripting | **XSS** (`<script>`) | reflected script tag |
| `path-traversal.pcap` | 10.99.2.13 | Path traversal | **LFI** (`../`) | `../../../../etc/passwd` |
| `cmd-injection.pcap` | 10.99.2.14 | OS command injection | **LFI** (`/etc/passwd`) | see honesty note below |

## Honesty note — what actually fires

Hakam is a **signature** DPI engine, and its families are what they are. The
`cmd-injection.pcap` payload is an OS-command-injection vector
(`;cat /etc/passwd`), but Hakam has **no dedicated command-injection family** —
it blocks this capture via the `/etc/passwd` token in its **LFI** signature set.
We keep the capture (the block is real and useful) but label it by what actually
matches, rather than claim command-injection coverage we don't have. The two LFI
captures (`path-traversal`, `cmd-injection`) exercise different tokens (`../`
vs a sensitive-file path).

## Regenerating / adding captures

Captures were taken with `tcpdump -i lo -w <name>.pcap 'host <src> and tcp port 80'`
while sending the request from `<src>` to the demo target. To add one, capture a
request whose attack token lands in the first 64 bytes (Hakam's sample window),
confirm it blocks, and add a row above + an entry in `scripts/replay-corpus.sh`.
