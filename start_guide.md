# Hakam — Startup Guide

> **Project location:** `~/hakam` on the Mac.
> OrbStack auto-mounts the Mac home into the VM at `/Users/omaralzhrani/hakam`,
> so both sides see the **same files**. Edit on Mac → VM sees it instantly.
> No `git pull`, no `rsync`.

---

## TL;DR — three terminals, ~30 seconds

After everything is installed (see §5 for first-time setup), the entire startup is:

```bash
# Terminal 1 — VM
orb -m hakam
cd ~/hakam
./scripts/setup-demo.sh
cargo xtask run --iface lo --mode skb --bind 0.0.0.0
```

```bash
# Terminal 2 — Mac
cd ~/hakam/hakam-ui
VITE_HAKAM_WS_URL=ws://hakam.orb.local:8080/ws npm run dev
# → open http://localhost:5173 in a browser
```

```bash
# Terminal 3 — VM
orb -m hakam
cd ~/hakam
./scripts/demo-cycle.sh
```

If the HUD shows **RECONNECTING** in the top-right, jump to §6 and read the
"HUD never connects" row first — it covers the 90% case.

---

## 1 · From zero — what each terminal does

### Terminal 1 — the kernel firewall

This terminal **must keep running** for the whole demo.

```bash
orb -m hakam                                     # boot/attach to the VM
cd ~/hakam
./scripts/setup-demo.sh                            # idempotent network bootstrap
cargo xtask run --iface lo --mode skb --bind 0.0.0.0
```

What `setup-demo.sh` does (safe to re-run):
- creates the `dummy0` interface if missing
- assigns all demo IPs to it: target (`10.99.0.10`), workstations (`10.99.1.10`, `10.99.2.10`),
  18 rotating attack sources (`10.99.{1,2}.11-19`), 10 benign sources (`10.99.3.10-19`)
- relaxes `rp_filter` to `2` so spoofed-source packets aren't silently dropped
- starts a Python **no-op TCP listener** on `10.99.0.10:80` (`scripts/target-listener.py`).
  This is critical: without a listener, the attacker `nc(1)` calls get a `TCP RST`
  before they can transmit the HTTP payload, so XDP only ever sees the SYN
  and the DPI signature engine has nothing to match. With it, the handshake
  completes and the actual `GET /q?x=admin'` flows across the wire.

What `cargo xtask run` does:
- builds `hakam-ebpf` (the BPF program) and `hakam-node` (the userspace bridge)
- attaches XDP_INGRESS + TC_EGRESS + a `sys_enter_connect` tracepoint to **`lo`**
- starts the WebSocket telemetry server on `:8080`

> **Why `lo`?** All demo IPs (attacker sources and the target) are aliases on
> `dummy0`. When two local IPs talk to each other, Linux routes the packet
> via the loopback interface, **not via `dummy0`**. The XDP hook has to live
> on `lo` for the inspection to see anything. `dummy0` is just a holder for
> the IP addresses.

`--bind 0.0.0.0` makes the WS reachable from the Mac via the OrbStack bridge.
For production you'd omit the flag (default `127.0.0.1`) and tunnel.

You should see roughly:

```
◉  XDP        armed on [dummy0] mode=SKB (generic)
◉  TC         armed on [dummy0] — outbound exfiltration killed at the NIC
◉  reachable  ws://10.x.x.x:8080/ws
◉  telemetry  ws://0.0.0.0:8080/ws
hakam@kernel ▸
```

Copy the `reachable` URL — it's the one to use from the Mac if `hakam.orb.local`
doesn't resolve.

### Terminal 2 — the HUD

```bash
cd ~/hakam/hakam-ui
VITE_HAKAM_WS_URL=ws://hakam.orb.local:8080/ws npm run dev
```

Open <http://localhost:5173>. Within ~2 s you should see:

- top-right: green dot + `KERNEL_LINK` (means the WebSocket is open and METRICS are flowing)
- left card: `HAKAM_ACTIVE` + non-zero CPU / latency tiles

If you see `RECONNECTING` or the left card is blank, see §6.

### Terminal 3 — the attack driver

This is what makes things light up on the HUD.

```bash
orb -m hakam
cd ~/hakam
./scripts/demo-cycle.sh                            # 113 s narrated loop, repeats
```

Or drive it manually — see §3.

---

## 2 · The narrated demo cycle

`./scripts/demo-cycle.sh` runs an unattended ~4-minute loop. **Continuous
benign traffic runs in the background for the entire cycle** (~2.5 req/s
from the `10.99.3.x` source pool), so attacks always land on top of real
traffic — the way an operator would actually watch them. The threat level
climbs gradually NOMINAL → SEVERE and then decays.

| # | Phase          | Duration | What happens on the HUD                                |
|---|----------------|---------:|--------------------------------------------------------|
| 0 | CALM           |    15 s | benign only — clean baseline, NOMINAL                    |
| 1 | PROBING        |    40 s | sparse first-touch anomalies (~1 every 10 s)             |
| 2 | INVESTIGATION  |    48 s | mixed families (~1 every 6 s) — multiple bars appear     |
| 3 | ESCALATION     |    40 s | full family spread (~1 every 3 s) — bars race            |
| 4 | PEAK           |    25 s | sustained mixed-vector ~1.7/s — threat level peaks SEVERE|
| 5 | CONTAINMENT    |    30 s | trickle of stragglers — level decays                     |
| 6 | RECOVERY       |    30 s | no attacks — return to NOMINAL                           |

Live keys while it's running: `space`=pause, `n`=next, `r`=restart, `0`–`6`=jump,
`q`=quit, `?`=help. The script narrates each phase in the terminal.

---

## 3 · Manual attack modes

If you want to drive scenarios by hand instead of the auto loop, use `seclist-attack.sh`:

```bash
cd ~/hakam
./scripts/seclist-attack.sh -l                  # list 12 attack families
./scripts/seclist-attack.sh                     # 30 random shots, then exit
./scripts/seclist-attack.sh -n 100 -d 100       # 100 shots, 100 ms apart
./scripts/seclist-attack.sh -c                  # continuous (Ctrl-C to stop)
./scripts/seclist-attack.sh -k SQLi -n 20       # only SQLi payloads
./scripts/seclist-attack.sh -k Log4Shell -c     # firehose just Log4Shell
./scripts/seclist-attack.sh -k RCE -n 50 -d 50  # rapid RCE burst
```

187 randomised HTTP payloads across 12 families, source IPs rotated through the
18 demo workstations created by `setup-demo.sh`.

---

## 4 · CLI reference (the `hakam@kernel ▸` prompt)

```
block <IP[/prefix]>     drop all packets from/to IP or CIDR range
unblock <IP[/prefix]>   restore traffic from/to IP or CIDR range
list                    print active block rules with age + TTL
status                  interface, hooks, signature corpus, blocklist
rules                   show DPI signature families and counts (bar chart)
stats                   live drops, latency p50/p99, detections per family
clear                   remove every entry from the blocklist
help, ?                 show command reference
quit, exit, q           detach XDP + TC + tracepoint, exit cleanly
```

Useful during a demo:

- `rules` — proves the 200+ signature corpus to a sceptical viewer
- `stats` — live counters, useful when the HUD is offscreen
- `clear` — instant reset between demo runs without waiting on the 120 s TTL

---

## 5 · One-time setup (skip if you've already done it)

### Create the OrbStack VM (on the Mac, one-time)

If `orb -m hakam` errors with `[-32098] machine not found: 'hakam'`, the VM
doesn't exist yet. Create it once:

```bash
# Install OrbStack first if you don't have it: https://orbstack.dev
orb create ubuntu hakam                            # latest Ubuntu, named "hakam"
orb list                                            # verify "hakam" shows running
```

The VM auto-mounts your Mac home at `/Users/omaralzhrani/` inside the guest,
so `~/hakam` on the Mac is the same directory as `/Users/omaralzhrani/hakam`
in the VM — no clone, no sync.

### On the VM (one-time)

```bash
orb -m hakam                                       # enter the VM you just created

# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env
rustup toolchain install nightly --component rust-src

# eBPF linker + system deps
sudo apt-get update && sudo apt-get install -y llvm clang libelf-dev pkg-config
cargo install bpf-linker
```

> **No `rustup target add bpfel-unknown-none` step.** xtask builds the BPF
> stdlib from source via `-Z build-std=core`, so `rust-src` (installed above)
> is all you need. On aarch64 hosts there's no prebuilt BPF std anyway, so
> trying to add the target would just fail.
>
> `bpf-linker` takes ~10 minutes to compile. Coffee break.

### On the Mac (one-time)

```bash
# Node.js + Rust (if you don't have them)
brew install node                                  # for the UI dev server
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# UI dependencies
cd ~/hakam/hakam-ui
npm install
```

### Verify the setup

Before going live, run the preflight from the Mac. It walks every common
failure point and prints PASS/FAIL:

```bash
cd ~/hakam
./scripts/preflight.sh
```

---

## 6 · Troubleshooting

| Symptom | Fix |
|---|---|
| **HUD shows `RECONNECTING` / left card empty after attacks** | Almost always a WebSocket URL mismatch. In Terminal 1, copy the `◉ reachable at ws://X.Y.Z.W:8080/ws` line that hakam-node prints on startup. Restart Terminal 2 with `VITE_HAKAM_WS_URL=ws://X.Y.Z.W:8080/ws npm run dev`. Then hard-reload the browser. |
| **HUD topology lights up but the left card stays at 0** | The page was loaded *before* hakam-node bound `:8080`. The WS reconnected mid-attack so the first BLOCKs were missed. Hard-reload the browser, then restart `demo-cycle.sh`. |
| **PROCESS_TELEMETRY shows nc events, but THREATS_NEUTRALIZED stays at 0** | The no-op TCP listener on `10.99.0.10:80` isn't running, so attacker SYNs get RST'd and the HTTP payload never goes on the wire. Check `ss -tln \| grep 10.99.0.10:80` — if nothing, run `./scripts/setup-demo.sh` again, or `sudo python3 scripts/target-listener.py &` manually. Log lives at `/tmp/hakam-target-listener.log`. |
| `[-32098] machine not found: 'hakam'` | The OrbStack VM doesn't exist yet. Run `orb create ubuntu hakam` on the Mac (see §5 "Create the OrbStack VM"), then re-try `orb -m hakam`. |
| `cargo: command not found` (in VM) | `source ~/.cargo/env`, or open a fresh shell |
| `error: no such command: 'xtask'` | You're outside the project. `cd ~/hakam` first. |
| `failed to attach XDP to dummy0 — is the interface UP?` | Run `./scripts/setup-demo.sh` again. |
| Attacks don't show up after a few shots | Source IPs got auto-blocked. Run `clear` in the hakam CLI, or wait 120 s for TTL expiry. |
| `nc -s 10.99.1.x` fails | Run `./scripts/setup-demo.sh` to re-add the IP aliases. |
| Spoofed source packets dropped silently | `./scripts/setup-demo.sh` already relaxes `rp_filter`. If not, run `sudo sysctl -w net.ipv4.conf.dummy0.rp_filter=2` |
| Q&A interrupts the cycle mid-phase | At the `hakam@kernel ▸` prompt, type `clear` between phases. Or run `demo-cycle.sh --manual` so each phase waits for ENTER. Live keys: space=pause, n=next, r=restart, 0–5=jump. |
| **Everything is on fire** | Stop apologising and play the fallback. See `demo/README.md` for the screencast playback runbook. |

> **First-step preflight, always:** run `./scripts/preflight.sh` from the Mac.
> It walks every common failure point (VM up, dummy0 up, kernel module loaded,
> build artifacts present, port 8080, Mac↔VM reachability) and prints a single
> PASS/FAIL verdict. Run it ~60 s before going on stage.

---

## 7 · Shutting down cleanly

In **Terminal 1** type `quit` (or `q`). That detaches XDP + TC + tracepoint and
exits. Then close the other terminals in any order.

If `hakam-node` ever crashes without `quit`, the next `cargo xtask run` will
clean up stale hooks automatically — re-running it is always safe.

---

## 8 · The big picture

```
┌─────────────────────────┐                    ┌──────────────────────────────┐
│ Mac (your laptop)       │                    │ Linux VM (OrbStack: hakam) │
│                         │                    │                              │
│  ~/hakam                │ ◀── same files ──▶ │ /Users/omaralzhrani/hakam    │
│  (single source of      │   (OrbStack auto-  │                              │
│   truth — git repo)     │    mount of Mac    │  cargo xtask run             │
│                         │    home in VM)     │   ↓                          │
│  npm run dev            │                    │  hakam-node binary         │
│   ↓                     │                    │   ↓                          │
│  http://localhost:5173  │ ◀──── WebSocket ──▶│  XDP + TC + Tracepoint       │
│  (browser HUD)          │       :8080/ws     │   bound to dummy0            │
│                         │                    │                              │
└─────────────────────────┘                    └──────────────────────────────┘
                                                          ▲
                                                          │ HTTP attacks
                                                          │
                                                ./scripts/demo-cycle.sh
                                                ./scripts/seclist-attack.sh
```

**Edit code on Mac, see it in VM instantly. No sync, no copy, no git pull.**
