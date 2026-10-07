# Recording a terminal demo

This directory documents how to record and replay Hakam's CLI. No terminal
recording is currently included.

## Prepare

Follow the [setup guide](../start_guide.md), verify the node's hook status, and
run a short traffic sample. Use the same checkout for the node and scripts so
the recording matches the current implementation.

## Record

With asciinema installed, run from the repository root on Linux:

```bash
./scripts/setup-demo.sh
asciinema rec demo/hakam-cycle.cast \
  --title "Hakam CLI demo" \
  --command 'cargo xtask run --iface lo --mode skb'
```

In a second Linux terminal:

```bash
./scripts/demo-cycle.sh
```

One cycle takes roughly four minutes. Record one or two cycles. Use `stats`,
`list`, and `rules` in the node console to show counters and policy state. Stop
the traffic driver, then type `quit` in the node console to finish the recording.
Use a readable terminal size, for example 120 columns by 40 rows.

## Replay

```bash
asciinema play demo/hakam-cycle.cast
asciinema play -s 1.5 demo/hakam-cycle.cast
```

## Share

Label the demo as a recording and state the checkout, kernel, interface, and XDP
mode used. Include a detection, actual drop counters, and manual release. A
signature event does not prove the initial request was prevented or the target
was compromised.

Re-record when hook behavior, console output, signatures, or the demo sequence
changes. Link the recording from the main README once it is available.
