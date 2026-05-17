# Hakam — screencast fallback

> **Purpose.** When the live demo fails on stage — VM crashed, mDNS broke, the projector hates you — play the recording in this folder instead. Zero apologies; the recording matches the live narration beat-for-beat so you can keep talking.
>
> **Two recordings, two scopes.** The kernel-side terminal goes into asciinema (perfect for code-heavy talks; one-line replay). The HUD goes into a screen recording (OBS / QuickTime). You play both side-by-side or pick one.

---

## What lives here

| File | Side | Tool | Notes |
|---|---|---|---|
| `hakam-cycle.cast`        | VM terminal | asciinema | Full `hakam-node` boot + 2-cycle `demo-cycle.sh` run. Plays with `asciinema play`. |
| `hakam-hud.mp4`           | Mac browser | OBS / QuickTime | 1080p screen recording of the HUD synced with the asciinema cast. |
| `hakam-hud.thumbnail.png` | Mac browser | screenshot     | Used in the README — pulled from the recording. |

**Status:** none committed yet. Recording is the operator's job (needs your screen + your VM + your monitor); this README is the standard operating procedure.

---

## Recording the kernel side (asciinema)

Inside the VM:

```bash
sudo apt install asciinema
cd ~/defthon
./scripts/setup-demo.sh

# Start a recording. Quit hakam-node (`q`) and demo-cycle (Ctrl-C) when
# you've covered enough material — the cast stops on shell exit.
asciinema rec demo/hakam-cycle.cast \
  --title "Hakam — kernel cycle" \
  --command 'cargo xtask run --iface lo --mode skb'

# In another VM terminal, fire two cycles' worth of demo:
./scripts/demo-cycle.sh
# Ctrl-C after ~3 cycles (~5–6 minutes). Exit hakam-node with `q`.
```

Replay during a talk:

```bash
# At normal speed
asciinema play demo/hakam-cycle.cast

# 1.5× speed for time-pressed slots
asciinema play -s 1.5 demo/hakam-cycle.cast

# Idle compression — collapses long countdowns to ≤1 s gaps
asciinema play -i 1 demo/hakam-cycle.cast
```

Tips:
- **Resize the terminal to ~120×40** before recording — the cast file remembers terminal size, so a too-small terminal at record time means a tiny replay window.
- **Disable the prompt's per-second timestamp** if your shell injects one — it adds a lot of redraw chatter to the cast.
- **Don't background hakam-node**; let it run in the foreground of the recorded shell so the operator playbook output (`◉ XDP armed…`) is captured.

---

## Recording the HUD (OBS / QuickTime)

Mac side, with hakam-node already running in the VM and `npm run dev` already serving the HUD on `http://localhost:5173`:

**OBS (recommended):**
- Source: Display Capture (or Window Capture on the browser)
- Output: 1920×1080, 30 fps, MP4 (H.264) — keeps it small and Universal Player-friendly
- Audio: off (you're narrating live, not in the recording)
- Save to `demo/hakam-hud.mp4`

**QuickTime fallback:**
- File → New Screen Recording → drag the selection box around the browser tab
- Stop after ~3 cycles
- Export → 1080p → save as `demo/hakam-hud.mp4`

Sync notes:
- Hit *record* on both at the same time. Start hakam-node afterwards so the recordings begin from a calm "kernel link · reconnecting" state and the audience watches the link come up live.
- Trim the leading and trailing seconds in post — both files should start with the *first* `BLOCK` for tight edit points.

---

## Pulling the thumbnail for the README

After recording the HUD video, snap one frame from the most-cinematic moment (peak assault with multiple bars + intercept splash):

```bash
# Mac. Snip the frame and crop to a useful aspect ratio.
ffmpeg -i demo/hakam-hud.mp4 -ss 00:01:42 -frames:v 1 \
       -vf "crop=in_w:in_h-50:0:25" demo/hakam-hud.thumbnail.png
```

Adjust `-ss` to the timestamp where the screen looks best.

---

## Playing the fallback during a presentation

The "everything is on fire" runbook:

1. **Don't stop talking.** Apologise once, max — "let's roll the recording" — and keep narrating from your slide deck.
2. **Open both files in side-by-side windows** (asciinema in a terminal at 120×40, the HUD video full-screen on the projector).
3. Start the HUD video first. Wait for the kernel-link chip to flip green. Then start the asciinema replay.
4. Time the narration to the **`PHASE N`** banners in the asciinema cast — those are your synchronization points, not the wall clock.
5. After 1.5 cycles you've made the point. Cut to the next slide.

If you only have time for one recording, pick the **HUD video** — it carries more visual information per second than the asciinema cast.

---

## Anti-checklist (what NOT to do)

- **Do NOT play the recording silently** in the background while talking about something else. Audiences spot the disconnect immediately and assume the live demo never worked.
- **Do NOT dub the recording with a voice-over.** A live narration over a recorded demo is the strongest fallback — the audience knows it's the recording, but they trust *you* are real.
- **Do NOT commit raw `.mov`** files. QuickTime exports are 4× the size of OBS H.264 for the same resolution. Always re-encode to MP4 before committing.

---

## Updating these files

Re-record after any change that affects the on-screen output:

- New signature added to `hakam-node/src/signatures.rs` (a new family bar may appear)
- HUD layout changed (any `hakam-ui/src/components/*.tsx` edit)
- `demo-cycle.sh` phase timing or order changed
- `hakam-node` boot output changed (new prominent line, e.g. the `reachable at` line added in Phase 4)

Commit a new cast/video; **do not amend the old one.** Git history of fallback recordings is its own audit trail.
