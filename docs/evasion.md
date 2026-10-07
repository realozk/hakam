# Hakam — Evasion Analysis

This table records selected payload examples for the current signature matcher.
It is a coverage reference, not an attack-detection rate for real traffic. Use
`cargo test -p hakam-node --test dpi_matcher` for userspace checks and
`./scripts/evasion-test.sh` for a live Linux exercise after signature changes.

## Detection pipeline

1. XDP samples the first 64 available bytes from eligible TCP segments.
2. Userspace orders retained samples by TCP sequence number, within a 256-byte per-flow cap.
3. The HTTP gate requires a recognized request method at the start of the view.
4. Aho-Corasick scans with ASCII case folding; a single URL-decoding fallback runs if the raw scan misses.

A match attempts to install a source block for subsequent packets. The initial
sampled request can already have reached the application.

---

## Result table

| # | Result | Technique | Mutation | Why |
|--:|:------:|-----------|----------|-----|
| 1 | **HIT** | Case fold | `union select 1,2` (lowercase) | ASCII case-folded to `UNION SELECT` — matches |
| 2 | **HIT** | Case fold | `UnIoN SeLeCt 1` (mixed case) | ASCII case-folded to `UNION SELECT` — matches |
| 3 | **HIT** | Case fold | `<script>alert(1)` (lowercase) | ASCII case-folded to `<SCRIPT>` — matches |
| 4 | **HIT** | Case fold | `<sCrIpT>alert(1)` (mixed case) | ASCII case-folded to `<SCRIPT>` — matches |
| 5 | **HIT** | Case fold | `javascript:alert(1)` (lowercase) | ASCII case-folded to `JAVASCRIPT:` — matches |
| 6 | **HIT** | Case fold | `' or '1'='1` (lowercase) | ASCII case-folded to `' OR '1'='1` — matches |
| 7 | **HIT** | Case fold | `;whoami` (lowercase) | ASCII case-folded to `;WHOAMI` — matches |
| 8 | **HIT** | URL-enc LFI | `..%2F..%2Fetc%2Fpasswd` | `..%2F` is an explicit signature |
| 9 | **HIT** | URL-enc LFI | `%2E%2E%2Fetc%2Fpasswd` | `%2E%2E%2F` is an explicit signature |
| 10 | **HIT** | URL-enc LFI | `%252E%252Eetc/passwd` (double-encoded) | `%252E%252E` is an explicit signature |
| 11 | **HIT** | URL encode | `UNION%20SELECT%201` (space → `%20`) | Single-pass URL decode → space → `UNION SELECT` matches |
| 12 | **HIT** | URL encode | `%27%20OR%20%271%27%3D%271` (full SQLi) | Single-pass URL decode → `' OR '1'='1` matches |
| 13 | **HIT** | URL encode | `%3Cscript%3Ealert(1)` | `<script>` is encoded, but `ALERT(1)` is its own signature — caught on the unencoded tail |
| 14 | MISS | URL encode | `UNION%2520SELECT` (double-encoded space) | `%2520` → `%20` after one decode; we deliberately do not decode a second time |
| 15 | MISS | SQL comment | `UNION/**/SELECT 1` | Comment breaks the space; `UNION/**/SELECT` ≠ `UNION SELECT` |
| 16 | MISS | SQL comment | `UN/*x*/ION SELECT 1` | Comment splits `UNION`; pattern never appears |
| 17 | MISS | SQL comment | `' OR/**/1=1--` | Comment breaks `' OR '`; tick-space pair missing |
| 18 | MISS | Whitespace | `UNION\tSELECT` (tab) | Tab ≠ space in pattern |
| 19 | MISS | Whitespace | `UNION\nSELECT` (newline) | Newline ≠ space in pattern |
| 20 | MISS | Whitespace | `UNION  SELECT` (double space) | Two spaces ≠ one space in pattern |
| 21 | MISS | Null byte | `UNION\x00SELECT` | Null byte splits the string; substring match fails |
| 22 | MISS | Null byte | `<SCR\x00IPT>` | Null byte inside `<SCRIPT>` breaks match |
| 23 | MISS | Payload offset | Attack at byte ≥ 64 of one segment (long path prefix) | The 64-byte sample window truncates within a single segment; some split patterns can match retained samples, but a single oversized segment does not |
| 24 | MISS | HTTP method | `PROPFIND /?x=UNION SELECT` | `PROPFIND` not in `is_http_request()` whitelist |
| 25 | MISS | HTTP method | `MKCOL /?x=<script>` | `MKCOL` not whitelisted |
| 26 | **HIT** | Plus encode | `UNION+SELECT+1` (+ for space) | form-urlencoded `+` → space rewrite in decode pass → matches |
| 27 | **HIT** | Plus encode | `UNION%2BSELECT` (encoded plus) | `%2B` → `+` (percent) → space (form) → `UNION SELECT` matches |
| 28 | MISS | Unicode | `ｕｎｉｏｎ ｓｅｌｅｃｔ` (fullwidth) | ASCII case folding does not normalize fullwidth characters |
| 29 | MISS | HTML entity | `&#85;NION SELECT` (`U` encoded) | No HTML entity decode |
| 30 | MISS | Hex SQL | `0x554e494f4e2053454c454354` | Hex literal for `UNION SELECT`; no hex decode |

**Score: 15 HIT / 15 MISS**. These outcomes describe this selected set only; they are not a general detection percentage.

---

## Known gaps

### 1. Single-pass URL decoding only
The matcher runs once on the raw bytes, then once more on a single-pass URL-decoded view (`%XX` → byte, `+` → space). This catches the common scanner mutations: `UNION%20SELECT`, `%27%20OR…`, `UNION+SELECT`, `UNION%2BSELECT`. **Gap:** double-encoded payloads such as `UNION%2520SELECT` only unwind to `UNION%20SELECT` after one decode and still miss — recursive decoding is deliberately not implemented, and additional normalization would require separate coverage and false-positive evaluation.

### 2. 64-byte capture window
The eBPF program samples only the first 64 bytes of each TCP segment. Attacks that begin after byte 64 — via long path prefixes or in POST bodies — are invisible to the inspector. For a typical `GET /?payload=...`, the payload starts around byte 6, leaving 58 bytes of usable inspection window.

### 3. Partial sample reassembly
Userspace orders retained samples from a four-tuple flow by raw TCP sequence
number and caps the buffer at 256 bytes. Duplicate sequence keys are ignored.
The implementation does not recover unsampled bytes, validate sequence gaps or
overlaps, reconcile conflicting retransmissions, or handle sequence wraparound.
A split pattern can match when all required bytes are retained, but this is not
complete TCP stream reconstruction.

### 4. ASCII case-insensitive only
The Aho-Corasick automaton folds ASCII case (A–Z ⇔ a–z). Unicode homoglyphs, fullwidth characters, and HTML/XML entities are not normalised, so a pattern relying on that normalization may be missed.

### 5. Fixed whitespace in patterns
Patterns are literal strings — `UNION SELECT` requires exactly one space. Tabs, newlines, double spaces, or SQL comments (`/**/`) between tokens all evade.

### 6. Non-standard HTTP methods
Only nine HTTP methods are recognised as HTTP traffic. WebDAV verbs (`PROPFIND`, `MKCOL`, `LOCK`) or custom methods bypass the `is_http_request()` guard and receive no DPI at all.

---

## Interpreting coverage

The 202-pattern corpus covers literal tokens from 13 attack families. It can
recognize the examples above when the relevant bytes are visible and the HTTP
gate passes. Patterns can also occur in legitimate content; a match is not proof
of exploitability or malicious intent.

Double encoding, unrecognized methods, unsupported normalization, encryption,
and the sampling window can all leave attacks undetected. A missed example in
this table does not establish that every related variation will miss: another
signature may match a different part of a request.

## Try selected examples

With the demo setup and node running on Linux:

```bash
printf 'GET /?id=union select user,pass from users HTTP/1.1\r\nHost: 10.99.0.10\r\n\r\n' \
  | nc -s 10.99.1.11 -w 1 10.99.0.10 80

printf 'GET /..%%2F..%%2Fetc%%2Fpasswd HTTP/1.1\r\nHost: 10.99.0.10\r\n\r\n' \
  | nc -s 10.99.1.12 -w 1 10.99.0.10 80
```

Inspect the node console or WebSocket for the category and pattern. Clear
existing source blocks before repeating. Packet segmentation and the 64-byte
sampling gate can affect a live result even when a userspace matcher test passes.
