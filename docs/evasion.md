# Hakam — Evasion Analysis

> Results derived from static analysis of `hakam-node/src/main.rs` and `hakam-node/src/signatures.rs`, verified by `scripts/evasion-test.sh`. Re-run the script after any signature change.

**Detection pipeline recap:**
1. eBPF captures the **first 64 bytes** of each TCP segment's payload
2. `signatures::is_http_request()` requires the payload to start with a standard HTTP method (`GET`, `POST`, `PUT`, `HEAD`, `DELETE`, `OPTIONS`, `PATCH`, `CONNECT`, `TRACE`)
3. The full corpus is compiled once into an **Aho-Corasick automaton** (built lazily via `signatures::matcher()`), case-insensitive on ASCII
4. The automaton runs **one single-pass scan** over the raw payload bytes — no per-packet allocation, leftmost-first match wins

---

## Result table

| # | Result | Technique | Mutation | Why |
|--:|:------:|-----------|----------|-----|
| 1 | **HIT** | Case fold | `union select 1,2` (lowercase) | Uppercased to `UNION SELECT` — matches |
| 2 | **HIT** | Case fold | `UnIoN SeLeCt 1` (mixed case) | Uppercased to `UNION SELECT` — matches |
| 3 | **HIT** | Case fold | `<script>alert(1)` (lowercase) | Uppercased to `<SCRIPT>` — matches |
| 4 | **HIT** | Case fold | `<sCrIpT>alert(1)` (mixed case) | Uppercased to `<SCRIPT>` — matches |
| 5 | **HIT** | Case fold | `javascript:alert(1)` (lowercase) | Uppercased to `JAVASCRIPT:` — matches |
| 6 | **HIT** | Case fold | `' or '1'='1` (lowercase) | Uppercased to `' OR '1'='1` — matches |
| 7 | **HIT** | Case fold | `;whoami` (lowercase) | Uppercased to `;WHOAMI` — matches |
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
| 23 | MISS | Payload offset | Attack at byte ≥ 64 of one segment (long path prefix) | The 64-byte sample window truncates within a single segment; multi-segment attacks recover via reassembly, but a single oversized segment does not |
| 24 | MISS | HTTP method | `PROPFIND /?x=UNION SELECT` | `PROPFIND` not in `is_http_request()` whitelist |
| 25 | MISS | HTTP method | `MKCOL /?x=<script>` | `MKCOL` not whitelisted |
| 26 | **HIT** | Plus encode | `UNION+SELECT+1` (+ for space) | form-urlencoded `+` → space rewrite in decode pass → matches |
| 27 | **HIT** | Plus encode | `UNION%2BSELECT` (encoded plus) | `%2B` → `+` (percent) → space (form) → `UNION SELECT` matches |
| 28 | MISS | Unicode | `ｕｎｉｏｎ ｓｅｌｅｃｔ` (fullwidth) | `to_ascii_uppercase()` skips non-ASCII; stays fullwidth |
| 29 | MISS | HTML entity | `&#85;NION SELECT` (`U` encoded) | No HTML entity decode |
| 30 | MISS | Hex SQL | `0x554e494f4e2053454c454354` | Hex literal for `UNION SELECT`; no hex decode |

**Score: 15 HIT / 15 MISS** — honest, no cherry-picking. (Test enforcement: `cargo test -p hakam-node --test dpi_matcher` pins each row.)

---

## Known gaps

### 1. Single-pass URL decoding only
The matcher runs once on the raw bytes, then once more on a single-pass URL-decoded view (`%XX` → byte, `+` → space). This catches the common scanner mutations: `UNION%20SELECT`, `%27%20OR…`, `UNION+SELECT`, `UNION%2BSELECT`. **Gap:** double-encoded payloads such as `UNION%2520SELECT` only unwind to `UNION%20SELECT` after one decode and still miss — recursive decoding is deliberately not implemented, since it amplifies false-positive surface on legitimate URLs.

### 2. 64-byte capture window
The eBPF program samples only the first 64 bytes of each TCP segment. Attacks that begin after byte 64 — via long path prefixes or in POST bodies — are invisible to the inspector. For a typical `GET /?payload=...`, the payload starts around byte 6, leaving 58 bytes of usable inspection window.

### 3. Userspace reassembly — sequence-ordered (Phase 2 #7)
Userspace stitches segments from the same 4-tuple flow (`src_addr`, `src_port`, `dst_addr`, `dst_port`) into a per-flow buffer capped at 256 bytes, ordered by **TCP sequence number** (the kernel stamps each sampled segment's `seq`). The split-attack evasion is therefore closed for **both in-order and out-of-order delivery**, and retransmits are deduped by sequence. **Residual gaps:** (a) only sampled segments participate — a payload split across a sub-64-byte segment (which isn't sampled) leaves a hole; (b) sequence-number wraparound mid-flow is not handled (segments are ordered by raw `u32` seq — astronomically unlikely within a ≤256-byte window, documented not handled).

### 4. ASCII case-insensitive only
The Aho-Corasick automaton folds ASCII case (A–Z ⇔ a–z). Unicode homoglyphs, fullwidth characters, and HTML/XML entities are not normalised, so any attack using them passes undetected.

### 5. Fixed whitespace in patterns
Patterns are literal strings — `UNION SELECT` requires exactly one space. Tabs, newlines, double spaces, or SQL comments (`/**/`) between tokens all evade.

### 6. Non-standard HTTP methods
Only nine HTTP methods are recognised as HTTP traffic. WebDAV verbs (`PROPFIND`, `MKCOL`, `LOCK`) or custom methods bypass the `is_http_request()` guard and receive no DPI at all.

---

## What Hakam is designed to stop

Automated scanner traffic (SQLmap, XSStrike, nuclei templates, Metasploit HTTP modules) almost universally uses verbatim, unencoded payloads in standard GET/POST requests. The 203-signature corpus is calibrated for this threat model: high-volume, low-sophistication, automated attacks that make up the vast majority of web-facing malicious traffic.

A determined attacker who reads this document can bypass Hakam with URL encoding alone. That is an honest limitation of signature-based inline DPI at the kernel layer.

---

## Live demo path — "we catch this even when mutated"

**Mutation: lowercase `union select`**

```bash
# On the VM, with hakam-node running:
{
  printf 'GET /?id=union select user,pass from users HTTP/1.1\r\nHost: 10.99.0.10\r\n\r\n'
} | nc -s 10.99.1.11 -w 1 10.99.0.10 80
```

The lowercase `union select` hits the Aho-Corasick automaton, which folds case as it scans — the firewall blocks it. Walk the audience through the pipeline: *"The matcher is case-insensitive at the automaton level, so case is not an evasion surface."*

**Bonus: URL-encoded path traversal still caught**

```bash
{
  printf 'GET /..%%2F..%%2Fetc%%2Fpasswd HTTP/1.1\r\nHost: 10.99.0.10\r\n\r\n'
} | nc -s 10.99.1.12 -w 1 10.99.0.10 80
```

`..%2F` is an explicit signature. The punchline: *"We don't just catch the raw `../` — we hardcoded the common URL-encoded forms too. Scanners rotate through these variants; we cover them all."*

---

## Q&A answer — rehearse under 30 seconds

> **Q: I can bypass your signatures with URL encoding. Isn't that trivial?**

"Single-pass URL decoding runs as a fallback when the raw match misses — `%XX` gets resolved and `+` is treated as space. So `UNION%20SELECT`, `UNION+SELECT`, even `UNION%2BSELECT` all match. What we don't do is recursive decoding: a payload double-encoded as `UNION%2520SELECT` slips through, and that's the trade-off — recursive decode amplifies false-positive surface on legitimate URLs.
Add in case folding (handled by the Aho-Corasick automaton itself) and the explicit LFI variants in the corpus, and the matcher covers the mutation classes that automated scanners actually rotate through."

*(~25 seconds)*
