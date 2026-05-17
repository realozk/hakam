# Hakam — Evasion Analysis

> Results derived from static analysis of `hakam-node/src/main.rs` and `hakam-node/src/signatures.rs`, verified by `scripts/evasion-test.sh`. Re-run the script after any signature change.

**Detection pipeline recap:**
1. eBPF captures the **first 64 bytes** of each TCP segment's payload
2. `is_http_request()` requires the payload to start with a standard HTTP method (`GET`, `POST`, `PUT`, `HEAD`, `DELETE`, `OPTIONS`, `PATCH`, `CONNECT`, `TRACE`)
3. Payload is converted to **ASCII uppercase only** (`to_ascii_uppercase()`)
4. Each of 203 signatures is matched as a **case-insensitive substring** against the uppercased text

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
| 11 | MISS | URL encode | `UNION%20SELECT%201` (space → `%20`) | `%20` ≠ space; no URL decode step |
| 12 | MISS | URL encode | `%27%20OR%20%271%27%3D%271` (full SQLi) | No URL decode; pattern not visible |
| 13 | MISS | URL encode | `%3Cscript%3Ealert(1)` | `<` and `>` encoded; no decode |
| 14 | MISS | URL encode | `UNION%2520SELECT` (double-encoded space) | `%2520` → `%20` after one decode, not caught |
| 15 | MISS | SQL comment | `UNION/**/SELECT 1` | Comment breaks the space; `UNION/**/SELECT` ≠ `UNION SELECT` |
| 16 | MISS | SQL comment | `UN/*x*/ION SELECT 1` | Comment splits `UNION`; pattern never appears |
| 17 | MISS | SQL comment | `' OR/**/1=1--` | Comment breaks `' OR '`; tick-space pair missing |
| 18 | MISS | Whitespace | `UNION\tSELECT` (tab) | Tab ≠ space in pattern |
| 19 | MISS | Whitespace | `UNION\nSELECT` (newline) | Newline ≠ space in pattern |
| 20 | MISS | Whitespace | `UNION  SELECT` (double space) | Two spaces ≠ one space in pattern |
| 21 | MISS | Null byte | `UNION\x00SELECT` | Null byte splits the string; substring match fails |
| 22 | MISS | Null byte | `<SCR\x00IPT>` | Null byte inside `<SCRIPT>` breaks match |
| 23 | MISS | Payload offset | Attack at byte ≥ 64 (long path prefix) | Capture window is 64 bytes; tail is never seen |
| 24 | MISS | HTTP method | `PROPFIND /?x=UNION SELECT` | `PROPFIND` not in `is_http_request()` whitelist |
| 25 | MISS | HTTP method | `MKCOL /?x=<script>` | `MKCOL` not whitelisted |
| 26 | MISS | Plus encode | `UNION+SELECT+1` (+ for space) | `+` ≠ space in pattern; no query-string decode |
| 27 | MISS | Plus encode | `UNION%2BSELECT` (encoded plus) | Double-indirection; no decode |
| 28 | MISS | Unicode | `ｕｎｉｏｎ ｓｅｌｅｃｔ` (fullwidth) | `to_ascii_uppercase()` skips non-ASCII; stays fullwidth |
| 29 | MISS | HTML entity | `&#85;NION SELECT` (`U` encoded) | No HTML entity decode |
| 30 | MISS | Hex SQL | `0x554e494f4e2053454c454354` | Hex literal for `UNION SELECT`; no hex decode |

**Score: 10 HIT / 20 MISS** — honest, no cherry-picking.

---

## Known gaps

### 1. No URL decoding
The most common evasion class. Any attack character URL-encoded (e.g., `%27` for `'`, `%20` for space) passes through the DPI undetected. **Exception:** LFI path-traversal variants — `..%2F`, `%2E%2E%2F`, and `%252E%252E` are explicit signatures, so those specific encodings are blocked.

### 2. 64-byte capture window
The eBPF program samples only the first 64 bytes of each TCP segment. Attacks that begin after byte 64 — via long path prefixes or in POST bodies — are invisible to the inspector. For a typical `GET /?payload=...`, the payload starts around byte 6, leaving 58 bytes of usable inspection window.

### 3. Single-segment only
Only the first TCP segment is inspected. A slow-loris or hand-crafted multi-segment sender can split the attack string across segment boundaries and evade every signature.

### 4. ASCII uppercase only
`to_ascii_uppercase()` normalises A–Z only. Unicode homoglyphs, fullwidth characters, and HTML/XML entities are not normalised, so any attack using them passes undetected.

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

The lowercase `union select` is uppercased to `UNION SELECT` before matching — the firewall blocks it. Walk the audience through the pipeline: *"We uppercase everything before we match, so case is not an evasion surface."*

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

"Yes, URL encoding of arbitrary attack characters defeats our DPI — we don't decode before matching. That's a real gap and we're not hiding it.
What we do cover: case mutations across all 203 signatures, and the common URL-encoded forms of LFI path traversal, which scanners rotate through constantly.
The use case we target is automated scanner traffic — SQLmap, Metasploit modules, nuclei templates. Those tools almost always use verbatim payloads. A human attacker who reads this table can bypass us; a scanner that fires textbook payloads cannot."

*(~25 seconds)*
