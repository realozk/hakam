//! End-to-end tests for the DPI matcher pipeline.
//!
//! Each test mirrors a row in `docs/evasion.md`. The HIT block enforces the
//! guarantees we make on stage; the MISS block locks down the documented
//! gaps so any regression that secretly closes them shows up in CI (and so
//! the docs stay honest as the matcher evolves).

use hakam_node::signatures::{is_http_request, match_payload};

fn hits(payload: &str) -> bool {
    match_payload(payload.as_bytes()).is_some()
}

fn category(payload: &str) -> Option<&'static str> {
    match_payload(payload.as_bytes()).map(|s| s.category)
}

// ── HIT rows from docs/evasion.md ────────────────────────────────────────────
// Each #[test] name encodes the table row it pins.

#[test]
fn hit_01_lowercase_sqli_union_select() {
    assert_eq!(category("GET /?x=union select 1,2 HTTP/1.1"), Some("SQLi"));
}

#[test]
fn hit_02_mixed_case_sqli() {
    assert_eq!(category("GET /?x=UnIoN SeLeCt 1 HTTP/1.1"), Some("SQLi"));
}

#[test]
fn hit_03_lowercase_xss_script_tag() {
    assert_eq!(category("GET /?x=<script>alert(1) HTTP/1.1"), Some("XSS"));
}

#[test]
fn hit_04_mixed_case_xss() {
    assert_eq!(category("GET /?x=<sCrIpT>alert(1) HTTP/1.1"), Some("XSS"));
}

#[test]
fn hit_05_lowercase_javascript_url() {
    assert_eq!(category("GET /?u=javascript:alert(1) HTTP/1.1"), Some("XSS"));
}

#[test]
fn hit_06_lowercase_sqli_or_truism() {
    assert_eq!(category("GET /?x=' or '1'='1 HTTP/1.1"), Some("SQLi"));
}

#[test]
fn hit_07_lowercase_rce_whoami() {
    assert_eq!(category("GET /?cmd=;whoami HTTP/1.1"), Some("RCE"));
}

#[test]
fn hit_08_url_encoded_lfi_slash_2f() {
    assert_eq!(category("GET /..%2F..%2Fetc%2Fpasswd HTTP/1.1"), Some("LFI"));
}

#[test]
fn hit_09_url_encoded_lfi_dot_dot() {
    assert_eq!(category("GET /%2E%2E%2Fetc%2Fpasswd HTTP/1.1"), Some("LFI"));
}

#[test]
fn hit_10_double_url_encoded_lfi() {
    assert_eq!(category("GET /%252E%252Eetc/passwd HTTP/1.1"), Some("LFI"));
}

// ── MISS rows — documented gaps ──────────────────────────────────────────────
// These tests pin the gaps listed in docs/evasion.md. Flipping any of them
// to HIT means a real behaviour change — update both the test and the doc.

#[test]
fn hit_11_url_encoded_space_in_sqli() {
    // After single-pass URL decode, %20 becomes space → UNION SELECT matches.
    assert_eq!(category("GET /?x=UNION%20SELECT%201 HTTP/1.1"), Some("SQLi"));
}

#[test]
fn hit_12_fully_url_encoded_sqli() {
    assert_eq!(category("GET /?x=%27%20OR%20%271%27%3D%271 HTTP/1.1"), Some("SQLi"));
}

#[test]
fn miss_14_double_url_encoded_space() {
    // %2520 decodes once to %20, not to a space — single-pass is deliberate.
    assert!(!hits("GET /?x=UNION%2520SELECT HTTP/1.1"));
}

#[test]
fn hit_13_url_encoded_script_still_caught_via_alert() {
    // <script> is URL-encoded as %3Cscript%3E, but the payload still contains
    // the literal `alert(1)` substring — and that is its own signature.
    // (docs/evasion.md row 13 originally listed this as a MISS — it isn't.)
    assert_eq!(category("GET /?x=%3Cscript%3Ealert(1) HTTP/1.1"), Some("XSS"));
}

#[test]
fn miss_15_sql_comment_breaks_pattern() {
    assert!(!hits("GET /?x=UNION/**/SELECT 1 HTTP/1.1"));
}

#[test]
fn miss_18_tab_instead_of_space() {
    assert!(!hits("GET /?x=UNION\tSELECT HTTP/1.1"));
}

#[test]
fn miss_23_attack_beyond_capture_window() {
    // PAYLOAD_LEN = 64. A long path prefix pushes the attack past byte 64.
    let long_prefix = "GET /aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/?x=UNION SELECT HTTP/1.1";
    let truncated = &long_prefix.as_bytes()[..hakam_common::PAYLOAD_LEN];
    assert!(match_payload(truncated).is_none());
}

#[test]
fn miss_24_propfind_bypasses_http_gate() {
    assert!(!hits("PROPFIND /?x=UNION SELECT HTTP/1.1"));
}

#[test]
fn hit_26_plus_decoded_to_space() {
    // form-urlencoded `+` → space rewrite is part of url_decoded.
    assert_eq!(category("GET /?x=UNION+SELECT+1 HTTP/1.1"), Some("SQLi"));
}

#[test]
fn hit_27_encoded_plus_chains_to_space() {
    // %2B → '+' (percent decode), then '+' → space (form decode) → UNION SELECT.
    assert_eq!(category("GET /?x=UNION%2BSELECT HTTP/1.1"), Some("SQLi"));
}

// ── HTTP method gate ─────────────────────────────────────────────────────────

#[test]
fn requires_http_method_prefix() {
    // Raw payload with no method — must not even reach the matcher.
    assert!(!is_http_request(b"UNION SELECT 1,2 FROM users"));
    assert!(match_payload(b"UNION SELECT 1,2 FROM users").is_none());
}

#[test]
fn accepts_every_recognised_method() {
    for method in [
        "GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE",
    ] {
        let line = format!("{method} /?x=union select HTTP/1.1");
        assert!(
            is_http_request(line.as_bytes()),
            "method '{method}' must be recognised by the HTTP gate",
        );
    }
}

#[test]
fn empty_payload_returns_none() {
    assert!(!is_http_request(b""));
    assert!(match_payload(b"").is_none());
}

#[test]
fn http_request_with_no_attack_returns_none() {
    assert!(match_payload(b"GET /index.html HTTP/1.1\r\nHost: example.com").is_none());
}

// ── Smoke coverage across the corpus ─────────────────────────────────────────

#[test]
fn each_declared_category_has_a_matchable_signature() {
    use hakam_node::signatures::{CATEGORIES, SIGNATURES};
    for cat in CATEGORIES {
        let sample = SIGNATURES
            .iter()
            .find(|s| s.category == *cat)
            .unwrap_or_else(|| panic!("CATEGORIES lists '{cat}' but SIGNATURES has none"));
        let payload = format!("GET /?x={} HTTP/1.1", sample.pattern);
        assert_eq!(
            category(&payload),
            Some(*cat),
            "category '{}' first signature '{}' did not round-trip through match_payload",
            cat,
            sample.pattern,
        );
    }
}
