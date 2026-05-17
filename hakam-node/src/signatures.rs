// DPI signature corpus for the Hakam HTTP-anchored payload inspector.
//
// Each `Sig` entry is a substring matched (case-insensitive) against the
// uppercased payload AFTER an HTTP method prefix has been confirmed.
// The kernel only samples the first PAYLOAD_LEN bytes of TCP segments, so
// patterns are kept short and characteristic of well-known attack classes.

#[derive(Copy, Clone)]
pub struct Sig {
    /// Uppercased needle to look for in the payload.
    pub pattern: &'static str,
    /// Top-level family (SQLi, XSS, RCE, …) — used for CLI/UI labels.
    pub category: &'static str,
    /// Kernel action label sent on detection.
    pub action: &'static str,
    /// Severity for UI / log colouring.
    pub severity: &'static str,
}

const fn sig(pattern: &'static str, category: &'static str, action: &'static str, severity: &'static str) -> Sig {
    Sig { pattern, category, action, severity }
}

pub const SIGNATURES: &[Sig] = &[
    // ── SQL injection (≈30) ──────────────────────────────────────────────────
    sig("' OR '",                "SQLi",       "XDP_DROP", "critical"),
    sig("' OR 1=1",              "SQLi",       "XDP_DROP", "critical"),
    sig("' OR 'A'='A",           "SQLi",       "XDP_DROP", "critical"),
    sig("UNION SELECT",          "SQLi",       "XDP_DROP", "critical"),
    sig("UNION ALL SELECT",      "SQLi",       "XDP_DROP", "critical"),
    sig("'; DROP",               "SQLi",       "XDP_DROP", "critical"),
    sig("DROP TABLE",            "SQLi",       "XDP_DROP", "critical"),
    sig("1=1--",                 "SQLi",       "XDP_DROP", "critical"),
    sig("1' AND '1'='1",         "SQLi",       "XDP_DROP", "critical"),
    sig("ADMIN'--",              "SQLi",       "XDP_DROP", "critical"),
    sig("ADMIN' #",              "SQLi",       "XDP_DROP", "critical"),
    sig("WAITFOR DELAY",         "SQLi",       "XDP_DROP", "high"),
    sig("SLEEP(",                "SQLi",       "XDP_DROP", "high"),
    sig("BENCHMARK(",            "SQLi",       "XDP_DROP", "high"),
    sig("PG_SLEEP(",             "SQLi",       "XDP_DROP", "high"),
    sig("EXTRACTVALUE(",         "SQLi",       "XDP_DROP", "high"),
    sig("UPDATEXML(",            "SQLi",       "XDP_DROP", "high"),
    sig("LOAD_FILE(",            "SQLi",       "XDP_DROP", "critical"),
    sig("INTO OUTFILE",          "SQLi",       "XDP_DROP", "critical"),
    sig("INTO DUMPFILE",         "SQLi",       "XDP_DROP", "critical"),
    sig("INFORMATION_SCHEMA",    "SQLi",       "XDP_DROP", "high"),
    sig("XP_CMDSHELL",           "SQLi",       "XDP_DROP", "critical"),
    sig("SP_EXECUTESQL",         "SQLi",       "XDP_DROP", "high"),
    sig("CONCAT(0X",             "SQLi",       "XDP_DROP", "high"),
    sig("CHAR(0X",               "SQLi",       "XDP_DROP", "high"),
    sig("CHR(",                  "SQLi",       "XDP_DROP", "medium"),
    sig("--+",                   "SQLi",       "XDP_DROP", "medium"),
    sig("/*!",                   "SQLi",       "XDP_DROP", "medium"),
    sig("' UNION",               "SQLi",       "XDP_DROP", "critical"),
    sig("ORDER BY 1--",          "SQLi",       "XDP_DROP", "high"),
    sig("HAVING 1=1",            "SQLi",       "XDP_DROP", "high"),

    // ── Cross-site scripting (≈30) ───────────────────────────────────────────
    sig("<SCRIPT",               "XSS",        "TC_ACT_SHOT", "critical"),
    sig("</SCRIPT>",             "XSS",        "TC_ACT_SHOT", "critical"),
    sig("JAVASCRIPT:",           "XSS",        "TC_ACT_SHOT", "high"),
    sig("ONERROR=",              "XSS",        "TC_ACT_SHOT", "high"),
    sig("ONLOAD=",               "XSS",        "TC_ACT_SHOT", "high"),
    sig("ONCLICK=",              "XSS",        "TC_ACT_SHOT", "high"),
    sig("ONMOUSEOVER=",          "XSS",        "TC_ACT_SHOT", "high"),
    sig("ONFOCUS=",              "XSS",        "TC_ACT_SHOT", "high"),
    sig("ONKEYUP=",              "XSS",        "TC_ACT_SHOT", "high"),
    sig("<IMG SRC=",             "XSS",        "TC_ACT_SHOT", "high"),
    sig("<IFRAME",               "XSS",        "TC_ACT_SHOT", "critical"),
    sig("<SVG",                  "XSS",        "TC_ACT_SHOT", "high"),
    sig("<OBJECT",               "XSS",        "TC_ACT_SHOT", "high"),
    sig("<EMBED",                "XSS",        "TC_ACT_SHOT", "high"),
    sig("<APPLET",               "XSS",        "TC_ACT_SHOT", "medium"),
    sig("<META HTTP-EQUIV",      "XSS",        "TC_ACT_SHOT", "medium"),
    sig("<LINK REL",             "XSS",        "TC_ACT_SHOT", "medium"),
    sig("<XML",                  "XSS",        "TC_ACT_SHOT", "medium"),
    sig("<BASE HREF",            "XSS",        "TC_ACT_SHOT", "medium"),
    sig("<MARQUEE",              "XSS",        "TC_ACT_SHOT", "medium"),
    sig("<TEXTAREA",             "XSS",        "TC_ACT_SHOT", "medium"),
    sig("<FORM ACTION",          "XSS",        "TC_ACT_SHOT", "medium"),
    sig("DOCUMENT.COOKIE",       "XSS",        "TC_ACT_SHOT", "critical"),
    sig("DOCUMENT.LOCATION",     "XSS",        "TC_ACT_SHOT", "high"),
    sig("WINDOW.LOCATION",       "XSS",        "TC_ACT_SHOT", "high"),
    sig("EVAL(",                 "XSS",        "TC_ACT_SHOT", "critical"),
    sig("EXPRESSION(",           "XSS",        "TC_ACT_SHOT", "high"),
    sig("XLINK:HREF",            "XSS",        "TC_ACT_SHOT", "medium"),
    sig("DATA:TEXT/HTML",        "XSS",        "TC_ACT_SHOT", "high"),
    sig("DATA:IMAGE/SVG",        "XSS",        "TC_ACT_SHOT", "medium"),
    sig("ALERT(1)",              "XSS",        "TC_ACT_SHOT", "high"),

    // ── Local-file inclusion / path traversal (≈20) ──────────────────────────
    sig("../",                   "LFI",        "XDP_DROP", "high"),
    sig("..\\",                  "LFI",        "XDP_DROP", "high"),
    sig("%2E%2E%2F",             "LFI",        "XDP_DROP", "high"),
    sig("%2E%2E/",               "LFI",        "XDP_DROP", "high"),
    sig("%252E%252E",            "LFI",        "XDP_DROP", "high"),
    sig("..%2F",                 "LFI",        "XDP_DROP", "high"),
    sig("..%5C",                 "LFI",        "XDP_DROP", "high"),
    sig("....//",                "LFI",        "XDP_DROP", "high"),
    sig("/ETC/PASSWD",           "LFI",        "XDP_DROP", "critical"),
    sig("/ETC/SHADOW",           "LFI",        "XDP_DROP", "critical"),
    sig("/ETC/HOSTS",            "LFI",        "XDP_DROP", "high"),
    sig("/PROC/SELF/",           "LFI",        "XDP_DROP", "high"),
    sig("/PROC/VERSION",         "LFI",        "XDP_DROP", "medium"),
    sig("BOOT.INI",              "LFI",        "XDP_DROP", "critical"),
    sig("WIN.INI",               "LFI",        "XDP_DROP", "high"),
    sig("/.SSH/AUTHORIZED_KEYS", "LFI",        "XDP_DROP", "critical"),
    sig("/.SSH/ID_RSA",          "LFI",        "XDP_DROP", "critical"),
    sig("WP-CONFIG.PHP",         "LFI",        "XDP_DROP", "critical"),
    sig("WEB.CONFIG",            "LFI",        "XDP_DROP", "high"),
    sig(".HTACCESS",             "LFI",        "XDP_DROP", "medium"),

    // ── Remote-code & command injection (≈30) ────────────────────────────────
    sig(";CAT ",                 "RCE",        "XDP_DROP", "critical"),
    sig(";LS ",                  "RCE",        "XDP_DROP", "high"),
    sig(";ID;",                  "RCE",        "XDP_DROP", "high"),
    sig(";WHOAMI",               "RCE",        "XDP_DROP", "high"),
    sig(";UNAME",                "RCE",        "XDP_DROP", "high"),
    sig(";PWD;",                 "RCE",        "XDP_DROP", "medium"),
    sig(";PS AUX",               "RCE",        "XDP_DROP", "medium"),
    sig("|/BIN/SH",              "RCE",        "XDP_DROP", "critical"),
    sig("|BASH -I",              "RCE",        "XDP_DROP", "critical"),
    sig("|/BIN/BASH",            "RCE",        "XDP_DROP", "critical"),
    sig("&&CAT",                 "RCE",        "XDP_DROP", "critical"),
    sig("&&LS",                  "RCE",        "XDP_DROP", "high"),
    sig(";NC -E",                "RCE",        "XDP_DROP", "critical"),
    sig(";NCAT",                 "RCE",        "XDP_DROP", "critical"),
    sig(";WGET ",                "RCE",        "XDP_DROP", "critical"),
    sig(";CURL ",                "RCE",        "XDP_DROP", "critical"),
    sig("||CAT",                 "RCE",        "XDP_DROP", "critical"),
    sig("$(CAT",                 "RCE",        "XDP_DROP", "critical"),
    sig("`CAT",                  "RCE",        "XDP_DROP", "critical"),
    sig("${IFS}",                "RCE",        "XDP_DROP", "high"),
    sig(";PHPINFO",              "RCE",        "XDP_DROP", "high"),
    sig("BASH -C",               "RCE",        "XDP_DROP", "critical"),
    sig("SH -C",                 "RCE",        "XDP_DROP", "critical"),
    sig("EXEC(",                 "RCE",        "XDP_DROP", "critical"),
    sig("SYSTEM(",               "RCE",        "XDP_DROP", "critical"),
    sig("POPEN(",                "RCE",        "XDP_DROP", "critical"),
    sig("PASSTHRU(",             "RCE",        "XDP_DROP", "critical"),
    sig("SHELL_EXEC",            "RCE",        "XDP_DROP", "critical"),
    sig("PROC_OPEN",             "RCE",        "XDP_DROP", "critical"),
    sig("BASE64 -D|SH",          "RCE",        "XDP_DROP", "critical"),

    // ── Server-side request forgery (≈15) ────────────────────────────────────
    sig("HTTP://127.0.0.1",      "SSRF",       "TC_ACT_SHOT", "high"),
    sig("HTTP://LOCALHOST",      "SSRF",       "TC_ACT_SHOT", "high"),
    sig("HTTP://0.0.0.0",        "SSRF",       "TC_ACT_SHOT", "high"),
    sig("HTTP://[::1]",          "SSRF",       "TC_ACT_SHOT", "high"),
    sig("169.254.169.254",       "SSRF",       "TC_ACT_SHOT", "critical"),
    sig("METADATA.GOOGLE",       "SSRF",       "TC_ACT_SHOT", "critical"),
    sig("METADATA/IDENTITY",     "SSRF",       "TC_ACT_SHOT", "critical"),
    sig("FILE:///",              "SSRF",       "TC_ACT_SHOT", "high"),
    sig("FTP://",                "SSRF",       "TC_ACT_SHOT", "medium"),
    sig("GOPHER://",             "SSRF",       "TC_ACT_SHOT", "high"),
    sig("DICT://",               "SSRF",       "TC_ACT_SHOT", "high"),
    sig("SFTP://",               "SSRF",       "TC_ACT_SHOT", "medium"),
    sig("LDAP://",               "SSRF",       "TC_ACT_SHOT", "high"),
    sig("EXPECT://",             "SSRF",       "TC_ACT_SHOT", "high"),
    sig("PHP://INPUT",           "SSRF",       "TC_ACT_SHOT", "critical"),

    // ── XML external entity (≈10) ────────────────────────────────────────────
    sig("<!ENTITY",              "XXE",        "TC_ACT_SHOT", "critical"),
    sig("<!DOCTYPE",             "XXE",        "TC_ACT_SHOT", "high"),
    sig("SYSTEM \"FILE:",        "XXE",        "TC_ACT_SHOT", "critical"),
    sig("SYSTEM 'FILE:",         "XXE",        "TC_ACT_SHOT", "critical"),
    sig("SYSTEM \"HTTP:",        "XXE",        "TC_ACT_SHOT", "high"),
    sig("XINCLUDE",              "XXE",        "TC_ACT_SHOT", "high"),
    sig("<?XML-STYLESHEET",      "XXE",        "TC_ACT_SHOT", "medium"),
    sig("&XXE;",                 "XXE",        "TC_ACT_SHOT", "critical"),
    sig("PARAMETER ENTITY",      "XXE",        "TC_ACT_SHOT", "high"),
    sig("<!ELEMENT",             "XXE",        "TC_ACT_SHOT", "medium"),

    // ── Log4Shell + Java deserialization (≈10) ───────────────────────────────
    sig("${JNDI:",               "Log4Shell",  "XDP_DROP", "critical"),
    sig("${JNDI:LDAP",           "Log4Shell",  "XDP_DROP", "critical"),
    sig("${JNDI:RMI",            "Log4Shell",  "XDP_DROP", "critical"),
    sig("${JNDI:DNS",            "Log4Shell",  "XDP_DROP", "critical"),
    sig("${LOWER:J}",            "Log4Shell",  "XDP_DROP", "critical"),
    sig("${UPPER:J}",            "Log4Shell",  "XDP_DROP", "critical"),
    sig("${::-J}",               "Log4Shell",  "XDP_DROP", "critical"),
    sig("O:8:\"STDCLASS\"",      "Deserial",   "XDP_DROP", "critical"),
    sig("RO0AB",                 "Deserial",   "XDP_DROP", "critical"),
    sig("AC ED 00 05",           "Deserial",   "XDP_DROP", "critical"),

    // ── NoSQL injection (≈10) ────────────────────────────────────────────────
    sig("[$NE]=",                "NoSQLi",     "XDP_DROP", "high"),
    sig("[$GT]=",                "NoSQLi",     "XDP_DROP", "high"),
    sig("[$LT]=",                "NoSQLi",     "XDP_DROP", "high"),
    sig("[$WHERE]=",             "NoSQLi",     "XDP_DROP", "critical"),
    sig("[$REGEX]=",             "NoSQLi",     "XDP_DROP", "high"),
    sig("\"$NE\":",              "NoSQLi",     "XDP_DROP", "high"),
    sig("\"$GT\":",              "NoSQLi",     "XDP_DROP", "high"),
    sig("\"$WHERE\":",           "NoSQLi",     "XDP_DROP", "critical"),
    sig("'; RETURN ",            "NoSQLi",     "XDP_DROP", "critical"),
    sig("MAPREDUCE",             "NoSQLi",     "XDP_DROP", "medium"),

    // ── Server-side template injection (≈10) ─────────────────────────────────
    sig("{{7*7}}",               "SSTI",       "XDP_DROP", "critical"),
    sig("{{7*'7'}}",             "SSTI",       "XDP_DROP", "critical"),
    sig("{{CONFIG}}",            "SSTI",       "XDP_DROP", "critical"),
    sig("${{7*7}}",              "SSTI",       "XDP_DROP", "critical"),
    sig("<%=7*7%>",              "SSTI",       "XDP_DROP", "critical"),
    sig("#{7*7}",                "SSTI",       "XDP_DROP", "critical"),
    sig("*{7*7}",                "SSTI",       "XDP_DROP", "high"),
    sig("{{REQUEST}}",           "SSTI",       "XDP_DROP", "high"),
    sig("__GLOBALS__",           "SSTI",       "XDP_DROP", "critical"),
    sig("__CLASS__.__MRO__",     "SSTI",       "XDP_DROP", "critical"),

    // ── Web shells (≈10) ─────────────────────────────────────────────────────
    sig("C99.PHP",               "WebShell",   "XDP_DROP", "critical"),
    sig("R57.PHP",               "WebShell",   "XDP_DROP", "critical"),
    sig("WSO.PHP",               "WebShell",   "XDP_DROP", "critical"),
    sig("B374K",                 "WebShell",   "XDP_DROP", "critical"),
    sig("WEEVELY",               "WebShell",   "XDP_DROP", "critical"),
    sig("CHINA CHOPPER",         "WebShell",   "XDP_DROP", "critical"),
    sig("EVAL($_POST",           "WebShell",   "XDP_DROP", "critical"),
    sig("EVAL($_GET",            "WebShell",   "XDP_DROP", "critical"),
    sig("ASSERT($_",             "WebShell",   "XDP_DROP", "critical"),
    sig("BASE64_DECODE($_",      "WebShell",   "XDP_DROP", "critical"),

    // ── Reconnaissance / sensitive paths (≈15) ───────────────────────────────
    sig("/PHPMYADMIN",           "Recon",      "XDP_DROP", "medium"),
    sig("/.GIT/CONFIG",          "Recon",      "XDP_DROP", "high"),
    sig("/.SVN/ENTRIES",         "Recon",      "XDP_DROP", "medium"),
    sig("/.ENV",                 "Recon",      "XDP_DROP", "high"),
    sig("/CONFIG.PHP",           "Recon",      "XDP_DROP", "high"),
    sig("/WP-ADMIN",             "Recon",      "XDP_DROP", "medium"),
    sig("/WP-LOGIN.PHP",         "Recon",      "XDP_DROP", "medium"),
    sig("/SETUP.PHP",            "Recon",      "XDP_DROP", "medium"),
    sig("/INSTALL.PHP",          "Recon",      "XDP_DROP", "medium"),
    sig("/CGI-BIN/",             "Recon",      "XDP_DROP", "medium"),
    sig("/MANAGER/HTML",         "Recon",      "XDP_DROP", "high"),
    sig("/.WELL-KNOWN/SECURITY", "Recon",      "XDP_DROP", "low"),
    sig("/ACTUATOR/ENV",         "Recon",      "XDP_DROP", "high"),
    sig("/SWAGGER.JSON",         "Recon",      "XDP_DROP", "low"),
    sig("/.AWS/CREDENTIALS",     "Recon",      "XDP_DROP", "critical"),

    // ── CVE-flavored / known exploits (≈10) ──────────────────────────────────
    sig("() { :;}",              "CVE",        "XDP_DROP", "critical"),  // Shellshock
    sig("CVE-2021-44228",        "CVE",        "XDP_DROP", "critical"),
    sig("/MOVEIT.DLL",           "CVE",        "XDP_DROP", "critical"),
    sig("_VTI_BIN",              "CVE",        "XDP_DROP", "high"),
    sig("STRUTS2-",              "CVE",        "XDP_DROP", "critical"),
    sig("SPRINGSHELL",           "CVE",        "XDP_DROP", "critical"),
    sig("/MANAGER/JMXPROXY",     "CVE",        "XDP_DROP", "critical"),
    sig("CMDPLUGIN",             "CVE",        "XDP_DROP", "high"),
    sig("XML-RPC.PHP",           "CVE",        "XDP_DROP", "medium"),
    sig("/UPL.PHP",              "CVE",        "XDP_DROP", "high"),
];

/// Distinct categories present in `SIGNATURES`, in display order.
pub const CATEGORIES: &[&str] = &[
    "SQLi", "XSS", "LFI", "RCE", "SSRF", "XXE",
    "Log4Shell", "Deserial", "NoSQLi", "SSTI",
    "WebShell", "Recon", "CVE",
];

/// Returns (category, count) pairs for the `rules` CLI command.
pub fn category_counts() -> Vec<(&'static str, usize)> {
    CATEGORIES
        .iter()
        .map(|&cat| {
            let n = SIGNATURES.iter().filter(|s| s.category == cat).count();
            (cat, n)
        })
        .collect()
}
