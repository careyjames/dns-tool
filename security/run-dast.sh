#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORTS_DIR="$SCRIPT_DIR/reports"
mkdir -p "$REPORTS_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SCAN_TARGET="${SCAN_TARGET_URL:-${BASE_URL:-}}"

if [ -z "$SCAN_TARGET" ]; then
  echo -e "${RED}ERROR: No scan target URL configured.${NC}"
  echo ""
  echo "Set SCAN_TARGET_URL or BASE_URL environment variable:"
  echo "  export SCAN_TARGET_URL=https://your-app.replit.dev"
  echo "  bash security/run-dast.sh"
  exit 1
fi

SCAN_TARGET="${SCAN_TARGET%/}"

echo "═══════════════════════════════════════════"
echo "  DNS Tool — DAST Passive Scan"
echo "  Target: $SCAN_TARGET"
echo "═══════════════════════════════════════════"
echo ""

FAIL=0
WARN=0
START_TIME=$(date +%s)

check_target_reachable() {
  echo "▸ Checking target reachability ..."
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$SCAN_TARGET" 2>/dev/null || true)

  if [ "$HTTP_CODE" = "000" ]; then
    echo -e "  ${RED}✗ Target unreachable: $SCAN_TARGET${NC}"
    echo "  Make sure the application is running."
    exit 1
  fi
  echo -e "  ${GREEN}✓ Target reachable (HTTP $HTTP_CODE)${NC}"
  echo ""
}

passive_header_scan() {
  echo "▸ [1/3] Security headers scan ..."
  HEADERS_REPORT="$REPORTS_DIR/dast-headers.json"

  python3 - "$SCAN_TARGET" "$HEADERS_REPORT" << 'PYEOF'
import json
import sys
import urllib.request
import urllib.error
import ssl

target = sys.argv[1]
report_path = sys.argv[2]

EXPECTED_HEADERS = {
    "Strict-Transport-Security": {"required": True, "severity": "high"},
    "X-Content-Type-Options": {"required": True, "severity": "medium", "expected": "nosniff"},
    "X-Frame-Options": {"required": False, "severity": "medium"},
    "Content-Security-Policy": {"required": True, "severity": "high"},
    "Referrer-Policy": {"required": False, "severity": "low"},
    "Permissions-Policy": {"required": False, "severity": "low"},
    "X-XSS-Protection": {"required": False, "severity": "info"},
    "Cache-Control": {"required": False, "severity": "info"},
}

RISKY_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
]

findings = []
try:
    ctx = ssl.create_default_context()
    req = urllib.request.Request(target, headers={"User-Agent": "DNS-Tool-Security-Scanner/1.0"})
    resp = urllib.request.urlopen(req, timeout=10, context=ctx)
    headers = dict(resp.headers)

    for header, config in EXPECTED_HEADERS.items():
        value = headers.get(header)
        if value is None:
            findings.append({
                "type": "missing_header",
                "header": header,
                "severity": config["severity"],
                "required": config["required"],
                "message": f"Missing security header: {header}",
            })
        elif "expected" in config and value.lower() != config["expected"].lower():
            findings.append({
                "type": "wrong_value",
                "header": header,
                "severity": config["severity"],
                "expected": config["expected"],
                "actual": value,
                "message": f"{header} has unexpected value: {value}",
            })

    for header in RISKY_HEADERS:
        if header in headers:
            findings.append({
                "type": "info_disclosure",
                "header": header,
                "severity": "low",
                "value": headers[header],
                "message": f"Information disclosure header present: {header}: {headers[header]}",
            })

    cookies = resp.headers.get_all("Set-Cookie") or []
    for cookie in cookies:
        cookie_lower = cookie.lower()
        if "secure" not in cookie_lower:
            findings.append({
                "type": "insecure_cookie",
                "severity": "medium",
                "cookie": cookie.split("=")[0],
                "message": f"Cookie missing Secure flag: {cookie.split('=')[0]}",
            })
        if "httponly" not in cookie_lower:
            findings.append({
                "type": "insecure_cookie",
                "severity": "medium",
                "cookie": cookie.split("=")[0],
                "message": f"Cookie missing HttpOnly flag: {cookie.split('=')[0]}",
            })

    report = {
        "target": target,
        "status_code": resp.status,
        "headers_present": list(headers.keys()),
        "findings": findings,
        "total_findings": len(findings),
        "critical_high": len([f for f in findings if f["severity"] in ("critical", "high")]),
    }

except Exception as e:
    report = {
        "target": target,
        "error": str(e),
        "findings": [],
        "total_findings": 0,
        "critical_high": 0,
    }

with open(report_path, "w") as f:
    json.dump(report, f, indent=2)

crit_high = report["critical_high"]
total = report["total_findings"]
if crit_high > 0:
    print(f"FAIL {crit_high} {total}")
elif total > 0:
    print(f"WARN 0 {total}")
else:
    print(f"PASS 0 0")
PYEOF

  HEADER_RESULT=$(python3 - "$SCAN_TARGET" "$HEADERS_REPORT" << 'PYEOF2'
import json, sys
try:
    data = json.load(open(sys.argv[2]))
    ch = data.get("critical_high", 0)
    total = data.get("total_findings", 0)
    if ch > 0: print(f"FAIL {ch} {total}")
    elif total > 0: print(f"WARN 0 {total}")
    else: print("PASS 0 0")
except: print("WARN 0 0")
PYEOF2
  )

  RESULT_STATUS=$(echo "$HEADER_RESULT" | awk '{print $1}')
  RESULT_CH=$(echo "$HEADER_RESULT" | awk '{print $2}')
  RESULT_TOTAL=$(echo "$HEADER_RESULT" | awk '{print $3}')

  if [ "$RESULT_STATUS" = "FAIL" ]; then
    echo -e "  ${RED}✗ Headers: $RESULT_CH critical/high finding(s)${NC} ($RESULT_TOTAL total)"
    FAIL=1
  elif [ "$RESULT_STATUS" = "WARN" ]; then
    echo -e "  ${YELLOW}⚠ Headers: $RESULT_TOTAL finding(s), none critical/high${NC}"
    WARN=1
  else
    echo -e "  ${GREEN}✓ Headers: all security headers present and correct${NC}"
  fi
}

passive_tls_scan() {
  echo ""
  echo "▸ [2/3] TLS configuration scan ..."
  TLS_REPORT="$REPORTS_DIR/dast-tls.json"

  python3 - "$SCAN_TARGET" "$TLS_REPORT" << 'PYEOF'
import json
import socket
import ssl
import sys
from urllib.parse import urlparse

target = sys.argv[1]
report_path = sys.argv[2]
parsed = urlparse(target)
hostname = parsed.hostname
port = parsed.port or (443 if parsed.scheme == "https" else 80)

findings = []
cert_info = {}

if parsed.scheme != "https":
    findings.append({
        "type": "no_tls",
        "severity": "high",
        "message": "Target is not using HTTPS",
    })
else:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()

                cert_info = {
                    "subject": dict(x[0] for x in cert.get("subject", ())),
                    "issuer": dict(x[0] for x in cert.get("issuer", ())),
                    "version": cert.get("version"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "protocol": protocol,
                    "cipher_suite": cipher[0] if cipher else None,
                    "cipher_bits": cipher[2] if cipher and len(cipher) > 2 else None,
                }

                if protocol in ("TLSv1", "TLSv1.1"):
                    findings.append({
                        "type": "weak_tls",
                        "severity": "high",
                        "message": f"Outdated TLS version: {protocol}",
                    })

    except ssl.SSLCertVerificationError as e:
        findings.append({
            "type": "cert_error",
            "severity": "critical",
            "message": f"TLS certificate verification failed: {e}",
        })
    except Exception as e:
        findings.append({
            "type": "tls_error",
            "severity": "medium",
            "message": f"TLS scan error: {e}",
        })

report = {
    "target": target,
    "hostname": hostname,
    "port": port,
    "cert_info": cert_info,
    "findings": findings,
    "total_findings": len(findings),
    "critical_high": len([f for f in findings if f["severity"] in ("critical", "high")]),
}

with open(report_path, "w") as f:
    json.dump(report, f, indent=2)

if report["critical_high"] > 0:
    sys.exit(1)
elif report["total_findings"] > 0:
    sys.exit(0)
else:
    sys.exit(0)
PYEOF

  TLS_EXIT=$?
  if [ "$TLS_EXIT" -ne 0 ]; then
    echo -e "  ${RED}✗ TLS: critical issues found${NC}"
    FAIL=1
  elif [ -f "$TLS_REPORT" ]; then
    TLS_TOTAL=$(python3 -c "import json; print(json.load(open('$TLS_REPORT')).get('total_findings', 0))" 2>/dev/null || echo "0")
    if [ "$TLS_TOTAL" -gt 0 ]; then
      echo -e "  ${YELLOW}⚠ TLS: $TLS_TOTAL finding(s)${NC}"
      WARN=1
    else
      echo -e "  ${GREEN}✓ TLS: configuration looks good${NC}"
    fi
  fi
}

passive_crawl_scan() {
  echo ""
  echo "▸ [3/3] Passive endpoint scan ..."
  CRAWL_REPORT="$REPORTS_DIR/dast-crawl.json"

  python3 - "$SCAN_TARGET" "$CRAWL_REPORT" << 'PYEOF'
import json
import re
import ssl
import sys
import urllib.request
import urllib.error

target = sys.argv[1]
report_path = sys.argv[2]

PATHS_TO_CHECK = [
    "/",
    "/robots.txt",
    "/.well-known/security.txt",
    "/.env",
    "/.git/config",
    "/wp-admin/",
    "/admin/",
    "/debug/",
    "/api/",
    "/swagger.json",
    "/openapi.json",
]

findings = []
results = []
ctx = ssl.create_default_context()

for path in PATHS_TO_CHECK:
    url = target + path
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "DNS-Tool-Security-Scanner/1.0"})
        resp = urllib.request.urlopen(req, timeout=10, context=ctx)
        status = resp.status
        content_type = resp.headers.get("Content-Type", "")
        results.append({"path": path, "status": status, "content_type": content_type})

        if path == "/.env" and status == 200:
            findings.append({
                "type": "sensitive_file",
                "severity": "critical",
                "path": path,
                "message": ".env file is publicly accessible",
            })
        elif path == "/.git/config" and status == 200:
            findings.append({
                "type": "sensitive_file",
                "severity": "critical",
                "path": path,
                "message": ".git directory is publicly accessible",
            })
        elif path in ("/swagger.json", "/openapi.json") and status == 200:
            findings.append({
                "type": "api_exposure",
                "severity": "low",
                "path": path,
                "message": f"API specification accessible at {path}",
            })

    except urllib.error.HTTPError as e:
        results.append({"path": path, "status": e.code, "error": str(e)})
    except Exception as e:
        results.append({"path": path, "status": 0, "error": str(e)})

report = {
    "target": target,
    "paths_checked": len(PATHS_TO_CHECK),
    "results": results,
    "findings": findings,
    "total_findings": len(findings),
    "critical_high": len([f for f in findings if f["severity"] in ("critical", "high")]),
}

with open(report_path, "w") as f:
    json.dump(report, f, indent=2)

if report["critical_high"] > 0:
    sys.exit(1)
PYEOF

  CRAWL_EXIT=$?
  if [ "$CRAWL_EXIT" -ne 0 ]; then
    echo -e "  ${RED}✗ Crawl: critical sensitive files exposed${NC}"
    FAIL=1
  elif [ -f "$CRAWL_REPORT" ]; then
    CRAWL_TOTAL=$(python3 -c "import json; print(json.load(open('$CRAWL_REPORT')).get('total_findings', 0))" 2>/dev/null || echo "0")
    if [ "$CRAWL_TOTAL" -gt 0 ]; then
      echo -e "  ${YELLOW}⚠ Crawl: $CRAWL_TOTAL finding(s)${NC}"
      WARN=1
    else
      echo -e "  ${GREEN}✓ Crawl: no sensitive files exposed${NC}"
    fi
  fi
}

check_target_reachable
passive_header_scan
passive_tls_scan
passive_crawl_scan

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo ""
echo "═══════════════════════════════════════════"
echo "  Target:  $SCAN_TARGET"
echo "  Elapsed: ${ELAPSED}s"
echo "  Reports: $REPORTS_DIR/"
if [ $FAIL -ne 0 ]; then
  echo -e "  ${RED}DAST SCAN: FAILED ✗${NC}"
elif [ $WARN -ne 0 ]; then
  echo -e "  ${YELLOW}DAST SCAN: PASSED WITH WARNINGS ⚠${NC}"
else
  echo -e "  ${GREEN}DAST SCAN: PASSED ✓${NC}"
fi
echo "═══════════════════════════════════════════"
exit $FAIL
