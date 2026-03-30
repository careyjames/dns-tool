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

WARN=0
START_TIME=$(date +%s)

echo "═══════════════════════════════════════════"
echo "  DNS Tool — Fast Security Scan"
echo "  (SAST + Dependencies + Secrets)"
echo "═══════════════════════════════════════════"
echo ""

detect_stack() {
  local stacks=""
  [ -f "$REPO_ROOT/go.mod" ] && stacks="$stacks go"
  [ -f "$REPO_ROOT/package.json" ] && stacks="$stacks node"
  [ -f "$REPO_ROOT/pyproject.toml" ] && stacks="$stacks python"
  echo "${stacks:-unknown}"
}

DETECTED_STACKS=$(detect_stack)
echo "  Detected stacks: $DETECTED_STACKS"
echo ""

STEP=1
TOTAL_STEPS=5

echo "▸ [$STEP/$TOTAL_STEPS] Semgrep SAST scan ..."
SEMGREP_OUTPUT="$REPORTS_DIR/semgrep.json"
if command -v semgrep &>/dev/null; then
  semgrep scan --config "$SCRIPT_DIR/semgrep-rules.yml" \
    --config "p/owasp-top-ten" \
    --json --output "$SEMGREP_OUTPUT" \
    --exclude "vendor" --exclude "node_modules" --exclude ".cache" \
    --exclude "attached_assets" --exclude ".agents" --exclude ".local" \
    --exclude "docs/legacy" --exclude "stubs" \
    "$REPO_ROOT/go-server" 2>/dev/null || true

  if [ -f "$SEMGREP_OUTPUT" ]; then
    SEMGREP_STATS=$(python3 -c "
import json
data = json.load(open('$SEMGREP_OUTPUT'))
results = data.get('results', [])
crit_high = len([r for r in results if r.get('extra', {}).get('severity', '').upper() in ('ERROR', 'CRITICAL', 'HIGH')])
medium = len([r for r in results if r.get('extra', {}).get('severity', '').upper() in ('WARNING', 'MEDIUM')])
print(f'{crit_high} {medium} {len(results)}')
" 2>/dev/null || echo "0 0 0")
    CRIT_HIGH=$(echo "$SEMGREP_STATS" | awk '{print $1}')
    MEDIUM=$(echo "$SEMGREP_STATS" | awk '{print $2}')
    TOTAL=$(echo "$SEMGREP_STATS" | awk '{print $3}')

    if [ "${CRIT_HIGH:-0}" -gt 0 ]; then
      echo -e "  ${RED}✗ Semgrep: $CRIT_HIGH critical/high finding(s)${NC} ($TOTAL total)"
    elif [ "${MEDIUM:-0}" -gt 0 ]; then
      echo -e "  ${YELLOW}⚠ Semgrep: $MEDIUM medium finding(s)${NC} ($TOTAL total)"
      WARN=1
    else
      echo -e "  ${GREEN}✓ Semgrep: $TOTAL finding(s), none critical/high${NC}"
    fi
  else
    echo -e "  ${YELLOW}⚠ Semgrep: no output produced${NC}"
    WARN=1
  fi
else
  echo -e "  ${YELLOW}⚠ Semgrep not installed — skipping SAST${NC}"
  WARN=1
fi

STEP=$((STEP + 1))
echo ""
echo "▸ [$STEP/$TOTAL_STEPS] OSV-Scanner dependency scan ..."
OSV_OUTPUT="$REPORTS_DIR/osv-scanner.json"
if command -v osv-scanner &>/dev/null; then
  osv-scanner scan --format json --output "$OSV_OUTPUT" \
    -r "$REPO_ROOT" 2>/dev/null || true

  if [ -f "$OSV_OUTPUT" ]; then
    OSV_VULNS=$(python3 -c "
import json
data = json.load(open('$OSV_OUTPUT'))
total = sum(len(r.get('packages', [])) for r in data.get('results', []))
print(total)
" 2>/dev/null || echo "0")
    if [ "${OSV_VULNS:-0}" -eq 0 ]; then
      echo -e "  ${GREEN}✓ OSV-Scanner: no known vulnerabilities${NC}"
    else
      echo -e "  ${YELLOW}⚠ OSV-Scanner: ${OSV_VULNS} vulnerable package(s) found${NC}"
      WARN=1
    fi
  else
    echo -e "  ${GREEN}✓ OSV-Scanner: no known vulnerabilities${NC}"
  fi
else
  echo -e "  ${YELLOW}⚠ OSV-Scanner not installed — skipping dependency scan${NC}"
  WARN=1
fi

STEP=$((STEP + 1))
echo ""
echo "▸ [$STEP/$TOTAL_STEPS] Secret scan (Gitleaks + Trivy) ..."
GITLEAKS_OUTPUT="$REPORTS_DIR/gitleaks.json"
TRIVY_SECRET_OUTPUT="$REPORTS_DIR/trivy-secrets.json"
SECRET_FAIL=0

if command -v gitleaks &>/dev/null; then
  gitleaks detect --source "$REPO_ROOT" \
    --config "$REPO_ROOT/.gitleaks.toml" \
    --report-format json --report-path "$GITLEAKS_OUTPUT" \
    --no-git 2>/dev/null || true

  if [ -f "$GITLEAKS_OUTPUT" ]; then
    LEAK_COUNT=$(python3 -c "import json; data=json.load(open('$GITLEAKS_OUTPUT')); print(len(data) if isinstance(data,list) else 0)" 2>/dev/null || echo "0")
    if [ "${LEAK_COUNT:-0}" -gt 0 ]; then
      echo -e "  ${RED}✗ Gitleaks: $LEAK_COUNT secret(s) detected${NC}"
      SECRET_FAIL=1
    else
      echo -e "  ${GREEN}✓ Gitleaks: no secrets detected${NC}"
    fi
  else
    echo -e "  ${GREEN}✓ Gitleaks: no secrets detected${NC}"
  fi
else
  echo -e "  ${CYAN}ℹ Gitleaks not installed — skipping${NC}"
fi

if command -v trivy &>/dev/null; then
  trivy fs --format json --output "$TRIVY_SECRET_OUTPUT" \
    --scanners secret \
    --skip-dirs .config/replit/.semgrep --skip-dirs node_modules --skip-dirs .cache \
    "$REPO_ROOT" 2>/dev/null || true

  if [ -f "$TRIVY_SECRET_OUTPUT" ]; then
    TRIVY_SECRETS=$(python3 -c "
import json
data = json.load(open('$TRIVY_SECRET_OUTPUT'))
total = sum(len(r.get('Secrets', [])) for r in data.get('Results', []))
print(total)
" 2>/dev/null || echo "0")
    if [ "${TRIVY_SECRETS:-0}" -gt 0 ]; then
      echo -e "  ${RED}✗ Trivy secrets: $TRIVY_SECRETS secret(s) found${NC}"
      SECRET_FAIL=1
    else
      echo -e "  ${GREEN}✓ Trivy secrets: clean${NC}"
    fi
  fi
else
  echo -e "  ${CYAN}ℹ Trivy not installed — skipping Trivy secret scan${NC}"
fi

if [ "$SECRET_FAIL" -ne 0 ]; then
  echo -e "  ${RED}  Secret scan: FAILED${NC}"
fi

STEP=$((STEP + 1))
echo ""
echo "▸ [$STEP/$TOTAL_STEPS] SECINTENT reconciliation ..."
SECINTENT_FAIL=0
python3 "$SCRIPT_DIR/secintent-check.py" || SECINTENT_FAIL=1

STEP=$((STEP + 1))
echo ""
echo "▸ [$STEP/$TOTAL_STEPS] Aggregating and gating ..."
python3 "$SCRIPT_DIR/report/aggregate.py" 2>/dev/null || true

BLOCKED=0
BASELINE_PATH="$REPORTS_DIR/baseline.json"
if [ -f "$REPORTS_DIR/latest.json" ]; then
  GATE_RESULT=$(python3 -c "
import json
report = json.load(open('$REPORTS_DIR/latest.json'))
blocked = len([f for f in report.get('findings', []) if f.get('action') == 'blocked'])
print(blocked)
" 2>/dev/null || echo "0")
  BLOCKED=${GATE_RESULT:-0}

  if [ "$BLOCKED" -gt 0 ]; then
    echo -e "  ${RED}✗ Aggregated gate: $BLOCKED new critical/high finding(s) blocking${NC}"
  else
    echo -e "  ${GREEN}✓ Aggregated gate: no new critical/high findings blocking${NC}"
  fi
else
  echo -e "  ${YELLOW}⚠ No aggregated report available${NC}"
  WARN=1
fi

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

FINAL_FAIL=0
if [ "$BLOCKED" -gt 0 ] || [ "$SECRET_FAIL" -ne 0 ] || [ "$SECINTENT_FAIL" -ne 0 ]; then
  FINAL_FAIL=1
fi

echo ""
echo "═══════════════════════════════════════════"
echo "  Elapsed: ${ELAPSED}s"
if [ $FINAL_FAIL -ne 0 ]; then
  echo -e "  ${RED}FAST SCAN: FAILED ✗${NC}"
elif [ $WARN -ne 0 ]; then
  echo -e "  ${YELLOW}FAST SCAN: PASSED WITH WARNINGS ⚠${NC}"
else
  echo -e "  ${GREEN}FAST SCAN: PASSED ✓${NC}"
fi
echo "═══════════════════════════════════════════"
exit $FINAL_FAIL
