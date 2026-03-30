#!/bin/bash
# Methodology Leak Audit — run from DnsToolWeb project root
# This script contains the specific banned patterns. It lives in the PRIVATE intel repo only.
cd /home/runner/workspace 2>/dev/null || true
echo "=== Methodology Leak Audit ==="
FOUND=0
grep -rni "three.layer\|3.layer\|processCT\|enrichSub\|probeCommon" \
  --include="*.md" --include="*.html" --include="*.txt" \
  --exclude-dir=go-server/internal --exclude-dir=.git \
  --exclude-dir=attached_assets 2>/dev/null && FOUND=1
grep -rni "~90\|~140\|~290" \
  --include="*.md" --include="*.html" --include="*.txt" \
  --exclude-dir=go-server/internal --exclude-dir=.git \
  --exclude-dir=attached_assets 2>/dev/null && FOUND=1
grep -rni "10MB.*body\|30s.*crt\|10MB.*limit" \
  --include="*.md" --include="*.html" --include="*.txt" \
  --exclude-dir=go-server/internal --exclude-dir=.git \
  --exclude-dir=attached_assets 2>/dev/null && FOUND=1
if [ $FOUND -eq 0 ]; then
  echo "CLEAN — no methodology leaks found"
else
  echo "LEAKS DETECTED — fix before ending session"
  exit 1
fi
