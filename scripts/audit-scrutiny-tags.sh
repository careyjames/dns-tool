#!/usr/bin/env bash
set -euo pipefail

science=0
design=0
plumbing=0
untagged=0

echo "=== DNS Tool Scrutiny Classification Audit ==="
echo ""

while IFS= read -r f; do
  tag=$(grep -m1 '^// dns-tool:scrutiny ' "$f" 2>/dev/null | sed 's|^// dns-tool:scrutiny ||' | awk '{print $1}' || true)
  case "$tag" in
    science)  science=$((science + 1)) ;;
    design)   design=$((design + 1)) ;;
    plumbing) plumbing=$((plumbing + 1)) ;;
    *)        untagged=$((untagged + 1))
              echo "  UNTAGGED: $f" ;;
  esac
done < <(find go-server -name "*.go" ! -name "*_test.go" -type f)

total=$((science + design + plumbing + untagged))
echo ""
echo "Summary:"
echo "  [SCIENCE]   $science files — RFC truth, formulas, confidence logic"
echo "  [DESIGN]    $design files — UX, styling, copy"
echo "  [PLUMBING]  $plumbing files — config, build, infrastructure"
echo "  [UNTAGGED]  $untagged files"
echo "  TOTAL:      $total Go files"
echo ""

if [ "$untagged" -gt 0 ]; then
  echo "ACTION NEEDED: $untagged files lack scrutiny classification."
  exit 1
else
  echo "All files classified."
fi
