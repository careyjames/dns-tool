#!/usr/bin/env bash
set -uo pipefail

echo "═══════════════════════════════════════════"
echo "  DNS Tool — Pre-Push Quality Gate"
echo "═══════════════════════════════════════════"
echo ""

FAIL=0

echo "▸ [1/3] go vet ..."
if (cd go-server && go vet ./... 2>&1); then
  echo "  ✓ go vet passed"
else
  echo "  ✗ go vet FAILED"
  FAIL=1
fi

echo ""
echo "▸ [2/3] core tests ..."
if (cd go-server && go test ./internal/analyzer/ ./internal/middleware/ ./internal/entitlements/ -timeout 120s -count=1 2>&1 | tail -5); then
  echo "  ✓ core tests passed"
else
  echo "  ✗ core tests FAILED"
  FAIL=1
fi

echo ""
echo "▸ [3/3] RFC attack vector tests ..."
if (cd go-server && go test ./internal/analyzer/ -run "RFCAttack" -timeout 60s -count=1 2>&1 | tail -3); then
  echo "  ✓ RFC attack tests passed"
else
  echo "  ✗ RFC attack tests FAILED"
  FAIL=1
fi

echo ""
echo "═══════════════════════════════════════════"
if [ $FAIL -eq 0 ]; then
  echo "  QUALITY GATE: PASSED ✓"
else
  echo "  QUALITY GATE: FAILED ✗"
fi
echo "═══════════════════════════════════════════"
exit $FAIL
