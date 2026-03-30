#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

MODE="${1:-fast}"

echo "=== DNS Tool Contract Test Suite (mode: $MODE) ==="
echo ""

FAILED=0

echo "--- 1. Schema Validation Tests ---"
if python -m pytest tests/test_schema_validation.py -v --tb=short 2>&1; then
    echo "[PASS] Schema validation"
else
    echo "[FAIL] Schema validation"
    FAILED=1
fi
echo ""

echo "--- 2. Golden Fixture Regression Tests ---"
if python -m pytest tests/test_golden.py -v --tb=short 2>&1; then
    echo "[PASS] Golden fixtures"
else
    echo "[FAIL] Golden fixtures"
    FAILED=1
fi
echo ""

echo "--- 3. Dependency Injection Tests ---"
if python -m pytest tests/test_dns_analyzer.py::TestDependencyInjection -v --tb=short 2>&1; then
    echo "[PASS] Dependency injection"
else
    echo "[FAIL] Dependency injection"
    FAILED=1
fi
echo ""

echo "--- 4. Edge Case Tests (offline DI-based) ---"
if python -m pytest tests/test_edge_cases.py -v --tb=short 2>&1; then
    echo "[PASS] Edge cases"
else
    echo "[FAIL] Edge cases"
    FAILED=1
fi
echo ""

echo "--- 5. Behavioral Contract Tests ---"
if python -m pytest tests/test_behavioral_contracts.py -v --tb=short 2>&1; then
    echo "[PASS] Behavioral contracts"
else
    echo "[FAIL] Behavioral contracts"
    FAILED=1
fi
echo ""

if [[ "$MODE" = "full" ]]; then
    echo "--- 6. Full Test Suite (includes integration tests) ---"
    if python -m pytest tests/ -v --tb=short --timeout=120 2>&1; then
        echo "[PASS] Full suite"
    else
        echo "[FAIL] Full suite (some tests may have pre-existing failures)"
        FAILED=1
    fi
    echo ""
else
    echo "--- Skipping full integration suite (run with: $0 full) ---"
    echo ""
fi

echo "==================================="
if [[ $FAILED -eq 0 ]]; then
    echo "ALL CONTRACT TESTS PASSED"
    exit 0
else
    echo "SOME TESTS FAILED - see output above"
    exit 1
fi
