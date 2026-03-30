#!/usr/bin/env bash
set -euo pipefail

HOOK=".git/hooks/pre-commit"

cat > "$HOOK" << 'EOF'
#!/usr/bin/env bash
set -euo pipefail

if git diff --cached --name-only | grep -qx 'CITATION.cff'; then
  if ! grep -qE '^license:\s*"BUSL-1\.1"\s*$' CITATION.cff; then
    echo "BLOCKED: CITATION.cff license must be BUSL-1.1"
    grep -n '^license:' CITATION.cff || true
    exit 1
  fi
fi
EOF

chmod +x "$HOOK"
echo "Pre-commit hook installed at $HOOK"
