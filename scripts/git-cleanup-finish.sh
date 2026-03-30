#!/bin/bash
set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}✓${NC} $1"; }
info() { echo -e "${YELLOW}▸${NC} $1"; }

cd "$(dirname "$0")/.."

echo ""
info "Finishing git cleanup — removing lock files and repacking"
echo ""
echo "  Before: .git size: $(du -sh .git | cut -f1)"
echo ""

info "Removing stale lock files..."
find .git -name '*.lock' -type f -delete 2>/dev/null || true
pass "Lock files removed"

info "Removing leftover dependabot refs..."
rm -rf .git/refs/heads/dependabot 2>/dev/null || true
rm -rf .git/refs/remotes 2>/dev/null || true
pass "Stale refs removed"

info "Cleaning packed-refs..."
if [ -f .git/packed-refs ]; then
  grep -v 'refs/remotes/' .git/packed-refs | grep -v 'dependabot/' > .git/packed-refs.tmp 2>/dev/null || true
  mv .git/packed-refs.tmp .git/packed-refs 2>/dev/null || true
  pass "Packed refs cleaned"
fi

info "Running git reflog expire..."
git reflog expire --expire=now --all 2>/dev/null || true
pass "Reflog expired"

info "Running aggressive git gc (this may take a minute)..."
git gc --prune=now --aggressive 2>/dev/null || true
pass "GC complete"

echo ""
echo "  After: .git size: $(du -sh .git | cut -f1)"
BLOBS=$(git rev-list --objects --all -- dns-tool-server dns-tool-server-new dns-tool 2>/dev/null | wc -l)
echo "  Binary objects remaining: $BLOBS"
echo ""

info "Re-adding remotes..."
git remote add origin https://github.com/IT-Help-San-Diego/dns-tool.git 2>/dev/null || true
git remote add gitsafe-backup git://gitsafe:5418/backup.git 2>/dev/null || true

pass "Done! Git history cleanup complete."
echo ""
