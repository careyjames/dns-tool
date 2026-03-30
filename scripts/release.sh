#!/usr/bin/env bash
# One-command release: bumps versions, validates, commits, tags, pushes.
# Usage: ./scripts/release.sh X.Y.Z
#
# Prerequisites:
#   - Clean working tree (no uncommitted changes)
#   - GITHUB_MASTER_PAT set with repo + workflow scope
#
# What it does:
#   1. Runs release-gate.sh (bumps all versioned artifacts, regenerates PDFs, validates)
#   2. Commits the release locally
#   3. Syncs to dns-tool (canonical repo) via git-sync.sh
#   4. Creates annotated tag vX.Y.Z
#   5. GitHub Actions creates the Release with SHA256SUMS (automatic)
#   6. Zenodo auto-archives via GitHub integration (automatic)
#
# Architecture:
#   Single-repo: IT-Help-San-Diego/dns-tool (BUSL-1.1 licensed).
#   Build tags separate OSS stubs (_oss.go) from intel (_intel.go).
#   Zenodo watches this repo for releases.

set -euo pipefail
cd "$(dirname "$0")/.."

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗ $1${NC}"; exit 1; }
info() { echo -e "${YELLOW}▸${NC} $1"; }

trap 'echo ""; echo -e "  ${RED}✗ Release pipeline failed at line $LINENO: $BASH_COMMAND${NC}"; echo "  Fix the error above and re-run: bash scripts/release.sh $1"' ERR

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 X.Y.Z"
  exit 1
fi

VER="$1"
TAG="v$VER"

if [[ "$VER" == v* ]]; then
  fail "Version must NOT have a leading 'v' (got: $VER). Use: ${VER#v}"
fi

if [[ ! "$VER" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  fail "Version must be X.Y.Z format (got: $VER)"
fi

TOKEN="${GH_SYNC_TOKEN:-${ORG_PAT:-${GITHUB_MASTER_PAT:-}}}"
if [ -z "$TOKEN" ]; then
  fail "GH_SYNC_TOKEN (or ORG_PAT) not set. Cannot authenticate with GitHub."
fi

if ! git diff-index --quiet HEAD -- 2>/dev/null; then
  fail "Working tree is not clean. Commit or stash changes before releasing."
fi

REPO="IT-Help-San-Diego/dns-tool"

echo ""
echo -e "${YELLOW}═══════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}  Release Pipeline — ${TAG}${NC}"
echo -e "${YELLOW}  repo: ${REPO}${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════${NC}"
echo ""

echo -e "${YELLOW}Step 1/4${NC}: Running release gate (version bump + validation)..."
echo ""
bash scripts/release-gate.sh "$VER"

echo ""
echo -e "${YELLOW}Step 2/4${NC}: Committing release locally..."
git add -A
git status --short
git commit -m "Release ${TAG}"
pass "Committed: Release ${TAG}"

echo ""
echo -e "${YELLOW}Step 3/4${NC}: Syncing to ${REPO}..."
bash scripts/git-sync.sh
pass "${REPO} synced"

echo ""
echo -e "${YELLOW}Step 4/4${NC}: Creating tag ${TAG}..."
git tag -a "${TAG}" -m "${TAG}"
git push origin "${TAG}"
pass "Tag ${TAG} created and pushed"

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Release ${TAG} complete${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
echo ""
echo "What happened:"
echo "  1. All versioned artifacts bumped to ${VER}"
echo "  2. PDFs regenerated (methodology, foundations, manifesto, comm standards)"
echo "  3. CITATION.cff version + date updated"
echo "  4. Go tests + quality gates passed"
echo "  5. Committed locally + synced to ${REPO}"
echo "  6. Tag ${TAG} created"
echo ""
echo "Next (automatic — no action needed):"
echo "  1. GitHub Actions creates Release with SHA256SUMS"
echo "  2. Zenodo auto-archives the GitHub Release"
echo ""
echo "Verify:"
echo "  - GitHub: https://github.com/${REPO}/releases/tag/${TAG}"
echo "  - Zenodo: https://zenodo.org/doi/10.5281/zenodo.18854899"
echo ""
