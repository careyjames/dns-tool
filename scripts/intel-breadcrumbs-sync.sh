#!/bin/bash
# Intel Breadcrumbs Sync — pull key docs from private dns-tool repo.
# Usage: bash scripts/intel-breadcrumbs-sync.sh
#
# Downloads PROJECT_CONTEXT.md, EVOLUTION.md, and EVOLUTION_APPEND_* files
# from the private Intel repo into .intel/breadcrumbs/ (gitignored).
# Uses the Replit GitHub integration for authentication.

set -euo pipefail
cd "$(dirname "$0")/.."

DEST=".intel/breadcrumbs"
mkdir -p "$DEST"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}✓${NC} $1"; }
info() { echo -e "${YELLOW}▸${NC} $1"; }

info "Syncing Intel breadcrumbs from IT-Help-San-Diego/dns-tool..."

node -e '
const fs = require("fs");
const path = require("path");

const REPO = "IT-Help-San-Diego/dns-tool";
const BRANCH = "main";
const DEST = process.argv[1];

const FILES = [
  "PROJECT_CONTEXT.md",
  "EVOLUTION.md",
  "ROADMAP.md",
  "MASTER_COPY.md",
  "INTEL_METHODOLOGY.md",
  "FILELIST.md",
  "STUB_AUDIT.md",
  "docs/PROJECT_CONTEXT.md",
  "docs/ARCHITECTURE_CLASSIFIED.md",
  "docs/INTELLIGENCE_ENGINE.md",
  "docs/BOUNDARY_MATRIX.md",
  "docs/BUILD_TAG_STRATEGY.md",
  "docs/EVOLUTION_APPEND_20260223.md",
  "docs/EVOLUTION_APPEND_20260224.md",
  "docs/EVOLUTION_APPEND_20260302.md",
  "docs/EVOLUTION_APPEND_20260304.md",
  "docs/EVOLUTION_APPEND_20260307.md",
];

async function getToken() {
  const hostname = process.env.REPLIT_CONNECTORS_HOSTNAME;
  const xReplitToken = process.env.REPL_IDENTITY
    ? "repl " + process.env.REPL_IDENTITY
    : process.env.WEB_REPL_RENEWAL
    ? "depl " + process.env.WEB_REPL_RENEWAL
    : null;
  if (!xReplitToken || !hostname) {
    const pat = process.env.GITHUB_MASTER_PAT;
    if (pat) return pat;
    throw new Error("No auth available");
  }
  const res = await fetch(
    "https://" + hostname + "/api/v2/connection?include_secrets=true&connector_names=github",
    { headers: { Accept: "application/json", X_REPLIT_TOKEN: xReplitToken } }
  );
  const data = await res.json();
  const conn = data.items?.[0];
  return conn?.settings?.access_token || conn?.settings?.oauth?.credentials?.access_token;
}

(async () => {
  const token = await getToken();
  let ok = 0, skip = 0;
  for (const f of FILES) {
    const url = "https://api.github.com/repos/" + REPO + "/contents/" + f + "?ref=" + BRANCH;
    const res = await fetch(url, {
      headers: { Authorization: "Bearer " + token, Accept: "application/vnd.github.v3+json" }
    });
    if (!res.ok) { console.error("SKIP " + f + " (" + res.status + ")"); skip++; continue; }
    const data = await res.json();
    const content = Buffer.from(data.content, "base64").toString("utf-8");
    const destPath = path.join(DEST, f.replace(/\//g, "_"));
    fs.writeFileSync(destPath, content);
    console.log("  OK " + f);
    ok++;
  }
  console.log("Done: " + ok + " synced, " + skip + " skipped");
})();
' "$DEST"

echo ""
info "Breadcrumbs stored in ${DEST}/"
ls "$DEST"/ 2>/dev/null
echo ""
pass "Intel breadcrumbs synced."
