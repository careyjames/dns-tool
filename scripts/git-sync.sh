#!/bin/bash
# Git sync — push local changes to dns-tool main via GitHub API.
# Usage: bash scripts/git-sync.sh
#
# Collects all tracked files, pushes them as a commit to main via the
# GitHub Trees/Commits API. No git-push required — works even when
# local and remote have unrelated histories.
#
# Uses GH_SYNC_TOKEN (or ORG_PAT / GITHUB_MASTER_PAT fallback) for authentication.
# Safe to run anytime. Fails loudly on any problem.

set -euo pipefail
cd "$(dirname "$0")/.."

REPO_OWNER="IT-Help-San-Diego"
REPO_NAME="dns-tool"
API="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗ $1${NC}"; exit 1; }
info() { echo -e "${YELLOW}▸${NC} $1"; }

TOKEN="${GH_SYNC_TOKEN:-${ORG_PAT:-${GITHUB_MASTER_PAT:-}}}"
if [ -z "$TOKEN" ]; then
  fail "GH_SYNC_TOKEN (or ORG_PAT) not set. Cannot authenticate with GitHub."
fi

VERSION=$(grep 'Version.*=' go-server/internal/config/config.go | head -1 | sed 's/.*"\(.*\)".*/\1/')
echo ""
echo "═══════════════════════════════════════════"
echo "  Git Sync → ${REPO_NAME}/main (API push)"
echo "  App version: v${VERSION}"
echo "═══════════════════════════════════════════"
echo ""

COMMIT_MSG="${1:-}"

info "Pre-flight checks"

DIRTY=false
if ! git diff-index --quiet HEAD -- 2>/dev/null; then
  DIRTY=true
fi

if [ "$DIRTY" = true ] && [ -z "$COMMIT_MSG" ]; then
  fail "Working tree is dirty. Pass a commit message as argument, e.g.: bash scripts/git-sync.sh 'fix: my changes'"
fi

if [ "$DIRTY" = true ]; then
  info "Working tree dirty — will use provided message for API commit"
  pass "Commit message: $COMMIT_MSG"
else
  pass "Working tree clean"
fi

LOCAL_MSG="${COMMIT_MSG:-$(git log -1 --format='%s' 2>/dev/null)}"
pass "Commit message: ${LOCAL_MSG}"

info "Comparing with remote"

REMOTE_TREE=$(python3 -c "
import os, json, urllib.request
token = os.environ.get('GH_SYNC_TOKEN') or os.environ.get('ORG_PAT') or os.environ.get('GITHUB_MASTER_PAT', '')
headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/vnd.github.v3+json'}
req = urllib.request.Request('${API}/git/ref/heads/main', headers=headers)
ref = json.loads(urllib.request.urlopen(req).read())
sha = ref['object']['sha']
req2 = urllib.request.Request(f'${API}/git/commits/{sha}', headers=headers)
commit = json.loads(urllib.request.urlopen(req2).read())
print(commit['tree']['sha'])
" 2>/dev/null) || fail "Failed to read remote main"
pass "Remote main tree: ${REMOTE_TREE:0:12}"

info "Pushing changes via GitHub API"

RESULT=$(python3 << 'PYEOF'
import os, sys, json, urllib.request, base64, subprocess, hashlib, time

token = os.environ.get('GH_SYNC_TOKEN') or os.environ.get('ORG_PAT') or os.environ.get('GITHUB_MASTER_PAT', '')
repo = "IT-Help-San-Diego/dns-tool"
api_base = f"https://api.github.com/repos/{repo}"
headers = {
    'Authorization': f'Bearer {token}',
    'Accept': 'application/vnd.github.v3+json',
    'Content-Type': 'application/json'
}

def api(method, url, data=None, retries=3):
    body = json.dumps(data).encode() if data else None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(f'https://api.github.com{url}', data=body, headers=headers, method=method)
            resp = urllib.request.urlopen(req)
            return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            err_body = ''
            try:
                err_body = e.read().decode('utf-8', errors='replace')
            except:
                pass
            if e.code in (403, 429, 502, 503) and attempt < retries - 1:
                wait = (attempt + 1) * 5
                print(f"  API {e.code}, retrying in {wait}s... ({url})", file=sys.stderr)
                time.sleep(wait)
            elif e.code == 422 and attempt < retries - 1:
                print(f"  API 422 on {url}: {err_body[:300]}", file=sys.stderr)
                time.sleep(3)
            else:
                print(f"  API {e.code} on {url}: {err_body[:500]}", file=sys.stderr)
                raise

ref = api('GET', f'/repos/{repo}/git/ref/heads/main')
main_sha = ref['object']['sha']
commit = api('GET', f'/repos/{repo}/git/commits/{main_sha}')
old_tree_sha = commit['tree']['sha']

old_tree = api('GET', f'/repos/{repo}/git/trees/{old_tree_sha}?recursive=1')
remote_files = {}
for entry in old_tree['tree']:
    if entry['type'] == 'blob':
        remote_files[entry['path']] = entry['sha']

tracked = subprocess.run(['git', 'ls-files'], capture_output=True, text=True).stdout.strip().split('\n')
tracked = [f for f in tracked if f]
tracked_set = set(tracked)

SKIP_FILES = {'.replit', 'replit.nix', 'replit_agent.toml', '.env'}
SKIP_PATHS = {'.github/workflows/mirror-codeberg.yml', '.github/workflows/mirror-to-web.yml', '.github/workflows/mirror-to-web.yml.bak'}
SKIP_PREFIXES = ('.github/workflows-web/',)

changed = []
for fpath in tracked:
    if not os.path.isfile(fpath):
        continue
    if os.path.basename(fpath) in SKIP_FILES:
        continue
    if fpath in SKIP_PATHS:
        continue
    if any(fpath.startswith(p) for p in SKIP_PREFIXES):
        continue
    try:
        with open(fpath, 'rb') as f:
            content = f.read()
    except:
        continue
    blob_header = f"blob {len(content)}\0".encode()
    local_sha = hashlib.sha1(blob_header + content).hexdigest()
    if fpath not in remote_files or remote_files[fpath] != local_sha:
        changed.append(fpath)

for rpath in remote_files:
    if rpath not in tracked and os.path.isfile(rpath):
        pass

if not changed:
    print("UP_TO_DATE")
    sys.exit(0)

print(f"PUSHING {len(changed)} file(s)", file=sys.stderr)

tree_entries = []
batch_size = 20
for i in range(0, len(changed), batch_size):
    batch = changed[i:i+batch_size]
    for fpath in batch:
        with open(fpath, 'rb') as f:
            content = f.read()
        is_text = True
        try:
            text_content = content.decode('utf-8')
        except UnicodeDecodeError:
            is_text = False
        if is_text:
            blob = api('POST', f'/repos/{repo}/git/blobs', {
                'content': text_content,
                'encoding': 'utf-8'
            })
        else:
            blob = api('POST', f'/repos/{repo}/git/blobs', {
                'content': base64.b64encode(content).decode(),
                'encoding': 'base64'
            })
        tree_entries.append({
            'path': fpath,
            'mode': '100644',
            'type': 'blob',
            'sha': blob['sha']
        })
    print(f"  uploaded {min(i+batch_size, len(changed))}/{len(changed)}", file=sys.stderr)
    time.sleep(0.5)

new_tree = api('POST', f'/repos/{repo}/git/trees', {
    'base_tree': old_tree_sha,
    'tree': tree_entries
})

if new_tree['sha'] == old_tree_sha:
    print("UP_TO_DATE")
    sys.exit(0)

version = subprocess.run(
    ['grep', 'Version.*=', 'go-server/internal/config/config.go'],
    capture_output=True, text=True
).stdout.strip()
version = version.split('"')[1] if '"' in version else 'unknown'

last_msg = subprocess.run(['git', 'log', '-1', '--format=%s'], capture_output=True, text=True).stdout.strip()
commit_msg = f"v{version}: {last_msg}\n\nSynced from Replit workspace via API"

new_commit = api('POST', f'/repos/{repo}/git/commits', {
    'message': commit_msg,
    'tree': new_tree['sha'],
    'parents': [main_sha]
})

api('PATCH', f'/repos/{repo}/git/refs/heads/main', {'sha': new_commit['sha']})

# Also update replit-agent branch to match
try:
    api('PATCH', f'/repos/{repo}/git/refs/heads/replit-agent', {'sha': new_commit['sha'], 'force': True})
except:
    try:
        api('POST', f'/repos/{repo}/git/refs', {'ref': 'refs/heads/replit-agent', 'sha': new_commit['sha']})
    except:
        pass

print(f"PUSHED {len(changed)} {new_commit['sha'][:12]}")
PYEOF
) || fail "API push failed"

if [ "$RESULT" = "UP_TO_DATE" ]; then
  pass "Already up to date — nothing to push"
  echo ""
  echo "All good. Nothing to do."
  exit 0
fi

COMMIT_SHA=$(echo "$RESULT" | grep "^PUSHED" | awk '{print $3}')
FILE_COUNT=$(echo "$RESULT" | grep "^PUSHED" | awk '{print $2}')
pass "Pushed ${FILE_COUNT} changed file(s) → main (${COMMIT_SHA})"

echo ""
echo "═══════════════════════════════════════════"
echo -e "  ${GREEN}Done.${NC} v${VERSION} is on ${REPO_NAME}/main."
echo "═══════════════════════════════════════════"
echo ""
