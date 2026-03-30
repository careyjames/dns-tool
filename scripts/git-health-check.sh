#!/bin/bash
# Git Health Check — run at session start
#
# MODES:
#   Default (no flags): Read-only. Safe from any context (agent or Shell).
#     Reports sync status and environment drift only.
#
#   --repair: Full repair mode. Run from Shell tab ONLY.
#     Clears lock files, aborts rebases, reattaches HEAD, updates tracking refs.
#     The Replit platform kills agent processes that write to .git (exit 254).
#
# PLATFORM FACTS (empirically tested Feb 18, 2026):
#   SAFE (read-only):  git rev-parse, git branch, git log, git diff,
#                      git ls-remote, git push (via PAT), cat .git/*
#   KILLS PROCESS:     git status, git fetch, git update-ref,
#                      echo > .git/*, rm .git/*.lock
#                      ANY write to .git/ → exit 254 + process tree killed
#   Error message:     "Avoid changing .git repository. When git operations
#                       are needed, only allow users who have proper git
#                       expertise to perform these actions themselves
#                       through shell tools."
#
# HISTORY: Stale lock files caused PUSH_REJECTED errors, stalled rebases,
# and wasted nearly a full day of production (Feb 2026).

cd /home/runner/workspace 2>/dev/null || exit 0

REPAIR=false
for arg in "$@"; do
  case "$arg" in
    --repair|--full) REPAIR=true ;;
    --read-only)     REPAIR=false ;;
  esac
done

FIXED=0

if [ "$REPAIR" = true ]; then

  # 1. Remove ALL stale lock files — comprehensive sweep
  LOCK_COUNT=0
  while IFS= read -r lockfile; do
    if [ -n "$lockfile" ]; then
      rm -f "$lockfile" 2>/dev/null && echo "Removed stale $lockfile" && LOCK_COUNT=$((LOCK_COUNT+1))
    fi
  done < <(find .git -name "*.lock" -type f 2>/dev/null)

  if [ "$LOCK_COUNT" -gt 0 ]; then
    FIXED=$((FIXED+LOCK_COUNT))
    echo "Cleared $LOCK_COUNT lock file(s)"
  fi

  # 2. Abort interrupted merge
  if [ -f ".git/MERGE_HEAD" ] || [ -f ".git/MERGE_MSG" ] || [ -f ".git/MERGE_MODE" ]; then
    git merge --abort 2>/dev/null && echo "Aborted interrupted merge" && FIXED=$((FIXED+1))
    rm -f .git/MERGE_HEAD .git/MERGE_MSG .git/MERGE_MODE 2>/dev/null
  fi

  # 3. Abort interrupted rebase
  if [ -d ".git/rebase-merge" ] || [ -d ".git/rebase-apply" ]; then
    git rebase --abort 2>/dev/null && echo "Aborted interrupted rebase" && FIXED=$((FIXED+1))
    rm -rf .git/rebase-merge .git/rebase-apply 2>/dev/null
  fi

  # 4. Fix detached HEAD — reattach to main
  CURRENT_HEAD=$(cat .git/HEAD 2>/dev/null)
  if echo "$CURRENT_HEAD" | grep -qv "ref:"; then
    printf 'ref: refs/heads/main\n' > .git/HEAD 2>/dev/null && echo "Reattached HEAD to main" && FIXED=$((FIXED+1))
  fi

  # 5. Update tracking refs
  echo "Updating tracking refs..."
  git fetch 2>/dev/null || true

  GITHUB_SHA=$(git ls-remote origin main 2>/dev/null | awk '{print $1}')
  CURRENT_REF=$(cat .git/refs/remotes/origin/main 2>/dev/null)
  if [ -n "$GITHUB_SHA" ] && [ "$CURRENT_REF" != "$GITHUB_SHA" ]; then
    git update-ref refs/remotes/origin/main "$GITHUB_SHA" 2>/dev/null \
      || echo "$GITHUB_SHA" > .git/refs/remotes/origin/main 2>/dev/null \
      || echo "  Tracking ref update failed"
    echo "  Tracking ref updated to ${GITHUB_SHA:0:7}"
  elif [ -n "$GITHUB_SHA" ]; then
    echo "  Tracking ref already current"
  fi

  # 6. Report status
  if [ $FIXED -eq 0 ]; then
    echo "Git health: CLEAN — zero lock files, no interrupted operations"
  else
    echo "Git health: fixed $FIXED issue(s)"
  fi

else
  echo "[read-only mode — .git repairs skipped (use --repair from Shell tab)]"
fi

# ── Everything below is read-only and safe from any context ──

git branch --show-current 2>/dev/null || true

# 6. Sync status via ls-remote (read-only, safe everywhere)
if [ -n "$GITHUB_MASTER_PAT" ]; then
  LOCAL_SHA=$(git rev-parse HEAD 2>/dev/null)
  REMOTE_SHA=$(git ls-remote "https://${GITHUB_MASTER_PAT}@github.com/IT-Help-San-Diego/dns-tool.git" refs/heads/main 2>/dev/null | awk '{print $1}')
  if [ -n "$REMOTE_SHA" ]; then
    if [ "$LOCAL_SHA" = "$REMOTE_SHA" ]; then
      echo "Sync status: MATCHED — local HEAD = GitHub HEAD ($LOCAL_SHA)"
    else
      echo "Sync status: MISMATCH"
      echo "  Local:  $LOCAL_SHA"
      echo "  GitHub: $REMOTE_SHA"
    fi
  fi
fi

# 7. Drift Cairn — environment drift check (always runs)
# Wrapper function prevents future shell edits from reintroducing gating bugs.
# Exit codes: 0=clean, 10=drift detected, 20=no manifest, 1=error
# NOTE: This script must NOT use set -e. Drift exit 10 is informational, not a failure.
run_cairn() {
  local cmd="$1"
  local baseline="${2:-}"
  local exit_code=0
  if [ -n "$baseline" ]; then
    bash scripts/drift-cairn.sh "$cmd" "$baseline" 2>/dev/null || exit_code=$?
  else
    bash scripts/drift-cairn.sh "$cmd" 2>/dev/null || exit_code=$?
  fi
  return $exit_code
}

if [ -f "scripts/drift-cairn.sh" ]; then
  echo ""
  CAIRN_EXIT=0
  run_cairn check || CAIRN_EXIT=$?
  if [ "$CAIRN_EXIT" -eq 20 ]; then
    echo "  (Taking initial snapshot — baseline: auto-bootstrap)"
    run_cairn snapshot auto-bootstrap || true
  fi
fi
