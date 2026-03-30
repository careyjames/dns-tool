#!/bin/bash
# Git Panel Reset — fixes the Replit Git panel showing stale commit counts
# Run from the Shell tab: bash scripts/git-panel-reset.sh
#
# WHY: The agent's push script uses git ls-remote (read-only) for sync
# verification, but the Git panel reads origin/main (the tracking ref).
# A stale .lock file can block the tracking ref from updating, causing
# the panel to show "X commits ahead" even though GitHub is current.
#
# PREVENTION: The agent's push script writes the last-pushed SHA to
# .gitpanel/last_pushed_sha. This script compares that marker against
# origin/main to detect staleness without needing the agent.

cd /home/runner/workspace

echo "=== Git Panel Reset ==="
echo ""

FIXED=0

# Step 1: Clear ALL lock files that block ref updates
LOCKS_FOUND=0
for lockfile in \
  ".git/refs/remotes/origin/main.lock" \
  ".git/objects/maintenance.lock" \
  ".git/refs/heads/main.lock"; do
  if [ -f "$lockfile" ]; then
    rm -f "$lockfile" 2>/dev/null
    echo "  Removed $lockfile"
    FIXED=$((FIXED+1))
    LOCKS_FOUND=$((LOCKS_FOUND+1))
  fi
done

# Sweep any other stale locks
OTHER_LOCKS=$(find .git -name "*.lock" -type f 2>/dev/null || true)
if [ -n "$OTHER_LOCKS" ]; then
  while IFS= read -r lockfile; do
    rm -f "$lockfile" 2>/dev/null && echo "  Removed $lockfile" && FIXED=$((FIXED+1)) && LOCKS_FOUND=$((LOCKS_FOUND+1))
  done <<< "$OTHER_LOCKS"
fi

if [ "$LOCKS_FOUND" -eq 0 ]; then
  echo "  No lock files found (good)"
fi

# Step 1b: Abort interrupted merge (blocks Git panel with "Resolve conflicts" overlay)
if [ -f ".git/MERGE_HEAD" ] || [ -f ".git/MERGE_MSG" ] || [ -f ".git/MERGE_MODE" ]; then
  git merge --abort 2>/dev/null && echo "  Aborted interrupted merge" && FIXED=$((FIXED+1))
  rm -f .git/MERGE_HEAD .git/MERGE_MSG .git/MERGE_MODE 2>/dev/null
fi

# Step 1c: Abort interrupted rebase
if [ -d ".git/rebase-merge" ] || [ -d ".git/rebase-apply" ]; then
  git rebase --abort 2>/dev/null && echo "  Aborted interrupted rebase" && FIXED=$((FIXED+1))
  rm -rf .git/rebase-merge .git/rebase-apply 2>/dev/null
fi

# Step 2: Fetch and force-update tracking ref
echo ""
echo "Fetching latest from GitHub..."
git fetch 2>/dev/null

GITHUB_SHA=$(git ls-remote origin main 2>/dev/null | awk '{print $1}')
CURRENT_REF=$(cat .git/refs/remotes/origin/main 2>/dev/null)

if [ -n "$GITHUB_SHA" ] && [ "$CURRENT_REF" != "$GITHUB_SHA" ]; then
  git update-ref refs/remotes/origin/main "$GITHUB_SHA" 2>/dev/null
  if [ $? -eq 0 ]; then
    echo "  Tracking ref updated to match GitHub: ${GITHUB_SHA:0:7}"
  else
    echo "  update-ref failed — writing ref file directly..."
    echo "$GITHUB_SHA" > .git/refs/remotes/origin/main 2>/dev/null
    echo "  Ref file written: ${GITHUB_SHA:0:7}"
  fi
elif [ -n "$GITHUB_SHA" ]; then
  echo "  Tracking ref already current: ${GITHUB_SHA:0:7}"
else
  echo "  Could not reach GitHub to verify"
fi

# Step 3: Report sync state
echo ""
LOCAL=$(git rev-parse HEAD 2>/dev/null)
REMOTE=$(git rev-parse origin/main 2>/dev/null)
AHEAD=$(git rev-list origin/main..HEAD --count 2>/dev/null || echo "?")

echo "  Local HEAD:  $LOCAL"
echo "  origin/main: $REMOTE"
echo "  Commits ahead: $AHEAD"

# Check marker file from agent's last push
if [ -f ".gitpanel/last_pushed_sha" ]; then
  LAST_PUSHED=$(cat .gitpanel/last_pushed_sha 2>/dev/null)
  echo "  Last agent push: $LAST_PUSHED"
  if [ "$REMOTE" = "$LAST_PUSHED" ] && [ "$AHEAD" != "0" ]; then
    echo ""
    echo "  INFO: origin/main matches the agent's last push."
    echo "  The $AHEAD commit(s) ahead are unpushed local checkpoints."
  fi
fi

echo ""
if [ "$AHEAD" = "0" ]; then
  echo "GIT PANEL: Should now show 0 ahead, 0 behind."
  echo "Close and re-open the Git tab to refresh."
else
  echo "GIT PANEL: $AHEAD commit(s) ahead of origin/main."
  echo "To push them: bash scripts/git-push.sh"
  echo "Or use the Git panel Push button."
fi
echo ""
echo "Done. $FIXED lock file(s) cleared."
