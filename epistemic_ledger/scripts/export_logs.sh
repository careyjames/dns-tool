#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="$(cd "$(dirname "$0")/.." && pwd)/generated"
mkdir -p "$OUT_DIR"

git log --pretty=format:"%h | %ad | %s" --date=iso \
  > "$OUT_DIR/git_log_summary.txt"

git log \
  --grep="incorrect" \
  --grep="interpret" \
  --grep="recommend" \
  --grep="scoring" \
  --grep="confidence" \
  --grep="authorization" \
  -i --date=iso --pretty=format:"%h | %ad | %s" \
  > "$OUT_DIR/git_log_filtered.txt"
