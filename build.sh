#!/bin/sh
# cache-bust: 2026-03-23T23:10Z — workspace cleaned from 7.7GB to 1.7GB
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

VERSION=$(grep 'Version.*=' "$SCRIPT_DIR/go-server/internal/config/config.go" | head -1 | sed 's/.*"\(.*\)".*/\1/')
GIT_COMMIT=$(git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS="-s -w \
  -X dnstool/go-server/internal/config.GitCommit=${GIT_COMMIT} \
  -X dnstool/go-server/internal/config.BuildTime=${BUILD_TIME}"

export GOCACHE=/tmp/go-build-cache
export GOMODCACHE=/tmp/go-mod-cache

cd "$SCRIPT_DIR/go-server"
CGO_ENABLED=0 GONOSUMCHECK=1 GIT_DIR=/dev/null go build \
  -buildvcs=false \
  -trimpath \
  -ldflags "$LDFLAGS" \
  -tags netgo \
  -o /tmp/dns-tool-new \
  ./cmd/server/
cd "$SCRIPT_DIR"
mv /tmp/dns-tool-new dns-tool-server-new
mv dns-tool-server-new dns-tool-server

rm -rf /tmp/go-build-cache /tmp/go-mod-cache 2>/dev/null || true

if [ "$1" = "--deploy" ]; then
  echo "Deployment build — cleaning large non-runtime files"
  echo "Before cleanup:"
  du -sh . 2>/dev/null || true

  rm -rf .git.backup* 2>/dev/null || true

  if [ -d .git ]; then
    echo "Removing .git directory — not needed at runtime"
    rm -rf .git
  fi

  rm -rf .local .cache .scannerwork .codex .drift .gitpanel \
         exports dnstool-intel-staging .intel \
         attached_assets .canvas artifacts \
         docs/legacy docs/EVOLUTION_APPEND_*.md docs/dns-tool-methodology.pdf \
         EVOLUTION.md PROJECT_CONTEXT.md \
         sonar-project.properties \
         2>/dev/null || true

  find go-server/internal -name '*_test.go' -delete 2>/dev/null || true

  echo "After cleanup:"
  du -sh . 2>/dev/null || true
  echo "Deployment cleanup complete"
fi

echo "Build complete: dns-tool-server (v${VERSION} ${GIT_COMMIT} ${BUILD_TIME})"
ls -la dns-tool-server
