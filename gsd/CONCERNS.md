# DNS Tool — Technical Debt & Concerns

## Critical
- **BIMI SVG Compliance**: `static/bimi-logo.svg` uses SVG Tiny PS headers but contains an embedded PNG via `<image>` data URI. Strict BIMI validators may reject this. The artwork is high-quality and renders correctly in all browsers, but a true SVG Tiny PS compliant version with vector paths would be ideal. Converting the detailed owl-of-athena artwork to vector paths without quality loss requires professional SVG authoring (not automated tracing).
- **favicon.svg**: Same pattern — embedded PNG data URI instead of vector paths. Works in all browsers but isn't a "true" vector favicon.

## High Priority
- **Large Files Needing Refactor**:
  - `go-server/internal/handlers/analysis.go` (~1,683 lines) — handles Standard, Covert, Executive report modes, integrity hashing, drift detection. Should split by report type.
  - `go-server/internal/analyzer/emailheader.go` (~71 KB) — email header parsing is complex but could be split into sub-modules.
  - `go-server/templates/results.html` — very large template, consider partial extraction.

- **Coverage Boost File Sprawl**: 27 files named `coverage_boost*.go` across handlers/ and analyzer/. These were added to hit coverage metrics but create directory clutter. Should be consolidated into primary `_test.go` files.

## Medium Priority
- **Stubs Directory**: Root `stubs/` directory contains files mirroring `go-server/internal/analyzer/` OSS stubs. Potential confusion about which is canonical. Clarify or remove.
- **Temporary Artifacts**: Files like `sedtgBx90`, `sedu0Dj8L` in root are `sed` artifacts that should be cleaned up.
- **IP-audit-log.txt**: Exists in root — should be in a dedicated logs directory or gitignored.
- **Error Handling Gaps**:
  - `handlers/history.go:72` — JSON unmarshal error not logged
  - `handlers/dossier.go` — similar pattern
  - `middleware/auth.go:46` — `UpdateSessionLastSeen` error explicitly ignored in goroutine

## Low Priority
- **Custom OAuth**: Uses hand-rolled OAuth 2.0 + PKCE instead of established libraries. Functional but higher maintenance burden.
- **Intel Sync Complexity**: The two-repo architecture (OSS stubs + intel repo) adds cognitive overhead. Well-architected but requires disciplined synchronization.
- **Go Version**: `go.mod` specifies `go 1.25.5` — ensure this aligns with target deployment environments.

## Documentation Gaps
- **Internal docs (gsd/)**: Internal breadcrumbs and documentation need systematic update.
- **MISSION.md**: Strategic conversations should be documented as intel breadcrumbs per user preferences.
- **Changelog**: Recent version bumps (26.34.15 → 26.34.18) need corresponding changelog entries for the public repo.
