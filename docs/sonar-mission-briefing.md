# SonarCloud Mission Briefing

## Date: March 28, 2026
## Current Version: 26.40.15
## Target Projects: `dns-tool-full` (intel) + `dns-tool-web` (public mirror)

---

## Current State Summary

### Changes Applied (v26.40.15 Cleanup)

#### GitHub Actions Fixes
- **Removed empty `mirror-codeberg.yml`** — was 0 bytes, causing GitHub Actions parse errors on every push
- **Hardened web `sonarcloud.yml`** — removed `continue-on-error: true`, added proper test skip patterns and coverage verification
- **Hardened web `ci.yml`** — added proper OSS binary build, `go vet`, and test execution with correct skip patterns

#### SonarCloud Configuration Fixes
- **Enhanced `sonar-project.properties` web transformation** — both `mirror-to-web.yml` and `scripts/sync-to-web.sh` now properly strip ALL intel-only multicriteria rules (probe, admin_probes, `_intel.go` files), clean coverage exclusions, and update the multicriteria key list
- **Previous exclusions preserved** — `AD0639176-snapshot.html` (frozen third-party document) remains excluded

#### JavaScript Modernization (Templates)
- **`var` → `const`/`let` sweep** across all templates:
  - `corpus.html` — `var` → `const`, functions-in-loops fixed (extracted named handlers)
  - `video_forgotten_domain.html` — `var` → `const`
  - `remediation.html` — `var` → `const`, functions-in-loops fixed
  - `owl_semaphore.html` — `var` → `const`
  - `signature.html` — `var` → `const`
  - `results_covert.html` — `var` → `const`
  - `topology.html` — bulk `var` → `let` conversion (~480 declarations)
- **Static directory sync** — `go-server/static/js/main.js` synced to `static/js/main.js`

---

## SonarCloud Project Structure

### Canonical Projects
| Project Key | Name | Repo |
|---|---|---|
| `dns-tool-full` | DNS Tool | IT-Help-San-Diego/dns-tool |

### Redundant Projects (Delete from SonarCloud Admin)
- `careyjames_dns-tool` — auto-imported duplicate
- `careyjames_dns-tool-intel` — auto-imported duplicate (retired)
- `dns-tool-web` — retired (consolidated into dns-tool-full)
- `careyjames_dns-tool-intel` — auto-imported duplicate (retired)

---

## Quality Gate Configuration

### DNS Tool (`dns-tool-full`)
- Full test suite with `-tags intel`
- Coverage profile generated with `coverprofile=coverage.out`
- All multicriteria suppressions documented in `sonar-project.properties`
- Coverage exclusions: dbq, server main, probe binary, templates, tools, static assets

---

## Workflow Matrix

### Workflows
| Workflow | Purpose | Status |
|---|---|---|
| `ci.yml` | Build & test (intel + OSS paths) | Active |
| `sonarcloud.yml` | Full SonarCloud analysis with coverage | Active |
| `dependency-audit.yml` | govulncheck + npm audit | Active |
| `backup-offsite.yml` | Mirror to off-site-backup | Active |

---

## Intentional Suppressions (sonar-project.properties)

All suppressions are documented with rationale in `sonar-project.properties`. Categories:
- **TLS/SSH security diagnostics** — probe and analyzer intentionally bypass certificate verification
- **Hardcoded DNS resolver IPs** — well-known public DNS services (8.8.8.8, 1.1.1.1, etc.)
- **HTML email compatibility** — bgcolor attributes and table layout for email client compatibility
- **Bootstrap ARIA patterns** — framework-managed accessibility (collapse, tabs)
- **Video subtitles** — decorative/demo animations without spoken content
- **CSS contrast** — dark theme, print stylesheet, and severity color coding
- **JavaScript patterns** — Math.random() for UI animation, empty catch blocks for graceful degradation
- **Go complexity** — force-directed graph algorithm, multi-path handler resolution
- **Go style** — var declaration preferences, background context for async operations

---

## Important Constraints
- **SRI hashes**: After ANY change to `static/js/main.js` or CSS, rebuild the Go binary. SRI hashes are computed at server startup.
- **Two static directories**: `go-server/static/` and `static/` must stay in sync.
- **CSP nonces**: All inline scripts use `nonce="{{.CspNonce}}"`. Use `addEventListener` in nonce'd script blocks.
- **Build tags**: Changes must build with both default (OSS) and `-tags intel` configurations.
- **Standing Gates**: Lighthouse 100, Observatory 145+ (A+), SonarCloud A/A/A are non-negotiable.
