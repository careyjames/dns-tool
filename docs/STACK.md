# DNS Tool — Technology Stack

## Languages
| Language | Role | Version |
|----------|------|---------|
| Go | Backend server, DNS analysis, API | 1.25.5 |
| JavaScript/TypeScript | Frontend logic, E2E tests, automation scripts | ES2022+ |
| SQL | Database schema, queries (PostgreSQL) | PostgreSQL 16 |
| Python | Audit scripts, PDF generation | 3.x |
| HTML/CSS | Templates (Go html/template), styling | HTML5/CSS3 |

## Backend Framework
- **Gin Gonic** (`github.com/gin-gonic/gin`) — HTTP router, middleware, template rendering
- **pgx/v5** (`github.com/jackc/pgx/v5`) — PostgreSQL driver
- **miekg/dns** (`codeberg.org/miekg/dns`) — DNS protocol library
- **Gonum** (`gonum.org/v1/gonum`) — EWMA sigma estimation, numerical analysis
- **google/uuid** — Unique identifier generation

## Frontend
- **Bootstrap 5** — UI components, grid, responsive layout
- **Foundation.js** — Custom lightweight supplement (`static/js/foundation.js`)
- **KaTeX** — Self-hosted LaTeX math rendering (`static/vendor/katex/`)
- **FontAwesome** — Iconography (subset, self-hosted)
- **Service Worker** — PWA offline support (`static/sw.js`)

## Database
- **PostgreSQL** — Primary relational store
- **SQLC** — SQL-to-Go code generation (`go-server/sqlc.yaml`)
- **Migrations** — Raw SQL files in `go-server/db/migrations/`

## Build & Package Management
- **build.sh** — Go compilation with ldflags (version, commit, timestamp)
- **Go Modules** — `go.mod` / `go.sum`
- **NPM** — `package.json` for testing/scripts dependencies
- **UV** — Python dependency management (`pyproject.toml`, `uv.lock`)

## External Services & APIs
| Service | Purpose | Integration Point |
|---------|---------|-------------------|
| Google OAuth 2.0 | User authentication (PKCE S256) | `internal/middleware/auth.go` |
| IPInfo.io | IP geolocation, ASN lookups | `internal/analyzer/ipinfo.go` |
| SecurityTrails | Subdomain discovery, reverse IP | `internal/analyzer/securitytrails.go` |
| OpenPhish | Phishing URL detection | `internal/analyzer/openphish.go` |
| CISA | Known exploited vulnerabilities feed | `internal/scanner/cisa.go` |
| Internet Archive | Wayback Machine automatic archival | `internal/wayback/client.go` |
| Discord | Webhook notifications | Config: `DISCORD_WEBHOOK_URL` |
| Notion | Roadmap synchronization | `scripts/notion-roadmap-sync.mjs` |
| GitHub | Intel sync, CI | `scripts/github-intel-sync.mjs` |
| DoH | DNS-over-HTTPS (Cloudflare, Google) | `internal/dnsclient/` |

## System Tools
| Tool | Purpose |
|------|---------|
| Nmap | DNS server security probing |
| testssl.sh | TLS/SSL analysis |
| Subfinder | Passive subdomain enumeration |
| WeasyPrint | HTML-to-PDF methodology docs |
| SonarQube | Code quality reporting |

## Quality Gates
| Script | Rule ID | Purpose |
|--------|---------|---------|
| `scripts/audit-css-cohesion.js` | R009 | CSS semantic color and opacity validation |
| `scripts/validate-scientific-colors.js` | R010 | Status color spectrum compliance |
| `scripts/feature-inventory.js` | R011 | Feature tracking and consistency |
