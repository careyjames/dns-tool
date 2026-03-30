# DNS Tool — Architecture

## High-Level Architecture
```
Client (Browser/PWA)
  │
  ▼
Gin Router (go-server/cmd/server/main.go)
  │
  ├─ Middleware Stack ──────────────────────────────┐
  │   ├─ Security Headers (CSP, HSTS, COOP, CORP)  │
  │   ├─ CSRF Protection (double-submit cookie)     │
  │   ├─ Rate Limiter (8 req/60s per IP)            │
  │   ├─ Session Management (cookie + DB)           │
  │   └─ Analytics (cookieless fingerprint)         │
  │                                                 │
  ├─ Handlers ──────────────────────────────────────┤
  │   ├─ AnalysisHandler.Analyze (POST /analyze)    │
  │   ├─ AnalysisHandler.ViewAnalysis (GET /analysis)│
  │   ├─ StaticHandler (favicon, BIMI, sitemap)     │
  │   ├─ HistoryHandler, DossierHandler             │
  │   ├─ AdminHandler (ops, probes, users)          │
  │   └─ ProxyHandler (BIMI logo proxy)             │
  │                                                 │
  ├─ Analyzer (Orchestrator) ───────────────────────┤
  │   ├─ SPF, DKIM, DMARC, DNSSEC, DANE/TLSA       │
  │   ├─ BIMI, MTA-STS, TLS-RPT, CAA               │
  │   ├─ Multi-Resolver Consensus (5 resolvers)     │
  │   └─ Provider Intelligence, IP Intel            │
  │                                                 │
  ├─ Intelligence Engines ──────────────────────────┤
  │   ├─ ICIE (Integrated Confidence in Ingested Evidence) │
  │   ├─ ICAE (Intelligence Confidence Audit Engine) │
  │   └─ ICuAE (Intelligence Currency Assurance Engine) │
  │                                                 │
  └─ PostgreSQL ────────────────────────────────────┘
```

## Go Package Layout
```
go-server/
├── cmd/server/
│   └── main.go              # Entry point, router setup, DI
├── internal/
│   ├── analyzer/            # DNS protocol analysis (largest package)
│   │   ├── orchestrator.go  # Parallel task runner with semaphore
│   │   ├── spf.go, dkim.go, dmarc.go, dnssec.go, dane.go
│   │   ├── bimi.go, mtasts.go, tlsrpt.go, caa.go
│   │   ├── emailheader.go   # RFC 5322 header parsing
│   │   ├── ipinfo.go        # IP intelligence
│   │   ├── securitytrails.go
│   │   ├── *_oss.go         # Open-source stubs (build tag: !intel)
│   │   └── *_test.go
│   ├── config/              # Configuration loading from env vars
│   ├── db/                  # Database connection pool
│   ├── dbq/                 # SQLC-generated type-safe queries
│   ├── dnsclient/           # Multi-resolver DNS querying
│   ├── handlers/            # HTTP handlers (analysis, history, admin, etc.)
│   ├── icae/                # Confidence audit engine
│   ├── icuae/               # Currency assurance engine
│   ├── middleware/          # Security, auth, rate limiting, analytics
│   ├── scanner/             # CISA feed, vulnerability scanning
│   └── templates/           # Template helper functions (SRI, version URLs)
├── db/
│   └── migrations/          # SQL migration files
└── sqlc.yaml                # SQLC configuration
```

## Static Asset Structure
```
static/
├── css/
│   ├── custom.css           # Main stylesheet (source)
│   ├── custom.min.css       # Minified (CSSO)
│   └── fontawesome-subset.min.css
├── js/
│   ├── main.js              # Frontend logic (source)
│   ├── main.min.js          # Minified (Terser)
│   └── foundation.js        # Custom Bootstrap supplement
├── images/
│   ├── owl-of-athena.png    # Brand logo (512x512)
│   ├── owl-of-athena-{160,240}.{png,webp}  # Responsive variants
│   └── diagrams/            # Architecture/methodology diagrams
├── vendor/
│   └── katex/               # Self-hosted KaTeX
├── webfonts/                # FontAwesome WOFF2
├── bimi-logo.svg            # BIMI brand indicator (SVG Tiny PS)
├── favicon.svg              # Vector favicon
├── sw.js                    # Service worker
├── manifest.json            # PWA manifest
├── robots.txt, llms.txt, llms-full.txt
└── .well-known/             # Security.txt, etc.
```

## Template Hierarchy
```
go-server/templates/
├── _head.html               # <head> with CSP nonces, SRI, meta
├── _nav.html                # Navigation bar, version badge
├── _footer.html             # Global footer with owl logo
├── _flash.html              # Alert/notification messages
├── index.html               # Landing page with domain search
├── results.html             # Engineer's Report (technical)
├── results_executive.html   # Executive's Report (high-level)
├── results_covert.html      # Covert Recon Mode
├── approach.html            # Methodology page
├── confidence.html          # Confidence framework page
├── dossier.html             # Domain dossier
├── history.html             # Scan history
├── stats.html               # Analytics dashboard
├── admin_ops.html           # Admin operations
├── admin_probes.html        # Probe fleet management
└── (others)                 # Zone, badge, toolkit, etc.
```

## Request Flow
1. **`main.go`** — Loads config, initializes DB pool, creates middleware stack, builds Gin router
2. **Router** — Maps HTTP methods/paths to handler functions
3. **Middleware** — CSP nonce injection, CSRF validation, rate limiting, session loading
4. **Handler** — Extracts domain from form/query, calls `Analyzer.AnalyzeDomain()`
5. **Orchestrator** — Runs parallel DNS analysis tasks with semaphore-controlled workers
6. **Resolvers** — Each task queries 5 DNS resolvers for consensus validation
7. **ICIE/ICAE/ICuAE** — Post-analysis confidence scoring and currency validation
8. **Template Rendering** — Results injected into Go template, HTML returned to client

## Repository Structure
| Repository | Visibility | Purpose |
|------------|-----------|---------|
| `IT-Help-San-Diego/dns-tool` | **Public** | Single-repo: webapp + intel (BUSL-1.1 licensed) |
| `IT-Help-San-Diego/dns-tool-cli` | **Public** | Future hacker CLI terminal app |

## Open-Core Build Model
- **OSS build** (`go build`): Uses `*_oss.go` stubs — return safe non-nil defaults, never errors
- **Intel build** (`go build -tags intel`): Uses `*_intel.go` with proprietary logic
- Build tag: `//go:build !intel` (OSS) vs `//go:build intel` (intel)
