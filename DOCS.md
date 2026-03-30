# DNS Tool — Documentation

## Overview

A comprehensive DNS intelligence and OSINT platform for domain security analysis. Built in Go with the Gin framework. Designed for three audiences:

- **Board-level executives**: Quick security posture at a glance
- **IT professionals**: Actionable email security recommendations
- **DNS specialists**: Deep technical record analysis

## Philosophy: No Proprietary Magic

Every conclusion must be independently verifiable using standard commands. The tool operates with strict adherence to RFC standards and observation-based language—never making definitive claims beyond what the data shows.

### Core Principles

1. **Fresh Data**: DNS records are always fetched live (TTL=0, no caching) because domains in trouble often have rapidly changing DNS records, and security incidents require up-to-the-second accuracy.

2. **Verifiable Results**: All analyses include equivalent shell commands users can run themselves for verification.

3. **Observation-Based Language**: Not "Is email encrypted?" but "Transport encryption observed?"

4. **Defensible Caches Only**:
   - RDAP registry data (24h) — registrar information rarely changes
   - DNS History (24h) — prevents excessive API calls to SecurityTrails
   - CT subdomains (1h) — append-only historical data
   - RFC metadata (24h) — reference data that updates slowly

## Symbiotic Security

Traditional DNS security tools treat DNSSEC as the only valid security measure, penalizing domains that skip it. This tool recognizes that enterprises implement security through multiple layers:

### Enterprise DNS Providers

Major cloud and infrastructure DNS providers offer DDoS protection, anycast networks, and 24/7 security monitoring. A domain on a top-tier enterprise DNS provider benefits from operational security measures (DDoS mitigation, anycast, 24/7 monitoring) that complement or partially offset the absence of DNSSEC chain-of-trust validation. These are classified as "Enterprise" in analysis results — acknowledging operational mitigations without equating them to cryptographic assurance (RFC 4033, Section 2).

### Legacy Providers

Certain legacy DNS providers are explicitly blocklisted to prevent false "Enterprise" tagging.

### Government Domains

Domains using .gov, .mil, and equivalent government TLDs operate under strict compliance frameworks with mandatory security requirements. These are recognized as "Government" tier with inherent trust.

### Self-Hosted Enterprise

Large organizations running their own NS infrastructure are detected by multiple nameservers matching the domain and recognized as capable of implementing alternative security.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | Yes | PostgreSQL connection string (e.g., `postgresql://user:pass@host/dbname`) |
| `SESSION_SECRET` | Yes | Session encryption key for CSRF protection |
| `PORT` | No | HTTP listen port (default: `5000`) |
| `PROBE_API_URL` | No | Primary probe fleet node URL |
| `PROBE_API_KEY` | No | Primary probe fleet authentication key |
| `PROBE_API_URL_2` | No | Secondary probe fleet node URL |
| `PROBE_API_KEY_2` | No | Secondary probe fleet authentication key |
| `SMTP_PROBE_MODE` | No | SMTP probe mode: `off` (default) or `remote` |
| `IPFS_PROBE_MODE` | No | IPFS fleet probe mode: `off` (default) or `remote` |
| `GOOGLE_CLIENT_ID` | No | Google OAuth 2.0 client ID |
| `GOOGLE_CLIENT_SECRET` | No | Google OAuth 2.0 client secret |
| `DISCORD_WEBHOOK_URL` | No | Discord notification webhook |
| `SECURITYTRAILS_API_KEY` | No | SecurityTrails API key for DNS history |

## Running the Application

The workflow executes:

```bash
gunicorn --bind 0.0.0.0:5000 --reuse-port --reload main:app
```

This command imports `main.py`, which contains an `os.execvp` trampoline. The trampoline immediately replaces the gunicorn process image with the compiled Go binary (`./dns-tool-server`), so gunicorn never actually starts. The Go binary takes over and binds to port 5000.

## Building

Rebuild the Go binary after any changes to `.go` files:

```bash
cd go-server && GIT_DIR=/dev/null go build -buildvcs=false -o /tmp/dns-tool-new ./cmd/server/
mv /tmp/dns-tool-new dns-tool-server-new && mv dns-tool-server-new dns-tool-server
```

Then restart the "Start application" workflow to reload the binary.

## Running Tests

```bash
cd go-server && go test ./... -v
```

Tests include unit tests, integration tests, golden rules (golden_rules_test.go), and behavioral contract tests.

## Architecture

```
main.py                    # Process trampoline (execs Go binary)
dns-tool-server            # Compiled Go binary
go-server/
  cmd/server/main.go       # Entry point
  cmd/probe/main.go        # Probe agent (Kali fleet nodes)
  internal/
    analyzer/              # DNS analysis engine
      web3.go              # Web3 domain analysis (IPFS, ENS, HNS)
      web3_resolution.go   # ENS/HNS input resolution
      web3_probe.go        # IPFS fleet probe client + consensus
      orchestrator.go      # Analysis orchestration
    handlers/              # HTTP route handlers
    dnsclient/             # Multi-resolver DNS client
    db/                    # PostgreSQL (pgx v5, sqlc)
    middleware/            # Security middleware
    telemetry/             # Caching, metrics
    config/                # Configuration (env vars, probe fleet)
    entitlements/          # Feature tier gating
  templates/               # Server-rendered HTML
  static/                  # CSS, JS, assets
```

## Key Features

### Email Security Analysis
SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI — RFC-compliant parsing and validation for all major email authentication protocols. Includes an Email Header Analyzer for pasting or uploading raw headers to verify authentication results and trace delivery routes.

### DNS Security
DNSSEC chain-of-trust verification, CAA certificate authority restrictions, DANE/TLSA certificate pinning, NS delegation consistency.

### Infrastructure Detection
Automatic enterprise DNS provider recognition, government domain tier classification, edge/CDN detection, SMTP transport validation.

### Web3 Domain Analysis
Detects and analyzes Web3 domain infrastructure via TXT record scanning. ENS `.eth` domains resolved via eth.limo gateway; Handshake TLDs via hnsdns.com/hdns.io resolvers. IPFS content identified through `_dnslink` TXT records. Authority containment prevents gateway infrastructure (NS, DNSSEC, CAA) from contaminating owner posture analysis. Distributed IPFS fleet probing (when `IPFS_PROBE_MODE=remote`) dispatches parallel requests to Kali probe fleet for multi-vantage content persistence verification, redirect divergence detection, and gateway infrastructure fingerprinting. Key files: `web3.go`, `web3_resolution.go`, `web3_probe.go`.

### Intelligence
AI Surface Scanner, CT subdomain discovery, DNS history timeline (SecurityTrails), IP Intelligence, phishing detection.

### Exposure Scanning
Two-tier approach to web security exposure detection:
- **Public Exposure Checks** (always-on): Scans publicly accessible page source and linked JavaScript for exposed secrets, API keys, and credentials.
- **Expanded Exposure Checks** (opt-in): Probes 8 well-known misconfiguration paths (/.env, /.git/config, /.git/HEAD, /.DS_Store, /server-status, /server-info, /wp-config.php.bak, /phpinfo.php) with content validation. Sequential requests with 200ms delays.

**Note**: These are informational reconnaissance checks — not PCI DSS ASV scans, penetration tests, or compliance attestations.

### Posture Scoring
CVSS-aligned risk assessment with actionable remediation recommendations.

### Confidence Engines

Two engines measure the quality of DNS Tool's own intelligence output, applying ICD 203 confidence methodology holistically:

**ICAE (Intelligence Confidence Audit Engine)** — measures analysis *correctness*. 129 deterministic test cases across 9 protocols (SPF, DKIM, DMARC, DANE, DNSSEC, BIMI, MTA-STS, TLS-RPT, CAA) exercised against fixture domains. Five-tier maturity model: Development → Verified → Consistent → Gold → Gold Master. Empirically validated via calibration: 129 cases × 5 resolver scenarios = 645 predictions, Brier Score 0.0018 (excellent), ECE 0.031 (good), using a conservatively calibrated shrinkage estimator. Results surfaced on the `/confidence` page and the homepage hero card.

**ICuAE (Intelligence Currency Audit Engine)** — measures data *timeliness*. 29 deterministic test cases across five dimensions:
- **TTL Compliance** (≥95% target): Do resolvers respect authoritative TTL limits? References RFC 8767 (serve-stale).
- **Completeness** (≥98% target): Are all expected record types collected?
- **Source Credibility** (≥90% target): Multi-resolver consensus strength.
- **Currentness** (<0.5× TTL target): How fresh is the data relative to its TTL?
- **TTL Relevance** (within standard range): Do observed TTLs match expected ranges for each record type?

Grading scale: Excellent (≥90) → Good (≥75) → Adequate (≥50) → Degraded (≥25) → Stale (<25). Each scan generates per-dimension scores, an overall weighted average, and SHA-3-512 provenance hashing. Excellence benchmarks derived from Farsight DNSDB, OpenINTEL, and DNSPerf real-world data.

**Phase 1 Advisory (Live)**: Per-dimension tuning hints with three threshold tiers (≤49 warning, ≤74 info, ≤89 lightbulb) surfaced inline in the Per-Dimension Averages table on the confidence page. Phase 2 (Suggested Config Profiles) and Phase 3 (Adaptive Auto-Tuning with rollback) are on the roadmap.

Standards: ICD 203 (Intelligence Community confidence framework), NIST SP 800-53 SI-7 (information integrity), ISO/IEC 25012 (data quality model).

### Reporting
Dual intelligence products: Engineer's DNS Intelligence Report (comprehensive technical detail) and Executive's DNS Intelligence Brief (concise board-ready summary with security scorecard, risk posture, and priority actions). Both use the same live analysis data — different formats for different audiences. Naming follows IC conventions: "Report" = comprehensive, "Brief" = concise decision-maker version. Configurable TLP classification (default: TLP:AMBER, aligned with CISA Cyber Hygiene practice) with TLP:GREEN and TLP:CLEAR options. JSON export for programmatic consumption.

### Report Integrity
Every analysis generates a SHA-3-512 integrity hash binding domain, analysis ID, timestamp, tool version, and canonicalized results data. Header preview format: `SHA-3: c82f✱✱✱✱ Report Integrity ↓` (4 hex chars + 4 star masks + anchor link to full hash section). Copy-to-clipboard support. Distinct from posture hash (drift detection).

### Internet Archive — Permanent Record
Every successful, non-private, non-scan-flagged analysis is automatically submitted to the Internet Archive via `web.archive.org/save/` in a background goroutine. The snapshot URL is stored in `domain_analyses.wayback_url` and displayed as a green "Archived" badge in the results header plus a dedicated "Internet Archive — Permanent Record" card on Engineer's and Executive's reports. Privacy guards ensure private and scanner-flagged analyses are never archived. This completes a three-layer evidence chain: SHA-3-512 integrity hash + posture hash for drift detection + third-party Wayback Machine archive.

## Critical Pages Registry

`docs/CRITICAL_PAGES.md` is a per-page issue tracking system that:
- Lists every critical page with its template file, sensitive areas, known issues, and resolved history
- Tracks cross-page regressions (when fixing page A breaks page B)
- Documents sensitive shared resources (`_nav.html`, `custom.min.css`, `main.js`, etc.) that affect multiple pages simultaneously
- Must be consulted before any CSS, JS, or template change, and updated when bugs are found or fixed

## Rate Limiting & Abuse Prevention

| Protection | Window | Purpose |
|------------|--------|---------|
| **Rate Limit** | 8 requests/minute per IP | Prevents abuse and network overload |
| **Anti-Repeat** | 15 seconds per domain | Prevents accidental double-clicks during DNS editing |

**Why 15 seconds for anti-repeat?** A sysadmin editing DNS in a registrar panel and switching tabs typically needs 20+ seconds. 15 seconds blocks rapid re-clicks that waste network resources without blocking legitimate edits.

**Note**: There is no "Force Fresh" toggle—every analysis is fresh. The anti-repeat protection is purely double-click prevention, not caching.

## Performance

| Operation | Expected Time | Notes |
|-----------|---------------|-------|
| Domain analysis | 5-30 seconds | Depends on DNS response times and number of queries |
| Page load | < 100ms | Static assets cached aggressively with immutable flags |

## Key Design Decisions

1. **Server-Side Rendering**: All pages rendered server-side using Go `html/template`. No client-side API calls. Better SEO, simpler deployment, inherent CSRF protection.

2. **Concurrent DNS Lookups**: Goroutines enable parallel queries across multiple resolvers with rapid aggregation.

3. **Multi-Resolver Consensus**: Queries Cloudflare, Google, Quad9, OpenDNS, and DNS4EU. Five-resolver consensus reduces resolver-specific anomalies and includes EU-sovereign infrastructure.

4. **CSP with Nonces**: Content Security Policy headers include per-request nonces for inline scripts, blocking XSS attacks while allowing necessary inline code.

5. **Dark Theme UI**: Bootstrap dark theme with custom CSS. Eye-friendly, modern, professional appearance.

6. **Security Middleware**: CSRF, rate limiting, SSRF hardening, security headers, CSP nonces.

7. **Database**: PostgreSQL via `pgx` v5. Queries generated by `sqlc` for type safety.

## Analytics Taxonomy

DNS Tool has two independent analytics systems that measure different things. They are complementary, not redundant.

### Layer 1: Product Analytics (Custom — Primary)

**Source**: `go-server/internal/middleware/analytics.go`, `go-server/internal/handlers/analytics.go`
**Storage**: `site_analytics` and `analysis_stats` tables (PostgreSQL)
**Dashboard**: `/ops/analytics` (admin-only, 30-day trend), `/stats` (public analysis counts)

Operates at the application layer. Intentionally filters out static assets, bots, health checks, and admin requests — only counts meaningful human page views.

| Metric | How It Works |
|--------|-------------|
| Pageviews | Counted per non-static, non-bot request |
| Unique visitors | Daily-rotating SHA3-512(salt + IP + UA) pseudoID — no PII stored, cannot be reconciled across days |
| Analyses run | Incremented on each successful domain analysis |
| Unique domains analyzed | Deduplicated per day |
| Top pages | JSONB map of normalized paths, merged via PostgreSQL `jsonb_object_agg` on flush |
| Top referrers | JSONB map of referring domains, same merge strategy |
| Analysis performance | Success rate, average duration (separate `analysis_stats` table) |

**Privacy model**: No cookies, no persistent IP storage, no PII. Pseudonymous daily IDs rotate with a new salt each day and are never written to the database. Excludes IPs listed in `ANALYTICS_EXCLUDE_IPS` env var. Excludes admin sessions.

**Flush strategy**: In-memory counters with RWMutex, flushed to PostgreSQL every 60 seconds via background goroutine. Final flush on graceful shutdown.

**Best for**: Product engagement, feature adoption, analysis volume, unique domains, scan performance, internal KPIs.

### Layer 2: Edge Analytics (Replit Platform)

**Source**: Replit deployment infrastructure (reverse proxy / load balancer level)
**Dashboard**: Replit project settings → Analytics tab (`replit.com/@careybalboa/DNS-Tool?settings.tab=customerUsage`)
**Storage**: Replit-managed, no programmatic API available

Operates at the HTTP reverse proxy level. Captures every single request hitting the deployment — including service worker fetches, favicon requests, static assets, bot crawlers, and health probes.

| Metric | Notes |
|--------|-------|
| Requests (time series) | All HTTP requests, including assets and bots |
| Unique IP addresses | Raw count, no deduplication across time windows |
| Top URLs | Includes `/sw.js`, favicons, static assets — not filtered |
| Top Referrers | Includes bot referrers (e.g., `ghost-rider/`) |
| HTTP Statuses (24h) | Status code distribution — useful for error rate monitoring |
| Request Durations (ms) | Latency histogram — useful for performance anomaly detection |
| Top Browsers | User-Agent parsing at proxy level |
| Top Devices | OS-level breakdown (includes server/bot OS like "Linux") |
| Top Countries | GeoIP-based country map |

**Best for**: Traffic volume, geographic distribution, latency anomalies, browser/device mix, bot detection, infrastructure health, status code monitoring.

### When Numbers Differ

The two systems will always show different numbers. This is expected and correct:

| Scenario | Custom Analytics | Replit Analytics |
|----------|-----------------|------------------|
| Bot fetches `/sw.js` 2,327 times | Not counted (static asset excluded) | Counted |
| User runs a domain analysis | Counted as pageview + analysis | Counted as 1 request |
| Favicon request | Not counted | Counted (2,045 in one week) |
| Admin views dashboard | Not counted (admin excluded) | Counted |
| Crawler with `ghost-rider/` referrer | Not counted (bot excluded) | Counted |

**Rule**: Use custom analytics for product questions ("How many analyses did users run?"). Use Replit analytics for infrastructure questions ("Are there latency spikes? What countries is traffic from?"). Never compare raw numbers across systems — they measure different populations.

## Caching Strategy

| Cache Target | TTL | Reason |
|--------------|-----|--------|
| DNS queries | TTL=0 (none) | Live data for security incidents |
| RDAP data | 24h | Registrar info rarely changes; prevents rate-limit issues |
| DNS History | 24h | SecurityTrails API quota protection (50 calls/month limit) |
| CT subdomains | 1h | Append-only data, minimal changes |
| RFC metadata | 24h | Reference data, infrequent updates |

## Database

PostgreSQL is the primary persistent store. Database schema is defined in `go-server/db/schema/schema.sql`. Queries are written in `go-server/db/queries/` and generated by `sqlc` into type-safe Go code in `go-server/internal/dbq/`.

- **Development and production use separate databases** (platform change, Dec 2025)
- Development database: Test scans only
- Production database: Real user scan history

## Troubleshooting

### Analysis Times Out

Some DNS servers respond slowly. Partial results are shown with a warning banner. Re-analyze to retry.

### RDAP Lookup Fails

Registry may be rate-limiting. Falls back to WHOIS. Cached data used if available.

### DNSSEC Shows "Unsigned" for Known-Secure Domain

Domain likely uses an enterprise DNS provider. Check the "DNS Tampering" scorecard—it should show "Enterprise". This is intentional per the symbiotic security philosophy.

### No MX Records Found

Domain may be intentionally non-mail. Check SPF for `v=spf1 -all` pattern. We detect and explain "no-mail domains".

### Rate Limit Exceeded

Maximum 8 requests per minute per IP. Wait 60 seconds and retry.

### Field Tech Toolkit
Guided network troubleshooting tool for everyone — step-by-step diagnostic flow with educational context. Beta feature.

**Guided Wizard Flow (Steps 0–5):**
- Cellular Data Check, Connection Type (Wi-Fi/Ethernet), Business vs Residential, Multiple Wi-Fi Networks, Port Forwarding/DDNS, Direct-to-Modem Isolation

**Diagnostic Tools:**
- What's My IP (public IP via Observe Probe VPS), External Port Check (remote probe), DNS Resolution Check

**Reference Resources:**
- Dual-Network Remote Support (iPhone hotspot + Ethernet for remote field diagnostics), Command-Line Quick Reference (ping, traceroute, ipconfig, netstat, dig, networkQuality), Recommended External Tools (Speedtest, Fast.com, PingPlotter, Downdetector, Fing, Wireshark)

**UX Features:**
- Triage matrix ("What Brought You Here?"): six scenario cards (Internet Down, Port Forwarding/Remote Access, Check My IP/Port, Router vs ISP Isolation, Remote Support Technician, CLI Reference) that jump users directly to the relevant diagnostic step
- Network chain visualization (device → Wi-Fi → router → modem → ISP → internet), step navigator with jump-links, "Found Something?" discovery mechanism at each wizard step, "Why This Matters" expandable sections with RFC citations, Command Preflight guidance for password-requiring terminal commands, platform-specific instructions (macOS/Windows/Linux)

**Endpoints:**
- `GET /toolkit` — Main page
- `POST /toolkit/myip` — Public IP detection
- `POST /toolkit/portcheck` — External port reachability check

## Version History

### v26.4.30+

- Go/Gin rewrite (complete backend replacement)
- Concurrent DNS analyzer with goroutines
- Enterprise provider golden rules with test coverage
- CSRF protection via middleware
- In-memory rate limiting (Redis-ready)
- Server-rendered Go templates
- Multi-resolver consensus (Cloudflare, Google, Quad9, OpenDNS, DNS4EU)
- AI Surface Scanner with prompt injection detection
- Email Header Analyzer with RFC parsing
- Multi-layer subdomain discovery with intelligent caching
- SecurityTrails DNS history integration
- IP Intelligence with IP-to-ASN attribution
- Posture scoring with CVSS alignment
- Dual intelligence products (Engineer's DNS Intelligence Report + Executive's DNS Intelligence Brief)
- OpenPhish integration
- Public exposure checks (secret scanning in page source)
- Expanded exposure checks (opt-in well-known path probing)
- Report integrity hash (SHA-3-512 with header preview)
- Posture drift detection foundation
- SMTP TLS transport validation
- CSP with nonces for XSS protection
