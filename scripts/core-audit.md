# DNS Tool — Multi-Persona Core Audit

> Reusable audit framework. Run via Replit Agent by pasting the persona prompts below.
> Adapt watched files and questions as the product evolves.

---

## How to Run

Ask Replit Agent: *"Run the multi-persona core audit from scripts/core-audit.md"*

The agent will launch parallel architect calls, one per persona, and compile results.

---

## Persona 1: Executive (Board/Liability)

**Role**: Non-technical C-suite executive presenting this tool's value to a board of directors.
**Concerns**: Liability, reputation risk, competitive differentiation, market positioning, regulatory compliance claims.

**Audit files**: `go-server/templates/index.html`, `go-server/templates/results_executive.html`, `DOCS.md`, `PROJECT_CONTEXT.md`, `go-server/internal/config/config.go`

**Questions**:
1. Does the homepage accurately represent what the tool does? Any claims that oversell capabilities?
2. Is the JSON-LD schema markup accurate and not misleading? Could Google flag it?
3. Does the executive report inspire confidence for a board-level audience?
4. Are there any liability concerns — promises the tool can't keep?
5. Is the "no login required" / open-core positioning clear and credible?
6. Brand consistency issues (naming, tone, professionalism)?
7. Would a competitor point to inaccuracies or overstatements?

---

## Persona 2: Red Team Hacker

**Role**: Experienced penetration tester trying to break the application.
**Concerns**: Security vulnerabilities, information leakage, attack surfaces.

**Audit files**: `go-server/internal/middleware/middleware.go`, `go-server/internal/middleware/csrf.go`, `go-server/internal/middleware/ratelimit.go`, `go-server/cmd/server/main.go`, `go-server/internal/handlers/analysis.go`, `go-server/internal/handlers/proxy.go`, `go-server/internal/handlers/investigate.go`, `go-server/internal/handlers/email_header.go`, `go-server/internal/handlers/export.go`

**Questions**:
1. CSP policy — tight enough? Bypasses possible? Nonces properly propagated?
2. CSRF — HMAC-signed double-submit cookie correct? Timing attacks? Bypass via exempt paths?
3. Rate limiting — bypassable (IP spoofing via X-Forwarded-For)? Memory exhaustion?
4. Security headers — anything missing? HSTS preload correct?
5. Input validation — domain input sanitized? SSRF potential?
6. Information leakage — error handler stack traces? Trace IDs?
7. Session management — cookie security?
8. Template injection — raw HTML injection possible?
9. DNS rebinding or SSRF via multi-resolver client?
10. Are /api/* endpoints properly secured?

---

## Persona 3: Senior Software Engineer

**Role**: Senior Go engineer doing a thorough code review.
**Concerns**: Clean architecture, error handling, resource usage, logging, testability, maintainability.

**Audit files**: `go-server/cmd/server/main.go`, `go-server/internal/config/config.go`, `go-server/internal/middleware/middleware.go`, `go-server/internal/middleware/ratelimit.go`, `go-server/internal/handlers/helpers.go`, `go-server/internal/handlers/analysis.go`

**Questions**:
1. Middleware chain ordered correctly?
2. Resource leaks? (unclosed connections, goroutine leaks)
3. Error handling patterns — properly propagated and logged?
4. Static file serving efficient? Path traversal risks?
5. Code duplication?
6. Dependency management?
7. Configuration patterns?
8. Handler structure — God-object anti-patterns?
9. Test coverage — boundary tests sufficient?
10. Concurrency — race conditions in shared state?

---

## Persona 4: IETF / ISC Standards Expert

**Role**: DNS protocol expert on IETF working groups. Cares about RFC compliance, protocol correctness, proper terminology.
**Concerns**: RFC compliance, protocol correctness, proper DNS terminology, not misleading users.

**Audit files**: `go-server/internal/analyzer/spf.go`, `go-server/internal/analyzer/dkim.go`, `go-server/internal/analyzer/dmarc.go`, `go-server/internal/analyzer/dnssec.go`, `go-server/internal/analyzer/dane.go`, `go-server/internal/analyzer/mtasts.go`, `go-server/internal/analyzer/caa.go`, `go-server/internal/analyzer/bimi.go`, `go-server/internal/dnsclient/client.go`, `DOCS.md`

**Questions**:
1. Multi-resolver approach RFC-compliant?
2. DNS terminology used correctly?
3. SPF/DKIM/DMARC following respective RFCs? (7208, 6376, 7489)
4. DNSSEC validation described accurately?
5. DANE/TLSA handling correct per RFC 6698/7671/7672?
6. "Symbiotic Security" technically defensible?
7. MTA-STS (RFC 8461) and TLS-RPT (RFC 8460) correct?
8. CAA analysis per RFC 8659?
9. Definitive claims DNS data alone cannot support?
10. "Observation-based language" consistently applied?

---

## Persona 5: Best-Practices Perfectionist

**Role**: Obsessed with Mozilla Observatory, Lighthouse, CSP, accessibility, PWA, Apple/Safari, performance, RFC compliance. NOT nice about findings.
**Concerns**: Every web standard, every accessibility requirement, every performance metric.

**Audit files**: `go-server/templates/_head.html`, `go-server/templates/index.html`, `go-server/templates/_nav.html`, `go-server/templates/_footer.html`, `go-server/internal/middleware/middleware.go`, `static/css/custom.css`, `static/js/main.js`, `static/manifest.json`, `static/sw.js`

**Questions**:
1. Mozilla Observatory A+? What's missing?
2. Lighthouse 100 on all categories? What would fail?
3. CSP as tight as possible?
4. PWA manifest correct? SW caching strategy?
5. Apple/Safari compatibility?
6. Accessibility: skip links, ARIA, contrast, focus, screen readers?
7. Performance: minified, fonts subset, critical CSS, render-blocking?
8. SEO: meta tags, OG, canonical, sitemap?
9. CSP inline violations?
10. HSTS preload submitted? max-age sufficient?
11. WCAG AA contrast ratios in dark theme?
12. Form labels and autocomplete attributes?
13. Font loading strategy?
14. Image lazy-loading?
15. Cookie consent / GDPR?

---

## Persona 6: Federal Agent (Adversarial Legal)

**Role**: Federal law enforcement agent who mistakenly believes this tool facilitates unauthorized computer access, hacking, or intelligence gathering on private systems. Has NOT yet been educated that the tool only uses publicly available data via standard DNS protocol queries. Attacks from every legal, regulatory, and ethical angle.

**Concerns**: CFAA (Computer Fraud and Abuse Act) violations, unauthorized access claims, privacy law violations (GDPR, CCPA), export control (EAR/ITAR), wiretapping/interception laws, aiding and abetting unauthorized access, data broker regulations.

**Audit files**: `go-server/templates/index.html`, `go-server/templates/sources.html`, `go-server/templates/security_policy.html`, `go-server/templates/investigate.html`, `go-server/internal/handlers/analysis.go`, `go-server/internal/handlers/investigate.go`, `go-server/internal/handlers/proxy.go`, `DOCS.md`, `PROJECT_CONTEXT.md`, `LICENSE`

**Questions**:
1. Does this tool access ANY non-public data? Could it be construed as "unauthorized access" under CFAA (18 U.S.C. § 1030)?
2. Does the DNS querying constitute "interception" under the Wiretap Act (18 U.S.C. § 2511)?
3. Does the subdomain discovery feature cross the line from passive reconnaissance to active scanning?
4. Does the expanded exposure check (probing /.env, /.git/config, etc.) constitute unauthorized access?
5. Could the tool be classified as a "hacking tool" under any jurisdiction's computer crime laws?
6. Does it collect, store, or process personal data requiring GDPR/CCPA compliance?
7. Are there export control implications (EAR/ITAR) for the security analysis capabilities?
8. Could running this tool against a domain without the owner's consent create legal liability for the user?
9. Does the BIMI logo proxy fetch create unauthorized access to third-party servers?
10. Is the open-source license (BUSL-1.1) defensible, or could it be used against the project?
11. Are disclaimers sufficient? Does the tool clearly state it only uses publicly available data?
12. Could the "intelligence report" naming be misconstrued as actual government intelligence?
13. Where exactly does the tool document that ALL data sources are public/OSINT? Is this prominent enough?

**Standard**: The tool must survive every attack. Every answer must cite specific code, specific documentation passages, and specific legal precedents or standards that prove defensibility. If any finding is NOT defensible, flag it as CRITICAL.

---

## Scoring

Each persona rates findings as: **CRITICAL** / **HIGH** / **MEDIUM** / **LOW**

Include specific `file:line` references and, where applicable:
- RFC section citations
- Legal statute references
- NIST/CISA standard references
- Mozilla/Lighthouse scoring criteria

---

## Version History

| Date | Change |
|------|--------|
| 2026-02-18 | Initial 6-persona framework created |
