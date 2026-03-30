# DNS Tool — Quick Reference
**Site:** https://dnstool.it-help.tech
**Version:** v26.25.82

---

## Public Pages

| Page | URL |
|------|-----|
| Homepage | https://dnstool.it-help.tech/ |
| Analyze (domain scan form) | https://dnstool.it-help.tech/analyze |
| Compare (side-by-side) | https://dnstool.it-help.tech/compare |
| Scan History | https://dnstool.it-help.tech/history |
| Domain Dossier | https://dnstool.it-help.tech/dossier |
| Domain Snapshot | https://dnstool.it-help.tech/snapshot/example.com |
| Drift Timeline | https://dnstool.it-help.tech/drift |
| Watchlist | https://dnstool.it-help.tech/watchlist |
| Statistics | https://dnstool.it-help.tech/stats |
| IP Intelligence | https://dnstool.it-help.tech/investigate |
| Email Header Analyzer | https://dnstool.it-help.tech/email-header |
| Field Tech Toolkit | https://dnstool.it-help.tech/toolkit |
| Confidence (ICAE) | https://dnstool.it-help.tech/confidence |
| Confidence Audit Log | https://dnstool.it-help.tech/confidence/audit-log |
| Sources | https://dnstool.it-help.tech/sources |
| Architecture | https://dnstool.it-help.tech/architecture |
| Approach | https://dnstool.it-help.tech/approach |
| Roadmap | https://dnstool.it-help.tech/roadmap |
| Changelog | https://dnstool.it-help.tech/changelog |
| About | https://dnstool.it-help.tech/about |
| About — Acknowledgments | https://dnstool.it-help.tech/about#acknowledgments |
| Security Policy | https://dnstool.it-help.tech/security-policy |
| Brand Colors | https://dnstool.it-help.tech/brand-colors |
| Color Science | https://dnstool.it-help.tech/color-science |
| FAQ — Subdomain Discovery | https://dnstool.it-help.tech/faq/subdomains |
| Badge / Shields.io | https://dnstool.it-help.tech/badge |
| Badge Embed Code | https://dnstool.it-help.tech/badge/embed |

## Authenticated Pages (sign-in required)

| Page | URL |
|------|-----|
| Zone File Upload | https://dnstool.it-help.tech/zone |

## Admin Pages (admin role required)

| Page | URL |
|------|-----|
| Admin Dashboard | https://dnstool.it-help.tech/ops |
| Analytics Dashboard | https://dnstool.it-help.tech/ops/analytics |
| JSON Export (all analyses) | https://dnstool.it-help.tech/export/json |

### Admin Dashboard Actions (/ops)
- **Yellow logout icon** — clears all sessions for that user, forcing sign-in fresh
- **Red trash icon** — deletes user + all associated data (sessions, analyses, zone imports). Only for non-admin users, with confirmation dialog
- **Purge Expired Sessions** — bulk cleanup button

## Analysis Result Pages

| Page | URL Pattern |
|------|-------------|
| View Analysis | https://dnstool.it-help.tech/analysis/{id} |
| Static/Read-Only View | https://dnstool.it-help.tech/analysis/{id}/view |
| Executive Brief View | https://dnstool.it-help.tech/analysis/{id}/executive |

## APIs

| Endpoint | Description |
|----------|-------------|
| GET /api/analysis/{id} | JSON analysis data |
| GET /api/analysis/{id}/checksum | SHA-3-512 checksum verification |
| GET /api/subdomains/{domain} | Subdomain enumeration results |
| GET /api/dns-history | DNS history data |
| GET /api/health | Health check |
| GET /export/subdomains | CSV export of subdomains |
| GET /proxy/bimi-logo | BIMI logo proxy (CORS/mixed-content fix) |
| GET /badge/shields?domain=x | Shields.io-compatible badge endpoint |

## Well-Known Endpoints

| Endpoint | URL |
|----------|-----|
| security.txt | https://dnstool.it-help.tech/.well-known/security.txt |
| robots.txt | https://dnstool.it-help.tech/robots.txt |
| sitemap.xml | https://dnstool.it-help.tech/sitemap.xml |
| manifest.json (PWA) | https://dnstool.it-help.tech/manifest.json |
| Service Worker | https://dnstool.it-help.tech/sw.js |
| LLMs.txt | https://dnstool.it-help.tech/llms.txt |
| LLMs-full.txt | https://dnstool.it-help.tech/llms-full.txt |

## Authentication

| Endpoint | Description |
|----------|-------------|
| /auth/login | Google OAuth sign-in |
| /auth/callback | OAuth callback |
| /auth/logout | Sign out |

---

## Terminal Commands (Explore & Audit)

```bash
# See the hacker verse (HTML comment, line 2)
curl -s https://dnstool.it-help.tech/ | head -20

# Architecture page source
curl -s https://dnstool.it-help.tech/architecture | head -5

# Grep all HTML comments
curl -s https://dnstool.it-help.tech/ | grep -A 15 "<!--"

# Health check
curl -s https://dnstool.it-help.tech/api/health

# robots.txt
curl -s https://dnstool.it-help.tech/robots.txt

# LLMs.txt
curl -s https://dnstool.it-help.tech/llms.txt

# security.txt
curl -s https://dnstool.it-help.tech/.well-known/security.txt

# Sitemap
curl -s https://dnstool.it-help.tech/sitemap.xml
```

---

## Easter Egg Inventory

| Name | Location | How to See It |
|------|----------|---------------|
| Hacker Poem v1 | index.html line 2 | `view-source:` or `curl` — HTML comment |
| Hacker Poem v2 | results.html line 2 | `view-source:` on any analysis result — HTML comment |
| Hacker Poem v3 | analysis.go (SHA-3 sidecar) | Download `.sha3` file from any JSON export — poem is in the sidecar |
| Browser Console Poem | results.html line 5510 | Open DevTools Console on any analysis result page |
| RFC 1392 Disclaimer | All poem locations + console | "Hacker per RFC 1392..." legal text in every poem |
| Covert Recon Mode | Navbar biohazard toggle | Click the biohazard icon — red-team UI theme with alternate scan phases |
| ASCII Art Hero | index.html line 217 | Desktop homepage — Unicode block-character "Domain Security Audit" |
| Covert ASCII Art | index.html line 217 | Enable Covert Mode — changes to "DNS RECON" block art |

---

## Environment Variable Controls

| Variable | Purpose |
|----------|---------|
| `MAINTENANCE_NOTE` | Set to any word (Maintenance, Beta, Update, etc.) to show a yellow pill badge in the navbar. Clear/delete to hide. |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret |
| `INITIAL_ADMIN_EMAIL` | Email address that gets admin role on first login |
| `PROBE_API_KEY` | API key for the external probe VPS (port checks, SMTP probing) |
