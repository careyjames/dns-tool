# DNS Tool — External Integrations

## Authentication
| Provider | Protocol | Implementation |
|----------|----------|----------------|
| Google OAuth 2.0 | PKCE (S256) | `internal/middleware/auth.go` |

## DNS Resolution
| Provider | Address | Protocol |
|----------|---------|----------|
| Cloudflare | 1.1.1.1 / DoH | UDP + HTTPS |
| Google | 8.8.8.8 / DoH | UDP + HTTPS |
| Quad9 | 9.9.9.9 | UDP |
| OpenDNS | 208.67.222.222 | UDP |
| DNS4EU | (configured) | UDP |

## Intelligence Feeds
| Service | Purpose | File |
|---------|---------|------|
| CISA KEV | Known exploited vulnerabilities | `internal/scanner/cisa.go` |
| OpenPhish | Phishing URL detection | `internal/analyzer/openphish.go` |
| IANA RDAP | TLD-to-RDAP server mapping | `internal/analyzer/rdap.go` |
| IETF Datatracker | RFC metadata for citations | `internal/analyzer/ietf.go` |

## Third-Party APIs
| Service | Purpose | Auth | File |
|---------|---------|------|------|
| IPInfo.io | IP geolocation, ASN | API key | `internal/analyzer/ipinfo.go` |
| SecurityTrails | Subdomain discovery | API key | `internal/analyzer/securitytrails.go` |
| Team Cymru | ASN attribution | Public | `internal/analyzer/cymru.go` |

## Probe Fleet
| Probe | Location | Capabilities |
|-------|----------|-------------|
| probe-01 | US-East (Boston) | SMTP, DANE, TLS |
| probe-02 | US-East (Kali/02) | SMTP, DANE, testssl.sh, Nmap |

## DevOps Integrations
| Service | Purpose | Config |
|---------|---------|--------|
| Discord | Webhook notifications | `DISCORD_WEBHOOK_URL` env var |
| Notion | Roadmap sync | `scripts/notion-roadmap-sync.mjs` |
| GitHub | Intel sync, CI | `scripts/github-intel-sync.mjs` |
| SonarQube | Code quality | `sonar-project.properties` |

## Environment Variables
| Variable | Required | Purpose |
|----------|----------|---------|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `SESSION_SECRET` | Yes | Cookie signing secret |
| `PORT` | No (default: 5000) | Server listen port |
| `BASE_URL` | No | Production URL override |
| `GOOGLE_CLIENT_ID` | No | OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | No | OAuth client secret |
| `PROBE_API_URL` | No | Primary probe endpoint |
| `PROBE_API_KEY` | No | Probe authentication |
| `DISCORD_WEBHOOK_URL` | No | Discord notifications |
| `MAINTENANCE_NOTE` | No | Navbar maintenance badge |
| `SMTP_PROBE_MODE` | No | skip/remote/local |
