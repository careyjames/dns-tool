# DNS Tool Intelligence Module — Definitive File List

## Classification: PROPRIETARY (This Repository)

### scoring/ — Posture Scoring & Risk Assessment
| File | Lines | Purpose |
|------|-------|---------|
| `posture.go` | 746 | CVSS-aligned posture scoring, risk level calculation, section status categorization |
| `confidence.go` | 51 | Confidence labeling system (Observed/Inferred/Third-party) |
| `confidence_test.go` | 110 | Confidence labeling tests |
| `dkim_state.go` | 88 | DKIM state machine analysis (Published/Missing/Weak/Revoked) |
| `dkim_state_test.go` | 396 | DKIM state analysis tests |

### remediation/ — RFC-Aligned Remediation Guidance
| File | Lines | Purpose |
|------|-------|---------|
| `remediation.go` | 1049 | Complete remediation engine: SPF ~all vs -all, DMARC policy progression, DKIM key strength, DNSSEC chain repair, DANE+MTA-STS best practices, CAA recommendations |

### providers/ — Provider Fingerprinting & Detection
| File | Lines | Purpose |
|------|-------|---------|
| `providers.go` | 377 | Email security management provider detection (DMARC monitoring, SPF flattening vendors) |
| `infrastructure.go` | 816 | Hosting, DNS, and email provider detection from DNS records |
| `edge_cdn.go` | 160 | CDN/edge network detection from ASN and DNS patterns |
| `saas_txt.go` | 126 | SaaS service detection from TXT record patterns |
| `ip_investigation.go` | 616 | IP-to-domain correlation, CDN/cloud provider detection, neighborhood analysis |

### golden_rules/ — Analysis Integrity Tests
| File | Lines | Purpose |
|------|-------|---------|
| `golden_rules_test.go` | 949 | Defines expected analysis behavior — the quality standard |
| `orchestrator_test.go` | 1251 | End-to-end orchestration behavior tests |

### commands/ — Verification Command Generation
| File | Lines | Purpose |
|------|-------|---------|
| `commands.go` | 450 | "Verify It Yourself" command generation for all protocols |
| `manifest.go` | 530 | Feature manifest system — what the tool checks and why |
| `manifest_test.go` | 201 | Manifest completeness tests |

### ai_surface/ — AI Governance Detection
| File | Lines | Purpose |
|------|-------|---------|
| `scanner.go` | 169 | AI Surface Scanner orchestrator |
| `llms_txt.go` | 127 | llms.txt / llms-full.txt detection and parsing |
| `robots_txt.go` | 181 | AI crawler directive detection in robots.txt |
| `poisoning.go` | 199 | AI recommendation poisoning indicator detection |
| `http.go` | 31 | HTTP client configuration for AI surface scanning |

## Classification: AGPL-3.0 (dnstoolweb Public Repository)

### Infrastructure (transport layer — "no proprietary magic")
- `analyzer.go` — Analyzer struct and initialization
- `orchestrator.go` — Concurrent analysis orchestration
- `spf.go`, `dkim.go`, `dmarc.go` — Protocol-specific DNS record parsing
- `dane.go`, `dnssec.go`, `bimi.go`, `caa.go` — Security protocol parsing
- `mta_sts.go`, `tlsrpt.go` — Transport security protocol parsing
- `records.go`, `ns_delegation.go` — Basic DNS record queries
- `smtp_transport.go` — SMTP TLS probing
- `registrar.go` — RDAP client for registrar data
- `dns_history.go`, `securitytrails.go` — DNS history API client
- `ietf_metadata.go` — RFC metadata lookups
- `subdomains.go` — CT log subdomain discovery
- `asn_lookup.go` — Team Cymru ASN lookups
- `dangling_dns.go` — Dangling DNS/subdomain takeover checks
- `https_svcb.go` — HTTPS/SVCB record parsing
- `cds_cdnskey.go` — CDS/CDNSKEY automation detection
- `smimea_openpgpkey.go` — Email encryption record detection
- `dmarc_report_auth.go` — DMARC external reporting authorization
- `security_txt.go` — security.txt fetching and parsing
- `util.go` — Shared utilities
- `ai_surface_bridge.go` — Bridge to AI surface scanner

### Other Infrastructure Packages
- `dnsclient/` — Native DNS query engine (miekg/dns)
- `handlers/` — HTTP request handlers
- `middleware/` — CSRF, rate limiting, security
- `templates/` — Server-rendered HTML
- `db/`, `dbq/` — Database layer
- `config/` — Configuration
- `telemetry/` — Metrics and monitoring
- `models/` — Data models
