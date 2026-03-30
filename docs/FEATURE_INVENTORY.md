# DNS Tool — Feature Overview

**Last Updated:** March 18, 2026 (v26.37.34)
**Implementation:** Go/Gin

---

## Purpose

This document provides a high-level overview of the DNS Tool's OSINT-based
domain security analysis capabilities for public reference. All data sources
are open-source intelligence — publicly available DNS records, certificate
transparency logs, RDAP registrar data, and web resources.

---

## Core DNS Security Analysis

The tool performs RFC-compliant parsing and validation of these protocols:

- **SPF Analysis** (RFC 7208) — mechanism parsing, lookup counting, permissiveness evaluation
- **DMARC Analysis** (RFC 7489) — policy parsing, alignment modes, reporting address extraction
- **DKIM Analysis** (RFC 6376) — selector probing, key strength assessment, provider-aware credit
- **MTA-STS Analysis** (RFC 8461) — policy file validation, mode parsing
- **TLS-RPT Analysis** (RFC 8460) — reporting address extraction
- **BIMI Analysis** (RFC 9495) — logo and VMC validation
- **DANE/TLSA Analysis** (RFC 6698, RFC 7672) — per-MX-host TLSA evaluation, DNSSEC requirement verification
- **DNSSEC Analysis** (RFC 4035) — chain of trust verification
- **CAA Analysis** (RFC 8659) — authorized CA parsing, MPIC awareness
- **NS Delegation Analysis** (RFC 1034) — delegation consistency, lame delegation detection
- **SMTP Transport Analysis** (RFC 3207) — live TLS probing with DNS-inferred fallback (conditional — cloud platforms may block outbound port 25; gracefully skipped when unavailable)

## Infrastructure Analysis

- DNS record lookups (A, AAAA, MX, TXT, NS, CNAME, CAA, SOA, SRV)
- Multi-resolver consensus (Cloudflare, Google, Quad9, OpenDNS, DNS4EU)
- Authoritative vs. resolver propagation comparison
- Registrar/RDAP lookup with caching
- Multi-layer subdomain discovery with intelligent caching (proprietary pipeline)
- DNS infrastructure provider detection and tier classification
- Hosting provider detection (web, DNS, email)
- DNS history timeline via SecurityTrails API (user-provided API key only; 50 req/month hard limit; never called automatically)

## Assessment and Scoring

- CVSS-aligned security posture assessment
- Mail posture classification
- RFC-aligned remediation engine with priority fixes
- ICuAE — Intelligence Currency Audit Engine: 29 deterministic test cases across 5 dimensions (Currentness, TTL Compliance, Completeness, Source Credibility, TTL Relevance), five-tier grading system aligned with ICD 203, NIST SP 800-53 SI-7, and ISO/IEC 25012

## Detection and Intelligence

- Email security management provider detection
- AI Surface Scanner (llms.txt, AI crawler governance, prompt injection detection)
- Public exposure checks: secret/credential scanning in publicly accessible page source and JavaScript
- Expanded exposure checks (opt-in): well-known misconfiguration path probing (/.env, /.git, /server-status, etc.) with content validation
- Web3 domain analysis: IPFS CID detection via `_dnslink` TXT records, ENS `.eth` resolution (eth.limo gateway), Handshake TLD resolution (hnsdns.com/hdns.io), typed evidence model (IPFSProbe, Web3DNSSECTrust), authority containment (gateway posture isolation), distributed IPFS fleet probing (multi-probe persistence verification with redirect divergence detection and infrastructure fingerprinting)
- Dangling DNS and subdomain takeover detection
- DMARC external reporting authorization verification
- Misplaced DMARC detection (post-analysis enrichment for incorrect record placement)
- Content-Usage directive detection (robots.txt AI governance signals)
- Nmap DNS server security probing (zone transfer, open recursion, NSID, cache snooping)
- OpenPhish community phishing URL feed integration (Email Header Analyzer body scanning)

## Platform Features

- Domain analysis with re-analyze capability
- Analysis history with search
- Side-by-side domain comparison
- Domain Snapshot (/snapshot/:domain) — quick security posture view
- Domain Comparison (/compare) — side-by-side security posture comparison
- Badge System (/badge) — SVG badges for DNS security posture with Shields.io compatibility and embed options
- Statistics dashboard
- JSON export
- Email Header Analyzer — multi-format support (paste, .eml, JSON, .mbox, .txt) with SPF/DKIM/DMARC verification, delivery route tracing, spoofing detection, subject line scam analysis (phone number obfuscation, fake payment amounts, homoglyph brand impersonation), third-party spam vendor detection (Proofpoint, Barracuda, Microsoft SCL, Mimecast), brand mismatch detection, BCC delivery detection, and educational "Understanding This Attack" explainer
- IP Intelligence (reverse lookups, ASN attribution, geolocation)
- Five intelligence products: Engineer's DNS Intelligence Report (comprehensive technical detail), Executive's DNS Intelligence Brief (concise board-ready summary with security scorecard), Recon Report (adversarial perspective), Domain Dossier, and Domain Comparison
- Configurable TLP classification (default: TLP:AMBER, with TLP:RED, TLP:AMBER+STRICT, TLP:GREEN and TLP:CLEAR options) aligned with CISA Cyber Hygiene practice and FIRST TLP v2.0
- Covert Recon Mode — adversarial dark theme with scotopic vision-optimized red-spectrum (#cc2020) palette, producing the Recon Report intelligence product; Focus Mode button (Fullscreen API with `webkit` fallback) hides browser chrome for full scotopic immersion (`fa-expand`/`fa-compress` icon swap on `fullscreenchange`/`webkitfullscreenchange`); dynamic `meta[name="theme-color"]` updates per covert environment (submarine `#0a0404`, tactical `#1a0808`, basement `#140606`); iPhone graceful degradation (Focus button hidden via `d-none` when `fullscreenEnabled` is `false`); audio permissions fix (Morse easter egg `.play().catch()` prevents `NotAllowedError` on autoplay-restricted browsers); DTIC/MIL-STD citations upgraded to three authoritative sources: [AD0639176](https://apps.dtic.mil/sti/citations/tr/AD0639176), [MIL-STD-3009 (ADA148883)](https://apps.dtic.mil/sti/tr/pdf/ADA148883.pdf), [MIL-STD-1472G](https://cvgstrategy.com/wp-content/uploads/2023/04/MIL-STD-1472G.pdf)
- Color Science page (/color-science) — live CIE scotopic/photopic luminosity validation and WCAG 2.2 contrast calculations for Covert Recon Mode palette, with MIL-STD-1472H compliance badges
- Report integrity hash (SHA-3-512 fingerprint binding domain, analysis ID, timestamp, tool version, and results data) with copy-to-clipboard and header preview
- Architecture page (/architecture) — interactive Mermaid diagrams of system architecture
- Posture drift detection foundation (canonical SHA-3-512 hashing for longitudinal monitoring, backward-compatible legacy SHA-256 recomputation)
- ICAE Intelligence Confidence Matrix with tier-colored next-tier progress labels and two-layer (Collection + Analysis) auditing, 129 deterministic test cases across 9 protocols, empirically validated via calibration metrics (Brier Score 0.0018, ECE 0.031, 645 predictions across 5 resolver scenarios)
- Changelog page
- Security policy page
- Sources and methodology reference
- Zone file upload (/zone) — authenticated-only bulk analysis from uploaded zone files
- Subdomain discovery FAQ (/faq/subdomains) — methodology and pipeline explanation
- Accountability log (/confidence/audit-log) — paginated hash integrity audit trail
- Download verification — Kali-style JSON download with SHA-3-512 .sha3 sidecar file
- Hash Integrity Audit Engine — automated recomputation and verification of stored posture hashes
- Brand colors page (/brand-colors) — brand palette reference with live CIE validation
- Origin story page (/about) with verified timeline: Memphis 1980, Nashville IT, Raspberry Pi, PhreakNIC ~2006, Hak5 offensive security, 2015-2024 defensive security (Objective-See, CISA RPT Jan 2022, Hak5 Payload Award Sept 2023), Python CLI (Snap Store Nov 2023), Go platform Feb 2025
- Wayback Machine automatic archival — every successful, non-private, non-scan-flagged analysis is submitted to the Internet Archive via web.archive.org/save/ in a background goroutine; snapshot URL stored in domain_analyses.wayback_url; green "Archived" badge in results header; "Internet Archive — Permanent Record" card on Engineer's and Executive's reports with View/Copy buttons; three-layer evidence chain (SHA-3-512 integrity hash + posture hash + third-party Wayback archive)

## Security and Infrastructure

- CSRF protection (HMAC-signed tokens)
- Rate limiting (per-IP)
- SSRF hardening
- Multi-resolver DNS client with DoH fallback and UDP fast-probe
- Provider health telemetry
- Concurrent analysis orchestrator with master deadline
- Google OAuth 2.0 with PKCE (S256) — OIDC nonce for replay protection, `iat` validation with 5-minute clock skew tolerance, 10-second HTTP client timeouts, SameSite=Lax on all auth cookies
- Admin panel: session management dashboard with per-user session counts (active/total), purge expired sessions, per-user session reset, user deletion (admin deletion blocked), CSRF-protected actions
- Privacy-preserving site analytics: IP+User-Agent fingerprinting with daily-rotating SHA-3-512 salt (no cookies, no PII), incremental 60-second flushes with additive SQL merge
- Privacy-preserving cookieless analytics
- Cryptographic provenance (SHA-3-512 hashing on JSON exports with detailed provenance metadata)

## Design Philosophy

- **OSINT methodology**: all data sourced from publicly available, open-source intelligence — DNS queries, CT logs, RDAP, publicly accessible web resources
- **Fresh data**: DNS records always fetched live (TTL=0, no cache)
- **Observation-based language**: no definitive claims, only observations
- **Open-Standard Protocols**: All analysis uses publicly verifiable DNS, SMTP, and HTTP protocols — results can be independently reproduced with standard tools (dig, openssl, curl)
- **RFC-backed**: all analysis grounded in published standards
- **Symbiotic security**: enterprise providers recognized for multi-layer security beyond DNSSEC alone

---

## Automated Verification

Feature parity is enforced by automated Go tests that verify every
schema key is present in orchestrator output. Golden rule tests guard
critical behaviors and prevent regressions.
