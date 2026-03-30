# DNS Tool — Authoritative Sources Registry

> **Purpose**: Canonical reference of every standards body, regulatory authority, RFC, and data source this project relies on. Every claim in code, templates, documentation, and UI copy must trace back to an entry here. If a source isn't listed, we don't cite it. If it's listed as "draft" or "proprietary," we label it as such — never as a ratified standard.

> **Rule**: Before implementing any feature that references a standard, verify its current status at the authoritative URL listed below. Drafts change. RFCs get obsoleted. Assumptions rot. Check first.

---

## 1. Standards Bodies & Regulatory Authorities

### IETF (Internet Engineering Task Force)
- **What**: Primary source for all internet protocol standards (RFCs)
- **URL**: https://www.ietf.org / https://datatracker.ietf.org
- **We track**: Every RFC cited below, plus active working group drafts relevant to DNS, email security, and AI governance
- **Status check**: https://datatracker.ietf.org/doc/{rfc-or-draft-name}/ — shows current status, obsoleted-by, errata
- **Rule**: Always check if an RFC has been obsoleted or updated before citing it. Use datatracker, not memory.

### NIST (National Institute of Standards and Technology)
- **What**: US federal standards for cybersecurity, cryptography, and information security
- **URL**: https://csrc.nist.gov
- **We track**:
  - SP 800-177 Rev 1 — Trustworthy Email (SPF/DKIM/DMARC/DANE guidance)
  - SP 800-53 Rev 5, SI-7 — System and Information Integrity: Software, Firmware, and Information Integrity (data integrity and completeness requirements)
  - Cryptographic key strength recommendations (RSA 2048-bit minimum)
  - CVSS severity color conventions (via NVD)
- **Used for**: Documentation citation style, cryptographic strength classification, remediation priority language, ICuAE data currency dimension grounding

### CISA (Cybersecurity and Infrastructure Security Agency)
- **What**: US federal cybersecurity authority
- **URL**: https://www.cisa.gov
- **We track**:
  - BOD 18-01 — Binding Operational Directive for federal email security (SPF, DMARC, STARTTLS)
  - NCATS Cyber Hygiene IP list — https://rules.ncats.cyber.dhs.gov/all.txt (daily refresh for scanner detection)
- **Used for**: Compliance context in reports, scanner classification, TLP alignment

### FBI Cyber Division
- **What**: US federal law enforcement cyber threat intelligence and operations
- **URL**: https://www.fbi.gov/investigate/cyber
- **We track**:
  - IC3 (Internet Crime Complaint Center) threat alerts
  - Joint Cybersecurity Advisories (co-authored with CISA/NSA)
  - Operation notifications (e.g., Operation Winter Shield)
- **Used for**: Threat landscape awareness, DNS infrastructure abuse patterns, phishing domain intelligence context

### NSA Cybersecurity Directorate
- **What**: US signals intelligence agency's public cybersecurity mission
- **URL**: https://www.nsa.gov/Cybersecurity/
- **We track**:
  - Cybersecurity advisories and technical guidance documents
  - Joint Cybersecurity Advisories (co-authored with CISA/FBI)
  - Cryptographic algorithm transition guidance
- **Used for**: Cryptographic strength validation context, infrastructure hardening guidance, adversary TTP awareness

### FIRST (Forum of Incident Response and Security Teams)
- **What**: Global incident response coordination body
- **URL**: https://www.first.org
- **We track**:
  - TLP v2.0 — Traffic Light Protocol for information sharing classification
  - CVSS v3.1 — Common Vulnerability Scoring System for risk-level badges
- **Used for**: Report classification (default TLP:AMBER), posture scoring severity levels

### CA/Browser Forum
- **What**: Industry body governing certificate authority practices
- **URL**: https://cabforum.org
- **We track**:
  - Ballot SC-067 — MPIC (Multi-Perspective Issuance Corroboration) requirements
- **Used for**: CAA record analysis context

### BIMI Group
- **What**: Industry group defining Brand Indicators for Message Identification
- **URL**: https://bimigroup.org
- **We track**: BIMI specification (now RFC 9495)
- **Used for**: BIMI record detection, VMC certificate validation context

---

## 2. IETF RFCs — By Functional Area

### Email Authentication & Security

| RFC | Title | Status | Our Use |
|-----|-------|--------|---------|
| 5321 | Simple Mail Transfer Protocol | Standards Track | SMTP transport, MX host extraction, null MX handling |
| 7208 | SPF (Sender Policy Framework) | Standards Track | Core SPF parsing, validation, 10-lookup limit |
| 6376 | DKIM (DomainKeys Identified Mail) | Standards Track | DKIM record parsing, signature verification |
| 7489 | DMARC | Informational | Policy enforcement, alignment, inherited policy (§6.6.3) |
| 8301 | DKIM Cryptographic Update | Standards Track | Key strength: 1024-bit (weak) vs 2048-bit (adequate) |
| 8463 | DKIM Ed25519 | Standards Track | Modern elliptic curve algorithm detection |
| 8461 | MTA-STS | Standards Track | Policy verification, MX pattern matching |
| 8460 | TLS-RPT | Standards Track | Reporting record and endpoint validation |
| 7505 | Null MX | Standards Track | No-mail domain detection and hardening |
| 6698 | DANE/TLSA | Standards Track | Certificate pinning for mail transport |
| 7672 | SMTP Security via DANE | Standards Track | Transport security, DANE precedence over MTA-STS |
| 9495 | BIMI | Experimental | Brand indicator detection |

### Email Authentication — Active Drafts

| Draft | Title | Status | Our Use |
|-------|-------|--------|---------|
| draft-ietf-dmarc-dmarcbis | DMARC Protocol Updates | Active WG Draft | Detects `np=`, `t=`, `psd=` tags |

### DNS & Infrastructure

| RFC | Title | Status | Our Use |
|-----|-------|--------|---------|
| 1034/1035 | DNS Core Protocol | Internet Standard | Native packet construction, enterprise DNS classification |
| 4033/4034/4035 | DNSSEC | Standards Track | Chain validation, AD flag verification |
| 8624 | DNSSEC Algorithm Guidance | Standards Track (obsoleted by 9904) | Legacy algorithm recommendations |
| 9904 | DNSSEC Algorithm Recommendation Update Process | Standards Track (Nov 2025) | Moves algorithm guidance to IANA registries; obsoletes RFC 8624 |
| 8078 | CDS and CDNSKEY | Standards Track | Automated DNSSEC key rollover signaling |
| 8659 | CAA | Standards Track | Certificate issuance control records |
| 8767 | Serving Stale Data to Improve DNS Resiliency | Standards Track | TTL compliance auditing, cache behavior analysis |
| 8162 | SMIMEA | Experimental | S/MIME certificate publication in DNS |
| 7929 | OPENPGPKEY | Standards Track | OpenPGP key publication in DNS |
| 9460/9461 | HTTPS/SVCB Records | Standards Track | Service binding, HTTPS parameter discovery |
| 6962 | Certificate Transparency | Experimental | Subdomain discovery via CT logs |
| 7483 | RDAP | Standards Track | Modern WHOIS replacement for registrar data |

### Web & AI Governance

| RFC/Draft | Title | Status | Our Use |
|-----------|-------|--------|---------|
| 9309 | Robots Exclusion Protocol | Standards Track | robots.txt parsing rules |
| 8615 | Well-Known URIs | Standards Track | .well-known/ path mechanics (NOT llms.txt) |
| draft-ietf-aipref-attach | Content-Usage Directive | **Active WG Draft (NOT ratified)** | We detect it on scanned domains; we do NOT use it in our own robots.txt |

### Miscellaneous

| RFC | Title | Status | Our Use |
|-----|-------|--------|---------|
| 9116 | security.txt | Standards Track | We detect security.txt on scanned domains |
| 1392 | Internet Users' Glossary | Informational | Definition of "Hacker" in community disclaimers |

### ODNI (Office of the Director of National Intelligence)
- **What**: US Intelligence Community oversight and analytic standards
- **URL**: https://www.dni.gov
- **We track**:
  - ICD 203 — Analytic Standards (Intelligence Community Directive on confidence levels and analytic tradecraft)
- **Used for**: ICAE and ICuAE confidence framework — five-tier maturity model, correctness/currency dual application of "confidence" to intelligence products

### ISO (International Organization for Standardization)
- **What**: International standards for quality, safety, and efficiency
- **URL**: https://www.iso.org
- **We track**:
  - ISO/IEC 25012:2008 — Data Quality Model (timeliness, completeness, credibility dimensions)
- **Used for**: ICuAE dimension taxonomy — mapping TTL Compliance, Completeness, Source Credibility, Currentness, and TTL Relevance to internationally recognized data quality characteristics

---

## 3. Quality Gate Authorities

These are not standards bodies but tool vendors whose metrics we treat as mandatory quality gates.

| Authority | Tool | Our Target | URL |
|-----------|------|------------|-----|
| Google | Lighthouse | Performance 100, Best Practices 100, Accessibility 100, SEO 100 | https://pagespeed.web.dev |
| Mozilla | Observatory | Score 145 (A+, never decrease) | https://observatory.mozilla.org |
| SonarSource | SonarCloud | Reliability A, Security A, Maintainability A | https://sonarcloud.io |

**Rule**: These scores are checked during development, not after. A regression in any gate blocks the change.

---

## 4. Data Sources & Intelligence Providers

| Source | What We Get | Rate Limits | URL |
|--------|------------|-------------|-----|
| Team Cymru | IP-to-ASN mapping via DNS | None known | https://www.team-cymru.com |
| OpenPhish | Phishing URL feed | Community feed | https://openphish.com |
| SecurityTrails | Historical DNS records | **50 req/month (hard)** | https://securitytrails.com |
| crt.sh | Certificate Transparency log search | Best-effort | https://crt.sh |
| IANA RDAP | Domain registration data | Best-effort | https://rdap.org |
| ip-api.com | Visitor geolocation (footer flag only) | 45/min (free tier) | https://ip-api.com |

### Excellence Benchmark Sources (ICuAE)

| Source | What We Use | Context |
|--------|------------|---------|
| Farsight DNSDB | Passive DNS collection frequency benchmarks | TTL Compliance and Currentness excellence targets |
| OpenINTEL | Large-scale DNS measurement dataset (Twente/SIDN) | Completeness and Source Credibility baselines |
| DNSPerf | Independent DNS resolver performance testing | Resolver reliability data for multi-resolver consensus benchmarks |

### DNS Resolvers (Multi-Resolver Consensus)

| Resolver | Operator | IP |
|----------|----------|----|
| Cloudflare | Cloudflare | 1.1.1.1 |
| Google | Google | 8.8.8.8 |
| Quad9 | Quad9 Foundation | 9.9.9.9 |
| OpenDNS | Cisco | 208.67.222.222 |
| DNS4EU | EU Digital Sovereignty | Varies |

---

## 5. Non-Standard / Proprietary Directives We Track

These are NOT ratified standards. We detect them as intelligence but never claim they are standards.

| Directive | Origin | Status | Our Position |
|-----------|--------|--------|-------------|
| Content-Usage | IETF aipref WG | Active draft (draft-ietf-aipref-attach) | Detect and report on scanned domains. Do NOT use in our own robots.txt until ratified. |
| Content-Signal | Cloudflare | Proprietary (contentsignals.org) | Not currently detected. Monitor for ecosystem adoption. |
| llms.txt | llmstxt.org | Community convention (NOT RFC 8615) | We serve it; our scanner detects it. Not an IETF standard — it's a community spec. |
| security.txt | IETF | RFC 9116 (Standards Track) | We detect it. This IS a ratified standard. |

---

## 6. Verification Checklist — Before Citing Any Source

1. **Is it ratified?** Check https://datatracker.ietf.org for RFC status. "Internet-Draft" or "Active WG Draft" means NOT ratified.
2. **Has it been obsoleted?** Check the "Obsoleted by" field on datatracker. Citing an obsoleted RFC is embarrassing.
3. **Is it the right RFC?** RFC 8615 defines .well-known/ mechanics — it does NOT define llms.txt. RFC 9309 defines robots.txt parsing — it does NOT define Content-Usage.
4. **Is it proprietary?** If it's from a single vendor (Cloudflare, Google, etc.) and not an IETF/W3C standard, label it "proprietary" or "vendor-specific."
5. **Do we use observation language?** "Detected," "observed," "present" — never "compliant" or "validated" unless we actually validate against the full spec.

---

## 7. Update Protocol

- **When adding a new feature**: Check if the underlying standard is listed here. If not, add it with current status.
- **Every quarter**: Spot-check draft statuses on datatracker. Drafts expire, get adopted, or die.
- **After any Lighthouse/Observatory/SonarCloud regression**: Trace the regression to its root cause and document in EVOLUTION.md "Gotchas" section.
- **Before citing any RFC in UI copy**: Verify it on datatracker. Do not trust cached memory.
