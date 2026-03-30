# DNS Tool — Master Copy (Approved Messaging)

> **Classification**: Internal — project-level reference document.
> **Last updated**: 2026-02-20 (v26.21.26)
> **Purpose**: Single source of truth for all marketing copy, SEO metadata, social tags, JSON-LD schema, and OG image specs. Update this document first, then propagate to code.

---

## 1. Brand Identity

| Element | Value |
|---------|-------|
| **Product name** | DNS Tool |
| **Subtitle** | Domain Security Intelligence |
| **Full title** | DNS Tool — Domain Security Intelligence |
| **Tagline** | DNS, same way since 1983 |
| **Philosophy** | Unix-native naming + strong positioning copy |
| **Naming rationale** | Owns Snap store listing, fits Unix tradition (nmap, dig, nslookup), lets positioning carry authority |
| **License** | BSL 1.1 (open-core) |
| **Company** | IT Help San Diego Inc. |

---

## 2. Stars-Aligned Keywords (Core 8)

These passed the triple test: "Do we do it? Would someone search for it? Does it matter?"

| # | Keyword Phrase | Why It Works |
|---|---------------|--------------|
| 1 | **domain security audit** | Core product description, high commercial intent |
| 2 | **SPF DKIM DMARC analyzer** | Protocol-specific, exact match for practitioner searches |
| 3 | **DNS intelligence report** | Unique differentiator — nobody else calls it this |
| 4 | **email authentication checker** | Broad funnel, captures non-expert searches |
| 5 | **OSINT domain security** | Community credibility, researcher audience |
| 6 | **DNS security posture** | Enterprise/CISO language, board-ready framing |
| 7 | **DANE TLSA checker** | Low competition, high authority — we actually do this well |
| 8 | **AI crawler governance audit** | Zero competition, emerging category we defined |

### Supporting Keywords (7 additional)

These appear in meta tags alongside the core 8, providing protocol coverage without bloat:

- DNSSEC validation
- BIMI checker
- MTA-STS checker
- CAA record check
- email header analyzer
- IP intelligence
- cybersecurity posture report

### Keywords We Dropped (and why)

| Dropped | Reason |
|---------|--------|
| SPF flattening | We don't do this |
| DMARC monitoring | Implies ongoing SaaS monitoring we don't offer |
| subdomain discovery | Not a primary feature |
| ASN lookup | Supporting feature, not searchable intent |
| DMARCbis, MPIC | Too niche, zero search volume |
| email security management | Too generic, dominated by Proofpoint/Mimecast |
| domain reputation | We analyze DNS, not reputation scoring |

---

## 3. Meta Tags (Current Approved)

### Title Tag
```
DNS Tool — Domain Security Intelligence | OSINT Reports
```

### Meta Description
```
OSINT domain security audit — no login required. Analyzes SPF, DKIM, DMARC, DANE, DNSSEC, BIMI, MTA-STS, CAA. Engineer & Executive intelligence reports. Open-standard protocols.
```

### Meta Keywords
```
domain security audit, SPF DKIM DMARC analyzer, DNS intelligence report, email authentication checker, OSINT domain security, DNS security posture, DANE TLSA checker, AI crawler governance audit, DNSSEC validation, BIMI checker, MTA-STS checker, CAA record check, email header analyzer, IP intelligence, cybersecurity posture report
```

---

## 4. Open Graph Tags (Facebook/LinkedIn)

```html
<meta property="og:url" content="https://dnstool.it-help.tech/">
<meta property="og:type" content="website">
<meta property="og:title" content="DNS Tool — Domain Security Intelligence | OSINT Reports">
<meta property="og:description" content="OSINT-based domain security audit producing Engineer's DNS Intelligence Reports and Executive's DNS Intelligence Briefs. Analyzes SPF, DKIM, DMARC, DANE/TLSA, DNSSEC, BIMI, MTA-STS, TLS-RPT, CAA from multiple intelligence sources. Email Header Analyzer, IP Intelligence, AI Surface Scanner. TLP classification. All analysis uses open-standard protocols.">
<meta property="og:image" content="https://dnstool.it-help.tech/static/images/og-image.png">
```

### OG Image Specs
- **Dimensions**: 1200 x 630 px (Facebook/LinkedIn optimal)
- **Format**: PNG
- **Content**: Dark theme matching site, product name + subtitle, protocol badges
- **Text**: "DNS Tool — Domain Security Intelligence"
- **Subtext**: "Engineer's Reports • Executive Briefs • OSINT Analysis"

---

## 5. Twitter Card Tags

```html
<meta name="twitter:card" content="summary_large_image">
<meta property="twitter:domain" content="dnstool.it-help.tech">
<meta property="twitter:url" content="https://dnstool.it-help.tech/">
<meta name="twitter:title" content="DNS Tool — Domain Security Intelligence | OSINT Reports">
<meta name="twitter:description" content="OSINT-based domain security audit producing Engineer's DNS Intelligence Reports and Executive's DNS Intelligence Briefs. Analyzes SPF, DKIM, DMARC, DANE/TLSA, DNSSEC, BIMI, MTA-STS, TLS-RPT, CAA from multiple intelligence sources. Email Header Analyzer, IP Intelligence, AI Surface Scanner. TLP classification. All analysis uses open-standard protocols.">
<meta name="twitter:image" content="https://dnstool.it-help.tech/static/images/og-image.png">
```

---

## 6. JSON-LD Schema (Structured Data)

```json
{
  "@context": "https://schema.org",
  "@type": "WebApplication",
  "name": "DNS Tool",
  "alternateName": "DNS Tool — Domain Security Intelligence",
  "description": "OSINT domain security audit producing Engineer's DNS Intelligence Reports and Executive's DNS Intelligence Briefs. Analyzes SPF, DKIM, DMARC, DANE, DNSSEC, BIMI, MTA-STS, CAA.",
  "url": "https://dnstool.it-help.tech",
  "applicationCategory": "SecurityApplication",
  "operatingSystem": "Web",
  "offers": {
    "@type": "Offer",
    "price": "0",
    "priceCurrency": "USD"
  },
  "creator": {
    "@type": "Organization",
    "name": "IT Help San Diego Inc.",
    "url": "https://it-help.tech"
  },
  "featureList": [
    "SPF record analysis",
    "DKIM signature validation",
    "DMARC policy evaluation",
    "DANE/TLSA record verification",
    "DNSSEC validation chain",
    "BIMI record analysis",
    "MTA-STS policy checking",
    "TLS-RPT configuration",
    "CAA record audit",
    "AI crawler governance audit",
    "Email header forensic analysis",
    "IP and ASN intelligence",
    "SMTP transport security probing",
    "Engineer's DNS Intelligence Report",
    "Executive's DNS Intelligence Brief"
  ]
}
```

---

## 7. Report Names (Capitalization Rules)

| Report Type | Official Name |
|------------|---------------|
| Technical | Engineer's DNS Intelligence Report |
| Executive | Executive's DNS Intelligence Brief |
| Generic reference | "intelligence reports" (lowercase when not naming the specific product) |

**Capitalization standard**: NIST/Chicago title case for all user-facing headings, badges, trust indicators. Never camelCase in UI copy.

---

## 8. Positioning Copy (Approved Phrases)

| Context | Copy |
|---------|------|
| Hero subtitle | Domain Security Intelligence |
| Footer tagline | DNS, same way since 1983 |
| What we are | OSINT platform for RFC-compliant domain security analysis |
| What we produce | Intelligence reports, not dashboards |
| How we work | Open-standard protocols, no login required |
| Differentiator | Observation-based analysis — we read the DNS record, we don't own the mailbox |
| TLP framing | FIRST TLP v2.0, default TLP:AMBER |

---

## 9. Multi-Part TLD Handling (co.uk Education)

### How We Handle It

DNS Tool correctly handles multi-part TLDs (also called "country-code second-level domains" or ccSLDs). Three layers:

1. **Public Suffix List** (`golang.org/x/net/publicsuffix`) — The Mozilla-maintained gold standard. Used for subdomain detection.
2. **Hardcoded ccSLD map** — 50+ entries covering `.co.uk`, `.com.au`, `.co.nz`, `.co.jp`, `.co.kr`, `.com.br`, `.com.cn`, `.co.in`, `.co.za`, `.com.mx`, `.co.il`, `.com.sg`, `.com.hk`, `.com.tw`, `.co.id`, `.com.ar` and their siblings. Used for NS delegation and enterprise DNS classification.
3. **ICAE test coverage** — Deterministic test cases for `bbc.co.uk` (enterprise-dns-008) and `example.com.au` (enterprise-dns-009).

### What Users Should Know

When scanning a `.co.uk` domain (e.g., `bbc.co.uk`):
- The registrable domain is correctly identified as `bbc.co.uk`, not `co.uk`
- NS delegation analysis correctly attributes nameservers to the organization
- Enterprise DNS classification works properly (dedicated vs. managed vs. shared)
- SPF, DKIM, DMARC lookups target the correct zone
- Subdomain detection correctly identifies `www.bbc.co.uk` as a subdomain of `bbc.co.uk`

### Common ccSLD Patterns

| Country | ccSLDs |
|---------|--------|
| UK | .co.uk, .org.uk, .gov.uk, .ac.uk, .me.uk |
| Australia | .com.au, .org.au, .gov.au, .edu.au, .net.au |
| New Zealand | .co.nz, .org.nz, .govt.nz, .net.nz |
| Japan | .co.jp, .or.jp, .go.jp, .ne.jp, .ac.jp |
| Brazil | .com.br, .org.br, .gov.br, .net.br |
| India | .co.in, .org.in, .gov.in, .net.in |
| South Africa | .co.za, .org.za, .gov.za, .net.za |

---

## 10. Changelog

| Date | Change | By |
|------|--------|----|
| 2026-02-20 | Initial master copy created. Stars-aligned keywords defined. | Agent |
| 2026-02-20 | Repos renamed to dns-tool (single-repo consolidation) | Agent |
| 2026-02-20 | SEO keywords refined from 30+ to 15 focused terms | Agent |

