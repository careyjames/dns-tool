# DNS Tool — System Architecture

## 1. High-Level System Overview

```mermaid
graph TB
    subgraph "Client Layer"
        Browser["Browser<br/>Bootstrap Dark Theme"]
    end

    subgraph "Application Server"
        GoBinary["dns-tool-server<br/>Go Binary · Port 5000"]
    end

    subgraph "Application Layer — Go/Gin"
        Router["Gin Router<br/>CSP Middleware"]
        Auth["Google OAuth 2.0 + PKCE<br/>stdlib only"]
        Analytics["Analytics Middleware<br/>Privacy-preserving · No cookies"]
        Handlers["Request Handlers<br/>analysis, history, export, dossier"]
        Templates["Go html/template<br/>Nonce-injected CSP"]
    end

    subgraph "Intelligence Engines"
        ICIE["ICIE<br/>Integrated Confidence in<br/>Ingested Evidence"]
        ICAE["ICAE<br/>Intelligence Confidence<br/>Audit Engine"]
        ICuAE["ICuAE<br/>Intelligence Currency<br/>Assurance Engine"]
    end

    subgraph "Data Collection"
        DNSClient["Multi-Resolver DNS Client<br/>Cloudflare · Google · Quad9 · OpenDNS · DNS4EU"]
        SMTP["SMTP Probe<br/>STARTTLS Verification"]
        CT["Certificate Transparency<br/>crt.sh + Certspotter"]
        HTTP["HTTP Probes<br/>MTA-STS · security.txt · BIMI"]
    end

    subgraph "Post-Analysis Enrichment"
        MisplacedDMARC["Misplaced DMARC Detection<br/>Root TXT scan · RFC 7489 §6.1"]
    end

    subgraph "Remote Infrastructure"
        ProbeServer["SMTP Probe API v2<br/>Ports 25 · 465 · 587"]
    end

    subgraph "Storage"
        PG[("PostgreSQL<br/>Neon-backed")]
    end

    subgraph "External (Optional)"
        SecurityTrails["SecurityTrails API<br/>User-key only · 50 req/mo"]
        IntelRepo["dns-tool (intel build)<br/>Private GitHub Repo"]
    end

    Browser -->|"HTTPS"| GoBinary
    GoBinary --> Router
    Router --> Auth
    Router --> Analytics
    Analytics --> Handlers
    Router --> Handlers
    Handlers --> Templates
    Handlers --> ICIE
    ICIE --> DNSClient
    ICIE -->|"X-Probe-Key auth"| ProbeServer
    ProbeServer -->|"TCP:25,465,587"| SMTP
    ICIE --> CT
    ICIE --> HTTP
    ICIE --> MisplacedDMARC
    ICIE --> ICAE
    ICIE --> ICuAE
    Handlers --> PG
    Analytics -->|"flush aggregates"| PG
    ICAE --> PG
    Handlers -.->|"user-provided key"| SecurityTrails
    GoBinary -.->|"build tags"| IntelRepo

    classDef default fill:#2563eb,stroke:#60a5fa,stroke-width:2px,color:#f0f6fc
    classDef engine fill:#2563eb,stroke:#60a5fa,stroke-width:2px,color:#fff,font-weight:bold
    classDef storage fill:#16a34a,stroke:#4ade80,stroke-width:2px,color:#fff,font-weight:bold
    classDef external fill:#9333ea,stroke:#c084fc,stroke-width:2px,color:#fff,font-weight:bold
    classDef client fill:#2563eb,stroke:#60a5fa,stroke-width:2px,color:#fff,font-weight:bold
    classDef app fill:#2563eb,stroke:#60a5fa,stroke-width:2px,color:#fff
    classDef warn fill:#ca8a04,stroke:#facc15,stroke-width:2px,color:#fff,font-weight:bold
    class ICIE,ICAE,ICuAE engine
    class PG storage
    class SecurityTrails,IntelRepo external
    class Browser client
    class Router,Auth,Analytics,Handlers,Templates app
    class DNSClient,SMTP,CT,HTTP engine
    class ProbeServer external
    class GoBinary app
    class MisplacedDMARC warn
```

## 2. ICIE — Intelligence Classification & Interpretation Engine

```mermaid
graph LR
    subgraph "Input"
        Domain["Domain Name"]
        Selectors["User DKIM Selectors<br/>(optional)"]
        APIKeys["User API Keys<br/>(optional)"]
    end

    subgraph "Collection Layer"
        DNS["DNS Record Collection<br/>A · AAAA · MX · NS · TXT · SOA<br/>CNAME · CAA · TLSA · SRV"]
        SPF["SPF Analysis<br/>RFC 7208"]
        DMARC["DMARC Analysis<br/>RFC 7489"]
        DKIM["DKIM Discovery<br/>RFC 6376<br/>81+ known selectors"]
        DNSSEC["DNSSEC Validation<br/>RFC 4033-4035"]
        DANE["DANE/TLSA<br/>RFC 6698"]
        MTASTS["MTA-STS<br/>RFC 8461"]
        BIMI["BIMI Check<br/>BIMI Spec"]
        CAA["CAA Records<br/>RFC 8659"]
        SMTP2["SMTP STARTTLS<br/>RFC 3207"]
        CT2["CT Log Search<br/>RFC 6962"]
        SubD["Subdomain Discovery<br/>CT + DNS Enumeration"]
    end

    subgraph "Post-Analysis Enrichment"
        MisplacedCheck["Misplaced DMARC Detection<br/>Root TXT → v=DMARC1 scan<br/>RFC 7489 §6.1"]
    end

    subgraph "Classification Layer"
        Posture["Mail Posture<br/>Classification"]
        Brand["Brand Security<br/>Verdict Matrix"]
        Transport["Transport Security<br/>Assessment"]
        Remediation["Remediation<br/>Engine"]
    end

    subgraph "Privacy Gate"
        Privacy{"AllSelectorsKnown()?"}
        Public["Public Analysis<br/>No novel intelligence"]
        Private["Private Analysis<br/>Authenticated + novel selectors"]
        Ephemeral["Ephemeral Analysis<br/>Anonymous + novel selectors<br/>Not persisted"]
    end

    subgraph "Output"
        Engineer["Engineer's Report<br/>Technical · RFC-cited"]
        Executive["Executive's Brief<br/>Board-ready · TLP-classified"]
        JSON["JSON Export<br/>Admin-only"]
    end

    Domain --> DNS
    Selectors --> DKIM
    APIKeys -.-> DNS
    DNS --> SPF & DMARC & DKIM & DNSSEC & DANE & MTASTS & BIMI & CAA & SMTP2 & CT2 & SubD
    DNS -->|"root TXT records"| MisplacedCheck
    MisplacedCheck -->|"enriches"| DMARC
    SPF & DMARC & DKIM --> Posture
    BIMI & CAA & DMARC --> Brand
    DANE & MTASTS & SMTP2 --> Transport
    Posture & Brand & Transport --> Remediation
    Selectors --> Privacy
    Privacy -->|"all known"| Public
    Privacy -->|"novel + auth"| Private
    Privacy -->|"novel + anon"| Ephemeral
    Remediation --> Engineer & Executive & JSON

    classDef default fill:#2563eb,stroke:#60a5fa,stroke-width:2px,color:#f0f6fc
    classDef rfc fill:#2563eb,stroke:#60a5fa,stroke-width:2px,color:#fff,font-weight:bold
    classDef gate fill:#ca8a04,stroke:#facc15,stroke-width:2px,color:#fff,font-weight:bold
    classDef output fill:#16a34a,stroke:#4ade80,stroke-width:2px,color:#fff,font-weight:bold
    classDef classify fill:#0891b2,stroke:#22d3ee,stroke-width:2px,color:#fff,font-weight:bold
    classDef input fill:#6366f1,stroke:#a5b4fc,stroke-width:2px,color:#fff,font-weight:bold
    classDef warn fill:#ca8a04,stroke:#facc15,stroke-width:2px,color:#fff,font-weight:bold
    class SPF,DMARC,DKIM,DNSSEC,DANE,MTASTS,CAA,SMTP2,CT2,SubD,BIMI,DNS rfc
    class Privacy,Public,Private,Ephemeral gate
    class Engineer,Executive,JSON output
    class Posture,Brand,Transport,Remediation classify
    class Domain,Selectors,APIKeys input
    class MisplacedCheck warn
```

## 3. ICAE — Intelligence Confidence Audit Engine

```mermaid
graph TB
    subgraph "Analysis Output"
        Verdicts["ICIE Verdict Results<br/>email_answer · brand_answer<br/>transport_answer · posture"]
    end

    subgraph "ICAE Evaluation Pipeline"
        Runner["Test Runner<br/>129 Deterministic Cases · 9 Protocols"]
        
        subgraph "Analysis Layer Cases"
            SPFCases["SPF Protocol<br/>20 cases"]
            DMARCCases["DMARC Protocol<br/>24 cases"]
            DNSSECCases["DNSSEC Protocol<br/>25 cases"]
            DKIMCases["DKIM Protocol<br/>8 cases"]
        end

        subgraph "Transport & Brand Cases"
            DANECases["DANE/TLSA Protocol<br/>14 cases"]
            MTASTSCases["MTA-STS Protocol<br/>12 cases"]
            TLSRPTCases["TLS-RPT Protocol<br/>5 cases"]
            BIMICases["BIMI Protocol<br/>11 cases"]
            CAACases["CAA Protocol<br/>10 cases"]
        end
    end

    subgraph "Maturity Model"
        Dev["Development<br/>< 100 passes"]
        Verified["Verified<br/>100+ passes"]
        Consistent["Consistent<br/>500+ passes · 30+ days"]
        Gold["Gold<br/>1000+ passes · 90+ days"]
        Master["Gold Master<br/>5000+ passes · 180+ days"]
    end

    subgraph "Storage"
        DB[("ice_audit_runs<br/>ice_case_results<br/>ice_protocol_scores")]
    end

    subgraph "Output"
        Scores["Protocol Confidence Scores<br/>0-100% per protocol"]
        Report["ICAE Audit Report<br/>Pass/Fail per case"]
        Calibration["Calibration Validation<br/>Brier Score · ECE<br/>Reliability Diagram"]
        Hash["SHA-3-512 Integrity Hash<br/>Tamper-evident audit trail"]
    end

    Verdicts --> Runner
    Runner --> SPFCases & DMARCCases & DNSSECCases & DKIMCases
    Runner --> DANECases & MTASTSCases & TLSRPTCases & BIMICases & CAACases
    SPFCases & DMARCCases & DNSSECCases & DKIMCases --> Scores
    DANECases & MTASTSCases & TLSRPTCases & BIMICases & CAACases --> Scores
    Scores --> Dev --> Verified --> Consistent --> Gold --> Master
    Runner --> DB
    Scores --> Report
    Scores --> Calibration
    Report --> Hash

    classDef default fill:#2563eb,stroke:#60a5fa,stroke-width:2px,color:#f0f6fc
    classDef maturity fill:#2563eb,stroke:#60a5fa,stroke-width:2px,color:#fff,font-weight:bold
    classDef cases fill:#0891b2,stroke:#22d3ee,stroke-width:2px,color:#fff,font-weight:bold
    classDef output fill:#16a34a,stroke:#4ade80,stroke-width:2px,color:#fff,font-weight:bold
    class Dev,Verified,Consistent,Gold,Master maturity
    class SPFCases,DMARCCases,DNSSECCases,DKIMCases cases
    class DANECases,MTASTSCases,TLSRPTCases,BIMICases,CAACases cases
    class Scores,Report,Hash output
```

## 4. Two-Repo Open-Core Architecture

```mermaid
graph TB
    subgraph "Public Repo: dns-tool"
        direction TB
        PublicGo["Go Source<br/>All framework code"]
        Stubs["12 OSS Stub Files<br/>//go:build !intel"]
        Templates2["HTML Templates"]
        Static["Static Assets"]
        Tests["Boundary Integrity Tests<br/>12 verification categories"]
        Scripts["Build & Deploy Scripts"]
    end

    subgraph "Private Repo: dns-tool (intel build)"
        direction TB
        Intel["Intelligence Modules<br/>//go:build intel"]
        ProviderDB["Provider Databases<br/>ESP detection · DKIM maps"]
        Methodology["Proprietary Methodology<br/>Classification algorithms"]
        Commercial["Commercial Roadmap<br/>Phase 2-4 plans"]
    end

    subgraph "Build System"
        BuildOSS["OSS Build<br/>go build (default)<br/>Stubs provide safe defaults"]
        BuildIntel["Intel Build<br/>go build -tags intel<br/>Full intelligence capabilities"]
    end

    subgraph "Sync Mechanism"
        Sync["github-intel-sync.mjs<br/>GitHub API read/write"]
    end

    PublicGo --> BuildOSS
    Stubs --> BuildOSS
    PublicGo --> BuildIntel
    Intel --> BuildIntel
    Sync <-->|"push/pull files"| Intel
    Tests -->|"verify no leaks"| PublicGo
    Tests -->|"verify stub contracts"| Stubs

    classDef default fill:#2563eb,stroke:#60a5fa,stroke-width:2px,color:#f0f6fc
    classDef public fill:#2563eb,stroke:#60a5fa,stroke-width:2px,color:#fff,font-weight:bold
    classDef private fill:#9333ea,stroke:#c084fc,stroke-width:2px,color:#fff,font-weight:bold
    classDef build fill:#16a34a,stroke:#4ade80,stroke-width:2px,color:#fff,font-weight:bold
    classDef sync fill:#ca8a04,stroke:#facc15,stroke-width:2px,color:#fff,font-weight:bold
    class PublicGo,Stubs,Templates2,Static,Tests,Scripts public
    class Intel,ProviderDB,Methodology,Commercial private
    class BuildOSS,BuildIntel build
    class Sync sync
```

## 5. Email Security Verdict Chain

```mermaid
graph TB
    subgraph "RFC Standards"
        RFC7208["RFC 7208<br/>SPF — Sender IP Authorization"]
        RFC6376["RFC 6376<br/>DKIM — Message Integrity"]
        RFC7489["RFC 7489<br/>DMARC — Policy & Alignment"]
    end

    subgraph "Authentication Triad"
        SPFCheck{"SPF Record?"}
        DKIMCheck{"DKIM Discoverable?"}
        DMARCCheck{"DMARC Policy?"}
    end

    subgraph "DMARC Enforcement Levels"
        Reject["p=reject<br/>Strongest · Messages rejected"]
        Quarantine["p=quarantine<br/>Moderate · Messages flagged"]
        None["p=none<br/>Monitor only · No enforcement"]
        Missing["No DMARC<br/>No policy"]
    end

    subgraph "Supplementary Checks"
        BIMI2["BIMI<br/>Brand Verification"]
        CAA2["CAA (RFC 8659)<br/>Certificate Restriction"]
    end

    subgraph "Brand Security Verdict Matrix"
        Protected["No — Protected<br/>reject + BIMI + CAA"]
        WellP["Unlikely — Well Protected<br/>reject + BIMI/VMC"]
        MostlyP["Possible — Mostly Protected<br/>reject + CAA only"]
        PartialP["Possible — Partially Protected<br/>reject + neither"]
        AtRisk["Likely — At Risk<br/>quarantine or none"]
        Exposed["Yes — Exposed<br/>No DMARC"]
    end

    RFC7208 --> SPFCheck
    RFC6376 --> DKIMCheck
    RFC7489 --> DMARCCheck
    DMARCCheck -->|"reject"| Reject
    DMARCCheck -->|"quarantine"| Quarantine
    DMARCCheck -->|"none"| None
    DMARCCheck -->|"missing"| Missing
    Reject --> BIMI2 & CAA2
    BIMI2 & CAA2 -->|"both present"| Protected
    BIMI2 -->|"BIMI/VMC present"| WellP
    CAA2 -->|"CAA only"| MostlyP
    BIMI2 & CAA2 -->|"neither"| PartialP
    Quarantine --> AtRisk
    None --> AtRisk
    Missing --> Exposed

    classDef default fill:#2563eb,stroke:#60a5fa,stroke-width:2px,color:#f0f6fc
    classDef safe fill:#16a34a,stroke:#4ade80,stroke-width:2px,color:#fff,font-weight:bold
    classDef warn fill:#ca8a04,stroke:#facc15,stroke-width:2px,color:#fff,font-weight:bold
    classDef danger fill:#dc2626,stroke:#f87171,stroke-width:2px,color:#fff,font-weight:bold
    classDef rfc fill:#2563eb,stroke:#60a5fa,stroke-width:2px,color:#fff,font-weight:bold
    classDef check fill:#0891b2,stroke:#22d3ee,stroke-width:2px,color:#fff,font-weight:bold
    class Protected,WellP safe
    class MostlyP,PartialP warn
    class AtRisk,Exposed danger
    class RFC7208,RFC6376,RFC7489 rfc
    class SPFCheck,DKIMCheck,DMARCCheck check
    class Reject,Quarantine,None,Missing default
    class BIMI2,CAA2 rfc
```

## 6. Misplaced DMARC Record Detection

```mermaid
graph TB
    subgraph "DNS Collection"
        RootTXT["Root Domain TXT Records<br/>dig example.com TXT"]
        DmarcTXT["_dmarc Subdomain TXT<br/>dig _dmarc.example.com TXT"]
    end

    subgraph "DetectMisplacedDMARC()"
        Scan["Scan Root TXT Records<br/>Case-insensitive v=DMARC1 match"]
        Found{"v=DMARC1 in root?"}
        Extract["Extract Policy<br/>Parse p= directive"]
        Build["Build Enrichment Map<br/>detected · records · policy"]
    end

    subgraph "Enrichment"
        Inject["Inject into DMARC Result<br/>misplaced_dmarc field"]
        Issue["Add to Report Issues<br/>Severity · Remediation"]
    end

    subgraph "Report Output"
        Warning["Misplaced Record Warning<br/>RFC 7489 §6.1 citation"]
        Fix["Remediation Guidance<br/>Move to _dmarc subdomain"]
    end

    RootTXT --> Scan
    Scan --> Found
    Found -->|"Yes"| Extract
    Found -->|"No"| DmarcTXT
    Extract --> Build
    Build --> Inject
    Inject --> Issue
    Issue --> Warning & Fix
    DmarcTXT -->|"Normal path"| Issue

    classDef default fill:#2563eb,stroke:#60a5fa,stroke-width:2px,color:#f0f6fc
    classDef warn fill:#ca8a04,stroke:#facc15,stroke-width:2px,color:#fff,font-weight:bold
    classDef safe fill:#16a34a,stroke:#4ade80,stroke-width:2px,color:#fff,font-weight:bold
    classDef danger fill:#dc2626,stroke:#f87171,stroke-width:2px,color:#fff,font-weight:bold
    classDef check fill:#0891b2,stroke:#22d3ee,stroke-width:2px,color:#fff,font-weight:bold
    class Scan,Found,Extract,Build check
    class Inject,Issue warn
    class Warning danger
    class Fix safe
    class RootTXT,DmarcTXT default
```

## 7. Request Lifecycle

```mermaid
sequenceDiagram
    participant B as Browser
    participant R as Gin Router
    participant MW as Middleware
    participant AN as Analytics
    participant H as Handler
    participant ICIE as ICIE Engine
    participant ICuAE as ICuAE Engine
    participant DNS as DNS Client
    participant DB as PostgreSQL

    B->>R: POST /analyze (domain=example.com)
    R->>MW: CSP · Rate Limit · Session
    MW->>AN: Record pageview (salted hash)
    AN->>H: analysisHandler()
    
    H->>ICIE: RunFullAnalysis(domain, selectors)
    
    par Concurrent DNS Collection
        ICIE->>DNS: Query Cloudflare 1.1.1.1
        ICIE->>DNS: Query Google 8.8.8.8
        ICIE->>DNS: Query Quad9 9.9.9.9
        ICIE->>DNS: Query OpenDNS 208.67.222.222
        ICIE->>DNS: Query DNS4EU 194.242.2.2
    end
    
    DNS-->>ICIE: Merged DNS Results
    
    ICIE->>ICIE: SPF Analysis (RFC 7208)
    ICIE->>ICIE: DMARC Analysis (RFC 7489)
    ICIE->>ICIE: Misplaced DMARC Detection
    ICIE->>ICIE: DKIM Discovery (81+ selectors)
    ICIE->>ICIE: DNSSEC Validation
    ICIE->>ICIE: Brand Verdict Matrix
    ICIE->>ICIE: Mail Posture Classification
    
    ICIE-->>H: AnalysisResult{}
    
    H->>ICuAE: Assess currency (staleness, TTL, freshness)
    ICuAE-->>H: CurrencyAudit{}
    
    H->>H: Privacy Gate (AllSelectorsKnown?)
    
    alt Public Analysis
        H->>DB: Persist full results
    else Private Analysis (auth + novel selectors)
        H->>DB: Persist with privacy flag
    else Ephemeral Analysis (anon + novel selectors)
        H-->>H: Do not persist
    end
    
    H->>AN: RecordAnalysis(domain)
    
    H->>R: Render template (engineer/executive)
    R-->>B: HTML Response with CSP nonce
    
    Note over AN,DB: Analytics flushed every 60s<br/>Daily-rotating salt · No PII
    AN->>DB: UPSERT site_analytics (aggregates)
```

## 8. Package Dependency Map

```mermaid
graph TB
    subgraph "cmd"
        Server["cmd/server<br/>main.go — entrypoint"]
    end

    subgraph "internal"
        Config["config<br/>AppVersion · env vars"]
        Middleware["middleware<br/>CSP · rate limit · session<br/>analytics (privacy-preserving)"]
        Handlers["handlers<br/>analysis · auth · history<br/>export · dossier · compare<br/>admin · analytics · about"]
        Analyzer["analyzer<br/>ICIE engine core<br/>posture · dkim · spf · dmarc<br/>remediation · brand · misplaced"]
        AISurface["analyzer/ai_surface<br/>robots.txt · llms.txt<br/>HTTP · poisoning · scanner"]
        ICAE2["icae<br/>ICAE engine · 129 cases<br/>calibration · runner · evaluator"]
        ICuAE2["icuae<br/>Currency assurance<br/>5 audit dimensions"]
        DNSClient2["dnsclient<br/>Multi-resolver queries"]
        DB2["db<br/>PostgreSQL via pgx"]
        DBQ["dbq<br/>Prepared query cache"]
        Models["models<br/>Data structures"]
        Providers["providers<br/>ESP detection stubs"]
        Telemetry["telemetry<br/>Structured logging"]
        Templates3["templates<br/>Template helpers"]
    end

    Server --> Config & Middleware & Handlers
    Handlers --> Analyzer & ICAE2 & ICuAE2 & DB2 & Models & Templates3
    Analyzer --> DNSClient2 & Providers & AISurface
    ICAE2 --> DB2 & Models
    ICuAE2 --> DB2 & Models
    Handlers --> Telemetry
    DB2 --> DBQ
    Middleware --> Config & Telemetry & DB2

    classDef default fill:#2563eb,stroke:#60a5fa,stroke-width:2px,color:#f0f6fc
    classDef core fill:#2563eb,stroke:#60a5fa,stroke-width:2px,color:#fff,font-weight:bold
    classDef engine fill:#0891b2,stroke:#22d3ee,stroke-width:2px,color:#fff,font-weight:bold
    classDef infra fill:#9333ea,stroke:#c084fc,stroke-width:2px,color:#fff,font-weight:bold
    class Analyzer,AISurface,ICAE2,ICuAE2 engine
    class Server,Handlers,Middleware core
    class DB2,DBQ,DNSClient2,Telemetry infra
    class Config,Models,Providers,Templates3 default
```

## 9. Distributed Probe Mesh — Future Architecture

The Distributed Probe Mesh extends DNS Tool's multi-vantage intelligence from
dedicated probe nodes to a volunteer network of browser-based DNS probes.

### Design Principles

- **Accuracy first**: Volunteer probes augment but never override trusted anchor nodes
- **Untrusted by default**: All volunteer data treated as untrusted; consensus is mathematically enforced
- **Privacy-preserving**: Blinded work queues, batched queries, ephemeral session IDs, no PII

### Consensus Model

```mermaid
graph TB
    subgraph "Trusted Anchors"
        N1["Anchor Node 1"]
        N2["Anchor Node 2"]
    end

    subgraph "Volunteer Probe Mesh"
        V1["Browser Probe<br/>AS1 · Region A"]
        V2["Browser Probe<br/>AS2 · Region B"]
        V3["Browser Probe<br/>AS3 · Region A"]
        VN["Browser Probe<br/>ASn · Region C"]
    end

    subgraph "Volunteer Probe Gateway"
        Relay["DoH Relay API<br/>Signed payloads · Rate limits"]
    end

    subgraph "Consensus Engine"
        CE["consensus_probe.go<br/>Byzantine threshold: ≥3 ASNs, ≥2 regions<br/>Reputation-weighted scoring"]
    end

    subgraph "Intelligence Engines"
        ICAE["ICAE/ICuAE<br/>Supplemental evidence"]
    end

    V1 & V2 & V3 & VN -->|"HTTPS"| Relay
    N1 & N2 -->|"Trusted anchor"| CE
    Relay -->|"Canonicalized results"| CE
    CE -->|"Consensus or Inconclusive"| ICAE

    classDef default fill:#2563eb,stroke:#60a5fa,stroke-width:2px,color:#f0f6fc
    classDef trusted fill:#16a34a,stroke:#4ade80,stroke-width:2px,color:#fff,font-weight:bold
    classDef volunteer fill:#9333ea,stroke:#c084fc,stroke-width:2px,color:#fff,font-weight:bold
    classDef engine fill:#0891b2,stroke:#22d3ee,stroke-width:2px,color:#fff,font-weight:bold
    class N1,N2 trusted
    class V1,V2,V3,VN volunteer
    class CE,ICAE engine
    class Relay default
```

### Phased Rollout

| Phase | Scope |
|-------|-------|
| **MVP** | Standalone DoH relay + web widget. A/AAAA/NS/MX/TXT queries. Per-probe metadata. |
| **Beta** | Consensus engine, ASN/geo diversity scoring, anomaly flags, volunteer badges. |
| **Production** | Reputation system, fraud detection, blinded task queues, browser extension, API for self-hosted nodes. |

### Community Model — Good Net Citizens

Volunteers contribute multi-vantage DNS intelligence as OSINT officers,
strengthening the public pool of infrastructure intelligence. Tiers:

- **Widget** — One-click browser participation (lightweight, privacy notice)
- **Extension** — Persistent probe node via browser extension
- **Self-Hosted** — API for power users running signed probe nodes

## 10. Encrypted DNS Transport Detection

DNS Tool will probe whether domains support encrypted DNS transports:

- **DoH** (DNS-over-HTTPS, RFC 8484) — HTTPS endpoint discovery via `.well-known/dns-query` and SVCB/HTTPS records
- **DoT** (DNS-over-TLS, RFC 7858) — TCP/853 connectivity and certificate validation
- **DDR** (Discovery of Designated Resolvers, RFC 9462) — SVCB `_dns.resolver.arpa` record detection

These complement the existing protocol analysis (SPF, DKIM, DMARC, DANE, DNSSEC,
CAA, MTA-STS, TLS-RPT, BIMI) and map to the DNS Engineer archetype's RFC-grounded
posture assessment.

---

## 11. Drift Engine — Posture Change Detection

The drift engine detects DNS posture changes between analyses, enabling continuous security monitoring.

```mermaid
graph LR
    SCAN["Domain Scan<br/>ICIE analysis"]:::blue --> HASH["Posture Hash<br/>SHA-256 canonical"]:::blue
    HASH -->|"hash changed"| DIFF["Posture Diff<br/>Field-by-field<br/>comparison"]:::cyan
    DIFF --> SEV["Severity Engine<br/>danger · warning<br/>success · info"]:::amber
    SEV --> EVENT["Drift Event<br/>PostgreSQL record"]:::green
    EVENT --> WATCH["Watchlist Lookup<br/>domain_watchlist"]:::purple
    WATCH --> QUEUE["Queue Notifications<br/>Per-endpoint routing"]:::purple
    QUEUE --> DELIVER["Delivery Loop<br/>30s poll · 50/batch<br/>SSRF-protected"]:::purple
    DELIVER --> DISCORD["Discord<br/>Webhook embed"]:::blue
    DELIVER --> WEBHOOK["Generic Webhook<br/>JSON POST"]:::blue
    DELIVER -.-> EMAIL["Email<br/>SES/SMTP (planned)"]:::gray

    classDef blue fill:#2563eb,stroke:#60a5fa,stroke-width:2px,color:#fff
    classDef cyan fill:#0a3a4a,stroke:#22d3ee,stroke-width:2px,color:#e6edf3
    classDef amber fill:#ca8a04,stroke:#facc15,stroke-width:2px,color:#fff
    classDef green fill:#16a34a,stroke:#4ade80,stroke-width:2px,color:#fff
    classDef purple fill:#9333ea,stroke:#c084fc,stroke-width:2px,color:#fff
    classDef gray fill:#1a1a2a,stroke:#6b7280,stroke-width:2px,color:#9ca3af,stroke-dasharray:5
```

### Key Components

| Component | File | Purpose |
|-----------|------|---------|
| Posture Hash | `posture_hash.go` | Canonical SHA-256 hash of analysis results |
| Posture Diff | `posture_diff.go` | Structured field-by-field comparison |
| Severity Classification | `posture_diff_oss.go` | Maps changes to Bootstrap severity classes |
| Drift Persistence | `analysis.go` | `persistDriftEvent()` creates drift events |
| Notification Queuing | `analysis.go` | `queueDriftNotifications()` routes to watchlist watchers |
| Delivery Loop | `main.go` | `startNotificationDelivery()` — 30s poll, 50/batch |
| SSRF Protection | `notifier.go` | `isSSRFSafe()` blocks private/loopback IPs |

### Drift Severity Rules (OSS Defaults)

- DMARC policy downgrade (reject → none): `danger`
- DMARC policy upgrade (none → reject): `success`
- Security status degradation (pass → fail): `danger`
- Security status improvement (fail → pass): `success`
- MX/NS record changes: `warning`
- Other changes: `info`

## 12. GitHub Issues Triage — Three-Tier Intelligence Routing

```mermaid
graph TD
    NEW["New Issue<br/>Template required"]:::blue
    NEW --> T1["Research Mission Critical<br/>RFC citation required<br/>P0 priority"]:::danger
    NEW --> T2["Cosmetic / UX / UI<br/>Screenshot required"]:::amber
    NEW --> T3["Security Vulnerability<br/>Auto-close + lock"]:::purple

    T1 --> VALIDATE["Content Validation<br/>RFC ref · Expected/Observed"]:::cyan
    VALIDATE -->|"Substantive"| ACCEPTED["triage/accepted"]:::green
    VALIDATE -->|"Incomplete"| NEEDSINFO["triage/needs-information"]:::amber

    T2 --> ACCEPTED
    T3 --> REDIRECT["Private Channel<br/>Security Advisory<br/>security@it-help.tech"]:::purple

    classDef blue fill:#2563eb,stroke:#60a5fa,stroke-width:2px,color:#fff
    classDef cyan fill:#0a3a4a,stroke:#22d3ee,stroke-width:2px,color:#e6edf3
    classDef amber fill:#ca8a04,stroke:#facc15,stroke-width:2px,color:#fff
    classDef green fill:#16a34a,stroke:#4ade80,stroke-width:2px,color:#fff
    classDef purple fill:#9333ea,stroke:#c084fc,stroke-width:2px,color:#fff
    classDef danger fill:#dc2626,stroke:#ef4444,stroke-width:2px,color:#fff
```

### Triage Categories

| Category | Priority | Automation | Examples |
|----------|----------|------------|---------|
| Research Mission Critical | P0 — Immediate | Validates RFC references, checks substantive content | Wrong RFC citation, flawed confidence logic, broken detection vector |
| Cosmetic / UX / UI | Normal cadence | Auto-acknowledge, version/device tracking | Layout bugs, accessibility issues, visual polish |
| Security Vulnerability | Private only | Auto-close, lock, redirect to advisory | Vulnerabilities, exploits, security flaws |

### Automated Safeguards

- **Blank issues disabled** — all reporters must choose a template
- **Duplicate check** — required checkbox: "I have searched existing issues"
- **Security keyword scanner** — detects vulnerability-related terms in non-security issues, flags for review
- **Idempotent comments** — bot markers prevent duplicate acknowledgments on edits
- **Label state machine** — `needs-triage` → `triage/accepted` or `triage/needs-information`

---

*Generated for DNS Tool v26.34.54 — March 6, 2026*
*Diagrams render natively on GitHub, GitLab, and VS Code with Mermaid plugins.*
