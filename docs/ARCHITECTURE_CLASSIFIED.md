# DNS Tool — Classified Intelligence Architecture

> **CLASSIFICATION: PROPRIETARY — Intel Repo Only**
> This document contains implementation details that MUST NOT appear in the public DnsToolWeb repository.
> The public-facing version is `docs/architecture/SYSTEM_ARCHITECTURE.md` — it shows structural architecture only.
> This classified version shows the full intelligence pipeline, provider databases, scoring algorithms, and methodology.

---

## 1. Complete Intelligence Pipeline (Full Chain)

```mermaid
graph TB
    subgraph "Input Layer"
        Domain["Domain Name"]
        Selectors["User DKIM Selectors"]
        APIKeys["User API Keys<br/>SecurityTrails (50 req/mo)"]
        ZoneFile["Zone File Upload<br/>(ON ROADMAP)"]
    end

    subgraph "Collection Layer — Multi-Source Intelligence"
        direction TB
        subgraph "DNS Resolution (UDP · 4 resolvers)"
            CF["Cloudflare 1.1.1.1"]
            Google["Google 8.8.8.8"]
            Q9["Quad9 9.9.9.9"]
            ODNS["OpenDNS 208.67.222.222"]
        end

        subgraph "Record Types (Full Spectrum)"
            A["A · AAAA"]
            MX["MX"]
            NS["NS"]
            TXT["TXT (SPF · DMARC · DKIM · BIMI · MTA-STS · TLS-RPT)"]
            CAA2["CAA"]
            TLSA["TLSA (DANE)"]
            SOA["SOA"]
            SRV["SRV"]
            CNAME["CNAME chains"]
        end

        subgraph "Active Probing"
            SMTP["SMTP STARTTLS<br/>Port 25 · EHLO · Certificate"]
            MTASTS["MTA-STS Policy Fetch<br/>/.well-known/mta-sts.txt"]
            SecurityTxt["security.txt<br/>/.well-known/security.txt"]
            BIMI3["BIMI VMC<br/>default._bimi TXT"]
        end

        subgraph "Certificate Transparency Pipeline"
            CTFetch["crt.sh PostgreSQL API<br/>10s independent context<br/>10MB body limit"]
            CTProcess["processCTEntries()<br/>Dedup · wildcard detection<br/>date normalization"]
            DNSProbe["probeCommonSubdomains()<br/>~290 service names<br/>20 goroutines · UDP<br/>15s independent context"]
            CNAMEChase["CNAME Chain Traversal<br/>Infrastructure fingerprinting"]
            Enrich["enrichSubdomainsV2()<br/>Live DNS A/CNAME resolution<br/>20 goroutines · 10s context"]
            SmartSort["sortSubdomainsSmartOrder()<br/>Service names first<br/>Then DNS-resolving<br/>Then cert activity"]
            DisplayCap["applySubdomainDisplayCap()<br/>200 display · 25 historical overflow<br/>NEVER hides active subs<br/>CSV export bypasses cap"]
        end
    end

    subgraph "AI Surface Intelligence"
        RobotsTxt["robots.txt AI Crawler Detection<br/>GPTBot · Claude-Web · Bingbot AI<br/>Directive classification"]
        LLMSTxt["llms.txt / llms-full.txt<br/>AI preference signals"]
        Poisoning["AI Recommendation Poisoning<br/>Indicator detection"]
        HTTPConfig["HTTP Client Config<br/>Timeout · headers · TLS"]
        AIScanner["AI Surface Scanner<br/>Orchestrator"]
    end

    subgraph "Provider Fingerprinting (CLASSIFIED)"
        ProviderDB["Provider Database<br/>377 lines · Pattern matching"]
        InfraDB["Infrastructure DB<br/>816 lines · Hosting/DNS/Email"]
        EdgeCDN["Edge/CDN Detection<br/>160 lines · ASN patterns"]
        SaaSTXT["SaaS TXT Detection<br/>126 lines · Domain verification"]
        IPDB["IP Investigation<br/>616 lines · CDN/cloud · neighborhood"]
        DKIMProv["DKIM Provider DB<br/>Selector-to-provider mapping"]
        EmailProv["Email Provider DB<br/>MX/SPF fingerprinting"]
    end

    Domain --> CF & Google & Q9 & ODNS
    CF & Google & Q9 & ODNS --> A & MX & NS & TXT & CAA2 & TLSA & SOA & SRV & CNAME
    Domain --> SMTP & MTASTS & SecurityTxt & BIMI3
    Domain --> CTFetch
    CTFetch --> CTProcess --> DNSProbe --> CNAMEChase --> Enrich --> SmartSort --> DisplayCap
    Domain --> AIScanner --> RobotsTxt & LLMSTxt & Poisoning
    MX & TXT & NS --> ProviderDB & InfraDB & EdgeCDN & SaaSTXT & EmailProv & DKIMProv
    A --> IPDB

    classDef classified fill:#7d3c98,stroke:#9b59b6,color:#fff
    classDef pipeline fill:#1a5276,stroke:#2980b9,color:#fff
    classDef collection fill:#0e6655,stroke:#1abc9c,color:#fff
    class ProviderDB,InfraDB,EdgeCDN,SaaSTXT,IPDB,DKIMProv,EmailProv classified
    class CTFetch,CTProcess,DNSProbe,CNAMEChase,Enrich,SmartSort,DisplayCap pipeline
    class CF,Google,Q9,ODNS collection
```

## 2. ICIE Classification Engine — Full Verdict Logic

```mermaid
graph TB
    subgraph "Posture Scoring (CLASSIFIED — scoring/posture.go · 746 lines)"
        CVSS["CVSS-Aligned Risk Scoring"]
        RiskLevels["Risk Level Classification<br/>Critical · High · Medium · Low · Info"]
        SectionStatus["Section Status Categorization<br/>Per-protocol health grades"]
        OverallPosture["Overall Posture Score<br/>Weighted composite"]
    end

    subgraph "Confidence Labeling (scoring/confidence.go)"
        Observed["Observed<br/>Direct DNS evidence"]
        Inferred["Inferred<br/>Pattern-matched from related records"]
        ThirdParty["Third-Party<br/>CT logs · external APIs"]
    end

    subgraph "DKIM State Machine (scoring/dkim_state.go)"
        Published["Published<br/>Valid DKIM key found"]
        Missing["Missing<br/>No key at selector"]
        Weak["Weak<br/>Key < 2048 bits"]
        Revoked["Revoked<br/>p= empty (RFC 6376)"]
    end

    subgraph "Brand Verdict Matrix (8 branches)"
        BV1["p=reject + BIMI + CAA → No (Protected)"]
        BV2["p=reject + one → Possible (Mostly Protected)"]
        BV3["p=reject + neither → Possible (Partially Protected)"]
        BV4["p=quarantine + BIMI + CAA → Possible (Mostly Protected)"]
        BV5["p=quarantine + one → Likely (At Risk)"]
        BV6["p=quarantine + neither → Likely (At Risk)"]
        BV7["p=none → Likely (At Risk)"]
        BV8["No DMARC → Yes (Exposed)"]
    end

    subgraph "Remediation Engine (CLASSIFIED — remediation/remediation.go · 1049 lines)"
        SPFRem["SPF Remediation<br/>~all vs -all progression<br/>Include chain optimization"]
        DMARCRem["DMARC Remediation<br/>none → quarantine → reject<br/>Percentage ramp guidance"]
        DKIMRem["DKIM Remediation<br/>Key strength · rotation<br/>Selector management"]
        DNSSECRem["DNSSEC Remediation<br/>Chain repair · algorithm upgrade"]
        DANERem["DANE + MTA-STS<br/>Deployment best practices<br/>Provider-specific guidance"]
        CAARem["CAA Recommendations<br/>Issue/issuewild restriction"]
    end

    CVSS --> RiskLevels --> SectionStatus --> OverallPosture
    OverallPosture --> SPFRem & DMARCRem & DKIMRem & DNSSECRem & DANERem & CAARem

    classDef classified fill:#7d3c98,stroke:#9b59b6,color:#fff
    classDef verdict fill:#1a5276,stroke:#2980b9,color:#fff
    class CVSS,RiskLevels,SectionStatus,OverallPosture,SPFRem,DMARCRem,DKIMRem,DNSSECRem,DANERem,CAARem classified
    class BV1,BV2,BV3,BV4,BV5,BV6,BV7,BV8 verdict
```

## 3. Provider Fingerprinting Chain (CLASSIFIED)

```mermaid
graph LR
    subgraph "Input Signals"
        MXRecords["MX Records<br/>e.g., aspmx.l.google.com"]
        SPFInclude["SPF include: directives<br/>e.g., _spf.google.com"]
        NSRecords["NS Records<br/>e.g., ns1.cloudflare.com"]
        TXTRecords["TXT Records<br/>Domain verification strings"]
        ARecords["A/AAAA Records<br/>IP addresses"]
        ASN["ASN Lookup<br/>BGP origin"]
    end

    subgraph "Provider Detection Engines"
        EmailDet["Email Provider Detection<br/>providers.go · 377 lines<br/>DMARC monitoring vendors<br/>SPF flattening services"]
        InfraDet["Infrastructure Detection<br/>infrastructure.go · 816 lines<br/>Hosting · DNS · Email<br/>Pattern-based fingerprinting"]
        CDNDet["CDN/Edge Detection<br/>edge_cdn.go · 160 lines<br/>ASN-based · DNS patterns"]
        SaaSDet["SaaS Detection<br/>saas_txt.go · 126 lines<br/>TXT record patterns"]
        IPDet["IP Investigation<br/>ip_investigation.go · 616 lines<br/>CDN/Cloud detection<br/>Neighborhood analysis"]
        DKIMDet["DKIM Provider Mapping<br/>dkim_providers.go<br/>Selector → Provider"]
    end

    subgraph "Intelligence Output"
        ProvList["Detected Providers<br/>Name · confidence · evidence"]
        InfraMap["Infrastructure Map<br/>Hosting · CDN · DNS · Email"]
        RiskFactors["Risk Factors<br/>Shared hosting · expired certs<br/>Dangling CNAMEs"]
    end

    MXRecords & SPFInclude --> EmailDet
    NSRecords --> InfraDet
    TXTRecords --> SaaSDet
    ARecords --> IPDet
    ASN --> CDNDet
    MXRecords & SPFInclude --> DKIMDet
    EmailDet & InfraDet & CDNDet & SaaSDet & IPDet & DKIMDet --> ProvList & InfraMap & RiskFactors

    classDef classified fill:#7d3c98,stroke:#9b59b6,color:#fff
    class EmailDet,InfraDet,CDNDet,SaaSDet,IPDet,DKIMDet classified
```

## 4. ICAE Audit Pipeline — Full Detail

```mermaid
graph TB
    subgraph "Test Case Architecture"
        subgraph "Analysis Layer (45 cases)"
            SPFCases["SPF Analysis · 8 cases<br/>hard fail · soft fail · none<br/>too many lookups · redirect<br/>multiple records · neutral · permerror"]
            DMARCCases["DMARC Analysis · 12 cases<br/>reject · quarantine · none<br/>missing · percentage · rua/ruf<br/>subdomain policy · alignment"]
            TransportCases["Transport Analysis · 8 cases<br/>DANE present · MTA-STS<br/>both present · neither<br/>STARTTLS only · partial"]
            PostureCases["Posture Classification · 9 cases<br/>no-mail verified · no-mail partial<br/>protected · partial · at-risk<br/>exposed · unknown"]
            BrandCases["Brand Impersonation · 8 cases<br/>Full matrix coverage<br/>reject+BIMI+CAA through missing DMARC"]
        end

        subgraph "Collection Layer (0 cases — planned)"
            CollectionPlanned["Future: raw DNS response<br/>validation per protocol"]
        end
    end

    subgraph "Evaluation Engine (icae/evaluate.go)"
        Validator["Case Validator<br/>Expected vs Actual comparison"]
        Extractor["Answer Extractor<br/>Protocol-specific field access"]
        Scorer["Protocol Scorer<br/>Pass/fail ratio per protocol"]
    end

    subgraph "Maturity Progression"
        M1["Development<br/>< 50% pass rate"]
        M2["Verified<br/>50-70% pass rate"]
        M3["Consistent<br/>70-90% pass rate"]
        M4["Gold<br/>90-99% pass rate"]
        M5["Master Gold<br/>100% sustained"]
    end

    subgraph "Storage (ice_* tables)"
        AuditRuns["ice_audit_runs<br/>Run metadata · timestamp · version"]
        CaseResults["ice_case_results<br/>Per-case pass/fail · actual vs expected"]
        ProtocolScores["ice_protocol_scores<br/>Aggregate scores per protocol"]
    end

    SPFCases & DMARCCases & TransportCases & PostureCases & BrandCases --> Validator
    Validator --> Extractor --> Scorer
    Scorer --> M1 --> M2 --> M3 --> M4 --> M5
    Validator --> AuditRuns & CaseResults
    Scorer --> ProtocolScores

    classDef engine fill:#0e6655,stroke:#1abc9c,color:#fff
    classDef maturity fill:#1a5276,stroke:#2980b9,color:#fff
    classDef storage fill:#145a32,stroke:#27ae60,color:#fff
    class Validator,Extractor,Scorer engine
    class M1,M2,M3,M4,M5 maturity
    class AuditRuns,CaseResults,ProtocolScores storage
```

## 5. Two-Repo Build Tag Boundary — Full Inventory

```mermaid
graph TB
    subgraph "Public Repo — DnsToolWeb (//go:build !intel)"
        subgraph "12 OSS Stub Files"
            S1["edge_cdn_oss.go<br/>CDN detection → empty"]
            S2["saas_txt_oss.go<br/>SaaS detection → empty"]
            S3["infrastructure_oss.go<br/>Infra detection → empty"]
            S4["providers_oss.go<br/>Provider detection → defaults"]
            S5["ip_investigation_oss.go<br/>IP analysis → empty"]
            S6["manifest_oss.go<br/>Feature manifest → nil"]
            S7["posture_diff_oss.go<br/>Posture diff → nil"]
            S8["ai/http_oss.go<br/>HTTP config → defaults"]
            S9["ai/llms_txt_oss.go<br/>LLMs.txt → empty"]
            S10["ai/robots_txt_oss.go<br/>Robots AI → empty"]
            S11["ai/poisoning_oss.go<br/>Poisoning → empty"]
            S12["ai/scanner_oss.go<br/>AI scanner → empty"]
        end

        subgraph "Core Framework (always compiled)"
            Analyzer2["analyzer.go · orchestrator.go"]
            Protocols["spf.go · dkim.go · dmarc.go<br/>dane.go · dnssec.go · bimi.go<br/>caa.go · mta_sts.go · tlsrpt.go"]
            Posture2["posture.go (brand verdict)"]
            Records2["records.go · ns_delegation.go"]
            SMTP3["smtp_transport.go"]
            SubDomain["subdomains.go (CT pipeline)"]
        end
    end

    subgraph "Private Repo — dnstool-intel (//go:build intel)"
        subgraph "12 Intel Files (replace stubs)"
            I1["edge_cdn_intel.go<br/>Real CDN fingerprinting"]
            I2["saas_txt_intel.go<br/>Real SaaS detection"]
            I3["infrastructure_intel.go<br/>Full infra DB"]
            I4["providers_intel.go<br/>Full provider DB"]
            I5["ip_investigation_intel.go<br/>Real IP analysis"]
            I6["manifest_intel.go<br/>Full feature manifest"]
            I7["(posture_diff_intel.go)<br/>Real posture diff"]
            I8["ai/http_intel.go<br/>Real HTTP config"]
            I9["ai/llms_txt_intel.go<br/>Real LLMs.txt analysis"]
            I10["ai/robots_txt_intel.go<br/>Real robots AI analysis"]
            I11["ai/poisoning_intel.go<br/>Real poisoning detection"]
            I12["ai/scanner_intel.go<br/>Real AI scanner"]
        end

        subgraph "Provider Databases (no public equivalent)"
            PDB1["providers.go — 25,780 bytes"]
            PDB2["infrastructure.go — 33,579 bytes"]
            PDB3["ip_investigation.go — 26,122 bytes"]
            PDB4["email_providers.go — 1,610 bytes"]
            PDB5["dkim_providers.go — 1,164 bytes"]
            PDB6["edge_cdn.go — 5,698 bytes"]
            PDB7["saas_txt.go — 5,796 bytes"]
        end

        subgraph "Proprietary Algorithms"
            Scoring2["scoring/posture.go — 29,730 bytes<br/>CVSS-aligned risk scoring"]
            Remediation2["remediation.go — 48,879 bytes<br/>Full remediation engine"]
            Commands2["commands.go — 19,278 bytes<br/>Verify It Yourself generation"]
            Manifest2["manifest.go — 23,578 bytes<br/>Feature manifest system"]
        end

        subgraph "Quality Gates"
            GoldenRules["golden_rules_test.go — 36,431 bytes<br/>Analysis behavior tests"]
            OrchestratorTests["orchestrator_test.go — 55,179 bytes<br/>E2E orchestration tests"]
            ConfTests["confidence_test.go · dkim_state_test.go<br/>Scoring validation"]
        end
    end

    S1 -.->|"replaced by"| I1
    S2 -.->|"replaced by"| I2
    S3 -.->|"replaced by"| I3
    S4 -.->|"replaced by"| I4
    S5 -.->|"replaced by"| I5
    S6 -.->|"replaced by"| I6
    S7 -.->|"replaced by"| I7
    S8 -.->|"replaced by"| I8
    S9 -.->|"replaced by"| I9
    S10 -.->|"replaced by"| I10
    S11 -.->|"replaced by"| I11
    S12 -.->|"replaced by"| I12

    classDef stub fill:#1a5276,stroke:#2980b9,color:#fff
    classDef intel fill:#7d3c98,stroke:#9b59b6,color:#fff
    classDef db fill:#922b21,stroke:#e74c3c,color:#fff
    classDef algo fill:#6c3483,stroke:#8e44ad,color:#fff
    class S1,S2,S3,S4,S5,S6,S7,S8,S9,S10,S11,S12 stub
    class I1,I2,I3,I4,I5,I6,I7,I8,I9,I10,I11,I12 intel
    class PDB1,PDB2,PDB3,PDB4,PDB5,PDB6,PDB7 db
    class Scoring2,Remediation2,Commands2,Manifest2 algo
```

## 6. Subdomain Discovery Pipeline — Sequence Detail (CLASSIFIED)

```mermaid
sequenceDiagram
    participant H as Handler
    participant CT as crt.sh API
    participant P as processCTEntries()
    participant DNS as UDP DNS Prober
    participant E as enrichSubdomainsV2()
    participant S as sortSubdomainsSmartOrder()
    participant C as applySubdomainDisplayCap()

    H->>CT: GET /?q=%.domain&output=json
    Note over CT: 10s independent context<br/>10MB body limit<br/>Graceful fallback on failure

    CT-->>P: JSON certificate entries
    P->>P: Deduplicate by normalized hostname
    P->>P: Extract name_value fields
    P->>P: Detect *.domain wildcards
    P->>P: Normalize dates (parseCertDate)

    H->>DNS: probeCommonSubdomains()
    Note over DNS: ~290 service names<br/>UDP A queries to 8.8.8.8<br/>Fallback: 1.1.1.1<br/>20 goroutines · 15s context<br/>Extract CNAME from response

    DNS-->>E: Probed subdomains + CNAMEs
    P-->>E: CT subdomains

    E->>E: Live DNS A/CNAME resolution
    Note over E: UDP ProbeExists()<br/>20 goroutines · 10s context<br/>Sets is_current flag

    E-->>S: Enriched subdomains
    S->>S: Well-known service names first
    S->>S: DNS-resolving hosts second
    S->>S: Certificate activity third
    S->>S: Preserve all fields through sort

    S-->>C: Sorted subdomains
    C->>C: Soft cap: 200 displayed
    C->>C: 25 historical overflow
    Note over C: NEVER hides active subs<br/>CSV export bypasses cap

    C-->>H: Final subdomain list
```

## 7. Privacy Mode Decision Tree

```mermaid
graph TB
    Start["User submits domain<br/>+ optional DKIM selectors"]

    Check{"Any user-provided<br/>DKIM selectors?"}

    NoSelectors["No novel selectors provided"]
    HasSelectors["User provided selectors"]

    Known{"AllSelectorsKnown()?<br/>Check against 81+ known list"}

    AllKnown["All selectors are in<br/>defaultDKIMSelectors"]
    HasNovel["At least one selector<br/>NOT in known list"]

    AuthCheck{"User authenticated?<br/>(Google OAuth session)"}

    Public["PUBLIC ANALYSIS<br/>No user intelligence exposed<br/>Full persistence<br/>Appears in history"]
    Private["PRIVATE ANALYSIS<br/>Novel selectors = user intelligence<br/>Persisted with privacy flag<br/>Only visible to authenticated user"]
    Ephemeral["EPHEMERAL ANALYSIS<br/>Novel selectors from anonymous user<br/>NOT persisted to database<br/>Results shown once, then gone<br/>No history entry created"]

    Start --> Check
    Check -->|"no"| NoSelectors --> Public
    Check -->|"yes"| HasSelectors --> Known
    Known -->|"all known"| AllKnown --> Public
    Known -->|"has novel"| HasNovel --> AuthCheck
    AuthCheck -->|"yes"| Private
    AuthCheck -->|"no"| Ephemeral

    classDef public fill:#145a32,stroke:#27ae60,color:#fff
    classDef private fill:#1a5276,stroke:#2980b9,color:#fff
    classDef ephemeral fill:#7d6608,stroke:#f1c40f,color:#fff
    classDef decision fill:#6c3483,stroke:#8e44ad,color:#fff
    class Public public
    class Private private
    class Ephemeral ephemeral
    class Check,Known,AuthCheck decision
```

---

*CLASSIFICATION: PROPRIETARY — dnstool-intel repository only*
*Generated for DNS Tool v26.20.73 — February 19, 2026*
*Public version: docs/architecture/SYSTEM_ARCHITECTURE.md (structural only)*
