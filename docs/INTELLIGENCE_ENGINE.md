# Intelligence Classification and Interpretation Engine (ICIE)

## Architecture & Roadmap Document — v1.1 (2026-02-17)

> **Status:** PARTIALLY ARCHIVED — Core ICIE architecture is implemented and live. Sections marked [CURRENT] are accurate. Sections marked [DESIGN] describe future phases.  
> **Canonical version:** Miro Blueprint board `uXjVG83d8PY=`, documents A6 (Intelligence Products Architecture) and A10 (ICAE Engine Architecture)  
> **Related engines:** ICAE (129 test cases, `go-server/internal/icae/`), ICuAE (29 test cases, `go-server/internal/icuae/`), ICSAE (standards compliance evaluator, `dns-eval/`)

---

> **Implementation Status (v26.19.20)**: This document describes both the current ICIE architecture and planned enhancements. Sections marked **[CURRENT]** describe implemented, working capabilities. Sections marked **[DESIGN — NOT YET IMPLEMENTED]** describe the architectural vision for future phases. The ICIE is real and functioning — posture scoring, remediation, protocol analysis, and confidence foundations are all implemented. The cross-reference corroboration engine and extended confidence levels are planned for future phases.

## 1. What Is This?

The DNS Tool has two distinct layers:

1. **The Core** (open source, auditable) — the machinery that goes out and collects raw DNS records, CT logs, RDAP data, and other publicly available intelligence. This is transparent. Anyone can see how we gather data.

2. **The Intelligence Classification and Interpretation Engine** (ICIE) — the brain that takes raw intelligence from multiple sources, cross-references them, determines source authority, resolves conflicts, and produces defensible security assessments. This is what we protect under BSL 1.1 because this is what nobody else does well.

Most DNS tools dump raw records and call it a day. We do what a trained OSINT analyst does: we **classify** and **interpret** the intelligence to produce actionable, standards-aligned security assessments.

---

## 2. How It Differs From Other Components

| Component | Purpose | Phase |
|-----------|---------|-------|
| **DNS Client** (Core) | Fetch raw records from resolvers | Collection |
| **Protocol Analyzers** (Core) | Parse individual record types (SPF, DMARC, etc.) | Extraction |
| **ICIE** | Cross-reference sources, rank authority, classify findings | **Classification & Interpretation** |
| **Posture Scoring** | Aggregate classified findings into risk score | Assessment |
| **Remediation Engine** | Generate actionable fixes from assessment | Prescription |
| **Drift Engine** | Compare assessments over time | Monitoring |

The ICIE sits between raw data extraction and final assessment. It's the layer that answers: *"Given everything we've observed from every source, what do we actually know, how confident are we, and what does it mean?"*

---

## 3. Intelligence Source Authority Hierarchy

Every piece of intelligence has a source. Sources have different authority levels. When sources conflict, authority determines truth.

### 3.1 Source Tiers

> **[CURRENT FRAMEWORK]** — This hierarchy guides implementation decisions. Source authority ranking is applied informally in the codebase (e.g., RDAP over WHOIS in registrar.go, authoritative over recursive in records.go). Formal per-finding tagging is planned for Phase 2.

| Tier | Authority Level | Sources | When Authoritative |
|------|----------------|---------|-------------------|
| **Tier 1: Authoritative DNS** | Highest | NS-delegated authoritative nameservers, SOA records | Always — this IS the domain's declared configuration |
| **Tier 2: Protocol Records** | High | SPF TXT, DMARC TXT, DKIM TXT, CAA, TLSA, MTA-STS, DNSSEC (DNSKEY/DS) | For their specific protocol — RFC-defined semantics |
| **Tier 3: Resolver Consensus** | High | Multi-resolver validation (Cloudflare, Google, Quad9, OpenDNS, DNS4EU) | When authoritative data is unavailable or for propagation validation |
| **Tier 4: Registry Data** | Medium-High | RDAP (primary), WHOIS (fallback) | For registrar/registration data; RDAP > WHOIS always |
| **Tier 5: Certificate Intelligence** | Medium | Certificate Transparency logs | For subdomain discovery, CA authorization validation |
| **Tier 6: Infrastructure Inference** | Medium | NS patterns, MX patterns, CNAME targets, A/AAAA records | For provider identification — inferred, not declared |
| **Tier 7: Third-Party Intelligence** | Low-Medium | SecurityTrails (history), Team Cymru (ASN), ip-api.com (geo), OpenPhish | For enrichment — external data, not domain-controlled |
| **Tier 8: Web Intelligence** | Low | HTTP probes (MTA-STS policy, security.txt, robots.txt, llms.txt) | For web-layer configuration — transient, not DNS-authoritative |

### 3.2 Authority Resolution Rules

> **[PARTIALLY CURRENT]** — Rules 1-6 are followed in practice throughout the codebase. Formal conflict-resolution logic with explicit tagging is planned for Phase 2.

When sources conflict, apply these rules in order:

1. **Authoritative DNS > Resolver cache** — If the authoritative nameserver says one thing and a recursive resolver says another, authoritative wins (the resolver may be stale).
2. **RDAP > WHOIS** — RDAP is the IETF-standardized successor (RFC 7482/7483). WHOIS is legacy, often unreliable, and increasingly restricted.
3. **Direct observation > inference** — A DKIM record we queried directly is more authoritative than a DKIM provider we inferred from SPF includes.
4. **Multiple-resolver consensus > single resolver** — If 4/5 resolvers agree and 1 disagrees, the consensus is authoritative.
5. **Live data > cached/historical data** — Current DNS state trumps SecurityTrails history for "what is the domain doing RIGHT NOW."
6. **RFC-defined semantics > vendor interpretation** — If an RFC says `p=reject` means reject, that's what it means. We don't soften or reinterpret.

---

## 4. Confidence Classification System

### [PARTIALLY IMPLEMENTED] — Foundation exists, extended levels are planned

Every finding in the ICIE carries a confidence classification. This already exists in `confidence.go` — the ICIE formalizes and extends it.

### 4.1 Confidence Levels

> The code currently implements THREE confidence levels: **Observed**, **Inferred**, and **Third-party** (in `confidence.go`). The additional levels (**Corroborated**, **Stale**, **Absent**) are architectural design targets for Phase 3.

| Level | Label | Definition | Example |
|-------|-------|------------|---------|
| **Observed** | "Observed" | Directly queried and verified from authoritative sources | SPF record retrieved via DNS TXT query |
| **Corroborated** | "Corroborated" [PLANNED] | Observed AND confirmed by independent second source | DKIM key found via DNS AND matches SPF include pattern for same provider |
| **Inferred** | "Inferred" | Derived from patterns, not directly declared | Email provider identified from MX record patterns |
| **Third-party** | "Third-party data" | From external intelligence sources, not domain-controlled | ASN attribution from Team Cymru, registrar from RDAP |
| **Stale** | "Stale intelligence" [PLANNED] | Data from cached or historical sources that may not reflect current state | SecurityTrails DNS history |
| **Absent** | "No evidence" [PLANNED] | Looked for but not found — absence is itself intelligence | No DKIM selectors discovered (doesn't mean DKIM isn't configured, just that we couldn't find it) |

### 4.2 Confidence Inheritance

> **[DESIGN — NOT YET IMPLEMENTED]** — This describes the planned confidence flow logic for Phase 3.

When a finding depends on another finding, confidence flows downward:

- If we **observe** an SPF record that **includes** `_spf.google.com`, the SPF record is `Observed` but the "Google is the email provider" conclusion is `Inferred`.
- If we then find a DKIM selector matching `google._domainkey` and it resolves, the provider classification upgrades to `Corroborated`.
- The posture score should weight `Corroborated` > `Observed` > `Inferred` > `Third-party` when findings affect risk level.

---

## 5. Interpretation Rules (The "What Does It Mean" Layer)

Raw data tells you WHAT. Interpretation tells you SO WHAT. This is the layer where we apply RFC knowledge, NIST/CISA guidance, and security expertise.

### 5.1 Protocol Interpretation Examples

> **[CURRENT]** — These interpretation patterns are implemented in posture.go and remediation.go.

| Raw Finding | Classification | Interpretation |
|-------------|---------------|----------------|
| `v=spf1 +all` | Observed, Critical | SPF record exists but permits ANY sender — equivalent to no protection (RFC 7208 §5.1) |
| `v=spf1 include:_spf.google.com ~all` | Observed, Warning | Legitimate senders declared but softfail allows spoofed mail through for DMARC evaluation |
| `v=spf1 include:_spf.google.com -all` | Observed, Note | Strict enforcement — may reject before DMARC can evaluate DKIM (RFC 7489 §10.1) |
| DMARC `p=none` with `rua=` | Observed, Monitoring | Domain is in monitoring phase — collecting data before enforcement |
| DMARC `p=reject` with `pct=100` | Observed, Enforcing | Full DMARC enforcement — strongest email authentication posture |
| No DKIM selectors found | Absent | Cannot confirm DKIM signing — may use selectors not in our probe list |
| DNSSEC AD flag set by Cloudflare | Corroborated [PLANNED label] | Validated DNSSEC chain — resolver confirmed cryptographic trust path |
| Registrar via RDAP: "GoDaddy" | Third-party | Registry data indicates registrar — not security-relevant but contextual |
| RDAP failed, WHOIS empty | No evidence | Registration data unavailable — do NOT label as "Registry Restricted" unless TLD is known-restricted |

### 5.2 Cross-Reference Interpretation

> **[DESIGN — NOT YET IMPLEMENTED]** — Formal cross-reference rules are planned for Phase 4. Some cross-referencing occurs informally in orchestrator.go and dkim_state.go.

This is where the ICIE becomes truly powerful — combining signals across protocols:

| Cross-Reference Pattern | Interpretation |
|--------------------------|----------------|
| SPF includes Google + DKIM has google selector + MX points to Google | **Corroborated**: Google Workspace is the primary email provider (3 independent signals) |
| DMARC `p=reject` + no SPF record | **Contradiction**: DMARC enforcement without SPF means only DKIM alignment can pass — likely misconfiguration |
| MTA-STS `mode: enforce` + no DANE + DNSSEC absent | **Partial protection**: Transport layer encrypted via MTA-STS but no cryptographic proof of server identity |
| CAA limits to Let's Encrypt + CT shows DigiCert certs | **Anomaly**: CA authorization doesn't match observed certificate issuance — possible pre-CAA legacy or violation |
| SPF `-all` + null MX + DMARC `p=reject` | **Corroborated no-mail intent**: Three independent signals confirm domain does not send email |

---

## 6. The "Registry Restricted" Golden Rule

This deserves its own section because it's been a recurring source of bugs.

**Rule**: The label "Registry Restricted" MUST ONLY appear when:
1. The TLD has a confirmed registry access policy that limits WHOIS/RDAP responses (e.g., `.es`, `.br`, `.kr`, `.cn`, `.ru`)
2. AND we have evidence the registry is actively restricting (not just that our lookup failed)

**Never use "Registry Restricted" as a fallback for**:
- RDAP timeout
- WHOIS returning empty
- Network errors
- Any TLD not in the confirmed-restricted list

**Instead, use**: "Registration data unavailable" with source "lookup_failed" and confidence "absent."

---

## 7. Implementation Phases

### Phase 1: Formalize Existing Intelligence (Current Session)
- Document the source authority hierarchy (this document)
- Map existing confidence labels to the ICIE framework
- Identify where the codebase already does ICIE-like work (it does — in posture.go, dkim_state.go, registrar.go, remediation.go)
- Create the `INTELLIGENCE_ENGINE.md` as the architectural spec

### Phase 2: Source Authority Tagging
- Every finding in the results map gets a `source_authority` tier tag
- Cross-reference engine: when multiple sources provide the same fact, record all sources and select the highest-authority one
- Conflict detection: flag when sources disagree (e.g., resolver cache vs. authoritative)

### Phase 3: Corroboration Engine
- Upgrade confidence from `Inferred` to `Corroborated` when multiple independent signals confirm a finding
- Provider resolution already does this partially in `dkim_state.go` — formalize and extend
- Add corroboration scoring to posture calculations

### Phase 4: Interpretation Rules Engine
- Codify the cross-reference interpretations as formal rules
- Emit structured "intelligence notes" that explain the "so what" behind findings
- These feed into both the Engineer's Report and Executive Brief

---

## 7.1 Confidence Engine Roadmap

> **[CURRENT FOUNDATION]** — Observed/Inferred confidence badges are implemented in registrar, hosting, DNS provider, and exposure sections. The roadmap below expands this into a comprehensive Confidence Engine across all protocol sections.

### CE Phase 1: Formal Per-Finding Confidence Tags
- Every protocol finding gets a structured `confidence` metadata object: `{level, source, method, timestamp}`
- Extend existing Observed/Inferred badges to all protocol sections (SPF, DMARC, DKIM, DNSSEC, DANE, MTA-STS, TLS-RPT, BIMI, CAA)
- Standardize confidence badge rendering across Engineer's Report and Executive Brief
- Source authority metadata attached to each finding (which resolver, which tier)

### CE Phase 2: Corroboration Engine
- When multiple independent signals confirm a finding, upgrade confidence from Inferred to **Corroborated**
- Cross-protocol corroboration rules: e.g., MX records + DKIM selectors + MTA-STS policy all pointing to same provider = Corroborated provider identification
- CT log subdomain data corroborating DNS-discovered infrastructure
- Add explicit "Corroborated" badge with tooltip showing corroborating sources

### CE Phase 3: Stale & Absent Semantics
- **Absent**: Protocol was actively probed but no evidence found (different from "not checked")
- **Stale**: Third-party or cached data that may not reflect current state
- Implement time-based staleness for CT log data, RDAP cache, and SecurityTrails history
- Absent/Stale indicators feed into posture scoring with appropriate weight reduction

### CE Phase 4: Confidence-Weighted Posture Scoring
- Posture scoring integrates confidence levels: Corroborated > Observed > Inferred > Third-party > Stale > Absent
- High-confidence findings carry more weight in risk calculations
- Executive Brief summary reflects confidence distribution alongside risk level
- Report appendix: Confidence Distribution Summary showing percentage of findings at each level

---

## 8. What Already Exists (Credit Where Due)

The codebase already implements significant ICIE functionality, just not formalized under this name:

| Existing Component | ICIE Function | File |
|-------------------|---------------|------|
| `confidence.go` | Confidence labeling (Observed/Inferred/Third-party) | `analyzer/confidence.go` |
| `posture.go` | Protocol state classification and risk scoring | `analyzer/posture.go` |
| `dkim_state.go` | Provider corroboration from multiple signals | `analyzer/dkim_state.go` |
| `registrar.go` | RDAP > WHOIS source authority (multi-endpoint resilience) | `analyzer/registrar.go` |
| `remediation.go` | RFC-aligned interpretation and fix generation | `analyzer/remediation.go` |
| `infrastructure.go` | Infrastructure inference from NS/MX/A patterns | `analyzer/infrastructure.go` |
| Resolver consensus | Multi-resolver validation | `dnsclient/` |
| Propagation status | Authoritative vs. resolver comparison | `orchestrator.go` |
| `posture_hash.go` | Canonical posture hashing for drift detection | `analyzer/posture_hash.go` |
| Mail posture labels | NIST/CISA-aligned classification | `remediation.go` |

The ICIE doesn't replace any of this — it formalizes the architecture, names the patterns, and identifies gaps where we should be doing more cross-referencing.

---

## 9. Relationship to Other Architectural Components

```
┌─────────────────────────────────────────────────────────┐
│                    DNS Tool Architecture                 │
│                                                         │
│  ┌─────────────┐   ┌──────────────┐   ┌──────────────┐ │
│  │  DNS Client  │   │  RDAP/WHOIS  │   │   CT Logs    │ │
│  │  (Core)      │   │  (Core)      │   │   (Core)     │ │
│  └──────┬───────┘   └──────┬───────┘   └──────┬───────┘ │
│         │                  │                   │         │
│         ▼                  ▼                   ▼         │
│  ┌─────────────────────────────────────────────────────┐ │
│  │        Protocol Analyzers (Core)                    │ │
│  │   SPF · DMARC · DKIM · DNSSEC · CAA · DANE · ...   │ │
│  └────────────────────────┬────────────────────────────┘ │
│                           │                              │
│                           ▼                              │
│  ┌─────────────────────────────────────────────────────┐ │
│  │  Intelligence Classification & Interpretation       │ │
│  │  Engine (ICIE) — BSL 1.1 Protected                  │ │
│  │                                                     │ │
│  │  • Source Authority Ranking [CURRENT — hierarchy defined]          │ │
│  │  • Confidence Classification [PARTIAL — 3 of 6 levels]            │ │
│  │  • Cross-Reference Corroboration [PLANNED — Phase 3]              │ │
│  │  • Conflict Detection & Resolution [PLANNED — Phase 2-3]         │ │
│  │  • RFC-Aligned Interpretation Rules [CURRENT — in protocol analyzers] │ │
│  └────────────────────────┬────────────────────────────┘ │
│                           │                              │
│              ┌────────────┼────────────┐                 │
│              ▼            ▼            ▼                 │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────────┐ │
│  │   Posture     │ │ Remediation  │ │  Intelligence    │ │
│  │   Scoring     │ │ Engine       │ │  Products        │ │
│  │              │ │              │ │  (Reports)       │ │
│  └──────────────┘ └──────────────┘ └──────────────────┘ │
│                                            │             │
│                           ┌────────────────┤             │
│                           ▼                ▼             │
│                   ┌──────────────┐ ┌──────────────────┐  │
│                   │  Engineer's  │ │  Executive's     │  │
│                   │  Report      │ │  Brief           │  │
│                   └──────────────┘ └──────────────────┘  │
│                                                          │
│  ┌─────────────────────────────────────────────────────┐ │
│  │  Drift Engine (Phase 2+)                            │ │
│  │  Compares ICIE outputs over time                    │ │
│  └─────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
```

---

## 10. Boundary Definition: Core vs. ICIE Modules

To eliminate ambiguity about what is open source and what is protected:

### Core Modules (Open Source)
These collect and parse raw data — no classification or interpretation logic:

| Module | Path | Function |
|--------|------|----------|
| DNS Client | `go-server/internal/dnsclient/` | Multi-resolver queries, DoH fallback, consensus validation |
| Record Parsers | `go-server/internal/analyzer/records.go` | Raw DNS record fetching (A, AAAA, MX, NS, TXT, SOA, CNAME) |
| RDAP/WHOIS Client | `go-server/internal/analyzer/registrar.go` (data fetch portions) | Multi-endpoint RDAP lookup, WHOIS fallback |
| CT Log Client | `go-server/internal/analyzer/subdomains.go` | Certificate Transparency log queries |
| HTTP Probes | Portions of MTA-STS, security.txt, AI surface (HTTP fetch only) | Fetching well-known URLs |

### ICIE Modules (BSL 1.1 Protected)
These classify, interpret, cross-reference, and produce assessments:

| Module | Path | Function |
|--------|------|----------|
| Confidence System | `go-server/internal/analyzer/confidence.go` | Source authority labeling |
| Posture Scoring | `go-server/internal/analyzer/posture.go` | Protocol state classification, risk scoring, grade assignment |
| DKIM State Machine | `go-server/internal/analyzer/dkim_state.go` | Provider corroboration, ambiguous selector reclassification |
| Remediation Engine | `go-server/internal/analyzer/remediation.go` | RFC-aligned fix generation, mail posture classification |
| Infrastructure Intelligence | `go-server/internal/analyzer/infrastructure.go` | Enterprise provider detection, tier classification |
| Protocol Analyzers (interpretation logic) | `go-server/internal/analyzer/spf.go`, `dmarc.go`, etc. | The "so what" classification within each analyzer |
| Orchestrator (assembly logic) | `go-server/internal/analyzer/orchestrator.go` | Cross-reference assembly, section status, propagation analysis |
| Posture Hash | `go-server/internal/analyzer/posture_hash.go` | Canonical hashing for drift detection |
| Intelligence Products | `go-server/templates/results.html`, `results_executive.html` | Report rendering and presentation |

**Note**: Some files contain both Core and ICIE logic (e.g., `registrar.go` fetches data AND interprets registration status). The boundary runs through the file at the point where raw data becomes classified intelligence.

---

## 11. Authoritative Disagreement Handling

> **[DESIGN — NOT YET IMPLEMENTED]** — Formal disagreement handling is planned. Currently, multi-resolver consensus in dnsclient validates propagation status.

When authoritative sources themselves disagree, confidence must be downgraded:

### Scenarios

| Scenario | Detection | Confidence Impact |
|----------|-----------|-------------------|
| **Lame delegation** | NS records point to servers that don't answer for the zone | Downgrade to "Degraded" — authoritative data is unreliable |
| **Split-horizon DNS** | Different resolvers return different A records for the same query | Flag as "Split-horizon detected" — findings are resolver-path-dependent |
| **Propagation delay** | Authoritative and recursive differ, but authoritative has fresh SOA serial | Mark recursive data as "Stale" — authoritative is correct, resolvers haven't caught up |
| **Conflicting TXT records** | Multiple SPF records found (RFC violation) | Both are "Observed" but the finding is "Misconfiguration" — multiple SPF records invalidate SPF (RFC 7208 §3.2) |
| **Registry vs. DNS** | RDAP shows one registrar but NS records delegate elsewhere | Both are correct for their domain — RDAP is registry data, NS is operational delegation. No conflict. |

### Rules
1. When authoritative sources disagree, **never silently pick one** — flag the disagreement and explain it
2. Downgrade confidence to the lower of the two conflicting sources
3. Add an explicit "intelligence note" explaining what we observed and why it matters

---

## 12. How Stale and Absent Affect Scoring

> **[DESIGN — NOT YET IMPLEMENTED]** — Requires extended confidence levels from Phase 3.

| Confidence Level | Scoring Impact | Reporting Impact |
|-----------------|----------------|------------------|
| **Observed** | Full weight in posture score | Definitive statement: "Domain has X configured" |
| **Corroborated** | Full weight + positive note | Stronger statement: "Confirmed by multiple independent signals" |
| **Inferred** | Full weight but flagged | Qualified statement: "Evidence suggests X" |
| **Third-party** | Contextual only — does not affect security score | Informational: "Registry data indicates X" |
| **Stale** | Reduced weight — historical context only | Temporal qualifier: "As of [date], domain had X" |
| **Absent** | Does NOT penalize — absence ≠ failure | Honest statement: "No evidence of X found — this does not confirm absence" |

**Critical principle for Absent**: Not finding a DKIM selector doesn't mean DKIM isn't configured — it means our probe list didn't match. We MUST say "No evidence found" not "DKIM is not configured." This is the difference between honest OSINT and false certainty.

---

## 13. Licensing Boundary

- **Core** (DNS client, record fetching, CT log queries): Open source, auditable, transparent. Lives in the public GitHub repository.
- **ICIE** (classification rules, interpretation logic, cross-reference engine, corroboration scoring): Protected under BSL 1.1. This is the proprietary intelligence that makes the tool's assessments defensible and accurate.
- **Intelligence Products** (report templates, executive brief formatting): BSL 1.1 protected. The presentation layer for ICIE outputs.

This boundary is clean: "How we collect" is open. "How we think" is protected.

---

## 14. Terminology

| Term | Definition |
|------|------------|
| **Core** | The open-source data collection layer — DNS queries, RDAP fetches, CT log searches, HTTP probes |
| **ICIE** | Intelligence Classification and Interpretation Engine — the protected layer that classifies, interprets, and cross-references raw intelligence |
| **Intelligence Source** | Any system that provides data about a domain (DNS resolver, RDAP server, CT log, etc.) |
| **Source Authority** | The trustworthiness tier assigned to an intelligence source (Tier 1-8) |
| **Confidence Level** | How certain we are about a specific finding (Observed → Corroborated → Inferred → Third-party → Stale → Absent) |
| **Corroboration** | When multiple independent intelligence sources confirm the same finding |
| **Intelligence Note** | A structured explanation of what a finding means and why it matters |
| **Intelligence Product** | The final output — Engineer's Report or Executive Brief |
| **Posture** | The overall security configuration state of a domain |
| **Drift** | A change in posture between two points in time |

---

*Document created: 2026-02-16*
*Author: DNS Tool Development*
*Status: Architecture specification & roadmap — Phase 1 complete (formalization), Phases 2-4 planned. Document updated v1.1 (2026-02-17) to clearly separate implemented vs planned capabilities.*
