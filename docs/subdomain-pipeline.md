# Subdomain Discovery Pipeline

## Technical Reference — v1.0 (2026-03-26)

> **Classification:** NON-NORMATIVE  
> **Authors:** Carey James Balboa (ORCID: 0009-0000-5237-9065), IT Help San Diego Inc.  
> **Version:** v26.38.39  
> **Date:** 2026-03-26  
> **DOI:** 10.5281/zenodo.18854899  
> **License:** BUSL-1.1  
> **Repository:** https://github.com/IT-Help-San-Diego/dns-tool  
> **Canonical location:** `docs/subdomain-pipeline.md`

---

## 1. Architecture Overview

The subdomain discovery pipeline is a multi-layered system that combines Certificate Transparency log aggregation, active DNS probing, external reconnaissance tools, and DNS enrichment into a unified subdomain inventory. The pipeline is designed for completeness: each layer contributes subdomains that the others miss, and results are deduplicated and persisted across layers.

### Pipeline Stages (Execution Order)

```
Cache ──→ CT Logs ──→ Active Probing ──→ External Tools ──→ DNS Enrichment ──→ Nmap SANs ──→ Persistence
  │          │              │                  │                  │                │              │
  │          │              │                  │                  │                │              ▼
  │          │              │                  │                  │                │        PostgreSQL
  │          │              │                  │                  │                │        CTStore +
  │          │              │                  │                  │                │        In-memory
  │          │              │                  │                  │                │        ctCache
  ▼          ▼              ▼                  ▼                  ▼                ▼
 Early    crt.sh +      ~350 common       Subfinder +       CNAME traversal   TLS cert
 return   CertSpotter   subdomain         Amass +           + provider        SAN
 if hit   (RFC 6962)    prefixes          HackerTarget      detection         extraction
```

### File Locations and Responsibilities

| File | Responsibility |
|------|---------------|
| `go-server/internal/analyzer/subdomains.go` | Core pipeline: `DiscoverSubdomains`, CT fetching, CertSpotter fallback, common subdomain probes, DNS enrichment, CNAME traversal, display cap, sorting |
| `go-server/internal/analyzer/subdomain_tools.go` | External tool integration: `RunExternalTools`, `runSubfinder`, `runAmass`, `fetchHackerTarget` |
| `go-server/internal/analyzer/subdomain_nmap.go` | Nmap SAN discovery: `enrichSubdomainsWithNmap`, TLS certificate SAN extraction via probe endpoints |
| `go-server/internal/analyzer/ct_store.go` | PostgreSQL-backed persistent CT cache: `CTStore` interface, `pgCTStore` implementation |
| `go-server/internal/analyzer/ct_enrichment.go` | Background SecurityTrails enrichment: `CTEnrichmentJob`, budget-controlled asynchronous subdomain merging |
| `go-server/internal/analyzer/securitytrails.go` | SecurityTrails API client: `FetchSubdomains`, API budget management, rate limit handling |
| `go-server/internal/analyzer/orchestrator.go` | Pipeline entry point: `discoverSubdomainsWithBudget`, budget allocation, parallel task scheduling |
| `go-server/db/migrations/005_ct_cache.sql` | Database schema for persistent CT cache |
| `go-server/db/queries/ct_cache.sql` | SQL queries for CT cache CRUD operations |

---

## 2. Data Sources (Pipeline Order)

### 2.1 Cache Layer: In-Memory ctCache + PostgreSQL CTStore

The first stage checks two cache tiers before performing any network requests.

**In-memory ctCache** — A process-local `map[string][]map[string]any` providing sub-millisecond lookups for domains analyzed during the current process lifetime.

**PostgreSQL CTStore** — Persistent storage implementing the `CTStore` interface. On cache hit, the result is promoted into the in-memory cache and returned immediately.

```go
if cached, ok := a.getCTCache(domain); ok {
    return returnCachedSubdomains(result, cached)
}

if a.CTStore != nil {
    if dbCached, ok := a.CTStore.Get(ctx, domain); ok && len(dbCached) > 0 {
        a.setCTCache(domain, dbCached)
        return returnCachedSubdomains(result, dbCached)
    }
}
```

The CT cache design follows the principle that CT logs (RFC 6962) are append-only, immutable historical records. Caching discovery data does not violate the platform's commitment to live analysis because the discovery layer (which certificates exist) is distinct from the liveness layer (which subdomains currently resolve in DNS).

### 2.2 crt.sh (Primary CT Provider)

The primary Certificate Transparency data source. Queries the crt.sh PostgreSQL-backed API with telemetry-aware cooldown detection.

- **URL pattern:** `https://crt.sh/?q=%25.{domain}&output=json&exclude=expired`
- **Fallback URL:** `https://crt.sh/?q=%25.{domain}&output=json` (includes expired, used when first query returns zero results)
- **Retry strategy:** Up to 2 attempts within a 90-second total budget
- **Per-attempt timeout:** 75 seconds
- **Response size limit:** 20 MiB
- **Cooldown awareness:** Checks `a.Telemetry.InCooldown(ctProvider)` before attempting; skips directly to CertSpotter fallback if in cooldown

On success, telemetry records the latency via `a.Telemetry.RecordSuccess()`. On failure, records failure reason via `a.Telemetry.RecordFailure()` for cooldown calculation.

### 2.3 CertSpotter (Fallback CT Provider)

Activated when crt.sh fails, returns zero results, or is in cooldown.

- **API endpoint:** `https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names`
- **Pagination:** Cursor-based, up to **25 pages** (100 entries per page)
- **Per-page timeout:** 15 seconds
- **Total budget:** 60 seconds
- **Cursor mechanism:** Uses the `id` field of the last entry as the `after` parameter

CertSpotter entries are converted to the same `ctEntry` format used by crt.sh, with `dns_names` joined by newlines into the `NameValue` field.

### 2.4 Common Subdomain Probes (~350 Names)

Active DNS resolution against a curated list of common service names. Each prefix is prepended to the target domain and probed for DNS existence.

- **Probe count:** 350+ common subdomain prefixes (defined in `commonSubdomainProbes`)
- **Categories covered:** Web (`www`, `www1`–`www3`), Mail (`mail`, `smtp`, `pop`, `imap`, `mx1`–`mx5`), VPN (`vpn`, `vpn1`–`vpn3`), API (`api`, `api1`–`api3`, `graphql`), DevOps (`ci`, `cd`, `jenkins`, `docker`, `k8s`), Cloud (`cdn`, `cdn1`–`cdn3`, `s3`, `storage`), Security (`sso`, `auth`, `oauth`, `vault`), Monitoring (`grafana`, `prometheus`, `nagios`, `datadog`), Regional (`us-east`, `us-west`, `eu-west`, `ap-south`), and more
- **Concurrency:** 30 goroutines via semaphore
- **Timeout:** 25 seconds
- **CNAME detection:** On successful probe, records CNAME target if present

Only subdomains not already discovered by CT logs are probed, avoiding redundant DNS queries.

### 2.5 External Tools (Parallel Execution)

Three external reconnaissance sources run in parallel via `RunExternalTools`:

#### Subfinder
- **Invocation:** `subfinder -d {domain} -silent -timeout 30`
- **Binary discovery:** `exec.LookPath("subfinder")`
- **Timeout:** 45 seconds (context-based)
- **Output parsing:** Line-by-line, validated against `isValidFQDNUnder()`

#### Amass
- **Invocation:** `amass enum -passive -d {domain} -timeout 1`
- **Binary discovery:** `exec.LookPath("amass")`
- **Timeout:** 45 seconds (context-based)
- **Mode:** Passive only (no active DNS brute-forcing)

#### HackerTarget API
- **Endpoint:** `https://api.hackertarget.com/hostsearch/?q={domain}`
- **Method:** HTTP GET
- **Timeout:** 30 seconds
- **Response format:** CSV (`hostname,ip` per line)
- **Rate limit detection:** Checks for `"API count exceeded"`, `"error check your search"`, `"No records found"`
- **Response size limit:** 1 MiB

All three tools' results are merged with deduplication via a `sync.Mutex`-protected `seen` map. Each result is validated with `isValidFQDNUnder()` to ensure it is a valid FQDN under the target domain and does not include wildcards.

### 2.6 DNS Enrichment (CNAME Traversal + Provider Detection)

After all discovery sources have contributed subdomains, two enrichment passes execute:

**enrichDNSWithCTData** — Cross-references DNS-probed subdomains against CT entries to attach certificate metadata (cert count, first-seen date, issuer list, current/expired status).

**enrichSubdomainsV2** — Performs live DNS resolution on up to 50 CT-discovered subdomains (those not already DNS-probed) to determine current liveness and CNAME targets:
- **Concurrency:** 20 goroutines via semaphore
- **Timeout:** 10 seconds
- **Scope:** Enriches non-DNS-sourced subdomains only (skips entries with `source: "dns"`)

### 2.7 Nmap SAN Discovery

When probe endpoints are available, the pipeline extracts Subject Alternative Names (SANs) from TLS certificates via Nmap `ssl-cert` script probes.

- **Function:** `enrichSubdomainsWithNmap`
- **Max subdomains probed:** 15
- **Timeout:** 90 seconds total
- **Concurrency:** 3 concurrent Nmap probes
- **Probe selection:** Prefers Kali-labeled probe endpoints

SANs discovered through TLS certificate inspection that are not already in the subdomain set are added as new entries.

### 2.8 SecurityTrails (Background Enrichment)

SecurityTrails operates asynchronously via the `CTEnrichmentJob`, not within the synchronous discovery pipeline.

- **Schedule:** Runs every 24 hours after a 60-second initial delay
- **Budget:** 50 API calls per month, with 5 reserved (effective: 45 calls/month)
- **Rate limit cooldown:** 6 hours on HTTP 429
- **Target selection:** Priority domains first, then top-analyzed domains (up to 50 total)
- **Merge strategy:** New SecurityTrails subdomains are merged into the existing CTStore entry, preserving all prior discovery data
- **Source attribution:** Merged entries tagged with `source: "securitytrails"`

---

## 3. Budget and Timing

### Context Budget Allocation

| Function | Budget | Notes |
|----------|--------|-------|
| `discoverSubdomainsWithBudget` | **60 seconds** | Allocated from parent context; capped by parent deadline if less than 60s remains |
| `fetchCTWithRetry` | **90 seconds** total | Outer budget for all crt.sh attempts |
| Per crt.sh attempt | **75 seconds** | Individual HTTP request timeout |
| `fetchCertspotter` | **60 seconds** total | Outer budget for all pages |
| Per CertSpotter page | **15 seconds** | Individual page fetch timeout |
| `probeCommonSubdomains` | **25 seconds** | DNS probing of ~350 common names |
| `runSubfinder` / `runAmass` | **45 seconds** each | External tool execution timeout |
| `fetchHackerTarget` | **30 seconds** | HTTP API timeout |
| `enrichSubdomainsV2` | **10 seconds** | DNS liveness enrichment |
| `enrichSubdomainsWithNmap` | **90 seconds** | TLS SAN extraction |
| `CTEnrichmentJob` (SecurityTrails) | **Async** | Not bounded by request context |

### Parallelism Model

The pipeline uses a layered parallelism approach:

1. **CT fetch** runs first (sequential with retry)
2. **Common subdomain probes** run after CT entries are processed (30-way concurrent)
3. **External tools** run in parallel with each other (3-way concurrent) and after CT processing
4. **DNS enrichment** runs after all discovery sources complete (20-way concurrent)
5. **Nmap SAN discovery** runs after enrichment (3-way concurrent)
6. **Persistence** runs asynchronously in a background goroutine

---

## 4. Key Commits

| Commit | Date | Changes |
|--------|------|---------|
| `8dbde39f` | 2026-03-23 | External tool integration (`RunExternalTools`, `runSubfinder`, `runAmass`, `fetchHackerTarget`); budget increase from 20s to 60s; CertSpotter pagination expanded from 10 to 25 pages |
| `bd180b87` | — | PostgreSQL-based persistent CT cache (`pgCTStore`, `CTStore` interface, migration 005) |
| `b18c8571` | 2026-03-17 | Expanded common subdomain probes to ~350 entries covering DevOps, cloud, security, regional, and specialized service patterns |

---

## 5. Why apple.com Jumped from ~2,400 to 5,894

The subdomain count increase is attributable to five compounding factors:

### 5.1 External Tool Integration
Subfinder, Amass, and HackerTarget each discover subdomains through different data sources (passive OSINT databases, DNS datasets, search engine scraping) that are completely independent of Certificate Transparency logs. For large domains like apple.com, these tools collectively contribute thousands of subdomains that have never appeared in CT logs—internal service names, development environments, regional endpoints, and infrastructure hostnames that use private or no TLS certificates.

### 5.2 Budget Tripled (20s → 60s)
The previous 20-second budget was insufficient for external tools to complete. Subfinder and Amass both have startup overhead and need 10–30 seconds for comprehensive passive enumeration. The 60-second budget ensures all three external tools have time to complete and return results before the context deadline.

### 5.3 CertSpotter Pagination Expanded (10 → 25 Pages)
At 100 entries per page, the previous 10-page limit capped CertSpotter results at ~1,000 certificates. For domains with extensive certificate histories (apple.com has thousands of certificates across multiple CAs), the 25-page limit allows up to ~2,500 certificate issuances to be processed.

### 5.4 Cache Integrity Fix
A prior issue allowed failure-poisoned cache entries (where a failed CT fetch resulted in a low subdomain count being cached) to persist and be returned on subsequent requests. The fix ensures that only successful, complete discovery results are persisted to the CTStore, preventing stale low counts from masking actual subdomain inventory.

### 5.5 Multiplicative Compounding
These effects are not additive—they compound multiplicatively. External tools discover subdomains that become candidates for DNS enrichment, which discovers CNAME targets, which may reveal additional infrastructure. The expanded CT data provides more base subdomains for the enrichment pass to validate. Each layer amplifies the others.

---

## 6. Reliability Analysis

### Repeatable Conditions
The pipeline produces consistent results when:
- External tool binaries (`subfinder`, `amass`) are installed and in `$PATH`
- crt.sh API is available and not rate-limiting the source IP
- HackerTarget API is within its free-tier rate limits
- Network connectivity permits DNS resolution and HTTPS requests
- PostgreSQL CTStore is available for cache reads/writes

### Fragile Points

| Component | Failure Mode | Impact | Mitigation |
|-----------|-------------|--------|------------|
| crt.sh | Rate limiting (HTTP 429/503), extended downtime | Primary CT source unavailable | Automatic fallback to CertSpotter; telemetry cooldown prevents repeated failed attempts |
| Subfinder/Amass binaries | Not installed | External tool results absent | Graceful degradation via `exec.LookPath()` check; pipeline continues without external tools |
| HackerTarget API | `"API count exceeded"` response | One external source lost | Detected and logged; other tools compensate |
| SecurityTrails | Monthly budget exhaustion (50 calls) | Background enrichment pauses | Budget tracking with 5-call reserve; rate limit cooldown of 6 hours |
| CertSpotter | API errors on first page | Complete CertSpotter failure (`hardFail: page == 0`) | Falls through to other discovery sources |
| DNS resolver | Timeout or SERVFAIL | Probed subdomains not confirmed as current | 25-second probe timeout; enrichment timeout of 10 seconds |

### Cache Warmth

Database cache warmth significantly affects perceived performance and result consistency:
- **Warm cache:** Immediate return of prior discovery results; no network requests
- **Cold cache:** Full pipeline execution (CT fetch + probing + external tools + enrichment)
- **Stale cache:** CT data is append-only, so cached data is never "wrong"—it may only be incomplete relative to newly issued certificates

---

## 7. Verification Record

### apple.com Discovery Results

| Metric | Value |
|--------|-------|
| Unique subdomains discovered | 5,894 |
| Unique certificates processed | 1,238 |
| Certificate Authorities observed | 4 |
| CNAME chains resolved | 32 |
| Discovery date | 2026-03-26 |
| Platform version | v26.38.39 |
| Source attribution | Certificate Transparency + DNS Intelligence |

### Source Breakdown

The 5,894 subdomains are attributed across the following discovery layers:
- **Certificate Transparency** (crt.sh / CertSpotter): Historical certificate SANs
- **Common subdomain probes**: Active DNS resolution of ~350 common prefixes
- **External tools** (Subfinder, Amass, HackerTarget): Passive OSINT enumeration
- **DNS enrichment**: CNAME traversal and liveness validation
- **Nmap SAN discovery**: TLS certificate SAN extraction (when probe endpoints available)

---

## References

- RFC 6962 — Certificate Transparency (Laurie, Langley, Kasper, 2013)
- crt.sh — Sectigo Certificate Search: https://crt.sh
- CertSpotter API — SSLMate: https://sslmate.com/certspotter/api/
- SecurityTrails API — https://securitytrails.com/corp/api
- Subfinder — https://github.com/projectdiscovery/subfinder
- Amass — https://github.com/owasp-amass/amass
- HackerTarget — https://hackertarget.com/api/
