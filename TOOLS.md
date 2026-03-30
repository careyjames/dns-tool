# Security Toolchain — Licensing, Limits & Compliance

> **Last reviewed**: 2026-02-22
> **Reviewed by**: Agent + operator verification
> **Purpose**: Document every external tool's license, usage constraints,
> rate limits, and legal compliance status for acquisition readiness.

---

## Licensing Summary

| Tool | License | Commercial Use | Redistribution | Our Usage |
|------|---------|---------------|----------------|-----------|
| **nmap** (v7.94) | NPSL v0.95 | End-user: Yes | OEM license required | End-user (shell out) |
| **subfinder** (v2.6.6) | MIT | Yes | Yes | End-user (shell out) |
| **amass** (v4.2.0) | Apache 2.0 | Yes | Yes (with notice) | End-user (shell out) |
| **dnsx** | MIT ([LICENSE](https://github.com/projectdiscovery/dnsx/blob/main/LICENSE.md)) | Yes | Yes | End-user (shell out) |
| **testssl.sh** (v3.0.8) | GPLv2 ([LICENSE](https://github.com/testssl/testssl.sh/blob/3.2/LICENSE)) | Yes | Yes (source required) | End-user (shell out) |
| **httpx** | MIT ([LICENSE](https://github.com/projectdiscovery/httpx/blob/main/LICENSE.md)) | Yes | Yes | End-user (shell out) |
| **nuclei** (v3.2.8) | MIT ([LICENSE](https://github.com/projectdiscovery/nuclei/blob/main/LICENSE.md)) | Yes | Yes | End-user (shell out) |
| **nmap-formatter** | MIT | Yes | Yes | End-user (shell out) |
| **whois** | GPL ([GNU inetutils](https://www.gnu.org/software/inetutils/)) | Yes | Yes (source required) | Standard lookup |
| **dnsutils** (dig/delv) | ISC ([BIND license](https://www.isc.org/licenses/)) | Yes | Yes | Standard lookup |

### Compliance Status: GREEN

All tools are used as **end-user utilities** — we shell out to them and parse
their output. We do NOT redistribute, embed, or bundle any of these tools.
Under every license listed above, end-user invocation is explicitly permitted
for commercial purposes.

**Nmap-specific note**: The NPSL restricts *redistribution* in proprietary
products (requires OEM license). We are NOT redistributing nmap — it is
installed via Nix as a system package and invoked via `exec.Command`. This
is the "end user" use case, fully permitted per NPSL §2 and the
[annotated license](https://nmap.org/npsl/npsl-annotated.html).

**testssl.sh note**: GPLv2 requires source disclosure if we *distribute* the
modified software. We do not distribute testssl.sh — we invoke it as an
installed system tool. No source disclosure obligation applies.

---

## Usage Limits & Rate Constraints

| Tool | Limit | Enforcement | Notes |
|------|-------|-------------|-------|
| **SecurityTrails** | 50 requests/month | API key, hard limit | User-key-only. NEVER call automatically. Manual trigger only. |
| **nmap NSE** | No API limit | Local execution | Bounded by per-scan timeouts (10–15s per script) |
| **subfinder** | No hard limit | Local execution | Passive enumeration; respects source rate limits |
| **amass** | No hard limit | Local execution | Can be slow on large domains; use timeout caps |
| **dnsx** | No hard limit | Local execution | Bulk resolver; respect target NS rate |
| **testssl.sh** | No API limit | Local execution | Single-target TLS probe; 75s timeout |
| **httpx** | No hard limit | Local execution | HTTP probing; respects connection limits |
| **nuclei** | No hard limit | Local execution | Template-based; use targeted templates only |
| **CT Logs** (crt.sh) | No formal limit | Public API | Rate-limited by crt.sh; cached 1 hour |
| **RDAP** (IANA) | No formal limit | Public API | Cached 24 hours |
| **Google OAuth 2.0** | No hard limit | Google Cloud project | Subject to Google Cloud quotas; standard OAuth 2.0 flow |
| **SMTP Probe** | Shared-secret auth | Probe API endpoint | Rate-limited server-side; 10s timeout per probe |
| **Public DNS resolvers** | No formal limit | Standard DNS queries | 5 resolvers queried per scan; standard UDP/TCP 53 |
| **ASN lookups** | No formal limit | Public whois/RDAP | Cached per scan |

---

## Nmap NSE Scripts — Category & Risk Classification

Each NSE script has an official category that determines its intrusiveness.
Our implementation only uses scripts appropriate for DNS security auditing
of domains the user has authorized for scanning.

| Script | Categories | Risk Level | What It Does |
|--------|-----------|------------|--------------|
| `dns-zone-transfer` | intrusive, discovery | **Intrusive** | Requests AXFR from authoritative NS — tests if zone data leaks |
| `dns-recursion` | default, safe | **Safe** | Checks if NS allows recursive queries (read-only) |
| `dns-nsid` | default, safe, discovery | **Safe** | Queries BIND version and server ID via CH TXT (read-only) |
| `dns-cache-snoop` | intrusive, discovery | **Intrusive** | Probes for cached DNS entries (non-recursive mode) |

### Intrusive Script Justification

**dns-zone-transfer**: Sending an AXFR request to an authoritative nameserver
is a standard security audit check. If the server is correctly configured, it
denies the transfer. If misconfigured, exposing the vulnerability to the domain
owner is the entire purpose of the audit. This is RFC-standard behavior
(RFC 5936 §6 — zone transfer access control).

**dns-cache-snoop**: We use the default `nonrecursive` mode only, which sends
a standard DNS query with the RD (Recursion Desired) bit cleared. This is a
read-only operation that does not pollute the cache. The `timed` mode (which
has cache pollution risk) is NOT used.

### Authorization Model & Scanning Scope

**Scope**: Scans target ONLY the authoritative nameservers (NS records)
for the domain the user submits. No third-party infrastructure is probed.
No recursive resolvers, no upstream providers, no unrelated hosts.

**Authorization**: The user initiates every scan by explicitly submitting a
domain via the web interface. By submitting a domain for analysis, the user
represents that they own or have authorization to audit that domain. This
is reinforced by:
1. **Terms of Use**: The platform's terms require users to have authorization
   for domains they scan (same model as Qualys SSL Labs, SecurityHeaders.com,
   MXToolbox, and other established scanning platforms).
2. **Authentication**: Google OAuth login provides user identity and
   accountability for every scan.
3. **Rate limiting**: 8 requests per 60 seconds prevents abuse.
4. **Logging**: All scans are logged with user identity for audit trail.

**Scanning behavior**: All NSE scripts send standard DNS protocol messages
to port 53 on the domain's own nameservers. Zone transfer (AXFR) is a
standard DNS operation that correctly-configured servers deny. No exploit
code is executed; no services are disrupted.

---

## Scan Timeouts & Resource Limits

| Component | Timeout | Purpose |
|-----------|---------|---------|
| Overall analysis | 60s | Context deadline for entire domain scan |
| nmap zone-transfer | 15s | Single NS AXFR probe |
| nmap recursion | 10s | Single NS recursion check |
| nmap NSID | 10s | Single NS identity probe |
| nmap cache-snoop | 10s | Single NS cache check |
| SMTP probe (remote) | 10s | Per-host banner capture |
| HTTP client | 10s | Standard HTTP requests |
| TLS analysis | 75s | testssl.sh deep scan |
| Backpressure | 10s | Queue timeout before rejection |

---

## RFC & Standards References

| Check | Standard | Reference |
|-------|----------|-----------|
| Zone transfer control | RFC 5936 §6 | AXFR access control requirements |
| Open recursion | RFC 5358 | Preventing use of recursive nameservers in reflector attacks |
| NSID disclosure | RFC 5001 | DNS Nameserver Identifier option |
| Server identity | RFC 4892 | Requirements for a mechanism identifying a name server instance |
| Cache snooping | N/A (best practice) | CERT/CC advisory on DNS cache snooping |
| SPF | RFC 7208 | Sender Policy Framework |
| DMARC | RFC 7489 | Domain-based Message Authentication |
| DKIM | RFC 6376 | DomainKeys Identified Mail Signatures |
| DNSSEC | RFC 4033–4035 | DNS Security Extensions |
| DANE | RFC 6698 | DNS-Based Authentication of Named Entities |
| MTA-STS | RFC 8461 | SMTP MTA Strict Transport Security |
| TLS-RPT | RFC 8460 | SMTP TLS Reporting |
| BIMI | RFC 9495 (Experimental) | Brand Indicators for Message Identification |
| CAA | RFC 8659 | DNS Certification Authority Authorization |

---

## Tool Source Repositories

| Tool | Repository | Verified |
|------|-----------|----------|
| nmap | https://github.com/nmap/nmap | Yes |
| subfinder | https://github.com/projectdiscovery/subfinder | Yes |
| amass | https://github.com/owasp-amass/amass | Yes |
| dnsx | https://github.com/projectdiscovery/dnsx | Yes |
| testssl.sh | https://github.com/testssl/testssl.sh | Yes |
| httpx | https://github.com/projectdiscovery/httpx | Yes |
| nuclei | https://github.com/projectdiscovery/nuclei | Yes |

---

## Review Cadence

- **Quarterly**: Verify license terms haven't changed for any tool
- **On upgrade**: Re-check license file in new version before updating Nix pin
- **On new tool addition**: Full license review + add to this document before merging
