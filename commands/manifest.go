// Copyright (c) 2024-2026 IT Help San Diego Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL — See LICENSE for terms.
// This file is part of the DNS Tool Intelligence Module.
package analyzer

type ManifestEntry struct {
        Feature          string
        Category         string
        Description      string
        SchemaKey        string
        DetectionMethods []string
        RFC              string
}

var FeatureParityManifest = []ManifestEntry{
        {
                Feature:     "SPF Analysis",
                Category:    "analysis",
                Description: "Parse and validate SPF records, count DNS lookups, detect mechanisms",
                SchemaKey:   "spf_analysis",
                DetectionMethods: []string{
                        "TXT record lookup",
                        "SPF mechanism parsing",
                        "DNS lookup counting",
                        "include chain resolution",
                        "redirect= chain following",
                },
                RFC: "RFC 7208",
        },
        {
                Feature:     "DMARC Analysis",
                Category:    "analysis",
                Description: "Parse DMARC policy, extract rua/ruf, validate alignment",
                SchemaKey:   "dmarc_analysis",
                DetectionMethods: []string{
                        "_dmarc TXT lookup",
                        "policy parsing",
                        "rua/ruf URI extraction",
                        "pct validation",
                        "subdomain policy",
                },
                RFC: "RFC 7489",
        },
        {
                Feature:     "DKIM Analysis",
                Category:    "analysis",
                Description: "Discover DKIM selectors, validate key records, detect test mode",
                SchemaKey:   "dkim_analysis",
                DetectionMethods: []string{
                        "Common selector probing",
                        "Provider-specific selector detection",
                        "Key record parsing (v, k, p, t flags)",
                        "Test mode (t=y) detection",
                        "Key size extraction",
                },
                RFC: "RFC 6376",
        },
        {
                Feature:     "MTA-STS Analysis",
                Category:    "analysis",
                Description: "Check MTA-STS DNS record and fetch/validate policy file",
                SchemaKey:   "mta_sts_analysis",
                DetectionMethods: []string{
                        "_mta-sts TXT lookup",
                        "Policy file HTTPS fetch",
                        "version/mode/max_age/mx validation",
                        "STSv1 version check",
                },
                RFC: "RFC 8461",
        },
        {
                Feature:     "TLS-RPT Analysis",
                Category:    "analysis",
                Description: "Check TLS-RPT DNS record, extract reporting endpoints",
                SchemaKey:   "tlsrpt_analysis",
                DetectionMethods: []string{
                        "_smtp._tls TXT lookup",
                        "rua extraction (mailto/https)",
                },
                RFC: "RFC 8460",
        },
        {
                Feature:     "BIMI Analysis",
                Category:    "analysis",
                Description: "Check BIMI DNS record, validate SVG logo, check VMC certificate",
                SchemaKey:   "bimi_analysis",
                DetectionMethods: []string{
                        "default._bimi TXT lookup",
                        "Logo URL extraction and validation",
                        "VMC/authority URL extraction",
                        "Logo preview proxy",
                },
                RFC: "RFC 9495",
        },
        {
                Feature:     "DANE/TLSA Analysis",
                Category:    "analysis",
                Description: "Check TLSA records for MX hosts, validate usage/selector/matching",
                SchemaKey:   "dane_analysis",
                DetectionMethods: []string{
                        "_25._tcp.<mx> TLSA lookup",
                        "Certificate usage parsing",
                        "Selector/matching type validation",
                },
                RFC: "RFC 7671",
        },
        {
                Feature:     "DNSSEC Analysis",
                Category:    "analysis",
                Description: "Check DNSSEC validation status via AD flag, explain trust model",
                SchemaKey:   "dnssec_analysis",
                DetectionMethods: []string{
                        "AD flag checking via resolver",
                        "DNSKEY record lookup",
                        "DS record presence",
                },
                RFC: "RFC 4035",
        },
        {
                Feature:     "CAA Analysis",
                Category:    "analysis",
                Description: "Check CAA records, separate issue/issuewild/iodef tags",
                SchemaKey:   "caa_analysis",
                DetectionMethods: []string{
                        "CAA record lookup",
                        "issue tag parsing",
                        "issuewild tag parsing (separate from issue per RFC 8659 §4.3)",
                        "iodef notification parsing",
                },
                RFC: "RFC 8659",
        },
        {
                Feature:     "NS Delegation Analysis",
                Category:    "analysis",
                Description: "Compare child vs parent NS records, check delegation consistency",
                SchemaKey:   "ns_delegation_analysis",
                DetectionMethods: []string{
                        "Authoritative NS query",
                        "Parent zone NS query",
                        "Delegation match comparison",
                },
                RFC: "RFC 1034",
        },
        {
                Feature:     "Basic DNS Records",
                Category:    "infrastructure",
                Description: "Fetch all standard record types (A, AAAA, MX, TXT, NS, CNAME, CAA, SOA, SRV)",
                SchemaKey:   "basic_records",
                DetectionMethods: []string{
                        "Multi-type DNS query",
                        "TTL extraction",
                },
        },
        {
                Feature:     "Authoritative Records",
                Category:    "infrastructure",
                Description: "Query authoritative nameservers directly for ground-truth records",
                SchemaKey:   "authoritative_records",
                DetectionMethods: []string{
                        "NS record discovery",
                        "Direct authoritative query",
                        "TCP fallback",
                },
        },
        {
                Feature:     "Resolver Consensus",
                Category:    "infrastructure",
                Description: "Query multiple public resolvers and compare results for consistency",
                SchemaKey:   "resolver_consensus",
                DetectionMethods: []string{
                        "Cloudflare DNS query",
                        "Google Public DNS query",
                        "Quad9 query",
                        "OpenDNS/Cisco Umbrella query",
                        "Cross-resolver comparison",
                },
        },
        {
                Feature:     "Propagation Status",
                Category:    "infrastructure",
                Description: "Compare resolver vs authoritative records per type to check propagation sync",
                SchemaKey:   "propagation_status",
                DetectionMethods: []string{
                        "Per-record-type comparison",
                },
        },
        {
                Feature:     "Registrar/RDAP Lookup",
                Category:    "infrastructure",
                Description: "Look up domain registrar, dates, WHOIS server via RDAP",
                SchemaKey:   "registrar_info",
                DetectionMethods: []string{
                        "IANA RDAP bootstrap",
                        "RDAP HTTP query",
                        "Response caching (24h TTL per RFC 9224)",
                },
                RFC: "RFC 9224",
        },
        {
                Feature:     "Certificate Transparency Subdomain Discovery",
                Category:    "infrastructure",
                Description: "Discover subdomains via CT log queries, classify by certificate status",
                SchemaKey:   "ct_subdomains",
                DetectionMethods: []string{
                        "crt.sh API query",
                        "Certificate parsing",
                        "Current/expired classification",
                        "CNAME resolution for discovered subdomains",
                        "Provider summary from CNAME targets",
                },
                RFC: "RFC 6962",
        },
        {
                Feature:     "DNS Infrastructure Detection",
                Category:    "detection",
                Description: "Identify DNS hosting provider, tier, and features from nameservers",
                SchemaKey:   "dns_infrastructure",
                DetectionMethods: []string{
                        "NS hostname matching against known providers",
                        "Provider tier classification (enterprise/professional/standard/basic)",
                        "Feature detection (DNSSEC support, DDoS protection, anycast, etc.)",
                        "Government domain detection",
                },
        },
        {
                Feature:     "Hosting Summary",
                Category:    "detection",
                Description: "Identify web hosting, DNS hosting, and email hosting providers",
                SchemaKey:   "hosting_summary",
                DetectionMethods: []string{
                        "A/AAAA record IP-to-provider mapping",
                        "NS record provider identification",
                        "MX record provider identification",
                },
        },
        {
                Feature:     "Email Security Management Detection",
                Category:    "detection",
                Description: "Detect third-party email security management services and monitoring providers",
                SchemaKey:   "email_security_mgmt",
                DetectionMethods: []string{
                        "DMARC rua URI provider matching",
                        "DMARC ruf URI provider matching",
                        "TLS-RPT rua URI provider matching",
                        "SPF include flattening provider detection",
                        "Hosted DKIM CNAME chain detection",
                        "MTA-STS CNAME hosting detection",
                        "Dynamic services NS delegation detection",
                        "CNAME provider mapping",
                },
        },
        {
                Feature:     "Mail Posture Classification",
                Category:    "detection",
                Description: "Classify domain mail intent (email_enabled, no_mail_verified, etc.)",
                SchemaKey:   "mail_posture",
                DetectionMethods: []string{
                        "MX record presence/absence analysis",
                        "Null MX detection (RFC 7505)",
                        "SPF -all / v=spf1 -all detection",
                        "Signal aggregation (MX, SPF, DMARC, DKIM, MTA-STS presence)",
                },
        },
        {
                Feature:     "Security Posture Assessment",
                Category:    "assessment",
                Description: "Evaluate overall domain security posture (STRONG/GOOD/FAIR/WEAK/CRITICAL)",
                SchemaKey:   "posture",
                DetectionMethods: []string{
                        "Protocol state evaluation (SPF+DMARC+DKIM+CAA presence)",
                        "DMARC policy strength assessment",
                        "Partial pct enforcement detection",
                        "Missing rua warning",
                        "Provider-aware DKIM credit",
                        "Deliberate monitoring detection (p=none with rua)",
                },
        },
        {
                Feature:     "Remediation Engine",
                Category:    "assessment",
                Description: "Generate prioritized fix recommendations with DNS examples and RFC references",
                SchemaKey:   "remediation",
                DetectionMethods: []string{
                        "Per-section status evaluation",
                        "Severity classification (Critical/High/Medium/Low)",
                        "DNS record examples",
                        "RFC section references",
                        "Top 3 fixes sorted by severity",
                        "Achievable posture projection",
                },
        },
        {
                Feature:     "Data Freshness Tracking",
                Category:    "infrastructure",
                Description: "Track when each analysis section was last queried",
                SchemaKey:   "_data_freshness",
                DetectionMethods: []string{
                        "Per-section timestamp tracking",
                },
        },
        {
                Feature:     "Domain Existence Detection",
                Category:    "infrastructure",
                Description: "Detect NXDOMAIN, SERVFAIL, undelegated domains",
                SchemaKey:   "domain_exists",
                DetectionMethods: []string{
                        "SOA/NS query",
                        "NXDOMAIN detection",
                        "Undelegated domain handling",
                },
        },
        {
                Feature:     "Domain Status",
                Category:    "infrastructure",
                Description: "Report domain status (active, undelegated, nxdomain) with descriptive message",
                SchemaKey:   "domain_status",
                DetectionMethods: []string{
                        "DNS response code interpretation",
                },
        },
        {
                Feature:     "Domain Status Message",
                Category:    "infrastructure",
                Description: "Human-readable description of domain status",
                SchemaKey:   "domain_status_message",
                DetectionMethods: []string{
                        "Status message generation",
                },
        },
        {
                Feature:     "Section Status Summary",
                Category:    "infrastructure",
                Description: "Per-section pass/fail status summary for quick overview",
                SchemaKey:   "section_status",
                DetectionMethods: []string{
                        "Per-section status aggregation",
                },
        },
        {
                Feature:     "Authoritative Query Status",
                Category:    "infrastructure",
                Description: "Status of direct authoritative nameserver queries",
                SchemaKey:   "auth_query_status",
                DetectionMethods: []string{
                        "Authoritative query result tracking",
                },
        },
        {
                Feature:     "Resolver TTL",
                Category:    "infrastructure",
                Description: "TTL values from public resolver responses",
                SchemaKey:   "resolver_ttl",
                DetectionMethods: []string{
                        "TTL extraction from resolver responses",
                },
        },
        {
                Feature:     "Authoritative TTL",
                Category:    "infrastructure",
                Description: "TTL values from authoritative nameserver responses",
                SchemaKey:   "auth_ttl",
                DetectionMethods: []string{
                        "TTL extraction from authoritative responses",
                },
        },
        {
                Feature:     "SMTP Transport Analysis",
                Category:    "infrastructure",
                Description: "SMTP transport security with STARTTLS, TLS version, cipher strength, certificate validation, and DNS-inferred fallback",
                SchemaKey:   "smtp_transport",
                DetectionMethods: []string{
                        "Direct SMTP probe (port 25 STARTTLS)",
                        "DNS inference (MTA-STS, DANE/TLSA, TLS-RPT, provider heuristics)",
                },
        },
        {
                Feature:     "Null MX Detection",
                Category:    "detection",
                Description: "Detect null MX record indicating domain does not accept mail",
                SchemaKey:   "has_null_mx",
                DetectionMethods: []string{
                        "MX record null check (RFC 7505)",
                },
        },
        {
                Feature:     "No-Mail Domain Detection",
                Category:    "detection",
                Description: "Determine if domain has declared no-mail intent",
                SchemaKey:   "is_no_mail_domain",
                DetectionMethods: []string{
                        "Null MX + SPF -all combination detection",
                        "Mail signal aggregation",
                },
        },
        {
                Feature:     "DMARC External Reporting Authorization",
                Category:    "analysis",
                Description: "Verify external DMARC report recipients have published authorization records",
                SchemaKey:   "dmarc_report_auth",
                DetectionMethods: []string{
                        "<domain>._report._dmarc.<external> TXT lookup",
                        "v=DMARC1 authorization record validation",
                },
                RFC: "RFC 7489 §7.1",
        },
        {
                Feature:     "Dangling DNS / Subdomain Takeover Risk",
                Category:    "detection",
                Description: "Detect CNAME records pointing to unclaimed services or NXDOMAIN targets",
                SchemaKey:   "dangling_dns",
                DetectionMethods: []string{
                        "CNAME target resolution check",
                        "Known takeover-vulnerable service fingerprinting",
                        "CT subdomain CNAME chain analysis",
                },
        },
        {
                Feature:     "HTTPS/SVCB Record Intelligence",
                Category:    "analysis",
                Description: "Query HTTPS and SVCB records, parse SvcParams for HTTP/3 and ECH support",
                SchemaKey:   "https_svcb",
                DetectionMethods: []string{
                        "HTTPS (type 65) record query",
                        "SVCB record query",
                        "SvcParam parsing (alpn, port, ipv4hint, ipv6hint, ech)",
                        "HTTP/3 and ECH capability detection",
                },
                RFC: "RFC 9460",
        },
        {
                Feature:     "IP-to-ASN Attribution",
                Category:    "infrastructure",
                Description: "Look up ASN information for A/AAAA records via Team Cymru DNS",
                SchemaKey:   "asn_info",
                DetectionMethods: []string{
                        "Team Cymru DNS-based ASN lookup (origin.asn.cymru.com)",
                        "IPv4 and IPv6 reverse mapping",
                        "AS name enrichment (peer.asn.cymru.com)",
                },
        },
        {
                Feature:     "Edge/CDN vs Origin Detection",
                Category:    "detection",
                Description: "Classify whether domain is behind a CDN/edge network or direct origin",
                SchemaKey:   "edge_cdn",
                DetectionMethods: []string{
                        "ASN-to-CDN provider mapping",
                        "CNAME chain CDN pattern matching",
                },
        },
        {
                Feature:     "SaaS TXT Footprint",
                Category:    "detection",
                Description: "Extract SaaS service verification records from TXT records",
                SchemaKey:   "saas_txt",
                DetectionMethods: []string{
                        "TXT record regex pattern matching against known SaaS verification prefixes",
                },
        },
        {
                Feature:     "CDS/CDNSKEY Automation Detection",
                Category:    "analysis",
                Description: "Detect automated DNSSEC key rollover signaling via CDS/CDNSKEY records",
                SchemaKey:   "cds_cdnskey",
                DetectionMethods: []string{
                        "CDS record query",
                        "CDNSKEY record query",
                        "Automation level classification",
                        "Delete signal detection (RFC 8078 §4)",
                },
                RFC: "RFC 8078",
        },
        {
                Feature:     "security.txt Detection",
                Category:    "analysis",
                Description: "Fetch and parse security.txt vulnerability disclosure policy (RFC 9116)",
                SchemaKey:   "security_txt",
                DetectionMethods: []string{
                        "/.well-known/security.txt HTTPS fetch",
                        "/security.txt fallback HTTPS fetch",
                        "Field parsing (Contact, Expires, Encryption, Policy, Canonical)",
                        "PGP signature detection",
                        "Expiry validation",
                },
                RFC: "RFC 9116",
        },
        {
                Feature:     "AI Surface Scanner",
                Category:    "analysis",
                Description: "Detect AI governance signals, LLM training exposure, and AI-targeted content manipulation",
                SchemaKey:   "ai_surface",
                DetectionMethods: []string{
                        "llms.txt / llms-full.txt detection",
                        "robots.txt AI crawler directive analysis",
                        "Prefilled AI prompt link detection",
                        "Prompt injection text detection",
                        "CSS-hidden prompt artifact detection",
                },
        },
        {
                Feature:     "SMIMEA/OPENPGPKEY Detection",
                Category:    "analysis",
                Description: "Detect email encryption key publication via SMIMEA and OPENPGPKEY records",
                SchemaKey:   "smimea_openpgpkey",
                DetectionMethods: []string{
                        "SMIMEA record query (*._smimecert)",
                        "OPENPGPKEY record query (*._openpgpkey)",
                },
                RFC: "RFC 8162",
        },
}

var RequiredSchemaKeys []string

func init() {
        seen := make(map[string]bool)
        for _, entry := range FeatureParityManifest {
                if !seen[entry.SchemaKey] {
                        RequiredSchemaKeys = append(RequiredSchemaKeys, entry.SchemaKey)
                        seen[entry.SchemaKey] = true
                }
        }
}

func GetManifestByCategory(category string) []ManifestEntry {
        var result []ManifestEntry
        for _, entry := range FeatureParityManifest {
                if entry.Category == category {
                        result = append(result, entry)
                }
        }
        return result
}
