// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
	"net/http"

	"dnstool/go-server/internal/config"

	"github.com/gin-gonic/gin"
)

const (
	rateLimitNone   = "No rate limits."
	methodHTTPSREST = "HTTPS REST API (no authentication required)"
	strPrimary      = "Primary"
	strResolver     = "Resolver"
)

type IntelSource struct {
	Name        string
	Icon        string
	Category    string
	Purpose     string
	Method      string
	RateLimits  string
	VerifyCmd   string
	URL         string
	APIRequired bool
	Free        bool
}

type SourcesHandler struct {
	Config *config.Config
}

func NewSourcesHandler(cfg *config.Config) *SourcesHandler {
	return &SourcesHandler{Config: cfg}
}

func (h *SourcesHandler) Sources(c *gin.Context) {
	nonce, _ := c.Get("csp_nonce")
	data := gin.H{
		keyAppVersion:      h.Config.AppVersion,
		keyMaintenanceNote: h.Config.MaintenanceNote,
		keyBetaPages:       h.Config.BetaPages,
		keyCspNonce:        nonce,
		keyActivePage:      "sources",
		"DNSSources":      getDNSSources(),
		"InfraSources":    getInfraSources(),
		"ThreatSources":   getThreatSources(),
		"HistorySources":  getHistorySources(),
		"MetaSources":     getMetaSources(),
		"TLPColors":       getTLPColors(),
		"CVSSColors":      getCVSSColors(),
	}
	mergeAuthData(c, h.Config, data)
	c.HTML(http.StatusOK, "sources.html", data)
}

func getDNSSources() []IntelSource {
	return []IntelSource{
		{
			Name:       "Multi-Resolver DNS Consensus",
			Icon:       "network-wired",
			Category:   strPrimary,
			Purpose:    "All DNS record queries (A, AAAA, MX, NS, TXT, CNAME, DNSKEY, DS, TLSA, CAA, HTTPS, SVCB, CDS, CDNSKEY, SMIMEA, OPENPGPKEY). Five resolvers queried in parallel with majority-agreement consensus to detect censorship, poisoning, or propagation delays.",
			Method:     "UDP/TCP DNS queries with DoH (DNS-over-HTTPS) fallback",
			RateLimits: "No rate limits. Public DNS resolvers are free and unrestricted.",
			VerifyCmd:  "dig @1.1.1.1 +short A example.com",
			URL:        "",
			Free:       true,
		},
		{
			Name:       "Cloudflare DNS (1.1.1.1)",
			Icon:       "shield-alt",
			Category:   strResolver,
			Purpose:    "Primary consensus resolver. Privacy-focused, DNSSEC-validating resolver operated by Cloudflare.",
			Method:     "UDP/TCP with DoH fallback via https://cloudflare-dns.com/dns-query",
			RateLimits: rateLimitNone,
			VerifyCmd:  "dig @1.1.1.1 +short A example.com",
			URL:        "https://developers.cloudflare.com/1.1.1.1/",
			Free:       true,
		},
		{
			Name:       "Google Public DNS (8.8.8.8)",
			Icon:       "globe",
			Category:   strResolver,
			Purpose:    "Primary consensus resolver. Globally distributed, DNSSEC-validating resolver operated by Google.",
			Method:     "UDP/TCP with DoH fallback via https://dns.google/resolve",
			RateLimits: rateLimitNone,
			VerifyCmd:  "dig @8.8.8.8 +short A example.com",
			URL:        "https://developers.google.com/speed/public-dns",
			Free:       true,
		},
		{
			Name:       "Quad9 (9.9.9.9)",
			Icon:       "shield-alt",
			Category:   strResolver,
			Purpose:    "Consensus resolver with threat-intelligence filtering. Swiss-based nonprofit, DNSSEC-validating.",
			Method:     "UDP/TCP with DoH fallback via https://dns.quad9.net/dns-query",
			RateLimits: rateLimitNone,
			VerifyCmd:  "dig @9.9.9.9 +short A example.com",
			URL:        "https://www.quad9.net/",
			Free:       true,
		},
		{
			Name:       "OpenDNS / Cisco Umbrella (208.67.222.222)",
			Icon:       "globe-americas",
			Category:   strResolver,
			Purpose:    "Consensus resolver. Enterprise-grade resolver operated by Cisco.",
			Method:     "UDP/TCP",
			RateLimits: rateLimitNone,
			VerifyCmd:  "dig @208.67.222.222 +short A example.com",
			URL:        "https://www.opendns.com/",
			Free:       true,
		},
		{
			Name:       "DNS4EU (86.54.11.100)",
			Icon:       "flag",
			Category:   strResolver,
			Purpose:    "EU-sovereign consensus resolver. Operated by a European Commission-funded consortium across 10 EU member states. Unfiltered variant, DNSSEC-validating, GDPR-compliant. Infrastructure exclusively within EU borders.",
			Method:     "UDP/TCP with DoH fallback via https://unfiltered.joindns4.eu/dns-query",
			RateLimits: "1,000 queries/sec per IP.",
			VerifyCmd:  "dig @86.54.11.100 +short A example.com",
			URL:        "https://www.joindns4.eu/",
			Free:       true,
		},
		{
			Name:       "Authoritative NS Direct Query",
			Icon:       "server",
			Category:   strPrimary,
			Purpose:    "Direct queries to the domain's own authoritative nameservers for DKIM selector probing, delegation checks, and DNSSEC chain validation. Bypasses resolver caching for ground-truth data.",
			Method:     "UDP/TCP DNS queries to authoritative NS IPs",
			RateLimits: "No rate limits (querying the domain's own infrastructure).",
			VerifyCmd:  "dig @ns1.example.com +short A example.com",
			Free:       true,
		},
	}
}

func getInfraSources() []IntelSource {
	return []IntelSource{
		{
			Name:       "Reverse DNS (PTR Records)",
			Icon:       "arrows-rotate",
			Category:   strPrimary,
			Purpose:    "Identifies hosting providers by resolving IP addresses back to hostnames. A PTR record for a CloudFront IP returns server-xxx.cloudfront.net, directly revealing the hosting provider without any third-party API.",
			Method:     "Standard DNS PTR query (dig -x)",
			RateLimits: "No rate limits. Standard DNS protocol.",
			VerifyCmd:  "dig +short -x 13.248.169.35",
			Free:       true,
		},
		{
			Name:       "Team Cymru IP-to-ASN Mapping",
			Icon:       "diagram-project",
			Category:   "Community",
			Purpose:    "Maps IP addresses to their owning Autonomous System Number (ASN) and organization. Identifies whether an IP belongs to AWS (AS16509), Cloudflare (AS13335), Google (AS15169), etc. Used for CDN/edge detection and infrastructure attribution.",
			Method:     "DNS TXT queries to origin.asn.cymru.com (IPv4) and origin6.asn.cymru.com (IPv6)",
			RateLimits: "No published rate limits. Free community DNS service. Responses are cacheable.",
			VerifyCmd:  "dig +short TXT 35.169.248.13.origin.asn.cymru.com",
			URL:        "https://www.team-cymru.com/ip-asn-mapping",
			Free:       true,
		},
		{
			Name:       "SMTP Transport Probing",
			Icon:       "envelope",
			Category:   strPrimary,
			Purpose:    "Live STARTTLS verification of mail servers. Tests TLS version support, cipher suites, certificate validity, and DANE/TLSA matching. Falls back to DNS-inferred analysis when direct connection is unavailable.",
			Method:     "TCP connection to port 25 with STARTTLS negotiation",
			RateLimits: "No rate limits (standard SMTP protocol).",
			VerifyCmd:  "openssl s_client -starttls smtp -connect mx.example.com:25",
			Free:       true,
		},
	}
}

func getThreatSources() []IntelSource {
	return []IntelSource{
		{
			Name:       "OpenPhish Community Feed",
			Icon:       "fish",
			Category:   "Community",
			Purpose:    "Community-maintained phishing URL feed used by the Email Header Analyzer to cross-reference URLs found in email bodies and headers against confirmed phishing campaigns. Cached locally with a 12-hour TTL.",
			Method:     "HTTPS fetch of plain-text URL list from GitHub-hosted public feed",
			RateLimits: "No published rate limits. Public GitHub-hosted feed, refreshed every 12 hours.",
			VerifyCmd:  "curl -s https://openphish.com/feed.txt | head -20",
			URL:        "https://openphish.com/",
			Free:       true,
		},
	}
}

func getHistorySources() []IntelSource {
	return []IntelSource{
		{
			Name:       "Certificate Transparency (crt.sh)",
			Icon:       "certificate",
			Category:   "Public Log",
			Purpose:    "Discovers subdomains by searching Certificate Transparency logs for all SSL/TLS certificates ever issued for a domain. Reveals infrastructure that may not be publicly linked.",
			Method:     "HTTPS query to crt.sh PostgreSQL interface",
			RateLimits: "Community service with telemetry-based cooldown. Honest timeout/error messaging when unavailable.",
			VerifyCmd:  "curl -s 'https://crt.sh/?q=%.example.com&output=json' | jq '.[].name_value'",
			URL:        "https://crt.sh/",
			Free:       true,
		},
	}
}

func getMetaSources() []IntelSource {
	return []IntelSource{
		{
			Name:       "IANA RDAP",
			Icon:       "building",
			Category:   "Registry",
			Purpose:    "Registration Data Access Protocol — the modern successor to WHOIS. Retrieves domain registrar, registration dates, status codes, and nameserver delegation from the authoritative registry.",
			Method:     methodHTTPSREST,
			RateLimits: "Varies by registry. Telemetry-based cooldown with honest unavailability messaging.",
			VerifyCmd:  "curl -s 'https://rdap.verisign.com/com/v1/domain/example.com' | jq '.entities[0].vcardArray'",
			URL:        "https://www.iana.org/domains/rdap",
			Free:       true,
		},
		{
			Name:       "IETF Datatracker",
			Icon:       "briefcase",
			Category:   "Reference",
			Purpose:    "Fetches RFC metadata (titles, status, obsoleted-by) for all cited RFCs. Ensures RFC references in remediation guidance are current and accurate.",
			Method:     methodHTTPSREST,
			RateLimits: "No published rate limits.",
			VerifyCmd:  "curl -s 'https://datatracker.ietf.org/doc/api/rfc/?format=json&rfc=7489' | jq '.objects[0].title'",
			URL:        "https://datatracker.ietf.org/",
			Free:       true,
		},
		{
			Name:       "ip-api.com",
			Icon:       "earth-americas",
			Category:   "Supplemental",
			Purpose:    "Visitor IP geolocation only (your location flag in the footer). Not used for any analysis data. Degrades gracefully on failure.",
			Method:     methodHTTPSREST,
			RateLimits: "45 requests/minute on free tier.",
			URL:        "https://ip-api.com/",
			Free:       true,
		},
	}
}
