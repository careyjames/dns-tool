// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
//
// Provider RFC Compliance Intelligence
//
// DNS providers sometimes deviate from RFC-recommended values or restrict
// administrator control over TTLs and SOA timers. This file identifies
// those deviations factually and cites the relevant RFCs so customers
// understand what their provider is doing differently and why it matters.

// dns-tool:scrutiny science
package icuae

import (
	"fmt"
	"strings"
)

type ProviderProfile struct {
	Name          string
	SOAExpire     uint32
	SOARefresh    uint32
	SOARetry      uint32
	SOAMinTTL     uint32
	ProxiedTTL    uint32
	AliasTTL      uint32
	TTLEditable   bool
	SOAEditable   bool
	MinAllowedTTL uint32
	Notes         []ProviderComplianceNote
}

type ProviderComplianceNote struct {
	Title   string
	RFC     string
	RFCLink string
	Detail  string
	Verdict string
}

const (
	providerCloudflare   = "Cloudflare"
	providerRoute53      = "AWS Route 53"
	providerGoDaddy      = "GoDaddy"
	providerNamecheap    = "Namecheap"
	providerHostinger    = "Hostinger"
	providerGandi        = "Gandi"
	providerPorkbun      = "Porkbun"
	providerHetzner      = "Hetzner"
	providerDigitalOcean = "DigitalOcean"
	providerLinode       = "Linode (Akamai)"
	providerOVH          = "OVH"
	providerDynDNS       = "Dyn"
	providerNS1          = "NS1 (IBM)"
	providerDNSMadeEasy  = "DNS Made Easy"
	providerGoogle       = "Google Cloud DNS"

	mapKeyWarning                                     = "warning"
	severityInfo                                      = "info"
	refHttpsDatatrackerIetfOrgDocHtmlRfc1912Section22 = "https://datatracker.ietf.org/doc/html/rfc1912#section-2.2"
	refRfc191222                                      = "RFC 1912 §2.2"
)

var providerProfiles = map[string]ProviderProfile{
	providerCloudflare: {
		Name:          providerCloudflare,
		SOAExpire:     604800,
		SOARefresh:    10000,
		SOARetry:      2400,
		SOAMinTTL:     3600,
		ProxiedTTL:    300,
		TTLEditable:   false,
		SOAEditable:   false,
		MinAllowedTTL: 60,
		Notes: []ProviderComplianceNote{
			{
				Title:   "SOA Expire below RFC 1912 recommendation",
				RFC:     refRfc191222,
				RFCLink: refHttpsDatatrackerIetfOrgDocHtmlRfc1912Section22,
				Detail:  "Cloudflare sets SOA Expire to 604,800 seconds (7 days). RFC 1912 §2.2 recommends 1,209,600–2,419,200 seconds (14–28 days). This means secondary nameservers stop serving the zone sooner if the primary becomes unreachable. Cloudflare's position is that their anycast architecture makes traditional zone transfer semantics less relevant. SOA timers are not editable on Free, Pro, or Business plans.",
				Verdict: "Below RFC recommendation",
			},
			{
				Title:   "Proxied record TTLs fixed at 300s",
				RFC:     "RFC 2181 §5.2",
				RFCLink: "https://datatracker.ietf.org/doc/html/rfc2181#section-5.2",
				Detail:  "Cloudflare overrides the zone administrator's TTL to 300 seconds for all proxied (orange-cloud) records. RFC 2181 §5.2 requires TTL uniformity within an RRset but does not mandate a specific value. As the authoritative server, Cloudflare is technically within its rights, but the administrator loses TTL control. This can affect ACME DNS-01 challenges and automation workflows that depend on rapid propagation.",
				Verdict: "Technically compliant, but overrides administrator intent",
			},
			{
				Title:   "Non-standard SOA serial format",
				RFC:     refRfc191222,
				RFCLink: refHttpsDatatrackerIetfOrgDocHtmlRfc1912Section22,
				Detail:  "RFC 1912 recommends YYYYMMDDNN format for SOA serial numbers (e.g., 2026022501). Cloudflare uses a proprietary serial number format that does not encode the date. RFC 1035 only requires the serial to increment on changes, so this is compliant with the mandatory standard but breaks the convention relied on by monitoring tools.",
				Verdict: "Compliant with RFC 1035, deviates from RFC 1912 convention",
			},
			{
				Title:   "Negative cache TTL delays new records",
				RFC:     "RFC 2308 §5",
				RFCLink: "https://datatracker.ietf.org/doc/html/rfc2308#section-5",
				Detail:  "Cloudflare's SOA MINIMUM (negative cache TTL) is 1,800–3,600 seconds (30–60 minutes). This controls how long resolvers cache NXDOMAIN responses. Newly created DNS records — including ACME DNS-01 challenge TXT records for Let's Encrypt — may be invisible for up to 1 hour even after creation. This causes certificate issuance failures for automation tools like cert-manager and Traefik. Workaround: pre-create placeholder records before they're needed. This is RFC-compliant but aggressive compared to the 300–900 seconds common at other providers.",
				Verdict: "RFC-compliant, but causes real-world automation failures",
			},
			{
				Title:   "Historical RFC 2181 §5.2 violation: TTL mismatch in CNAME RRsets",
				RFC:     "RFC 2181 §5.2",
				RFCLink: "https://datatracker.ietf.org/doc/html/rfc2181#section-5.2",
				Detail:  "In February 2022, Cloudflare's resolver (1.1.1.1) returned CNAME responses with mismatched TTLs within the same RRset — including cases where one TTL was zero and another was non-zero. RFC 2181 §5.2 explicitly states: 'the TTLs of all RRs in an RRSet must be the same.' systemd-resolved (used by Arch Linux, Ubuntu, Fedora, and most modern Linux distributions) correctly rejected these responses per the RFC, causing widespread DNS resolution failures. Cloudflare acknowledged the issue and it appears to have been fixed, but it demonstrated that Cloudflare's DNS infrastructure can deviate from RFC requirements in ways that break compliant resolver implementations.",
				Verdict: "Was a documented RFC violation — appears resolved",
			},
		},
	},
	providerRoute53: {
		Name:          providerRoute53,
		AliasTTL:      60,
		TTLEditable:   false,
		SOAEditable:   true,
		MinAllowedTTL: 0,
		Notes: []ProviderComplianceNote{
			{
				Title:   "Alias record TTLs fixed at 60s",
				RFC:     "RFC 1035 §3.2.1",
				RFCLink: "https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.1",
				Detail:  "AWS Route 53 alias records pointing to AWS resources (ELB, CloudFront, S3, API Gateway) have a fixed TTL of 60 seconds that cannot be modified. Route 53 alias records are an AWS-specific extension — not part of standard DNS RFCs. They solve the CNAME-at-apex problem (RFC prohibits CNAME at zone apex) by appearing as A/AAAA records to resolvers. The 60-second TTL ensures fast failover but removes administrator TTL control.",
				Verdict: "Proprietary extension — not covered by DNS RFCs",
			},
		},
	},
	providerGoDaddy: {
		Name:          providerGoDaddy,
		TTLEditable:   true,
		SOAEditable:   false,
		MinAllowedTTL: 600,
		Notes: []ProviderComplianceNote{
			{
				Title:   "Minimum TTL enforced at 600s",
				RFC:     "RFC 1035 §3.2.1",
				RFCLink: "https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.1",
				Detail:  "GoDaddy enforces a minimum TTL of 600 seconds (10 minutes). RFC 1035 defines TTL as a value between 0 and 2^31−1 seconds, with no mandated minimum. The 600-second floor prevents administrators from setting shorter TTLs that may be needed for ACME challenges or rapid failover scenarios.",
				Verdict: "Imposes restriction not required by RFCs",
			},
		},
	},
	providerHostinger: {
		Name:          providerHostinger,
		TTLEditable:   true,
		SOAEditable:   false,
		MinAllowedTTL: 0,
	},
	providerGandi: {
		Name:          providerGandi,
		TTLEditable:   true,
		SOAEditable:   false,
		MinAllowedTTL: 300,
	},
	providerPorkbun: {
		Name:          providerPorkbun,
		TTLEditable:   true,
		SOAEditable:   false,
		MinAllowedTTL: 300,
	},
	providerHetzner: {
		Name:          providerHetzner,
		TTLEditable:   true,
		SOAEditable:   false,
		MinAllowedTTL: 0,
	},
	providerDigitalOcean: {
		Name:          providerDigitalOcean,
		TTLEditable:   true,
		SOAEditable:   false,
		MinAllowedTTL: 30,
	},
	providerLinode: {
		Name:          providerLinode,
		TTLEditable:   true,
		SOAEditable:   false,
		MinAllowedTTL: 300,
	},
	providerOVH: {
		Name:          providerOVH,
		TTLEditable:   true,
		SOAEditable:   false,
		MinAllowedTTL: 60,
	},
	providerDynDNS: {
		Name:          providerDynDNS,
		TTLEditable:   true,
		SOAEditable:   false,
		MinAllowedTTL: 30,
	},
	providerNS1: {
		Name:          providerNS1,
		TTLEditable:   true,
		SOAEditable:   true,
		MinAllowedTTL: 0,
	},
	providerDNSMadeEasy: {
		Name:          providerDNSMadeEasy,
		TTLEditable:   true,
		SOAEditable:   false,
		MinAllowedTTL: 30,
	},
	providerGoogle: {
		Name:          providerGoogle,
		TTLEditable:   true,
		SOAEditable:   true,
		MinAllowedTTL: 0,
	},
}

func DetectDNSProvider(dnsProviders, nsRecords []string) string {
	all := strings.Join(append(dnsProviders, nsRecords...), " ")
	lower := strings.ToLower(all)

	switch {
	case strings.Contains(lower, "cloudflare"):
		return providerCloudflare
	case strings.Contains(lower, "awsdns") || strings.Contains(lower, "route 53") || strings.Contains(lower, "route53"):
		return providerRoute53
	case strings.Contains(lower, "godaddy") || strings.Contains(lower, "domaincontrol"):
		return providerGoDaddy
	case strings.Contains(lower, "namecheap") || strings.Contains(lower, "registrar-servers"):
		return providerNamecheap
	case strings.Contains(lower, "hostinger") || strings.Contains(lower, "dns-parking"):
		return providerHostinger
	case strings.Contains(lower, "gandi"):
		return providerGandi
	case strings.Contains(lower, "porkbun"):
		return providerPorkbun
	case strings.Contains(lower, "hetzner"):
		return providerHetzner
	case strings.Contains(lower, "digitalocean"):
		return providerDigitalOcean
	case strings.Contains(lower, "linode") || strings.Contains(lower, "akamai"):
		return providerLinode
	case strings.Contains(lower, "ovh"):
		return providerOVH
	case strings.Contains(lower, "dynect") || strings.Contains(lower, "dyn.com"):
		return providerDynDNS
	case strings.Contains(lower, "nsone") || strings.Contains(lower, "ns1.p") || strings.Contains(lower, "dns1.p09.nsone"):
		return providerNS1
	case strings.Contains(lower, "dnsmadeeasy"):
		return providerDNSMadeEasy
	case strings.Contains(lower, "googledomains") || strings.Contains(lower, "google"):
		return providerGoogle
	default:
		return ""
	}
}

func GetProviderProfile(providerName string) (ProviderProfile, bool) {
	p, ok := providerProfiles[providerName]
	return p, ok
}

func AnnotateFindingForProvider(f *TTLFinding, providerName string) {
	profile, ok := providerProfiles[providerName]
	if !ok {
		return
	}

	switch {
	case f.RecordType == "SOA" && providerName == providerCloudflare:
		f.ProviderNote = fmt.Sprintf(
			"Cloudflare manages SOA timers automatically. "+
				"Free/Pro/Business plans cannot modify SOA values. "+
				"Observed TTL (%s) is set by Cloudflare, not the zone administrator. "+
				"See RFC 1912 §2.2 for recommended SOA timer values.",
			formatTTLDuration(f.ObservedTTL),
		)

	case (f.RecordType == "A" || f.RecordType == "AAAA") && providerName == providerCloudflare:
		if f.ObservedTTL == profile.ProxiedTTL {
			f.ProviderNote = fmt.Sprintf(
				"This TTL (%s) matches Cloudflare's fixed proxied-record TTL. "+
					"If this record is proxied (orange cloud), the TTL is enforced by Cloudflare and cannot be changed. "+
					"Disable proxying (gray cloud) to regain TTL control, at the cost of losing Cloudflare's DDoS protection and CDN.",
				formatTTLDuration(f.ObservedTTL),
			)
		}

	case (f.RecordType == "A" || f.RecordType == "AAAA") && providerName == providerRoute53:
		if f.ObservedTTL == profile.AliasTTL || f.ObservedTTL == 0 {
			f.ProviderNote = fmt.Sprintf(
				"AWS Route 53 alias records have a fixed TTL of 60 seconds when pointing to AWS resources (ELB, CloudFront, S3). " +
					"This is an AWS-specific extension, not part of DNS RFCs. " +
					"To set a custom TTL, use a standard A/AAAA record or CNAME instead of an alias — but note this loses automatic IP tracking.",
			)
		}

	default:
		if profile.MinAllowedTTL > 0 && f.TypicalTTL < profile.MinAllowedTTL {
			f.ProviderNote = fmt.Sprintf(
				"%s enforces a minimum TTL of %s. "+
					"Our recommendation of %s may not be achievable with this provider.",
				profile.Name,
				formatTTLDuration(profile.MinAllowedTTL),
				formatTTLDuration(f.TypicalTTL),
			)
		}
	}
}

type SOAComplianceReport struct {
	Provider   string                 `json:"provider"`
	HasSOA     bool                   `json:"has_soa"`
	Serial     string                 `json:"serial,omitempty"`
	Refresh    uint32                 `json:"refresh,omitempty"`
	Retry      uint32                 `json:"retry,omitempty"`
	Expire     uint32                 `json:"expire,omitempty"`
	MinTTL     uint32                 `json:"min_ttl,omitempty"`
	PrimaryNS  string                 `json:"primary_ns,omitempty"`
	AdminEmail string                 `json:"admin_email,omitempty"`
	Findings   []SOAComplianceFinding `json:"findings,omitempty"`
}

func (r SOAComplianceReport) HasFindings() bool { return len(r.Findings) > 0 }

type SOAComplianceFinding struct {
	Field       string `json:"field"`
	Observed    string `json:"observed"`
	RFCRange    string `json:"rfc_range"`
	RFC         string `json:"rfc"`
	RFCLink     string `json:"rfc_link"`
	Severity    string `json:"severity"`
	Explanation string `json:"explanation"`
}

func (f SOAComplianceFinding) SeverityClass() string {
	switch f.Severity {
	case mapKeyWarning:
		return mapKeyWarning
	case severityInfo:
		return severityInfo
	default:
		return "danger"
	}
}

func AnalyzeSOACompliance(soaRaw, providerName string) SOAComplianceReport {
	report := SOAComplianceReport{Provider: providerName}

	parts := strings.Fields(soaRaw)
	if len(parts) < 7 {
		return report
	}

	report.HasSOA = true
	report.PrimaryNS = strings.TrimSuffix(parts[0], ".")
	report.AdminEmail = strings.TrimSuffix(parts[1], ".")
	report.Serial = parts[2]

	var refresh, retry, expire, minTTL uint32
	fmt.Sscanf(parts[3], "%d", &refresh)
	fmt.Sscanf(parts[4], "%d", &retry)
	fmt.Sscanf(parts[5], "%d", &expire)
	fmt.Sscanf(parts[6], "%d", &minTTL)

	report.Refresh = refresh
	report.Retry = retry
	report.Expire = expire
	report.MinTTL = minTTL

	if expire < 1209600 {
		sev := mapKeyWarning
		if expire < 604800 {
			sev = "error"
		}
		explanation := fmt.Sprintf(
			"SOA Expire is %s. RFC 1912 §2.2 recommends 1,209,600–2,419,200 seconds (14–28 days). "+
				"If the primary nameserver becomes unreachable, secondary nameservers will stop serving this zone after only %s.",
			formatTTLDuration(expire), formatTTLDuration(expire),
		)
		if providerName == providerCloudflare {
			explanation += " Cloudflare's anycast architecture reduces the practical risk, but this value departs from the RFC recommendation."
		}
		report.Findings = append(report.Findings, SOAComplianceFinding{
			Field:       "Expire",
			Observed:    formatTTLDuration(expire),
			RFCRange:    "14–28 days (1,209,600–2,419,200s)",
			RFC:         refRfc191222,
			RFCLink:     refHttpsDatatrackerIetfOrgDocHtmlRfc1912Section22,
			Severity:    sev,
			Explanation: explanation,
		})
	}

	if refresh < 1200 {
		report.Findings = append(report.Findings, SOAComplianceFinding{
			Field:       "Refresh",
			Observed:    formatTTLDuration(refresh),
			RFCRange:    "1,200–43,200s (20 min – 12 hours)",
			RFC:         refRfc191222,
			RFCLink:     refHttpsDatatrackerIetfOrgDocHtmlRfc1912Section22,
			Severity:    severityInfo,
			Explanation: fmt.Sprintf("SOA Refresh is %s, below the RFC 1912 recommended minimum of 1,200 seconds.", formatTTLDuration(refresh)),
		})
	}

	if expire > 0 && refresh > 0 && expire <= refresh+retry {
		report.Findings = append(report.Findings, SOAComplianceFinding{
			Field:       "Expire vs Refresh+Retry",
			Observed:    fmt.Sprintf("Expire=%s ≤ Refresh+Retry=%s", formatTTLDuration(expire), formatTTLDuration(refresh+retry)),
			RFCRange:    "Expire must be > Refresh + Retry",
			RFC:         refRfc191222,
			RFCLink:     refHttpsDatatrackerIetfOrgDocHtmlRfc1912Section22,
			Severity:    "error",
			Explanation: "If Expire is not greater than Refresh + Retry, secondary nameservers may stop serving the zone before they've had a chance to retry the primary.",
		})
	}

	if minTTL > 86400 {
		report.Findings = append(report.Findings, SOAComplianceFinding{
			Field:       "Minimum (Negative Cache TTL)",
			Observed:    formatTTLDuration(minTTL),
			RFCRange:    "300–86,400s (5 min – 1 day)",
			RFC:         "RFC 2308 §5",
			RFCLink:     "https://datatracker.ietf.org/doc/html/rfc2308#section-5",
			Severity:    mapKeyWarning,
			Explanation: fmt.Sprintf("SOA MINIMUM (negative cache TTL) is %s. High values cause NXDOMAIN responses to be cached for extended periods, delaying visibility of newly created records.", formatTTLDuration(minTTL)),
		})
	}

	return report
}
