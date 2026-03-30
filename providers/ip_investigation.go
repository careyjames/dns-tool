// Copyright (c) 2024-2026 IT Help San Diego Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL — See LICENSE for terms.
// This file is part of the DNS Tool Intelligence Module.
package analyzer

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
)

type IPRelationship struct {
	Classification string `json:"classification"`
	Evidence       string `json:"evidence"`
	RecordType     string `json:"record_type,omitempty"`
	Hostname       string `json:"hostname,omitempty"`
}

var (
	ipv4Re = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	ipv6Re = regexp.MustCompile(`(?i)^[0-9a-f:]+$`)

	spfIPv4Re = regexp.MustCompile(`(?i)ip4:([^\s;]+)`)
	spfIPv6Re = regexp.MustCompile(`(?i)ip6:([^\s;]+)`)
)

const (
	neighborhoodDisplayCap = 10

	classCDNEdge       = "CDN/Edge Network"
	classCloudHosting  = "Cloud Hosting"
	classDirectA       = "Direct Asset (A Record)"
	classDirectAAAA    = "Direct Asset (AAAA Record)"
	classDirectReverse = "Direct Asset (Reverse DNS)"
	classEmailMX       = "Email Provider (MX)"
	classDNSNS         = "DNS Provider (NS)"
	classSPFAuth       = "SPF-Authorized Sender"
	classSPFAuthIncl   = "SPF-Authorized Sender (via include)"
	classCTSubdomain   = "CT Subdomain Match"
	classIPNeighbor    = "IP Neighbor"
	classUnrelated     = "Unrelated"

	keyClassification = "classification"
	keyEvidence       = "evidence"
	keyRecordType     = "record_type"
	keyHostname       = "hostname"
	keyStatus         = "status"
	keyASN            = "asn"
	keyASNInfo        = "asn_info"
	keyASName         = "as_name"
	keyIsCDN          = "is_cdn"
	keyCDNProvider    = "cdn_provider"
	keyPTRRecords     = "ptr_records"
	keyFCRDNSMatch    = "fcrdns_match"

	recTypeASN  = "ASN"
	recTypePTR  = "PTR"
	recTypeA    = "A"
	recTypeAAAA = "AAAA"
	recTypeMX   = "MX"
	recTypeNS   = "NS"
	recTypeSPF  = "SPF"
	recTypeACT  = "A (CT)"
	recTypeST   = "SecurityTrails"

	sevSuccess   = "success"
	sevInfo      = "info"
	sevWarning   = "warning"
	sevPrimary   = "primary"
	sevSecondary = "secondary"
)

func newRelationship(classification, evidence, recordType string) map[string]any {
	return map[string]any{
		keyClassification: classification,
		keyEvidence:       evidence,
		keyRecordType:     recordType,
	}
}

func newRelationshipWithHost(classification, evidence, recordType, hostname string) map[string]any {
	return map[string]any{
		keyClassification: classification,
		keyEvidence:       evidence,
		keyRecordType:     recordType,
		keyHostname:       hostname,
	}
}

func ValidateIPAddress(ip string) bool {
	return net.ParseIP(ip) != nil
}

func IsPrivateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() || parsed.IsUnspecified()
}

func IsIPv6(ip string) bool {
	return strings.Contains(ip, ":")
}

func (a *Analyzer) InvestigateIP(ctx context.Context, domain, ip string) map[string]any {
	result := map[string]any{
		keyStatus:    sevSuccess,
		"domain":     domain,
		"ip":         ip,
		"ip_version": "IPv4",

		keyPTRRecords:  []string{},
		keyFCRDNSMatch: false,
		keyASNInfo:     map[string]any{},
		keyIsCDN:       false,
		keyCDNProvider: "",

		"direct_relationships": []map[string]any{},
		"infra_context":        []map[string]any{},
		"neighborhood":         []map[string]any{},
		"neighborhood_total":   0,
		"neighborhood_context": "",

		"executive_verdict":  "",
		"verdict_severity":   sevInfo,
		"direct_match_count": 0,

		"relationships":    []map[string]any{},
		"summary":          "",
		keyClassification:  classUnrelated,
		"match_count":      0,
	}

	if IsIPv6(ip) {
		result["ip_version"] = "IPv6"
	}

	var directRels []map[string]any
	var infraRels []map[string]any

	directRels = a.checkPTRRecords(ctx, ip, domain, result, directRels)
	directRels = a.checkDomainARecords(ctx, domain, ip, directRels)
	directRels = a.checkMXRecords(ctx, domain, ip, directRels)
	directRels = a.checkNSRecords(ctx, domain, ip, directRels)
	directRels = a.checkSPFAuthorization(ctx, domain, ip, directRels)

	infraRels = a.checkCTSubdomains(ctx, domain, ip, infraRels)

	asnInfo := a.lookupInvestigationASN(ctx, ip)
	result[keyASNInfo] = asnInfo

	ptrRecords, _ := result[keyPTRRecords].([]string)
	cdnProvider, isCDN := checkASNForCDNDirect(asnInfo, ptrRecords)
	asnStr := mapGetStr(asnInfo, keyASN)
	if isCDN {
		result[keyIsCDN] = true
		result[keyCDNProvider] = cdnProvider
		infraRels = append(infraRels, newRelationship(
			classCDNEdge,
			fmt.Sprintf("IP belongs to %s (ASN %s)", cdnProvider, asnStr),
			recTypeASN,
		))
	} else if cdnProvider != "" {
		result[keyIsCDN] = false
		result[keyCDNProvider] = ""
		result["cloud_provider"] = cdnProvider
		infraRels = append(infraRels, newRelationship(
			classCloudHosting,
			fmt.Sprintf("IP belongs to %s (ASN %s)", cdnProvider, asnStr),
			recTypeASN,
		))
	}

	var neighborhoodRels []map[string]any
	var neighborhoodTotal int
	var neighborhoodCtx string

	initSecurityTrails()
	if securityTrailsEnabled {
		neighborhoodRels, neighborhoodTotal = fetchNeighborhoodDomains(ctx, ip, domain)
		effectiveProvider := cdnProvider
		if effectiveProvider == "" {
			ep, _ := result["cloud_provider"].(string)
			effectiveProvider = ep
		}
		neighborhoodCtx = buildNeighborhoodContext(effectiveProvider, neighborhoodTotal)
	}

	result["direct_relationships"] = directRels
	result["infra_context"] = infraRels
	result["neighborhood"] = neighborhoodRels
	result["neighborhood_total"] = neighborhoodTotal
	result["neighborhood_context"] = neighborhoodCtx
	result["direct_match_count"] = len(directRels)

	var allRels []map[string]any
	allRels = append(allRels, directRels...)
	allRels = append(allRels, infraRels...)
	result["relationships"] = allRels
	result["match_count"] = len(directRels) + len(infraRels)

	classification, summary := classifyOverall(directRels, infraRels, cdnProvider, result)
	result[keyClassification] = classification
	result["summary"] = summary
	result["executive_verdict"] = buildExecutiveVerdict(classification, cdnProvider, domain, ip, directRels, infraRels, asnInfo)
	result["verdict_severity"] = verdictSeverity(classification)

	return result
}

func fetchNeighborhoodDomains(ctx context.Context, ip, investigatedDomain string) ([]map[string]any, int) {
	domains, err := FetchDomainsByIP(ctx, ip)
	if err != nil || len(domains) == 0 {
		return nil, 0
	}

	var filtered []string
	domainLower := strings.ToLower(investigatedDomain)
	for _, d := range domains {
		if strings.ToLower(d) != domainLower && !strings.HasSuffix(strings.ToLower(d), "."+domainLower) {
			filtered = append(filtered, d)
		}
	}

	filteredTotal := len(filtered)
	if filteredTotal == 0 {
		return nil, 0
	}

	displayCount := filteredTotal
	if displayCount > neighborhoodDisplayCap {
		displayCount = neighborhoodDisplayCap
	}

	var rels []map[string]any
	for i := 0; i < displayCount; i++ {
		rels = append(rels, newRelationshipWithHost(
			classIPNeighbor,
			fmt.Sprintf("%s also resolves to this IP", filtered[i]),
			recTypeST,
			filtered[i],
		))
	}

	return rels, filteredTotal
}

func buildNeighborhoodContext(cdnProvider string, totalDomains int) string {
	if totalDomains == 0 {
		return "No other domains were found sharing this IP address."
	}
	if cdnProvider != "" {
		return fmt.Sprintf("This IP belongs to %s's edge network. The %d domain(s) listed below are other %s customers routed through the same edge node — they have no organizational relationship to your domain. CDN edge IPs are shared among thousands of unrelated websites.", cdnProvider, totalDomains, cdnProvider)
	}
	if totalDomains > 50 {
		return fmt.Sprintf("%d domains share this IP address, suggesting a large shared hosting environment or load balancer. Co-tenancy on shared hosting is normal but may warrant review if you expect dedicated infrastructure.", totalDomains)
	}
	if totalDomains > 10 {
		return fmt.Sprintf("%d domains share this IP address, indicating shared hosting. These are other customers of the same hosting provider — they are not necessarily related to your domain.", totalDomains)
	}
	return fmt.Sprintf("%d domain(s) share this IP address. On a dedicated or small shared host, co-tenants may be worth reviewing for reputation or security concerns.", totalDomains)
}

func buildExecutiveVerdict(classification, cdnProvider, domain, ip string, directRels, infraRels []map[string]any, asnInfo map[string]any) string {
	asName := mapGetStr(asnInfo, keyASN)
	orgName := mapGetStr(asnInfo, keyASName)

	switch {
	case classification == classDirectA || classification == classDirectAAAA:
		return fmt.Sprintf("This IP is a direct infrastructure asset for %s — it hosts your domain's web content.", domain)
	case classification == classDirectReverse:
		return fmt.Sprintf("This IP's reverse DNS (PTR) record points to %s, confirming it is assigned to your domain's infrastructure.", domain)
	case classification == classEmailMX:
		hostname := findFirstHostname(directRels, classEmailMX)
		if hostname != "" {
			return fmt.Sprintf("This IP belongs to your email provider (%s) and handles mail delivery for %s.", hostname, domain)
		}
		return fmt.Sprintf("This IP serves as an email server for %s.", domain)
	case classification == classDNSNS:
		hostname := findFirstHostname(directRels, classDNSNS)
		if hostname != "" {
			return fmt.Sprintf("This IP hosts one of your nameservers (%s) that provides DNS resolution for %s.", hostname, domain)
		}
		return fmt.Sprintf("This IP is a nameserver providing DNS resolution for %s.", domain)
	case strings.HasPrefix(classification, classSPFAuth):
		return fmt.Sprintf("This IP is authorized to send email on behalf of %s via SPF policy. It is a legitimate email sender for your domain.", domain)
	case classification == classCTSubdomain:
		return fmt.Sprintf("This IP hosts a subdomain of %s discovered via Certificate Transparency logs — it is part of your broader infrastructure.", domain)
	case classification == classCDNEdge:
		if cdnProvider != "" {
			return fmt.Sprintf("This IP is a %s CDN edge node. Your domain's traffic may route through it, but it is shared infrastructure — not dedicated to %s.", cdnProvider, domain)
		}
		return "This IP belongs to a CDN/edge network and serves as shared proxy infrastructure."
	case classification == classCloudHosting:
		if cdnProvider != "" {
			return fmt.Sprintf("This IP is hosted on %s cloud infrastructure (ASN %s). It is a cloud-hosted server, not a CDN edge node.", cdnProvider, asName)
		}
		return "This IP is hosted on cloud infrastructure."
	default:
		if orgName != "" {
			return fmt.Sprintf("This IP (AS%s, %s) has no direct relationship to %s in DNS records, email infrastructure, or SPF authorization.", asName, orgName, domain)
		}
		return fmt.Sprintf("This IP has no direct relationship to %s in DNS records, email infrastructure, or SPF authorization.", domain)
	}
}

func findFirstHostname(rels []map[string]any, classification string) string {
	for _, rel := range rels {
		if mapGetStr(rel, keyClassification) == classification {
			return mapGetStr(rel, keyHostname)
		}
	}
	return ""
}

func verdictSeverity(classification string) string {
	switch {
	case strings.HasPrefix(classification, "Direct Asset"):
		return sevSuccess
	case classification == classEmailMX, classification == classDNSNS:
		return sevInfo
	case strings.HasPrefix(classification, classSPFAuth):
		return sevWarning
	case classification == classCTSubdomain:
		return sevInfo
	case classification == classCDNEdge:
		return sevPrimary
	case classification == classCloudHosting:
		return sevInfo
	default:
		return sevSecondary
	}
}

func (a *Analyzer) checkPTRRecords(ctx context.Context, ip, domain string, result map[string]any, rels []map[string]any) []map[string]any {
	arpaName := buildArpaName(ip)
	if arpaName == "" {
		return rels
	}

	ptrRecords := a.DNS.QueryDNS(ctx, recTypePTR, arpaName)
	var cleaned []string
	for _, ptr := range ptrRecords {
		ptr = strings.TrimSuffix(ptr, ".")
		cleaned = append(cleaned, ptr)
	}
	result[keyPTRRecords] = cleaned

	for _, ptr := range cleaned {
		ptrLower := strings.ToLower(ptr)
		domainLower := strings.ToLower(domain)

		if ptrLower == domainLower || strings.HasSuffix(ptrLower, "."+domainLower) {
			result[keyFCRDNSMatch] = true
			rels = append(rels, newRelationshipWithHost(
				classDirectReverse,
				fmt.Sprintf("PTR record %s matches domain %s", ptr, domain),
				recTypePTR,
				ptr,
			))
		}

		fwdIPs := a.DNS.QueryDNS(ctx, recTypeA, ptr+".")
		for _, fwdIP := range fwdIPs {
			if fwdIP == ip {
				if !result[keyFCRDNSMatch].(bool) {
					result[keyFCRDNSMatch] = true
				}
				break
			}
		}
	}

	return rels
}

func (a *Analyzer) checkDomainARecords(ctx context.Context, domain, ip string, rels []map[string]any) []map[string]any {
	for _, host := range []string{domain, "www." + domain} {
		aRecords := a.DNS.QueryDNS(ctx, recTypeA, host)
		for _, rec := range aRecords {
			if rec == ip {
				rels = append(rels, newRelationshipWithHost(
					classDirectA,
					fmt.Sprintf("%s resolves to %s", host, ip),
					recTypeA,
					host,
				))
			}
		}

		aaaaRecords := a.DNS.QueryDNS(ctx, recTypeAAAA, host)
		for _, rec := range aaaaRecords {
			if rec == ip {
				rels = append(rels, newRelationshipWithHost(
					classDirectAAAA,
					fmt.Sprintf("%s resolves to %s", host, ip),
					recTypeAAAA,
					host,
				))
			}
		}
	}
	return rels
}

func (a *Analyzer) checkMXRecords(ctx context.Context, domain, ip string, rels []map[string]any) []map[string]any {
	mxRecords := a.DNS.QueryDNS(ctx, recTypeMX, domain)
	for _, mx := range mxRecords {
		mxHost := extractMXHost(mx)
		if mxHost == "" {
			continue
		}

		aRecords := a.DNS.QueryDNS(ctx, recTypeA, mxHost+".")
		for _, rec := range aRecords {
			if rec == ip {
				rels = append(rels, newRelationshipWithHost(
					classEmailMX,
					fmt.Sprintf("MX host %s resolves to %s", mxHost, ip),
					recTypeMX,
					mxHost,
				))
			}
		}

		aaaaRecords := a.DNS.QueryDNS(ctx, recTypeAAAA, mxHost+".")
		for _, rec := range aaaaRecords {
			if rec == ip {
				rels = append(rels, newRelationshipWithHost(
					classEmailMX,
					fmt.Sprintf("MX host %s resolves to %s", mxHost, ip),
					recTypeMX,
					mxHost,
				))
			}
		}
	}
	return rels
}

func (a *Analyzer) checkNSRecords(ctx context.Context, domain, ip string, rels []map[string]any) []map[string]any {
	nsRecords := a.DNS.QueryDNS(ctx, recTypeNS, domain)
	for _, ns := range nsRecords {
		ns = strings.TrimSuffix(ns, ".")

		aRecords := a.DNS.QueryDNS(ctx, recTypeA, ns+".")
		for _, rec := range aRecords {
			if rec == ip {
				rels = append(rels, newRelationshipWithHost(
					classDNSNS,
					fmt.Sprintf("Nameserver %s resolves to %s", ns, ip),
					recTypeNS,
					ns,
				))
			}
		}
	}
	return rels
}

func (a *Analyzer) checkSPFAuthorization(ctx context.Context, domain, ip string, rels []map[string]any) []map[string]any {
	txtRecords := a.DNS.QueryDNS(ctx, "TXT", domain)
	spfRecord := findSPFTXTRecord(txtRecords)
	if spfRecord == "" {
		return rels
	}

	if checkIPInSPFRecord(spfRecord, ip) {
		rels = append(rels, newRelationship(
			classSPFAuth,
			fmt.Sprintf("IP %s is directly authorized in SPF record", ip),
			recTypeSPF,
		))
	}

	rels = a.checkSPFIncludes(ctx, spfRecord, ip, rels)
	return rels
}

func findSPFTXTRecord(txtRecords []string) string {
	for _, txt := range txtRecords {
		lower := strings.ToLower(txt)
		if strings.HasPrefix(lower, "v=spf1") || strings.HasPrefix(lower, "\"v=spf1") {
			return txt
		}
	}
	return ""
}

func (a *Analyzer) checkSPFIncludes(ctx context.Context, spfRecord, ip string, rels []map[string]any) []map[string]any {
	lower := strings.ToLower(spfRecord)
	includeMatches := spfIncludeRe.FindAllStringSubmatch(lower, -1)
	for _, m := range includeMatches {
		includeDomain := m[1]
		includeTXTs := a.DNS.QueryDNS(ctx, "TXT", includeDomain)
		for _, iTXT := range includeTXTs {
			if checkIPInSPFRecord(iTXT, ip) {
				rels = append(rels, newRelationshipWithHost(
					classSPFAuthIncl,
					fmt.Sprintf("IP %s authorized via include:%s", ip, includeDomain),
					recTypeSPF,
					includeDomain,
				))
			}
		}
	}
	return rels
}

func checkIPInSPFRecord(spfRecord, ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	if matchesSPFMechanisms(spfIPv4Re.FindAllStringSubmatch(spfRecord, -1), parsedIP, ip, false) {
		return true
	}
	return matchesSPFMechanisms(spfIPv6Re.FindAllStringSubmatch(spfRecord, -1), parsedIP, ip, true)
}

func matchesSPFMechanisms(matches [][]string, parsedIP net.IP, ip string, caseInsensitive bool) bool {
	for _, m := range matches {
		mechanism := m[1]
		if strings.Contains(mechanism, "/") {
			_, cidr, err := net.ParseCIDR(mechanism)
			if err == nil && cidr.Contains(parsedIP) {
				return true
			}
		} else if caseInsensitive {
			if strings.EqualFold(mechanism, ip) {
				return true
			}
		} else if mechanism == ip {
			return true
		}
	}
	return false
}

func (a *Analyzer) checkCTSubdomains(ctx context.Context, domain, ip string, rels []map[string]any) []map[string]any {
	ctResult := a.DiscoverSubdomains(ctx, domain)
	subdomains, ok := ctResult["subdomains"].([]map[string]any)
	if !ok {
		return rels
	}

	for _, sub := range subdomains {
		subdomain, _ := sub["subdomain"].(string)
		if subdomain == "" {
			continue
		}

		aRecords := a.DNS.QueryDNS(ctx, recTypeA, subdomain+".")
		for _, rec := range aRecords {
			if rec == ip {
				rels = append(rels, newRelationshipWithHost(
					classCTSubdomain,
					fmt.Sprintf("CT-discovered subdomain %s resolves to %s", subdomain, ip),
					recTypeACT,
					subdomain,
				))
			}
		}
	}
	return rels
}

func (a *Analyzer) lookupInvestigationASN(ctx context.Context, ip string) map[string]any {
	if IsIPv6(ip) {
		return a.lookupIPv6ASN(ctx, ip)
	}
	return a.lookupIPv4ASN(ctx, ip)
}

func checkASNForCDNDirect(asnInfo map[string]any, ptrRecords []string) (provider string, isCDN bool) {
	asn, _ := asnInfo[keyASN].(string)
	if asn == "" {
		return "", false
	}
	if cdn, ok := cdnASNs[asn]; ok {
		return cdn, true
	}
	return classifyCloudIP(asn, ptrRecords)
}

func buildArpaName(ip string) string {
	if IsIPv6(ip) {
		reversed := reverseIPv6(ip)
		if reversed == "" {
			return ""
		}
		return reversed + ".ip6.arpa"
	}
	reversed := reverseIPv4(ip)
	if reversed == "" {
		return ""
	}
	return reversed + ".in-addr.arpa"
}

func extractMXHost(mx string) string {
	parts := strings.Fields(mx)
	if len(parts) >= 2 {
		return strings.TrimSuffix(parts[1], ".")
	}
	if len(parts) == 1 {
		return strings.TrimSuffix(parts[0], ".")
	}
	return ""
}

func classifyOverall(directRels, infraRels []map[string]any, cdnProvider string, result map[string]any) (string, string) {
	allRels := append(directRels, infraRels...)

	if len(allRels) == 0 {
		ip, _ := result["ip"].(string)
		domain, _ := result["domain"].(string)
		asnInfo, _ := result[keyASNInfo].(map[string]any)
		asName, _ := asnInfo[keyASName].(string)
		if asName != "" {
			return classUnrelated, fmt.Sprintf("IP %s (%s) has no direct relationship to %s.", ip, asName, domain)
		}
		return classUnrelated, fmt.Sprintf("IP %s has no direct relationship to %s.", ip, domain)
	}

	priorities := map[string]int{
		classDirectA:       1,
		classDirectAAAA:    1,
		classDirectReverse: 2,
		classEmailMX:       3,
		classDNSNS:         4,
		classSPFAuth:       5,
		classSPFAuthIncl:   6,
		classCTSubdomain:   7,
		classCDNEdge:       8,
		classCloudHosting:  9,
	}

	best := allRels[0]
	bestPriority := 99
	for _, rel := range allRels {
		class, _ := rel[keyClassification].(string)
		if p, ok := priorities[class]; ok && p < bestPriority {
			bestPriority = p
			best = rel
		}
	}

	classification, _ := best[keyClassification].(string)
	evidence, _ := best[keyEvidence].(string)

	if len(allRels) == 1 {
		return classification, evidence
	}
	return classification, fmt.Sprintf("%s (and %d other relationship(s) found)", evidence, len(allRels)-1)
}

func mapGetStr(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}
