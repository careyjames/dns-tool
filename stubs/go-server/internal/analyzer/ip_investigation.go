// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// This file contains stub implementations. See the corresponding _intel.go file (requires -tags intel build).
package analyzer

import (
	"context"
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
	classCTSubdomain   = "CT Subdomain Match"
)

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
		"status":     "success",
		"domain":     domain,
		"ip":         ip,
		"ip_version": "IPv4",

		"ptr_records":  []string{},
		"fcrdns_match": false,
		"asn_info":     map[string]any{},
		"is_cdn":       false,
		"cdn_provider": "",

		"direct_relationships": []map[string]any{},
		"infra_context":        []map[string]any{},
		"neighborhood":         []map[string]any{},
		"neighborhood_total":   0,
		"neighborhood_context": "",

		"executive_verdict":  "",
		"verdict_severity":   "info",
		"direct_match_count": 0,

		"relationships":  []map[string]any{},
		"summary":        "",
		"classification": "Unrelated",
		"match_count":    0,
	}

	if IsIPv6(ip) {
		result["ip_version"] = "IPv6"
	}

	return result
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

func fetchNeighborhoodDomains(ctx context.Context, ip, investigatedDomain string) ([]map[string]any, int) {
	return nil, 0
}

func buildNeighborhoodContext(cdnProvider string, totalDomains int) string {
	return ""
}

func buildExecutiveVerdict(classification, cdnProvider, domain, ip string, directRels, infraRels []map[string]any, asnInfo map[string]any) string {
	return ""
}

func findFirstHostname(rels []map[string]any, classification string) string {
	return ""
}

func verdictSeverity(classification string) string {
	return "info"
}

func (a *Analyzer) checkPTRRecords(ctx context.Context, ip, domain string, result map[string]any, rels []map[string]any) []map[string]any {
	return rels
}

func (a *Analyzer) checkDomainARecords(ctx context.Context, domain, ip string, rels []map[string]any) []map[string]any {
	return rels
}

func (a *Analyzer) checkMXRecords(ctx context.Context, domain, ip string, rels []map[string]any) []map[string]any {
	return rels
}

func (a *Analyzer) checkNSRecords(ctx context.Context, domain, ip string, rels []map[string]any) []map[string]any {
	return rels
}

func (a *Analyzer) checkSPFAuthorization(ctx context.Context, domain, ip string, rels []map[string]any) []map[string]any {
	return rels
}

func findSPFTXTRecord(txtRecords []string) string {
	return ""
}

func (a *Analyzer) checkSPFIncludes(ctx context.Context, spfRecord, ip string, rels []map[string]any) []map[string]any {
	return rels
}

func checkIPInSPFRecord(spfRecord, ip string) bool {
	return false
}

func (a *Analyzer) checkCTSubdomains(ctx context.Context, domain, ip string, rels []map[string]any) []map[string]any {
	return rels
}

func (a *Analyzer) lookupInvestigationASN(ctx context.Context, ip string) map[string]any {
	return map[string]any{}
}

func checkASNForCDNDirect(asnInfo map[string]any, ptrRecords []string) (provider string, isCDN bool) {
	return "", false
}

func extractMXHost(mx string) string {
	return ""
}

func classifyOverall(directRels, infraRels []map[string]any, cdnProvider string, result map[string]any) (string, string) {
	return "Unrelated", ""
}

func mapGetStr(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}
