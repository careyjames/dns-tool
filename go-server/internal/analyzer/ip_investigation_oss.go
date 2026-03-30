//go:build !intel

// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// Stub implementations. See the corresponding _intel.go file (requires -tags intel build).
// dns-tool:scrutiny science
package analyzer

import "context"

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

func fetchNeighborhoodDomains(ctx context.Context, ip, investigatedDomain string) ([]map[string]any, int) {
        return nil, 0
}

func buildNeighborhoodContext(cdnProvider string, totalDomains int) string {
        return ""
}

func buildExecutiveVerdict(classification, cdnProvider, domain, ip string, directRels, infraRels []map[string]any, asnInfo map[string]any) string {
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

func classifyOverall(directRels, infraRels []map[string]any, cdnProvider string, result map[string]any) (string, string) {
        return "Unrelated", ""
}
