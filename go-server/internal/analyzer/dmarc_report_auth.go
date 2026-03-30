// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"golang.org/x/net/publicsuffix"
)

func (a *Analyzer) ValidateDMARCExternalAuth(ctx context.Context, domain string, dmarcData map[string]any) map[string]any {
	result := map[string]any{
		"status":           "success",
		"checked":          false,
		"external_domains": []map[string]any{},
		"issues":           []string{},
	}

	ruaStr := getStr(dmarcData, "rua")
	rufStr := getStr(dmarcData, "ruf")

	externalDomains := collectExternalDomains(domain, ruaStr, rufStr)
	if len(externalDomains) == 0 {
		result[mapKeyMessage] = "No external reporting domains detected"
		return result
	}

	result["checked"] = true
	var domainResults []map[string]any
	var issues []string

	for extDomain, sources := range externalDomains {
		dr := a.checkExternalAuth(ctx, domain, extDomain, sources)
		domainResults = append(domainResults, dr)
		if !dr["authorized"].(bool) {
			issues = append(issues, fmt.Sprintf("External domain %s has not authorized %s to send DMARC reports (missing %s._report._dmarc.%s TXT record)", extDomain, domain, domain, extDomain))
		}
	}

	if len(issues) > 0 {
		result["status"] = "warning"
		result[mapKeyMessage] = fmt.Sprintf("%d of %d external reporting domains missing authorization", len(issues), len(externalDomains))
	} else {
		result[mapKeyMessage] = fmt.Sprintf("All %d external reporting domains properly authorized", len(externalDomains))
	}

	result["external_domains"] = domainResults
	result["issues"] = issues
	return result
}

func collectExternalDomains(domain, ruaStr, rufStr string) map[string][]string {
	external := make(map[string][]string)
	domainOrg := orgDomain(domain)

	for _, d := range ExtractMailtoDomains(ruaStr) {
		if !sameOrgDomain(d, domain, domainOrg) {
			external[d] = appendUnique(external[d], "rua")
		}
	}
	for _, d := range ExtractMailtoDomains(rufStr) {
		if !sameOrgDomain(d, domain, domainOrg) {
			external[d] = appendUnique(external[d], "ruf")
		}
	}
	return external
}

func orgDomain(d string) string {
	d = strings.TrimRight(d, ".")
	reg, err := publicsuffix.EffectiveTLDPlusOne(d)
	if err != nil {
		return strings.ToLower(d)
	}
	return strings.ToLower(reg)
}

func sameOrgDomain(a, b, bOrg string) bool {
	if strings.EqualFold(a, b) {
		return true
	}
	return strings.EqualFold(orgDomain(a), bOrg)
}

func appendUnique(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}

func (a *Analyzer) checkExternalAuth(ctx context.Context, reportingDomain, externalDomain string, sources []string) map[string]any {
	authDomain := fmt.Sprintf("%s._report._dmarc.%s", reportingDomain, externalDomain)
	records := a.DNS.QueryDNS(ctx, "TXT", authDomain)

	slog.Debug("DMARC external auth check",
		"auth_domain", authDomain,
		"records_count", len(records),
		"records", fmt.Sprintf("%v", records),
	)

	authorized := false
	var authRecord string
	for _, rec := range records {
		lower := strings.ToLower(rec)
		if strings.HasPrefix(lower, "v=dmarc1") {
			authorized = true
			authRecord = rec
			break
		}
	}

	return map[string]any{
		"external_domain": externalDomain,
		"sources":         sources,
		"auth_domain":     authDomain,
		"authorized":      authorized,
		"auth_record":     authRecord,
		"confidence":      ConfidenceObservedMap(MethodDNSRecord),
	}
}
