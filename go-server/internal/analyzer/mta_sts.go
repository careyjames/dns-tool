// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

const (
	mapKeyFetched = "fetched"
	mapKeyMaxAge  = "max_age"
	mapKeySuccess = "success"
	mapKeyMtaMode = "mode"
	mapKeyMtaRaw  = "raw"
)

var mtaStsIDRe = regexp.MustCompile(`(?i)id=([^;\s]+)`)

func filterSTSRecords(records []string) []string {
	var valid []string
	for _, r := range records {
		if strings.HasPrefix(strings.ToLower(r), "v=stsv1") {
			valid = append(valid, r)
		}
	}
	return valid
}

func extractSTSID(record string) *string {
	if m := mtaStsIDRe.FindStringSubmatch(record); m != nil {
		return &m[1]
	}
	return nil
}

func (a *Analyzer) lookupMTASTSCNAME(ctx context.Context, domain string) *string {
	mtaStsHost := fmt.Sprintf("mta-sts.%s", domain)
	cnameRecords := a.DNS.QueryDNS(ctx, "CNAME", mtaStsHost)
	if len(cnameRecords) > 0 {
		cname := strings.TrimRight(cnameRecords[0], ".")
		return &cname
	}
	return nil
}

func extractPolicyMode(policyData map[string]any) *string {
	if !policyData[mapKeyFetched].(bool) {
		return nil
	}
	if m, ok := policyData[mapKeyMtaMode].(string); ok && m != "" {
		return &m
	}
	return nil
}

func determineMTASTSStatus(policyData map[string]any, mode *string) (string, string, []string) {
	var policyIssues []string
	hasVersion, _ := policyData["has_version"].(bool)

	if !policyData[mapKeyFetched].(bool) || mode == nil {
		return determineMTASTSFallbackStatus(policyData)
	}

	if !hasVersion {
		policyIssues = append(policyIssues, "Policy file missing required 'version: STSv1' field (RFC 8461 §3.2)")
	}

	status, message := determineMTASTSModeStatus(*mode, policyData)

	if !hasVersion && status == mapKeySuccess {
		status = mapKeyWarning
		message += " (missing version field in policy)"
	}

	return status, message, policyIssues
}

func determineMTASTSFallbackStatus(policyData map[string]any) (string, string, []string) {
	if policyData[mapKeyError] != nil {
		return mapKeyWarning, "MTA-STS DNS record found but policy file inaccessible", nil
	}
	return mapKeySuccess, "MTA-STS record found", nil
}

func determineMTASTSModeStatus(mode string, policyData map[string]any) (string, string) {
	switch mode {
	case "enforce":
		mxList := policyData["mx"].([]string)
		if len(mxList) > 0 {
			return mapKeySuccess, fmt.Sprintf("MTA-STS enforced - TLS required for %d mail server(s)", len(mxList))
		}
		return mapKeySuccess, "MTA-STS enforced - TLS required for mail delivery"
	case "testing":
		return mapKeyWarning, "MTA-STS in testing mode - TLS failures reported but not enforced"
	case "none":
		return mapKeyWarning, "MTA-STS policy disabled (mode=none)"
	default:
		return mapKeySuccess, "MTA-STS policy found"
	}
}

func (a *Analyzer) AnalyzeMTASTS(ctx context.Context, domain string) map[string]any {
	mtaStsDomain := fmt.Sprintf("_mta-sts.%s", domain)
	records := a.DNS.QueryDNS(ctx, "TXT", mtaStsDomain)

	baseResult := map[string]any{
		"status":         mapKeyWarning,
		mapKeyMessage:    "No MTA-STS record found",
		"record":         nil,
		"dns_id":         nil,
		mapKeyMtaMode:    nil,
		"policy":         nil,
		"policy_mode":    nil,
		"policy_max_age": nil,
		"policy_mx":      []string{},
		"policy_fetched": false,
		"policy_error":   nil,
		"hosting_cname":  nil,
	}

	if len(records) == 0 {
		return baseResult
	}

	validRecords := filterSTSRecords(records)
	if len(validRecords) == 0 {
		baseResult[mapKeyMessage] = "No valid MTA-STS record found"
		return baseResult
	}

	record := validRecords[0]
	dnsID := extractSTSID(record)
	hostingCNAME := a.lookupMTASTSCNAME(ctx, domain)

	policyURL := fmt.Sprintf("https://mta-sts.%s/.well-known/mta-sts.txt", domain)
	policyData := a.fetchMTASTSPolicy(ctx, policyURL)

	mode := extractPolicyMode(policyData)
	status, message, policyIssues := determineMTASTSStatus(policyData, mode)

	return map[string]any{
		"status":         status,
		mapKeyMessage:    message,
		"record":         record,
		"dns_id":         derefStr(dnsID),
		mapKeyMtaMode:    derefStr(mode),
		"policy":         policyData[mapKeyMtaRaw],
		"policy_mode":    policyData[mapKeyMtaMode],
		"policy_max_age": policyData[mapKeyMaxAge],
		"policy_mx":      policyData["mx"],
		"policy_fetched": policyData[mapKeyFetched],
		"policy_error":   policyData[mapKeyError],
		"hosting_cname":  derefStr(hostingCNAME),
		"policy_issues":  policyIssues,
	}
}

type mtaSTSPolicyFields struct {
	mode       string
	maxAge     int
	mx         []string
	hasVersion bool
	version    string
}

func parseMTASTSPolicyLines(policyText string) mtaSTSPolicyFields {
	var fields mtaSTSPolicyFields
	for _, line := range strings.Split(policyText, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		parseMTASTSPolicyLine(lower, line, &fields)
	}
	return fields
}

func parseMTASTSPolicyLine(lower, line string, fields *mtaSTSPolicyFields) {
	switch {
	case strings.HasPrefix(lower, "version:"):
		ver := strings.TrimSpace(line[8:])
		if strings.EqualFold(ver, "STSv1") {
			fields.hasVersion = true
		}
		fields.version = ver
	case strings.HasPrefix(lower, "mode:"):
		fields.mode = strings.TrimSpace(strings.ToLower(line[5:]))
	case strings.HasPrefix(lower, "max_age:"):
		var maxAge int
		fmt.Sscanf(strings.TrimSpace(line[8:]), "%d", &maxAge)
		if maxAge > 0 {
			fields.maxAge = maxAge
		}
	case strings.HasPrefix(lower, "mx:"):
		mx := strings.TrimSpace(line[3:])
		if mx != "" {
			fields.mx = append(fields.mx, mx)
		}
	}
}

func (a *Analyzer) fetchMTASTSPolicy(ctx context.Context, policyURL string) map[string]any {
	result := map[string]any{
		mapKeyFetched: false,
		mapKeyMtaRaw:  nil,
		mapKeyMtaMode: nil,
		mapKeyMaxAge:  nil,
		"mx":          []string{},
		mapKeyError:   nil,
	}

	resp, err := a.HTTP.Get(ctx, policyURL)
	if err != nil {
		errMsg := classifyHTTPError(err, 50)
		if strings.Contains(err.Error(), "tls") || strings.Contains(err.Error(), "certificate") {
			errMsg = "SSL certificate error"
		}
		result[mapKeyError] = errMsg
		return result
	}

	body, err := a.HTTP.ReadBody(resp, 1<<20)
	if err != nil {
		result[mapKeyError] = "Failed to read response"
		return result
	}

	if resp.StatusCode != 200 {
		result[mapKeyError] = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return result
	}

	policyText := string(body)
	result[mapKeyFetched] = true
	result[mapKeyMtaRaw] = policyText

	fields := parseMTASTSPolicyLines(policyText)
	if fields.mode != "" {
		result[mapKeyMtaMode] = fields.mode
	}
	if fields.maxAge > 0 {
		result[mapKeyMaxAge] = fields.maxAge
	}
	if len(fields.mx) > 0 {
		result["mx"] = fields.mx
	}
	if fields.version != "" {
		result["policy_version"] = fields.version
	}
	result["has_version"] = fields.hasVersion

	return result
}
