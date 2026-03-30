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
	mapKeyDmarcLike    = "dmarc_like"
	mapKeyQuarantine   = "quarantine"
	mapKeyRecords      = "records"
	mapKeyReject       = "reject"
	mapKeyRelaxed      = "relaxed"
	mapKeyStatus       = "status"
	mapKeyValidRecords = "valid_records"
)

var (
	dmarcPolicyRe   = regexp.MustCompile(`(?i)\bp=(\w+)`)
	dmarcSPRe       = regexp.MustCompile(`(?i)\bsp=(\w+)`)
	dmarcPctRe      = regexp.MustCompile(`(?i)\bpct=(\d+)`)
	dmarcASPFRe     = regexp.MustCompile(`(?i)\baspf=([rs])`)
	dmarcADKIMRe    = regexp.MustCompile(`(?i)\badkim=([rs])`)
	dmarcRUARe      = regexp.MustCompile(`(?i)\brua=([^;\s]+)`)
	dmarcRUFRe      = regexp.MustCompile(`(?i)\bruf=([^;\s]+)`)
	dmarcNPRe       = regexp.MustCompile(`(?i)\bnp=(\w+)`)
	dmarcTRe        = regexp.MustCompile(`(?i)\bt=([yn])`)
	dmarcPSDRe      = regexp.MustCompile(`(?i)\bpsd=([yn])`)
	mailtoExtractRe = regexp.MustCompile(`(?i)mailto:([^,;\s]+)`)
)

type dmarcTags struct {
	policy          *string
	subdomainPolicy *string
	pct             int
	aspf            string
	adkim           string
	rua             *string
	ruf             *string
	npPolicy        *string
	tTesting        *string
	psdFlag         *string
	unknownTags     []string
}

var knownDMARCTags = map[string]bool{
	"v": true, "p": true, "sp": true, "pct": true,
	"aspf": true, "adkim": true, "rua": true, "ruf": true,
	"fo": true, "rf": true, "ri": true,
	"np": true, "t": true, "psd": true,
}

func parseDMARCTags(record string) dmarcTags {
	recordLower := strings.ToLower(record)
	tags := dmarcTags{pct: 100, aspf: mapKeyRelaxed, adkim: mapKeyRelaxed}

	if m := dmarcPolicyRe.FindStringSubmatch(recordLower); m != nil {
		tags.policy = &m[1]
	}
	if m := dmarcSPRe.FindStringSubmatch(recordLower); m != nil {
		tags.subdomainPolicy = &m[1]
	}
	if m := dmarcPctRe.FindStringSubmatch(recordLower); m != nil {
		fmt.Sscanf(m[1], "%d", &tags.pct)
	}
	if m := dmarcASPFRe.FindStringSubmatch(recordLower); m != nil {
		if m[1] == "s" {
			tags.aspf = "strict"
		}
	}
	if m := dmarcADKIMRe.FindStringSubmatch(recordLower); m != nil {
		if m[1] == "s" {
			tags.adkim = "strict"
		}
	}
	if m := dmarcRUARe.FindStringSubmatch(record); m != nil {
		tags.rua = &m[1]
	}
	if m := dmarcRUFRe.FindStringSubmatch(record); m != nil {
		tags.ruf = &m[1]
	}
	if m := dmarcNPRe.FindStringSubmatch(recordLower); m != nil {
		tags.npPolicy = &m[1]
	}
	if m := dmarcTRe.FindStringSubmatch(recordLower); m != nil {
		tags.tTesting = &m[1]
	}
	if m := dmarcPSDRe.FindStringSubmatch(recordLower); m != nil {
		tags.psdFlag = &m[1]
	}

	tags.unknownTags = detectUnknownDMARCTags(record)

	return tags
}

func detectUnknownDMARCTags(record string) []string {
	var unknown []string
	parts := strings.Split(record, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		eqIdx := strings.Index(part, "=")
		if eqIdx < 0 {
			continue
		}
		tagName := strings.TrimSpace(strings.ToLower(part[:eqIdx]))
		if tagName == "" {
			continue
		}
		if !knownDMARCTags[tagName] {
			unknown = append(unknown, part)
		}
	}
	return unknown
}

func classifyDMARCPolicyVerdict(policy string, pct int) (string, string, []string) {
	var status, message string
	var issues []string

	switch policy {
	case "none":
		status = "warning"
		message = "DMARC in monitoring mode (p=none) - spoofed mail still delivered, no enforcement"
		issues = append(issues, "Policy p=none provides no protection - spoofed emails reach inboxes")
	case mapKeyReject:
		status, message, issues = classifyEnforcementLevel(mapKeyReject, pct, "excellent")
	case mapKeyQuarantine:
		status, message, issues = classifyEnforcementLevel(mapKeyQuarantine, pct, "good")
	default:
		status = "info"
		message = "DMARC record found but policy unclear"
	}

	return status, message, issues
}

func classifyEnforcementLevel(policy string, pct int, quality string) (string, string, []string) {
	if pct < 100 {
		return "warning",
			fmt.Sprintf("DMARC %s but only %d%% enforced - partial protection", policy, pct),
			[]string{fmt.Sprintf("Only %d%% of mail subject to policy", pct)}
	}
	return "success", fmt.Sprintf("DMARC policy %s (100%%) - %s protection", policy, quality), nil
}

func checkDMARCSubdomainIssues(tags dmarcTags) []string {
	if tags.policy == nil {
		return nil
	}
	if *tags.policy != mapKeyReject && *tags.policy != mapKeyQuarantine {
		return nil
	}
	var issues []string
	if tags.subdomainPolicy != nil && *tags.subdomainPolicy == "none" {
		issues = append(issues, fmt.Sprintf("Subdomains unprotected (sp=none while p=%s)", *tags.policy))
	}
	if tags.npPolicy == nil && tags.subdomainPolicy == nil {
		issues = append(issues, "No np= tag (DMARCbis) — non-existent subdomains inherit p= policy but adding np=reject provides explicit protection against subdomain spoofing")
	}
	return issues
}

func checkDMARCReportingIssues(tags dmarcTags) []string {
	var issues []string
	if tags.rua == nil {
		issues = append(issues, "No aggregate reporting (rua) configured — you won't receive reports about authentication results and potential abuse")
	}
	return issues
}

func buildRUFNote(tags dmarcTags) map[string]any {
	if tags.ruf != nil {
		return map[string]any{
			mapKeyStatus: "present",
			"summary":    "Forensic reporting (ruf) is configured, but most major providers do not send forensic reports.",
			"detail":     "RFC 7489 §7.3 warns that forensic reports can expose PII (full message headers or bodies). Google, Microsoft, and Yahoo do not honour ruf= requests. The DMARCbis draft (draft-ietf-dmarc-dmarcbis) has formally removed ruf= from the specification. Consider removing this tag to simplify your record.",
		}
	}
	return map[string]any{
		mapKeyStatus: "absent",
		"summary":    "No forensic reporting (ruf) tag — this is correct.",
		"detail":     "The absence of ruf= is not a gap. RFC 7489 §7.3 warns that forensic reports can expose PII (full message headers or bodies). Google, Microsoft, and Yahoo do not honour ruf= requests regardless. The DMARCbis draft (draft-ietf-dmarc-dmarcbis) has formally removed ruf= from the specification, confirming its deprecation. Omitting ruf= is the recommended modern practice.",
	}
}

func evaluateDMARCPolicy(tags dmarcTags) (string, string, []string) {
	if tags.policy == nil {
		return "info", "DMARC record found but policy unclear", nil
	}

	status, message, issues := classifyDMARCPolicyVerdict(*tags.policy, tags.pct)
	issues = append(issues, checkDMARCSubdomainIssues(tags)...)
	issues = append(issues, checkDMARCReportingIssues(tags)...)
	issues = append(issues, checkDMARCUnknownTags(tags)...)

	return status, message, issues
}

func checkDMARCUnknownTags(tags dmarcTags) []string {
	if len(tags.unknownTags) == 0 {
		return nil
	}
	var issues []string
	for _, tag := range tags.unknownTags {
		eqIdx := strings.Index(tag, "=")
		tagName := strings.TrimSpace(tag[:eqIdx])
		issues = append(issues, fmt.Sprintf("Unrecognized DMARC tag '%s' — per RFC 7489 §6.3, mail receivers will silently ignore this tag. If this is a typo, your intended policy is not being enforced", tagName))
	}
	return issues
}

func classifyDMARCRecords(records []string) (validDMARC, dmarcLike []string) {
	for _, record := range records {
		if record == "" {
			continue
		}
		lower := strings.ToLower(strings.TrimSpace(record))
		if lower == "v=dmarc1" || strings.HasPrefix(lower, "v=dmarc1;") || strings.HasPrefix(lower, "v=dmarc1 ") {
			validDMARC = append(validDMARC, record)
		} else if strings.Contains(lower, "dmarc") {
			dmarcLike = append(dmarcLike, record)
		}
	}
	return
}

func evaluateDMARCRecordSet(validDMARC []string) (string, string, []string, dmarcTags) {
	tags := dmarcTags{pct: 100, aspf: mapKeyRelaxed, adkim: mapKeyRelaxed}

	if len(validDMARC) == 0 {
		return "error", "No valid DMARC record found", nil, tags
	}
	if len(validDMARC) > 1 {
		return "error",
			"Multiple DMARC records found — receivers must treat this as no DMARC (RFC 7489 §6.6.3)",
			[]string{"Multiple DMARC records cause PermError — only one record permitted per RFC 7489"},
			tags
	}

	tags = parseDMARCTags(validDMARC[0])
	status, message, issues := evaluateDMARCPolicy(tags)
	return status, message, issues, tags
}

func buildDMARCbisTags(tags dmarcTags) map[string]string {
	dmarcbisTags := map[string]string{}
	if tags.npPolicy != nil {
		dmarcbisTags["np"] = *tags.npPolicy
	}
	if tags.tTesting != nil {
		dmarcbisTags["t"] = *tags.tTesting
	}
	if tags.psdFlag != nil {
		dmarcbisTags["psd"] = *tags.psdFlag
	}
	return dmarcbisTags
}

func ensureStringSlices(result map[string]any, keys ...string) {
	for _, key := range keys {
		if result[key] == nil {
			result[key] = []string{}
		}
	}
}

func (a *Analyzer) AnalyzeDMARC(ctx context.Context, domain string) map[string]any {
	dmarcRecords := a.DNS.QueryDNS(ctx, "TXT", fmt.Sprintf("_dmarc.%s", domain))

	baseResult := map[string]any{
		mapKeyStatus:       "missing",
		mapKeyMessage:      "No DMARC record found",
		mapKeyRecords:      []string{},
		mapKeyValidRecords: []string{},
		mapKeyDmarcLike:    []string{},
		"policy":           nil,
		"subdomain_policy": nil,
		"pct":              100,
		"aspf":             mapKeyRelaxed,
		"adkim":            mapKeyRelaxed,
		"rua":              nil,
		"ruf":              nil,
		"ruf_note":         map[string]any{},
		"np_policy":        nil,
		"t_testing":        nil,
		"psd_flag":         nil,
		"dmarcbis_tags":    map[string]string{},
		"unknown_tags":     []string(nil),
		mapKeyIssues:       []string{},
	}

	if len(dmarcRecords) == 0 {
		return baseResult
	}

	validDMARC, dmarcLike := classifyDMARCRecords(dmarcRecords)
	status, message, issues, tags := evaluateDMARCRecordSet(validDMARC)

	result := map[string]any{
		mapKeyStatus:       status,
		mapKeyMessage:      message,
		mapKeyRecords:      dmarcRecords,
		mapKeyValidRecords: validDMARC,
		mapKeyDmarcLike:    dmarcLike,
		"policy":           derefStr(tags.policy),
		"subdomain_policy": derefStr(tags.subdomainPolicy),
		"pct":              tags.pct,
		"aspf":             tags.aspf,
		"adkim":            tags.adkim,
		"rua":              derefStr(tags.rua),
		"ruf":              derefStr(tags.ruf),
		"ruf_note":         buildRUFNote(tags),
		"np_policy":        derefStr(tags.npPolicy),
		"t_testing":        derefStr(tags.tTesting),
		"psd_flag":         derefStr(tags.psdFlag),
		"dmarcbis_tags":    buildDMARCbisTags(tags),
		"unknown_tags":     tags.unknownTags,
		mapKeyIssues:       issues,
	}

	ensureStringSlices(result, mapKeyValidRecords, mapKeyDmarcLike, mapKeyIssues)

	return result
}

func DetectMisplacedDMARC(rootTXTRecords []string) map[string]any {
	var found []string
	for _, record := range rootTXTRecords {
		lower := strings.ToLower(strings.TrimSpace(record))
		if lower == "v=dmarc1" || strings.HasPrefix(lower, "v=dmarc1;") || strings.HasPrefix(lower, "v=dmarc1 ") {
			found = append(found, record)
		}
	}
	if len(found) == 0 {
		return map[string]any{
			"detected": false,
		}
	}
	tags := parseDMARCTags(found[0])
	policy := ""
	if tags.policy != nil {
		policy = *tags.policy
	}
	return map[string]any{
		"detected":    true,
		mapKeyRecords: found,
		"policy_hint": policy,
		mapKeyMessage: "DMARC record found in root TXT records — this is ignored by mail receivers. DMARC records must be published at _dmarc.<domain> per RFC 7489 §6.1.",
	}
}

func ExtractMailtoDomains(ruaString string) []string {
	if ruaString == "" {
		return nil
	}
	var domains []string
	matches := mailtoExtractRe.FindAllStringSubmatch(ruaString, -1)
	for _, m := range matches {
		addr := m[1]
		if idx := strings.Index(addr, "@"); idx >= 0 {
			d := strings.TrimRight(strings.TrimSpace(addr[idx+1:]), ".")
			if d != "" {
				domains = append(domains, strings.ToLower(d))
			}
		}
	}
	return domains
}
