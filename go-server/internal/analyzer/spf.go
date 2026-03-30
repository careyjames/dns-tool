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
	mapKeyIncludes         = "includes"
	mapKeyLookupMechanisms = "lookup_mechanisms"
	mapKeySpfLike          = "spf_like"
	strStrict              = "STRICT"
)

const spfRecordNone = "(none)"

var (
	spfIncludeRe  = regexp.MustCompile(`(?i)include:([^\s]+)`)
	spfAMechRe    = regexp.MustCompile(`(?i)\ba([:/\s]|$)`)
	spfMXMechRe   = regexp.MustCompile(`(?i)\bmx([:/\s]|$)`)
	spfPTRMechRe  = regexp.MustCompile(`(?i)\bptr([:/\s]|$)`)
	spfExistsRe   = regexp.MustCompile(`(?i)exists:`)
	spfRedirectRe = regexp.MustCompile(`(?i)redirect=([^\s]+)`)
	spfAllRe      = regexp.MustCompile(`(?i)([+\-~?]?)all\b`)
)

type spfMechanismResult struct {
	lookupCount      int
	lookupMechanisms []string
	includes         []string
	issues           []string
}

func countSPFLookupMechanisms(spfLower string) spfMechanismResult {
	var r spfMechanismResult

	includeMatches := spfIncludeRe.FindAllStringSubmatch(spfLower, -1)
	for _, m := range includeMatches {
		r.includes = append(r.includes, m[1])
		r.lookupMechanisms = append(r.lookupMechanisms, fmt.Sprintf("include:%s", m[1]))
	}
	r.lookupCount += len(includeMatches)

	aMatches := spfAMechRe.FindAllString(spfLower, -1)
	r.lookupCount += len(aMatches)
	if len(aMatches) > 0 {
		r.lookupMechanisms = append(r.lookupMechanisms, "a mechanism")
	}

	mxMatches := spfMXMechRe.FindAllString(spfLower, -1)
	r.lookupCount += len(mxMatches)
	if len(mxMatches) > 0 {
		r.lookupMechanisms = append(r.lookupMechanisms, "mx mechanism")
	}

	ptrMatches := spfPTRMechRe.FindAllString(spfLower, -1)
	r.lookupCount += len(ptrMatches)
	if len(ptrMatches) > 0 {
		r.lookupMechanisms = append(r.lookupMechanisms, "ptr mechanism (deprecated)")
		r.issues = append(r.issues, "PTR mechanism used (deprecated, slow)")
	}

	existsMatches := spfExistsRe.FindAllString(spfLower, -1)
	r.lookupCount += len(existsMatches)
	if len(existsMatches) > 0 {
		r.lookupMechanisms = append(r.lookupMechanisms, "exists mechanism")
	}

	redirectMatch := spfRedirectRe.FindStringSubmatch(spfLower)
	if redirectMatch != nil {
		r.lookupCount++
		r.lookupMechanisms = append(r.lookupMechanisms, fmt.Sprintf("redirect:%s", redirectMatch[1]))
	}

	return r
}

func classifyAllQualifier(spfLower string) (*string, *string, []string) {
	allMatch := spfAllRe.FindStringSubmatch(spfLower)
	if allMatch == nil {
		return nil, nil, nil
	}

	qualifier := allMatch[1]
	if qualifier == "" {
		qualifier = "+"
	}
	am := qualifier + "all"

	var issues []string
	var p string
	switch qualifier {
	case "+", "":
		p = "DANGEROUS"
		issues = append(issues, "+all allows anyone to send as your domain")
	case "?":
		p = "NEUTRAL"
		issues = append(issues, "?all provides no protection")
	case "~":
		p = "SOFT"
	case "-":
		p = strStrict
	}

	return &p, &am, issues
}

type spfParseResult struct {
	lookupCount      int
	lookupMechanisms []string
	includes         []string
	permissiveness   *string
	allMechanism     *string
	issues           []string
	noMailIntent     bool
}

func parseSPFMechanisms(spfRecord string) spfParseResult {
	spfLower := strings.ToLower(spfRecord)

	r := countSPFLookupMechanisms(spfLower)
	permissiveness, allMechanism, allIssues := classifyAllQualifier(spfLower)
	issues := append(r.issues, allIssues...)

	hasSenders := len(r.includes) > 0 || len(spfAMechRe.FindAllString(spfLower, -1)) > 0 || len(spfMXMechRe.FindAllString(spfLower, -1)) > 0
	if permissiveness != nil && *permissiveness == strStrict && hasSenders {
		issues = append(issues, "RFC 7489: -all may cause rejection before DMARC evaluation, preventing DKIM from being checked")
	}

	noMailIntent := false
	normalized := strings.Join(strings.Fields(strings.TrimSpace(spfLower)), " ")
	if normalized == "v=spf1 -all" || normalized == "\"v=spf1 -all\"" {
		noMailIntent = true
	}

	return spfParseResult{
		lookupCount:      r.lookupCount,
		lookupMechanisms: r.lookupMechanisms,
		includes:         r.includes,
		permissiveness:   permissiveness,
		allMechanism:     allMechanism,
		issues:           issues,
		noMailIntent:     noMailIntent,
	}
}

func buildSPFVerdict(s *spfEvalState, validSPF, spfLike []string) (string, string) {
	if len(validSPF) > 1 {
		return mapKeyError, "Multiple SPF records found - this causes SPF to fail (RFC 7208)"
	}
	if len(validSPF) == 0 {
		if len(spfLike) > 0 {
			return mapKeyWarning, "SPF-like record found but not valid — check syntax"
		}
		return "missing", "No SPF record found"
	}

	if s.lookupCount > 10 {
		return mapKeyError, fmt.Sprintf("SPF exceeds 10 DNS lookup limit (%d/10) — PermError per RFC 7208 §4.6.4", s.lookupCount)
	}
	if s.lookupCount == 10 {
		return mapKeyWarning, "SPF at lookup limit (10/10 lookups) - no room for growth"
	}
	if s.permissiveness != nil && *s.permissiveness == "DANGEROUS" {
		return mapKeyError, "SPF uses +all - anyone can send as this domain"
	}
	if s.permissiveness != nil && *s.permissiveness == "NEUTRAL" {
		return mapKeyWarning, "SPF uses ?all - provides no protection"
	}

	if s.noMailIntent {
		return mapKeySuccess, "Valid SPF (no mail allowed) - domain declares it sends no email"
	}
	if s.permissiveness != nil && *s.permissiveness == strStrict {
		return mapKeySuccess, fmt.Sprintf("SPF valid with strict enforcement (-all), %d/10 lookups", s.lookupCount)
	}
	if s.permissiveness != nil && *s.permissiveness == "SOFT" {
		return mapKeySuccess, fmt.Sprintf("SPF valid with industry-standard soft fail (~all), %d/10 lookups", s.lookupCount)
	}
	return mapKeySuccess, fmt.Sprintf("SPF valid, %d/10 lookups", s.lookupCount)
}

func classifySPFRecords(records []string) (validSPF, spfLike []string) {
	for _, record := range records {
		if record == "" {
			continue
		}
		lower := strings.ToLower(strings.TrimSpace(record))
		if lower == "v=spf1" || strings.HasPrefix(lower, "v=spf1 ") {
			validSPF = append(validSPF, record)
		} else if strings.Contains(lower, "spf") {
			spfLike = append(spfLike, record)
		}
	}
	return
}

func evaluateSPFRecordSet(validSPF []string) spfParseResult {
	result := spfParseResult{}

	if len(validSPF) > 1 {
		result.issues = append(result.issues, "Multiple SPF records (hard fail)")
	}

	if len(validSPF) == 1 {
		result = parseSPFMechanisms(validSPF[0])
		if result.lookupCount > 10 {
			result.issues = append(result.issues, fmt.Sprintf("Exceeds 10 DNS lookup limit (%d lookups)", result.lookupCount))
		} else if result.lookupCount == 10 {
			result.issues = append(result.issues, "At lookup limit (10/10)")
		}
	}

	return result
}

func extractRedirectTarget(spfRecord string) string {
	m := spfRedirectRe.FindStringSubmatch(spfRecord)
	if m == nil {
		return ""
	}
	return strings.TrimRight(m[1], ".")
}

func hasAllMechanism(spfRecord string) bool {
	return spfAllRe.MatchString(spfRecord)
}

type spfRedirectHop struct {
	Domain    string `json:"domain"`
	SPFRecord string `json:"spf_record"`
}

func (a *Analyzer) processSPFRedirectHop(ctx context.Context, target string, cumulativeLookups int) (hop spfRedirectHop, hopLookups int, issues []string, hasMore bool) {
	targetTXT := a.DNS.QueryDNS(ctx, "TXT", target)
	targetValid, _ := classifySPFRecords(targetTXT)

	if len(targetValid) == 0 {
		issues = append(issues, fmt.Sprintf("SPF redirect target %s has no valid SPF record — results in PermError (RFC 7208 §6.1)", target))
		hop = spfRedirectHop{Domain: target, SPFRecord: spfRecordNone}
		return
	}
	if len(targetValid) > 1 {
		issues = append(issues, fmt.Sprintf("SPF redirect target %s has multiple SPF records — results in PermError", target))
	}

	resolvedRecord := targetValid[0]
	hop = spfRedirectHop{Domain: target, SPFRecord: resolvedRecord}

	targetMechs := countSPFLookupMechanisms(strings.ToLower(resolvedRecord))
	hopLookups = targetMechs.lookupCount

	hasMore = extractRedirectTarget(resolvedRecord) != "" && !hasAllMechanism(resolvedRecord)
	return
}

func checkRedirectTermination(currentRecord, target string, visited map[string]bool, cumulativeLookups int) (issue string, stop bool) {
	if target == "" {
		return "", true
	}
	if hasAllMechanism(currentRecord) {
		return "", true
	}
	if visited[strings.ToLower(target)] {
		return fmt.Sprintf("SPF redirect loop detected at %s", target), true
	}
	if cumulativeLookups > 10 {
		return "SPF redirect chain exceeds 10 DNS lookup limit", true
	}
	return "", false
}

func (a *Analyzer) followSPFRedirectChain(ctx context.Context, spfRecord string, totalLookups int) ([]spfRedirectHop, string, int, []string) {
	var chain []spfRedirectHop
	visited := map[string]bool{}
	var redirectIssues []string
	currentRecord := spfRecord
	cumulativeLookups := totalLookups

	for i := 0; i < 10; i++ {
		target := extractRedirectTarget(currentRecord)
		issue, stop := checkRedirectTermination(currentRecord, target, visited, cumulativeLookups)
		if issue != "" {
			redirectIssues = append(redirectIssues, issue)
		}
		if stop {
			break
		}
		visited[strings.ToLower(target)] = true

		hop, hopLookups, hopIssues, hasMore := a.processSPFRedirectHop(ctx, target, cumulativeLookups)
		chain = append(chain, hop)
		cumulativeLookups += hopLookups
		redirectIssues = append(redirectIssues, hopIssues...)

		if hop.SPFRecord == spfRecordNone {
			break
		}

		if hasMore {
			currentRecord = hop.SPFRecord
			continue
		}

		return chain, hop.SPFRecord, cumulativeLookups, redirectIssues
	}

	if len(chain) > 0 {
		return chain, chain[len(chain)-1].SPFRecord, cumulativeLookups, redirectIssues
	}
	return chain, "", cumulativeLookups, redirectIssues
}

func redirectChainToMaps(chain []spfRedirectHop) []map[string]any {
	var maps []map[string]any
	for _, hop := range chain {
		maps = append(maps, map[string]any{
			"domain":     hop.Domain,
			"spf_record": hop.SPFRecord,
		})
	}
	return maps
}

type spfEvalState struct {
	lookupCount      int
	lookupMechanisms []string
	includes         []string
	permissiveness   *string
	allMechanism     *string
	noMailIntent     bool
	issues           []string
}

func mergeResolvedSPF(resolved string, s *spfEvalState) {
	r := parseSPFMechanisms(resolved)
	s.lookupMechanisms = append(s.lookupMechanisms, r.lookupMechanisms...)
	s.includes = append(s.includes, r.includes...)
	if r.permissiveness != nil {
		s.permissiveness = r.permissiveness
	}
	if r.allMechanism != nil {
		s.allMechanism = r.allMechanism
	}
	if r.noMailIntent {
		s.noMailIntent = true
	}
}

func (a *Analyzer) handleSPFRedirectChain(ctx context.Context, validSPF []string, s *spfEvalState) ([]map[string]any, string) {
	if len(validSPF) != 1 {
		return nil, ""
	}

	target := extractRedirectTarget(validSPF[0])
	if target == "" || hasAllMechanism(validSPF[0]) {
		return nil, ""
	}

	chain, resolved, totalLookups, redirectIssues := a.followSPFRedirectChain(ctx, validSPF[0], s.lookupCount)
	s.lookupCount = totalLookups
	s.issues = append(s.issues, redirectIssues...)
	redirectChainMaps := redirectChainToMaps(chain)

	if resolved != "" && resolved != spfRecordNone {
		mergeResolvedSPF(resolved, s)
		return redirectChainMaps, resolved
	}

	return redirectChainMaps, ""
}

func (a *Analyzer) AnalyzeSPF(ctx context.Context, domain string) map[string]any {
	txtRecords := a.DNS.QueryDNS(ctx, "TXT", domain)

	baseResult := map[string]any{
		"status":               "missing",
		"message":              "No SPF record found",
		"records":              []string{},
		mapKeyValidRecords:     []string{},
		mapKeySpfLike:          []string{},
		"lookup_count":         0,
		mapKeyLookupMechanisms: []string{},
		"permissiveness":       nil,
		"all_mechanism":        nil,
		mapKeyIssues:           []string{},
		mapKeyIncludes:         []string{},
		"no_mail_intent":       false,
		"redirect_chain":       []map[string]any{},
		"resolved_spf":         "",
	}

	if len(txtRecords) == 0 {
		return baseResult
	}

	validSPF, spfLike := classifySPFRecords(txtRecords)
	parsed := evaluateSPFRecordSet(validSPF)

	s := &spfEvalState{
		lookupCount:      parsed.lookupCount,
		lookupMechanisms: parsed.lookupMechanisms,
		includes:         parsed.includes,
		permissiveness:   parsed.permissiveness,
		allMechanism:     parsed.allMechanism,
		noMailIntent:     parsed.noMailIntent,
		issues:           parsed.issues,
	}

	redirectChainMaps, resolvedSPF := a.handleSPFRedirectChain(ctx, validSPF, s)

	status, message := buildSPFVerdict(s, validSPF, spfLike)

	if len(redirectChainMaps) > 0 && resolvedSPF != "" {
		chainDomains := make([]string, 0, len(redirectChainMaps))
		for _, hop := range redirectChainMaps {
			chainDomains = append(chainDomains, hop["domain"].(string))
		}
		message = fmt.Sprintf("%s (via redirect: %s)", message, strings.Join(chainDomains, " → "))
	}

	if redirectChainMaps == nil {
		redirectChainMaps = []map[string]any{}
	}

	result := map[string]any{
		"status":               status,
		"message":              message,
		"records":              txtRecords,
		mapKeyValidRecords:     validSPF,
		mapKeySpfLike:          spfLike,
		"lookup_count":         s.lookupCount,
		mapKeyLookupMechanisms: s.lookupMechanisms,
		"permissiveness":       derefStr(s.permissiveness),
		"all_mechanism":        derefStr(s.allMechanism),
		mapKeyIssues:           s.issues,
		mapKeyIncludes:         s.includes,
		"no_mail_intent":       s.noMailIntent,
		"redirect_chain":       redirectChainMaps,
		"resolved_spf":         resolvedSPF,
	}

	ensureStringSlices(result, mapKeyValidRecords, mapKeySpfLike, mapKeyLookupMechanisms, mapKeyIssues, mapKeyIncludes)

	return result
}
