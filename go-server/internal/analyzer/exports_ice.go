// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

func ExportClassifyAllQualifier(spfRecord string) *string {
	p, _, _ := classifyAllQualifier(spfRecord)
	return p
}

func ExportCountSPFLookups(spfRecord string) int {
	r := parseSPFMechanisms(spfRecord)
	return r.lookupCount
}

func ExportBuildSPFVerdict(lookupCount int, permissiveness *string, noMailIntent bool, validSPF, spfLike []string) (string, string) {
	s := &spfEvalState{
		lookupCount:    lookupCount,
		permissiveness: permissiveness,
		noMailIntent:   noMailIntent,
	}
	return buildSPFVerdict(s, validSPF, spfLike)
}

func ExportParseSPFMechanisms(spfRecord string) (int, []string, []string, *string, *string, []string, bool) {
	r := parseSPFMechanisms(spfRecord)
	return r.lookupCount, r.lookupMechanisms, r.includes, r.permissiveness, r.allMechanism, r.issues, r.noMailIntent
}

func ExportClassifySPFRecords(records []string) ([]string, []string) {
	return classifySPFRecords(records)
}

func ExportBuildEmailAnswer(isNoMailDomain bool, dmarcPolicy string, dmarcPct int, nullMX bool, hasSPF, hasDMARC bool) string {
	ps := protocolState{
		isNoMailDomain: isNoMailDomain || nullMX,
		dmarcPolicy:    dmarcPolicy,
		dmarcPct:       dmarcPct,
	}
	return buildEmailAnswer(ps, hasSPF, hasDMARC)
}

func ExportBuildEmailAnswerStructured(isNoMailDomain bool, dmarcPolicy string, dmarcPct int, nullMX bool, hasSPF, hasDMARC bool) map[string]string {
	ps := protocolState{
		isNoMailDomain: isNoMailDomain || nullMX,
		dmarcPolicy:    dmarcPolicy,
		dmarcPct:       dmarcPct,
	}
	return buildEmailAnswerStructured(ps, hasSPF, hasDMARC)
}

func ExportClassifyEnterpriseDNS(domain string, nameservers []string) map[string]any {
	return classifyEnterpriseDNS(domain, nameservers)
}

func ExportBuildDNSVerdict(dnssecOK, dnssecBroken bool) map[string]any {
	ps := protocolState{
		dnssecOK:     dnssecOK,
		dnssecBroken: dnssecBroken,
	}
	verdicts := map[string]any{}
	buildDNSVerdict(ps, verdicts)
	return verdicts["dns_tampering"].(map[string]any)
}

func ExportClassifyNSProvider(ns string) string {
	return classifyNSProvider(ns)
}

func ExportRegistrableDomain(domain string) string {
	return registrableDomain(domain)
}

func ExportAnalyzeDKIMKey(record string) map[string]any {
	return analyzeDKIMKey(record)
}

func ExportClassifySelectorProvider(selectorName, primaryProvider string) string {
	return classifySelectorProvider(selectorName, primaryProvider)
}

func ExportIdentifyCAIssuer(record string) string {
	return identifyCAIssuer(record)
}

func ExportParseCAARecords(records []string) ([]string, []string, bool, bool) {
	parsed := parseCAARecords(records)
	return collectMapKeys(parsed.issueSet), collectMapKeys(parsed.issuewildSet), parsed.hasWildcard, parsed.hasIodef
}

func ExportBuildCAAMessage(issuers, wildcardIssuers []string, hasWildcard bool) string {
	return buildCAAMessage(issuers, wildcardIssuers, hasWildcard)
}

func ExportFilterSTSRecords(records []string) []string {
	return filterSTSRecords(records)
}

func ExportExtractSTSID(record string) *string {
	return extractSTSID(record)
}

func ExportDetermineMTASTSModeStatus(mode string, policyData map[string]any) (string, string) {
	return determineMTASTSModeStatus(mode, policyData)
}

func ExportParseMTASTSPolicyLines(policyText string) (string, int, []string, bool) {
	f := parseMTASTSPolicyLines(policyText)
	return f.mode, f.maxAge, f.mx, f.hasVersion
}

func ExportFilterBIMIRecords(records []string) []string {
	return filterBIMIRecords(records)
}

func ExportExtractBIMIURLs(record string) (*string, *string) {
	return extractBIMIURLs(record)
}

func ExportParseTLSAEntry(entry string, mxHost, tlsaName string) (map[string]any, bool) {
	return parseTLSAEntry(entry, mxHost, tlsaName)
}

func ExportExtractMXHosts(mxRecords []string) []string {
	return extractMXHosts(mxRecords)
}

func ExportBuildDANEVerdict(allTLSA []map[string]any, hostsWithDANE, mxHosts []string, mxCapability map[string]any) (string, string, []string) {
	return buildDANEVerdict(allTLSA, hostsWithDANE, mxHosts, mxCapability)
}

func ExportIsHostedEmailProvider(domain string) bool {
	return isHostedEmailProvider(domain)
}

func ExportIsBIMICapableProvider(domain string) bool {
	return isBIMICapableProvider(domain)
}

func ExportClassifyDMARCRecords(records []string) ([]string, []string) {
	return classifyDMARCRecords(records)
}

func ExportParseDMARCPolicy(record string) (policy string, pct int, hasRUA bool) {
	tags := parseDMARCTags(record)
	p := ""
	if tags.policy != nil {
		p = *tags.policy
	}
	return p, tags.pct, tags.rua != nil
}

func ExportExtractTLSRPTURIs(record string) []string {
	return extractTLSRPTURIs(record)
}

func ExportBuildBrandVerdict(dmarcMissing bool, dmarcPolicy string, bimiOK, caaOK bool) map[string]any {
	ps := protocolState{
		dmarcMissing: dmarcMissing,
		dmarcPolicy:  dmarcPolicy,
		bimiOK:       bimiOK,
		caaOK:        caaOK,
	}
	verdicts := map[string]any{}
	buildBrandVerdict(ps, verdicts)
	result, _ := verdicts["brand_impersonation"].(map[string]any)
	return result
}
