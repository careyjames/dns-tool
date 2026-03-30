// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
//
// Golden Fixture Test Cases — End-to-end correctness validation.
//
// These fixtures represent real-world domain configurations that have been
// manually verified. Each fixture tests the full analysis pipeline from
// raw DNS records through to final verdicts, ensuring the entire chain
// produces correct results.
//
// Unlike unit-level analysis tests (which test individual functions),
// fixture tests combine multiple functions to verify integrated behavior.
// This catches bugs that only appear when functions interact.
// dns-tool:scrutiny science
package icae

import (
	"dnstool/go-server/internal/analyzer"
	"fmt"
	"strings"
)

func FixtureTestCases() []TestCase {
	var cases []TestCase
	cases = append(cases, wellConfiguredDomainFixtures()...)
	cases = append(cases, noMailDomainFixtures()...)
	cases = append(cases, partialProtectionFixtures()...)
	cases = append(cases, edgeCaseFixtures()...)
	return cases
}

func wellConfiguredDomainFixtures() []TestCase {
	return []TestCase{
		{
			CaseID:     "fixture-wellcfg-001",
			CaseName:   "Well-configured domain: reject + SPF + DMARC = not spoofable",
			Protocol:   mapKeyDmarc,
			Layer:      LayerAnalysis,
			RFCSection: citFixtureE2eDmarcSPF,
			Expected:   "No — SPF and DMARC reject policy enforced",
			RunFn: func() (string, bool) {
				spfRecords := []string{"v=spf1 include:_spf.google.com -all"}
				valid, _ := analyzer.ExportClassifySPFRecords(spfRecords)
				hasSPF := len(valid) > 0

				answer := analyzer.ExportBuildEmailAnswer(false, "reject", 100, false, hasSPF, true)
				return answer, answer == "No — SPF and DMARC reject policy enforced"
			},
		},
		{
			CaseID:     "fixture-wellcfg-002",
			CaseName:   "Well-configured domain: reject + BIMI + CAA = brand protected",
			Protocol:   mapKeyDmarc,
			Layer:      LayerAnalysis,
			RFCSection: citFixtureE2eBimiCAA,
			Expected:   "answer=No, label=Protected",
			RunFn: func() (string, bool) {
				verdict := analyzer.ExportBuildBrandVerdict(false, "reject", true, true)
				answer, _ := verdict[mapKeyAnswer].(string)
				label, _ := verdict["label"].(string)
				actual := fmt.Sprintf("answer=%s, label=%s", answer, label)
				return actual, answer == "No" && label == "Protected"
			},
		},
		{
			CaseID:     "fixture-wellcfg-003",
			CaseName:   "Well-configured domain: DNSSEC signed + enterprise DNS = protected",
			Protocol:   "dnssec",
			Layer:      LayerAnalysis,
			RFCSection: citFixtureE2eDNSSEC,
			Expected:   "tampering=No, provider=Cloudflare",
			RunFn: func() (string, bool) {
				dnsVerdict := analyzer.ExportBuildDNSVerdict(true, false)
				answer, _ := dnsVerdict[mapKeyAnswer].(string)

				enterprise := analyzer.ExportClassifyEnterpriseDNS("example.com", []string{"ns1.cloudflare.com.", "ns2.cloudflare.com."})
				providers, _ := enterprise["dns_providers"].([]string)
				provider := ""
				if len(providers) > 0 {
					provider = providers[0]
				}

				actual := fmt.Sprintf("tampering=%s, provider=%s", answer, provider)
				return actual, answer == "No" && provider == "Cloudflare"
			},
		},
		{
			CaseID:     "fixture-wellcfg-004",
			CaseName:   "Well-configured domain: MTA-STS enforce + valid policy",
			Protocol:   "mta_sts",
			Layer:      LayerAnalysis,
			RFCSection: citFixtureE2eMTASTS,
			Expected:   "mode=enforce, status=success, max_age valid",
			RunFn: func() (string, bool) {
				stsRecords := analyzer.ExportFilterSTSRecords([]string{"v=STSv1; id=20260220T000000", "unrelated-txt-record"})
				if len(stsRecords) != 1 {
					return fmt.Sprintf("filtered %d records, expected 1", len(stsRecords)), false
				}

				id := analyzer.ExportExtractSTSID(stsRecords[0])
				if id == nil {
					return "nil ID", false
				}

				mode, maxAge, mx, hasVersion := analyzer.ExportParseMTASTSPolicyLines(
					"version: STSv1\nmode: enforce\nmax_age: 604800\nmx: mail.example.com\nmx: *.example.com\n",
				)
				if !hasVersion || mode != "enforce" || maxAge != 604800 || len(mx) != 2 {
					return fmt.Sprintf("mode=%s, maxAge=%d, mx=%d, version=%t", mode, maxAge, len(mx), hasVersion), false
				}

				status, _ := analyzer.ExportDetermineMTASTSModeStatus(mode, map[string]any{
					"mx": mx,
				})
				actual := fmt.Sprintf("mode=%s, status=%s, max_age=%d", mode, status, maxAge)
				return actual, status == mapKeySuccess
			},
		},
		{
			CaseID:     "fixture-wellcfg-005",
			CaseName:   "Well-configured domain: DANE full MX coverage",
			Protocol:   "dane",
			Layer:      LayerAnalysis,
			RFCSection: citFixtureE2eDANE,
			Expected:   "DANE verdict=success with full coverage",
			RunFn: func() (string, bool) {
				mxHosts := analyzer.ExportExtractMXHosts([]string{"10 mail.example.com.", "20 mail2.example.com."})

				tlsa1, valid1 := analyzer.ExportParseTLSAEntry(
					"3 1 1 aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344",
					testMailExampleCom, "_25._tcp.mail.example.com",
				)
				tlsa2, valid2 := analyzer.ExportParseTLSAEntry(
					"3 1 1 eeff0011aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd",
					"mail2.example.com", "_25._tcp.mail2.example.com",
				)
				if !valid1 || !valid2 {
					return "invalid TLSA", false
				}

				allTLSA := []map[string]any{tlsa1, tlsa2}
				hostsWithDANE := []string{testMailExampleCom, "mail2.example.com"}
				status, _, _ := analyzer.ExportBuildDANEVerdict(allTLSA, hostsWithDANE, mxHosts, nil)

				actual := fmt.Sprintf("status=%s, mx=%d, dane_hosts=%d", status, len(mxHosts), len(hostsWithDANE))
				return actual, status == mapKeySuccess
			},
		},
	}
}

func noMailDomainFixtures() []TestCase {
	return []TestCase{
		{
			CaseID:     "fixture-nomail-001",
			CaseName:   "No-mail domain: null MX + SPF -all = not spoofable",
			Protocol:   mapKeyDmarc,
			Layer:      LayerAnalysis,
			RFCSection: citFixtureE2eNullMXSPF,
			Expected:   "No — null MX indicates no-mail domain",
			RunFn: func() (string, bool) {
				mxHosts := analyzer.ExportExtractMXHosts([]string{"0 ."})
				isNullMX := len(mxHosts) == 0

				spfRecords := []string{testSPFDenyAll}
				valid, _ := analyzer.ExportClassifySPFRecords(spfRecords)
				hasSPF := len(valid) > 0

				qual := analyzer.ExportClassifyAllQualifier(testSPFDenyAll)
				isStrict := qual != nil && *qual == "STRICT"

				answer := analyzer.ExportBuildEmailAnswer(true, "", 0, true, hasSPF, false)

				actual := fmt.Sprintf("answer=%s, nullMX=%t, strict=%t", answer, isNullMX, isStrict)
				return actual, answer == "No — null MX indicates no-mail domain" && isNullMX && isStrict
			},
		},
		{
			CaseID:     "fixture-nomail-002",
			CaseName:   "No-mail domain: SPF -all standalone = success status",
			Protocol:   "spf",
			Layer:      LayerAnalysis,
			RFCSection: citFixtureE2eSPF,
			Expected:   "SPF status=success for no-mail",
			RunFn: func() (string, bool) {
				count, _, _, perm, _, _, noMail := analyzer.ExportParseSPFMechanisms(testSPFDenyAll)
				status, _ := analyzer.ExportBuildSPFVerdict(count, perm, noMail, []string{testSPFDenyAll}, nil)
				actual := fmt.Sprintf("status=%s, noMail=%t", status, noMail)
				return actual, status == mapKeySuccess && noMail
			},
		},
	}
}

func partialProtectionFixtures() []TestCase {
	return []TestCase{
		{
			CaseID:     "fixture-partial-001",
			CaseName:   "Partial protection: quarantine + no BIMI + no CAA",
			Protocol:   mapKeyDmarc,
			Layer:      LayerAnalysis,
			RFCSection: citFixtureE2eBimiCAASec,
			Expected:   "answer=Likely, label=Basic",
			RunFn: func() (string, bool) {
				verdict := analyzer.ExportBuildBrandVerdict(false, "quarantine", false, false)
				answer, _ := verdict[mapKeyAnswer].(string)
				label, _ := verdict["label"].(string)
				actual := fmt.Sprintf("answer=%s, label=%s", answer, label)
				return actual, answer == "Likely" && label == "Basic"
			},
		},
		{
			CaseID:     "fixture-partial-002",
			CaseName:   "Partial protection: p=none with SPF = monitor-only spoofable",
			Protocol:   mapKeyDmarc,
			Layer:      LayerAnalysis,
			RFCSection: citFixtureE2eDmarcS63,
			Expected:   "monitor-only (spoofable)",
			RunFn: func() (string, bool) {
				result := analyzer.ExportBuildEmailAnswerStructured(false, "none", 0, false, true, true)
				color := result["color"]
				answer := analyzer.ExportBuildEmailAnswer(false, "none", 0, false, true, true)
				actual := fmt.Sprintf("color=%s, answer=%s", color, answer)
				return actual, color == "danger" && strings.Contains(answer, "monitor-only")
			},
		},
		{
			CaseID:     "fixture-partial-003",
			CaseName:   "Partial protection: quarantine at 25% = limited coverage",
			Protocol:   mapKeyDmarc,
			Layer:      LayerAnalysis,
			RFCSection: citFixtureE2eDmarcS63,
			Expected:   "partial percentage flagged",
			RunFn: func() (string, bool) {
				answer := analyzer.ExportBuildEmailAnswer(false, "quarantine", 25, false, true, true)
				return answer, strings.Contains(answer, "limited percentage")
			},
		},
	}
}

func edgeCaseFixtures() []TestCase {
	return []TestCase{
		{
			CaseID:     "fixture-edge-001",
			CaseName:   "Edge case: +all SPF = dangerous despite having DMARC reject",
			Protocol:   "spf",
			Layer:      LayerAnalysis,
			RFCSection: citFixtureE2eSPFS5,
			Expected:   "SPF dangerous even with DMARC reject",
			RunFn: func() (string, bool) {
				qual := analyzer.ExportClassifyAllQualifier("v=spf1 +all")
				if qual == nil || *qual != "DANGEROUS" {
					return "qualifier not DANGEROUS", false
				}
				status, msg := analyzer.ExportBuildSPFVerdict(1, qual, false, []string{"v=spf1 +all"}, nil)
				actual := fmt.Sprintf("status=%s, dangerous=%t", status, strings.Contains(msg, "anyone can send"))
				return actual, status == "error" && strings.Contains(msg, "anyone can send")
			},
		},
		{
			CaseID:     "fixture-edge-002",
			CaseName:   "Edge case: BIMI record with no VMC authority URL",
			Protocol:   "bimi",
			Layer:      LayerAnalysis,
			RFCSection: "BIMI Spec §3 (end-to-end)",
			Expected:   "logo URL present, authority nil",
			RunFn: func() (string, bool) {
				records := analyzer.ExportFilterBIMIRecords([]string{"v=BIMI1; l=https://example.com/logo.svg;"})
				if len(records) != 1 {
					return fmt.Sprintf("filtered %d records", len(records)), false
				}
				logo, auth := analyzer.ExportExtractBIMIURLs(records[0])
				hasLogo := logo != nil && strings.HasPrefix(*logo, "https://")
				noAuth := auth == nil || *auth == ""
				actual := "logo=nil"
				if logo != nil {
					actual = fmt.Sprintf("logo=%s, auth_nil=%t", *logo, noAuth)
				}
				return actual, hasLogo && noAuth
			},
		},
		{
			CaseID:     "fixture-edge-003",
			CaseName:   "Edge case: CAA with only iodef (no issue/issuewild) = open issuance",
			Protocol:   "caa",
			Layer:      LayerAnalysis,
			RFCSection: citFixtureE2eCAASection,
			Expected:   "0 issuers but has iodef",
			RunFn: func() (string, bool) {
				issuers, wildcardIssuers, _, hasIodef := analyzer.ExportParseCAARecords([]string{
					`0 iodef "mailto:certs@example.com"`,
				})
				actual := fmt.Sprintf("issuers=%d, wildcards=%d, iodef=%t", len(issuers), len(wildcardIssuers), hasIodef)
				return actual, len(issuers) == 0 && len(wildcardIssuers) == 0 && hasIodef
			},
		},
		{
			CaseID:     "fixture-edge-004",
			CaseName:   "Edge case: DANE partial MX coverage = warning verdict",
			Protocol:   "dane",
			Layer:      LayerAnalysis,
			RFCSection: citFixtureE2eDANE,
			Expected:   "DANE warning for partial coverage",
			RunFn: func() (string, bool) {
				mxHosts := analyzer.ExportExtractMXHosts([]string{"10 mail.example.com.", "20 mail2.example.com."})
				tlsa, valid := analyzer.ExportParseTLSAEntry(
					"3 1 1 aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344",
					testMailExampleCom, "_25._tcp.mail.example.com",
				)
				if !valid {
					return "invalid TLSA", false
				}
				hostsWithDANE := []string{testMailExampleCom}
				status, _, _ := analyzer.ExportBuildDANEVerdict([]map[string]any{tlsa}, hostsWithDANE, mxHosts, nil)
				actual := fmt.Sprintf("status=%s, covered=%d/%d", status, len(hostsWithDANE), len(mxHosts))
				return actual, status == "warning"
			},
		},
		{
			CaseID:     "fixture-edge-005",
			CaseName:   "Edge case: stub defaults prevent false BIMI capability",
			Protocol:   "bimi",
			Layer:      LayerAnalysis,
			RFCSection: "Stub contract (end-to-end)",
			Expected:   "hosted=true, bimi_capable=false",
			RunFn: func() (string, bool) {
				hosted := analyzer.ExportIsHostedEmailProvider("unknown-provider.example")
				bimiCapable := analyzer.ExportIsBIMICapableProvider("unknown-provider.example")
				actual := fmt.Sprintf("hosted=%t, bimi_capable=%t", hosted, bimiCapable)
				return actual, hosted && !bimiCapable
			},
		},
	}
}
