// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package icae

import (
        "dnstool/go-server/internal/analyzer"
        "fmt"
        "strings"
)

const (
        testDKIMPrefix           = "v=DKIM1; k=rsa; p="
        testProviderMicrosoft365 = "Microsoft 365"
        testProviderLetsEncrypt  = "Let's Encrypt"
        testCAAIssueLetsEncrypt  = `0 issue "letsencrypt.org"`
        testBIMIRecord           = "v=BIMI1; l=https://example.com/logo.svg"
        fmtAnswerLabel           = "answer=%s, label=%s"
        testMail1ExampleCom      = "mail1.example.com"
        testMailExampleCom       = "mail.example.com"

        mapKeyEnforce      = "enforce"
        mapKeyMatchingType = "matching_type"
        mapKeyMtaSts       = "mta_sts"
        mapKeyMxHost       = "mx_host"
        mapKeyTlsrpt       = "tlsrpt"
        mapKeyUsage        = "usage"
        mapKeyWarning      = "warning"
        strAdequate        = "Adequate"
        strEd25519         = "ed25519"
        protocolDKIM       = "dkim"
        protocolBIMI       = "bimi"
        protocolDANE       = "dane"
        expectedTrue       = "true"
)

func dkimAnalysisCases() []TestCase {
        rsa2048Record := testDKIMPrefix + strings.Repeat("A", 266)
        rsa1024Record := testDKIMPrefix + strings.Repeat("A", 134)

        return []TestCase{
                {
                        CaseID:     "dkim-analysis-001",
                        CaseName:   "2048-bit RSA key classified as adequate",
                        Protocol:   protocolDKIM,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDKIM8301,
                        Expected:   "adequate",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportAnalyzeDKIMKey(rsa2048Record)
                                strength, _ := result["key_strength"].(string)
                                return strength, strength == "adequate"
                        },
                },
                {
                        CaseID:     "dkim-analysis-002",
                        CaseName:   "1024-bit RSA key classified as weak",
                        Protocol:   protocolDKIM,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDKIM8301,
                        Expected:   "weak",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportAnalyzeDKIMKey(rsa1024Record)
                                strength, _ := result["key_strength"].(string)
                                return strength, strength == "weak"
                        },
                },
                {
                        CaseID:     "dkim-analysis-003",
                        CaseName:   "Revoked key detected (p= empty)",
                        Protocol:   protocolDKIM,
                        Layer:      LayerAnalysis,
                        RFCSection: citRFC6376S361,
                        Expected:   expectedTrue,
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportAnalyzeDKIMKey(testDKIMPrefix)
                                revoked, _ := result["revoked"].(bool)
                                return fmt.Sprintf("%v", revoked), revoked == true
                        },
                },
                {
                        CaseID:     "dkim-analysis-004",
                        CaseName:   "Test mode detected (t=y flag)",
                        Protocol:   protocolDKIM,
                        Layer:      LayerAnalysis,
                        RFCSection: citRFC6376S361,
                        Expected:   expectedTrue,
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportAnalyzeDKIMKey("v=DKIM1; k=rsa; t=y; p=" + strings.Repeat("A", 266))
                                testMode, _ := result["test_mode"].(bool)
                                return fmt.Sprintf("%v", testMode), testMode == true
                        },
                },
                {
                        CaseID:     "dkim-analysis-005",
                        CaseName:   "Ed25519 key type parsed correctly",
                        Protocol:   protocolDKIM,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDKIM8463,
                        Expected:   strEd25519,
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportAnalyzeDKIMKey("v=DKIM1; k=ed25519; p=AAAA")
                                keyType, _ := result["key_type"].(string)
                                return keyType, keyType == strEd25519
                        },
                },
                {
                        CaseID:     "dkim-analysis-006",
                        CaseName:   "Selector provider classified for Google",
                        Protocol:   protocolDKIM,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDKIM6376,
                        Expected:   "Google Workspace",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportClassifySelectorProvider("google._domainkey", "Unknown")
                                return result, result == "Google Workspace"
                        },
                },
                {
                        CaseID:     "dkim-analysis-007",
                        CaseName:   "Selector provider classified for Microsoft 365",
                        Protocol:   protocolDKIM,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDKIM6376,
                        Expected:   testProviderMicrosoft365,
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportClassifySelectorProvider("selector1._domainkey", testProviderMicrosoft365)
                                return result, result == testProviderMicrosoft365
                        },
                },
        }
}

func caaAnalysisCases() []TestCase {
        return []TestCase{
                {
                        CaseID:     "caa-analysis-001",
                        CaseName:   "CAA issuer identified as Let's Encrypt",
                        Protocol:   "caa",
                        Layer:      LayerAnalysis,
                        RFCSection: citRFC8659S4,
                        Expected:   testProviderLetsEncrypt,
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportIdentifyCAIssuer(testCAAIssueLetsEncrypt)
                                return result, result == testProviderLetsEncrypt
                        },
                },
                {
                        CaseID:     "caa-analysis-002",
                        CaseName:   "CAA issuer identified as DigiCert",
                        Protocol:   "caa",
                        Layer:      LayerAnalysis,
                        RFCSection: citRFC8659S4,
                        Expected:   "DigiCert",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportIdentifyCAIssuer("0 issue \"digicert.com\"")
                                return result, result == "DigiCert"
                        },
                },
                {
                        CaseID:     "caa-analysis-003",
                        CaseName:   "CAA records parsed with issuewild detected",
                        Protocol:   "caa",
                        Layer:      LayerAnalysis,
                        RFCSection: citRFC8659S43,
                        Expected:   expectedTrue,
                        RunFn: func() (string, bool) {
                                _, _, hasWildcard, _ := analyzer.ExportParseCAARecords([]string{
                                        testCAAIssueLetsEncrypt,
                                        "0 issuewild \"digicert.com\"",
                                })
                                return fmt.Sprintf("%v", hasWildcard), hasWildcard == true
                        },
                },
                {
                        CaseID:     "caa-analysis-004",
                        CaseName:   "CAA iodef record detected",
                        Protocol:   "caa",
                        Layer:      LayerAnalysis,
                        RFCSection: citRFC8659S44,
                        Expected:   expectedTrue,
                        RunFn: func() (string, bool) {
                                _, _, _, hasIodef := analyzer.ExportParseCAARecords([]string{
                                        testCAAIssueLetsEncrypt,
                                        "0 iodef \"mailto:security@example.com\"",
                                })
                                return fmt.Sprintf("%v", hasIodef), hasIodef == true
                        },
                },
                {
                        CaseID:     "caa-analysis-005",
                        CaseName:   "CAA message built correctly with issuers",
                        Protocol:   "caa",
                        Layer:      LayerAnalysis,
                        RFCSection: rfcCAA8659,
                        Expected:   "contains 'CAA configured'",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportBuildCAAMessage([]string{testProviderLetsEncrypt}, nil, false)
                                return result, strings.Contains(result, "CAA configured")
                        },
                },
        }
}

func mtaStsAnalysisCases() []TestCase {
        return []TestCase{
                {
                        CaseID:     "mta_sts-analysis-001",
                        CaseName:   "MTA-STS enforce mode returns success",
                        Protocol:   mapKeyMtaSts,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcMTASTSSection5,
                        Expected:   mapKeySuccess,
                        RunFn: func() (string, bool) {
                                policyData := map[string]any{"mx": []string{testMailExampleCom}}
                                status, _ := analyzer.ExportDetermineMTASTSModeStatus(mapKeyEnforce, policyData)
                                return status, status == mapKeySuccess
                        },
                },
                {
                        CaseID:     "mta_sts-analysis-002",
                        CaseName:   "MTA-STS testing mode returns warning",
                        Protocol:   mapKeyMtaSts,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcMTASTSSection5,
                        Expected:   mapKeyWarning,
                        RunFn: func() (string, bool) {
                                policyData := map[string]any{"mx": []string{testMailExampleCom}}
                                status, _ := analyzer.ExportDetermineMTASTSModeStatus("testing", policyData)
                                return status, status == mapKeyWarning
                        },
                },
                {
                        CaseID:     "mta_sts-analysis-003",
                        CaseName:   "MTA-STS policy parsing extracts mode and mx",
                        Protocol:   mapKeyMtaSts,
                        Layer:      LayerAnalysis,
                        RFCSection: citRFC8461S32,
                        Expected:   mapKeyEnforce,
                        RunFn: func() (string, bool) {
                                mode, _, mx, hasVersion := analyzer.ExportParseMTASTSPolicyLines("version: STSv1\nmode: enforce\nmax_age: 86400\nmx: mail.example.com\nmx: *.example.com")
                                ok := mode == mapKeyEnforce && len(mx) == 2 && hasVersion
                                actual := fmt.Sprintf("mode=%s mx=%d version=%v", mode, len(mx), hasVersion)
                                if !ok {
                                        return actual, false
                                }
                                return mode, true
                        },
                },
                {
                        CaseID:     "mta_sts-analysis-004",
                        CaseName:   "MTA-STS valid record filtered correctly",
                        Protocol:   mapKeyMtaSts,
                        Layer:      LayerAnalysis,
                        RFCSection: citRFC8461S31,
                        Expected:   "1",
                        RunFn: func() (string, bool) {
                                records := analyzer.ExportFilterSTSRecords([]string{"v=STSv1; id=20230101", "not-an-sts-record"})
                                actual := fmt.Sprintf("%d", len(records))
                                return actual, len(records) == 1
                        },
                },
                {
                        CaseID:     "mta_sts-analysis-005",
                        CaseName:   "MTA-STS ID extracted from record",
                        Protocol:   mapKeyMtaSts,
                        Layer:      LayerAnalysis,
                        RFCSection: citRFC8461S31,
                        Expected:   "20230101",
                        RunFn: func() (string, bool) {
                                id := analyzer.ExportExtractSTSID("v=STSv1; id=20230101")
                                if id == nil {
                                        return "nil", false
                                }
                                return *id, *id == "20230101"
                        },
                },
        }
}

func tlsrptAnalysisCases() []TestCase {
        return []TestCase{
                {
                        CaseID:     "tlsrpt-analysis-001",
                        CaseName:   "DKIM key classification: 2048-bit RSA adequate per crypto policy",
                        Protocol:   mapKeyTlsrpt,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDKIM8301,
                        Expected:   strAdequate,
                        RunFn: func() (string, bool) {
                                c := analyzer.ClassifyDKIMKey("rsa", 2048)
                                return c.Label, c.Label == strAdequate
                        },
                },
                {
                        CaseID:     "tlsrpt-analysis-002",
                        CaseName:   "DKIM key classification: Ed25519 strong per crypto policy",
                        Protocol:   mapKeyTlsrpt,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDKIM8301,
                        Expected:   "Strong",
                        RunFn: func() (string, bool) {
                                c := analyzer.ClassifyDKIMKey(strEd25519, 256)
                                return c.Label, c.Label == "Strong"
                        },
                },
                {
                        CaseID:     "tlsrpt-analysis-003",
                        CaseName:   "DS digest type 2 (SHA-256) classified as adequate",
                        Protocol:   mapKeyTlsrpt,
                        Layer:      LayerAnalysis,
                        RFCSection: citRFC8624S33,
                        Expected:   strAdequate,
                        RunFn: func() (string, bool) {
                                c := analyzer.ClassifyDSDigest(2)
                                return c.Label, c.Label == strAdequate
                        },
                },
        }
}

func bimiAnalysisCases() []TestCase {
        return []TestCase{
                {
                        CaseID:     "bimi-analysis-001",
                        CaseName:   "BIMI record filtered correctly (v=BIMI1)",
                        Protocol:   protocolBIMI,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcBIMISection3,
                        Expected:   "1",
                        RunFn: func() (string, bool) {
                                records := analyzer.ExportFilterBIMIRecords([]string{testBIMIRecord, "not-bimi"})
                                actual := fmt.Sprintf("%d", len(records))
                                return actual, len(records) == 1
                        },
                },
                {
                        CaseID:     "bimi-analysis-002",
                        CaseName:   "BIMI logo URL extracted from record",
                        Protocol:   protocolBIMI,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcBIMISection3,
                        Expected:   "https://example.com/logo.svg",
                        RunFn: func() (string, bool) {
                                logo, _ := analyzer.ExportExtractBIMIURLs("v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem")
                                if logo == nil {
                                        return "nil", false
                                }
                                return *logo, *logo == "https://example.com/logo.svg"
                        },
                },
                {
                        CaseID:     "bimi-analysis-003",
                        CaseName:   "BIMI VMC URL extracted from record",
                        Protocol:   protocolBIMI,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcBIMISection3,
                        Expected:   "https://example.com/vmc.pem",
                        RunFn: func() (string, bool) {
                                _, vmc := analyzer.ExportExtractBIMIURLs("v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem")
                                if vmc == nil {
                                        return "nil", false
                                }
                                return *vmc, *vmc == "https://example.com/vmc.pem"
                        },
                },
                {
                        CaseID:     "bimi-analysis-004",
                        CaseName:   "BIMI record without VMC returns nil authority URL",
                        Protocol:   protocolBIMI,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcBIMISection3,
                        Expected:   "nil",
                        RunFn: func() (string, bool) {
                                _, vmc := analyzer.ExportExtractBIMIURLs(testBIMIRecord)
                                return fmt.Sprintf("%v", vmc), vmc == nil
                        },
                },
        }
}

func regressionCases() []TestCase {
        return []TestCase{
                {
                        CaseID:     "provider-regression-001",
                        CaseName:   "Stub isHostedEmailProvider returns true (conservative default prevents DANE recs for hosted providers)",
                        Protocol:   protocolDANE,
                        Layer:      LayerAnalysis,
                        RFCSection: citRFC7672S13,
                        Expected:   expectedTrue,
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportIsHostedEmailProvider("example.com")
                                return fmt.Sprintf("%v", result), result == true
                        },
                },
                {
                        CaseID:     "provider-regression-002",
                        CaseName:   "Stub isBIMICapableProvider returns false (conservative default prevents false BIMI capability claims)",
                        Protocol:   protocolBIMI,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcBIMISection3,
                        Expected:   "false",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportIsBIMICapableProvider("example.com")
                                return fmt.Sprintf("%v", result), result == false
                        },
                },
                {
                        CaseID:     "brand-regression-001",
                        CaseName:   "Brand verdict: quarantine + BIMI + CAA = Unlikely / Well Protected",
                        Protocol:   mapKeyDmarc,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDMARCSection63,
                        Expected:   "answer=Unlikely, label=Well Protected",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportBuildBrandVerdict(false, "quarantine", true, true)
                                answer, _ := result[mapKeyAnswer].(string)
                                label, _ := result[mapKeyLabel].(string)
                                actual := fmt.Sprintf(fmtAnswerLabel, answer, label)
                                return actual, answer == "Unlikely" && label == "Well Protected"
                        },
                },
                {
                        CaseID:     "brand-regression-002",
                        CaseName:   "Brand verdict: reject + BIMI + CAA = No / Protected",
                        Protocol:   mapKeyDmarc,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDMARCSection63,
                        Expected:   "answer=No, label=Protected",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportBuildBrandVerdict(false, "reject", true, true)
                                answer, _ := result[mapKeyAnswer].(string)
                                label, _ := result[mapKeyLabel].(string)
                                actual := fmt.Sprintf(fmtAnswerLabel, answer, label)
                                return actual, answer == "No" && label == "Protected"
                        },
                },
                {
                        CaseID:     "brand-regression-003",
                        CaseName:   "Brand verdict: reject + no BIMI + no CAA = Possible / Partially Protected",
                        Protocol:   mapKeyDmarc,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDMARCSection63,
                        Expected:   "answer=Possible, label=Partially Protected",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportBuildBrandVerdict(false, "reject", false, false)
                                answer, _ := result[mapKeyAnswer].(string)
                                label, _ := result[mapKeyLabel].(string)
                                actual := fmt.Sprintf(fmtAnswerLabel, answer, label)
                                return actual, answer == "Possible" && label == "Partially Protected"
                        },
                },
                {
                        CaseID:     "brand-regression-004",
                        CaseName:   "Brand verdict: missing DMARC = Yes / Exposed",
                        Protocol:   mapKeyDmarc,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDMARCSection63,
                        Expected:   "answer=Yes, label=Exposed",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportBuildBrandVerdict(true, "", false, false)
                                answer, _ := result[mapKeyAnswer].(string)
                                label, _ := result[mapKeyLabel].(string)
                                actual := fmt.Sprintf(fmtAnswerLabel, answer, label)
                                return actual, answer == "Yes" && label == "Exposed"
                        },
                },
                {
                        CaseID:     "mta_sts-regression-001",
                        CaseName:   "MTA-STS enforce mode returns success status",
                        Protocol:   mapKeyMtaSts,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcMTASTSSection5,
                        Expected:   mapKeySuccess,
                        RunFn: func() (string, bool) {
                                policyData := map[string]any{"mx": []string{testMailExampleCom}}
                                status, _ := analyzer.ExportDetermineMTASTSModeStatus(mapKeyEnforce, policyData)
                                return status, status == mapKeySuccess
                        },
                },
                {
                        CaseID:     "mta_sts-regression-002",
                        CaseName:   "MTA-STS testing mode returns warning status",
                        Protocol:   mapKeyMtaSts,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcMTASTSSection5,
                        Expected:   mapKeyWarning,
                        RunFn: func() (string, bool) {
                                policyData := map[string]any{"mx": []string{testMailExampleCom}}
                                status, _ := analyzer.ExportDetermineMTASTSModeStatus("testing", policyData)
                                return status, status == mapKeyWarning
                        },
                },
                {
                        CaseID:     "mta_sts-regression-003",
                        CaseName:   "MTA-STS none mode returns warning status (disabled policy)",
                        Protocol:   mapKeyMtaSts,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcMTASTSSection5,
                        Expected:   mapKeyWarning,
                        RunFn: func() (string, bool) {
                                policyData := map[string]any{"mx": []string{}}
                                status, _ := analyzer.ExportDetermineMTASTSModeStatus("none", policyData)
                                return status, status == mapKeyWarning
                        },
                },
                {
                        CaseID:     "bimi-regression-001",
                        CaseName:   "Only valid BIMI records (v=BIMI1) are filtered in",
                        Protocol:   protocolBIMI,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcBIMISection3,
                        Expected:   "1 valid record",
                        RunFn: func() (string, bool) {
                                records := analyzer.ExportFilterBIMIRecords([]string{
                                        testBIMIRecord,
                                        "v=spf1 include:x ~all",
                                        "random-txt-record",
                                })
                                actual := fmt.Sprintf("%d valid record", len(records))
                                return actual, len(records) == 1
                        },
                },
                {
                        CaseID:     "bimi-regression-002",
                        CaseName:   "Empty BIMI input returns zero records",
                        Protocol:   protocolBIMI,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcBIMISection3,
                        Expected:   "0",
                        RunFn: func() (string, bool) {
                                records := analyzer.ExportFilterBIMIRecords([]string{})
                                actual := fmt.Sprintf("%d", len(records))
                                return actual, len(records) == 0
                        },
                },
                {
                        CaseID:     "dane-regression-001",
                        CaseName:   "DANE verdict with valid TLSA covering all MX = success",
                        Protocol:   protocolDANE,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDANE7672,
                        Expected:   mapKeySuccess,
                        RunFn: func() (string, bool) {
                                tlsa := []map[string]any{
                                        {mapKeyMxHost: testMailExampleCom, mapKeyUsage: 3, mapKeyMatchingType: 1},
                                }
                                status, _, _ := analyzer.ExportBuildDANEVerdict(tlsa, []string{testMailExampleCom}, []string{testMailExampleCom}, nil)
                                return status, status == mapKeySuccess
                        },
                },
                {
                        CaseID:     "dane-regression-002",
                        CaseName:   "DANE verdict with partial MX coverage = partial",
                        Protocol:   protocolDANE,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDANE7672,
                        Expected:   mapKeyWarning,
                        RunFn: func() (string, bool) {
                                tlsa := []map[string]any{
                                        {mapKeyMxHost: testMail1ExampleCom, mapKeyUsage: 3, mapKeyMatchingType: 1},
                                }
                                status, _, _ := analyzer.ExportBuildDANEVerdict(tlsa, []string{testMail1ExampleCom}, []string{testMail1ExampleCom, "mail2.example.com"}, nil)
                                return status, status == mapKeyWarning
                        },
                },
        }
}

func daneAnalysisCases() []TestCase {
        return []TestCase{
                {
                        CaseID:     "dane-analysis-001",
                        CaseName:   "TLSA entry parsed with usage 3 (DANE-EE)",
                        Protocol:   protocolDANE,
                        Layer:      LayerAnalysis,
                        RFCSection: citRFC7672S31,
                        Expected:   "DANE-EE (Domain-issued certificate)",
                        RunFn: func() (string, bool) {
                                rec, ok := analyzer.ExportParseTLSAEntry("3 1 1 AABBCCDD", testMailExampleCom, "_25._tcp.mail.example.com")
                                if !ok {
                                        return "parse failed", false
                                }
                                usageName, _ := rec["usage_name"].(string)
                                return usageName, usageName == "DANE-EE (Domain-issued certificate)"
                        },
                },
                {
                        CaseID:     "dane-analysis-002",
                        CaseName:   "TLSA usage 0 triggers RFC 7672 recommendation",
                        Protocol:   protocolDANE,
                        Layer:      LayerAnalysis,
                        RFCSection: citRFC7672S31,
                        Expected:   "contains recommendation",
                        RunFn: func() (string, bool) {
                                rec, ok := analyzer.ExportParseTLSAEntry("0 1 1 AABBCCDD", testMailExampleCom, "_25._tcp.mail.example.com")
                                if !ok {
                                        return "parse failed", false
                                }
                                recommendation, _ := rec["recommendation"].(string)
                                return recommendation, strings.Contains(recommendation, rfcDANE7672)
                        },
                },
                {
                        CaseID:     "dane-analysis-003",
                        CaseName:   "MX hosts extracted correctly from records",
                        Protocol:   protocolDANE,
                        Layer:      LayerAnalysis,
                        RFCSection: citRFC5321S5,
                        Expected:   "2",
                        RunFn: func() (string, bool) {
                                hosts := analyzer.ExportExtractMXHosts([]string{"10 mail1.example.com.", "20 mail2.example.com."})
                                actual := fmt.Sprintf("%d", len(hosts))
                                return actual, len(hosts) == 2
                        },
                },
                {
                        CaseID:     "dane-analysis-004",
                        CaseName:   "DANE verdict with all MX covered = success",
                        Protocol:   protocolDANE,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDANE7672,
                        Expected:   mapKeySuccess,
                        RunFn: func() (string, bool) {
                                tlsa := []map[string]any{
                                        {mapKeyMxHost: testMailExampleCom, mapKeyUsage: 3, mapKeyMatchingType: 1},
                                }
                                status, _, _ := analyzer.ExportBuildDANEVerdict(tlsa, []string{testMailExampleCom}, []string{testMailExampleCom}, nil)
                                return status, status == mapKeySuccess
                        },
                },
                {
                        CaseID:     "dane-analysis-005",
                        CaseName:   "DANE verdict with no TLSA records = info",
                        Protocol:   protocolDANE,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDANE7672,
                        Expected:   "info",
                        RunFn: func() (string, bool) {
                                status, _, _ := analyzer.ExportBuildDANEVerdict(nil, nil, []string{testMailExampleCom}, nil)
                                return status, status == "info"
                        },
                },
        }
}
