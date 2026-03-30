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
        testNS1Cloudflare   = "ns1.cloudflare.com"
        testNS2Cloudflare   = "ns2.cloudflare.com"
        testDomainExample   = "example.com"
        testDomainExampleAU = "example.com.au"
        testDomainApple     = "apple.com"
        testSPFIncludeXSoft = "v=spf1 include:x ~all"
        testSPFSoftAll      = "v=spf1 ~all"

        mapKeyAnswer            = "answer"
        mapKeyColor             = "color"
        mapKeyDanger            = "danger"
        mapKeyDedicated         = "dedicated"
        mapKeyDmarc             = "dmarc"
        mapKeyDnssec            = "dnssec"
        mapKeyEnterprisePattern = "enterprise_pattern"
        mapKeyError             = "error"
        mapKeyLabel             = "label"
        mapKeyManaged           = "managed"
        mapKeyReject            = "reject"
        mapKeySuccess           = "success"
        strNil                  = "nil"
        strDangerous            = "DANGEROUS"
        strStrict               = "STRICT"
        strSoft                 = "SOFT"
        protoSPF                = "spf"
)

func AnalysisTestCases() []TestCase {
        var cases []TestCase
        cases = append(cases, spfAnalysisCases()...)
        cases = append(cases, dmarcAnalysisCases()...)
        cases = append(cases, spfVerdictCases()...)
        cases = append(cases, emailAnswerCases()...)
        cases = append(cases, dnssecVerdictCases()...)
        cases = append(cases, enterpriseDNSCases()...)
        cases = append(cases, dkimAnalysisCases()...)
        cases = append(cases, caaAnalysisCases()...)
        cases = append(cases, mtaStsAnalysisCases()...)
        cases = append(cases, tlsrptAnalysisCases()...)
        cases = append(cases, bimiAnalysisCases()...)
        cases = append(cases, daneAnalysisCases()...)
        cases = append(cases, regressionCases()...)
        cases = append(cases, FixtureTestCases()...)
        return cases
}

func checkQualifier(spfRecord, expected string) func() (string, bool) {
        return func() (string, bool) {
                result := analyzer.ExportClassifyAllQualifier(spfRecord)
                if result == nil {
                        return strNil, false
                }
                return *result, *result == expected
        }
}

func spfAnalysisCases() []TestCase {
        return []TestCase{
                {
                        CaseID:     "spf-analysis-001",
                        CaseName:   "SPF ~all classified as SOFT (industry standard)",
                        Protocol:   protoSPF,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcSPFSection5,
                        Expected:   strSoft,
                        RunFn:      checkQualifier("v=spf1 include:_spf.google.com ~all", strSoft),
                },
                {
                        CaseID:     "spf-analysis-002",
                        CaseName:   "SPF -all classified as STRICT",
                        Protocol:   protoSPF,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcSPFSection5,
                        Expected:   strStrict,
                        RunFn:      checkQualifier("v=spf1 include:_spf.google.com -all", strStrict),
                },
                {
                        CaseID:     "spf-analysis-003",
                        CaseName:   "SPF +all classified as DANGEROUS",
                        Protocol:   protoSPF,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcSPFSection5,
                        Expected:   strDangerous,
                        RunFn:      checkQualifier("v=spf1 +all", strDangerous),
                },
                {
                        CaseID:     "spf-analysis-004",
                        CaseName:   "SPF ?all classified as NEUTRAL",
                        Protocol:   protoSPF,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcSPFSection5,
                        Expected:   "NEUTRAL",
                        RunFn:      checkQualifier("v=spf1 ?all", "NEUTRAL"),
                },
                {
                        CaseID:     "spf-analysis-005",
                        CaseName:   "SPF bare all (no qualifier) defaults to DANGEROUS (+all)",
                        Protocol:   protoSPF,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcSPFSection5,
                        Expected:   strDangerous,
                        RunFn:      checkQualifier("v=spf1 all", strDangerous),
                },
                {
                        CaseID:     "spf-analysis-006",
                        CaseName:   "SPF lookup count with includes",
                        Protocol:   protoSPF,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcSPFSection464,
                        Expected:   "3 lookups",
                        RunFn: func() (string, bool) {
                                count := analyzer.ExportCountSPFLookups("v=spf1 include:_spf.google.com include:spf.protection.outlook.com include:sendgrid.net ~all")
                                actual := fmt.Sprintf("%d lookups", count)
                                return actual, count == 3
                        },
                },
                {
                        CaseID:     "spf-analysis-007",
                        CaseName:   "SPF over 10 lookup limit detected as error",
                        Protocol:   protoSPF,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcSPFSection464,
                        Expected:   mapKeyError,
                        RunFn: func() (string, bool) {
                                status, _ := analyzer.ExportBuildSPFVerdict(11, strPtr(strSoft), false, []string{testSPFSoftAll}, nil)
                                return status, status == mapKeyError
                        },
                },
                {
                        CaseID:     "spf-analysis-008",
                        CaseName:   "SPF valid ~all with 3 lookups classified as success",
                        Protocol:   protoSPF,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcSPF,
                        Expected:   mapKeySuccess,
                        RunFn: func() (string, bool) {
                                status, _ := analyzer.ExportBuildSPFVerdict(3, strPtr(strSoft), false, []string{testSPFIncludeXSoft}, nil)
                                return status, status == mapKeySuccess
                        },
                },
                {
                        CaseID:     "spf-analysis-009",
                        CaseName:   "Multiple SPF records classified as error",
                        Protocol:   protoSPF,
                        Layer:      LayerAnalysis,
                        RFCSection: citRFC7208S32,
                        Expected:   mapKeyError,
                        RunFn: func() (string, bool) {
                                status, _ := analyzer.ExportBuildSPFVerdict(3, strPtr(strSoft), false, []string{testSPFSoftAll, "v=spf1 -all"}, nil)
                                return status, status == mapKeyError
                        },
                },
                {
                        CaseID:     "spf-analysis-010",
                        CaseName:   "No SPF record classified as missing",
                        Protocol:   protoSPF,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcSPF,
                        Expected:   "missing",
                        RunFn: func() (string, bool) {
                                status, _ := analyzer.ExportBuildSPFVerdict(0, nil, false, nil, nil)
                                return status, status == "missing"
                        },
                },
                {
                        CaseID:     "spf-analysis-011",
                        CaseName:   "SPF no-mail intent (v=spf1 -all) classified as success",
                        Protocol:   protoSPF,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcSPF,
                        Expected:   mapKeySuccess,
                        RunFn: func() (string, bool) {
                                status, _ := analyzer.ExportBuildSPFVerdict(0, strPtr(strStrict), true, []string{"v=spf1 -all"}, nil)
                                return status, status == mapKeySuccess
                        },
                },
                {
                        CaseID:     "spf-analysis-012",
                        CaseName:   "SPF -all with senders triggers RFC 7489 warning",
                        Protocol:   protoSPF,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDMARC,
                        Expected:   "contains RFC 7489 warning",
                        RunFn: func() (string, bool) {
                                _, _, _, _, _, issues, _ := analyzer.ExportParseSPFMechanisms("v=spf1 include:_spf.google.com -all")
                                for _, issue := range issues {
                                        if strings.Contains(issue, rfcDMARC) {
                                                return "RFC 7489 warning present", true
                                        }
                                }
                                return fmt.Sprintf("no RFC 7489 warning in %v", issues), false
                        },
                },
                {
                        CaseID:     "spf-analysis-013",
                        CaseName:   "SPF ~all does NOT trigger RFC 7489 premature rejection warning",
                        Protocol:   protoSPF,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDMARC,
                        Expected:   "no RFC 7489 warning",
                        RunFn: func() (string, bool) {
                                _, _, _, _, _, issues, _ := analyzer.ExportParseSPFMechanisms("v=spf1 include:_spf.google.com ~all")
                                for _, issue := range issues {
                                        if strings.Contains(issue, rfcDMARC) {
                                                return "false positive: RFC 7489 warning on ~all", false
                                        }
                                }
                                return "no RFC 7489 warning", true
                        },
                },
                {
                        CaseID:     "spf-analysis-014",
                        CaseName:   "SPF record classification separates valid from spf-like",
                        Protocol:   protoSPF,
                        Layer:      LayerAnalysis,
                        RFCSection: citRFC7208S3,
                        Expected:   "1 valid, 1 spf-like",
                        RunFn: func() (string, bool) {
                                valid, spfLike := analyzer.ExportClassifySPFRecords([]string{testSPFIncludeXSoft, "spf2.0/mfrom include:y ~all"})
                                actual := fmt.Sprintf("%d valid, %d spf-like", len(valid), len(spfLike))
                                return actual, len(valid) == 1 && len(spfLike) == 1
                        },
                },
        }
}

func dmarcAnalysisCases() []TestCase {
        return []TestCase{
                {
                        CaseID:     "dmarc-analysis-001",
                        CaseName:   "DMARC reject + SPF + DKIM = not spoofable",
                        Protocol:   mapKeyDmarc,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDMARCSection63,
                        Expected:   "No — SPF and DMARC reject policy enforced",
                        RunFn: func() (string, bool) {
                                answer := analyzer.ExportBuildEmailAnswer(false, mapKeyReject, 100, false, true, true)
                                return answer, answer == "No — SPF and DMARC reject policy enforced"
                        },
                },
                {
                        CaseID:     "dmarc-analysis-002",
                        CaseName:   "DMARC p=none is monitor-only (spoofable)",
                        Protocol:   mapKeyDmarc,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDMARCSection63,
                        Expected:   "Yes — DMARC is monitor-only (p=none)",
                        RunFn: func() (string, bool) {
                                answer := analyzer.ExportBuildEmailAnswer(false, "none", 0, false, true, true)
                                return answer, answer == "Yes — DMARC is monitor-only (p=none)"
                        },
                },
                {
                        CaseID:     "dmarc-analysis-003",
                        CaseName:   "No SPF + no DMARC = fully spoofable",
                        Protocol:   mapKeyDmarc,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDMARC,
                        Expected:   "Yes — no SPF or DMARC protection",
                        RunFn: func() (string, bool) {
                                answer := analyzer.ExportBuildEmailAnswer(false, "", 0, false, false, false)
                                return answer, answer == "Yes — no SPF or DMARC protection"
                        },
                },
                {
                        CaseID:     "dmarc-analysis-004",
                        CaseName:   "DMARC quarantine at 100% = unlikely spoofable",
                        Protocol:   mapKeyDmarc,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDMARCSection63,
                        Expected:   "Unlikely — SPF and DMARC quarantine policy enforced",
                        RunFn: func() (string, bool) {
                                answer := analyzer.ExportBuildEmailAnswer(false, "quarantine", 100, false, true, true)
                                return answer, answer == "Unlikely — SPF and DMARC quarantine policy enforced"
                        },
                },
                {
                        CaseID:     "dmarc-analysis-005",
                        CaseName:   "DMARC quarantine at partial pct = partially protected",
                        Protocol:   mapKeyDmarc,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDMARCSection63,
                        Expected:   "Partially — DMARC quarantine at limited percentage",
                        RunFn: func() (string, bool) {
                                answer := analyzer.ExportBuildEmailAnswer(false, "quarantine", 50, false, true, true)
                                return answer, answer == "Partially — DMARC quarantine at limited percentage"
                        },
                },
                {
                        CaseID:     "dmarc-analysis-006",
                        CaseName:   "SPF only (no DMARC) = likely spoofable",
                        Protocol:   mapKeyDmarc,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDMARC,
                        Expected:   "Likely — SPF alone cannot prevent spoofing",
                        RunFn: func() (string, bool) {
                                answer := analyzer.ExportBuildEmailAnswer(false, "", 0, false, true, false)
                                return answer, answer == "Likely — SPF alone cannot prevent spoofing"
                        },
                },
                {
                        CaseID:     "dmarc-analysis-007",
                        CaseName:   "Null MX (no-mail domain) = not spoofable",
                        Protocol:   mapKeyDmarc,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcNullMX7505,
                        Expected:   "No — null MX indicates no-mail domain",
                        RunFn: func() (string, bool) {
                                answer := analyzer.ExportBuildEmailAnswer(false, "", 0, true, false, false)
                                return answer, answer == "No — null MX indicates no-mail domain"
                        },
                },
                {
                        CaseID:     "dmarc-analysis-008",
                        CaseName:   "DMARC present but no SPF = partial protection",
                        Protocol:   mapKeyDmarc,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDMARC,
                        Expected:   "Partially — DMARC present but no SPF",
                        RunFn: func() (string, bool) {
                                answer := analyzer.ExportBuildEmailAnswer(false, mapKeyReject, 100, false, false, true)
                                return answer, answer == "Partially — DMARC present but no SPF"
                        },
                },
        }
}

func spfVerdictCases() []TestCase {
        return []TestCase{
                {
                        CaseID:     "spf-verdict-001",
                        CaseName:   "~all verdict message contains 'industry-standard'",
                        Protocol:   protoSPF,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcSPF,
                        Expected:   "contains 'industry-standard'",
                        RunFn: func() (string, bool) {
                                _, msg := analyzer.ExportBuildSPFVerdict(3, strPtr(strSoft), false, []string{testSPFIncludeXSoft}, nil)
                                return msg, strings.Contains(msg, "industry-standard")
                        },
                },
                {
                        CaseID:     "spf-verdict-002",
                        CaseName:   "+all verdict message warns 'anyone can send'",
                        Protocol:   protoSPF,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcSPFSection5,
                        Expected:   "contains 'anyone can send'",
                        RunFn: func() (string, bool) {
                                _, msg := analyzer.ExportBuildSPFVerdict(1, strPtr(strDangerous), false, []string{"v=spf1 +all"}, nil)
                                return msg, strings.Contains(msg, "anyone can send")
                        },
                },
                {
                        CaseID:     "spf-verdict-003",
                        CaseName:   "SPF over 10 lookups verdict cites RFC 7208 §4.6.4",
                        Protocol:   protoSPF,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcSPFSection464,
                        Expected:   "contains 'RFC 7208'",
                        RunFn: func() (string, bool) {
                                _, msg := analyzer.ExportBuildSPFVerdict(11, strPtr(strSoft), false, []string{testSPFSoftAll}, nil)
                                return msg, strings.Contains(msg, rfcSPF)
                        },
                },
        }
}

func emailAnswerCases() []TestCase {
        return []TestCase{
                {
                        CaseID:     "email-answer-001",
                        CaseName:   "Structured email answer for reject = green/success",
                        Protocol:   mapKeyDmarc,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDMARCSection63,
                        Expected:   mapKeySuccess,
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportBuildEmailAnswerStructured(false, mapKeyReject, 100, false, true, true)
                                color := result[mapKeyColor]
                                return color, color == mapKeySuccess
                        },
                },
                {
                        CaseID:     "email-answer-002",
                        CaseName:   "Structured email answer for p=none = red/danger",
                        Protocol:   mapKeyDmarc,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDMARCSection63,
                        Expected:   mapKeyDanger,
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportBuildEmailAnswerStructured(false, "none", 0, false, true, true)
                                color := result[mapKeyColor]
                                return color, color == mapKeyDanger
                        },
                },
                {
                        CaseID:     "email-answer-003",
                        CaseName:   "Structured email answer for no protection = red/danger",
                        Protocol:   mapKeyDmarc,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDMARC,
                        Expected:   mapKeyDanger,
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportBuildEmailAnswerStructured(false, "", 0, false, false, false)
                                color := result[mapKeyColor]
                                return color, color == mapKeyDanger
                        },
                },
        }
}

func dnssecVerdictCases() []TestCase {
        return []TestCase{
                {
                        CaseID:     "dnssec-verdict-001",
                        CaseName:   "DNSSEC signed = No tampering possible",
                        Protocol:   mapKeyDnssec,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDNSSECSection2,
                        Expected:   "No",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportBuildDNSVerdict(true, false)
                                answer := result[mapKeyAnswer].(string)
                                return answer, answer == "No"
                        },
                },
                {
                        CaseID:     "dnssec-verdict-002",
                        CaseName:   "DNSSEC signed verdict is Protected",
                        Protocol:   mapKeyDnssec,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDNSSECSection2,
                        Expected:   "Protected",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportBuildDNSVerdict(true, false)
                                label := result[mapKeyLabel].(string)
                                return label, label == "Protected"
                        },
                },
                {
                        CaseID:     "dnssec-verdict-003",
                        CaseName:   "DNSSEC broken = tampering possible (Yes)",
                        Protocol:   mapKeyDnssec,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDNSSEC,
                        Expected:   "Yes",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportBuildDNSVerdict(false, true)
                                answer := result[mapKeyAnswer].(string)
                                return answer, answer == "Yes"
                        },
                },
                {
                        CaseID:     "dnssec-verdict-004",
                        CaseName:   "DNSSEC broken label is Exposed",
                        Protocol:   mapKeyDnssec,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDNSSEC,
                        Expected:   "Exposed",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportBuildDNSVerdict(false, true)
                                label := result[mapKeyLabel].(string)
                                return label, label == "Exposed"
                        },
                },
                {
                        CaseID:     "dnssec-verdict-005",
                        CaseName:   "DNSSEC absent = Possible tampering",
                        Protocol:   mapKeyDnssec,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDNSSEC,
                        Expected:   "Possible",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportBuildDNSVerdict(false, false)
                                answer := result[mapKeyAnswer].(string)
                                return answer, answer == "Possible"
                        },
                },
                {
                        CaseID:     "dnssec-verdict-006",
                        CaseName:   "DNSSEC absent label is Not Configured",
                        Protocol:   mapKeyDnssec,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDNSSEC,
                        Expected:   "Not Configured",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportBuildDNSVerdict(false, false)
                                label := result[mapKeyLabel].(string)
                                return label, label == "Not Configured"
                        },
                },
                {
                        CaseID:     "dnssec-verdict-007",
                        CaseName:   "DNSSEC signed reason mentions cryptographic",
                        Protocol:   mapKeyDnssec,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDNSSECSection2,
                        Expected:   "contains 'cryptographic'",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportBuildDNSVerdict(true, false)
                                reason := result["reason"].(string)
                                return reason, strings.Contains(reason, "cryptographic")
                        },
                },
        }
}

func enterpriseDNSCases() []TestCase {
        return []TestCase{
                {
                        CaseID:     "enterprise-dns-001",
                        CaseName:   "All org-branded NS = dedicated infrastructure",
                        Protocol:   mapKeyDnssec,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDNSSection22,
                        Expected:   mapKeyDedicated,
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportClassifyEnterpriseDNS(testDomainApple, []string{
                                        "a.ns.apple.com", "b.ns.apple.com", "c.ns.apple.com", "d.ns.apple.com",
                                })
                                pattern, _ := result[mapKeyEnterprisePattern].(string)
                                return pattern, pattern == mapKeyDedicated
                        },
                },
                {
                        CaseID:     "enterprise-dns-002",
                        CaseName:   "Mixed org-branded + provider NS = mixed configuration",
                        Protocol:   mapKeyDnssec,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDNSSection22,
                        Expected:   "mixed",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportClassifyEnterpriseDNS(testDomainExample, []string{
                                        "ns1.example.com", "ns2.example.com", testNS1Cloudflare,
                                })
                                pattern, _ := result[mapKeyEnterprisePattern].(string)
                                return pattern, pattern == "mixed"
                        },
                },
                {
                        CaseID:     "enterprise-dns-003",
                        CaseName:   "Multiple providers = multi-provider redundancy",
                        Protocol:   mapKeyDnssec,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDNSSection22,
                        Expected:   "multi-provider",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportClassifyEnterpriseDNS(testDomainExample, []string{
                                        testNS1Cloudflare, testNS2Cloudflare,
                                        "pdns1.ultradns.net", "pdns2.ultradns.net",
                                })
                                pattern, _ := result[mapKeyEnterprisePattern].(string)
                                return pattern, pattern == "multi-provider"
                        },
                },
                {
                        CaseID:     "enterprise-dns-004",
                        CaseName:   "Single provider = managed DNS",
                        Protocol:   mapKeyDnssec,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDNSSection22,
                        Expected:   mapKeyManaged,
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportClassifyEnterpriseDNS(testDomainExample, []string{
                                        testNS1Cloudflare, testNS2Cloudflare,
                                })
                                pattern, _ := result[mapKeyEnterprisePattern].(string)
                                return pattern, pattern == mapKeyManaged
                        },
                },
                {
                        CaseID:     "enterprise-dns-005",
                        CaseName:   "Empty nameservers returns nil (no classification)",
                        Protocol:   mapKeyDnssec,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDNS,
                        Expected:   strNil,
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportClassifyEnterpriseDNS(testDomainExample, []string{})
                                return strNil, result == nil
                        },
                },
                {
                        CaseID:     "enterprise-dns-006",
                        CaseName:   "Dedicated label includes org domain name",
                        Protocol:   mapKeyDnssec,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDNSSection22,
                        Expected:   "contains 'apple.com'",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportClassifyEnterpriseDNS(testDomainApple, []string{
                                        "a.ns.apple.com", "b.ns.apple.com",
                                })
                                detail, _ := result["enterprise_detail"].(string)
                                return detail, strings.Contains(detail, testDomainApple)
                        },
                },
                {
                        CaseID:     "enterprise-dns-007",
                        CaseName:   "Akamai akam.net nameservers detected as managed provider",
                        Protocol:   mapKeyDnssec,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDNS,
                        Expected:   mapKeyManaged,
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportClassifyEnterpriseDNS(testDomainExample, []string{
                                        "a1-1.akam.net", "a2-2.akam.net", "a3-3.akam.net",
                                })
                                pattern, _ := result[mapKeyEnterprisePattern].(string)
                                return pattern, pattern == mapKeyManaged
                        },
                },
                {
                        CaseID:     "enterprise-dns-008",
                        CaseName:   "Multi-label TLD handled correctly (co.uk)",
                        Protocol:   mapKeyDnssec,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDNSSection22,
                        Expected:   mapKeyDedicated,
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportClassifyEnterpriseDNS("bbc.co.uk", []string{
                                        "ns1.bbc.co.uk", "ns2.bbc.co.uk",
                                })
                                pattern, _ := result[mapKeyEnterprisePattern].(string)
                                return pattern, pattern == mapKeyDedicated
                        },
                },
                {
                        CaseID:     "enterprise-dns-009",
                        CaseName:   "registrableDomain extracts correct base for .com.au",
                        Protocol:   mapKeyDnssec,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDNS,
                        Expected:   testDomainExampleAU,
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportRegistrableDomain(testDomainExampleAU)
                                return result, result == testDomainExampleAU
                        },
                },
                {
                        CaseID:     "enterprise-dns-010",
                        CaseName:   "NS provider detection identifies Route 53",
                        Protocol:   mapKeyDnssec,
                        Layer:      LayerAnalysis,
                        RFCSection: rfcDNS,
                        Expected:   "contains 'Route 53'",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportClassifyNSProvider("ns-1234.awsdns-56.org")
                                return result, strings.Contains(result, "Route 53")
                        },
                },
        }
}

func strPtr(s string) *string { return &s }
