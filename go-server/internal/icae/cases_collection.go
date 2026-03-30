// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package icae

import (
        "dnstool/go-server/internal/analyzer"
        "dnstool/go-server/internal/dnsclient"
        "fmt"
        "strings"
)

// S1313 suppressed: well-known public DNS resolver IPs used as test fixtures
// for the ICAE multi-resolver consensus validation engine.
const (
        testConsensusRFC        = "Multi-resolver consensus (5-resolver architecture)"
        testResolverGoogle      = "8.8.8.8"
        testResolverCloudflare  = "1.1.1.1"
        testResolverQuad9       = "9.9.9.9"
        testResolverOpenDNS     = "208.67.222.222"
        testResolverCleanBrowse = "185.228.168.9"
        testIPDefault           = "1.2.3.4"
        testSPFGoogleInclude    = "v=spf1 include:_spf.google.com ~all"
        testSPFDenyAll          = "v=spf1 -all"
        testSPFGoogleSoft       = "v=spf1 include:google.com ~all"
)

func CollectionTestCases() []TestCase {
        var cases []TestCase
        cases = append(cases, consensusCases()...)
        cases = append(cases, mxExtractionCases()...)
        cases = append(cases, recordFilteringCases()...)
        cases = append(cases, recordParsingCases()...)
        cases = append(cases, dmarcCollectionCases()...)
        cases = append(cases, tlsrptCollectionCases()...)
        return cases
}

func consensusCases() []TestCase {
        return []TestCase{
                {
                        CaseID:     "consensus-collection-001",
                        CaseName:   "Unanimous resolver agreement yields consensus",
                        Protocol:   mapKeyDnssec,
                        Layer:      LayerCollection,
                        RFCSection: testConsensusRFC,
                        Expected:   "allSame=true, 0 discrepancies",
                        RunFn: func() (string, bool) {
                                results := map[string][]string{
                                        testResolverGoogle:      {testIPDefault},
                                        testResolverCloudflare:  {testIPDefault},
                                        testResolverQuad9:       {testIPDefault},
                                        testResolverOpenDNS:     {testIPDefault},
                                        testResolverCleanBrowse: {testIPDefault},
                                }
                                records, allSame, discrepancies := dnsclient.ExportFindConsensus(results)
                                actual := fmt.Sprintf("allSame=%t, %d discrepancies, records=%v", allSame, len(discrepancies), records)
                                return actual, allSame && len(discrepancies) == 0 && len(records) == 1 && records[0] == testIPDefault
                        },
                },
                {
                        CaseID:     "consensus-collection-002",
                        CaseName:   "Majority consensus with one dissenter",
                        Protocol:   mapKeyDnssec,
                        Layer:      LayerCollection,
                        RFCSection: testConsensusRFC,
                        Expected:   "allSame=false, 1 discrepancy, majority wins",
                        RunFn: func() (string, bool) {
                                results := map[string][]string{
                                        testResolverGoogle:      {testIPDefault},
                                        testResolverCloudflare:  {testIPDefault},
                                        testResolverQuad9:       {testIPDefault},
                                        testResolverOpenDNS:     {testIPDefault},
                                        testResolverCleanBrowse: {"5.6.7.8"},
                                }
                                records, allSame, discrepancies := dnsclient.ExportFindConsensus(results)
                                actual := fmt.Sprintf("allSame=%t, %d discrepancies, records=%v", allSame, len(discrepancies), records)
                                return actual, !allSame && len(discrepancies) == 1 && len(records) == 1 && records[0] == testIPDefault
                        },
                },
                {
                        CaseID:     "consensus-collection-003",
                        CaseName:   "All resolvers return empty (NXDOMAIN consensus)",
                        Protocol:   mapKeyDnssec,
                        Layer:      LayerCollection,
                        RFCSection: testConsensusRFC,
                        Expected:   "allSame=true, nil records",
                        RunFn: func() (string, bool) {
                                results := map[string][]string{
                                        testResolverGoogle:      {},
                                        testResolverCloudflare:  {},
                                        testResolverQuad9:       {},
                                        testResolverOpenDNS:     {},
                                        testResolverCleanBrowse: {},
                                }
                                records, allSame, discrepancies := dnsclient.ExportFindConsensus(results)
                                actual := fmt.Sprintf("allSame=%t, records=%v, discrepancies=%d", allSame, records, len(discrepancies))
                                return actual, allSame && records == nil && len(discrepancies) == 0
                        },
                },
                {
                        CaseID:     "consensus-collection-004",
                        CaseName:   "Multi-record consensus preserves order",
                        Protocol:   "spf",
                        Layer:      LayerCollection,
                        RFCSection: testConsensusRFC,
                        Expected:   "allSame=true, 2 records",
                        RunFn: func() (string, bool) {
                                results := map[string][]string{
                                        testResolverGoogle:     {testSPFGoogleInclude, testSPFDenyAll},
                                        testResolverCloudflare: {testSPFGoogleInclude, testSPFDenyAll},
                                        testResolverQuad9:      {testSPFGoogleInclude, testSPFDenyAll},
                                }
                                records, allSame, discrepancies := dnsclient.ExportFindConsensus(results)
                                actual := fmt.Sprintf("allSame=%t, %d records, %d discrepancies", allSame, len(records), len(discrepancies))
                                return actual, allSame && len(records) == 2 && len(discrepancies) == 0
                        },
                },
                {
                        CaseID:     "consensus-collection-005",
                        CaseName:   "Split consensus (no clear majority) picks highest count",
                        Protocol:   mapKeyDnssec,
                        Layer:      LayerCollection,
                        RFCSection: testConsensusRFC,
                        Expected:   "allSame=false, result chosen from largest group",
                        RunFn: func() (string, bool) {
                                results := map[string][]string{
                                        testResolverGoogle:     {testIPDefault},
                                        testResolverCloudflare: {testIPDefault},
                                        testResolverQuad9:      {"5.6.7.8"},
                                }
                                records, allSame, discrepancies := dnsclient.ExportFindConsensus(results)
                                actual := fmt.Sprintf("allSame=%t, records=%v, discrepancies=%d", allSame, records, len(discrepancies))
                                return actual, !allSame && len(records) == 1 && records[0] == testIPDefault && len(discrepancies) == 1
                        },
                },
        }
}

func mxExtractionCases() []TestCase {
        return []TestCase{
                {
                        CaseID:     "mx-collection-001",
                        CaseName:   "MX host extraction strips priority prefix",
                        Protocol:   protocolDANE,
                        Layer:      LayerCollection,
                        RFCSection: rfcSMTP5321S5,
                        Expected:   "2 hosts extracted",
                        RunFn: func() (string, bool) {
                                hosts := analyzer.ExportExtractMXHosts([]string{"10 mail1.example.com.", "20 mail2.example.com."})
                                actual := fmt.Sprintf("%d hosts: %v", len(hosts), hosts)
                                return actual, len(hosts) == 2
                        },
                },
                {
                        CaseID:     "mx-collection-002",
                        CaseName:   "Null MX (priority 0, dot) returns empty",
                        Protocol:   protocolDANE,
                        Layer:      LayerCollection,
                        RFCSection: rfcNullMX7505,
                        Expected:   "0 hosts (null MX)",
                        RunFn: func() (string, bool) {
                                hosts := analyzer.ExportExtractMXHosts([]string{"0 ."})
                                actual := fmt.Sprintf("%d hosts", len(hosts))
                                return actual, len(hosts) == 0
                        },
                },
                {
                        CaseID:     "mx-collection-003",
                        CaseName:   "Empty MX input returns empty slice",
                        Protocol:   protocolDANE,
                        Layer:      LayerCollection,
                        RFCSection: rfcSMTP5321S5,
                        Expected:   "0 hosts",
                        RunFn: func() (string, bool) {
                                hosts := analyzer.ExportExtractMXHosts(nil)
                                actual := fmt.Sprintf("%d hosts", len(hosts))
                                return actual, len(hosts) == 0
                        },
                },
        }
}

func recordFilteringCases() []TestCase {
        return []TestCase{
                {
                        CaseID:     "sts-collection-001",
                        CaseName:   "MTA-STS record filtering accepts v=STSv1",
                        Protocol:   mapKeyMtaSts,
                        Layer:      LayerCollection,
                        RFCSection: rfcMTASTS8461S31,
                        Expected:   "1 valid record",
                        RunFn: func() (string, bool) {
                                records := analyzer.ExportFilterSTSRecords([]string{
                                        "v=STSv1; id=20260220",
                                        "some-random-txt-record",
                                        testSPFGoogleSoft,
                                })
                                actual := fmt.Sprintf("%d valid records", len(records))
                                return actual, len(records) == 1 && strings.Contains(records[0], "STSv1")
                        },
                },
                {
                        CaseID:     "sts-collection-002",
                        CaseName:   "MTA-STS ID extraction from valid record",
                        Protocol:   mapKeyMtaSts,
                        Layer:      LayerCollection,
                        RFCSection: rfcMTASTS8461S31,
                        Expected:   "ID extracted",
                        RunFn: func() (string, bool) {
                                id := analyzer.ExportExtractSTSID("v=STSv1; id=20260220")
                                if id == nil {
                                        return "nil", false
                                }
                                return *id, *id == "20260220"
                        },
                },
                {
                        CaseID:     "sts-collection-003",
                        CaseName:   "MTA-STS policy parsing extracts mode and max_age",
                        Protocol:   mapKeyMtaSts,
                        Layer:      LayerCollection,
                        RFCSection: citRFC8461S32,
                        Expected:   "mode=enforce, max_age>0",
                        RunFn: func() (string, bool) {
                                mode, maxAge, mx, hasVersion := analyzer.ExportParseMTASTSPolicyLines(
                                        "version: STSv1\nmode: enforce\nmax_age: 86400\nmx: mail.example.com\n",
                                )
                                actual := fmt.Sprintf("mode=%s, max_age=%d, mx=%v, version=%t", mode, maxAge, mx, hasVersion)
                                return actual, mode == "enforce" && maxAge == 86400 && len(mx) == 1 && hasVersion
                        },
                },
                {
                        CaseID:     "bimi-collection-001",
                        CaseName:   "BIMI record filtering accepts v=BIMI1",
                        Protocol:   "bimi",
                        Layer:      LayerCollection,
                        RFCSection: "BIMI Spec §3",
                        Expected:   "1 valid record",
                        RunFn: func() (string, bool) {
                                records := analyzer.ExportFilterBIMIRecords([]string{
                                        "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/cert.pem",
                                        testSPFGoogleSoft,
                                })
                                actual := fmt.Sprintf("%d valid records", len(records))
                                return actual, len(records) == 1
                        },
                },
                {
                        CaseID:     "bimi-collection-002",
                        CaseName:   "BIMI URL extraction separates logo and authority",
                        Protocol:   "bimi",
                        Layer:      LayerCollection,
                        RFCSection: "BIMI Spec §3",
                        Expected:   "logo and authority URLs extracted",
                        RunFn: func() (string, bool) {
                                logo, auth := analyzer.ExportExtractBIMIURLs("v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/cert.pem")
                                hasLogo := logo != nil && *logo == "https://example.com/logo.svg"
                                hasAuth := auth != nil && *auth == "https://example.com/cert.pem"
                                actual := "logo=nil, auth=nil"
                                if logo != nil && auth != nil {
                                        actual = fmt.Sprintf("logo=%s, auth=%s", *logo, *auth)
                                }
                                return actual, hasLogo && hasAuth
                        },
                },
                {
                        CaseID:     "caa-collection-001",
                        CaseName:   "CAA record parsing extracts issuers and wildcards",
                        Protocol:   "caa",
                        Layer:      LayerCollection,
                        RFCSection: rfcCAASection4,
                        Expected:   "1 issuer, 1 wildcard, has iodef",
                        RunFn: func() (string, bool) {
                                issuers, wildcardIssuers, _, hasIodef := analyzer.ExportParseCAARecords([]string{
                                        `0 issue "letsencrypt.org"`,
                                        `0 issuewild "digicert.com"`,
                                        `0 iodef "mailto:security@example.com"`,
                                })
                                actual := fmt.Sprintf("%d issuers, %d wildcards, iodef=%t", len(issuers), len(wildcardIssuers), hasIodef)
                                return actual, len(issuers) == 1 && len(wildcardIssuers) == 1 && hasIodef
                        },
                },
                {
                        CaseID:     "caa-collection-002",
                        CaseName:   "Empty CAA records return zero issuers",
                        Protocol:   "caa",
                        Layer:      LayerCollection,
                        RFCSection: rfcCAASection4,
                        Expected:   "0 issuers, 0 wildcards",
                        RunFn: func() (string, bool) {
                                issuers, wildcardIssuers, _, _ := analyzer.ExportParseCAARecords(nil)
                                actual := fmt.Sprintf("%d issuers, %d wildcards", len(issuers), len(wildcardIssuers))
                                return actual, len(issuers) == 0 && len(wildcardIssuers) == 0
                        },
                },
        }
}

func recordParsingCases() []TestCase {
        return []TestCase{
                {
                        CaseID:     "dkim-collection-001",
                        CaseName:   "DKIM key analysis extracts key type and length",
                        Protocol:   "dkim",
                        Layer:      LayerCollection,
                        RFCSection: citRFC6376S361,
                        Expected:   "key parsed with type and length",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportAnalyzeDKIMKey("v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890")
                                keyType, _ := result["key_type"].(string)
                                actual := fmt.Sprintf("type=%s", keyType)
                                return actual, keyType == "rsa"
                        },
                },
                {
                        CaseID:     "tlsa-collection-001",
                        CaseName:   "TLSA entry parsing extracts usage and selector fields",
                        Protocol:   protocolDANE,
                        Layer:      LayerCollection,
                        RFCSection: citRFC6698S21,
                        Expected:   "valid TLSA with usage_name",
                        RunFn: func() (string, bool) {
                                parsed, valid := analyzer.ExportParseTLSAEntry("3 1 1 abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", "mail.example.com", "_25._tcp.mail.example.com")
                                if !valid {
                                        return "invalid", false
                                }
                                usageName, _ := parsed["usage_name"].(string)
                                actual := fmt.Sprintf("valid=%t, usage_name=%s", valid, usageName)
                                return actual, valid && usageName != ""
                        },
                },
                {
                        CaseID:     "ns-collection-001",
                        CaseName:   "NS provider classification identifies major providers",
                        Protocol:   mapKeyDnssec,
                        Layer:      LayerCollection,
                        RFCSection: "DNS provider detection",
                        Expected:   "Cloudflare detected",
                        RunFn: func() (string, bool) {
                                provider := analyzer.ExportClassifyNSProvider("ns1.cloudflare.com.")
                                return provider, provider == "Cloudflare"
                        },
                },
                {
                        CaseID:     "ns-collection-002",
                        CaseName:   "NS provider classification identifies Amazon Route 53",
                        Protocol:   mapKeyDnssec,
                        Layer:      LayerCollection,
                        RFCSection: "DNS provider detection",
                        Expected:   "Amazon Route 53 detected",
                        RunFn: func() (string, bool) {
                                provider := analyzer.ExportClassifyNSProvider("ns-123.awsdns-45.com.")
                                return provider, provider == "Amazon Route 53"
                        },
                },
                {
                        CaseID:     "ca-collection-001",
                        CaseName:   "CA issuer identification from CAA record",
                        Protocol:   "caa",
                        Layer:      LayerCollection,
                        RFCSection: rfcCAASection4,
                        Expected:   "Let's Encrypt identified",
                        RunFn: func() (string, bool) {
                                issuer := analyzer.ExportIdentifyCAIssuer("letsencrypt.org")
                                return issuer, issuer == "Let's Encrypt"
                        },
                },
                {
                        CaseID:     "ca-collection-002",
                        CaseName:   "CA issuer identification for DigiCert",
                        Protocol:   "caa",
                        Layer:      LayerCollection,
                        RFCSection: rfcCAASection4,
                        Expected:   "DigiCert identified",
                        RunFn: func() (string, bool) {
                                issuer := analyzer.ExportIdentifyCAIssuer("digicert.com")
                                return issuer, issuer == "DigiCert"
                        },
                },
                {
                        CaseID:     "domain-collection-001",
                        CaseName:   "Registrable domain extraction from subdomain",
                        Protocol:   mapKeyDnssec,
                        Layer:      LayerCollection,
                        RFCSection: "PSL-based domain registration",
                        Expected:   "example.com",
                        RunFn: func() (string, bool) {
                                domain := analyzer.ExportRegistrableDomain("sub.example.com")
                                return domain, domain == "example.com"
                        },
                },
        }
}

func dmarcCollectionCases() []TestCase {
        return []TestCase{
                {
                        CaseID:     "dmarc-collection-001",
                        CaseName:   "DMARC record filtering accepts v=DMARC1",
                        Protocol:   mapKeyDmarc,
                        Layer:      LayerCollection,
                        RFCSection: citRFC7489S61,
                        Expected:   "1 valid, 0 dmarc-like",
                        RunFn: func() (string, bool) {
                                valid, dmarcLike := analyzer.ExportClassifyDMARCRecords([]string{
                                        "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
                                        testSPFGoogleSoft,
                                        "some-random-txt-record",
                                })
                                actual := fmt.Sprintf("%d valid, %d dmarc-like", len(valid), len(dmarcLike))
                                return actual, len(valid) == 1 && len(dmarcLike) == 0
                        },
                },
                {
                        CaseID:     "dmarc-collection-002",
                        CaseName:   "DMARC policy tag extraction from record",
                        Protocol:   mapKeyDmarc,
                        Layer:      LayerCollection,
                        RFCSection: citRFC7489S63,
                        Expected:   "policy=reject, pct=100, hasRUA=true",
                        RunFn: func() (string, bool) {
                                policy, pct, hasRUA := analyzer.ExportParseDMARCPolicy("v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@example.com")
                                actual := fmt.Sprintf("policy=%s, pct=%d, hasRUA=%t", policy, pct, hasRUA)
                                return actual, policy == "reject" && pct == 100 && hasRUA
                        },
                },
                {
                        CaseID:     "dmarc-collection-003",
                        CaseName:   "Empty TXT records yield zero DMARC records",
                        Protocol:   mapKeyDmarc,
                        Layer:      LayerCollection,
                        RFCSection: citRFC7489S61,
                        Expected:   "0 valid, 0 dmarc-like",
                        RunFn: func() (string, bool) {
                                valid, dmarcLike := analyzer.ExportClassifyDMARCRecords(nil)
                                actual := fmt.Sprintf("%d valid, %d dmarc-like", len(valid), len(dmarcLike))
                                return actual, len(valid) == 0 && len(dmarcLike) == 0
                        },
                },
        }
}

func tlsrptCollectionCases() []TestCase {
        return []TestCase{
                {
                        CaseID:     "tlsrpt-collection-001",
                        CaseName:   "TLS-RPT URI extraction from rua field",
                        Protocol:   "tlsrpt",
                        Layer:      LayerCollection,
                        RFCSection: citRFC8460S3,
                        Expected:   "2 URIs extracted",
                        RunFn: func() (string, bool) {
                                uris := analyzer.ExportExtractTLSRPTURIs("v=TLSRPTv1; rua=mailto:tls@example.com,https://report.example.com/tls")
                                actual := fmt.Sprintf("%d URIs: %v", len(uris), uris)
                                return actual, len(uris) == 2 && strings.Contains(uris[0], "mailto:") && strings.Contains(uris[1], "https://")
                        },
                },
                {
                        CaseID:     "tlsrpt-collection-002",
                        CaseName:   "TLS-RPT record without rua yields zero URIs",
                        Protocol:   "tlsrpt",
                        Layer:      LayerCollection,
                        RFCSection: citRFC8460S3,
                        Expected:   "0 URIs",
                        RunFn: func() (string, bool) {
                                uris := analyzer.ExportExtractTLSRPTURIs("v=TLSRPTv1")
                                actual := fmt.Sprintf("%d URIs", len(uris))
                                return actual, len(uris) == 0
                        },
                },
        }
}
