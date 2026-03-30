// Copyright (c) 2024-2026 IT Help San Diego Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL — See LICENSE for terms.
// This file is part of the DNS Tool Intelligence Module.
package analyzer

import (
        "fmt"
        "strings"
)

const (
        sectionDNSRecords = "DNS Records"
        sectionInfraIntel = "Infrastructure Intelligence"
        sectionAISurface  = sectionAISurface
        rfcDNS1035        = "RFC 1035"
)

type VerifyCommand struct {
        Section     string
        Description string
        Command     string
        RFC         string
}

func GenerateVerificationCommands(domain string, results map[string]any) []VerifyCommand {
        var cmds []VerifyCommand

        cmds = append(cmds, generateDNSRecordCommands(domain)...)
        cmds = append(cmds, generateSPFCommands(domain)...)
        cmds = append(cmds, generateDMARCCommands(domain)...)
        cmds = append(cmds, generateDKIMCommands(domain, results)...)
        cmds = append(cmds, generateDNSSECCommands(domain)...)
        cmds = append(cmds, generateDANECommands(domain, results)...)
        cmds = append(cmds, generateMTASTSCommands(domain)...)
        cmds = append(cmds, generateTLSRPTCommands(domain)...)
        cmds = append(cmds, generateBIMICommands(domain)...)
        cmds = append(cmds, generateCAACommands(domain)...)
        cmds = append(cmds, generateRegistrarCommands(domain)...)
        cmds = append(cmds, generateSMTPCommands(domain, results)...)
        cmds = append(cmds, generateCTCommands(domain)...)
        cmds = append(cmds, generateDMARCReportAuthCommands(domain, results)...)
        cmds = append(cmds, generateHTTPSSVCBCommands(domain)...)
        cmds = append(cmds, generateASNCommands(results)...)
        cmds = append(cmds, generateCDSCommands(domain)...)
        cmds = append(cmds, generateSecurityTxtCommands(domain)...)
        cmds = append(cmds, generateAISurfaceCommands(domain)...)

        return cmds
}

func generateSecurityTxtCommands(domain string) []VerifyCommand {
        return []VerifyCommand{
                {
                        Section:     "security.txt",
                        Description: "Fetch security.txt vulnerability disclosure policy",
                        Command:     fmt.Sprintf("curl -sL https://%s/.well-known/security.txt", domain),
                        RFC:         "RFC 9116",
                },
        }
}

func generateDNSRecordCommands(domain string) []VerifyCommand {
        return []VerifyCommand{
                {
                        Section:     sectionDNSRecords,
                        Description: "Query A records (IPv4 addresses)",
                        Command:     fmt.Sprintf("dig +short A %s", domain),
                        RFC:         rfcDNS1035,
                },
                {
                        Section:     sectionDNSRecords,
                        Description: "Query AAAA records (IPv6 addresses)",
                        Command:     fmt.Sprintf("dig +short AAAA %s", domain),
                        RFC:         "RFC 3596",
                },
                {
                        Section:     sectionDNSRecords,
                        Description: "Query MX records (mail servers)",
                        Command:     fmt.Sprintf("dig +short MX %s", domain),
                        RFC:         "RFC 5321",
                },
                {
                        Section:     sectionDNSRecords,
                        Description: "Query NS records (nameservers)",
                        Command:     fmt.Sprintf("dig +short NS %s", domain),
                        RFC:         rfcDNS1035,
                },
                {
                        Section:     sectionDNSRecords,
                        Description: "Query all TXT records",
                        Command:     fmt.Sprintf("dig +short TXT %s", domain),
                        RFC:         rfcDNS1035,
                },
                {
                        Section:     sectionDNSRecords,
                        Description: "Multi-resolver consensus (compare across resolvers)",
                        Command:     fmt.Sprintf("dig @1.1.1.1 +short A %s && dig @8.8.8.8 +short A %s && dig @9.9.9.9 +short A %s && dig @208.67.222.222 +short A %s", domain, domain, domain, domain),
                        RFC:         "",
                },
        }
}

func generateSPFCommands(domain string) []VerifyCommand {
        return []VerifyCommand{
                {
                        Section:     "SPF",
                        Description: "Retrieve SPF record",
                        Command:     fmt.Sprintf("dig +short TXT %s | grep 'v=spf1'", domain),
                        RFC:         "RFC 7208",
                },
        }
}

func generateDMARCCommands(domain string) []VerifyCommand {
        return []VerifyCommand{
                {
                        Section:     "DMARC",
                        Description: "Retrieve DMARC policy",
                        Command:     fmt.Sprintf("dig +short TXT _dmarc.%s", domain),
                        RFC:         "RFC 7489",
                },
        }
}

func generateDKIMCommands(domain string, results map[string]any) []VerifyCommand {
        cmds := []VerifyCommand{
                {
                        Section:     "DKIM",
                        Description: "Check common DKIM selectors (example: google, selector1)",
                        Command:     fmt.Sprintf("dig +short TXT google._domainkey.%s\ndig +short TXT selector1._domainkey.%s\ndig +short TXT selector2._domainkey.%s\ndig +short TXT default._domainkey.%s", domain, domain, domain, domain),
                        RFC:         "RFC 6376",
                },
        }

        if dkim, ok := results["dkim_analysis"].(map[string]any); ok {
                if selectors, ok := dkim["selectors"].([]any); ok {
                        for _, sel := range selectors {
                                if selMap, ok := sel.(map[string]any); ok {
                                        if selName, ok := selMap["selector"].(string); ok {
                                                cmds = append(cmds, VerifyCommand{
                                                        Section:     "DKIM",
                                                        Description: fmt.Sprintf("Verify discovered selector: %s", selName),
                                                        Command:     fmt.Sprintf("dig +short TXT %s._domainkey.%s", selName, domain),
                                                        RFC:         "RFC 6376 §3.6.2.2",
                                                })
                                        }
                                }
                        }
                }
        }

        return cmds
}

func generateDNSSECCommands(domain string) []VerifyCommand {
        return []VerifyCommand{
                {
                        Section:     "DNSSEC",
                        Description: "Check for DNSSEC signatures (RRSIG records)",
                        Command:     fmt.Sprintf("dig +dnssec +short A %s", domain),
                        RFC:         "RFC 4035",
                },
                {
                        Section:     "DNSSEC",
                        Description: "Query DNSKEY records",
                        Command:     fmt.Sprintf("dig +short DNSKEY %s", domain),
                        RFC:         "RFC 4034",
                },
                {
                        Section:     "DNSSEC",
                        Description: "Query DS records at parent zone",
                        Command:     fmt.Sprintf("dig +short DS %s", domain),
                        RFC:         "RFC 4034",
                },
                {
                        Section:     "DNSSEC",
                        Description: "Verify AD (Authenticated Data) flag",
                        Command:     fmt.Sprintf("dig +adflag A %s | grep flags", domain),
                        RFC:         "RFC 4035 §3.2.3",
                },
        }
}

func generateDANECommands(domain string, results map[string]any) []VerifyCommand {
        var cmds []VerifyCommand

        mxHosts := extractMXHostsFromResults(results)
        if len(mxHosts) == 0 {
                cmds = append(cmds, VerifyCommand{
                        Section:     "DANE/TLSA",
                        Description: "Query TLSA records for mail server (replace mx.example.com with actual MX)",
                        Command:     fmt.Sprintf("dig +short TLSA _25._tcp.mx.%s", domain),
                        RFC:         "RFC 7672",
                })
        } else {
                for _, mx := range mxHosts {
                        mx = strings.TrimSuffix(mx, ".")
                        cmds = append(cmds, VerifyCommand{
                                Section:     "DANE/TLSA",
                                Description: fmt.Sprintf("Query TLSA records for %s", mx),
                                Command:     fmt.Sprintf("dig +short TLSA _25._tcp.%s", mx),
                                RFC:         "RFC 7672",
                        })
                }
        }

        return cmds
}

func generateMTASTSCommands(domain string) []VerifyCommand {
        return []VerifyCommand{
                {
                        Section:     "MTA-STS",
                        Description: "Check MTA-STS DNS record",
                        Command:     fmt.Sprintf("dig +short TXT _mta-sts.%s", domain),
                        RFC:         "RFC 8461",
                },
                {
                        Section:     "MTA-STS",
                        Description: "Fetch MTA-STS policy file",
                        Command:     fmt.Sprintf("curl -sL https://mta-sts.%s/.well-known/mta-sts.txt", domain),
                        RFC:         "RFC 8461 §3.3",
                },
        }
}

func generateTLSRPTCommands(domain string) []VerifyCommand {
        return []VerifyCommand{
                {
                        Section:     "TLS-RPT",
                        Description: "Check TLS-RPT reporting record",
                        Command:     fmt.Sprintf("dig +short TXT _smtp._tls.%s", domain),
                        RFC:         "RFC 8460",
                },
        }
}

func generateBIMICommands(domain string) []VerifyCommand {
        return []VerifyCommand{
                {
                        Section:     "BIMI",
                        Description: "Check BIMI record for brand logo",
                        Command:     fmt.Sprintf("dig +short TXT default._bimi.%s", domain),
                        RFC:         "RFC 9495",
                },
        }
}

func generateCAACommands(domain string) []VerifyCommand {
        return []VerifyCommand{
                {
                        Section:     "CAA",
                        Description: "Query CAA records (certificate authority authorization)",
                        Command:     fmt.Sprintf("dig +short CAA %s", domain),
                        RFC:         "RFC 8659",
                },
        }
}

func generateRegistrarCommands(domain string) []VerifyCommand {
        return []VerifyCommand{
                {
                        Section:     "Registrar",
                        Description: "RDAP lookup for registration data",
                        Command:     fmt.Sprintf("curl -sL 'https://rdap.org/domain/%s' | python3 -m json.tool | head -40", domain),
                        RFC:         "RFC 9083",
                },
        }
}

func generateSMTPCommands(domain string, results map[string]any) []VerifyCommand {
        var cmds []VerifyCommand

        mxHosts := extractMXHostsFromResults(results)
        if len(mxHosts) == 0 {
                cmds = append(cmds, VerifyCommand{
                        Section:     "SMTP Transport",
                        Description: "Test STARTTLS on mail server (replace mx.example.com with actual MX)",
                        Command:     fmt.Sprintf("openssl s_client -starttls smtp -connect mx.%s:25 -brief 2>&1 | head -5", domain),
                        RFC:         "RFC 3207",
                })
        } else {
                mx := strings.TrimSuffix(mxHosts[0], ".")
                cmds = append(cmds, VerifyCommand{
                        Section:     "SMTP Transport",
                        Description: fmt.Sprintf("Test STARTTLS on %s", mx),
                        Command:     fmt.Sprintf("openssl s_client -starttls smtp -connect %s:25 -brief 2>&1 | head -5", mx),
                        RFC:         "RFC 3207",
                })
        }

        return cmds
}

func generateCTCommands(domain string) []VerifyCommand {
        return []VerifyCommand{
                {
                        Section:     "Certificate Transparency",
                        Description: "Search CT logs for subdomains",
                        Command:     fmt.Sprintf("curl -s 'https://crt.sh/?q=%%25.%s&output=json' | python3 -c \"import json,sys; [print(e['name_value']) for e in json.load(sys.stdin)]\" | sort -u | head -20", domain),
                        RFC:         "RFC 6962",
                },
        }
}

func generateDMARCReportAuthCommands(domain string, results map[string]any) []VerifyCommand {
        var cmds []VerifyCommand

        dmarcAuth, _ := results["dmarc_report_auth"].(map[string]any)
        if dmarcAuth == nil {
                return cmds
        }

        extDomains, _ := dmarcAuth["external_domains"].([]map[string]any)
        for _, ed := range extDomains {
                extDomain, _ := ed["external_domain"].(string)
                if extDomain == "" {
                        continue
                }
                cmds = append(cmds, VerifyCommand{
                        Section:     "DMARC Report Auth",
                        Description: fmt.Sprintf("Check external reporting authorization for %s", extDomain),
                        Command:     fmt.Sprintf("dig +short TXT %s._report._dmarc.%s", domain, extDomain),
                        RFC:         "RFC 7489 §7.1",
                })
        }

        return cmds
}

func generateHTTPSSVCBCommands(domain string) []VerifyCommand {
        return []VerifyCommand{
                {
                        Section:     "HTTPS/SVCB",
                        Description: "Query HTTPS records (type 65)",
                        Command:     fmt.Sprintf("dig +short TYPE65 %s", domain),
                        RFC:         "RFC 9460",
                },
        }
}

func generateASNCommands(results map[string]any) []VerifyCommand {
        var cmds []VerifyCommand

        basicRecords, _ := results["basic_records"].(map[string]any)
        if basicRecords == nil {
                return cmds
        }

        aRecords, _ := basicRecords["A"].([]string)
        if len(aRecords) > 0 {
                ip := aRecords[0]
                reversed := reverseIPv4(ip)
                if reversed != "" {
                        cmds = append(cmds, VerifyCommand{
                                Section:     sectionInfraIntel,
                                Description: fmt.Sprintf("Reverse DNS (PTR) lookup for %s — identifies hosting provider", ip),
                                Command:     fmt.Sprintf("dig +short -x %s", ip),
                                RFC:         rfcDNS1035,
                        })
                        cmds = append(cmds, VerifyCommand{
                                Section:     sectionInfraIntel,
                                Description: fmt.Sprintf("Look up ASN for %s via Team Cymru (free, no rate limits)", ip),
                                Command:     fmt.Sprintf("dig +short TXT %s.origin.asn.cymru.com", reversed),
                                RFC:         "",
                        })
                        cmds = append(cmds, VerifyCommand{
                                Section:     sectionInfraIntel,
                                Description: "Look up ASN organization name",
                                Command:     fmt.Sprintf("dig +short TXT AS$(dig +short TXT %s.origin.asn.cymru.com | awk -F'|' '{print $1}' | tr -d ' \"').peer.asn.cymru.com", reversed),
                                RFC:         "",
                        })
                }
        }

        return cmds
}

func generateCDSCommands(domain string) []VerifyCommand {
        return []VerifyCommand{
                {
                        Section:     "CDS/CDNSKEY",
                        Description: "Query CDS records (automated DNSSEC key rollover)",
                        Command:     fmt.Sprintf("dig +short CDS %s", domain),
                        RFC:         "RFC 8078",
                },
                {
                        Section:     "CDS/CDNSKEY",
                        Description: "Query CDNSKEY records",
                        Command:     fmt.Sprintf("dig +short CDNSKEY %s", domain),
                        RFC:         "RFC 8078",
                },
        }
}

func generateAISurfaceCommands(domain string) []VerifyCommand {
        return []VerifyCommand{
                {
                        Section:     sectionAISurface,
                        Description: "Check for llms.txt (LLM context file)",
                        Command:     fmt.Sprintf("curl -sL -o /dev/null -w '%%{http_code}' https://%s/llms.txt", domain),
                },
                {
                        Section:     sectionAISurface,
                        Description: "Check for llms-full.txt (extended LLM context)",
                        Command:     fmt.Sprintf("curl -sL -o /dev/null -w '%%{http_code}' https://%s/llms-full.txt", domain),
                },
                {
                        Section:     sectionAISurface,
                        Description: "Check robots.txt for AI crawler directives",
                        Command:     fmt.Sprintf("curl -sL https://%s/robots.txt | grep -i -E 'GPTBot|ChatGPT-User|Google-Extended|CCBot|anthropic|ClaudeBot|Bytespider|PerplexityBot'", domain),
                },
        }
}

func extractMXHostsFromResults(results map[string]any) []string {
        basic, ok := results["basic_records"].(map[string]any)
        if !ok {
                return nil
        }
        mxRaw, ok := basic["MX"]
        if !ok {
                return nil
        }
        return parseMXHostEntries(mxRaw)
}

func parseMXHostEntries(mxRaw any) []string {
        var hosts []string
        switch mx := mxRaw.(type) {
        case []string:
                for _, h := range mx {
                        hosts = appendMXHost(hosts, h)
                }
        case []any:
                for _, h := range mx {
                        if s, ok := h.(string); ok {
                                hosts = appendMXHost(hosts, s)
                        }
                }
        }
        return hosts
}

func appendMXHost(hosts []string, entry string) []string {
        parts := strings.Fields(entry)
        if len(parts) >= 2 {
                return append(hosts, parts[len(parts)-1])
        }
        if len(parts) == 1 {
                return append(hosts, parts[0])
        }
        return hosts
}
