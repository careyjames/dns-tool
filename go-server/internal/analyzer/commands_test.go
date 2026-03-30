// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
        "strings"
        "testing"
)

func TestGoldenRuleExtractMXHostsUppercaseKeys(t *testing.T) {
        results := map[string]any{
                "basic_records": map[string]any{
                        "MX": []string{"10 mx1.example.com.", "20 mx2.example.com."},
                },
        }
        hosts := extractMXHostsFromResults(results)
        if len(hosts) != 2 {
                t.Fatalf("expected 2 MX hosts, got %d: %v", len(hosts), hosts)
        }
        if hosts[0] != "mx1.example.com" {
                t.Errorf("expected mx1.example.com, got %s", hosts[0])
        }
        if hosts[1] != "mx2.example.com" {
                t.Errorf("expected mx2.example.com, got %s", hosts[1])
        }
}

func TestGoldenRuleExtractMXHostsLowercaseKeys(t *testing.T) {
        results := map[string]any{
                "basic_records": map[string]any{
                        "mx": []any{
                                map[string]any{"host": "mx1.example.com.", "priority": 10},
                        },
                },
        }
        hosts := extractMXHostsFromResults(results)
        if len(hosts) != 1 {
                t.Fatalf("expected 1 MX host, got %d: %v", len(hosts), hosts)
        }
        if hosts[0] != "mx1.example.com" {
                t.Errorf("expected mx1.example.com, got %s", hosts[0])
        }
}

func TestGoldenRuleExtractMXHostsFromJSON(t *testing.T) {
        results := map[string]any{
                "basic_records": map[string]any{
                        "MX": []any{"1 smtp.google.com."},
                },
        }
        hosts := extractMXHostsFromResults(results)
        if len(hosts) != 1 {
                t.Fatalf("expected 1 MX host, got %d: %v", len(hosts), hosts)
        }
        if hosts[0] != "smtp.google.com" {
                t.Errorf("expected smtp.google.com, got %s", hosts[0])
        }
}

func TestGoldenRuleExtractMXHostsMissingBasicRecords(t *testing.T) {
        results := map[string]any{}
        hosts := extractMXHostsFromResults(results)
        if hosts != nil {
                t.Errorf("expected nil, got %v", hosts)
        }
}

func TestGoldenRuleExtractIPsUppercaseKeys(t *testing.T) {
        results := map[string]any{
                "basic_records": map[string]any{
                        "A": []string{"1.2.3.4", "5.6.7.8", "9.10.11.12"},
                },
        }
        ips := extractIPsFromResults(results)
        if len(ips) != 2 {
                t.Fatalf("expected 2 IPs (capped), got %d: %v", len(ips), ips)
        }
        if ips[0] != "1.2.3.4" {
                t.Errorf("expected 1.2.3.4, got %s", ips[0])
        }
}

func TestGoldenRuleExtractIPsFromJSON(t *testing.T) {
        results := map[string]any{
                "basic_records": map[string]any{
                        "A": []any{"10.0.0.1"},
                },
        }
        ips := extractIPsFromResults(results)
        if len(ips) != 1 {
                t.Fatalf("expected 1 IP, got %d: %v", len(ips), ips)
        }
        if ips[0] != "10.0.0.1" {
                t.Errorf("expected 10.0.0.1, got %s", ips[0])
        }
}

func TestGoldenRuleNoMXHostPlaceholder(t *testing.T) {
        results := map[string]any{
                "basic_records": map[string]any{
                        "MX": []string{"1 smtp.google.com."},
                },
        }
        cmds := GenerateVerificationCommands("it-help.tech", results)
        for _, cmd := range cmds {
                if strings.Contains(cmd.Command, "MX_HOST") {
                        t.Errorf("found literal MX_HOST placeholder in command: %s", cmd.Command)
                }
        }
}

func TestGoldenRuleDANECommandsUseRealMX(t *testing.T) {
        results := map[string]any{
                "basic_records": map[string]any{
                        "MX": []string{"10 mail.example.org."},
                },
        }
        cmds := GenerateVerificationCommands("example.org", results)
        foundTLSA := false
        foundOpenSSL := false
        for _, cmd := range cmds {
                if strings.Contains(cmd.Command, "_25._tcp.mail.example.org") {
                        foundTLSA = true
                }
                if strings.Contains(cmd.Command, "openssl") && strings.Contains(cmd.Command, "mail.example.org") {
                        foundOpenSSL = true
                }
        }
        if !foundTLSA {
                t.Error("expected TLSA command with real MX host mail.example.org")
        }
        if !foundOpenSSL {
                t.Error("expected openssl STARTTLS command with real MX host mail.example.org")
        }
}

func TestGoldenRuleASNCommandsUseReversedIP(t *testing.T) {
        results := map[string]any{
                "basic_records": map[string]any{
                        "A": []string{"13.226.251.106"},
                },
        }
        cmds := GenerateVerificationCommands("example.com", results)
        found := false
        for _, cmd := range cmds {
                if strings.Contains(cmd.Command, "106.251.226.13.origin.asn.cymru.com") {
                        found = true
                }
        }
        if !found {
                t.Error("expected ASN command with reversed IP 106.251.226.13")
        }
}

func TestGoldenRuleAllCommandsHaveSectionAndDescription(t *testing.T) {
        results := map[string]any{
                "basic_records": map[string]any{
                        "MX": []string{"10 mx.example.com."},
                        "A":  []string{"1.2.3.4"},
                },
                "dkim_analysis": map[string]any{
                        "selectors": map[string]any{
                                "google": map[string]any{},
                        },
                },
        }
        cmds := GenerateVerificationCommands("example.com", results)
        if len(cmds) == 0 {
                t.Fatal("expected at least one verification command")
        }
        for i, cmd := range cmds {
                if cmd.Section == "" {
                        t.Errorf("command %d has empty section: %s", i, cmd.Command)
                }
                if cmd.Description == "" {
                        t.Errorf("command %d has empty description: %s", i, cmd.Command)
                }
                if cmd.Command == "" {
                        t.Errorf("command %d has empty command", i)
                }
        }
}

func TestGoldenRuleCommandsDontContainTrailingDots(t *testing.T) {
        results := map[string]any{
                "basic_records": map[string]any{
                        "MX": []string{"10 mx1.example.com."},
                },
        }
        cmds := GenerateVerificationCommands("example.com", results)
        for _, cmd := range cmds {
                if strings.Contains(cmd.Command, "mx1.example.com.") {
                        t.Errorf("command contains trailing dot in hostname: %s", cmd.Command)
                }
        }
}

func TestGoldenRuleDKIMSelectorsFromResults(t *testing.T) {
        results := map[string]any{
                "basic_records": map[string]any{},
                "dkim_analysis": map[string]any{
                        "selectors": map[string]any{
                                "google":    map[string]any{},
                                "selector1": map[string]any{},
                        },
                },
        }
        cmds := GenerateVerificationCommands("example.com", results)
        dkimCmds := 0
        for _, cmd := range cmds {
                if strings.Contains(cmd.Command, "_domainkey") {
                        dkimCmds++
                }
        }
        if dkimCmds != 2 {
                t.Errorf("expected 2 DKIM commands (google, selector1), got %d", dkimCmds)
        }
}

func TestGoldenRuleTLDSkipsEmailAndWebCommands(t *testing.T) {
        results := map[string]any{}
        cmds := GenerateVerificationCommands("com", results)
        for _, cmd := range cmds {
                if cmd.Section == sectionEmailAuth {
                        t.Errorf("TLD should not have email auth commands, got: %s", cmd.Command)
                }
                if strings.Contains(cmd.Command, "mta-sts") || strings.Contains(cmd.Command, "_smtp._tls") ||
                        strings.Contains(cmd.Command, "_bimi") || strings.Contains(cmd.Command, "security.txt") ||
                        strings.Contains(cmd.Command, "llms.txt") || strings.Contains(cmd.Command, "robots.txt") {
                        t.Errorf("TLD should not have web/email transport commands, got: %s", cmd.Command)
                }
        }
        hasDNSSEC := false
        hasNS := false
        for _, cmd := range cmds {
                if strings.Contains(cmd.Command, "DNSKEY") {
                        hasDNSSEC = true
                }
                if strings.Contains(cmd.Command, " NS") {
                        hasNS = true
                }
        }
        if !hasDNSSEC {
                t.Error("TLD should still have DNSSEC commands")
        }
        if !hasNS {
                t.Error("TLD should still have NS record commands")
        }
}

func TestGoldenRuleRegularDomainHasAllSections(t *testing.T) {
        results := map[string]any{
                "basic_records": map[string]any{
                        "MX": []string{"10 mx.example.com."},
                        "A":  []string{"1.2.3.4"},
                },
        }
        cmds := GenerateVerificationCommands("example.com", results)
        sections := make(map[string]bool)
        for _, cmd := range cmds {
                sections[cmd.Section] = true
        }
        for _, expected := range []string{sectionDNSRecords, sectionEmailAuth, sectionTransport, sectionDomainSec} {
                if !sections[expected] {
                        t.Errorf("regular domain should have section %s", expected)
                }
        }
}

func TestExtractDKIMSelectors_NilResults(t *testing.T) {
        selectors := extractDKIMSelectors(nil)
        if selectors != nil {
                t.Errorf("expected nil for nil results, got %v", selectors)
        }
}

func TestExtractDKIMSelectors_NoDKIMKey(t *testing.T) {
        results := map[string]any{"basic_records": map[string]any{}}
        selectors := extractDKIMSelectors(results)
        if selectors != nil {
                t.Errorf("expected nil when no dkim key, got %v", selectors)
        }
}

func TestExtractDKIMSelectors_EmptySelectors(t *testing.T) {
        results := map[string]any{
                "dkim_analysis": map[string]any{
                        "selectors": map[string]any{},
                },
        }
        selectors := extractDKIMSelectors(results)
        if selectors != nil {
                t.Errorf("expected nil for empty selectors, got %v", selectors)
        }
}

func TestExtractDKIMSelectors_SortedOutput(t *testing.T) {
        results := map[string]any{
                "dkim_analysis": map[string]any{
                        "selectors": map[string]any{
                                "zoho":      map[string]any{},
                                "google":    map[string]any{},
                                "selector1": map[string]any{},
                        },
                },
        }
        selectors := extractDKIMSelectors(results)
        if len(selectors) != 3 {
                t.Fatalf("expected 3, got %d", len(selectors))
        }
        if selectors[0] != "google" || selectors[1] != "selector1" || selectors[2] != "zoho" {
                t.Errorf("selectors not sorted: %v", selectors)
        }
}

func TestGoldenRuleEmptyDomainStillGeneratesCommands(t *testing.T) {
        results := map[string]any{}
        cmds := GenerateVerificationCommands("", results)
        if cmds == nil {
                t.Error("expected non-nil commands even for empty domain")
        }
}

func TestGoldenRuleSMTPCommandUsesRealMX(t *testing.T) {
        results := map[string]any{
                "basic_records": map[string]any{
                        "MX": []string{"10 mail.example.com."},
                },
        }
        cmds := GenerateVerificationCommands("example.com", results)
        found := false
        for _, cmd := range cmds {
                if strings.Contains(cmd.Command, "openssl") && strings.Contains(cmd.Command, "-starttls smtp") && strings.Contains(cmd.Command, "mail.example.com:25") {
                        found = true
                }
        }
        if !found {
                t.Error("expected SMTP STARTTLS command with real MX host mail.example.com:25")
        }
}
