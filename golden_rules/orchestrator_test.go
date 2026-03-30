// Copyright (c) 2024-2026 IT Help San Diego Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL — See LICENSE for terms.
// This file is part of the DNS Tool Intelligence Module.
package analyzer

import (
        "strings"
        "testing"
)

const (
        testRiskLow      = "Low Risk"
        testRiskMedium   = "Medium Risk"
        testRiskCritical = "Critical Risk"
        testDomainFake   = "fake.example"
        testDomainExample = "example.com"
        testHelloWorld   = "Hello World"
)

func newTestAnalyzer() *Analyzer {
        return &Analyzer{
                maxConcurrent: 6,
                semaphore:     make(chan struct{}, 6),
                ctCache:       make(map[string]ctCacheEntry),
        }
}

func TestNonExistentDomainStructure(t *testing.T) {
        a := newTestAnalyzer()
        msg := "Domain is not delegated"
        result := a.buildNonExistentResult(testDomainFake, "undelegated", &msg)

        if result["domain_exists"] != false {
                t.Errorf("expected domain_exists=false, got %v", result["domain_exists"])
        }
        if result["domain_status"] != "undelegated" {
                t.Errorf("expected domain_status=undelegated, got %v", result["domain_status"])
        }

        basic, ok := result["basic_records"].(map[string]any)
        if !ok {
                t.Fatal("basic_records is not map[string]any")
        }
        expectedTypes := []string{"A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"}
        for _, rtype := range expectedTypes {
                arr, ok := basic[rtype].([]string)
                if !ok {
                        t.Errorf("basic_records[%s] is not []string", rtype)
                        continue
                }
                if len(arr) != 0 {
                        t.Errorf("basic_records[%s] should be empty, got %v", rtype, arr)
                }
        }

        dane, ok := result["dane_analysis"].(map[string]any)
        if !ok {
                t.Fatal("dane_analysis is not map[string]any")
        }
        if dane["has_dane"] != false {
                t.Errorf("expected dane has_dane=false, got %v", dane["has_dane"])
        }
        tlsa, ok := dane["tlsa_records"].([]any)
        if !ok {
                t.Fatal("dane tlsa_records is not []any")
        }
        if len(tlsa) != 0 {
                t.Error("expected empty tlsa_records")
        }
        issues, ok := dane["issues"].([]string)
        if !ok {
                t.Fatal("dane issues is not []string")
        }
        if len(issues) != 0 {
                t.Error("expected empty dane issues")
        }
}

func TestNonExistentDomainAllSectionsNA(t *testing.T) {
        a := newTestAnalyzer()
        result := a.buildNonExistentResult(testDomainFake, "undelegated", nil)

        naSections := []string{
                "spf_analysis", "dmarc_analysis", "dkim_analysis",
                "mta_sts_analysis", "tlsrpt_analysis", "bimi_analysis",
                "dane_analysis", "caa_analysis", "dnssec_analysis",
        }

        for _, section := range naSections {
                m, ok := result[section].(map[string]any)
                if !ok {
                        t.Errorf("%s is not map[string]any", section)
                        continue
                }
                if m["status"] != "n/a" {
                        t.Errorf("%s status expected n/a, got %v", section, m["status"])
                }
        }
}

func TestNonExistentDomainPosture(t *testing.T) {
        a := newTestAnalyzer()
        result := a.buildNonExistentResult(testDomainFake, "undelegated", nil)

        posture, ok := result["posture"].(map[string]any)
        if !ok {
                t.Fatal("posture is not map[string]any")
        }
        if posture["score"] != 0 {
                t.Errorf("expected score=0, got %v", posture["score"])
        }
        if posture["grade"] != "N/A" {
                t.Errorf("expected grade=N/A, got %v", posture["grade"])
        }
        if posture["color"] != "secondary" {
                t.Errorf("expected color=secondary, got %v", posture["color"])
        }
}

func TestPostureFullProtection(t *testing.T) {
        a := newTestAnalyzer()
        results := map[string]any{
                "spf_analysis":   map[string]any{"status": "success", "all_mechanism": "-all"},
                "dmarc_analysis": map[string]any{"status": "success", "policy": "reject"},
                "dkim_analysis":  map[string]any{"status": "success"},
                "mta_sts_analysis": map[string]any{"status": "success"},
                "tlsrpt_analysis":  map[string]any{"status": "success"},
                "bimi_analysis":    map[string]any{"status": "success"},
                "dane_analysis":    map[string]any{"has_dane": true},
                "caa_analysis":     map[string]any{"status": "success"},
                "dnssec_analysis":  map[string]any{"status": "success"},
        }

        posture := a.CalculatePosture(results)
        score, _ := posture["score"].(int)
        if score < 90 {
                t.Errorf("expected score >= 90 for full protection, got %d", score)
        }
        if posture["state"] != "Secure" {
                t.Errorf("expected state Secure, got %v", posture["state"])
        }
        if posture["color"] != "success" {
                t.Errorf("expected color success, got %v", posture["color"])
        }
}

func TestPostureMinimalSPFOnly(t *testing.T) {
        a := newTestAnalyzer()
        results := map[string]any{
                "spf_analysis":     map[string]any{"status": "success"},
                "dmarc_analysis":   map[string]any{},
                "dkim_analysis":    map[string]any{},
                "mta_sts_analysis": map[string]any{},
                "tlsrpt_analysis":  map[string]any{},
                "bimi_analysis":    map[string]any{},
                "dane_analysis":    map[string]any{},
                "caa_analysis":     map[string]any{},
                "dnssec_analysis":  map[string]any{},
        }

        posture := a.CalculatePosture(results)
        if posture["state"] != "High Risk" {
                t.Errorf("expected state High Risk (SPF only, no DMARC), got %v", posture["state"])
        }
}

func TestPostureScoreCapping(t *testing.T) {
        a := newTestAnalyzer()
        results := map[string]any{
                "spf_analysis":     map[string]any{"status": "success", "all_mechanism": "-all"},
                "dmarc_analysis":   map[string]any{"status": "success", "policy": "reject"},
                "dkim_analysis":    map[string]any{"status": "success"},
                "mta_sts_analysis": map[string]any{"status": "success"},
                "tlsrpt_analysis":  map[string]any{"status": "success"},
                "bimi_analysis":    map[string]any{"status": "success"},
                "dane_analysis":    map[string]any{"has_dane": true},
                "caa_analysis":     map[string]any{"status": "success"},
                "dnssec_analysis":  map[string]any{"status": "success"},
        }

        posture := a.CalculatePosture(results)
        score, _ := posture["score"].(int)
        if score > 100 {
                t.Errorf("score should be capped at 100, got %d", score)
        }
        if score != 100 {
                t.Errorf("expected score=100, got %d", score)
        }
}

func TestPostureIssuesTracking(t *testing.T) {
        a := newTestAnalyzer()
        results := map[string]any{
                "spf_analysis":     map[string]any{},
                "dmarc_analysis":   map[string]any{},
                "dkim_analysis":    map[string]any{},
                "mta_sts_analysis": map[string]any{},
                "tlsrpt_analysis":  map[string]any{},
                "bimi_analysis":    map[string]any{},
                "dane_analysis":    map[string]any{},
                "caa_analysis":     map[string]any{},
                "dnssec_analysis":  map[string]any{},
        }

        posture := a.CalculatePosture(results)
        issues, ok := posture["issues"].([]string)
        if !ok {
                t.Fatal("issues is not []string")
        }

        expectedIssues := []string{
                "No SPF record",
                "No DMARC record",
                "No DKIM found",
        }

        if len(issues) != len(expectedIssues) {
                t.Errorf("expected %d issues, got %d: %v", len(expectedIssues), len(issues), issues)
        }
        for i, expected := range expectedIssues {
                if i < len(issues) && issues[i] != expected {
                        t.Errorf("issue[%d] expected %q, got %q", i, expected, issues[i])
                }
        }

        absent, _ := posture["absent"].([]string)
        foundCAAInAbsent := false
        for _, a := range absent {
                if a == "CAA" {
                        foundCAAInAbsent = true
                }
        }
        if !foundCAAInAbsent {
                t.Error("CAA should appear in absent list (Low severity, not in issues/recommendations)")
        }
}

func TestPostureProviderAwareDKIM(t *testing.T) {
        a := newTestAnalyzer()
        results := map[string]any{
                "spf_analysis":     map[string]any{"status": "success"},
                "dmarc_analysis":   map[string]any{"status": "success", "policy": "reject"},
                "dkim_analysis":    map[string]any{"status": "info", "primary_provider": "Google Workspace"},
                "mta_sts_analysis": map[string]any{"status": "success"},
                "tlsrpt_analysis":  map[string]any{"status": "success"},
                "bimi_analysis":    map[string]any{},
                "dane_analysis":    map[string]any{},
                "caa_analysis":     map[string]any{"status": "success"},
                "dnssec_analysis":  map[string]any{},
        }

        posture := a.CalculatePosture(results)
        state, _ := posture["state"].(string)
        if !strings.HasPrefix(state, testRiskLow) {
                t.Errorf("expected Low Risk for provider-aware DKIM, got %v", state)
        }

        configured, _ := posture["configured"].([]string)
        found := false
        for _, c := range configured {
                if strings.Contains(c, "provider-verified") {
                        found = true
                        break
                }
        }
        if !found {
                t.Error("expected 'provider-verified' in configured list")
        }

        monitoring, _ := posture["monitoring"].([]string)
        if len(monitoring) > 0 {
                t.Errorf("known provider DKIM should not be in monitoring, got %v", monitoring)
        }
}

func TestPostureUnknownProviderDKIM(t *testing.T) {
        a := newTestAnalyzer()
        results := map[string]any{
                "spf_analysis":     map[string]any{"status": "success"},
                "dmarc_analysis":   map[string]any{"status": "success", "policy": "reject"},
                "dkim_analysis":    map[string]any{"status": "info", "primary_provider": "Unknown"},
                "mta_sts_analysis": map[string]any{},
                "tlsrpt_analysis":  map[string]any{},
                "bimi_analysis":    map[string]any{},
                "dane_analysis":    map[string]any{},
                "caa_analysis":     map[string]any{},
                "dnssec_analysis":  map[string]any{},
        }

        posture := a.CalculatePosture(results)
        monitoring, _ := posture["monitoring"].([]string)
        if len(monitoring) == 0 {
                t.Error("unknown provider DKIM should be in monitoring")
        }
        state, _ := posture["state"].(string)
        if !strings.Contains(state, "Monitoring") {
                t.Errorf("expected state containing Monitoring, got %v", state)
        }
}

func TestPostureTruthBasedGrades(t *testing.T) {
        tests := []struct {
                name          string
                results       map[string]any
                expectedGrade string
                expectedColor string
                messageContains string
        }{
                {
                        name: "Informational — full protection with reject + CAA + DNSSEC",
                        results: map[string]any{
                                "spf_analysis":     map[string]any{"status": "success", "all_mechanism": "-all"},
                                "dmarc_analysis":   map[string]any{"status": "success", "policy": "reject"},
                                "dkim_analysis":    map[string]any{"status": "success"},
                                "mta_sts_analysis": map[string]any{"status": "success"},
                                "tlsrpt_analysis":  map[string]any{"status": "success"},
                                "bimi_analysis":    map[string]any{"status": "success"},
                                "dane_analysis":    map[string]any{"has_dane": true},
                                "caa_analysis":     map[string]any{"status": "success"},
                                "dnssec_analysis":  map[string]any{"status": "success"},
                        },
                        expectedGrade: "Secure",
                        expectedColor: "success",
                        messageContains: "DMARC enforcement",
                },
                {
                        name: "Low — core with reject + CAA, optional missing",
                        results: map[string]any{
                                "spf_analysis":     map[string]any{"status": "success", "all_mechanism": "-all"},
                                "dmarc_analysis":   map[string]any{"status": "success", "policy": "reject"},
                                "dkim_analysis":    map[string]any{"status": "success"},
                                "mta_sts_analysis": map[string]any{},
                                "tlsrpt_analysis":  map[string]any{},
                                "bimi_analysis":    map[string]any{},
                                "dane_analysis":    map[string]any{},
                                "caa_analysis":     map[string]any{"status": "success"},
                                "dnssec_analysis":  map[string]any{},
                        },
                        expectedGrade: testRiskLow,
                        expectedColor: "success",
                        messageContains: "not configured",
                },
                {
                        name: "Low Risk — quarantine with core configured",
                        results: map[string]any{
                                "spf_analysis":     map[string]any{"status": "success"},
                                "dmarc_analysis":   map[string]any{"status": "success", "policy": "quarantine"},
                                "dkim_analysis":    map[string]any{"status": "success"},
                                "mta_sts_analysis": map[string]any{},
                                "tlsrpt_analysis":  map[string]any{},
                                "bimi_analysis":    map[string]any{},
                                "dane_analysis":    map[string]any{},
                                "caa_analysis":     map[string]any{},
                                "dnssec_analysis":  map[string]any{},
                        },
                        expectedGrade: testRiskLow,
                        expectedColor: "success",
                        messageContains: "quarantine",
                },
                {
                        name: "Medium Risk — core present but DMARC p=none",
                        results: map[string]any{
                                "spf_analysis":     map[string]any{"status": "success"},
                                "dmarc_analysis":   map[string]any{"status": "warning", "policy": "none", "valid_records": []string{"v=DMARC1; p=none"}},
                                "dkim_analysis":    map[string]any{"status": "success"},
                                "mta_sts_analysis": map[string]any{},
                                "tlsrpt_analysis":  map[string]any{},
                                "bimi_analysis":    map[string]any{},
                                "dane_analysis":    map[string]any{},
                                "caa_analysis":     map[string]any{},
                                "dnssec_analysis":  map[string]any{},
                        },
                        expectedGrade: testRiskMedium,
                        expectedColor: "warning",
                        messageContains: "monitoring mode",
                },
                {
                        name: "Medium Risk — SPF + DMARC but no DKIM",
                        results: map[string]any{
                                "spf_analysis":     map[string]any{"status": "success"},
                                "dmarc_analysis":   map[string]any{"status": "success", "policy": "reject"},
                                "dkim_analysis":    map[string]any{},
                                "mta_sts_analysis": map[string]any{},
                                "tlsrpt_analysis":  map[string]any{},
                                "bimi_analysis":    map[string]any{},
                                "dane_analysis":    map[string]any{},
                                "caa_analysis":     map[string]any{},
                                "dnssec_analysis":  map[string]any{},
                        },
                        expectedGrade: testRiskMedium,
                        expectedColor: "warning",
                        messageContains: "DKIM not verified",
                },
                {
                        name: "High Risk — SPF only, no DMARC",
                        results: map[string]any{
                                "spf_analysis":     map[string]any{"status": "success"},
                                "dmarc_analysis":   map[string]any{},
                                "dkim_analysis":    map[string]any{},
                                "mta_sts_analysis": map[string]any{},
                                "tlsrpt_analysis":  map[string]any{},
                                "bimi_analysis":    map[string]any{},
                                "dane_analysis":    map[string]any{},
                                "caa_analysis":     map[string]any{},
                                "dnssec_analysis":  map[string]any{},
                        },
                        expectedGrade: "High Risk",
                        expectedColor: "warning",
                        messageContains: "DMARC",
                },
                {
                        name: "Critical Risk — nothing configured",
                        results: map[string]any{
                                "spf_analysis":     map[string]any{},
                                "dmarc_analysis":   map[string]any{},
                                "dkim_analysis":    map[string]any{},
                                "mta_sts_analysis": map[string]any{},
                                "tlsrpt_analysis":  map[string]any{},
                                "bimi_analysis":    map[string]any{},
                                "dane_analysis":    map[string]any{},
                                "caa_analysis":     map[string]any{},
                                "dnssec_analysis":  map[string]any{},
                        },
                        expectedGrade: testRiskCritical,
                        expectedColor: "danger",
                        messageContains: "fully vulnerable",
                },
        }

        a := newTestAnalyzer()
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        posture := a.CalculatePosture(tt.results)
                        state, _ := posture["state"].(string)
                        if !strings.HasPrefix(state, tt.expectedGrade) {
                                t.Errorf("expected state starting with %s, got %v", tt.expectedGrade, state)
                        }
                        if posture["color"] != tt.expectedColor {
                                t.Errorf("expected color %s, got %v", tt.expectedColor, posture["color"])
                        }
                        label, _ := posture["message"].(string)
                        if !strings.Contains(strings.ToLower(label), strings.ToLower(tt.messageContains)) {
                                t.Errorf("expected message containing %q, got %q", tt.messageContains, label)
                        }
                })
        }
}

func TestRemediationTopFixes(t *testing.T) {
        a := newTestAnalyzer()

        results := map[string]any{
                "spf_analysis":     map[string]any{},
                "dmarc_analysis":   map[string]any{},
                "dkim_analysis":    map[string]any{},
                "mta_sts_analysis": map[string]any{},
                "tlsrpt_analysis":  map[string]any{},
                "bimi_analysis":    map[string]any{},
                "dane_analysis":    map[string]any{},
                "caa_analysis":     map[string]any{},
                "dnssec_analysis":  map[string]any{},
        }

        remediation := a.GenerateRemediation(results)
        topFixes, ok := remediation["top_fixes"].([]map[string]any)
        if !ok {
                t.Fatal("top_fixes is not []map[string]any")
        }
        if len(topFixes) != 3 {
                t.Errorf("expected 3 top fixes, got %d", len(topFixes))
        }

        for _, fix := range topFixes {
                severity, _ := fix["severity_label"].(string)
                if severity != "Critical" && severity != "High" && severity != "Medium" && severity != "Low" {
                        t.Errorf("unexpected severity: %s", severity)
                }
                rfcURL, _ := fix["rfc_url"].(string)
                if rfcURL == "" {
                        t.Error("expected non-empty rfc_url")
                }
                if !strings.Contains(rfcURL, "#section") {
                        t.Errorf("RFC URL should link to specific section: %s", rfcURL)
                }
        }

        if topFixes[0]["severity_label"] != "Critical" {
                t.Errorf("first fix should be Critical severity, got %v", topFixes[0]["severity_label"])
        }
}

func TestRemediationFullySecure(t *testing.T) {
        a := newTestAnalyzer()

        results := map[string]any{
                "spf_analysis":     map[string]any{"status": "success", "all_mechanism": "-all"},
                "dmarc_analysis":   map[string]any{"status": "success", "policy": "reject"},
                "dkim_analysis":    map[string]any{"status": "success"},
                "mta_sts_analysis": map[string]any{"status": "success"},
                "tlsrpt_analysis":  map[string]any{"status": "success"},
                "bimi_analysis":    map[string]any{"status": "success"},
                "dane_analysis":    map[string]any{"has_dane": true},
                "caa_analysis":     map[string]any{"status": "success"},
                "dnssec_analysis":  map[string]any{"status": "success"},
        }

        remediation := a.GenerateRemediation(results)
        topFixes, ok := remediation["top_fixes"].([]map[string]any)
        if !ok {
                t.Fatal("top_fixes is not []map[string]any")
        }
        if len(topFixes) != 0 {
                t.Errorf("fully secure domain should have 0 fixes, got %d", len(topFixes))
        }
        if remediation["posture_achievable"] != "Secure" {
                t.Errorf("expected achievable Secure, got %v", remediation["posture_achievable"])
        }
}

func TestGovernmentDomainDetection(t *testing.T) {
        a := newTestAnalyzer()

        tests := []struct {
                domain string
        }{
                {"whitehouse.gov"},
                {"army.mil"},
                {"service.gov.uk"},
                {"defence.gov.au"},
                {"canada.gc.ca"},
        }

        for _, tt := range tests {
                t.Run(tt.domain, func(t *testing.T) {
                        results := map[string]any{
                                "basic_records": map[string]any{
                                        "A":  []string{},
                                        "NS": []string{},
                                        "MX": []string{},
                                },
                                "caa_analysis":   map[string]any{},
                                "dnssec_analysis": map[string]any{},
                        }
                        infra := a.AnalyzeDNSInfrastructure(tt.domain, results)
                        if infra["is_government"] != true {
                                t.Errorf("%s should be detected as government domain", tt.domain)
                        }
                })
        }
}

func TestEnterpriseProviderDetection(t *testing.T) {
        a := newTestAnalyzer()

        tests := []struct {
                name     string
                ns       []string
                expected string
        }{
                {"Cloudflare", []string{"ns1.cloudflare.com", "ns2.cloudflare.com"}, "enterprise"},
                {"Route53", []string{"ns-123.awsdns-01.net", "ns-456.awsdns-02.org"}, "enterprise"},
                {"Azure", []string{"ns1-01.azure-dns.com", "ns2-01.azure-dns.net"}, "enterprise"},
                {"UltraDNS", []string{"udns1.ultradns.net", "udns2.ultradns.net"}, "enterprise"},
                {"CSC-NetNames", []string{"ns1.netnames.net", "ns2.netnames.net", "ns5.netnames.net", "ns6.netnames.net"}, "enterprise"},
                {"GoDaddy", []string{"ns1.domaincontrol.com", "ns2.domaincontrol.com"}, "managed"},
                {"Namecheap", []string{"ns1.registrar-servers.com", "ns2.registrar-servers.com"}, "managed"},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        results := map[string]any{
                                "basic_records": map[string]any{
                                        "A":  []string{},
                                        "NS": tt.ns,
                                        "MX": []string{},
                                },
                                "caa_analysis":    map[string]any{},
                                "dnssec_analysis": map[string]any{},
                        }
                        infra := a.AnalyzeDNSInfrastructure(testDomainExample, results)
                        if infra["provider_tier"] != tt.expected {
                                t.Errorf("expected tier %s for %s, got %v", tt.expected, tt.name, infra["provider_tier"])
                        }
                })
        }
}

func TestNonGovernmentDomainNotDetected(t *testing.T) {
        a := newTestAnalyzer()

        domains := []string{"google.com", "amazon.com", "github.io", "example.org"}

        for _, domain := range domains {
                t.Run(domain, func(t *testing.T) {
                        results := map[string]any{
                                "basic_records": map[string]any{
                                        "A":  []string{},
                                        "NS": []string{"ns1.example.com"},
                                        "MX": []string{},
                                },
                                "caa_analysis":    map[string]any{},
                                "dnssec_analysis": map[string]any{},
                        }
                        infra := a.AnalyzeDNSInfrastructure(domain, results)
                        if infra["is_government"] == true {
                                t.Errorf("%s should not be detected as government domain", domain)
                        }
                })
        }
}

func TestStrContainsAny(t *testing.T) {
        tests := []struct {
                s        string
                substrs  []string
                expected bool
        }{
                {testHelloWorld, []string{"hello"}, true},
                {testHelloWorld, []string{"WORLD"}, true},
                {testHelloWorld, []string{"foo", "bar"}, false},
                {"cloudflare.com", []string{"cloud", "azure"}, true},
                {"", []string{"anything"}, false},
                {"something", []string{}, false},
        }

        for _, tt := range tests {
                result := strContainsAny(tt.s, tt.substrs...)
                if result != tt.expected {
                        t.Errorf("strContainsAny(%q, %v) = %v, want %v", tt.s, tt.substrs, result, tt.expected)
                }
        }
}

func TestStrHasSuffix(t *testing.T) {
        tests := []struct {
                s        string
                suffixes []string
                expected bool
        }{
                {"whitehouse.gov", []string{".gov", ".mil"}, true},
                {"army.mil", []string{".gov", ".mil"}, true},
                {"google.com", []string{".gov", ".mil"}, false},
                {"service.gov.uk", []string{".gov.uk"}, true},
                {"", []string{".gov"}, false},
        }

        for _, tt := range tests {
                result := strHasSuffix(tt.s, tt.suffixes...)
                if result != tt.expected {
                        t.Errorf("strHasSuffix(%q, %v) = %v, want %v", tt.s, tt.suffixes, result, tt.expected)
                }
        }
}

func TestUniqueStrings(t *testing.T) {
        tests := []struct {
                input    []string
                expected int
        }{
                {[]string{"a", "b", "c"}, 3},
                {[]string{"a", "a", "b"}, 2},
                {[]string{"x", "x", "x"}, 1},
                {[]string{}, 0},
                {nil, 0},
        }

        for _, tt := range tests {
                result := uniqueStrings(tt.input)
                if len(result) != tt.expected {
                        t.Errorf("uniqueStrings(%v) returned %d items, want %d", tt.input, len(result), tt.expected)
                }
        }
}

func TestGetStr(t *testing.T) {
        m := map[string]any{"key": "value", "num": 42}

        if got := getStr(m, "key"); got != "value" {
                t.Errorf("getStr(m, 'key') = %q, want 'value'", got)
        }
        if got := getStr(m, "num"); got != "" {
                t.Errorf("getStr(m, 'num') = %q, want ''", got)
        }
        if got := getStr(m, "missing"); got != "" {
                t.Errorf("getStr(m, 'missing') = %q, want ''", got)
        }
}

func TestGetSlice(t *testing.T) {
        m := map[string]any{
                "strings": []string{"a", "b"},
                "anys":    []any{"c", "d"},
                "mixed":   []any{"e", 42},
                "notslice": "hello",
        }

        if got := getSlice(m, "strings"); len(got) != 2 || got[0] != "a" {
                t.Errorf("getSlice strings unexpected: %v", got)
        }
        if got := getSlice(m, "anys"); len(got) != 2 || got[0] != "c" {
                t.Errorf("getSlice anys unexpected: %v", got)
        }
        if got := getSlice(m, "mixed"); len(got) != 1 || got[0] != "e" {
                t.Errorf("getSlice mixed unexpected: %v", got)
        }
        if got := getSlice(m, "notslice"); got != nil {
                t.Errorf("getSlice notslice expected nil, got %v", got)
        }
        if got := getSlice(m, "missing"); got != nil {
                t.Errorf("getSlice missing expected nil, got %v", got)
        }
}

func TestGetBool(t *testing.T) {
        m := map[string]any{"flag": true, "off": false, "str": "true"}

        if getBool(m, "flag") != true {
                t.Error("getBool flag expected true")
        }
        if getBool(m, "off") != false {
                t.Error("getBool off expected false")
        }
        if getBool(m, "str") != false {
                t.Error("getBool str expected false")
        }
        if getBool(m, "missing") != false {
                t.Error("getBool missing expected false")
        }
}

func TestGetMap(t *testing.T) {
        sub := map[string]any{"nested": true}
        m := map[string]any{"sub": sub, "str": "hello"}

        if got := getMap(m, "sub"); got == nil || got["nested"] != true {
                t.Error("getMap sub unexpected")
        }
        if getMap(m, "str") != nil {
                t.Error("getMap str expected nil")
        }
        if getMap(m, "missing") != nil {
                t.Error("getMap missing expected nil")
        }
}

func TestPostureIssuesSeveritySeparation(t *testing.T) {
        a := newTestAnalyzer()
        results := map[string]any{
                "spf_analysis":     map[string]any{"status": "success"},
                "dmarc_analysis":   map[string]any{"status": "success", "policy": "reject"},
                "dkim_analysis":    map[string]any{"status": "success"},
                "mta_sts_analysis": map[string]any{},
                "tlsrpt_analysis":  map[string]any{},
                "bimi_analysis":    map[string]any{},
                "dane_analysis":    map[string]any{},
                "caa_analysis":     map[string]any{},
                "dnssec_analysis":  map[string]any{},
        }

        posture := a.CalculatePosture(results)

        criticalIssues, _ := posture["critical_issues"].([]string)
        if len(criticalIssues) > 0 {
                t.Errorf("Low domain should have no critical issues, got %v", criticalIssues)
        }

        absent, _ := posture["absent"].([]string)
        foundCAA := false
        for _, a := range absent {
                if a == "CAA" {
                        foundCAA = true
                }
        }
        if !foundCAA {
                t.Error("missing CAA should appear in absent list (Low severity advisory)")
        }

        state, _ := posture["state"].(string)
        if !strings.HasPrefix(state, testRiskLow) {
                t.Errorf("expected Low Risk posture with core email auth, got %v", state)
        }
}

func TestPosturePartialDMARCPctDowngrade(t *testing.T) {
        a := newTestAnalyzer()
        results := map[string]any{
                "spf_analysis":     map[string]any{"status": "success"},
                "dmarc_analysis":   map[string]any{"status": "warning", "policy": "reject", "pct": 50, "valid_records": []string{"v=DMARC1; p=reject; pct=50"}},
                "dkim_analysis":    map[string]any{"status": "success"},
                "mta_sts_analysis": map[string]any{},
                "tlsrpt_analysis":  map[string]any{},
                "bimi_analysis":    map[string]any{},
                "dane_analysis":    map[string]any{},
                "caa_analysis":     map[string]any{"status": "success"},
                "dnssec_analysis":  map[string]any{},
        }

        posture := a.CalculatePosture(results)
        state, _ := posture["state"].(string)
        if state == testRiskLow {
                t.Error("DMARC pct=50 with p=reject should NOT grade Low Risk — partial enforcement per RFC 7489 §6.3")
        }
        if state != testRiskMedium {
                t.Errorf("expected Medium Risk for partial DMARC enforcement, got %v", state)
        }
        msg, _ := posture["message"].(string)
        if !strings.Contains(msg, "partial") && !strings.Contains(msg, "pct=50") {
                t.Errorf("message should mention partial enforcement, got %q", msg)
        }
}

func TestPostureMissingDMARCRuaWarning(t *testing.T) {
        a := newTestAnalyzer()
        results := map[string]any{
                "spf_analysis":     map[string]any{"status": "success"},
                "dmarc_analysis":   map[string]any{"status": "success", "policy": "reject"},
                "dkim_analysis":    map[string]any{"status": "success"},
                "mta_sts_analysis": map[string]any{},
                "tlsrpt_analysis":  map[string]any{},
                "bimi_analysis":    map[string]any{},
                "dane_analysis":    map[string]any{},
                "caa_analysis":     map[string]any{"status": "success"},
                "dnssec_analysis":  map[string]any{},
        }

        posture := a.CalculatePosture(results)
        issues, _ := posture["issues"].([]string)
        found := false
        for _, issue := range issues {
                if strings.Contains(issue, "rua") || strings.Contains(issue, "aggregate reporting") {
                        found = true
                        break
                }
        }
        if !found {
                t.Error("expected rua missing warning in issues when DMARC has no rua configured")
        }
}

func TestPostureSPFSoftfailVsHardfail(t *testing.T) {
        a := newTestAnalyzer()

        hardfail := map[string]any{
                "spf_analysis":     map[string]any{"status": "success", "all_mechanism": "-all"},
                "dmarc_analysis":   map[string]any{"status": "success", "policy": "reject"},
                "dkim_analysis":    map[string]any{"status": "success"},
                "mta_sts_analysis": map[string]any{},
                "tlsrpt_analysis":  map[string]any{},
                "bimi_analysis":    map[string]any{},
                "dane_analysis":    map[string]any{},
                "caa_analysis":     map[string]any{"status": "success"},
                "dnssec_analysis":  map[string]any{},
        }
        softfail := map[string]any{
                "spf_analysis":     map[string]any{"status": "success", "all_mechanism": "~all"},
                "dmarc_analysis":   map[string]any{"status": "success", "policy": "reject"},
                "dkim_analysis":    map[string]any{"status": "success"},
                "mta_sts_analysis": map[string]any{},
                "tlsrpt_analysis":  map[string]any{},
                "bimi_analysis":    map[string]any{},
                "dane_analysis":    map[string]any{},
                "caa_analysis":     map[string]any{"status": "success"},
                "dnssec_analysis":  map[string]any{},
        }

        pHard := a.CalculatePosture(hardfail)
        pSoft := a.CalculatePosture(softfail)

        scoreHard, _ := pHard["score"].(int)
        scoreSoft, _ := pSoft["score"].(int)
        if scoreHard <= scoreSoft {
                t.Errorf("SPF -all (hardfail) should score higher than ~all (softfail): got %d vs %d", scoreHard, scoreSoft)
        }

        configured, _ := pSoft["configured"].([]string)
        foundSoftfail := false
        for _, c := range configured {
                if strings.Contains(c, "~all") {
                        foundSoftfail = true
                }
        }
        if !foundSoftfail {
                t.Error("SPF with ~all should show (~all) in configured list")
        }

        recommendations, _ := pSoft["recommendations"].([]string)
        issues, _ := pSoft["issues"].([]string)
        allTexts := append(recommendations, issues...)
        foundRec := false
        for _, r := range allTexts {
                if strings.Contains(r, "softfail") || strings.Contains(r, "~all") {
                        foundRec = true
                }
        }
        if foundRec {
                t.Error("SPF ~all with DMARC reject + DKIM should NOT generate a recommendation about upgrading to -all")
        }

        softfailNoDMARC := map[string]any{
                "spf_analysis":     map[string]any{"status": "success", "all_mechanism": "~all"},
                "dmarc_analysis":   map[string]any{"status": "warning", "policy": "none"},
                "dkim_analysis":    map[string]any{},
                "mta_sts_analysis": map[string]any{},
                "tlsrpt_analysis":  map[string]any{},
                "bimi_analysis":    map[string]any{},
                "dane_analysis":    map[string]any{},
                "caa_analysis":     map[string]any{},
                "dnssec_analysis":  map[string]any{},
        }
        pSoftNoDMARC := a.CalculatePosture(softfailNoDMARC)
        confNoDMARC, _ := pSoftNoDMARC["configured"].([]string)
        foundSoftfailNoDMARC := false
        for _, c := range confNoDMARC {
                if strings.Contains(c, "~all") {
                        foundSoftfailNoDMARC = true
                }
        }
        if !foundSoftfailNoDMARC {
                t.Error("SPF ~all without DMARC enforcement should still show (~all) in configured list")
        }
}

func TestPostureMissingSPFScoreZero(t *testing.T) {
        a := newTestAnalyzer()
        results := map[string]any{
                "spf_analysis":     map[string]any{"status": "warning", "valid_records": []string{}},
                "dmarc_analysis":   map[string]any{"status": "warning", "valid_records": []string{}},
                "dkim_analysis":    map[string]any{},
                "mta_sts_analysis": map[string]any{},
                "tlsrpt_analysis":  map[string]any{},
                "bimi_analysis":    map[string]any{},
                "dane_analysis":    map[string]any{},
                "caa_analysis":     map[string]any{},
                "dnssec_analysis":  map[string]any{},
        }

        posture := a.CalculatePosture(results)
        score, _ := posture["score"].(int)
        if score != 0 {
                t.Errorf("domain with all missing records should score 0, got %d", score)
        }
        state, _ := posture["state"].(string)
        if state != testRiskCritical {
                t.Errorf("domain with no email auth should be Critical Risk, got %s", state)
        }
}

func TestPostureNoMailDomainSecure(t *testing.T) {
        a := newTestAnalyzer()
        results := map[string]any{
                "spf_analysis":     map[string]any{"status": "success", "all_mechanism": "-all", "no_mail_intent": true},
                "dmarc_analysis":   map[string]any{"status": "success", "policy": "reject"},
                "dkim_analysis":    map[string]any{},
                "mta_sts_analysis": map[string]any{},
                "tlsrpt_analysis":  map[string]any{},
                "bimi_analysis":    map[string]any{},
                "dane_analysis":    map[string]any{},
                "caa_analysis":     map[string]any{},
                "dnssec_analysis":  map[string]any{},
                "has_null_mx":      true,
        }

        posture := a.CalculatePosture(results)
        state, _ := posture["state"].(string)
        if state != "Secure" {
                t.Errorf("no-mail domain with SPF -all + DMARC reject should be Secure, got %s", state)
        }
        msg, _ := posture["message"].(string)
        if !strings.Contains(msg, "No-mail") && !strings.Contains(msg, "no-mail") {
                t.Errorf("message should indicate no-mail domain, got %q", msg)
        }
}

func TestPostureNoMailDomainPartial(t *testing.T) {
        a := newTestAnalyzer()
        results := map[string]any{
                "spf_analysis":     map[string]any{"status": "success", "all_mechanism": "-all", "no_mail_intent": true},
                "dmarc_analysis":   map[string]any{},
                "dkim_analysis":    map[string]any{},
                "mta_sts_analysis": map[string]any{},
                "tlsrpt_analysis":  map[string]any{},
                "bimi_analysis":    map[string]any{},
                "dane_analysis":    map[string]any{},
                "caa_analysis":     map[string]any{},
                "dnssec_analysis":  map[string]any{},
                "has_null_mx":      true,
        }

        posture := a.CalculatePosture(results)
        state, _ := posture["state"].(string)
        if state == testRiskCritical {
                t.Error("no-mail domain with SPF -all should not be Critical Risk — it has partial no-mail protection")
        }
}

func isSPFHardfailFix(f map[string]any) bool {
        title, _ := f["title"].(string)
        return strings.Contains(title, "hard fail") || strings.Contains(title, "-all")
}

func extractAllFixes(t *testing.T, remediation map[string]any) []map[string]any {
        t.Helper()
        allFixes, ok := remediation["all_fixes"].([]map[string]any)
        if !ok {
                t.Fatal("all_fixes is not []map[string]any")
        }
        return allFixes
}

func buildSPFSoftfailResults(spf, dmarc map[string]any) map[string]any {
        return map[string]any{
                "domain":           testDomainExample,
                "spf_analysis":     spf,
                "dmarc_analysis":   dmarc,
                "dkim_analysis":    map[string]any{},
                "mta_sts_analysis": map[string]any{},
                "tlsrpt_analysis":  map[string]any{},
                "bimi_analysis":    map[string]any{},
                "dane_analysis":    map[string]any{},
                "caa_analysis":     map[string]any{},
                "dnssec_analysis":  map[string]any{},
        }
}

func findSPFHardfailFix(t *testing.T, fixes []map[string]any) map[string]any {
        t.Helper()
        for _, f := range fixes {
                if isSPFHardfailFix(f) {
                        return f
                }
        }
        return nil
}

func TestRemediationSPFSoftfailUpgrade(t *testing.T) {
        a := newTestAnalyzer()

        t.Run("enforced_dmarc_suppresses_hardfail", func(t *testing.T) {
                results := buildSPFSoftfailResults(
                        map[string]any{"status": "success", "all_mechanism": "~all"},
                        map[string]any{"status": "success", "policy": "reject"},
                )
                results["dkim_analysis"] = map[string]any{"status": "success"}
                results["mta_sts_analysis"] = map[string]any{"status": "success"}
                results["tlsrpt_analysis"] = map[string]any{"status": "success"}
                results["bimi_analysis"] = map[string]any{"status": "success"}
                results["dane_analysis"] = map[string]any{"has_dane": true}
                results["caa_analysis"] = map[string]any{"status": "success"}
                results["dnssec_analysis"] = map[string]any{"status": "success"}

                if findSPFHardfailFix(t, extractAllFixes(t, a.GenerateRemediation(results))) != nil {
                        t.Error("SPF softfail with DMARC reject + DKIM should NOT generate hardfail upgrade fix")
                }
        })

        t.Run("unenforced_dmarc_generates_hardfail", func(t *testing.T) {
                results := buildSPFSoftfailResults(
                        map[string]any{"status": "success", "all_mechanism": "~all", "includes": []string{"_spf.google.com"}},
                        map[string]any{"status": "warning", "policy": "none"},
                )

                fix := findSPFHardfailFix(t, extractAllFixes(t, a.GenerateRemediation(results)))
                if fix == nil {
                        t.Fatal("SPF softfail without DMARC enforcement should generate hardfail upgrade fix")
                }
                sev, _ := fix["severity_label"].(string)
                if sev != "Low" {
                        t.Errorf("SPF softfail-to-hardfail upgrade should be Low severity, got %s", sev)
                }
                rec, _ := fix["dns_record"].(string)
                if !strings.Contains(rec, "_spf.google.com") {
                        t.Errorf("SPF fix should use actual includes from domain, got: %s", rec)
                }
        })
}

func TestDKIMTestFlagDetection(t *testing.T) {
        record := "v=DKIM1; k=rsa; t=y; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3QFG6HUNa2TY3OwWBqo7zAmHE7GpRODsR3sFjYMmCTD8rIiPHCnWH8dRszc3E0nPA7JhZSY7oPqQVKrI7UbIU"
        keyInfo := analyzeDKIMKey(record)
        if keyInfo == nil {
                t.Fatal("analyzeDKIMKey returned nil")
        }
        testMode, _ := keyInfo["test_mode"].(bool)
        if !testMode {
                t.Error("expected test_mode=true for DKIM record with t=y flag per RFC 6376 §3.6.1")
        }
        issues, _ := keyInfo["issues"].([]string)
        foundIssue := false
        for _, issue := range issues {
                if strings.Contains(issue, "test mode") {
                        foundIssue = true
                        break
                }
        }
        if !foundIssue {
                t.Error("expected test mode issue in key analysis")
        }
}

func TestDKIMNoTestFlagNormal(t *testing.T) {
        record := "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"
        keyInfo := analyzeDKIMKey(record)
        if keyInfo == nil {
                t.Fatal("analyzeDKIMKey returned nil")
        }
        testMode, _ := keyInfo["test_mode"].(bool)
        if testMode {
                t.Error("expected test_mode=false for normal DKIM record without t=y")
        }
}

func TestDKIMInconclusiveNotAbsent(t *testing.T) {
        a := newTestAnalyzer()
        results := map[string]any{
                "spf_analysis":     map[string]any{"status": "success"},
                "dmarc_analysis":   map[string]any{"status": "success", "policy": "reject"},
                "dkim_analysis":    map[string]any{"status": "info", "primary_provider": "Unknown"},
                "mta_sts_analysis": map[string]any{},
                "tlsrpt_analysis":  map[string]any{},
                "bimi_analysis":    map[string]any{},
                "dane_analysis":    map[string]any{},
                "caa_analysis":     map[string]any{},
                "dnssec_analysis":  map[string]any{},
        }

        posture := a.CalculatePosture(results)

        monitoring, _ := posture["monitoring"].([]string)
        foundInconclusive := false
        for _, m := range monitoring {
                if strings.Contains(m, "inconclusive") {
                        foundInconclusive = true
                }
        }
        if !foundInconclusive {
                t.Errorf("DKIM with unknown provider should be 'inconclusive' in monitoring, got %v", monitoring)
        }

        absent, _ := posture["absent"].([]string)
        for _, a := range absent {
                if strings.Contains(a, "DKIM") {
                        t.Error("inconclusive DKIM should NOT be in absent list")
                }
        }

        issues, _ := posture["critical_issues"].([]string)
        for _, issue := range issues {
                if strings.Contains(issue, "No DKIM found") {
                        t.Error("inconclusive DKIM should NOT generate 'No DKIM found' issue")
                }
        }

        recs, _ := posture["recommendations"].([]string)
        foundRec := false
        for _, r := range recs {
                if strings.Contains(r, "not discoverable") && strings.Contains(r, "RFC 6376") {
                        foundRec = true
                }
        }
        if !foundRec {
                t.Error("inconclusive DKIM should generate an informational recommendation citing RFC 6376")
        }
}

func TestDKIMInconclusiveGradeNotMedium(t *testing.T) {
        a := newTestAnalyzer()
        results := map[string]any{
                "spf_analysis":     map[string]any{"status": "success"},
                "dmarc_analysis":   map[string]any{"status": "success", "policy": "reject"},
                "dkim_analysis":    map[string]any{"status": "info", "primary_provider": "Unknown"},
                "mta_sts_analysis": map[string]any{},
                "tlsrpt_analysis":  map[string]any{},
                "bimi_analysis":    map[string]any{},
                "dane_analysis":    map[string]any{},
                "caa_analysis":     map[string]any{},
                "dnssec_analysis":  map[string]any{},
        }

        posture := a.CalculatePosture(results)
        state, _ := posture["state"].(string)
        if state == testRiskMedium {
                t.Errorf("inconclusive DKIM with SPF+DMARC should NOT be Medium Risk (was equating inconclusive with absent), got %s", state)
        }
        if !strings.Contains(state, "Monitoring") {
                t.Errorf("inconclusive DKIM should include Monitoring suffix, got %s", state)
        }
}

func TestDKIMNoMailDomainSkipsRemediation(t *testing.T) {
        a := newTestAnalyzer()
        results := map[string]any{
                "domain":           "nomail.example.com",
                "spf_analysis":     map[string]any{"status": "success", "all_mechanism": "-all", "no_mail_intent": true},
                "dmarc_analysis":   map[string]any{"status": "success", "policy": "reject"},
                "dkim_analysis":    map[string]any{},
                "mta_sts_analysis": map[string]any{},
                "tlsrpt_analysis":  map[string]any{},
                "bimi_analysis":    map[string]any{},
                "dane_analysis":    map[string]any{},
                "caa_analysis":     map[string]any{},
                "dnssec_analysis":  map[string]any{},
                "has_null_mx":      true,
        }

        remediation := a.GenerateRemediation(results)
        allFixes, _ := remediation["all_fixes"].([]map[string]any)
        for _, f := range allFixes {
                section, _ := f["section"].(string)
                if section == "dkim" {
                        t.Error("no-mail domain should NOT generate any DKIM remediation fix")
                }
        }

        posture := a.CalculatePosture(results)
        issues, _ := posture["critical_issues"].([]string)
        for _, issue := range issues {
                if strings.Contains(issue, "DKIM") {
                        t.Error("no-mail domain should NOT have DKIM in critical issues")
                }
        }
}

func TestDKIMInconclusiveRemediationSeverity(t *testing.T) {
        a := newTestAnalyzer()
        results := map[string]any{
                "domain":           "example.com",
                "spf_analysis":     map[string]any{"status": "success"},
                "dmarc_analysis":   map[string]any{"status": "success", "policy": "reject"},
                "dkim_analysis":    map[string]any{"status": "info", "primary_provider": "Unknown"},
                "mta_sts_analysis": map[string]any{},
                "tlsrpt_analysis":  map[string]any{},
                "bimi_analysis":    map[string]any{},
                "dane_analysis":    map[string]any{},
                "caa_analysis":     map[string]any{},
                "dnssec_analysis":  map[string]any{},
        }

        remediation := a.GenerateRemediation(results)
        allFixes, _ := remediation["all_fixes"].([]map[string]any)

        for _, f := range allFixes {
                section, _ := f["section"].(string)
                if section == "dkim" {
                        severity, _ := f["severity"].(string)
                        if severity == "Critical" || severity == "High" {
                                t.Errorf("inconclusive DKIM should NOT have %s severity — should be Low since DKIM absence cannot be confirmed (RFC 6376 §3.6.2.1)", severity)
                        }
                        title, _ := f["title"].(string)
                        if strings.Contains(title, "Configure") {
                                t.Error("inconclusive DKIM should say 'Verify' not 'Configure' — we cannot confirm DKIM is absent")
                        }
                }
        }
}
