// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// Tests for this package are maintained in the private repository.
// See the _intel.go and boundary_integrity_test.go files for the extended test suite.
package analyzer

import (
        "context"
        "os"
        "path/filepath"
        "strings"
        "testing"
        "time"
)

const errExpectedGot = "expected %q, got %q"
const providerGoogleWorkspace = "Google Workspace"

func TestEmailAnswerNoMailDomain(t *testing.T) {
        ps := protocolState{isNoMailDomain: true}
        answer := buildEmailAnswer(ps, false, false)
        if answer != "No — null MX indicates no-mail domain" {
                t.Errorf("no-mail domain should return 'No — null MX indicates no-mail domain', got: %s", answer)
        }
}

func TestEmailAnswerRejectPolicy(t *testing.T) {
        ps := protocolState{dmarcPolicy: "reject"}
        answer := buildEmailAnswer(ps, true, true)
        expected := "No — SPF and DMARC reject policy enforced"
        if answer != expected {
                t.Errorf(errExpectedGot, expected, answer)
        }
}

func TestEmailAnswerNoProtection(t *testing.T) {
        ps := protocolState{}
        answer := buildEmailAnswer(ps, false, false)
        expected := "Yes — no SPF or DMARC protection"
        if answer != expected {
                t.Errorf(errExpectedGot, expected, answer)
        }
}

func TestEmailAnswerMonitorOnly(t *testing.T) {
        ps := protocolState{dmarcPolicy: "none"}
        answer := buildEmailAnswer(ps, true, true)
        expected := "Yes — DMARC is monitor-only (p=none)"
        if answer != expected {
                t.Errorf(errExpectedGot, expected, answer)
        }
}

func TestEmailAnswerQuarantineFull(t *testing.T) {
        ps := protocolState{dmarcPolicy: "quarantine", dmarcPct: 100}
        answer := buildEmailAnswer(ps, true, true)
        expected := "Unlikely — SPF and DMARC quarantine policy enforced"
        if answer != expected {
                t.Errorf(errExpectedGot, expected, answer)
        }
}

func TestEmailAnswerSPFOnly(t *testing.T) {
        ps := protocolState{}
        answer := buildEmailAnswer(ps, true, false)
        expected := "Likely — SPF alone cannot prevent spoofing"
        if answer != expected {
                t.Errorf(errExpectedGot, expected, answer)
        }
}

func TestGoldenRuleUSAGov(t *testing.T) {
        ps := protocolState{
                dmarcPolicy: "reject",
                dmarcPct:    100,
                dmarcHasRua: true,
                spfOK:       true,
        }

        answer := buildEmailAnswer(ps, true, true)
        if answer != "No — SPF and DMARC reject policy enforced" {
                t.Errorf("usa.gov-like domain (SPF+DMARC reject, no MX) should show 'No', got: %s", answer)
        }

        verdicts := buildVerdicts(verdictInput{ps: ps, ds: DKIMProviderInferred, hasSPF: true, hasDMARC: true, hasDKIM: true})
        emailAnswer, ok := verdicts["email_answer"].(string)
        if !ok || emailAnswer == "" {
                t.Error("verdicts must contain non-empty 'email_answer' string")
        }

        brandVerdict, ok := verdicts["brand_impersonation"].(map[string]any)
        if !ok {
                t.Fatal("verdicts must contain brand_impersonation map")
        }
        brandAnswer, _ := brandVerdict["answer"].(string)
        if brandAnswer == "No" {
                t.Errorf("usa.gov-like domain (DMARC reject, no BIMI, no CAA) brand verdict should NOT be 'No', got: %s — BIMI and CAA gaps must be reflected", brandAnswer)
        }
        if brandAnswer != "Possible" {
                t.Errorf("usa.gov-like domain (DMARC reject, no BIMI, no CAA) brand verdict should be 'Possible' (RFC 7489 blocks email spoofing but no BIMI/CAA leaves visual+cert vectors open), got: %s", brandAnswer)
        }
}

func TestBrandVerdictFullProtection(t *testing.T) {
        ps := protocolState{
                dmarcPolicy: "reject",
                bimiOK:      true,
                caaOK:       true,
        }
        verdicts := make(map[string]any)
        buildBrandVerdict(ps, verdicts)
        brand := verdicts["brand_impersonation"].(map[string]any)
        if brand["answer"] != "No" {
                t.Errorf("DMARC reject + BIMI + CAA should be 'No', got: %s", brand["answer"])
        }
}

func TestBrandVerdictPartialGaps(t *testing.T) {
        ps := protocolState{
                dmarcPolicy: "reject",
                bimiOK:      true,
                caaOK:       false,
        }
        verdicts := make(map[string]any)
        buildBrandVerdict(ps, verdicts)
        brand := verdicts["brand_impersonation"].(map[string]any)
        if brand["answer"] != "Unlikely" {
                t.Errorf("DMARC reject + BIMI/VMC (no CAA) should be 'Unlikely' — reject blocks email spoofing and BIMI/VMC verifies brand identity; CAA is a secondary vector, got: %s", brand["answer"])
        }
        if brand["label"] != "Well Protected" {
                t.Errorf("expected 'Well Protected', got: %s", brand["label"])
        }
        if brand["color"] != "success" {
                t.Errorf("expected success color for Well Protected brand verdict, got: %s", brand["color"])
        }
}

func TestBrandVerdictRejectCAANoBIMI(t *testing.T) {
        ps := protocolState{
                dmarcPolicy: "reject",
                bimiOK:      false,
                caaOK:       true,
        }
        verdicts := make(map[string]any)
        buildBrandVerdict(ps, verdicts)
        brand := verdicts["brand_impersonation"].(map[string]any)
        if brand["answer"] != "Possible" {
                t.Errorf("DMARC reject + CAA (no BIMI) should be 'Possible' — email blocked but no visual brand verification, got: %s", brand["answer"])
        }
        if brand["label"] != "Mostly Protected" {
                t.Errorf("expected 'Mostly Protected', got: %s", brand["label"])
        }
}

func TestBrandVerdictRejectNoBIMINoCAA(t *testing.T) {
        ps := protocolState{
                dmarcPolicy: "reject",
                bimiOK:      false,
                caaOK:       false,
        }
        verdicts := make(map[string]any)
        buildBrandVerdict(ps, verdicts)
        brand := verdicts["brand_impersonation"].(map[string]any)
        if brand["answer"] != "Possible" {
                t.Errorf("DMARC reject without BIMI or CAA should be 'Possible' (RFC 7489 §6.3 blocks email spoofing but no BIMI/CAA leaves visual+cert vectors open), got: %s", brand["answer"])
        }
        if brand["label"] != "Partially Protected" {
                t.Errorf("expected 'Partially Protected', got: %s", brand["label"])
        }
        if brand["color"] != "warning" {
                t.Errorf("expected color 'warning' for partially protected brand, got: %s", brand["color"])
        }
}

func TestBrandVerdictQuarantineWithBIMICAA(t *testing.T) {
        ps := protocolState{
                dmarcPolicy: "quarantine",
                bimiOK:      true,
                caaOK:       true,
        }
        verdicts := make(map[string]any)
        buildBrandVerdict(ps, verdicts)
        brand := verdicts["brand_impersonation"].(map[string]any)
        if brand["answer"] != "Unlikely" {
                t.Errorf("DMARC quarantine + BIMI/VMC + CAA addresses all three brand-faking vectors — should be 'Unlikely', got: %s", brand["answer"])
        }
        if brand["label"] != "Well Protected" {
                t.Errorf("expected 'Well Protected', got: %s", brand["label"])
        }
        if brand["color"] != "success" {
                t.Errorf("expected success color for Well Protected verdict, got: %s", brand["color"])
        }
}

func TestBrandVerdictQuarantineAlone(t *testing.T) {
        ps := protocolState{
                dmarcPolicy: "quarantine",
                bimiOK:      false,
                caaOK:       false,
        }
        verdicts := make(map[string]any)
        buildBrandVerdict(ps, verdicts)
        brand := verdicts["brand_impersonation"].(map[string]any)
        if brand["answer"] != "Likely" {
                t.Errorf("DMARC quarantine without BIMI/CAA should be 'Likely' (RFC 7489 quarantine only flags mail, no brand reinforcement), got: %s", brand["answer"])
        }
}

func TestBrandVerdictDMARCNone(t *testing.T) {
        ps := protocolState{
                dmarcPolicy: "none",
                dmarcOK:     true,
        }
        verdicts := make(map[string]any)
        buildBrandVerdict(ps, verdicts)
        brand := verdicts["brand_impersonation"].(map[string]any)
        if brand["answer"] != "Likely" {
                t.Errorf("DMARC p=none should be 'Likely' (RFC 7489 monitor-only, no enforcement), got: %s", brand["answer"])
        }
        if brand["label"] != "Basic" {
                t.Errorf("expected 'Basic', got: %s", brand["label"])
        }
}

func TestBrandVerdictDMARCMissing(t *testing.T) {
        ps := protocolState{
                dmarcMissing: true,
        }
        verdicts := make(map[string]any)
        buildBrandVerdict(ps, verdicts)
        brand := verdicts["brand_impersonation"].(map[string]any)
        if brand["answer"] != "Yes" {
                t.Errorf("No DMARC should be 'Yes' (no RFC 7489 protection at all), got: %s", brand["answer"])
        }
        if brand["label"] != "Exposed" {
                t.Errorf("expected 'Exposed', got: %s", brand["label"])
        }
}

func TestProbableNoMailDetection(t *testing.T) {
        results := map[string]any{
                "basic_records": map[string]any{},
        }
        if !detectProbableNoMail(results) {
                t.Error("domain with no MX in basic_records should be detected as probable no-mail")
        }

        resultsWithMX := map[string]any{
                "basic_records": map[string]any{
                        "MX": []string{"10 mail.example.com."},
                },
        }
        if detectProbableNoMail(resultsWithMX) {
                t.Error("domain with MX records should NOT be detected as probable no-mail")
        }
}

func TestDMARCRuaDetection(t *testing.T) {
        dmarcWithRua := map[string]any{
                "status": "success",
                "policy": "reject",
                "pct":    100,
                "rua":    "mailto:dc1e127b@inbox.ondmarc.com",
        }
        _, _, _, hasRua, _, _ := evaluateDMARCState(dmarcWithRua)
        if !hasRua {
                t.Error("DMARC record with rua= should set dmarcHasRua=true")
        }

        dmarcNoRua := map[string]any{
                "status": "success",
                "policy": "reject",
                "pct":    100,
                "rua":    "",
        }
        _, _, _, hasRuaEmpty, _, _ := evaluateDMARCState(dmarcNoRua)
        if hasRuaEmpty {
                t.Error("DMARC record with empty rua should set dmarcHasRua=false")
        }

        dmarcNilRua := map[string]any{
                "status": "success",
                "policy": "reject",
                "pct":    100,
        }
        _, _, _, hasRuaNil, _, _ := evaluateDMARCState(dmarcNilRua)
        if hasRuaNil {
                t.Error("DMARC record with no rua key should set dmarcHasRua=false")
        }
}

func TestGoldenRuleNoMXDomain(t *testing.T) {
        ps := protocolState{
                dmarcPolicy:    "reject",
                dmarcPct:       100,
                isNoMailDomain: true,
        }

        answer := buildEmailAnswer(ps, true, true)
        if answer != "No — null MX indicates no-mail domain" {
                t.Errorf("no-MX domain with null MX should show no-mail answer, got: %s", answer)
        }
}

func TestGoldenRuleRemediationNotStubbed(t *testing.T) {
        a := &Analyzer{}
        results := map[string]any{
                "domain": "stub-test.example.com",
                "spf_analysis": map[string]any{
                        "status": "not_found",
                },
                "dmarc_analysis": map[string]any{
                        "status": "not_found",
                },
                "dkim_analysis": map[string]any{
                        "status": "info",
                },
                "mta_sts_analysis": map[string]any{
                        "status": "not_found",
                },
                "tlsrpt_analysis": map[string]any{
                        "status": "not_found",
                },
                "bimi_analysis": map[string]any{
                        "status": "not_found",
                },
                "dane_analysis": map[string]any{
                        "status": "not_found",
                },
                "caa_analysis": map[string]any{
                        "status": "not_found",
                },
                "dnssec_analysis": map[string]any{
                        "status": "unsigned",
                },
                "basic_records": map[string]any{
                        "MX": []string{"mx.example.com."},
                },
        }

        remediation := a.GenerateRemediation(results)

        topFixes, _ := remediation["top_fixes"].([]map[string]any)
        allFixes, _ := remediation["all_fixes"].([]map[string]any)
        fixCount, _ := remediation["fix_count"].(float64)

        if len(topFixes) == 0 {
                t.Fatal("GenerateRemediation must produce non-empty top_fixes for a domain missing SPF, DMARC, DKIM — remediation engine is stubbed")
        }
        if len(allFixes) == 0 {
                t.Fatal("GenerateRemediation must produce non-empty all_fixes — remediation engine is stubbed")
        }
        if fixCount == 0 {
                t.Fatal("GenerateRemediation must produce non-zero fix_count — remediation engine is stubbed")
        }

        firstFix := topFixes[0]
        requiredKeys := []string{"title", "fix", "severity_label", "severity_color"}
        for _, key := range requiredKeys {
                val, ok := firstFix[key].(string)
                if !ok || val == "" {
                        t.Errorf("top fix must have non-empty %q field", key)
                }
        }
}

func TestGoldenRuleRemediationWellConfiguredDomain(t *testing.T) {
        a := &Analyzer{}
        results := map[string]any{
                "domain": "secure.example.com",
                "spf_analysis": map[string]any{
                        "status":    "success",
                        "qualifier": "-all",
                },
                "dmarc_analysis": map[string]any{
                        "status": "success",
                        "policy": "reject",
                        "pct":    100,
                        "rua":    "mailto:dmarc@example.com",
                },
                "dkim_analysis": map[string]any{
                        "status": "success",
                },
                "mta_sts_analysis": map[string]any{
                        "status": "success",
                },
                "tlsrpt_analysis": map[string]any{
                        "status": "success",
                },
                "bimi_analysis": map[string]any{
                        "status": "success",
                },
                "dane_analysis": map[string]any{
                        "status": "success",
                },
                "caa_analysis": map[string]any{
                        "status": "success",
                },
                "dnssec_analysis": map[string]any{
                        "status": "secure",
                },
                "basic_records": map[string]any{
                        "MX": []string{"mx.example.com."},
                },
        }

        remediation := a.GenerateRemediation(results)

        allFixes, _ := remediation["all_fixes"].([]map[string]any)
        topFixes, _ := remediation["top_fixes"].([]map[string]any)

        if len(allFixes) > 3 {
                t.Errorf("well-configured domain should have very few fixes (at most 3), got %d", len(allFixes))
        }
        if len(topFixes) > 3 {
                t.Errorf("top_fixes should never exceed 3 items, got %d", len(topFixes))
        }
}

func TestGoldenRuleRemediationProviderAware(t *testing.T) {
        daneResult := providerSupportsDANE("")
        if !daneResult {
                t.Fatal("providerSupportsDANE must return true for empty/unknown provider — benefit of the doubt")
        }
        bimiResult := providerSupportsBIMI("")
        if !bimiResult {
                t.Fatal("providerSupportsBIMI must return true for empty/unknown provider — benefit of the doubt")
        }

        a := &Analyzer{}
        results := map[string]any{
                "domain": "example.com",
                "spf_analysis": map[string]any{
                        "status":        "success",
                        "record":        "v=spf1 include:_spf.google.com ~all",
                        "all_mechanism": "~all",
                },
                "dmarc_analysis": map[string]any{
                        "status": "success",
                        "policy": "reject",
                        "pct":    100,
                        "rua":    "mailto:dmarc@example.com",
                },
                "dkim_analysis": map[string]any{
                        "status":           "success",
                        "has_dkim":         true,
                        "primary_provider": "Self-hosted",
                },
                "mta_sts_analysis": map[string]any{
                        "status": "success",
                },
                "tlsrpt_analysis": map[string]any{
                        "status": "success",
                },
                "bimi_analysis": map[string]any{
                        "status": "success",
                },
                "dane_analysis": map[string]any{
                        "status":   "info",
                        "has_dane": false,
                },
                "dnssec_analysis": map[string]any{
                        "status": "success",
                },
                "caa_analysis": map[string]any{
                        "status": "success",
                },
                "basic_records": map[string]any{
                        "MX": []string{"mail.example.com."},
                },
        }

        remediation := a.GenerateRemediation(results)
        allFixes, _ := remediation["all_fixes"].([]map[string]any)

        for _, f := range allFixes {
                title, _ := f["title"].(string)
                if strings.Contains(title, "Upgrading SPF to -all") {
                        t.Fatalf("Remediation must never suggest upgrading from ~all to -all — ~all is best practice with DMARC reject. Got: %q", title)
                }
        }

        posture := a.CalculatePosture(results)
        monitoring, _ := posture["monitoring"].([]string)
        for _, m := range monitoring {
                if strings.Contains(m, "consider upgrading to hard fail") || strings.Contains(m, "consider upgrading to -all") {
                        t.Fatalf("Posture monitoring must never suggest upgrading from ~all to -all — ~all is industry-standard with DMARC reject (RFC 7489). Got: %q", m)
                }
        }
        recommendations, _ := posture["recommendations"].([]string)
        for _, r := range recommendations {
                if strings.Contains(r, "consider upgrading to hard fail") || strings.Contains(r, "consider upgrading to -all") {
                        t.Fatalf("Posture recommendations must never suggest upgrading from ~all to -all — ~all is industry-standard with DMARC reject (RFC 7489). Got: %q", r)
                }
        }
}

func TestGoldenRuleHostedProviderNoDANE(t *testing.T) {
        a := &Analyzer{}
        hostedResults := map[string]any{
                "domain": "example.com",
                "spf_analysis": map[string]any{
                        "status":        "success",
                        "record":        "v=spf1 include:_spf.google.com ~all",
                        "all_mechanism": "~all",
                },
                "dmarc_analysis": map[string]any{
                        "status": "success",
                        "policy": "reject",
                        "pct":    100,
                        "rua":    "mailto:dmarc@example.com",
                },
                "dkim_analysis": map[string]any{
                        "status":           "success",
                        "has_dkim":         true,
                        "primary_provider": providerGoogleWorkspace,
                },
                "mta_sts_analysis": map[string]any{
                        "status": "success",
                },
                "tlsrpt_analysis": map[string]any{
                        "status": "success",
                },
                "bimi_analysis": map[string]any{
                        "status":   "info",
                        "has_bimi": false,
                },
                "dane_analysis": map[string]any{
                        "status":   "info",
                        "has_dane": false,
                },
                "dnssec_analysis": map[string]any{
                        "status": "secure",
                },
                "caa_analysis": map[string]any{
                        "status": "success",
                },
                "basic_records": map[string]any{
                        "MX": []string{"aspmx.l.google.com."},
                },
        }

        remediation := a.GenerateRemediation(hostedResults)
        allFixes, _ := remediation["all_fixes"].([]map[string]any)

        for _, f := range allFixes {
                title, _ := f["title"].(string)
                if strings.Contains(title, "DANE") || strings.Contains(title, "TLSA") {
                        t.Fatalf("Remediation must NOT recommend DANE/TLSA for hosted email providers (Google Workspace) — they don't support inbound DANE. Got: %q", title)
                }
        }

        if !isHostedEmailProvider(providerGoogleWorkspace) {
                t.Fatal("isHostedEmailProvider must return true for 'Google Workspace' — it is a hosted provider that cannot deploy inbound DANE")
        }

        hostedProviders := []string{providerGoogleWorkspace, "Microsoft 365", "Zoho Mail"}
        for _, p := range hostedProviders {
                if providerSupportsDANE(p) {
                        t.Fatalf("providerSupportsDANE must return false for hosted provider %q — hosted providers cannot deploy inbound DANE", p)
                }
        }
}

func TestGoldenRuleBIMIRecommendedRegardlessOfProvider(t *testing.T) {
        providers := []string{providerGoogleWorkspace, "Microsoft 365", "Zoho Mail", "Fastmail", "ProtonMail", "Self-hosted"}
        for _, provider := range providers {
                t.Run(provider, func(t *testing.T) {
                        a := &Analyzer{}
                        results := map[string]any{
                                "domain": "example.com",
                                "spf_analysis": map[string]any{
                                        "status":        "success",
                                        "record":        "v=spf1 include:example.com ~all",
                                        "all_mechanism": "~all",
                                },
                                "dmarc_analysis": map[string]any{
                                        "status": "success",
                                        "policy": "reject",
                                        "pct":    100,
                                        "rua":    "mailto:dmarc@example.com",
                                },
                                "dkim_analysis": map[string]any{
                                        "status":           "success",
                                        "has_dkim":         true,
                                        "primary_provider": provider,
                                },
                                "mta_sts_analysis": map[string]any{
                                        "status": "success",
                                },
                                "tlsrpt_analysis": map[string]any{
                                        "status": "success",
                                },
                                "bimi_analysis": map[string]any{
                                        "status":   "info",
                                        "has_bimi": false,
                                },
                                "dane_analysis": map[string]any{
                                        "status":   "info",
                                        "has_dane": false,
                                },
                                "dnssec_analysis": map[string]any{
                                        "status": "secure",
                                },
                                "caa_analysis": map[string]any{
                                        "status": "success",
                                },
                                "basic_records": map[string]any{
                                        "MX": []string{"mail.example.com."},
                                },
                        }

                        remediation := a.GenerateRemediation(results)
                        allFixes, _ := remediation["all_fixes"].([]map[string]any)

                        foundBIMI := false
                        for _, f := range allFixes {
                                title, _ := f["title"].(string)
                                if strings.Contains(title, "BIMI") {
                                        foundBIMI = true
                                }
                        }
                        if !foundBIMI {
                                t.Fatalf("BIMI must be recommended for any provider with DMARC reject — BIMI is receiver-side (Gmail, Apple Mail, Yahoo verify it), sending provider %q is irrelevant", provider)
                        }
                })
        }
}

func TestGoldenRuleMailPostureNotStubbed(t *testing.T) {
        results := map[string]any{
                "domain": "test.example.com",
                "spf_analysis": map[string]any{
                        "status": "not_found",
                },
                "dmarc_analysis": map[string]any{
                        "status": "not_found",
                },
                "dkim_analysis": map[string]any{
                        "status": "info",
                },
                "mta_sts_analysis": map[string]any{
                        "status": "not_found",
                },
                "tlsrpt_analysis": map[string]any{
                        "status": "not_found",
                },
                "basic_records": map[string]any{
                        "MX": []string{"mx.example.com."},
                },
        }

        mp := buildMailPosture(results)

        classification, _ := mp["classification"].(string)
        label, _ := mp["label"].(string)
        color, _ := mp["color"].(string)

        if classification == "" {
                t.Fatal("buildMailPosture must return non-empty classification — mail posture engine is stubbed")
        }
        if label == "" {
                t.Fatal("buildMailPosture must return non-empty label — mail posture engine is stubbed")
        }
        if color == "" {
                t.Fatal("buildMailPosture must return non-empty color — mail posture engine is stubbed")
        }
}

func TestGoldenRuleFixToMapNotEmpty(t *testing.T) {
        f := fix{
                Title:         "Test Fix",
                Description:   "Test description",
                SeverityLevel: sevCritical,
                RFC:           "RFC 7489",
                RFCURL:        "https://example.com",
                Section:       "SPF",
        }

        m := fixToMap(f)

        if len(m) == 0 {
                t.Fatal("fixToMap must return non-empty map — function is stubbed")
        }
        if m["title"] != "Test Fix" {
                t.Errorf("fixToMap must preserve title, got %v", m["title"])
        }
        if m["severity_label"] != severityCritical {
                t.Errorf("fixToMap must preserve severity_label, got %v", m["severity_label"])
        }
}

func TestGoldenRuleStubRegistryComplete(t *testing.T) {
        knownStubFiles := map[string]bool{
                "ai_surface/http.go":           true,
                "ai_surface/http_oss.go":       true,
                "ai_surface/llms_txt.go":       true,
                "ai_surface/llms_txt_oss.go":   true,
                "ai_surface/poisoning.go":      true,
                "ai_surface/poisoning_oss.go":  true,
                "ai_surface/robots_txt.go":     true,
                "ai_surface/robots_txt_oss.go": true,
                "confidence.go":                true,
                "dkim_state.go":                true,
                "edge_cdn_oss.go":              true,
                "infrastructure.go":            true,
                "infrastructure_oss.go":        true,
                "ip_investigation.go":          true,
                "ip_investigation_oss.go":      true,
                "manifest.go":                  true,
                "manifest_oss.go":              true,
                "providers.go":                 true,
                "providers_oss.go":             true,
                "saas_txt_oss.go":              true,
        }

        analyzerDir := "."
        stubMarker := "stub implementations"

        err := filepath.Walk(analyzerDir, func(path string, info os.FileInfo, err error) error {
                if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
                        return nil
                }
                data, readErr := os.ReadFile(path)
                if readErr != nil {
                        return nil
                }
                firstLines := string(data)
                if len(firstLines) > 500 {
                        firstLines = firstLines[:500]
                }
                if strings.Contains(strings.ToLower(firstLines), stubMarker) {
                        rel := path
                        if !knownStubFiles[rel] {
                                t.Errorf("UNREGISTERED stub file detected: %s — add to knownStubFiles or implement it", rel)
                        }
                }
                return nil
        })
        if err != nil {
                t.Fatalf("failed to walk analyzer directory: %v", err)
        }

        t.Logf("Stub registry: %d files are known stubs from intel-tagged files", len(knownStubFiles))
}

func TestGoldenRuleNoProviderIntelligenceInPublicFiles(t *testing.T) {
        knownStubFiles := map[string]bool{
                "ai_surface/http.go":           true,
                "ai_surface/http_oss.go":       true,
                "ai_surface/llms_txt.go":       true,
                "ai_surface/llms_txt_oss.go":   true,
                "ai_surface/poisoning.go":      true,
                "ai_surface/poisoning_oss.go":  true,
                "ai_surface/robots_txt.go":     true,
                "ai_surface/robots_txt_oss.go": true,
                "confidence.go":                true,
                "dkim_state.go":                true,
                "edge_cdn_oss.go":              true,
                "infrastructure.go":            true,
                "infrastructure_oss.go":        true,
                "ip_investigation.go":          true,
                "ip_investigation_oss.go":      true,
                "manifest.go":                  true,
                "manifest_oss.go":              true,
                "providers.go":                 true,
                "providers_oss.go":             true,
                "saas_txt_oss.go":              true,
        }

        forbiddenPairPatterns := []string{
                `"google", "microsoft"`,
                `"google", "yahoo"`,
                `"microsoft", "yahoo"`,
                `"yahoo", "zoho"`,
                `"zoho", "fastmail"`,
                `"fastmail", "proofpoint"`,
                `"proofpoint", "mimecast"`,
                `"mimecast", "barracuda"`,
                `"barracuda", "rackspace"`,
                `"amazon ses", "sendgrid"`,
                `"sendgrid", "mailgun"`,
                `"mailgun", "postmark"`,
                `"postmark", "sparkpost"`,
                `"sparkpost", "mailchimp"`,
                `"mailchimp", "constant contact"`,
                `"google", "yahoo", "fastmail", "apple"`,
        }

        capabilityProviderNames := []string{
                "mimecast", "barracuda", "rackspace", "sparkpost",
                "constant contact", "amazon ses",
        }

        err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
                if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
                        return nil
                }
                if knownStubFiles[path] {
                        return nil
                }
                data, readErr := os.ReadFile(path)
                if readErr != nil {
                        return nil
                }
                content := string(data)
                lower := strings.ToLower(content)

                for _, pattern := range forbiddenPairPatterns {
                        if strings.Contains(lower, pattern) {
                                t.Errorf("LEAKED PROVIDER INTELLIGENCE in %s: found pattern %q — provider capability lists belong in _intel.go files only", path, pattern)
                        }
                }

                if path == "remediation.go" || path == "posture.go" || path == "scoring.go" {
                        for _, name := range capabilityProviderNames {
                                if strings.Contains(lower, `"`+name+`"`) {
                                        t.Errorf("LEAKED PROVIDER NAME in %s: found %q — provider capability data belongs in _intel.go files only", path, name)
                                }
                        }
                }

                return nil
        })
        if err != nil {
                t.Fatalf("failed to walk analyzer directory: %v", err)
        }
}

func TestGoldenRuleRemediationDelegatesProviderLogic(t *testing.T) {
        data, err := os.ReadFile("remediation.go")
        if err != nil {
                t.Fatalf("cannot read remediation.go: %v", err)
        }
        content := string(data)

        if !strings.Contains(content, "isHostedEmailProvider(") {
                t.Fatal("remediation.go must delegate DANE provider checks to isHostedEmailProvider() — do not inline provider lists")
        }
        if !strings.Contains(content, "isBIMICapableProvider(") {
                t.Fatal("remediation.go must delegate BIMI provider checks to isBIMICapableProvider() — do not inline provider lists")
        }

        forbiddenInRemediation := []string{
                `[]string{`,
                `map[string]bool{`,
                `map[string]string{`,
        }
        lines := strings.Split(content, "\n")
        inDANEFunc := false
        inBIMIFunc := false
        for _, line := range lines {
                trimmed := strings.TrimSpace(line)
                if strings.HasPrefix(trimmed, "func providerSupportsDANE") {
                        inDANEFunc = true
                }
                if strings.HasPrefix(trimmed, "func providerSupportsBIMI") {
                        inBIMIFunc = true
                }
                if (inDANEFunc || inBIMIFunc) && strings.HasPrefix(trimmed, "}") && !strings.Contains(trimmed, "{") {
                        inDANEFunc = false
                        inBIMIFunc = false
                }
                if inDANEFunc || inBIMIFunc {
                        for _, forbidden := range forbiddenInRemediation {
                                if strings.Contains(trimmed, forbidden) {
                                        t.Errorf("providerSupportsDANE/BIMI in remediation.go contains inline collection %q — delegate to providers.go stub instead", forbidden)
                                }
                        }
                }
        }
}

func TestGoldenRuleStubBoundaryFunctionsRegistered(t *testing.T) {
        knownBoundaryFunctions := []string{
                "func isHostedEmailProvider(",
                "func isBIMICapableProvider(",
                "func isKnownDKIMProvider(",
        }

        knownBoundaryFiles := map[string]bool{
                "ai_surface/http.go":           true,
                "ai_surface/http_oss.go":       true,
                "ai_surface/llms_txt.go":       true,
                "ai_surface/llms_txt_oss.go":   true,
                "ai_surface/poisoning.go":      true,
                "ai_surface/poisoning_oss.go":  true,
                "ai_surface/robots_txt.go":     true,
                "ai_surface/robots_txt_oss.go": true,
                "confidence.go":                true,
                "dkim_state.go":                true,
                "edge_cdn_oss.go":              true,
                "infrastructure.go":            true,
                "infrastructure_oss.go":        true,
                "ip_investigation.go":          true,
                "ip_investigation_oss.go":      true,
                "manifest.go":                  true,
                "manifest_oss.go":              true,
                "providers.go":                 true,
                "providers_oss.go":             true,
                "saas_txt_oss.go":              true,
        }

        providerFuncPattern := "func is"
        providerFuncSuffix := "Provider("

        err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
                if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
                        return nil
                }
                if knownBoundaryFiles[path] {
                        return nil
                }
                if strings.HasSuffix(path, "_intel.go") {
                        return nil
                }
                data, readErr := os.ReadFile(path)
                if readErr != nil {
                        return nil
                }
                content := string(data)

                for _, fn := range knownBoundaryFunctions {
                        if strings.Contains(content, fn) {
                                t.Errorf("BOUNDARY FUNCTION %s found in non-boundary file %s — intelligence boundary functions must only be defined in stub or intel files", fn, path)
                        }
                }

                for _, line := range strings.Split(content, "\n") {
                        trimmed := strings.TrimSpace(line)
                        if strings.HasPrefix(trimmed, providerFuncPattern) && strings.Contains(trimmed, providerFuncSuffix) {
                                t.Errorf("UNREGISTERED PROVIDER FUNCTION in non-boundary file %s: %q — provider capability functions must be defined in stub or intel files only", path, trimmed)
                        }
                }

                return nil
        })
        if err != nil {
                t.Fatalf("failed to walk analyzer directory: %v", err)
        }

        stubFiles := []string{"providers.go", "providers_oss.go"}
        var combinedStub strings.Builder
        for _, sf := range stubFiles {
                data, err := os.ReadFile(sf)
                if err != nil {
                        continue
                }
                combinedStub.Write(data)
                combinedStub.WriteByte('\n')
        }
        stubContent := combinedStub.String()
        for _, fn := range knownBoundaryFunctions {
                if !strings.Contains(stubContent, fn) {
                        t.Errorf("providers boundary missing function %s — stub must define all intelligence boundary functions", fn)
                }
        }
}

func TestGoldenRuleWildcardCTDetection(t *testing.T) {
        entries := []ctEntry{
                {NameValue: "*.example.com\nexample.com", NotBefore: "2025-01-01", NotAfter: "2027-01-01", IssuerName: "C=US, O=Let's Encrypt, CN=E6"},
                {NameValue: "*.example.com\nexample.com", NotBefore: "2024-06-01", NotAfter: "2024-12-01", IssuerName: "C=US, O=Google Trust Services, CN=AE1"},
        }

        wc := detectWildcardCerts(entries, "example.com")
        if wc == nil {
                t.Fatal("wildcard certs must be detected when CT entries contain *.domain")
        }
        if !wc["present"].(bool) {
                t.Error("wildcard_certs.present must be true")
        }
        if wc["pattern"].(string) != "*.example.com" {
                t.Errorf("wildcard pattern must be *.example.com, got %s", wc["pattern"])
        }
        if !wc["current"].(bool) {
                t.Error("wildcard_certs.current must be true when at least one cert is not expired")
        }

        subdomainSet := make(map[string]map[string]any)
        processCTEntries(entries, "example.com", subdomainSet)
        if len(subdomainSet) != 0 {
                t.Errorf("wildcard-only CT entries must produce 0 explicit subdomains, got %d", len(subdomainSet))
        }
}

func TestGoldenRuleWildcardNotFalsePositive(t *testing.T) {
        entries := []ctEntry{
                {NameValue: "mail.example.com", NotBefore: "2025-01-01", NotAfter: "2026-01-01", IssuerName: "CN=E6"},
                {NameValue: "www.example.com", NotBefore: "2025-01-01", NotAfter: "2026-01-01", IssuerName: "CN=E6"},
        }

        wc := detectWildcardCerts(entries, "example.com")
        if wc != nil {
                t.Error("wildcard detection must not fire when no wildcard entries exist")
        }

        subdomainSet := make(map[string]map[string]any)
        processCTEntries(entries, "example.com", subdomainSet)
        if len(subdomainSet) != 2 {
                t.Errorf("expected 2 explicit subdomains, got %d", len(subdomainSet))
        }
        if _, ok := subdomainSet["mail.example.com"]; !ok {
                t.Error("mail.example.com must be in subdomainSet")
        }
        if _, ok := subdomainSet["www.example.com"]; !ok {
                t.Error("www.example.com must be in subdomainSet")
        }
}

func TestGoldenRuleSubdomainDiscoveryUnder60s(t *testing.T) {
        if testing.Short() {
                t.Skip("skipping network-dependent test in short mode")
        }
        if os.Getenv("CI") != "" {
                t.Skip("skipping network-dependent test in CI")
        }

        a := New(WithInitialIANAFetch(false))
        ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
        defer cancel()

        start := time.Now()
        result := a.DiscoverSubdomains(ctx, "it-help.tech")
        elapsed := time.Since(start)

        if elapsed >= 60*time.Second {
                t.Fatalf("subdomain discovery took %s — must complete under 60 seconds", elapsed)
        }

        status, _ := result["status"].(string)
        if status != "success" {
                t.Errorf("subdomain discovery status must be 'success', got %q", status)
        }

        subs, _ := result["subdomains"].([]map[string]any)
        if len(subs) == 0 {
                t.Fatal("subdomain discovery must find at least one subdomain for it-help.tech")
        }

        for _, sd := range subs {
                name, _ := sd["name"].(string)
                if name == "" {
                        t.Error("subdomain entry has empty or missing name")
                }
                if !strings.HasSuffix(name, ".it-help.tech") {
                        t.Errorf("subdomain %q does not belong to it-help.tech", name)
                }
        }

        t.Logf("subdomain discovery completed in %s — found %d subdomains", elapsed, len(subs))
}

func TestGoldenRuleSPFAncillaryCorroboration(t *testing.T) {
        tests := []struct {
                name          string
                mx            []string
                spf           string
                wantProvider  string
                wantAncillary bool
        }{
                {
                        name:         "Google MX + Google SPF = Google Workspace",
                        mx:           []string{"aspmx.l.google.com."},
                        spf:          "v=spf1 include:_spf.google.com ~all",
                        wantProvider: providerGoogleWS,
                },
                {
                        name:          "O365 MX + Google-only SPF = Microsoft 365 with ancillary note",
                        mx:            []string{"example-com.mail.protection.outlook.com."},
                        spf:           "v=spf1 include:_spf.google.com ~all",
                        wantProvider:  providerMicrosoft365,
                        wantAncillary: true,
                },
                {
                        name:          "Self-hosted MX + Google SPF = self-hosted with ancillary note",
                        mx:            []string{"mail.example.com."},
                        spf:           "v=spf1 include:_spf.google.com ~all",
                        wantProvider:  "Self-hosted",
                        wantAncillary: true,
                },
                {
                        name:         "No MX + Google SPF = Google Workspace (no MX to contradict)",
                        mx:           []string{},
                        spf:          "v=spf1 include:_spf.google.com ~all",
                        wantProvider: providerGoogleWS,
                },
                {
                        name:         "Google MX + no SPF = Google Workspace from MX only",
                        mx:           []string{"aspmx.l.google.com."},
                        spf:          "",
                        wantProvider: providerGoogleWS,
                },
                {
                        name:         "Proofpoint gateway + Google SPF = Google behind gateway",
                        mx:           []string{"mx01.example.pphosted.com."},
                        spf:          "v=spf1 include:_spf.google.com ~all",
                        wantProvider: providerGoogleWS,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        result := detectPrimaryMailProvider(tt.mx, tt.spf)
                        provider := result.Primary
                        note := result.SPFAncillaryNote

                        if provider != tt.wantProvider {
                                t.Errorf("provider = %q, want %q", provider, tt.wantProvider)
                        }
                        if tt.wantAncillary && note == "" {
                                t.Error("expected ancillary note but got empty string")
                        }
                        if !tt.wantAncillary && note != "" {
                                t.Errorf("unexpected ancillary note: %q", note)
                        }
                })
        }
}

func TestGoldenRuleSubdomainCurrentFirstOrdering(t *testing.T) {
        subdomains := []map[string]any{
                {"name": "zeta.example.com", "is_current": false, "first_seen": "2023-01-01"},
                {"name": "alpha.example.com", "is_current": true},
                {"name": "beta.example.com", "is_current": false, "first_seen": "2025-06-01"},
                {"name": "gamma.example.com", "is_current": true},
                {"name": "delta.example.com", "is_current": false, "first_seen": "2024-03-15"},
                {"name": "epsilon.example.com", "is_current": true},
        }

        sorted := sortSubdomainsSmartOrder(subdomains)

        lastCurrentIdx := -1
        firstHistoricalIdx := len(sorted)
        for i, sd := range sorted {
                if isCur, ok := sd["is_current"].(bool); ok && isCur {
                        lastCurrentIdx = i
                } else if i < firstHistoricalIdx {
                        firstHistoricalIdx = i
                }
        }

        if lastCurrentIdx >= firstHistoricalIdx {
                t.Fatalf("CRITICAL: current subdomains must ALL appear before historical — last current at index %d, first historical at index %d", lastCurrentIdx, firstHistoricalIdx)
        }

        for i := 0; i < firstHistoricalIdx-1; i++ {
                a := sorted[i]["name"].(string)
                b := sorted[i+1]["name"].(string)
                if a > b {
                        t.Errorf("current subdomains must be sorted alphabetically — %q before %q", a, b)
                }
        }

        for i := firstHistoricalIdx; i < len(sorted)-1; i++ {
                di, _ := sorted[i]["first_seen"].(string)
                dj, _ := sorted[i+1]["first_seen"].(string)
                if di < dj {
                        t.Errorf("historical subdomains must be sorted by date descending — %q before %q", di, dj)
                }
        }
}

func TestGoldenRuleDisplayCapNeverHidesCurrent(t *testing.T) {
        subdomains := make([]map[string]any, 0, 300)

        for i := 0; i < 220; i++ {
                subdomains = append(subdomains, map[string]any{
                        "name":       strings.Replace("sub-XXX.example.com", "XXX", strings.Repeat("a", i+1), 1),
                        "is_current": true,
                })
        }
        for i := 0; i < 80; i++ {
                subdomains = append(subdomains, map[string]any{
                        "name":       strings.Replace("old-XXX.example.com", "XXX", strings.Repeat("b", i+1), 1),
                        "is_current": false,
                        "first_seen": "2020-01-01",
                })
        }

        result := map[string]any{}
        applySubdomainDisplayCap(result, subdomains, 220)

        displayed := result["subdomains"].([]map[string]any)

        currentInDisplay := 0
        for _, sd := range displayed {
                if isCur, ok := sd["is_current"].(bool); ok && isCur {
                        currentInDisplay++
                }
        }

        if currentInDisplay != 220 {
                t.Fatalf("CRITICAL: display cap must never hide current subdomains — showed %d of 220 current", currentInDisplay)
        }

        if len(displayed) != 245 {
                t.Errorf("expected 245 displayed (220 current + 25 historical overflow), got %d", len(displayed))
        }

        if _, ok := result["display_capped"]; !ok {
                t.Error("display_capped flag must be set when total exceeds display limit")
        }
}

func TestGoldenRuleDisplayCapSmallSetUncapped(t *testing.T) {
        subdomains := make([]map[string]any, 0, 50)
        for i := 0; i < 50; i++ {
                subdomains = append(subdomains, map[string]any{
                        "name":       "sub.example.com",
                        "is_current": true,
                })
        }

        result := map[string]any{}
        applySubdomainDisplayCap(result, subdomains, 50)

        displayed := result["subdomains"].([]map[string]any)
        if len(displayed) != 50 {
                t.Errorf("small sets must not be capped — expected 50, got %d", len(displayed))
        }
        if _, ok := result["display_capped"]; ok {
                t.Error("display_capped must not be set for sets under soft cap")
        }
}

func TestGoldenRuleCTUnavailableFallbackProducesResults(t *testing.T) {
        entries := []ctEntry{}
        deduped := deduplicateCTEntries(entries)
        if len(deduped) != 0 {
                t.Error("deduplicating empty CT entries must return empty slice")
        }

        wc := detectWildcardCerts(entries, "example.com")
        if wc != nil {
                t.Error("wildcard detection must return nil for empty CT entries")
        }

        summary := buildCASummary(entries)
        if len(summary) != 0 {
                t.Error("CA summary must return empty for empty CT entries")
        }
}

func TestGoldenRulePipelineFieldsPreservedThroughSort(t *testing.T) {
        subdomains := []map[string]any{
                {
                        "name":         "current.example.com",
                        "is_current":   true,
                        "cname_target": "cdn.example.com",
                        "source":       "ct",
                        "first_seen":   "2025-01-01",
                        "cert_count":   3,
                },
                {
                        "name":       "old.example.com",
                        "is_current": false,
                        "source":     "dns",
                        "first_seen": "2023-01-01",
                },
        }

        sorted := sortSubdomainsSmartOrder(subdomains)

        for _, sd := range sorted {
                name, _ := sd["name"].(string)
                if _, ok := sd["source"]; !ok {
                        t.Errorf("CRITICAL: sort must preserve 'source' field on %s", name)
                }
                if _, ok := sd["first_seen"]; !ok {
                        t.Errorf("CRITICAL: sort must preserve 'first_seen' field on %s", name)
                }
        }

        first := sorted[0]
        if first["name"].(string) != "current.example.com" {
                t.Error("current subdomain must appear first after sort")
        }
        if _, ok := first["cname_target"]; !ok {
                t.Error("CRITICAL: sort must preserve 'cname_target' field")
        }
        if first["cert_count"] != 3 {
                t.Error("CRITICAL: sort must preserve 'cert_count' field")
        }
}

func TestGoldenRuleFreeCertAuthorityDetection(t *testing.T) {
        freeCases := []string{
                "Let's Encrypt",
                "C=US, O=Let's Encrypt, CN=R3",
                "Amazon",
                "Cloudflare Inc ECC CA-3",
                "Google Trust Services",
                "ZeroSSL",
        }
        for _, ca := range freeCases {
                if !matchesFreeCertAuthority(ca) {
                        t.Errorf("must recognize %q as free CA", ca)
                }
        }

        paidCases := []string{
                "DigiCert SHA2 Extended Validation Server CA",
                "Sectigo RSA Domain Validation Secure Server CA",
                "GeoTrust RSA CA 2018",
                "Entrust Certification Authority - L1K",
        }
        for _, ca := range paidCases {
                if matchesFreeCertAuthority(ca) {
                        t.Errorf("must NOT recognize %q as free CA", ca)
                }
        }
}

func TestGoldenRuleDKIMDelegationProviderMatching(t *testing.T) {
        cases := []struct {
                ns       string
                expected string
        }{
                {"ns-dkim.ondmarc.com", "Red Sift OnDMARC"},
                {"ns1.easydmarc.com", "EasyDMARC"},
                {"dkim.valimail.com", "Valimail"},
                {"ns.dmarcian.com", "dmarcian"},
                {"dkim.powerdmarc.com", "PowerDMARC"},
                {"ns.agari.com", "Agari (Fortra)"},
                {"dkim.socketlabs.com", "SocketLabs"},
                {"ns.proofpoint.com", "Proofpoint"},
                {"dkim.mimecast.com", "Mimecast"},
                {"unknown-provider.example.net", ""},
        }

        for _, tc := range cases {
                t.Run(tc.ns, func(t *testing.T) {
                        got := matchDKIMNSProvider([]string{tc.ns})
                        if got != tc.expected {
                                t.Errorf("for NS %s: expected provider %q, got %q", tc.ns, tc.expected, got)
                        }
                })
        }
}

func TestGoldenRuleDKIMDelegationStructure(t *testing.T) {
        d := DKIMDelegation{
                Detected:    true,
                Nameservers: []string{"ns-dkim.ondmarc.com"},
                Provider:    "Red Sift OnDMARC",
        }
        if !d.Detected {
                t.Error("Detected should be true")
        }
        if len(d.Nameservers) != 1 || d.Nameservers[0] != "ns-dkim.ondmarc.com" {
                t.Errorf("unexpected nameservers: %v", d.Nameservers)
        }
        if d.Provider != "Red Sift OnDMARC" {
                t.Errorf("unexpected provider: %s", d.Provider)
        }

        empty := DKIMDelegation{}
        if empty.Detected {
                t.Error("empty delegation should have Detected=false")
        }
}

func TestGoldenRuleSimplifyIssuer(t *testing.T) {
        cases := []struct {
                input    string
                expected string
        }{
                {`C=US, O="GoDaddy.com, Inc.", CN=Go Daddy Secure Certificate Authority - G2`, "GoDaddy.com, Inc."},
                {`C=US, O=Let's Encrypt, CN=R3`, "Let's Encrypt"},
                {`C=US, O=DigiCert Inc, CN=DigiCert SHA2 Extended Validation Server CA`, "DigiCert Inc"},
                {`CN=Some CA`, "Some CA"},
                {`C=US, ST=Arizona, L=Scottsdale, O="GoDaddy.com, Inc.", OU=http://certs.godaddy.com/repository/, CN=Go Daddy Secure Certificate Authority - G2`, "GoDaddy.com, Inc."},
                {``, ""},
                {`O=Simple Org`, "Simple Org"},
        }
        for _, tc := range cases {
                t.Run(tc.expected, func(t *testing.T) {
                        got := simplifyIssuer(tc.input)
                        if got != tc.expected {
                                t.Errorf("simplifyIssuer(%q) = %q, want %q", tc.input, got, tc.expected)
                        }
                })
        }
}

func TestGoldenRuleZohoSquareSelectors(t *testing.T) {
        for _, sel := range []string{selZoho, selZohoMail, selZmail, selSquare, selSquareup, selSQ} {
                found := false
                for _, def := range defaultDKIMSelectors {
                        if def == sel {
                                found = true
                                break
                        }
                }
                if !found {
                        t.Errorf("selector %q must be in defaultDKIMSelectors", sel)
                }
        }

        if selectorProviderMap[selZoho] != providerZohoMail {
                t.Errorf("zoho selector should map to %s", providerZohoMail)
        }
        if selectorProviderMap[selSquare] != providerSquareOnline {
                t.Errorf("square selector should map to %s", providerSquareOnline)
        }
}

func TestNoMailRemediationHasSeverityColor(t *testing.T) {
        ps := protocolState{
                isNoMailDomain: true,
                dmarcMissing:   true,
        }
        var fixes []fix
        fixes = appendNoMailHardeningFixes(fixes, ps, "example.com")
        if len(fixes) < 2 {
                t.Fatalf("expected at least 2 no-mail fixes, got %d", len(fixes))
        }
        for _, f := range fixes {
                if f.SeverityLevel.Color == "" {
                        t.Errorf("no-mail fix %q has empty SeverityLevel.Color — badge will be invisible", f.Title)
                }
                if f.SeverityLevel.Order == 0 {
                        t.Errorf("no-mail fix %q has SeverityLevel.Order 0 — will sort incorrectly", f.Title)
                }
                if f.SeverityLevel.Name != severityHigh {
                        t.Errorf("no-mail fix %q should be %s severity, got %s", f.Title, severityHigh, f.SeverityLevel.Name)
                }
        }
}

func TestProbableNoMailRemediationHasSeverityColor(t *testing.T) {
        ps := protocolState{
                probableNoMail: true,
                dmarcMissing:   true,
        }
        var fixes []fix
        fixes = appendProbableNoMailFixes(fixes, ps, "example.com")
        if len(fixes) < 2 {
                t.Fatalf("expected at least 2 probable no-mail fixes, got %d", len(fixes))
        }
        for _, f := range fixes {
                if f.SeverityLevel.Color == "" {
                        t.Errorf("probable no-mail fix %q has empty SeverityLevel.Color — badge will be invisible", f.Title)
                }
        }
}

func TestDeliberateMonitoringNoneWithRua(t *testing.T) {
        ps := protocolState{
                dmarcOK:     true,
                dmarcHasRua: true,
                spfOK:       true,
                dmarcPolicy: "none",
        }
        deliberate, msg := evaluateDeliberateMonitoring(ps, 2)
        if !deliberate {
                t.Error("p=none with rua and spfOK and 2 configured should trigger deliberate monitoring")
        }
        if msg == "" {
                t.Error("monitoring message should not be empty")
        }
}

func TestDeliberateMonitoringQuarantineFull(t *testing.T) {
        ps := protocolState{
                dmarcOK:     true,
                dmarcHasRua: true,
                spfOK:       true,
                dmarcPolicy: "quarantine",
                dmarcPct:    100,
        }
        deliberate, msg := evaluateDeliberateMonitoring(ps, 3)
        if !deliberate {
                t.Error("p=quarantine at 100% with rua should trigger deliberate deployment phase")
        }
        if msg == "" {
                t.Error("deployment phase message should not be empty")
        }
}

func TestDeliberateMonitoringQuarantinePartial(t *testing.T) {
        ps := protocolState{
                dmarcOK:     true,
                dmarcHasRua: true,
                spfOK:       true,
                dmarcPolicy: "quarantine",
                dmarcPct:    50,
        }
        deliberate, msg := evaluateDeliberateMonitoring(ps, 2)
        if !deliberate {
                t.Error("p=quarantine at 50% with rua should trigger deliberate deployment phase")
        }
        if msg == "" {
                t.Error("deployment phase message should not be empty")
        }
}

func TestDeliberateMonitoringNoRua(t *testing.T) {
        ps := protocolState{
                dmarcOK:     true,
                dmarcHasRua: false,
                spfOK:       true,
                dmarcPolicy: "none",
        }
        deliberate, _ := evaluateDeliberateMonitoring(ps, 3)
        if deliberate {
                t.Error("p=none WITHOUT rua should NOT trigger deliberate monitoring")
        }
}

func TestDeliberateMonitoringRejectNotMonitoring(t *testing.T) {
        ps := protocolState{
                dmarcOK:     true,
                dmarcHasRua: true,
                spfOK:       true,
                dmarcPolicy: "reject",
        }
        deliberate, _ := evaluateDeliberateMonitoring(ps, 5)
        if deliberate {
                t.Error("p=reject should NOT trigger monitoring phase — reject is fully enforced")
        }
}

func TestMailPostureClassificationNoMailVerified(t *testing.T) {
        mf := mailFlags{hasNullMX: true, spfDenyAll: true, dmarcReject: true, dmarcPolicy: "reject"}
        mc := classifyMailPosture(mf, 3, "example.com", protocolState{})
        if mc.classification != "no_mail_verified" {
                t.Errorf("null MX + SPF -all + DMARC reject should be no_mail_verified, got %s", mc.classification)
        }
        if !mc.isNoMail {
                t.Error("no_mail_verified should set isNoMail = true")
        }
}

func TestMailPostureClassificationNoMailPartial(t *testing.T) {
        mf := mailFlags{hasNullMX: true, spfDenyAll: true, dmarcReject: false, dmarcPolicy: "none"}
        mc := classifyMailPosture(mf, 2, "example.com", protocolState{})
        if mc.classification != "no_mail_partial" {
                t.Errorf("null MX + SPF -all but no DMARC reject should be no_mail_partial, got %s", mc.classification)
        }
        if !mc.isNoMail {
                t.Error("no_mail_partial should set isNoMail = true")
        }
}

func TestMailPostureClassificationNoMailIntent(t *testing.T) {
        mf := mailFlags{hasNullMX: false, hasMX: false, spfDenyAll: true}
        mc := classifyMailPosture(mf, 1, "example.com", protocolState{})
        if mc.classification != "no_mail_intent" {
                t.Errorf("no MX + SPF -all should be no_mail_intent, got %s", mc.classification)
        }
        if !mc.isNoMail {
                t.Error("no_mail_intent should set isNoMail = true for recommended records")
        }
}

func TestDetectMisplacedDMARCNone(t *testing.T) {
        rootTXT := []string{
                "v=spf1 include:_spf.google.com ~all",
                "google-site-verification=abc123",
        }
        result := DetectMisplacedDMARC(rootTXT)
        if result["detected"] != false {
                t.Error("should not detect misplaced DMARC when none present in root TXT")
        }
}

func TestDetectMisplacedDMARCReject(t *testing.T) {
        rootTXT := []string{
                "v=spf1 include:_spf.google.com ~all",
                "v=DMARC1;p=reject;pct=100;rua=mailto:your email address",
        }
        result := DetectMisplacedDMARC(rootTXT)
        if result["detected"] != true {
                t.Fatal("should detect misplaced DMARC record in root TXT")
        }
        if result["policy_hint"] != "reject" {
                t.Errorf("policy_hint should be reject, got %v", result["policy_hint"])
        }
        records, ok := result["records"].([]string)
        if !ok || len(records) != 1 {
                t.Fatalf("should have exactly 1 misplaced record, got %v", result["records"])
        }
        msg, _ := result["message"].(string)
        if msg == "" {
                t.Error("message should not be empty")
        }
}

func TestDetectMisplacedDMARCCaseInsensitive(t *testing.T) {
        rootTXT := []string{"V=DMARC1; p=none;"}
        result := DetectMisplacedDMARC(rootTXT)
        if result["detected"] != true {
                t.Error("should detect case-insensitive v=DMARC1")
        }
        if result["policy_hint"] != "none" {
                t.Errorf("policy_hint should be none, got %v", result["policy_hint"])
        }
}

func TestDetectMisplacedDMARCNoPolicy(t *testing.T) {
        rootTXT := []string{"v=DMARC1"}
        result := DetectMisplacedDMARC(rootTXT)
        if result["detected"] != true {
                t.Error("should detect bare v=DMARC1 record")
        }
        if result["policy_hint"] != "" {
                t.Errorf("policy_hint should be empty for bare v=DMARC1, got %v", result["policy_hint"])
        }
}

func TestMailPostureClassificationProtected(t *testing.T) {
        mf := mailFlags{hasMX: true, hasSPF: true, hasDMARC: true, hasDKIM: true, dmarcReject: true, dmarcPolicy: "reject"}
        mc := classifyMailPosture(mf, 0, "example.com", protocolState{})
        if mc.classification != "protected" {
                t.Errorf("full mail domain with all controls should be protected, got %s", mc.classification)
        }
        if mc.isNoMail {
                t.Error("protected mail domain should not be isNoMail")
        }
}
