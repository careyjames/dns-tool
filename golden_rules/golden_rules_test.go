// Copyright (c) 2024-2026 IT Help San Diego Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL — See LICENSE for terms.
// This file is part of the DNS Tool Intelligence Module.
package analyzer

import (
        "strings"
        "testing"
)

const (
        fixUpgradeSPFHardFail  = "Upgrade SPF to hard fail (-all)"
        fixAddDMARCReporting   = "Add DMARC aggregate reporting"
        providerGoogleWorkspace = "Google Workspace"
)

func baseResults() map[string]any {
        return map[string]any{
                "spf_analysis":     map[string]any{"status": "warning"},
                "dmarc_analysis":   map[string]any{"status": "warning"},
                "dkim_analysis":    map[string]any{"status": "warning"},
                "mta_sts_analysis": map[string]any{"status": "warning"},
                "tlsrpt_analysis":  map[string]any{"status": "warning"},
                "bimi_analysis":    map[string]any{"status": "warning"},
                "dane_analysis":    map[string]any{"has_dane": false},
                "caa_analysis":     map[string]any{"status": "warning"},
                "dnssec_analysis":  map[string]any{"status": "warning", "chain_of_trust": "none"},
                "has_null_mx":      false,
                "is_no_mail_domain": false,
                "domain":           "example.com",
        }
}

func withSPF(r map[string]any, status, allMech, permissiveness string) map[string]any {
        spf := map[string]any{
                "status":         status,
                "all_mechanism":  allMech,
                "permissiveness": permissiveness,
        }
        if status == "success" || (status == "warning" && allMech != "") {
                spf["valid_records"] = []string{"v=spf1 " + allMech}
        }
        r["spf_analysis"] = spf
        return r
}

func withSPFLookups(r map[string]any, count int) map[string]any {
        spf := r["spf_analysis"].(map[string]any)
        spf["lookup_count"] = count
        return r
}

func withDMARC(r map[string]any, status, policy string) map[string]any {
        dmarc := map[string]any{
                "status": status,
                "policy": policy,
        }
        if status != "warning" || policy != "" {
                dmarc["valid_records"] = []string{"v=DMARC1; p=" + policy}
        }
        r["dmarc_analysis"] = dmarc
        return r
}

func withDMARCRua(r map[string]any, rua string) map[string]any {
        dmarc := r["dmarc_analysis"].(map[string]any)
        dmarc["rua"] = rua
        return r
}

func withDMARCPct(r map[string]any, pct int) map[string]any {
        dmarc := r["dmarc_analysis"].(map[string]any)
        dmarc["pct"] = pct
        return r
}

func withDKIM(r map[string]any, status, provider string) map[string]any {
        dkim := map[string]any{
                "status":           status,
                "primary_provider": provider,
        }
        r["dkim_analysis"] = dkim
        return r
}

func withDKIMWeakKeys(r map[string]any) map[string]any {
        dkim := r["dkim_analysis"].(map[string]any)
        dkim["key_issues"] = []string{"1024-bit RSA key is weak"}
        return r
}

func withDKIMThirdPartyOnly(r map[string]any) map[string]any {
        dkim := r["dkim_analysis"].(map[string]any)
        dkim["third_party_only"] = true
        return r
}

func withDNSSEC(r map[string]any, status, chain string) map[string]any {
        r["dnssec_analysis"] = map[string]any{
                "status":         status,
                "chain_of_trust": chain,
        }
        return r
}

func withDANE(r map[string]any, hasDane bool) map[string]any {
        r["dane_analysis"] = map[string]any{"has_dane": hasDane}
        return r
}

func withCAA(r map[string]any, status string) map[string]any {
        r["caa_analysis"] = map[string]any{"status": status}
        return r
}

func withMTASTS(r map[string]any, status string) map[string]any {
        r["mta_sts_analysis"] = map[string]any{"status": status}
        return r
}

func withTLSRPT(r map[string]any, status string) map[string]any {
        r["tlsrpt_analysis"] = map[string]any{"status": status}
        return r
}

func withBIMI(r map[string]any, status string) map[string]any {
        r["bimi_analysis"] = map[string]any{"status": status}
        return r
}

func withNoMail(r map[string]any) map[string]any {
        spf := r["spf_analysis"].(map[string]any)
        spf["no_mail_intent"] = true
        r["has_null_mx"] = true
        r["is_no_mail_domain"] = true
        return r
}

func testAnalyzer() *Analyzer {
        return &Analyzer{
                maxConcurrent: 6,
                semaphore:     make(chan struct{}, 6),
                ctCache:       make(map[string]ctCacheEntry),
        }
}

func getFixTitles(remediation map[string]any) []string {
        allFixes, ok := remediation["all_fixes"].([]map[string]any)
        if !ok {
                return nil
        }
        titles := make([]string, len(allFixes))
        for i, f := range allFixes {
                titles[i], _ = f["title"].(string)
        }
        return titles
}

func hasFix(remediation map[string]any, title string) bool {
        for _, t := range getFixTitles(remediation) {
                if t == title {
                        return true
                }
        }
        return false
}

func hasFixContaining(remediation map[string]any, substr string) bool {
        for _, t := range getFixTitles(remediation) {
                if strings.Contains(t, substr) {
                        return true
                }
        }
        return false
}

func getFixSeverity(remediation map[string]any, title string) string {
        allFixes, ok := remediation["all_fixes"].([]map[string]any)
        if !ok {
                return ""
        }
        for _, f := range allFixes {
                if t, _ := f["title"].(string); t == title {
                        sev, _ := f["severity_label"].(string)
                        return sev
                }
        }
        return ""
}

func getFixSeverityContaining(remediation map[string]any, substr string) string {
        allFixes, ok := remediation["all_fixes"].([]map[string]any)
        if !ok {
                return ""
        }
        for _, f := range allFixes {
                if t, _ := f["title"].(string); strings.Contains(t, substr) {
                        sev, _ := f["severity_label"].(string)
                        return sev
                }
        }
        return ""
}

func requireFix(t *testing.T, remediation map[string]any, title string) {
        t.Helper()
        if !hasFix(remediation, title) {
                t.Errorf("expected fix %q but it was not generated. Got fixes: %v", title, getFixTitles(remediation))
        }
}

func requireFixContaining(t *testing.T, remediation map[string]any, substr string) {
        t.Helper()
        if !hasFixContaining(remediation, substr) {
                t.Errorf("expected fix containing %q but none found. Got fixes: %v", substr, getFixTitles(remediation))
        }
}

func forbidFix(t *testing.T, remediation map[string]any, title string) {
        t.Helper()
        if hasFix(remediation, title) {
                t.Errorf("fix %q should NOT be generated but it was", title)
        }
}

func forbidFixContaining(t *testing.T, remediation map[string]any, substr string) {
        t.Helper()
        if hasFixContaining(remediation, substr) {
                t.Errorf("fix containing %q should NOT be generated but it was. Got fixes: %v", substr, getFixTitles(remediation))
        }
}

func requireSeverity(t *testing.T, remediation map[string]any, title, expectedSeverity string) {
        t.Helper()
        actual := getFixSeverity(remediation, title)
        if actual == "" {
                t.Errorf("fix %q not found, cannot check severity", title)
                return
        }
        if actual != expectedSeverity {
                t.Errorf("fix %q: expected severity %q, got %q", title, expectedSeverity, actual)
        }
}

func requireSeverityContaining(t *testing.T, remediation map[string]any, substr, expectedSeverity string) {
        t.Helper()
        actual := getFixSeverityContaining(remediation, substr)
        if actual == "" {
                t.Errorf("fix containing %q not found, cannot check severity", substr)
                return
        }
        if actual != expectedSeverity {
                t.Errorf("fix containing %q: expected severity %q, got %q", substr, expectedSeverity, actual)
        }
}

func getPostureSlice(posture map[string]any, key string) []string {
        raw, ok := posture[key]
        if !ok {
                return nil
        }
        switch v := raw.(type) {
        case []string:
                return v
        case []any:
                out := make([]string, 0, len(v))
                for _, item := range v {
                        if s, ok := item.(string); ok {
                                out = append(out, s)
                        }
                }
                return out
        }
        return nil
}

func sliceContains(slice []string, substr string) bool {
        for _, s := range slice {
                if strings.Contains(s, substr) {
                        return true
                }
        }
        return false
}

func postureHas(t *testing.T, posture map[string]any, bucket, substr string) {
        t.Helper()
        items := getPostureSlice(posture, bucket)
        if !sliceContains(items, substr) {
                t.Errorf("expected %q in posture[%q], got %v", substr, bucket, items)
        }
}

func postureNotHas(t *testing.T, posture map[string]any, bucket, substr string) {
        t.Helper()
        items := getPostureSlice(posture, bucket)
        if sliceContains(items, substr) {
                t.Errorf("did NOT expect %q in posture[%q], but found it in %v", substr, bucket, items)
        }
}

func gradeEq(t *testing.T, posture map[string]any, expected string) {
        t.Helper()
        actual, _ := posture["state"].(string)
        if actual != expected {
                t.Errorf("expected grade %q, got %q", expected, actual)
        }
}

func gradeContains(t *testing.T, posture map[string]any, substr string) {
        t.Helper()
        actual, _ := posture["state"].(string)
        if !strings.Contains(actual, substr) {
                t.Errorf("expected grade containing %q, got %q", substr, actual)
        }
}

func TestGoldenRulesSPF(t *testing.T) {
        a := testAnalyzer()

        t.Run("Rule01_SPF_PlusAll_Critical", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "+all", "DANGEROUS")
                withDMARC(r, "success", "reject")
                withDKIM(r, "success", "")
                rem := a.GenerateRemediation(r)
                pos := a.CalculatePosture(r)

                requireFix(t, rem, "Fix dangerously permissive SPF")
                requireSeverity(t, rem, "Fix dangerously permissive SPF", "Critical")
                postureHas(t, pos, "configured", "SPF (+all)")
                postureHas(t, pos, "critical_issues", "anyone can send")
        })

        t.Run("Rule02_SPF_NeutralAll_High", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "?all", "NEUTRAL")
                withDMARC(r, "success", "reject")
                withDKIM(r, "success", "")
                rem := a.GenerateRemediation(r)
                pos := a.CalculatePosture(r)

                requireFix(t, rem, "Strengthen SPF enforcement")
                requireSeverity(t, rem, "Strengthen SPF enforcement", "High")
                postureHas(t, pos, "configured", "SPF (?all)")
                postureHas(t, pos, "critical_issues", "no protection")
        })

        t.Run("Rule03_SPF_SoftAll_WithDKIM_NoUpgradeFix", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "~all", "")
                withDMARC(r, "success", "reject")
                withDKIM(r, "success", "")
                rem := a.GenerateRemediation(r)

                forbidFix(t, rem, fixUpgradeSPFHardFail)
                forbidFixContaining(t, rem, "hard fail")
        })

        t.Run("Rule03b_SPF_SoftAll_WithProviderDKIM_NoUpgradeFix", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "~all", "")
                withDMARC(r, "success", "reject")
                withDKIM(r, "info", providerGoogleWorkspace)
                rem := a.GenerateRemediation(r)

                forbidFix(t, rem, fixUpgradeSPFHardFail)
        })

        t.Run("Rule04_SPF_SoftAll_NoDKIM_UpgradeFix", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "~all", "")
                withDMARC(r, "success", "reject")
                withDKIM(r, "warning", "Unknown")
                rem := a.GenerateRemediation(r)

                requireFix(t, rem, fixUpgradeSPFHardFail)
                requireSeverity(t, rem, fixUpgradeSPFHardFail, "Low")
        })

        t.Run("Rule05_SPF_HardFail_NoSPFFix", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "-all", "")
                withDMARC(r, "success", "reject")
                withDKIM(r, "success", "")
                rem := a.GenerateRemediation(r)

                forbidFixContaining(t, rem, "SPF")
        })

        t.Run("Rule06_SPF_Missing_CriticalFix", func(t *testing.T) {
                r := baseResults()
                r["spf_analysis"] = map[string]any{"status": "warning"}
                withDMARC(r, "success", "reject")
                withDKIM(r, "success", "")
                rem := a.GenerateRemediation(r)
                pos := a.CalculatePosture(r)

                requireFix(t, rem, "Publish SPF record")
                requireSeverity(t, rem, "Publish SPF record", "Critical")
                postureHas(t, pos, "absent", "SPF")
                postureHas(t, pos, "critical_issues", "No SPF")
        })

        t.Run("Rule07_SPF_LookupExceeded_MediumFix", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "~all", "")
                withSPFLookups(r, 15)
                withDMARC(r, "success", "reject")
                withDKIM(r, "success", "")
                rem := a.GenerateRemediation(r)

                requireFix(t, rem, "Reduce SPF DNS lookups")
                requireSeverity(t, rem, "Reduce SPF DNS lookups", "Medium")
        })

        t.Run("Rule08_SPF_SoftAll_NoMail_NoUpgradeFix", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "-all", "")
                withDMARC(r, "success", "reject")
                withDKIM(r, "warning", "")
                withNoMail(r)
                rem := a.GenerateRemediation(r)

                forbidFix(t, rem, fixUpgradeSPFHardFail)
        })
}

func TestGoldenRulesDMARC(t *testing.T) {
        a := testAnalyzer()

        t.Run("Rule09_DMARC_Missing_CriticalFix", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "~all", "")
                withDKIM(r, "success", "")
                rem := a.GenerateRemediation(r)
                pos := a.CalculatePosture(r)

                requireFix(t, rem, "Publish DMARC policy")
                requireSeverity(t, rem, "Publish DMARC policy", "Critical")
                postureHas(t, pos, "absent", "DMARC")
                postureHas(t, pos, "critical_issues", "No DMARC")
        })

        t.Run("Rule10_DMARC_None_HighFix", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "~all", "")
                withDMARC(r, "warning", "none")
                withDKIM(r, "success", "")
                rem := a.GenerateRemediation(r)

                requireFix(t, rem, "Escalate DMARC from monitoring to enforcement")
                requireSeverity(t, rem, "Escalate DMARC from monitoring to enforcement", "High")
        })

        t.Run("Rule11_DMARC_Quarantine_LowFix", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "~all", "")
                withDMARC(r, "success", "quarantine")
                withDKIM(r, "success", "")
                rem := a.GenerateRemediation(r)

                requireFix(t, rem, "Upgrade DMARC to reject policy")
                requireSeverity(t, rem, "Upgrade DMARC to reject policy", "Low")
        })

        t.Run("Rule12_DMARC_Reject_NoFix", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "~all", "")
                withDMARC(r, "success", "reject")
                withDKIM(r, "success", "")
                rem := a.GenerateRemediation(r)

                forbidFixContaining(t, rem, "DMARC")
        })

        t.Run("Rule13_DMARC_NoRua_MediumFix", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "~all", "")
                withDMARC(r, "success", "quarantine")
                withDKIM(r, "success", "")
                rem := a.GenerateRemediation(r)

                requireFix(t, rem, fixAddDMARCReporting)
                requireSeverity(t, rem, fixAddDMARCReporting, "Medium")
        })

        t.Run("Rule14_DMARC_HasRua_NoReportingFix", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "~all", "")
                withDMARC(r, "success", "quarantine")
                withDMARCRua(r, "mailto:reports@example.com")
                withDKIM(r, "success", "")
                rem := a.GenerateRemediation(r)

                forbidFix(t, rem, fixAddDMARCReporting)
        })
}

func TestGoldenRulesDKIM(t *testing.T) {
        a := testAnalyzer()

        t.Run("Rule15_DKIM_Found_NoFix", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "~all", "")
                withDMARC(r, "success", "reject")
                withDKIM(r, "success", "")
                rem := a.GenerateRemediation(r)

                forbidFixContaining(t, rem, "DKIM")
        })

        t.Run("Rule16_DKIM_ProviderVerified_NoFix", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "~all", "")
                withDMARC(r, "success", "reject")
                withDKIM(r, "info", providerGoogleWorkspace)
                rem := a.GenerateRemediation(r)

                forbidFixContaining(t, rem, "Configure DKIM")
                forbidFixContaining(t, rem, "Verify DKIM")
        })

        t.Run("Rule17_DKIM_WeakKeys_MediumFix", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "~all", "")
                withDMARC(r, "success", "reject")
                withDKIM(r, "success", "")
                withDKIMWeakKeys(r)
                rem := a.GenerateRemediation(r)

                requireFix(t, rem, "Upgrade weak DKIM keys")
                requireSeverity(t, rem, "Upgrade weak DKIM keys", "Medium")
        })

        t.Run("Rule18_DKIM_Inconclusive_LowFix", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "~all", "")
                withDMARC(r, "success", "reject")
                withDKIM(r, "info", "Unknown")
                rem := a.GenerateRemediation(r)
                pos := a.CalculatePosture(r)

                requireFix(t, rem, "Verify DKIM configuration")
                requireSeverity(t, rem, "Verify DKIM configuration", "Low")
                postureHas(t, pos, "monitoring", "DKIM (inconclusive)")
        })

        t.Run("Rule19_DKIM_Absent_HighFix", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "~all", "")
                withDMARC(r, "success", "reject")
                withDKIM(r, "warning", "")
                rem := a.GenerateRemediation(r)
                pos := a.CalculatePosture(r)

                requireFix(t, rem, "Configure DKIM signing")
                requireSeverity(t, rem, "Configure DKIM signing", "High")
                postureHas(t, pos, "absent", "DKIM")
        })

        t.Run("Rule20_DKIM_ThirdPartyOnly_MediumFix", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "~all", "")
                withDMARC(r, "success", "reject")
                withDKIM(r, "warning", providerGoogleWorkspace)
                withDKIMThirdPartyOnly(r)
                rem := a.GenerateRemediation(r)
                pos := a.CalculatePosture(r)

                requireFixContaining(t, rem, "Enable DKIM for")
                requireSeverityContaining(t, rem, "Enable DKIM for", "Medium")
                postureHas(t, pos, "configured", "DKIM (third-party)")
                postureNotHas(t, pos, "absent", "DKIM")
        })

        t.Run("Rule20b_DKIM_PartialStatus_ThirdPartyOnly", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "-all", "")
                withDMARC(r, "success", "reject")
                withDKIM(r, "partial", providerGoogleWorkspace)
                withDKIMThirdPartyOnly(r)
                withCAA(r, "success")
                pos := a.CalculatePosture(r)

                postureHas(t, pos, "configured", "DKIM (third-party)")
                postureNotHas(t, pos, "absent", "DKIM")

                grade, _ := pos["grade"].(string)
                if grade == riskMedium || grade == riskHigh || grade == riskCritical {
                        t.Errorf("SPF -all + DMARC reject + third-party DKIM should not be %s, got %s", riskMedium, grade)
                }

                verdicts, _ := pos["verdicts"].(map[string]any)
                emailAnswer, _ := verdicts["email_answer"].(string)
                if emailAnswer == "Partially" || emailAnswer == "Yes" {
                        t.Errorf("email_answer should be 'No' for SPF -all + DMARC reject + third-party DKIM, got %s", emailAnswer)
                }
        })

        t.Run("Rule21_DKIM_NoMail_NoFix", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "-all", "")
                withDMARC(r, "success", "reject")
                withDKIM(r, "warning", "")
                withNoMail(r)
                rem := a.GenerateRemediation(r)

                forbidFixContaining(t, rem, "DKIM")
        })
}

func TestGoldenRulesDNSSEC(t *testing.T) {
        a := testAnalyzer()

        t.Run("Rule22_DNSSEC_OK_NoFix", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "~all", "")
                withDMARC(r, "success", "reject")
                withDKIM(r, "success", "")
                withDNSSEC(r, "success", "complete")
                rem := a.GenerateRemediation(r)

                forbidFixContaining(t, rem, "DNSSEC")
        })

        t.Run("Rule23_DNSSEC_BrokenChain_CriticalFix", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "~all", "")
                withDMARC(r, "success", "reject")
                withDKIM(r, "success", "")
                withDNSSEC(r, "warning", "broken")
                rem := a.GenerateRemediation(r)

                requireFix(t, rem, "Fix broken DNSSEC chain of trust")
                requireSeverity(t, rem, "Fix broken DNSSEC chain of trust", "Critical")
        })

        t.Run("Rule24_DNSSEC_Absent_LowFix", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "~all", "")
                withDMARC(r, "success", "reject")
                withDKIM(r, "success", "")
                withDNSSEC(r, "warning", "none")
                rem := a.GenerateRemediation(r)

                requireFix(t, rem, "Enable DNSSEC")
                requireSeverity(t, rem, "Enable DNSSEC", "Low")
        })
}

func TestGoldenRulesDANE(t *testing.T) {
        a := testAnalyzer()

        t.Run("Rule25_DANE_WithoutDNSSEC_HighFix", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "~all", "")
                withDMARC(r, "success", "reject")
                withDKIM(r, "success", "")
                withDANE(r, true)
                withDNSSEC(r, "warning", "none")
                rem := a.GenerateRemediation(r)

                requireFix(t, rem, "Enable DNSSEC for DANE validation")
                requireSeverity(t, rem, "Enable DNSSEC for DANE validation", "High")
        })

        t.Run("Rule26_DANE_Absent_DNSSEC_Present_LowFix", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "~all", "")
                withDMARC(r, "success", "reject")
                withDKIM(r, "success", "")
                withDANE(r, false)
                withDNSSEC(r, "success", "complete")
                rem := a.GenerateRemediation(r)

                requireFixContaining(t, rem, "Deploy DANE")
                requireSeverityContaining(t, rem, "Deploy DANE", "Low")
        })

        t.Run("Rule27_DANE_And_DNSSEC_Both_Present_NoDANEFix", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "~all", "")
                withDMARC(r, "success", "reject")
                withDKIM(r, "success", "")
                withDANE(r, true)
                withDNSSEC(r, "success", "complete")
                rem := a.GenerateRemediation(r)

                forbidFixContaining(t, rem, "DANE")
        })

        t.Run("Rule28_DANE_And_DNSSEC_Both_Absent_NoDANEFix", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "~all", "")
                withDMARC(r, "success", "reject")
                withDKIM(r, "success", "")
                withDANE(r, false)
                withDNSSEC(r, "warning", "none")
                rem := a.GenerateRemediation(r)

                forbidFixContaining(t, rem, "DANE")
        })
}

func TestGoldenRulesCAA(t *testing.T) {
        a := testAnalyzer()

        t.Run("Rule29_CAA_Absent_LowFix", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "~all", "")
                withDMARC(r, "success", "reject")
                withDKIM(r, "success", "")
                withCAA(r, "warning")
                rem := a.GenerateRemediation(r)

                requireFix(t, rem, "Add CAA records")
                requireSeverity(t, rem, "Add CAA records", "Low")
        })

        t.Run("Rule30_CAA_Present_NoFix", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "~all", "")
                withDMARC(r, "success", "reject")
                withDKIM(r, "success", "")
                withCAA(r, "success")
                rem := a.GenerateRemediation(r)

                forbidFixContaining(t, rem, "CAA")
        })
}

func TestGoldenRulesPostureGrades(t *testing.T) {
        a := testAnalyzer()

        t.Run("Rule31_FullSecurity_SecureGrade", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "-all", "")
                withDMARC(r, "success", "reject")
                withDKIM(r, "success", "")
                withCAA(r, "success")
                withDNSSEC(r, "success", "complete")
                pos := a.CalculatePosture(r)

                gradeEq(t, pos, "Secure")
        })

        t.Run("Rule32_CoreWithReject_LowRisk", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "~all", "")
                withDMARC(r, "success", "reject")
                withDKIM(r, "success", "")
                pos := a.CalculatePosture(r)

                gradeContains(t, pos, "Low Risk")
        })

        t.Run("Rule33_CoreWithNone_MediumRiskMonitoring", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "~all", "")
                withDMARC(r, "warning", "none")
                withDKIM(r, "success", "")
                pos := a.CalculatePosture(r)

                gradeContains(t, pos, "Medium Risk")
                gradeContains(t, pos, "Monitoring")
        })

        t.Run("Rule34_SPFOnly_HighRisk", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "~all", "")
                pos := a.CalculatePosture(r)

                gradeContains(t, pos, "High Risk")
        })

        t.Run("Rule35_NothingConfigured_CriticalRisk", func(t *testing.T) {
                r := baseResults()
                pos := a.CalculatePosture(r)

                gradeContains(t, pos, "Critical Risk")
        })

        t.Run("Rule36_DMARC_None_InMonitoring_NotRecommended", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "~all", "")
                withDMARC(r, "warning", "none")
                withDKIM(r, "success", "")
                pos := a.CalculatePosture(r)

                postureHas(t, pos, "monitoring", "DMARC")
                postureHas(t, pos, "monitoring", "p=none")
        })

        t.Run("Rule37_CAA_Absent_InNotConfigured_NotRecommended", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "~all", "")
                withDMARC(r, "success", "reject")
                withDKIM(r, "success", "")
                withCAA(r, "warning")
                pos := a.CalculatePosture(r)

                postureHas(t, pos, "absent", "CAA")
                postureNotHas(t, pos, "recommendations", "CAA")
        })

        t.Run("Rule38_SPF_SoftAll_NotRecommended_WhenDKIMPresent", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "~all", "")
                withDMARC(r, "success", "reject")
                withDKIM(r, "success", "")
                pos := a.CalculatePosture(r)

                postureNotHas(t, pos, "recommendations", "SPF")
                postureNotHas(t, pos, "recommendations", "hard fail")
                postureNotHas(t, pos, "recommendations", "-all")
        })

        t.Run("Rule39_DMARC_NoRua_InRecommendations", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "~all", "")
                withDMARC(r, "success", "reject")
                withDKIM(r, "success", "")
                pos := a.CalculatePosture(r)

                postureHas(t, pos, "recommendations", "DMARC aggregate reporting")
        })
}

func TestGoldenRulesNoMail(t *testing.T) {
        a := testAnalyzer()

        t.Run("Rule40_NoMail_Secure", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "-all", "")
                withDMARC(r, "success", "reject")
                withDKIM(r, "warning", "")
                withNoMail(r)
                pos := a.CalculatePosture(r)

                gradeEq(t, pos, "Secure")
        })

        t.Run("Rule41_NoMail_NoDKIMFix", func(t *testing.T) {
                r := withSPF(baseResults(), "success", "-all", "")
                withDMARC(r, "success", "reject")
                withDKIM(r, "warning", "")
                withNoMail(r)
                rem := a.GenerateRemediation(r)

                forbidFixContaining(t, rem, "DKIM")
        })
}

// =============================================================================
// Gold Standard Domain Profiles
// =============================================================================
// These tests model the actual DNS profiles of well-known domains.
// They serve as regression guards: if a domain's real DNS changes, the test
// should fail, prompting investigation and an intentional update.
// =============================================================================

func TestGoldStandard_Cloudflare(t *testing.T) {
        // cloudflare.com DNS profile (verified 2026-02-12):
        //   MX:     cf-emailsecurity.net (Cloudflare's own gateway, not in our known gateway list)
        //   SPF:    v=spf1 ... include:_spf.google.com ... -all
        //   DMARC:  v=DMARC1; p=reject; pct=100; rua=mailto:rua@cloudflare.com,...
        //   DKIM:   No selectors found (google, google2048, default, selector1, cf1 all empty)
        //   DNSSEC: Active (DNSKEY + DS present, chain valid)
        //   CAA:    Comprehensive (11 records)
        //   MTA-STS: Not configured
        //   TLS-RPT: Not configured
        //   BIMI:   Not configured
        //
        // Provider detection path:
        //   MX "cf-emailsecurity.net" → not in mxToDKIMProvider → mxProvider=""
        //   SPF "include:_spf.google.com" → spfProvider="Google Workspace"
        //   resolveProviderWithGateway("", "Google Workspace") → provider="Google Workspace", gateway=nil
        //   No DKIM selectors → status="info", isKnownDKIMProvider=true → DKIMProviderInferred
        //
        // This is the gold standard for the "known provider, no direct DKIM selectors" pattern.

        a := testAnalyzer()

        buildCloudflareResults := func() map[string]any {
                r := baseResults()
                r["domain"] = "cloudflare.com"
                withSPF(r, "success", "-all", "")
                withDMARC(r, "success", "reject")
                withDMARCRua(r, "mailto:rua@cloudflare.com")
                withDKIM(r, "info", providerGoogleWorkspace)
                withDNSSEC(r, "success", "full")
                withCAA(r, "success")
                withMTASTS(r, "warning")
                withTLSRPT(r, "warning")
                withBIMI(r, "warning")
                return r
        }

        t.Run("Rule_CF01_Grade_Secure", func(t *testing.T) {
                r := buildCloudflareResults()
                pos := a.CalculatePosture(r)
                grade, _ := pos["grade"].(string)

                if grade != "Secure" {
                        t.Errorf("cloudflare.com grade = %q, want %q", grade, "Secure")
                }
        })

        t.Run("Rule_CF02_DKIM_ProviderInferred_Configured", func(t *testing.T) {
                r := buildCloudflareResults()
                pos := a.CalculatePosture(r)

                postureHas(t, pos, "configured", "DKIM (provider-verified)")
                postureNotHas(t, pos, "absent", "DKIM")
                postureNotHas(t, pos, "monitoring", "DKIM")
        })

        t.Run("Rule_CF03_SPF_HardFail_Configured", func(t *testing.T) {
                r := buildCloudflareResults()
                pos := a.CalculatePosture(r)

                postureHas(t, pos, "configured", "SPF (-all)")
        })

        t.Run("Rule_CF04_DMARC_Reject_Configured", func(t *testing.T) {
                r := buildCloudflareResults()
                pos := a.CalculatePosture(r)

                postureHas(t, pos, "configured", "DMARC (reject)")
        })

        t.Run("Rule_CF05_DNSSEC_Configured", func(t *testing.T) {
                r := buildCloudflareResults()
                pos := a.CalculatePosture(r)

                postureHas(t, pos, "configured", "DNSSEC")
        })

        t.Run("Rule_CF06_CAA_Configured", func(t *testing.T) {
                r := buildCloudflareResults()
                pos := a.CalculatePosture(r)

                postureHas(t, pos, "configured", "CAA")
        })

        t.Run("Rule_CF07_EmailSpoofing_No", func(t *testing.T) {
                r := buildCloudflareResults()
                pos := a.CalculatePosture(r)

                verdicts, _ := pos["verdicts"].(map[string]any)
                emailAns, _ := verdicts["email_answer"].(string)
                if emailAns != "No" {
                        t.Errorf("cloudflare.com email_answer = %q, want %q", emailAns, "No")
                }
        })

        t.Run("Rule_CF08_No_SPF_Upgrade_Fix", func(t *testing.T) {
                r := buildCloudflareResults()
                rem := a.GenerateRemediation(r)

                forbidFixContaining(t, rem, "SPF")
        })

        t.Run("Rule_CF09_No_HighSeverity_Fixes", func(t *testing.T) {
                r := buildCloudflareResults()
                rem := a.GenerateRemediation(r)

                allFixes, _ := rem["all_fixes"].([]map[string]any)
                for _, fix := range allFixes {
                        sev, _ := fix["severity_label"].(string)
                        title, _ := fix["title"].(string)
                        if sev == "High" || sev == "Critical" {
                                t.Errorf("cloudflare.com should have no High/Critical fixes, found %q (%s)", title, sev)
                        }
                }
        })

        t.Run("Rule_CF10_MTA_STS_Absent", func(t *testing.T) {
                r := buildCloudflareResults()
                pos := a.CalculatePosture(r)

                postureHas(t, pos, "absent", "MTA-STS")
        })

        t.Run("Rule_CF11_DMARC_Reporting_No_Fix", func(t *testing.T) {
                r := buildCloudflareResults()
                rem := a.GenerateRemediation(r)

                forbidFixContaining(t, rem, "DMARC aggregate reporting")
        })
}
