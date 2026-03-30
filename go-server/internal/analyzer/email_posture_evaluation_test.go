package analyzer

import (
        "testing"
)

func TestEvaluateSPFState_CB7(t *testing.T) {
        t.Run("success", func(t *testing.T) {
                spf := map[string]any{"status": "success", "record_count": 1}
                ok, warn, miss, hard, dang, neut, exceed, count := evaluateSPFState(spf)
                if !ok {
                        t.Fatal("expected ok=true")
                }
                if warn || miss || hard || dang || neut || exceed {
                        t.Fatal("expected no warning/missing/hard/danger/neutral/exceed flags for success")
                }
                if count < 0 {
                        t.Fatalf("expected non-negative count, got %d", count)
                }
        })
        t.Run("missing", func(t *testing.T) {
                spf := map[string]any{"status": "missing"}
                _, _, miss, _, _, _, _, _ := evaluateSPFState(spf)
                if !miss {
                        t.Fatal("expected missing=true")
                }
        })
        t.Run("warning", func(t *testing.T) {
                spf := map[string]any{"status": "warning", "record_count": 1}
                _, warn, _, _, _, _, _, _ := evaluateSPFState(spf)
                if !warn {
                        t.Fatal("expected warning=true")
                }
        })
        t.Run("nil", func(t *testing.T) {
                _, _, miss, _, _, _, _, _ := evaluateSPFState(nil)
                if !miss {
                        t.Fatal("expected missing=true for nil")
                }
        })
}

func TestEvaluateDMARCState_CB7(t *testing.T) {
        t.Run("success with reject", func(t *testing.T) {
                dmarc := map[string]any{
                        "status":       "success",
                        "record_count": 1,
                        "policy":       "reject",
                        "rua":          "mailto:dmarc@example.com",
                        "pct":          float64(100),
                }
                ok, warn, miss, hasRua, policy, pct := evaluateDMARCState(dmarc)
                if !ok {
                        t.Fatal("expected ok=true")
                }
                if warn {
                        t.Fatal("expected warn=false")
                }
                if miss {
                        t.Fatal("expected miss=false")
                }
                if !hasRua {
                        t.Fatal("expected hasRua=true")
                }
                if policy != "reject" {
                        t.Fatalf("expected policy=reject, got %q", policy)
                }
                if pct != 100 {
                        t.Fatalf("expected pct=100, got %d", pct)
                }
        })
        t.Run("missing", func(t *testing.T) {
                _, _, miss, _, _, _ := evaluateDMARCState(nil)
                if !miss {
                        t.Fatal("expected missing=true")
                }
        })
}

func TestEvaluateDKIMState_CB7(t *testing.T) {
        t.Run("success", func(t *testing.T) {
                dkim := map[string]any{"status": "success"}
                ok, prov, partial, weak, tpo, pp := evaluateDKIMState(dkim)
                if !ok {
                        t.Fatal("expected ok=true")
                }
                if partial || weak || tpo {
                        t.Fatal("expected no partial/weak/thirdParty flags for success")
                }
                if prov {
                        t.Fatal("expected prov=false for generic success")
                }
                if pp != "" {
                        t.Fatalf("expected empty primary provider, got %q", pp)
                }
        })
        t.Run("nil", func(t *testing.T) {
                ok, _, _, _, _, _ := evaluateDKIMState(nil)
                if ok {
                        t.Fatal("expected ok=false for nil")
                }
        })
}

func TestEvaluateSimpleProtocolState_CB7(t *testing.T) {
        m := map[string]any{"status": "success"}
        if !evaluateSimpleProtocolState(m, "status") {
                t.Fatal("expected true for success status")
        }
        m2 := map[string]any{"status": "error"}
        if evaluateSimpleProtocolState(m2, "status") {
                t.Fatal("expected false for non-success")
        }
}

func TestEvaluateDANEState_CB7(t *testing.T) {
        ps := &protocolState{}
        dane := map[string]any{"status": "success", "has_dane": true}
        evaluateDANEState(dane, ps)
        if !ps.daneOK {
                t.Fatal("expected daneOK=true")
        }

        ps2 := &protocolState{}
        evaluateDANEState(nil, ps2)
        if ps2.daneOK {
                t.Fatal("expected daneOK=false for nil")
        }
}

func TestEvaluateDNSSECState_CB7(t *testing.T) {
        ps := &protocolState{}
        dnssec := map[string]any{"status": "success", "signed": true}
        evaluateDNSSECState(dnssec, ps)
        if !ps.dnssecOK {
                t.Fatal("expected dnssecOK=true")
        }
}

func TestClassifySPF_CB7(t *testing.T) {
        t.Run("missing", func(t *testing.T) {
                ps := protocolState{spfMissing: true}
                acc := &postureAccumulator{}
                classifySPF(ps, acc)
                if len(acc.issues) == 0 {
                        t.Fatal("expected issue for missing SPF")
                }
        })
        t.Run("dangerous plus all", func(t *testing.T) {
                ps := protocolState{spfDangerous: true}
                acc := &postureAccumulator{}
                classifySPF(ps, acc)
                if len(acc.issues) == 0 {
                        t.Fatal("expected issue for dangerous SPF")
                }
        })
        t.Run("lookup exceeded", func(t *testing.T) {
                ps := protocolState{spfOK: true, spfLookupExceeded: true, spfLookupCount: 15}
                acc := &postureAccumulator{}
                classifySPF(ps, acc)
                if len(acc.issues) == 0 {
                        t.Fatal("expected issue for lookup exceeded")
                }
        })
        t.Run("neutral", func(t *testing.T) {
                ps := protocolState{spfOK: true, spfNeutral: true}
                acc := &postureAccumulator{}
                classifySPF(ps, acc)
                if len(acc.recommendations) == 0 {
                        t.Fatal("expected recommendation for neutral SPF")
                }
        })
}

func TestClassifyDMARC_CB7(t *testing.T) {
        t.Run("missing", func(t *testing.T) {
                ps := protocolState{dmarcMissing: true}
                acc := &postureAccumulator{}
                classifyDMARC(ps, acc)
                if len(acc.issues) == 0 {
                        t.Fatal("expected issue for missing DMARC")
                }
        })
        t.Run("success reject", func(t *testing.T) {
                ps := protocolState{dmarcOK: true, dmarcPolicy: "reject", dmarcPct: 100, dmarcHasRua: true}
                acc := &postureAccumulator{}
                classifyDMARC(ps, acc)
        })
        t.Run("warning", func(t *testing.T) {
                ps := protocolState{dmarcWarning: true, dmarcPolicy: "none"}
                acc := &postureAccumulator{}
                classifyDMARC(ps, acc)
                if len(acc.issues) == 0 && len(acc.recommendations) == 0 {
                        t.Fatal("expected issues or recommendations for DMARC warning")
                }
        })
}

func TestClassifyDKIMPosture_CB7(t *testing.T) {
        t.Run("provider known", func(t *testing.T) {
                acc := &postureAccumulator{}
                classifyDKIMPosture(DKIMProviderInferred, "google", acc)
        })
        t.Run("success", func(t *testing.T) {
                acc := &postureAccumulator{}
                classifyDKIMPosture(DKIMSuccess, "", acc)
        })
        t.Run("absent", func(t *testing.T) {
                acc := &postureAccumulator{}
                classifyDKIMPosture(DKIMAbsent, "", acc)
        })
        t.Run("weak keys", func(t *testing.T) {
                acc := &postureAccumulator{}
                classifyDKIMPosture(DKIMWeakKeysOnly, "", acc)
                if len(acc.issues) == 0 {
                        t.Fatal("expected issue for weak DKIM keys")
                }
        })
        t.Run("third party only", func(t *testing.T) {
                acc := &postureAccumulator{}
                classifyDKIMPosture(DKIMThirdPartyOnly, "", acc)
        })
        t.Run("no mail domain", func(t *testing.T) {
                acc := &postureAccumulator{}
                classifyDKIMPosture(DKIMNoMailDomain, "", acc)
        })
        t.Run("inconclusive", func(t *testing.T) {
                acc := &postureAccumulator{}
                classifyDKIMPosture(DKIMInconclusive, "", acc)
        })
}

func TestClassifyPresence_CB7(t *testing.T) {
        acc := &postureAccumulator{}
        classifyPresence(true, "MTA-STS", acc)
        classifyPresence(false, "MTA-STS", acc)
}

func TestComputeInternalScore_CB7(t *testing.T) {
        ps := protocolState{
                spfOK:    true,
                dmarcOK:  true,
                dkimOK:   true,
                daneOK:   true,
                dnssecOK: true,
                mtaStsOK: true,
                tlsrptOK: true,
                bimiOK:   true,
                caaOK:    true,
        }
        score := computeInternalScore(ps, DKIMSuccess)
        if score <= 0 {
                t.Fatalf("expected positive score, got %d", score)
        }
}

func TestComputeSPFScore_CB7(t *testing.T) {
        ps := protocolState{spfOK: true, spfHardFail: true}
        s := computeSPFScore(ps)
        if s <= 0 {
                t.Fatal("expected positive SPF score")
        }
}

func TestComputeDMARCScore_CB7(t *testing.T) {
        ps := protocolState{dmarcOK: true, dmarcPolicy: "reject", dmarcPct: 100, dmarcHasRua: true}
        s := computeDMARCScore(ps)
        if s <= 0 {
                t.Fatal("expected positive DMARC score")
        }
}

func TestComputeDKIMScore_CB7(t *testing.T) {
        s := computeDKIMScore(DKIMSuccess)
        if s <= 0 {
                t.Fatal("expected positive DKIM score")
        }
        s2 := computeDKIMScore(DKIMAbsent)
        if s2 > 0 {
                t.Fatal("expected zero or negative score for absent DKIM")
        }
}

func TestComputeAuxScore_CB7(t *testing.T) {
        ps := protocolState{
                daneOK:   true,
                dnssecOK: true,
                mtaStsOK: true,
                tlsrptOK: true,
                bimiOK:   true,
                caaOK:    true,
        }
        s := computeAuxScore(ps)
        if s <= 0 {
                t.Fatal("expected positive aux score")
        }
}

func TestGetNumericValue_CB7(t *testing.T) {
        m := map[string]any{"score": float64(85)}
        v := getNumericValue(m, "score")
        if v != 85 {
                t.Fatalf("expected 85, got %f", v)
        }
        v2 := getNumericValue(m, "missing")
        if v2 != 0 {
                t.Fatalf("expected 0, got %f", v2)
        }
}

func TestBuildEmailAnswer_CB7(t *testing.T) {
        ps := protocolState{spfOK: true, dmarcOK: true, dmarcPolicy: "reject"}
        result := buildEmailAnswer(ps, true, true)
        if result == "" {
                t.Fatal("expected non-empty email answer")
        }

        ps2 := protocolState{spfMissing: true, dmarcMissing: true}
        result2 := buildEmailAnswer(ps2, false, false)
        if result2 == "" {
                t.Fatal("expected non-empty email answer for missing protocols")
        }
}

func TestBuildEmailAnswerStructured_CB7(t *testing.T) {
        ps := protocolState{spfOK: true, dmarcOK: true, dmarcPolicy: "reject", dmarcPct: 100}
        m := buildEmailAnswerStructured(ps, true, true)
        if m == nil {
                t.Fatal("expected non-nil map")
        }
}

func TestClassifyDanglingDNS_CB7(t *testing.T) {
        acc := &postureAccumulator{}
        classifyDanglingDNS(map[string]any{"dangling_dns": map[string]any{"detected": false}}, acc)
        if len(acc.issues) > 0 {
                t.Fatal("expected no issues when no dangling DNS")
        }

        acc2 := &postureAccumulator{}
        classifyDanglingDNS(map[string]any{"dangling_dns": map[string]any{"detected": true}}, acc2)
}

func TestClassifySimpleProtocols_CB7(t *testing.T) {
        ps := protocolState{mtaStsOK: true, tlsrptOK: true, bimiOK: true, caaOK: true}
        acc := &postureAccumulator{}
        classifySimpleProtocols(ps, false, acc)
}

func TestClassifyDANE_CB7(t *testing.T) {
        acc := &postureAccumulator{}
        classifyDANE(protocolState{daneOK: true}, acc)
        classifyDANE(protocolState{daneOK: false}, acc)
}

func TestClassifyDNSSEC_CB7(t *testing.T) {
        acc := &postureAccumulator{}
        classifyDNSSEC(protocolState{dnssecOK: true}, acc)
        classifyDNSSEC(protocolState{dnssecOK: false}, acc)
}

func TestAppendSPFFixes_CB7(t *testing.T) {
        ps := protocolState{spfMissing: true}
        results := map[string]any{"domain": "example.com"}
        fixes := appendSPFFixes(nil, ps, DKIMAbsent, results, "example.com")
        if len(fixes) == 0 {
                t.Fatal("expected fixes for missing SPF")
        }
}

func TestAppendDMARCFixes_CB7(t *testing.T) {
        ps := protocolState{dmarcMissing: true}
        results := map[string]any{"domain": "example.com"}
        fixes := appendDMARCFixes(nil, ps, results, "example.com")
        if len(fixes) == 0 {
                t.Fatal("expected fixes for missing DMARC")
        }
}

func TestAppendDKIMFixes_CB7(t *testing.T) {
        ps := protocolState{}
        results := map[string]any{"domain": "example.com"}
        fixes := appendDKIMFixes(nil, ps, DKIMAbsent, results, "example.com")
        if len(fixes) == 0 {
                t.Fatal("expected fixes for absent DKIM")
        }
}

func TestWeakKeysFix_CB7(t *testing.T) {
        f := weakKeysFix("example.com")
        if f.Title == "" {
                t.Fatal("expected non-empty title")
        }
}

func TestAppendCAAFixes_CB7(t *testing.T) {
        ps := protocolState{caaOK: false}
        fixes := appendCAAFixes(nil, ps, "example.com")
        if len(fixes) == 0 {
                t.Fatal("expected CAA fixes")
        }
}

func TestAppendMTASTSFixes_CB7(t *testing.T) {
        ps := protocolState{mtaStsOK: false}
        fixes := appendMTASTSFixes(nil, ps, "example.com")
        if len(fixes) == 0 {
                t.Fatal("expected MTA-STS fixes")
        }
}

func TestAppendTLSRPTFixes_CB7(t *testing.T) {
        ps := protocolState{tlsrptOK: false}
        fixes := appendTLSRPTFixes(nil, ps, "example.com")
        if len(fixes) == 0 {
                t.Fatal("expected TLS-RPT fixes")
        }
}

func TestAppendSPFLookupFix_CB7(t *testing.T) {
        ps := protocolState{spfLookupExceeded: true, spfLookupCount: 15}
        fixes := appendSPFLookupFix(nil, ps)
        if len(fixes) == 0 {
                t.Fatal("expected lookup fix")
        }
}

func TestAppendSPFUpgradeFix_CB7(t *testing.T) {
        ps := protocolState{spfOK: true, spfWarning: true}
        fixes := appendSPFUpgradeFix(nil, ps, DKIMSuccess, "example.com", []string{"_spf.google.com"})
        _ = fixes
}

func TestClassifyDKIMState_CB7(t *testing.T) {
        ps := protocolState{dkimOK: true}
        ds := classifyDKIMState(ps)
        if ds == DKIMAbsent {
                t.Fatal("expected non-absent DKIM state")
        }

        ps2 := protocolState{dkimProvider: true}
        ds2 := classifyDKIMState(ps2)
        if ds2 != DKIMProviderInferred {
                t.Fatalf("expected DKIMProviderInferred, got %v", ds2)
        }

        ps3 := protocolState{dkimPartial: true}
        ds3 := classifyDKIMState(ps3)
        if ds3 != DKIMThirdPartyOnly {
                t.Fatalf("expected DKIMThirdPartyOnly, got %v", ds3)
        }

        ps4 := protocolState{dkimWeakKeys: true}
        ds4 := classifyDKIMState(ps4)
        if ds4 != DKIMWeakKeysOnly {
                t.Fatalf("expected DKIMWeakKeysOnly, got %v", ds4)
        }

        ps5 := protocolState{isNoMailDomain: true}
        ds5 := classifyDKIMState(ps5)
        if ds5 != DKIMNoMailDomain {
                t.Fatalf("expected DKIMNoMailDomain, got %v", ds5)
        }
}

func TestDKIMStateString_CB7(t *testing.T) {
        tests := []struct {
                state DKIMState
                want  string
        }{
                {DKIMAbsent, "absent"},
                {DKIMSuccess, "success"},
                {DKIMProviderInferred, "provider_inferred"},
                {DKIMThirdPartyOnly, "third_party_only"},
                {DKIMInconclusive, "inconclusive"},
                {DKIMWeakKeysOnly, "weak_keys_only"},
                {DKIMNoMailDomain, "no_mail_domain"},
                {DKIMState(99), "unknown(99)"},
        }
        for _, tt := range tests {
                if got := tt.state.String(); got != tt.want {
                        t.Errorf("DKIMState(%d).String() = %q, want %q", tt.state, got, tt.want)
                }
        }
}

func TestDKIMStateIsPresent_CB7(t *testing.T) {
        if !DKIMSuccess.IsPresent() {
                t.Fatal("DKIMSuccess should be present")
        }
        if DKIMAbsent.IsPresent() {
                t.Fatal("DKIMAbsent should not be present")
        }
        if DKIMInconclusive.IsPresent() {
                t.Fatal("DKIMInconclusive should not be present")
        }
}

func TestDKIMStateIsConfigured_CB7(t *testing.T) {
        if !DKIMSuccess.IsConfigured() {
                t.Fatal("DKIMSuccess should be configured")
        }
        if DKIMWeakKeysOnly.IsConfigured() {
                t.Fatal("DKIMWeakKeysOnly should not be configured")
        }
}

func TestDKIMStateNeedsAction_CB7(t *testing.T) {
        if !DKIMAbsent.NeedsAction() {
                t.Fatal("DKIMAbsent should need action")
        }
        if DKIMSuccess.NeedsAction() {
                t.Fatal("DKIMSuccess should not need action")
        }
}

func TestDKIMStateNeedsMonitoring_CB7(t *testing.T) {
        if !DKIMInconclusive.NeedsMonitoring() {
                t.Fatal("DKIMInconclusive should need monitoring")
        }
        if DKIMSuccess.NeedsMonitoring() {
                t.Fatal("DKIMSuccess should not need monitoring")
        }
}

func TestAppendDNSSECFixes_CB7(t *testing.T) {
        ps := protocolState{dnssecOK: false}
        fixes := appendDNSSECFixes(nil, ps)
        if len(fixes) == 0 {
                t.Fatal("expected DNSSEC fixes")
        }
}

func TestAppendDANEFixes_CB7(t *testing.T) {
        ps := protocolState{daneOK: false}
        results := map[string]any{"domain": "example.com"}
        fixes := appendDANEFixes(nil, ps, results, "example.com")
        _ = fixes
}

func TestAppendNoMailHardeningFixes_CB7(t *testing.T) {
        ps := protocolState{isNoMailDomain: true}
        fixes := appendNoMailHardeningFixes(nil, ps, "example.com")
        if len(fixes) == 0 {
                t.Fatal("expected no-mail hardening fixes")
        }
}

func TestAppendProbableNoMailFixes_CB7(t *testing.T) {
        ps := protocolState{probableNoMail: true}
        fixes := appendProbableNoMailFixes(nil, ps, "example.com")
        if len(fixes) == 0 {
                t.Fatal("expected probable no-mail fixes")
        }
}

func TestAppendBIMIFixes_CB7(t *testing.T) {
        ps := protocolState{bimiOK: false, dmarcOK: true, dmarcPolicy: "reject"}
        fixes := appendBIMIFixes(nil, ps, "example.com")
        if len(fixes) == 0 {
                t.Fatal("expected BIMI fixes for bimiOK=false")
        }
}

func TestEvaluateDKIMIssues_CB7(t *testing.T) {
        t.Run("nil dkim", func(t *testing.T) {
                weak, tpo := evaluateDKIMIssues(nil)
                if weak || tpo {
                        t.Fatal("expected no issues for nil dkim")
                }
        })
        t.Run("with issues", func(t *testing.T) {
                dkim := map[string]any{
                        "issues": []any{"weak key detected", "third-party selector only"},
                }
                weak, tpo := evaluateDKIMIssues(dkim)
                if !weak {
                        t.Error("expected weak=true")
                }
                if !tpo {
                        t.Error("expected thirdParty=true")
                }
        })
}

func TestScanDKIMIssueStrings_CB7(t *testing.T) {
        weak, tpo := scanDKIMIssueStrings([]any{"weak key", "third-party only"})
        if !weak {
                t.Error("expected weak=true")
        }
        if !tpo {
                t.Error("expected thirdParty=true")
        }
}

func TestClassifyDMARCSuccess_CB7(t *testing.T) {
        t.Run("reject full", func(t *testing.T) {
                ps := protocolState{dmarcOK: true, dmarcPolicy: "reject", dmarcPct: 100, dmarcHasRua: true}
                acc := &postureAccumulator{}
                classifyDMARCSuccess(ps, acc)
        })
        t.Run("quarantine", func(t *testing.T) {
                ps := protocolState{dmarcOK: true, dmarcPolicy: "quarantine", dmarcPct: 50}
                acc := &postureAccumulator{}
                classifyDMARCSuccess(ps, acc)
        })
        t.Run("none", func(t *testing.T) {
                ps := protocolState{dmarcOK: true, dmarcPolicy: "none"}
                acc := &postureAccumulator{}
                classifyDMARCSuccess(ps, acc)
        })
}

func TestClassifyDMARCWarning_CB7(t *testing.T) {
        t.Run("none policy warning", func(t *testing.T) {
                ps := protocolState{dmarcWarning: true, dmarcPolicy: "none"}
                acc := &postureAccumulator{}
                classifyDMARCWarning(ps, acc)
        })
}

func TestExtractIntFieldDefault_CB7(t *testing.T) {
        m := map[string]any{"count": float64(42)}
        v := extractIntFieldDefault(m, "count", 0)
        if v != 42 {
                t.Fatalf("expected 42, got %d", v)
        }
        v2 := extractIntFieldDefault(m, "missing", 99)
        if v2 != 99 {
                t.Fatalf("expected 99, got %d", v2)
        }
        v3 := extractIntFieldDefault(nil, "x", 5)
        if v3 != 5 {
                t.Fatalf("expected 5, got %d", v3)
        }
}

func TestClassifyEmailSpoofability_CB7(t *testing.T) {
        t.Run("reject policy", func(t *testing.T) {
                ps := protocolState{
                        spfOK:       true,
                        dmarcOK:     true,
                        dmarcPolicy: "reject",
                        dmarcPct:    100,
                        dkimOK:      true,
                }
                result := classifyEmailSpoofability(ps, true, true)
                if result == 0 {
                        t.Fatal("expected non-zero spoofability classification")
                }
        })
        t.Run("no spf no dmarc", func(t *testing.T) {
                ps := protocolState{
                        spfMissing:   true,
                        dmarcMissing: true,
                }
                result := classifyEmailSpoofability(ps, false, false)
                if result == 0 {
                        t.Fatal("expected non-zero spoofability classification")
                }
        })
        t.Run("quarantine partial", func(t *testing.T) {
                ps := protocolState{
                        spfOK:       true,
                        dmarcOK:     true,
                        dmarcPolicy: "quarantine",
                        dmarcPct:    50,
                }
                result := classifyEmailSpoofability(ps, true, true)
                if result == 0 {
                        t.Fatal("expected non-zero spoofability classification")
                }
        })
        t.Run("none policy", func(t *testing.T) {
                ps := protocolState{
                        spfOK:       true,
                        dmarcOK:     true,
                        dmarcPolicy: "none",
                }
                result := classifyEmailSpoofability(ps, true, true)
                if result == 0 {
                        t.Fatal("expected non-zero spoofability classification")
                }
        })
}

func TestDetermineGrade_CB7(t *testing.T) {
        ps := protocolState{
                spfOK:       true,
                dmarcOK:     true,
                dmarcPolicy: "reject",
                dmarcPct:    100,
                dkimOK:      true,
                dnssecOK:    true,
                daneOK:      true,
                mtaStsOK:    true,
                bimiOK:      true,
                caaOK:       true,
        }
        gi := gradeInput{}
        state, icon, color, message := determineGrade(ps, DKIMSuccess, gi)
        if state == "" || icon == "" || color == "" || message == "" {
                t.Fatalf("expected non-empty grade values: state=%q icon=%q color=%q msg=%q", state, icon, color, message)
        }
}
