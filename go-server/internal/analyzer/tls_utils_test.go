package analyzer

import (
        "crypto/tls"
        "errors"
        "strings"
        "testing"
        "time"
)

func TestTruncate_CB3(t *testing.T) {
        if got := truncate("hello", 10); got != "hello" {
                t.Errorf("truncate short = %q", got)
        }
        if got := truncate("hello world", 5); got != "hello" {
                t.Errorf("truncate long = %q", got)
        }
        if got := truncate("", 5); got != "" {
                t.Errorf("truncate empty = %q", got)
        }
}

func TestTlsVersionString_CB3(t *testing.T) {
        tests := []struct {
                v    uint16
                want string
        }{
                {tls.VersionTLS13, "TLSv1.3"},
                {tls.VersionTLS12, "TLSv1.2"},
                {tls.VersionTLS11, "TLSv1.1"},
                {tls.VersionTLS10, "TLSv1.0"},
                {0x0200, "TLS 0x0200"},
        }
        for _, tc := range tests {
                if got := tlsVersionString(tc.v); got != tc.want {
                        t.Errorf("tlsVersionString(0x%04x) = %q, want %q", tc.v, got, tc.want)
                }
        }
}

func TestCipherBitsValues(t *testing.T) {
        for _, suite := range tls.CipherSuites() {
                bits := cipherBits(suite.ID)
                name := suite.Name
                if strings.Contains(name, "256") || strings.Contains(name, "CHACHA20") {
                        if bits != 256 {
                                t.Errorf("cipherBits(%s) = %d, want 256", name, bits)
                        }
                } else if strings.Contains(name, "128") {
                        if bits != 128 {
                                t.Errorf("cipherBits(%s) = %d, want 128", name, bits)
                        }
                }
        }
}

func TestClassifySMTPError_CB3(t *testing.T) {
        tests := []struct {
                err  string
                want string
        }{
                {"connection timeout", "Connection timeout"},
                {"deadline exceeded", "Connection timeout"},
                {"connection refused", "Connection refused"},
                {"network unreachable", "Network unreachable"},
                {"no such host", "DNS resolution failed"},
                {"some other error", "some other error"},
        }
        for _, tc := range tests {
                if got := classifySMTPError(errors.New(tc.err)); got != tc.want {
                        t.Errorf("classifySMTPError(%q) = %q, want %q", tc.err, got, tc.want)
                }
        }
}

func TestMapGetStrSafe_CB3(t *testing.T) {
        if got := mapGetStrSafe(nil, "key"); got != "" {
                t.Errorf("nil map = %q", got)
        }
        if got := mapGetStrSafe(map[string]any{"key": "val"}, "key"); got != "val" {
                t.Errorf("present = %q", got)
        }
        if got := mapGetStrSafe(map[string]any{"key": 42}, "key"); got != "" {
                t.Errorf("wrong type = %q", got)
        }
        if got := mapGetStrSafe(map[string]any{}, "missing"); got != "" {
                t.Errorf("missing = %q", got)
        }
}

func TestToFloat64Val_CB3(t *testing.T) {
        tests := []struct {
                v    any
                want float64
        }{
                {float64(3.14), 3.14},
                {int(42), 42.0},
                {int64(100), 100.0},
                {"string", 0},
                {nil, 0},
        }
        for _, tc := range tests {
                if got := toFloat64Val(tc.v); got != tc.want {
                        t.Errorf("toFloat64Val(%v) = %f, want %f", tc.v, got, tc.want)
                }
        }
}

func TestUpdateSummary_CB3(t *testing.T) {
        s := &smtpSummary{}
        sr := map[string]any{
                mapKeyReachable:         true,
                mapKeyStarttls:          true,
                mapKeyTlsVersion:        "TLSv1.3",
                mapKeyCertValid:         true,
                mapKeyCertDaysRemaining: 10,
        }
        updateSummary(s, sr)
        if s.Reachable != 1 {
                t.Errorf("Reachable = %d", s.Reachable)
        }
        if s.StartTLSSupport != 1 {
                t.Errorf("StartTLSSupport = %d", s.StartTLSSupport)
        }
        if s.TLS13 != 1 {
                t.Errorf("TLS13 = %d", s.TLS13)
        }
        if s.ValidCerts != 1 {
                t.Errorf("ValidCerts = %d", s.ValidCerts)
        }
        if s.ExpiringSoon != 1 {
                t.Errorf("ExpiringSoon = %d", s.ExpiringSoon)
        }

        s2 := &smtpSummary{}
        sr2 := map[string]any{
                mapKeyReachable:  true,
                mapKeyStarttls:   true,
                mapKeyTlsVersion: "TLSv1.2",
                mapKeyCertValid:  false,
        }
        updateSummary(s2, sr2)
        if s2.TLS12 != 1 {
                t.Errorf("TLS12 = %d", s2.TLS12)
        }
        if s2.ValidCerts != 0 {
                t.Errorf("ValidCerts = %d", s2.ValidCerts)
        }
}

func TestSummaryToMap_CB3(t *testing.T) {
        s := &smtpSummary{
                TotalServers:    3,
                Reachable:       2,
                StartTLSSupport: 2,
                TLS13:           1,
                TLS12:           1,
                ValidCerts:      2,
                ExpiringSoon:    0,
        }
        m := summaryToMap(s)
        if m[mapKeyTotalServers] != 3 {
                t.Errorf("total_servers = %v", m[mapKeyTotalServers])
        }
        if m[mapKeyReachable] != 2 {
                t.Errorf("reachable = %v", m[mapKeyReachable])
        }
}

func TestSmtpProbeVerdictFromSummary_CB3(t *testing.T) {
        tests := []struct {
                name    string
                summary smtpSummary
                want    string
        }{
                {"all tls", smtpSummary{Reachable: 2, StartTLSSupport: 2, ValidCerts: 2}, mapKeyAllTls},
                {"partial tls", smtpSummary{Reachable: 2, StartTLSSupport: 1, ValidCerts: 1}, mapKeyPartialTls},
                {"no tls", smtpSummary{Reachable: 2, StartTLSSupport: 0}, mapKeyNoTls},
                {"mismatch certs", smtpSummary{Reachable: 2, StartTLSSupport: 2, ValidCerts: 1}, mapKeyPartialTls},
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        got := smtpProbeVerdictFromSummary(&tc.summary)
                        if got != tc.want {
                                t.Errorf("got %q, want %q", got, tc.want)
                        }
                })
        }
}

func TestDerivePrimaryStatus_CB3(t *testing.T) {
        tests := []struct {
                name   string
                policy map[string]any
                probe  map[string]any
                want   string
        }{
                {"observed all_tls enforced", map[string]any{mapKeyVerdict: mapKeyEnforced}, map[string]any{mapKeyStatus: mapKeyObserved, mapKeyProbeVerdict: mapKeyAllTls}, mapKeySuccess},
                {"observed all_tls no policy", map[string]any{mapKeyVerdict: verdictNone}, map[string]any{mapKeyStatus: mapKeyObserved, mapKeyProbeVerdict: mapKeyAllTls}, mapKeySuccess},
                {"observed partial_tls", map[string]any{mapKeyVerdict: verdictNone}, map[string]any{mapKeyStatus: mapKeyObserved, mapKeyProbeVerdict: mapKeyPartialTls}, "warning"},
                {"observed no_tls", map[string]any{mapKeyVerdict: verdictNone}, map[string]any{mapKeyStatus: mapKeyObserved, mapKeyProbeVerdict: mapKeyNoTls}, mapKeyError},
                {"skipped enforced", map[string]any{mapKeyVerdict: mapKeyEnforced}, map[string]any{mapKeyStatus: mapKeySkipped}, mapKeySuccess},
                {"skipped monitored", map[string]any{mapKeyVerdict: mapKeyMonitored}, map[string]any{mapKeyStatus: mapKeySkipped}, "info"},
                {"skipped opportunistic", map[string]any{mapKeyVerdict: mapKeyOpportunistic}, map[string]any{mapKeyStatus: mapKeySkipped}, "inferred"},
                {"skipped none", map[string]any{mapKeyVerdict: verdictNone}, map[string]any{mapKeyStatus: mapKeySkipped}, "info"},
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        got := derivePrimaryStatus(tc.policy, tc.probe)
                        if got != tc.want {
                                t.Errorf("got %q, want %q", got, tc.want)
                        }
                })
        }
}

func TestDerivePrimaryMessage_CB3(t *testing.T) {
        noMX := derivePrimaryMessage(map[string]any{}, map[string]any{}, nil)
        if noMX != "No MX records found" {
                t.Errorf("no MX = %q", noMX)
        }

        observed := derivePrimaryMessage(
                map[string]any{mapKeyVerdict: mapKeyEnforced},
                map[string]any{
                        mapKeyStatus: mapKeyObserved,
                        mapKeySummary: map[string]any{
                                mapKeyReachable:         2,
                                mapKeyStarttlsSupported: 2,
                        },
                },
                []string{"mx1.example.com"},
        )
        if !strings.Contains(observed, "2 server(s) verified") {
                t.Errorf("observed full tls = %q", observed)
        }

        partial := derivePrimaryMessage(
                map[string]any{mapKeyVerdict: mapKeyEnforced},
                map[string]any{
                        mapKeyStatus: mapKeyObserved,
                        mapKeySummary: map[string]any{
                                mapKeyReachable:         3,
                                mapKeyStarttlsSupported: 1,
                        },
                },
                []string{"mx1.example.com"},
        )
        if !strings.Contains(partial, "1/3 servers") {
                t.Errorf("observed partial = %q", partial)
        }

        enforced := derivePrimaryMessage(
                map[string]any{mapKeyVerdict: mapKeyEnforced, mapKeySignals: []string{"s1", "s2"}},
                map[string]any{mapKeyStatus: mapKeySkipped},
                []string{"mx1.example.com"},
        )
        if !strings.Contains(enforced, "enforced") {
                t.Errorf("enforced = %q", enforced)
        }

        monitored := derivePrimaryMessage(
                map[string]any{mapKeyVerdict: mapKeyMonitored, mapKeySignals: []string{"s1"}},
                map[string]any{mapKeyStatus: mapKeySkipped},
                []string{"mx1.example.com"},
        )
        if !strings.Contains(monitored, "monitoring") {
                t.Errorf("monitored = %q", monitored)
        }

        opportunistic := derivePrimaryMessage(
                map[string]any{mapKeyVerdict: mapKeyOpportunistic, mapKeySignals: []string{"s1"}},
                map[string]any{mapKeyStatus: mapKeySkipped},
                []string{"mx1.example.com"},
        )
        if !strings.Contains(opportunistic, "inferred") {
                t.Errorf("opportunistic = %q", opportunistic)
        }

        none := derivePrimaryMessage(
                map[string]any{mapKeyVerdict: verdictNone},
                map[string]any{mapKeyStatus: mapKeySkipped},
                []string{"mx1.example.com"},
        )
        if !strings.Contains(none, "No transport encryption") {
                t.Errorf("none = %q", none)
        }
}

func TestBuildInferenceNote_CB3(t *testing.T) {
        observed := buildInferenceNote(map[string]any{mapKeyStatus: mapKeyObserved})
        if observed != "" {
                t.Errorf("observed should be empty, got %q", observed)
        }
        skipped := buildInferenceNote(map[string]any{mapKeyStatus: mapKeySkipped})
        if skipped == "" {
                t.Error("skipped should return note")
        }
}

func TestBuildInferenceSignals_CB3(t *testing.T) {
        policy := map[string]any{mapKeySignals: []string{"signal1"}}
        telem := map[string]any{mapKeyTlsrptConfigured: true}
        got := buildInferenceSignals(policy, telem)
        if len(got) != 2 {
                t.Errorf("expected 2 signals, got %d", len(got))
        }

        policy2 := map[string]any{mapKeySignals: []string{"TLS-RPT configured already"}}
        got2 := buildInferenceSignals(policy2, telem)
        if len(got2) != 1 {
                t.Errorf("expected 1 signal (no dup), got %d", len(got2))
        }

        got3 := buildInferenceSignals(policy, map[string]any{mapKeyTlsrptConfigured: false})
        if len(got3) != 1 {
                t.Errorf("expected 1 signal when not configured, got %d", len(got3))
        }
}

func TestComputeProbeConsensus_CB3(t *testing.T) {
        empty := computeProbeConsensus(nil)
        if empty[mapKeyAgreement] != "unknown" {
                t.Errorf("empty = %v", empty[mapKeyAgreement])
        }

        emptySlice := computeProbeConsensus([]map[string]any{})
        if emptySlice[mapKeyAgreement] != "unknown" {
                t.Errorf("emptySlice = %v", emptySlice[mapKeyAgreement])
        }

        noData := computeProbeConsensus([]map[string]any{
                {mapKeyStatus: mapKeySkipped},
        })
        if noData[mapKeyAgreement] != "no_data" {
                t.Errorf("noData = %v", noData[mapKeyAgreement])
        }

        unanimous := computeProbeConsensus([]map[string]any{
                {mapKeyStatus: mapKeyObserved, mapKeyProbeVerdict: mapKeyAllTls},
                {mapKeyStatus: mapKeyObserved, mapKeyProbeVerdict: mapKeyAllTls},
        })
        if unanimous[mapKeyAgreement] != "unanimous_tls" {
                t.Errorf("unanimous = %v", unanimous[mapKeyAgreement])
        }

        unanimousNoTls := computeProbeConsensus([]map[string]any{
                {mapKeyStatus: mapKeyObserved, mapKeyProbeVerdict: mapKeyNoTls},
                {mapKeyStatus: mapKeyObserved, mapKeyProbeVerdict: mapKeyNoTls},
        })
        if unanimousNoTls[mapKeyAgreement] != "unanimous_no_tls" {
                t.Errorf("unanimousNoTls = %v", unanimousNoTls[mapKeyAgreement])
        }

        split := computeProbeConsensus([]map[string]any{
                {mapKeyStatus: mapKeyObserved, mapKeyProbeVerdict: mapKeyAllTls},
                {mapKeyStatus: mapKeyObserved, mapKeyProbeVerdict: mapKeyNoTls},
        })
        if split[mapKeyAgreement] != "split" {
                t.Errorf("split = %v", split[mapKeyAgreement])
        }
}

func TestComputePolicyVerdict_CB3(t *testing.T) {
        tests := []struct {
                name    string
                policy  map[string]any
                signals []string
                want    string
        }{
                {"enforce", map[string]any{mapKeyMtaSts: map[string]any{mapKeyPresent: true, "mode": "enforce"}, mapKeyDane: map[string]any{mapKeyPresent: false}}, nil, mapKeyEnforced},
                {"dane", map[string]any{mapKeyMtaSts: map[string]any{mapKeyPresent: false}, mapKeyDane: map[string]any{mapKeyPresent: true}}, nil, mapKeyEnforced},
                {"testing", map[string]any{mapKeyMtaSts: map[string]any{mapKeyPresent: true, "mode": "testing"}, mapKeyDane: map[string]any{mapKeyPresent: false}}, nil, mapKeyMonitored},
                {"signals only", map[string]any{mapKeyMtaSts: map[string]any{mapKeyPresent: false}, mapKeyDane: map[string]any{mapKeyPresent: false}}, []string{"something"}, mapKeyOpportunistic},
                {"none", map[string]any{mapKeyMtaSts: map[string]any{mapKeyPresent: false}, mapKeyDane: map[string]any{mapKeyPresent: false}}, nil, verdictNone},
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        got := computePolicyVerdict(tc.policy, tc.signals)
                        if got != tc.want {
                                t.Errorf("got %q, want %q", got, tc.want)
                        }
                })
        }
}

func TestInferFromProvider_CB3(t *testing.T) {
        tests := []struct {
                hosts []string
                empty bool
        }{
                {[]string{"aspmx.l.google.com"}, false},
                {[]string{"mail.protection.outlook.com"}, false},
                {[]string{"pphosted.com"}, false},
                {[]string{"mail.protonmail.ch"}, false},
                {[]string{"mx.custom.example.com"}, true},
                {nil, true},
        }
        for _, tc := range tests {
                got := inferFromProvider(tc.hosts)
                if tc.empty && got != "" {
                        t.Errorf("inferFromProvider(%v) = %q, want empty", tc.hosts, got)
                }
                if !tc.empty && got == "" {
                        t.Errorf("inferFromProvider(%v) = empty, want non-empty", tc.hosts)
                }
        }
}

func TestExtractTLSRPTURIs_CB3(t *testing.T) {
        got := extractTLSRPTURIs("v=TLSRPTv1; rua=mailto:tls@example.com, https://report.example.com")
        if len(got) != 2 {
                t.Fatalf("expected 2 URIs, got %d", len(got))
        }
        if got[0] != "mailto:tls@example.com" {
                t.Errorf("first = %q", got[0])
        }

        empty := extractTLSRPTURIs("v=TLSRPTv1;")
        if len(empty) != 0 {
                t.Errorf("expected 0 URIs, got %d", len(empty))
        }
}

func TestBuildTelemetrySection_CB3(t *testing.T) {
        empty := buildTelemetrySection(AnalysisInputs{})
        if empty[mapKeyTlsrptConfigured] != false {
                t.Error("empty should have tlsrpt_configured=false")
        }

        withTLS := buildTelemetrySection(AnalysisInputs{
                TLSRPTResult: map[string]any{
                        mapKeyStatus: mapKeySuccess,
                        "record":     "v=TLSRPTv1; rua=mailto:tls@example.com",
                },
        })
        if withTLS[mapKeyTlsrptConfigured] != true {
                t.Error("expected tlsrpt_configured=true")
        }
        if withTLS["observability"] != true {
                t.Error("expected observability=true")
        }
}

func TestSmtpResponseComplete_CB3(t *testing.T) {
        if !smtpResponseComplete("220 mail.example.com ESMTP\r\n") {
                t.Error("expected complete for single line with space after code")
        }
        if smtpResponseComplete("250-PIPELINING\r\n") {
                t.Error("expected incomplete for continuation line")
        }
}

func TestGetIssuesList_CB3(t *testing.T) {
        got := getIssuesList(map[string]any{"issues": []string{"a", "b"}})
        if len(got) != 2 {
                t.Errorf("got %d issues", len(got))
        }
        got2 := getIssuesList(map[string]any{})
        if len(got2) != 0 {
                t.Errorf("got %d for empty", len(got2))
        }
}

func TestApplyPrimaryResult_B3(t *testing.T) {
        probe := map[string]any{"existing": "val"}
        applyPrimaryResult(probe, nil)
        if len(probe) != 1 {
                t.Error("nil should not modify probe")
        }
        applyPrimaryResult(probe, map[string]any{"new": "val2"})
        if probe["new"] != "val2" {
                t.Error("should apply new keys")
        }
}

func TestClassifyRemoteProbeStatus_CB3(t *testing.T) {
        if got := classifyRemoteProbeStatus(200); got != "" {
                t.Errorf("200 = %q", got)
        }
        if got := classifyRemoteProbeStatus(401); got == "" {
                t.Error("401 should fail")
        }
        if got := classifyRemoteProbeStatus(429); got == "" {
                t.Error("429 should fail")
        }
        if got := classifyRemoteProbeStatus(500); !strings.Contains(got, "500") {
                t.Errorf("500 = %q", got)
        }
}

func TestCountCoreIssues_B3(t *testing.T) {
        fixes := []fix{
                {SeverityLevel: sevCritical},
                {SeverityLevel: sevHigh},
                {SeverityLevel: sevMedium},
                {SeverityLevel: sevLow},
        }
        if got := countCoreIssues(fixes); got != 2 {
                t.Errorf("got %d, want 2", got)
        }
        if got := countCoreIssues(nil); got != 0 {
                t.Errorf("nil = %d", got)
        }
}

func TestHasSeverity_B3(t *testing.T) {
        fixes := []fix{{SeverityLevel: sevMedium}}
        if !hasSeverity(fixes, severityMedium) {
                t.Error("should find Medium")
        }
        if hasSeverity(fixes, severityCritical) {
                t.Error("should not find Critical")
        }
        if hasSeverity(nil, severityMedium) {
                t.Error("nil should return false")
        }
}

func TestFilterBySeverity_B3(t *testing.T) {
        fixes := []fix{
                {Title: "a", SeverityLevel: sevCritical},
                {Title: "b", SeverityLevel: sevMedium},
                {Title: "c", SeverityLevel: sevCritical},
        }
        got := filterBySeverity(fixes, severityCritical)
        if len(got) != 2 {
                t.Errorf("got %d, want 2", len(got))
        }
        got2 := filterBySeverity(fixes, severityLow)
        if len(got2) != 0 {
                t.Errorf("got %d, want 0", len(got2))
        }
}

func TestJoinFixTitles_B3(t *testing.T) {
        fixes := []fix{{Title: "A"}, {Title: "B"}, {Title: "C"}}
        if got := joinFixTitles(fixes); got != "A, B, C" {
                t.Errorf("got %q", got)
        }
        if joinFixTitles(nil) != "" {
                t.Error("nil should return empty")
        }
}

func TestComputeAchievablePosture_B3(t *testing.T) {
        if got := computeAchievablePosture(protocolState{}, nil); got != "Secure" {
                t.Errorf("no fixes = %q", got)
        }
        if got := computeAchievablePosture(protocolState{}, []fix{{SeverityLevel: sevMedium}}); got != "Secure" {
                t.Errorf("medium-only (no core issues) = %q", got)
        }
        if got := computeAchievablePosture(protocolState{}, []fix{
                {SeverityLevel: sevCritical},
                {SeverityLevel: sevHigh},
                {SeverityLevel: sevMedium},
        }); got != "Low Risk" {
                t.Errorf("3 fixes with critical = %q", got)
        }
        if got := computeAchievablePosture(protocolState{}, []fix{
                {SeverityLevel: sevCritical},
                {SeverityLevel: sevHigh},
                {SeverityLevel: sevMedium},
                {SeverityLevel: sevLow},
        }); got != "Moderate Risk" {
                t.Errorf("4 fixes with critical = %q", got)
        }
}

func TestBuildPerSection_B3(t *testing.T) {
        fixes := []fix{
                {Title: "A", Section: "SPF", SeverityLevel: sevCritical},
                {Title: "B", Section: "SPF", SeverityLevel: sevMedium},
                {Title: "C", Section: "DMARC", SeverityLevel: sevHigh},
                {Title: "D", Section: "", SeverityLevel: sevLow},
        }
        got := buildPerSection(fixes)
        spf, ok := got["SPF"].([]map[string]any)
        if !ok || len(spf) != 2 {
                t.Errorf("SPF section = %v", got["SPF"])
        }
        dmarc, ok := got["DMARC"].([]map[string]any)
        if !ok || len(dmarc) != 1 {
                t.Errorf("DMARC section = %v", got["DMARC"])
        }
        if _, ok := got[""]; ok {
                t.Error("empty section should not appear")
        }
}

func TestAppendNoMailHardeningFixes_B3(t *testing.T) {
        ps := protocolState{spfHardFail: false, dmarcMissing: true}
        fixes := appendNoMailHardeningFixes(nil, ps, "example.com")
        if len(fixes) != 2 {
                t.Fatalf("expected 2 fixes, got %d", len(fixes))
        }
        if fixes[0].Section != sectionSPF {
                t.Errorf("first section = %q", fixes[0].Section)
        }
        if fixes[1].Section != sectionDMARC {
                t.Errorf("second section = %q", fixes[1].Section)
        }

        ps2 := protocolState{spfHardFail: true, dmarcPolicy: policyReject}
        fixes2 := appendNoMailHardeningFixes(nil, ps2, "example.com")
        if len(fixes2) != 0 {
                t.Errorf("fully hardened should have 0 fixes, got %d", len(fixes2))
        }
}

func TestAppendProbableNoMailFixes_B3(t *testing.T) {
        ps := protocolState{spfHardFail: false, dmarcMissing: true}
        fixes := appendProbableNoMailFixes(nil, ps, "example.com")
        if len(fixes) != 2 {
                t.Fatalf("expected 2 fixes, got %d", len(fixes))
        }

        ps2 := protocolState{spfHardFail: true, dmarcPolicy: policyReject}
        fixes2 := appendProbableNoMailFixes(nil, ps2, "example.com")
        if len(fixes2) != 0 {
                t.Errorf("expected 0, got %d", len(fixes2))
        }
}

func TestAppendDNSSECFixes_B3(t *testing.T) {
        broken := appendDNSSECFixes(nil, protocolState{dnssecBroken: true})
        if len(broken) != 1 || broken[0].SeverityLevel != sevCritical {
                t.Errorf("broken = %d fixes", len(broken))
        }

        missing := appendDNSSECFixes(nil, protocolState{})
        if len(missing) != 1 || missing[0].SeverityLevel != sevMedium {
                t.Errorf("missing = %d fixes", len(missing))
        }

        ok := appendDNSSECFixes(nil, protocolState{dnssecOK: true})
        if len(ok) != 0 {
                t.Errorf("ok should have 0, got %d", len(ok))
        }

        deprecated := appendDNSSECFixes(nil, protocolState{dnssecOK: true, dnssecAlgoStrength: "deprecated"})
        if len(deprecated) != 1 || deprecated[0].SeverityLevel != sevHigh {
                t.Errorf("deprecated = %d fixes", len(deprecated))
        }

        legacy := appendDNSSECFixes(nil, protocolState{dnssecOK: true, dnssecAlgoStrength: "legacy"})
        if len(legacy) != 1 || legacy[0].SeverityLevel != sevMedium {
                t.Errorf("legacy = %d fixes", len(legacy))
        }
}

func TestAppendDANEFixes_B3(t *testing.T) {
        daneNoDnssec := appendDANEFixes(nil, protocolState{daneOK: true, dnssecOK: false}, map[string]any{}, "example.com")
        if len(daneNoDnssec) != 1 {
                t.Fatalf("dane without dnssec = %d", len(daneNoDnssec))
        }
        if daneNoDnssec[0].SeverityLevel != sevHigh {
                t.Errorf("severity = %v", daneNoDnssec[0].SeverityLevel)
        }

        noDaneWithDnssec := appendDANEFixes(nil, protocolState{daneOK: false, dnssecOK: true}, map[string]any{}, "example.com")
        if len(noDaneWithDnssec) != 1 {
                t.Fatalf("no dane with dnssec = %d", len(noDaneWithDnssec))
        }
        if noDaneWithDnssec[0].Section != sectionDANE {
                t.Errorf("section = %q", noDaneWithDnssec[0].Section)
        }
}

func TestAppendBIMIFixes_B3(t *testing.T) {
        withReject := appendBIMIFixes(nil, protocolState{bimiOK: false, dmarcPolicy: policyReject}, "example.com")
        if len(withReject) != 1 {
                t.Errorf("expected 1 fix, got %d", len(withReject))
        }

        noBimi := appendBIMIFixes(nil, protocolState{bimiOK: false, dmarcPolicy: "none"}, "example.com")
        if len(noBimi) != 0 {
                t.Errorf("expected 0 for non-reject, got %d", len(noBimi))
        }

        hasBimi := appendBIMIFixes(nil, protocolState{bimiOK: true, dmarcPolicy: policyReject}, "example.com")
        if len(hasBimi) != 0 {
                t.Errorf("expected 0 when bimi ok, got %d", len(hasBimi))
        }
}

func TestSortFixes_B3(t *testing.T) {
        fixes := []fix{
                {Title: "Z", SeverityLevel: sevLow},
                {Title: "A", SeverityLevel: sevCritical},
                {Title: "M", SeverityLevel: sevHigh},
                {Title: "B", SeverityLevel: sevCritical},
        }
        sortFixes(fixes)
        if fixes[0].Title != "A" || fixes[1].Title != "B" {
                t.Errorf("first two = %q, %q", fixes[0].Title, fixes[1].Title)
        }
        if fixes[2].Title != "M" {
                t.Errorf("third = %q", fixes[2].Title)
        }
}

func TestFixToMap_B3(t *testing.T) {
        f := fix{
                Title:         "Test",
                Description:   "Desc",
                DNSHost:       "example.com",
                DNSType:       "TXT",
                DNSValue:      "val",
                DNSPurpose:    "purpose",
                DNSHostHelp:   "help",
                DNSRecord:     "record",
                RFC:           "RFC 1234",
                RFCURL:        "https://example.com",
                SeverityLevel: sevHigh,
                Section:       "SPF",
        }
        m := fixToMap(f)
        if m["title"] != "Test" {
                t.Errorf("title = %v", m["title"])
        }
        if m["dns_host"] != "example.com" {
                t.Errorf("dns_host = %v", m["dns_host"])
        }
        if m["dns_record"] != "record" {
                t.Errorf("dns_record = %v", m["dns_record"])
        }
}

func TestExtractDomain_B3(t *testing.T) {
        if got := extractDomain(map[string]any{"domain": "test.com"}); got != "test.com" {
                t.Errorf("got %q", got)
        }
        if got := extractDomain(map[string]any{}); got != "yourdomain.com" {
                t.Errorf("fallback = %q", got)
        }
}

func TestDkimSelectorForProvider_B3(t *testing.T) {
        if got := dkimSelectorForProvider("Google Workspace"); got != "google" {
                t.Errorf("google = %q", got)
        }
        if got := dkimSelectorForProvider("Microsoft 365"); got != "selector1" {
                t.Errorf("microsoft = %q", got)
        }
        if got := dkimSelectorForProvider("Office 365"); got != "selector1" {
                t.Errorf("office = %q", got)
        }
        if got := dkimSelectorForProvider("Unknown"); got != "selector1" {
                t.Errorf("unknown = %q", got)
        }
}

func TestBuildSPFValue_B3(t *testing.T) {
        got := buildSPFValue([]string{"_spf.google.com"}, "~all")
        if got != "v=spf1 include:_spf.google.com ~all" {
                t.Errorf("got %q", got)
        }
        got2 := buildSPFValue(nil, "-all")
        if got2 != "v=spf1 -all" {
                t.Errorf("empty includes = %q", got2)
        }
}

func TestExtractSPFIncludes_B3(t *testing.T) {
        got := extractSPFIncludes(map[string]any{
                "spf_analysis": map[string]any{
                        "includes": []string{"_spf.google.com"},
                },
        })
        if len(got) != 1 || got[0] != "_spf.google.com" {
                t.Errorf("got %v", got)
        }

        got2 := extractSPFIncludes(map[string]any{
                "spf_analysis": map[string]any{
                        "includes": []any{"_spf.google.com", "other.com"},
                },
        })
        if len(got2) != 2 {
                t.Errorf("got %d", len(got2))
        }

        got3 := extractSPFIncludes(map[string]any{})
        if got3 != nil {
                t.Errorf("empty = %v", got3)
        }
}

func TestBuildNoMailSignals_B3(t *testing.T) {
        mf := mailFlags{hasNullMX: true, spfDenyAll: true, dmarcReject: true}
        signals, count := buildNoMailSignals(mf)
        if count != 3 {
                t.Errorf("count = %d", count)
        }
        if signals["null_mx"] == nil {
                t.Error("expected null_mx signal")
        }

        mf2 := mailFlags{}
        _, count2 := buildNoMailSignals(mf2)
        if count2 != 0 {
                t.Errorf("count = %d", count2)
        }
}

func TestBuildMissingSteps_B3(t *testing.T) {
        mf := mailFlags{hasSPF: false, hasDMARC: false, hasDKIM: false}
        steps := buildMissingSteps(mf)
        if len(steps) != 3 {
                t.Errorf("got %d steps", len(steps))
        }

        mf2 := mailFlags{hasSPF: true, hasDMARC: true, hasDKIM: true}
        steps2 := buildMissingSteps(mf2)
        if len(steps2) != 0 {
                t.Errorf("got %d steps", len(steps2))
        }
}

func TestBuildNoMailRecommendedRecords_B3(t *testing.T) {
        mf := mailFlags{}
        records := buildNoMailRecommendedRecords(mf, "example.com")
        if len(records) != 3 {
                t.Errorf("got %d records", len(records))
        }

        mf2 := mailFlags{hasNullMX: true, spfDenyAll: true, dmarcReject: true}
        records2 := buildNoMailRecommendedRecords(mf2, "example.com")
        if len(records2) != 0 {
                t.Errorf("got %d records", len(records2))
        }
}

func TestExtractFirstMXHost_B3(t *testing.T) {
        got := extractFirstMXHost(map[string]any{
                "mx_records": []any{
                        map[string]any{"host": "mx.example.com."},
                },
        })
        if got != "mx.example.com" {
                t.Errorf("got %q", got)
        }

        got2 := extractFirstMXHost(map[string]any{
                "mx_records": []any{
                        map[string]any{"exchange": "mx2.example.com."},
                },
        })
        if got2 != "mx2.example.com" {
                t.Errorf("exchange = %q", got2)
        }

        got3 := extractFirstMXHost(map[string]any{
                "mx_analysis": map[string]any{
                        "mx_hosts": []any{"mx3.example.com."},
                },
        })
        if got3 != "mx3.example.com" {
                t.Errorf("analysis = %q", got3)
        }

        got4 := extractFirstMXHost(map[string]any{})
        if got4 != "mail.yourdomain.com" {
                t.Errorf("fallback = %q", got4)
        }
}

func TestIsDANEDeployable_B3(t *testing.T) {
        if isDANEDeployable(map[string]any{}) {
                t.Error("empty should be false")
        }
        if !isDANEDeployable(map[string]any{
                "dnssec_analysis": map[string]any{"status": "secure"},
        }) {
                t.Error("secure should be true")
        }
        if isDANEDeployable(map[string]any{
                "dnssec_analysis": map[string]any{"status": "insecure"},
        }) {
                t.Error("insecure should be false")
        }
}

func TestParseCertDate_CB3(t *testing.T) {
        got := parseCertDate("2024-01-15T10:30:00")
        if got.IsZero() {
                t.Error("should parse ISO datetime")
        }
        got2 := parseCertDate("2024-01-15 10:30:00")
        if got2.IsZero() {
                t.Error("should parse space datetime")
        }
        got3 := parseCertDate("2024-01-15")
        if got3.IsZero() {
                t.Error("should parse date only")
        }
        got4 := parseCertDate("")
        if !got4.IsZero() {
                t.Error("empty should be zero")
        }
        got5 := parseCertDate("invalid")
        if !got5.IsZero() {
                t.Error("invalid should be zero")
        }
        got6 := parseCertDate("2024-01-15T10:30:00Z extra")
        if got6.IsZero() {
                t.Error("should parse with truncation fallback")
        }
}

func TestSimplifyIssuer_CB3(t *testing.T) {
        if got := simplifyIssuer("O=Let's Encrypt, CN=R3"); got != "Let's Encrypt" {
                t.Errorf("O= case = %q", got)
        }
        if got := simplifyIssuer("CN=DigiCert SHA2"); got != "DigiCert SHA2" {
                t.Errorf("CN= case = %q", got)
        }
        long := strings.Repeat("a", 50)
        if got := simplifyIssuer(long); len(got) != 43 {
                t.Errorf("long = %q (len %d)", got, len(got))
        }
        if got := simplifyIssuer("short"); got != "short" {
                t.Errorf("short = %q", got)
        }
}

func TestAtoi_CB3(t *testing.T) {
        if got := atoi("123"); got != 123 {
                t.Errorf("123 = %d", got)
        }
        if got := atoi("0"); got != 0 {
                t.Errorf("0 = %d", got)
        }
        if got := atoi("abc"); got != 0 {
                t.Errorf("abc = %d", got)
        }
        if got := atoi("12x3"); got != 123 {
                t.Errorf("12x3 = %d", got)
        }
}

func TestNormalizeCTName_CB3(t *testing.T) {
        if got := normalizeCTName("sub.example.com", "example.com"); got != "sub.example.com" {
                t.Errorf("normal = %q", got)
        }
        if got := normalizeCTName("*.example.com", "example.com"); got != "" {
                t.Errorf("wildcard root = %q", got)
        }
        if got := normalizeCTName("*.sub.example.com", "example.com"); got != "sub.example.com" {
                t.Errorf("wildcard sub = %q", got)
        }
        if got := normalizeCTName("example.com", "example.com"); got != "" {
                t.Errorf("same domain = %q", got)
        }
        if got := normalizeCTName("other.net", "example.com"); got != "" {
                t.Errorf("different domain = %q", got)
        }
        if got := normalizeCTName("", "example.com"); got != "" {
                t.Errorf("empty = %q", got)
        }
        if got := normalizeCTName("  SUB.EXAMPLE.COM  ", "example.com"); got != "sub.example.com" {
                t.Errorf("uppercase = %q", got)
        }
}

func TestContainsString_CB3(t *testing.T) {
        if !containsString([]string{"a", "b", "c"}, "b") {
                t.Error("should find b")
        }
        if containsString([]string{"a", "b", "c"}, "d") {
                t.Error("should not find d")
        }
        if containsString(nil, "a") {
                t.Error("nil should not find")
        }
}

func TestDeduplicateCTEntries_CB3(t *testing.T) {
        entries := []ctEntry{
                {SerialNumber: "A", NameValue: "a"},
                {SerialNumber: "A", NameValue: "a2"},
                {SerialNumber: "B", NameValue: "b"},
                {SerialNumber: "", NameValue: "c"},
                {SerialNumber: "", NameValue: "d"},
        }
        got := deduplicateCTEntries(entries)
        if len(got) != 4 {
                t.Errorf("expected 4, got %d", len(got))
        }
}

func TestSortSubdomainsSmartOrder_CB3(t *testing.T) {
        subs := []map[string]any{
                {mapKeyName: "z.example.com", mapKeyIsCurrent: false, mapKeyFirstSeen: "2024-01-01"},
                {mapKeyName: "a.example.com", mapKeyIsCurrent: true},
                {mapKeyName: "m.example.com", mapKeyIsCurrent: true},
                {mapKeyName: "b.example.com", mapKeyIsCurrent: false, mapKeyFirstSeen: "2024-06-01"},
        }
        sorted := sortSubdomainsSmartOrder(subs)
        if sorted[0][mapKeyName] != "a.example.com" {
                t.Errorf("first = %v", sorted[0][mapKeyName])
        }
        if sorted[1][mapKeyName] != "m.example.com" {
                t.Errorf("second = %v", sorted[1][mapKeyName])
        }
        if sorted[2][mapKeyName] != "b.example.com" {
                t.Errorf("third = %v (should be more recent)", sorted[2][mapKeyName])
        }
}

func TestApplySubdomainDisplayCap_CB3(t *testing.T) {
        result := map[string]any{}
        subs := make([]map[string]any, 50)
        for i := range subs {
                subs[i] = map[string]any{mapKeyName: "sub"}
        }
        applySubdomainDisplayCap(result, subs, 30)
        if result[mapKeyDisplayedCount] != 50 {
                t.Errorf("under cap: displayed = %v", result[mapKeyDisplayedCount])
        }

        result2 := map[string]any{}
        largeSubs := make([]map[string]any, 250)
        for i := range largeSubs {
                largeSubs[i] = map[string]any{mapKeyName: "sub"}
        }
        applySubdomainDisplayCap(result2, largeSubs, 100)
        if result2[mapKeyDisplayedCount] != 200 {
                t.Errorf("over cap: displayed = %v", result2[mapKeyDisplayedCount])
        }
        if result2["display_capped"] != true {
                t.Error("should be capped")
        }

        result3 := map[string]any{}
        applySubdomainDisplayCap(result3, largeSubs, 210)
        displayed := result3[mapKeyDisplayedCount].(int)
        if displayed != 235 {
                t.Errorf("currentCount > softCap: displayed = %d", displayed)
        }
}

func TestIsWildcardCertEntry_CB3(t *testing.T) {
        entry := ctEntry{NameValue: "*.example.com\nsub.example.com"}
        if !isWildcardCertEntry(entry, "*.example.com") {
                t.Error("should match wildcard")
        }
        entry2 := ctEntry{NameValue: "sub.example.com"}
        if isWildcardCertEntry(entry2, "*.example.com") {
                t.Error("should not match")
        }
}

func TestCtEntryCoversName_CB3(t *testing.T) {
        entry := ctEntry{NameValue: "*.example.com\nsub.example.com"}
        if !ctEntryCoversName(entry, "sub.example.com") {
                t.Error("should cover exact name")
        }
        if !ctEntryCoversName(entry, "foo.example.com") {
                t.Error("should cover wildcard")
        }
        if ctEntryCoversName(entry, "other.net") {
                t.Error("should not cover different domain")
        }
}

func TestBuildCASummary_CB3(t *testing.T) {
        entries := []ctEntry{
                {IssuerName: "O=Let's Encrypt", NotBefore: "2024-01-01", NotAfter: "2025-01-01"},
                {IssuerName: "O=Let's Encrypt", NotBefore: "2024-06-01", NotAfter: "2025-06-01"},
                {IssuerName: "O=DigiCert", NotBefore: "2024-03-01", NotAfter: "2025-03-01"},
        }
        summary := buildCASummary(entries)
        if len(summary) != 2 {
                t.Fatalf("expected 2 CAs, got %d", len(summary))
        }
        if summary[0][mapKeyName] != "Let's Encrypt" {
                t.Errorf("first CA = %v", summary[0][mapKeyName])
        }
        if summary[0][mapKeyCertCount] != 2 {
                t.Errorf("cert count = %v", summary[0][mapKeyCertCount])
        }
}

func TestCountSubdomainStats_CB3(t *testing.T) {
        subs := []map[string]any{
                {mapKeyIsCurrent: true},
                {mapKeyIsCurrent: false},
                {mapKeyIsCurrent: true},
                {"other": "val"},
        }
        current, expired := countSubdomainStats(subs)
        if current != 2 {
                t.Errorf("current = %d", current)
        }
        if expired != 2 {
                t.Errorf("expired = %d", expired)
        }
}

func TestConvertCertspotterEntries_CB3(t *testing.T) {
        csEntries := []certspotterEntry{
                {DNSNames: []string{"a.com", "b.com"}, NotBefore: "2024-01-01", NotAfter: "2025-01-01"},
        }
        got := convertCertspotterEntries(csEntries)
        if len(got) != 1 {
                t.Fatalf("expected 1, got %d", len(got))
        }
        if got[0].NameValue != "a.com\nb.com" {
                t.Errorf("name value = %q", got[0].NameValue)
        }
}

func TestNormalizeHomoglyphs_CB3(t *testing.T) {
        if got := normalizeHomoglyphs("G00gle"); got != "Google" {
                t.Errorf("0->o = %q", got)
        }
        if got := normalizeHomoglyphs("Pay1ng"); got != "Paylng" {
                t.Errorf("1->l = %q", got)
        }
        if got := normalizeHomoglyphs("hello"); got != "hello" {
                t.Errorf("no change = %q", got)
        }
}

func TestMatchesBrand_B3(t *testing.T) {
        if !matchesBrand("PayPal", []string{"paypal"}, "paypal account", "", "", "fakeemail.com") {
                t.Error("should match paypal in subject from non-paypal domain")
        }
        if matchesBrand("PayPal", []string{"paypal"}, "paypal account", "", "", "paypal.com") {
                t.Error("should not match when domain is paypal")
        }
        if !matchesBrand("PayPal", []string{"paypal"}, "", "paypal user", "", "fakeemail.com") {
                t.Error("should match paypal in from")
        }
}

func TestExtractAllEmailAddresses_B3(t *testing.T) {
        got := extractAllEmailAddresses("hello user@example.com and admin@test.org")
        if len(got) != 2 {
                t.Errorf("expected 2, got %d", len(got))
        }
        got2 := extractAllEmailAddresses("no emails here")
        if len(got2) != 0 {
                t.Errorf("expected 0, got %d", len(got2))
        }
}

func TestExtractFirstEmailFromField_B3(t *testing.T) {
        got := extractFirstEmailFromField("rfc822;user@example.com")
        if got != "user@example.com" {
                t.Errorf("got %q", got)
        }
        got2 := extractFirstEmailFromField("no-email")
        if got2 != "no-email" {
                t.Errorf("fallback = %q", got2)
        }
}

func TestCheckAllAuthPass_B3(t *testing.T) {
        r := &EmailHeaderAnalysis{
                SPFResult:   AuthResult{Result: authResultPass},
                DMARCResult: AuthResult{Result: authResultPass},
                DKIMResults: []AuthResult{{Result: authResultPass}},
        }
        if !checkAllAuthPass(r) {
                t.Error("should be true when all pass")
        }

        r2 := &EmailHeaderAnalysis{
                SPFResult:   AuthResult{Result: authResultFail},
                DMARCResult: AuthResult{Result: authResultPass},
                DKIMResults: []AuthResult{{Result: authResultPass}},
        }
        if checkAllAuthPass(r2) {
                t.Error("should be false when SPF fails")
        }

        r3 := &EmailHeaderAnalysis{
                SPFResult:   AuthResult{Result: authResultPass},
                DMARCResult: AuthResult{Result: authResultPass},
                DKIMResults: []AuthResult{{Result: authResultFail}},
        }
        if checkAllAuthPass(r3) {
                t.Error("should be false when no DKIM passes")
        }
}

func TestStripHTMLTags_B3(t *testing.T) {
        got := stripHTMLTags("<html><body><p>Hello &amp; world</p></body></html>")
        if !strings.Contains(got, "Hello & world") {
                t.Errorf("got %q", got)
        }
        if strings.Contains(got, "<") {
                t.Errorf("should not contain HTML tags: %q", got)
        }

        got2 := stripHTMLTags("<script>alert('xss')</script><p>Safe</p>")
        if strings.Contains(got2, "alert") {
                t.Errorf("script should be removed: %q", got2)
        }
        if !strings.Contains(got2, "Safe") {
                t.Errorf("content should remain: %q", got2)
        }

        got3 := stripHTMLTags("<style>.x{color:red}</style><p>Text</p>")
        if strings.Contains(got3, "color") {
                t.Errorf("style should be removed: %q", got3)
        }
}

func TestDetectSpamFlags_B3(t *testing.T) {
        headers := []headerField{
                {Name: "x-spam-flag", Value: "yes"},
        }
        r := &EmailHeaderAnalysis{}
        detectSpamFlags(headers, r)
        if !r.SpamFlagged {
                t.Error("should detect x-spam-flag: yes")
        }

        r2 := &EmailHeaderAnalysis{}
        headers2 := []headerField{
                {Name: "x-apple-action", Value: "JUNK"},
        }
        detectSpamFlags(headers2, r2)
        if !r2.SpamFlagged {
                t.Error("should detect apple junk")
        }

        r3 := &EmailHeaderAnalysis{}
        headers3 := []headerField{
                {Name: "x-apple-movetofolder", Value: "Junk"},
        }
        detectSpamFlags(headers3, r3)
        if !r3.SpamFlagged {
                t.Error("should detect apple move to junk")
        }

        r4 := &EmailHeaderAnalysis{}
        headers4 := []headerField{
                {Name: "x-barracuda-spam-status", Value: "Yes"},
        }
        detectSpamFlags(headers4, r4)
        if !r4.SpamFlagged {
                t.Error("should detect barracuda spam")
        }
}

func TestDetectVendorSpamScores_B3(t *testing.T) {
        r := &EmailHeaderAnalysis{}
        headers := []headerField{
                {Name: "x-barracuda-spam-score", Value: "7.5"},
                {Name: "x-mimecast-spam-score", Value: "3"},
                {Name: "x-proofpoint-spam-details-enc", Value: "encoded"},
                {Name: "x-forefront-antispam-report", Value: "SCL:6;SFV:SPM"},
        }
        detectVendorSpamScores(headers, r)
        if !r.MicrosoftSCLFound {
                t.Error("should find SCL")
        }
        if r.MicrosoftSCL != 6 {
                t.Errorf("SCL = %d", r.MicrosoftSCL)
        }
        if !r.SpamFlagged {
                t.Error("SCL >= 5 should flag as spam")
        }
        if len(r.SpamFlagSources) < 4 {
                t.Errorf("expected 4+ sources, got %d", len(r.SpamFlagSources))
        }
}

func TestDetectBCCDelivery_B3(t *testing.T) {
        r := &EmailHeaderAnalysis{To: "user@example.com"}
        headers := []headerField{
                {Name: "delivered-to", Value: "other@example.com"},
        }
        detectBCCDelivery(headers, r)
        if !r.BCCDelivery {
                t.Error("should detect BCC")
        }
        if r.BCCRecipient != "other@example.com" {
                t.Errorf("recipient = %q", r.BCCRecipient)
        }

        r2 := &EmailHeaderAnalysis{To: "user@example.com"}
        headers2 := []headerField{
                {Name: "delivered-to", Value: "user@example.com"},
        }
        detectBCCDelivery(headers2, r2)
        if r2.BCCDelivery {
                t.Error("should not detect BCC when To matches")
        }

        r3 := &EmailHeaderAnalysis{To: ""}
        detectBCCDelivery(nil, r3)
        if r3.BCCDelivery {
                t.Error("empty To should not detect BCC")
        }
}

func TestGenerateVerdict_B3(t *testing.T) {
        r := &EmailHeaderAnalysis{
                Flags: []HeaderFlag{
                        {Severity: sevDanger},
                },
        }
        generateVerdict(r)
        if r.Verdict != "suspicious" {
                t.Errorf("danger flags = %q", r.Verdict)
        }

        r2 := &EmailHeaderAnalysis{
                Flags: []HeaderFlag{
                        {Severity: sevWarning},
                },
        }
        generateVerdict(r2)
        if r2.Verdict != "caution" {
                t.Errorf("warning flags = %q", r2.Verdict)
        }

        r3 := &EmailHeaderAnalysis{
                Flags: []HeaderFlag{
                        {Severity: sevInfo},
                },
        }
        generateVerdict(r3)
        if r3.Verdict != "clean" {
                t.Errorf("info only = %q", r3.Verdict)
        }
}

func TestFormatDelay_B3(t *testing.T) {
        tests := []struct {
                ms   int
                want string
        }{
                {500, "<1s"},
                {5000, "5s"},
                {90000, "1.5m"},
                {7200000, "2.0h"},
        }
        for _, tc := range tests {
                got := formatDelay(time.Duration(tc.ms) * time.Millisecond)
                if got != tc.want {
                        t.Errorf("formatDelay(%dms) = %q, want %q", tc.ms, got, tc.want)
                }
        }
}

func TestExtractDomainFromEmailAddress_B3(t *testing.T) {
        tests := []struct {
                addr string
                want string
        }{
                {"user@example.com", "example.com"},
                {"<user@example.com>", "example.com"},
                {"John Doe <user@example.com>", "example.com"},
                {"nodomain", ""},
                {"", ""},
        }
        for _, tc := range tests {
                got := extractDomainFromEmailAddress(tc.addr)
                if got != tc.want {
                        t.Errorf("extractDomainFromEmailAddress(%q) = %q, want %q", tc.addr, got, tc.want)
                }
        }
}

func TestDomainsRelaxedMatch_B3(t *testing.T) {
        if !domainsRelaxedMatch("example.com", "sub.example.com") {
                t.Error("should match subdomain")
        }
        if !domainsRelaxedMatch("sub.example.com", "example.com") {
                t.Error("should match parent")
        }
        if domainsRelaxedMatch("example.com", "other.com") {
                t.Error("should not match different domains")
        }
}

func TestClassifyReturnPathAlignment_B3(t *testing.T) {
        if got := classifyReturnPathAlignment("example.com", "example.com"); got != "aligned" {
                t.Errorf("same = %q", got)
        }
        if got := classifyReturnPathAlignment("example.com", "sub.example.com"); got != "relaxed" {
                t.Errorf("subdomain = %q", got)
        }
        if got := classifyReturnPathAlignment("example.com", "other.com"); got != alignMisaligned {
                t.Errorf("different = %q", got)
        }
}

func TestScanPhraseCategory_B3(t *testing.T) {
        cfg := phraseScanConfig{
                phrases:        []string{"urgent", "act now"},
                multiCategory:  "Multi",
                multiSev:       sevDanger,
                multiDesc:      "Multiple matches",
                minForMulti:    2,
                singleCategory: "Single",
                singleSev:      sevWarning,
                singleDesc:     "Single match",
        }
        got := scanPhraseCategory("this is urgent and you must act now", cfg)
        if got == nil || got.Category != "Multi" {
                t.Error("should match multi")
        }

        got2 := scanPhraseCategory("this is urgent", cfg)
        if got2 == nil || got2.Category != "Single" {
                t.Error("should match single")
        }

        got3 := scanPhraseCategory("nothing to see here", cfg)
        if got3 != nil {
                t.Error("should not match")
        }
}

func TestScanFirstMatch_B3(t *testing.T) {
        got := scanFirstMatch("hello world", []string{"world"}, "Cat", "sev", "desc", "prefix: ")
        if got == nil {
                t.Fatal("should match")
        }
        if got.Evidence != "prefix: world" {
                t.Errorf("evidence = %q", got.Evidence)
        }

        got2 := scanFirstMatch("hello", []string{"world"}, "Cat", "sev", "desc", "prefix: ")
        if got2 != nil {
                t.Error("should not match")
        }
}

func TestIsSuspicious_B3(t *testing.T) {
        if !isSuspicious(verdictCounts{danger: 1}, false) {
                t.Error("danger > 0 should be suspicious")
        }
        if !isSuspicious(verdictCounts{phishingDanger: 2}, false) {
                t.Error("phishing >= 2 should be suspicious")
        }
        if !isSuspicious(verdictCounts{phishingDanger: 1}, true) {
                t.Error("spam + phishing should be suspicious")
        }
        if isSuspicious(verdictCounts{}, false) {
                t.Error("empty should not be suspicious")
        }
}

func TestClassifyCTFailure_CB3(t *testing.T) {
        if got := classifyCTFailure(""); got != "timeout" {
                t.Errorf("empty = %q", got)
        }
        if got := classifyCTFailure("deadline exceeded"); got != "timeout" {
                t.Errorf("deadline = %q", got)
        }
        if got := classifyCTFailure("some error"); got != mapKeyError {
                t.Errorf("other = %q", got)
        }
}

func TestParseDNAttributes_CB3(t *testing.T) {
        got := parseDNAttributes("O=Example, CN=test")
        if len(got) != 2 {
                t.Errorf("expected 2, got %d: %v", len(got), got)
        }
        quoted := parseDNAttributes(`O="Test, Inc", CN=foo`)
        if len(quoted) != 2 {
                t.Errorf("quoted expected 2, got %d: %v", len(quoted), quoted)
        }
}

func TestMarshalRemoteProbeBody_CB3(t *testing.T) {
        body, fail := marshalRemoteProbeBody([]string{"mx1.example.com", "mx2.example.com"})
        if body == nil || fail != "" {
                t.Error("should succeed")
        }

        many := make([]string, 10)
        for i := range many {
                many[i] = "mx.example.com"
        }
        body2, _ := marshalRemoteProbeBody(many)
        if body2 == nil {
                t.Error("should succeed with truncation")
        }
}

func TestGetVerdict_B3(t *testing.T) {
        got := getVerdict(map[string]any{
                "spf_analysis": map[string]any{"status": "success"},
        }, "spf_analysis")
        if got != "success" {
                t.Errorf("got %q", got)
        }
        got2 := getVerdict(map[string]any{}, "missing")
        if got2 != "" {
                t.Errorf("missing = %q", got2)
        }
}

func TestDetectWildcardCerts_CB3(t *testing.T) {
        entries := []ctEntry{
                {NameValue: "*.example.com\nsub.example.com", NotBefore: "2024-01-01", NotAfter: "2099-01-01", IssuerName: "O=LE"},
        }
        got := detectWildcardCerts(entries, "example.com")
        if got == nil {
                t.Fatal("should detect wildcard")
        }
        if got["present"] != true {
                t.Error("present should be true")
        }

        got2 := detectWildcardCerts([]ctEntry{{NameValue: "sub.example.com"}}, "example.com")
        if got2 != nil {
                t.Error("should return nil for no wildcard")
        }
}

func TestCollectSubdomains_CB3(t *testing.T) {
        set := map[string]map[string]any{
                "a": {mapKeyName: "a", mapKeyCnameTarget: "b.com"},
                "b": {mapKeyName: "b"},
        }
        subs, cnameCount := collectSubdomains(set)
        if len(subs) != 2 {
                t.Errorf("expected 2, got %d", len(subs))
        }
        if cnameCount != 1 {
                t.Errorf("cname count = %d", cnameCount)
        }
}

func TestAppendTLSRPTFixes_B3(t *testing.T) {
        fixes := appendTLSRPTFixes(nil, protocolState{tlsrptOK: false, daneOK: true}, "example.com")
        if len(fixes) != 1 {
                t.Fatalf("expected 1, got %d", len(fixes))
        }
        if !strings.Contains(fixes[0].Description, "DNSSEC + DANE") {
                t.Errorf("should mention DANE: %q", fixes[0].Description)
        }

        fixes2 := appendTLSRPTFixes(nil, protocolState{tlsrptOK: false, mtaStsOK: true}, "example.com")
        if !strings.Contains(fixes2[0].Description, "MTA-STS") {
                t.Errorf("should mention MTA-STS: %q", fixes2[0].Description)
        }

        fixes3 := appendTLSRPTFixes(nil, protocolState{tlsrptOK: true}, "example.com")
        if len(fixes3) != 0 {
                t.Errorf("ok should have 0, got %d", len(fixes3))
        }

        fixes4 := appendTLSRPTFixes(nil, protocolState{tlsrptOK: false, isNoMailDomain: true}, "example.com")
        if len(fixes4) != 0 {
                t.Errorf("no mail should have 0, got %d", len(fixes4))
        }
}

func TestAppendMTASTSFixes_B3(t *testing.T) {
        fixes := appendMTASTSFixes(nil, protocolState{mtaStsOK: false}, "example.com")
        if len(fixes) != 1 {
                t.Errorf("expected 1, got %d", len(fixes))
        }
        fixes2 := appendMTASTSFixes(nil, protocolState{mtaStsOK: true}, "example.com")
        if len(fixes2) != 0 {
                t.Errorf("ok = %d", len(fixes2))
        }
        fixes3 := appendMTASTSFixes(nil, protocolState{isNoMailDomain: true}, "example.com")
        if len(fixes3) != 0 {
                t.Errorf("no mail = %d", len(fixes3))
        }
}

func TestAppendCAAFixes_B3(t *testing.T) {
        fixes := appendCAAFixes(nil, protocolState{caaOK: false}, "example.com")
        if len(fixes) != 1 {
                t.Errorf("expected 1, got %d", len(fixes))
        }
        fixes2 := appendCAAFixes(nil, protocolState{caaOK: true}, "example.com")
        if len(fixes2) != 0 {
                t.Errorf("ok = %d", len(fixes2))
        }
}

func TestAppendDKIMFixes_B3(t *testing.T) {
        fixes := appendDKIMFixes(nil, protocolState{}, DKIMWeakKeysOnly, map[string]any{}, "example.com")
        if len(fixes) != 1 || fixes[0].Title != "Upgrade DKIM Key Strength" {
                t.Errorf("weak keys: %v", fixes)
        }

        fixes2 := appendDKIMFixes(nil, protocolState{}, DKIMAbsent, map[string]any{}, "example.com")
        if len(fixes2) != 1 || fixes2[0].Title != "Configure DKIM Signing" {
                t.Errorf("absent: %v", fixes2)
        }

        fixes3 := appendDKIMFixes(nil, protocolState{}, DKIMThirdPartyOnly, map[string]any{}, "example.com")
        if len(fixes3) != 1 || fixes3[0].Title != "Add Primary Domain DKIM" {
                t.Errorf("third party: %v", fixes3)
        }

        fixes4 := appendDKIMFixes(nil, protocolState{}, DKIMSuccess, map[string]any{}, "example.com")
        if len(fixes4) != 0 {
                t.Errorf("success = %d", len(fixes4))
        }
}

func TestParseEmailDate_B3(t *testing.T) {
        got, err := parseEmailDate("Mon, 02 Jan 2006 15:04:05 -0700")
        if err != nil {
                t.Errorf("RFC1123Z-like = %v", err)
        }
        if got.Year() != 2006 {
                t.Errorf("year = %d", got.Year())
        }

        _, err2 := parseEmailDate("not a date")
        if err2 == nil {
                t.Error("should fail for invalid")
        }

        got3, err3 := parseEmailDate("Mon, 02 Jan 2006 15:04:05 -0700 (PST)")
        if err3 != nil {
                t.Errorf("with paren = %v", err3)
        }
        if got3.Year() != 2006 {
                t.Errorf("paren year = %d", got3.Year())
        }
}

func TestPopulateCTResults_CB3(t *testing.T) {
        result := map[string]any{}
        entries := []ctEntry{
                {IssuerName: "O=LE", NotBefore: "2024-01-01", NotAfter: "2025-01-01"},
        }
        populateCTResults(result, entries, entries, "example.com", true)
        if result["total_certs"] != 1 {
                t.Errorf("total_certs = %v", result["total_certs"])
        }

        result2 := map[string]any{}
        populateCTResults(result2, nil, nil, "example.com", false)
        if _, ok := result2["total_certs"]; ok {
                t.Error("should not populate when not available")
        }
}
