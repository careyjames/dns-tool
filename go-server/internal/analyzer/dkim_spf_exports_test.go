package analyzer

import (
        "strings"
        "testing"
)

func TestDKIMStateString(t *testing.T) {
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
                        t.Errorf("DKIMState(%d).String() = %q, want %q", int(tt.state), got, tt.want)
                }
        }
}

func TestDKIMStateIsConfigured(t *testing.T) {
        tests := []struct {
                state DKIMState
                want  bool
        }{
                {DKIMSuccess, true},
                {DKIMProviderInferred, true},
                {DKIMThirdPartyOnly, true},
                {DKIMAbsent, false},
                {DKIMInconclusive, false},
                {DKIMWeakKeysOnly, false},
                {DKIMNoMailDomain, false},
        }
        for _, tt := range tests {
                if got := tt.state.IsConfigured(); got != tt.want {
                        t.Errorf("DKIMState(%d).IsConfigured() = %v, want %v", int(tt.state), got, tt.want)
                }
        }
}

func TestDKIMStateNeedsAction(t *testing.T) {
        if !DKIMAbsent.NeedsAction() {
                t.Error("DKIMAbsent.NeedsAction() should be true")
        }
        if DKIMSuccess.NeedsAction() {
                t.Error("DKIMSuccess.NeedsAction() should be false")
        }
        if DKIMInconclusive.NeedsAction() {
                t.Error("DKIMInconclusive.NeedsAction() should be false")
        }
}

func TestDKIMStateNeedsMonitoring(t *testing.T) {
        if !DKIMInconclusive.NeedsMonitoring() {
                t.Error("DKIMInconclusive.NeedsMonitoring() should be true")
        }
        if DKIMAbsent.NeedsMonitoring() {
                t.Error("DKIMAbsent.NeedsMonitoring() should be false")
        }
        if DKIMSuccess.NeedsMonitoring() {
                t.Error("DKIMSuccess.NeedsMonitoring() should be false")
        }
}

func TestClassifyDKIMState(t *testing.T) {
        tests := []struct {
                name string
                ps   protocolState
                want DKIMState
        }{
                {"no_mail", protocolState{isNoMailDomain: true}, DKIMNoMailDomain},
                {"dkim_ok", protocolState{dkimOK: true}, DKIMSuccess},
                {"provider", protocolState{dkimProvider: true}, DKIMProviderInferred},
                {"partial", protocolState{dkimPartial: true}, DKIMThirdPartyOnly},
                {"third_party_only", protocolState{dkimThirdPartyOnly: true}, DKIMThirdPartyOnly},
                {"weak_keys", protocolState{dkimWeakKeys: true}, DKIMWeakKeysOnly},
                {"absent", protocolState{}, DKIMAbsent},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        if got := classifyDKIMState(tt.ps); got != tt.want {
                                t.Errorf("classifyDKIMState() = %v, want %v", got, tt.want)
                        }
                })
        }
}

func TestConfidenceInferredMap(t *testing.T) {
        m := ConfidenceInferredMap("test method")
        if m["level"] != ConfidenceInferred {
                t.Errorf("level = %v, want %v", m["level"], ConfidenceInferred)
        }
        if m["label"] != ConfidenceLabelInferred {
                t.Errorf("label = %v, want %v", m["label"], ConfidenceLabelInferred)
        }
        if m["method"] != "test method" {
                t.Errorf("method = %v", m["method"])
        }
}

func TestConfidenceThirdPartyMap(t *testing.T) {
        m := ConfidenceThirdPartyMap("team cymru")
        if m["level"] != ConfidenceThirdParty {
                t.Errorf("level = %v, want %v", m["level"], ConfidenceThirdParty)
        }
        if m["label"] != ConfidenceLabelThirdParty {
                t.Errorf("label = %v, want %v", m["label"], ConfidenceLabelThirdParty)
        }
}

func TestDisplayVal(t *testing.T) {
        if displayVal("") != "(none)" {
                t.Error("empty string should be (none)")
        }
        if displayVal("  ") != "(none)" {
                t.Error("whitespace should be (none)")
        }
        if displayVal("pass") != "pass" {
                t.Error("pass should remain pass")
        }
        if displayVal("  pass  ") != "pass" {
                t.Error("should trim whitespace")
        }
}

func TestNormalizeStatusVal(t *testing.T) {
        if got := normalizeStatusVal("Pass"); got != "pass" {
                t.Errorf("got %q, want pass", got)
        }
        if got := normalizeStatusVal("Pass (details)"); got != "pass" {
                t.Errorf("got %q, want pass (strip parens)", got)
        }
        if got := normalizeStatusVal("  REJECT  "); got != "reject" {
                t.Errorf("got %q, want reject", got)
        }
}

func TestClassifyPolicyChange(t *testing.T) {
        tests := []struct {
                prev, curr, want string
        }{
                {"reject", "none", "danger"},
                {"reject", "quarantine", "danger"},
                {"none", "reject", "success"},
                {"quarantine", "reject", "success"},
                {"reject", "reject", "info"},
                {"", "reject", "success"},
                {"reject", "", "danger"},
        }
        for _, tt := range tests {
                if got := classifyPolicyChange(tt.prev, tt.curr); got != tt.want {
                        t.Errorf("classifyPolicyChange(%q, %q) = %q, want %q", tt.prev, tt.curr, got, tt.want)
                }
        }
}

func TestClassifyStatusChange(t *testing.T) {
        tests := []struct {
                prev, curr, want string
        }{
                {"pass", "fail", "danger"},
                {"pass", "missing", "danger"},
                {"fail", "pass", "success"},
                {"missing", "configured", "success"},
                {"pass", "configured", "warning"},
                {"fail", "missing", "warning"},
        }
        for _, tt := range tests {
                if got := classifyStatusChange(tt.prev, tt.curr); got != tt.want {
                        t.Errorf("classifyStatusChange(%q, %q) = %q, want %q", tt.prev, tt.curr, got, tt.want)
                }
        }
}

func TestClassifyDriftSeverity(t *testing.T) {
        tests := []struct {
                label, prev, curr, want string
        }{
                {"DMARC Policy", "reject", "none", "danger"},
                {"SPF Status", "pass", "fail", "danger"},
                {"DANE Present", "enabled", "missing", "danger"},
                {"SPF Records", "v=spf1 a", "v=spf1 mx", "warning"},
                {"DKIM Selectors", "s1", "s2", "warning"},
                {"CAA Tags", "tag1", "tag2", "warning"},
                {"Mail Posture", "old", "new", "info"},
        }
        for _, tt := range tests {
                if got := classifyDriftSeverity(tt.label, tt.prev, tt.curr); got != tt.want {
                        t.Errorf("classifyDriftSeverity(%q, %q, %q) = %q, want %q", tt.label, tt.prev, tt.curr, got, tt.want)
                }
        }
}

func TestComputePostureDiff_NoDiffs(t *testing.T) {
        a := map[string]any{}
        diffs := ComputePostureDiff(a, a)
        if len(diffs) != 0 {
                t.Errorf("expected 0 diffs, got %d", len(diffs))
        }
}

func TestComputePostureDiff_SPFChange(t *testing.T) {
        prev := map[string]any{
                "spf_analysis": map[string]any{mapKeyStatus: "pass"},
        }
        curr := map[string]any{
                "spf_analysis": map[string]any{mapKeyStatus: "fail"},
        }
        diffs := ComputePostureDiff(prev, curr)
        found := false
        for _, d := range diffs {
                if d.Label == "SPF Status" {
                        found = true
                        if d.Previous != "pass" || d.Current != "fail" {
                                t.Errorf("unexpected diff values: %+v", d)
                        }
                }
        }
        if !found {
                t.Error("expected SPF Status diff")
        }
}

func TestComputePostureDiff_DANEBoolChange(t *testing.T) {
        prev := map[string]any{
                mapKeyDaneAnalysis: map[string]any{"has_dane": true},
        }
        curr := map[string]any{
                mapKeyDaneAnalysis: map[string]any{"has_dane": false},
        }
        diffs := ComputePostureDiff(prev, curr)
        found := false
        for _, d := range diffs {
                if d.Label == "DANE Present" {
                        found = true
                }
        }
        if !found {
                t.Error("expected DANE Present diff")
        }
}

func TestExtractSelectorName(t *testing.T) {
        if got := extractSelectorName("myselector"); got != "myselector" {
                t.Errorf("string case: got %q", got)
        }
        if got := extractSelectorName(map[string]any{"selector": "s1"}); got != "s1" {
                t.Errorf("map selector case: got %q", got)
        }
        if got := extractSelectorName(map[string]any{"name": "n1"}); got != "n1" {
                t.Errorf("map name case: got %q", got)
        }
        if got := extractSelectorName(map[string]any{"other": "val"}); got != "" {
                t.Errorf("map no match: got %q", got)
        }
        if got := extractSelectorName(42); got != "" {
                t.Errorf("int case: got %q", got)
        }
}

func TestFindExternalAuthMap(t *testing.T) {
        t.Run("direct", func(t *testing.T) {
                results := map[string]any{
                        "dmarc_report_auth": map[string]any{"key": "val"},
                }
                m := findExternalAuthMap(results)
                if m == nil || m["key"] != "val" {
                        t.Error("expected direct match")
                }
        })
        t.Run("nested", func(t *testing.T) {
                results := map[string]any{
                        "dmarc": map[string]any{
                                "external_report_auth": map[string]any{"nested": true},
                        },
                }
                m := findExternalAuthMap(results)
                if m == nil || m["nested"] != true {
                        t.Error("expected nested match")
                }
        })
        t.Run("nil", func(t *testing.T) {
                m := findExternalAuthMap(map[string]any{})
                if m != nil {
                        t.Error("expected nil for empty results")
                }
        })
        t.Run("wrong_type", func(t *testing.T) {
                results := map[string]any{
                        "dmarc_report_auth": "not a map",
                }
                m := findExternalAuthMap(results)
                if m != nil {
                        t.Error("expected nil for wrong type")
                }
        })
        t.Run("dmarc_not_map", func(t *testing.T) {
                results := map[string]any{
                        "dmarc": "not a map",
                }
                m := findExternalAuthMap(results)
                if m != nil {
                        t.Error("expected nil for dmarc not a map")
                }
        })
        t.Run("no_external_report_auth", func(t *testing.T) {
                results := map[string]any{
                        "dmarc": map[string]any{},
                }
                m := findExternalAuthMap(results)
                if m != nil {
                        t.Error("expected nil when no external_report_auth key")
                }
        })
}

func TestExtractDMARCRuaTargets(t *testing.T) {
        t.Run("nil_auth", func(t *testing.T) {
                got := extractDMARCRuaTargets(map[string]any{})
                if got != nil {
                        t.Error("expected nil")
                }
        })
        t.Run("string_targets", func(t *testing.T) {
                results := map[string]any{
                        "dmarc_report_auth": map[string]any{
                                "external_domains": []any{"example.com", "test.com"},
                        },
                }
                got := extractDMARCRuaTargets(results)
                if len(got) != 2 || got[0] != "example.com" {
                        t.Errorf("got %v", got)
                }
        })
        t.Run("map_targets", func(t *testing.T) {
                results := map[string]any{
                        "dmarc_report_auth": map[string]any{
                                "external_domains": []any{
                                        map[string]any{"domain": "foo.com"},
                                },
                        },
                }
                got := extractDMARCRuaTargets(results)
                if len(got) != 1 || got[0] != "foo.com" {
                        t.Errorf("got %v", got)
                }
        })
        t.Run("domains_fallback", func(t *testing.T) {
                results := map[string]any{
                        "dmarc_report_auth": map[string]any{
                                "domains": []any{"fallback.com"},
                        },
                }
                got := extractDMARCRuaTargets(results)
                if len(got) != 1 || got[0] != "fallback.com" {
                        t.Errorf("got %v", got)
                }
        })
        t.Run("not_list", func(t *testing.T) {
                results := map[string]any{
                        "dmarc_report_auth": map[string]any{
                                "external_domains": "not a list",
                        },
                }
                got := extractDMARCRuaTargets(results)
                if got != nil {
                        t.Error("expected nil for non-list targets")
                }
        })
}

func TestBuildEmailVerdict(t *testing.T) {
        t.Run("enforcing_reject", func(t *testing.T) {
                vi := verdictInput{
                        ps:       protocolState{dmarcPolicy: "reject", dmarcPct: 100},
                        ds:       DKIMSuccess,
                        hasSPF:   true,
                        hasDMARC: true,
                }
                verdicts := map[string]any{}
                buildEmailVerdict(vi, verdicts)
                v := verdicts[mapKeyEmailSpoofing].(map[string]any)
                if v[mapKeyLabel] != strProtected {
                        t.Errorf("expected Protected, got %v", v[mapKeyLabel])
                }
        })
        t.Run("spf_only", func(t *testing.T) {
                vi := verdictInput{hasSPF: true, hasDMARC: false}
                verdicts := map[string]any{}
                buildEmailVerdict(vi, verdicts)
                v := verdicts[mapKeyEmailSpoofing].(map[string]any)
                if v[mapKeyLabel] != strBasic {
                        t.Errorf("expected Basic, got %v", v[mapKeyLabel])
                }
        })
        t.Run("none", func(t *testing.T) {
                vi := verdictInput{hasSPF: false, hasDMARC: false}
                verdicts := map[string]any{}
                buildEmailVerdict(vi, verdicts)
                v := verdicts[mapKeyEmailSpoofing].(map[string]any)
                if v[mapKeyLabel] != strExposed {
                        t.Errorf("expected Exposed, got %v", v[mapKeyLabel])
                }
        })
        t.Run("spf_and_dmarc_weak", func(t *testing.T) {
                vi := verdictInput{
                        ps:       protocolState{dmarcPolicy: "none"},
                        hasSPF:   true,
                        hasDMARC: true,
                }
                verdicts := map[string]any{}
                buildEmailVerdict(vi, verdicts)
                v := verdicts[mapKeyEmailSpoofing].(map[string]any)
                if v[mapKeyLabel] != strBasic {
                        t.Errorf("expected Basic for weak dmarc, got %v", v[mapKeyLabel])
                }
        })
        t.Run("dmarc_only", func(t *testing.T) {
                vi := verdictInput{hasSPF: false, hasDMARC: true}
                verdicts := map[string]any{}
                buildEmailVerdict(vi, verdicts)
                v := verdicts[mapKeyEmailSpoofing].(map[string]any)
                if v[mapKeyLabel] != strExposed {
                        t.Errorf("expected Exposed for dmarc only, got %v", v[mapKeyLabel])
                }
        })
}

func TestBuildBrandVerdict(t *testing.T) {
        t.Run("missing_dmarc", func(t *testing.T) {
                verdicts := map[string]any{}
                buildBrandVerdict(protocolState{dmarcMissing: true}, verdicts)
                v := verdicts[mapKeyBrandImpersonation].(map[string]any)
                if v[mapKeyLabel] != strExposed {
                        t.Errorf("got %v", v[mapKeyLabel])
                }
        })
        t.Run("reject_bimi_caa", func(t *testing.T) {
                verdicts := map[string]any{}
                buildBrandVerdict(protocolState{dmarcPolicy: "reject", bimiOK: true, caaOK: true}, verdicts)
                v := verdicts[mapKeyBrandImpersonation].(map[string]any)
                if v[mapKeyLabel] != strProtected {
                        t.Errorf("got %v", v[mapKeyLabel])
                }
        })
        t.Run("reject_bimi_no_caa", func(t *testing.T) {
                verdicts := map[string]any{}
                buildBrandVerdict(protocolState{dmarcPolicy: "reject", bimiOK: true}, verdicts)
                v := verdicts[mapKeyBrandImpersonation].(map[string]any)
                if v[mapKeyLabel] != "Well Protected" {
                        t.Errorf("got %v", v[mapKeyLabel])
                }
        })
        t.Run("reject_caa_no_bimi", func(t *testing.T) {
                verdicts := map[string]any{}
                buildBrandVerdict(protocolState{dmarcPolicy: "reject", caaOK: true}, verdicts)
                v := verdicts[mapKeyBrandImpersonation].(map[string]any)
                if v[mapKeyLabel] != "Mostly Protected" {
                        t.Errorf("got %v", v[mapKeyLabel])
                }
        })
        t.Run("reject_no_bimi_no_caa", func(t *testing.T) {
                verdicts := map[string]any{}
                buildBrandVerdict(protocolState{dmarcPolicy: "reject"}, verdicts)
                v := verdicts[mapKeyBrandImpersonation].(map[string]any)
                if v[mapKeyLabel] != "Partially Protected" {
                        t.Errorf("got %v", v[mapKeyLabel])
                }
        })
        t.Run("quarantine_bimi_caa", func(t *testing.T) {
                verdicts := map[string]any{}
                buildBrandVerdict(protocolState{dmarcPolicy: "quarantine", bimiOK: true, caaOK: true}, verdicts)
                v := verdicts[mapKeyBrandImpersonation].(map[string]any)
                if v[mapKeyLabel] != "Well Protected" {
                        t.Errorf("got %v", v[mapKeyLabel])
                }
        })
        t.Run("quarantine_bimi_only", func(t *testing.T) {
                verdicts := map[string]any{}
                buildBrandVerdict(protocolState{dmarcPolicy: "quarantine", bimiOK: true}, verdicts)
                v := verdicts[mapKeyBrandImpersonation].(map[string]any)
                if v[mapKeyLabel] != "Mostly Protected" {
                        t.Errorf("got %v", v[mapKeyLabel])
                }
        })
        t.Run("quarantine_caa_only", func(t *testing.T) {
                verdicts := map[string]any{}
                buildBrandVerdict(protocolState{dmarcPolicy: "quarantine", caaOK: true}, verdicts)
                v := verdicts[mapKeyBrandImpersonation].(map[string]any)
                if v[mapKeyLabel] != "Partially Protected" {
                        t.Errorf("got %v", v[mapKeyLabel])
                }
        })
        t.Run("quarantine_nothing", func(t *testing.T) {
                verdicts := map[string]any{}
                buildBrandVerdict(protocolState{dmarcPolicy: "quarantine"}, verdicts)
                v := verdicts[mapKeyBrandImpersonation].(map[string]any)
                if v[mapKeyLabel] != strBasic {
                        t.Errorf("got %v", v[mapKeyLabel])
                }
        })
        t.Run("none_policy", func(t *testing.T) {
                verdicts := map[string]any{}
                buildBrandVerdict(protocolState{dmarcPolicy: "none"}, verdicts)
                v := verdicts[mapKeyBrandImpersonation].(map[string]any)
                if v[mapKeyLabel] != strBasic {
                        t.Errorf("got %v", v[mapKeyLabel])
                }
                reason := v[mapKeyReason].(string)
                if !strings.Contains(reason, "monitor-only") {
                        t.Errorf("expected monitor-only in reason for none policy, got %s", reason)
                }
        })
        t.Run("unknown_policy", func(t *testing.T) {
                verdicts := map[string]any{}
                buildBrandVerdict(protocolState{dmarcPolicy: "something"}, verdicts)
                v := verdicts[mapKeyBrandImpersonation].(map[string]any)
                if v[mapKeyLabel] != strBasic {
                        t.Errorf("got %v", v[mapKeyLabel])
                }
        })
}

func TestBuildVerdicts(t *testing.T) {
        vi := verdictInput{
                ps:       protocolState{dmarcPolicy: "reject", dmarcPct: 100, dnssecOK: true},
                ds:       DKIMSuccess,
                hasSPF:   true,
                hasDMARC: true,
                hasDKIM:  true,
        }
        verdicts := buildVerdicts(vi)
        if _, ok := verdicts[mapKeyEmailSpoofing]; !ok {
                t.Error("missing email_spoofing verdict")
        }
        if _, ok := verdicts[mapKeyBrandImpersonation]; !ok {
                t.Error("missing brand_impersonation verdict")
        }
        if _, ok := verdicts[mapKeyDnsTampering]; !ok {
                t.Error("missing dns_tampering verdict")
        }
        if _, ok := verdicts[mapKeyTransport]; !ok {
                t.Error("missing transport verdict")
        }
        if _, ok := verdicts["email_answer"]; !ok {
                t.Error("missing email_answer")
        }
        if _, ok := verdicts["email_answer_short"]; !ok {
                t.Error("missing email_answer_short")
        }
}

func TestBuildDescriptiveMessage_Boost(t *testing.T) {
        msg := buildDescriptiveMessage(protocolState{}, []string{"SPF", "DMARC"}, []string{"DANE"}, []string{"DKIM"})
        if !strings.Contains(msg, "2 protocols configured") {
                t.Errorf("missing configured count in: %s", msg)
        }
        if !strings.Contains(msg, "1 not configured") {
                t.Errorf("missing absent count in: %s", msg)
        }
        if !strings.Contains(msg, "1 need attention") {
                t.Errorf("missing monitoring count in: %s", msg)
        }

        empty := buildDescriptiveMessage(protocolState{}, nil, nil, nil)
        if empty != "Email security posture evaluated" {
                t.Errorf("got %q", empty)
        }
}

func TestGetNumericValue_Boost(t *testing.T) {
        m := map[string]any{
                "float":   3.14,
                "int":     42,
                "int64":   int64(100),
                "str":     "hello",
                "missing": nil,
        }
        if got := getNumericValue(m, "float"); got != 3.14 {
                t.Errorf("float: got %v", got)
        }
        if got := getNumericValue(m, "int"); got != 42.0 {
                t.Errorf("int: got %v", got)
        }
        if got := getNumericValue(m, "int64"); got != 100.0 {
                t.Errorf("int64: got %v", got)
        }
        if got := getNumericValue(m, "str"); got != 0 {
                t.Errorf("str: got %v", got)
        }
        if got := getNumericValue(m, "nonexistent"); got != 0 {
                t.Errorf("nonexistent: got %v", got)
        }
}

func TestCanonicalPostureHashLegacySHA256(t *testing.T) {
        results := map[string]any{}
        hash := CanonicalPostureHashLegacySHA256(results)
        if hash == "" {
                t.Error("expected non-empty hash")
        }
        if len(hash) != 64 {
                t.Errorf("expected 64-char hex hash, got %d chars", len(hash))
        }

        hash2 := CanonicalPostureHashLegacySHA256(results)
        if hash != hash2 {
                t.Error("expected deterministic hash")
        }

        results2 := map[string]any{
                "spf_analysis": map[string]any{mapKeyStatus: "pass"},
        }
        hash3 := CanonicalPostureHashLegacySHA256(results2)
        if hash3 == hash {
                t.Error("expected different hash for different input")
        }
}

func TestExtractSortedNS(t *testing.T) {
        t.Run("from_basic_records", func(t *testing.T) {
                results := map[string]any{
                        "basic_records": map[string]any{
                                "ns": []any{"ns2.example.com", "ns1.example.com"},
                        },
                }
                got := extractSortedNS(results)
                if got != "ns1.example.com,ns2.example.com" {
                        t.Errorf("got %q", got)
                }
        })
        t.Run("from_authoritative", func(t *testing.T) {
                results := map[string]any{
                        "basic_records":         map[string]any{},
                        "authoritative_records": map[string]any{"ns": []string{"ns2.test.com", "ns1.test.com"}},
                }
                got := extractSortedNS(results)
                if got != "ns1.test.com,ns2.test.com" {
                        t.Errorf("got %q", got)
                }
        })
        t.Run("empty", func(t *testing.T) {
                got := extractSortedNS(map[string]any{})
                if got != "" {
                        t.Errorf("got %q", got)
                }
        })
        t.Run("wrong_type", func(t *testing.T) {
                results := map[string]any{
                        "basic_records": map[string]any{"ns": 42},
                }
                got := extractSortedNS(results)
                if got != "" {
                        t.Errorf("got %q for wrong type", got)
                }
        })
}

func TestExtractSortedRecords(t *testing.T) {
        t.Run("string_slice", func(t *testing.T) {
                results := map[string]any{
                        "spf_analysis": map[string]any{
                                "records": []string{"b", "a"},
                        },
                }
                got := extractSortedRecords(results, "spf_analysis", "records")
                if got != "a,b" {
                        t.Errorf("got %q", got)
                }
        })
        t.Run("any_slice", func(t *testing.T) {
                results := map[string]any{
                        "spf_analysis": map[string]any{
                                "records": []any{"z", "a"},
                        },
                }
                got := extractSortedRecords(results, "spf_analysis", "records")
                if got != "a,z" {
                        t.Errorf("got %q", got)
                }
        })
        t.Run("missing_section", func(t *testing.T) {
                got := extractSortedRecords(map[string]any{}, "spf_analysis", "records")
                if got != "" {
                        t.Errorf("got %q", got)
                }
        })
        t.Run("missing_key", func(t *testing.T) {
                results := map[string]any{
                        "spf_analysis": map[string]any{},
                }
                got := extractSortedRecords(results, "spf_analysis", "records")
                if got != "" {
                        t.Errorf("got %q", got)
                }
        })
}

func TestDetectSpamFlags_Boost(t *testing.T) {
        t.Run("x-spam-flag-yes", func(t *testing.T) {
                fields := []headerField{{Name: "x-spam-flag", Value: "yes"}}
                result := &EmailHeaderAnalysis{}
                detectSpamFlags(fields, result)
                if !result.SpamFlagged {
                        t.Error("expected spam flagged")
                }
        })
        t.Run("apple-junk", func(t *testing.T) {
                fields := []headerField{{Name: "x-apple-action", Value: "JUNK"}}
                result := &EmailHeaderAnalysis{}
                detectSpamFlags(fields, result)
                if !result.SpamFlagged {
                        t.Error("expected spam flagged for Apple JUNK")
                }
        })
        t.Run("apple-movetofolder-junk", func(t *testing.T) {
                fields := []headerField{{Name: "x-apple-movetofolder", Value: "Junk"}}
                result := &EmailHeaderAnalysis{}
                detectSpamFlags(fields, result)
                if !result.SpamFlagged {
                        t.Error("expected spam flagged for Apple MoveToFolder Junk")
                }
        })
        t.Run("barracuda-yes", func(t *testing.T) {
                fields := []headerField{{Name: "x-barracuda-spam-status", Value: "Yes"}}
                result := &EmailHeaderAnalysis{}
                detectSpamFlags(fields, result)
                if !result.SpamFlagged {
                        t.Error("expected spam flagged for Barracuda")
                }
        })
        t.Run("no-spam", func(t *testing.T) {
                fields := []headerField{{Name: "subject", Value: "hello"}}
                result := &EmailHeaderAnalysis{}
                detectSpamFlags(fields, result)
                if result.SpamFlagged {
                        t.Error("should not be spam flagged")
                }
        })
}

func TestDetectVendorSpamScores_Boost(t *testing.T) {
        t.Run("barracuda_score", func(t *testing.T) {
                fields := []headerField{{Name: "x-barracuda-spam-score", Value: "7.5"}}
                result := &EmailHeaderAnalysis{}
                detectVendorSpamScores(fields, result)
                if len(result.SpamFlagSources) != 1 {
                        t.Errorf("expected 1 source, got %d", len(result.SpamFlagSources))
                }
        })
        t.Run("mimecast", func(t *testing.T) {
                fields := []headerField{{Name: "x-mimecast-spam-score", Value: "5"}}
                result := &EmailHeaderAnalysis{}
                detectVendorSpamScores(fields, result)
                if len(result.SpamFlagSources) != 1 {
                        t.Errorf("expected 1 source, got %d", len(result.SpamFlagSources))
                }
        })
        t.Run("proofpoint", func(t *testing.T) {
                fields := []headerField{{Name: "x-proofpoint-spam-details-enc", Value: "encoded-data"}}
                result := &EmailHeaderAnalysis{}
                detectVendorSpamScores(fields, result)
                if len(result.SpamFlagSources) != 1 {
                        t.Errorf("expected 1 source, got %d", len(result.SpamFlagSources))
                }
        })
        t.Run("microsoft_scl_high", func(t *testing.T) {
                fields := []headerField{{Name: "x-forefront-antispam-report", Value: "SFV:SPM;SCL:9;SRV:;IPV:NLI"}}
                result := &EmailHeaderAnalysis{}
                detectVendorSpamScores(fields, result)
                if !result.SpamFlagged {
                        t.Error("expected spam flagged for SCL >= 5")
                }
                if !result.MicrosoftSCLFound {
                        t.Error("expected MicrosoftSCLFound")
                }
                if result.MicrosoftSCL != 9 {
                        t.Errorf("expected SCL 9, got %d", result.MicrosoftSCL)
                }
        })
        t.Run("microsoft_scl_low", func(t *testing.T) {
                fields := []headerField{{Name: "x-forefront-antispam-report", Value: "SCL:1"}}
                result := &EmailHeaderAnalysis{}
                detectVendorSpamScores(fields, result)
                if result.SpamFlagged {
                        t.Error("should not be spam flagged for low SCL")
                }
                if result.MicrosoftSCL != 1 {
                        t.Errorf("expected SCL 1, got %d", result.MicrosoftSCL)
                }
        })
        t.Run("clx_score_very_negative", func(t *testing.T) {
                fields := []headerField{{Name: "x-clx-score", Value: "-200"}}
                result := &EmailHeaderAnalysis{}
                detectVendorSpamScores(fields, result)
                found := false
                for _, s := range result.SpamFlagSources {
                        if strings.Contains(s, "CLX") {
                                found = true
                        }
                }
                if !found {
                        t.Error("expected CLX score source")
                }
        })
}

func TestDetectBCCDelivery_Boost(t *testing.T) {
        t.Run("bcc_detected", func(t *testing.T) {
                fields := []headerField{{Name: "delivered-to", Value: "hidden@example.com"}}
                result := &EmailHeaderAnalysis{To: "visible@example.com"}
                detectBCCDelivery(fields, result)
                if !result.BCCDelivery {
                        t.Error("expected BCC delivery detected")
                }
                if result.BCCRecipient != "hidden@example.com" {
                        t.Errorf("got recipient %q", result.BCCRecipient)
                }
        })
        t.Run("same_recipient", func(t *testing.T) {
                fields := []headerField{{Name: "delivered-to", Value: "user@example.com"}}
                result := &EmailHeaderAnalysis{To: "user@example.com"}
                detectBCCDelivery(fields, result)
                if result.BCCDelivery {
                        t.Error("should not detect BCC when To matches Delivered-To")
                }
        })
        t.Run("empty_to", func(t *testing.T) {
                fields := []headerField{{Name: "delivered-to", Value: "user@example.com"}}
                result := &EmailHeaderAnalysis{}
                detectBCCDelivery(fields, result)
                if result.BCCDelivery {
                        t.Error("should not detect BCC with empty To")
                }
        })
        t.Run("original_recipient", func(t *testing.T) {
                fields := []headerField{{Name: "original-recipient", Value: "rfc822;other@example.com"}}
                result := &EmailHeaderAnalysis{To: "visible@example.com"}
                detectBCCDelivery(fields, result)
                if !result.BCCDelivery {
                        t.Error("expected BCC detection via original-recipient")
                }
        })
        t.Run("no_delivered_to", func(t *testing.T) {
                fields := []headerField{{Name: "subject", Value: "test"}}
                result := &EmailHeaderAnalysis{To: "user@example.com"}
                detectBCCDelivery(fields, result)
                if result.BCCDelivery {
                        t.Error("should not detect BCC without delivered-to header")
                }
        })
}

func TestCheckAllAuthPass_Boost(t *testing.T) {
        t.Run("all_pass", func(t *testing.T) {
                result := &EmailHeaderAnalysis{
                        SPFResult:   AuthResult{Result: "pass"},
                        DMARCResult: AuthResult{Result: "pass"},
                        DKIMResults: []AuthResult{{Result: "pass"}},
                }
                if !checkAllAuthPass(result) {
                        t.Error("expected true when all auth pass")
                }
        })
        t.Run("spf_fail", func(t *testing.T) {
                result := &EmailHeaderAnalysis{
                        SPFResult:   AuthResult{Result: "fail"},
                        DMARCResult: AuthResult{Result: "pass"},
                        DKIMResults: []AuthResult{{Result: "pass"}},
                }
                if checkAllAuthPass(result) {
                        t.Error("expected false when SPF fails")
                }
        })
        t.Run("no_dkim_pass", func(t *testing.T) {
                result := &EmailHeaderAnalysis{
                        SPFResult:   AuthResult{Result: "pass"},
                        DMARCResult: AuthResult{Result: "pass"},
                        DKIMResults: []AuthResult{{Result: "fail"}},
                }
                if checkAllAuthPass(result) {
                        t.Error("expected false when no DKIM passes")
                }
        })
        t.Run("empty_dkim", func(t *testing.T) {
                result := &EmailHeaderAnalysis{
                        SPFResult:   AuthResult{Result: "pass"},
                        DMARCResult: AuthResult{Result: "pass"},
                }
                if checkAllAuthPass(result) {
                        t.Error("expected false with empty DKIM results")
                }
        })
}

func TestExtractFirstEmailFromField_Boost(t *testing.T) {
        got := extractFirstEmailFromField("rfc822;user@example.com")
        if got != "user@example.com" {
                t.Errorf("got %q", got)
        }

        if got2 := extractFirstEmailFromField("no-email-here"); got2 != "no-email-here" {
                t.Errorf("expected trimmed input, got %q", got2)
        }
}

func TestMatchesBrand_Boost(t *testing.T) {
        if !matchesBrand("PayPal", []string{"paypal"}, "paypal invoice", "noreply@evil.com", "paypal invoice", "evil.com") {
                t.Error("expected match on subject keyword")
        }
        if !matchesBrand("PayPal", []string{"paypal"}, "test", "paypal-support@evil.com", "test", "evil.com") {
                t.Error("expected match on from keyword")
        }
        if matchesBrand("PayPal", []string{"paypal"}, "hello", "user@gmail.com", "hello", "gmail.com") {
                t.Error("expected no match")
        }
}

func TestAssessProvider(t *testing.T) {
        policy := map[string]any{}
        signals := assessProvider([]string{"mx1.google.com"}, policy, nil)
        if len(signals) == 0 {
                t.Error("expected provider signal for google.com MX")
        }
        p, ok := policy["provider"].(map[string]any)
        if !ok || p["identified"] != true {
                t.Error("expected provider identified")
        }
}

func TestAssessProviderNoMatch(t *testing.T) {
        policy := map[string]any{}
        signals := assessProvider([]string{"mx.custom.org"}, policy, nil)
        if len(signals) != 0 {
                t.Error("expected no signal for unknown MX")
        }
}

func TestBuildMultiProbeEntry(t *testing.T) {
        entry := buildMultiProbeEntry(smtpProbeResult{
                id:   "us-east",
                data: map[string]any{mapKeyStatus: mapKeyObserved, mapKeyProbeVerdict: mapKeyAllTls},
        })
        if entry["probe_id"] != "us-east" {
                t.Errorf("got probe_id %v", entry["probe_id"])
        }
        if entry[mapKeyStatus] != mapKeyObserved {
                t.Errorf("got status %v", entry[mapKeyStatus])
        }
}

func TestApplyPrimaryResult(t *testing.T) {
        probe := map[string]any{}
        primary := map[string]any{
                mapKeyStatus:       mapKeyObserved,
                mapKeyProbeVerdict: mapKeyAllTls,
                mapKeySummary:      map[string]any{"total": 2},
                mapKeyObservations: []map[string]any{{"host": "mx1"}},
        }
        applyPrimaryResult(probe, primary)
        if probe[mapKeyStatus] != mapKeyObserved {
                t.Error("status not applied")
        }
        if probe[mapKeyProbeVerdict] != mapKeyAllTls {
                t.Error("probe_verdict not applied")
        }
}

func TestEvaluateDANEState_Boost(t *testing.T) {
        t.Run("has_dane", func(t *testing.T) {
                ps := &protocolState{}
                evaluateDANEState(map[string]any{"has_dane": true}, ps)
                if !ps.daneOK {
                        t.Error("expected daneOK")
                }
        })
        t.Run("not_deployable", func(t *testing.T) {
                ps := &protocolState{}
                evaluateDANEState(map[string]any{"dane_deployable": false}, ps)
                if !ps.daneProviderLimited {
                        t.Error("expected daneProviderLimited")
                }
        })
        t.Run("missing", func(t *testing.T) {
                ps := &protocolState{}
                evaluateDANEState(map[string]any{mapKeyStatus: "missing"}, ps)
                if ps.daneOK || ps.daneProviderLimited {
                        t.Error("expected no dane state for missing record")
                }
        })
        t.Run("nil", func(t *testing.T) {
                ps := &protocolState{}
                evaluateDANEState(nil, ps)
                if ps.daneOK {
                        t.Error("expected no dane state for nil")
                }
        })
}

func TestDetectProbableNoMail_Boost(t *testing.T) {
        t.Run("has_mx", func(t *testing.T) {
                result := detectProbableNoMail(map[string]any{
                        "basic_records": map[string]any{"MX": []string{"mx.example.com"}},
                })
                if result {
                        t.Error("should not be no-mail with MX records")
                }
        })
        t.Run("no_mx", func(t *testing.T) {
                result := detectProbableNoMail(map[string]any{
                        "basic_records": map[string]any{},
                })
                if !result {
                        t.Error("expected probable no-mail without MX")
                }
        })
        t.Run("nil_basic", func(t *testing.T) {
                result := detectProbableNoMail(map[string]any{})
                if result {
                        t.Error("should return false for nil basic_records")
                }
        })
        t.Run("has_mx_any", func(t *testing.T) {
                result := detectProbableNoMail(map[string]any{
                        "basic_records": map[string]any{},
                        "mx_records":    []any{"mx.example.com"},
                })
                if result {
                        t.Error("should not be no-mail with mx_records")
                }
        })
}

func TestIsMissingRecord_Boost(t *testing.T) {
        if !isMissingRecord(nil) {
                t.Error("nil should be missing")
        }
        if !isMissingRecord(map[string]any{mapKeyStatus: "error"}) {
                t.Error("error should be missing")
        }
        if !isMissingRecord(map[string]any{mapKeyStatus: "missing"}) {
                t.Error("missing should be missing")
        }
        if !isMissingRecord(map[string]any{mapKeyStatus: "n/a"}) {
                t.Error("n/a should be missing")
        }
        if isMissingRecord(map[string]any{mapKeyStatus: "success"}) {
                t.Error("success should not be missing")
        }
}

func TestHasNonEmptyString_Boost(t *testing.T) {
        if hasNonEmptyString(nil, "key") {
                t.Error("nil map should return false")
        }
        if hasNonEmptyString(map[string]any{}, "key") {
                t.Error("missing key should return false")
        }
        if hasNonEmptyString(map[string]any{"key": ""}, "key") {
                t.Error("empty string should return false")
        }
        if !hasNonEmptyString(map[string]any{"key": "value"}, "key") {
                t.Error("non-empty string should return true")
        }
        if hasNonEmptyString(map[string]any{"key": 42}, "key") {
                t.Error("non-string should return false")
        }
}

func TestExtractIntFieldDefault_Boost(t *testing.T) {
        m := map[string]any{
                "int_val":   42,
                "float_val": 3.14,
                "str_val":   "hello",
        }
        if got := extractIntFieldDefault(m, "int_val", 0); got != 42 {
                t.Errorf("int_val: got %d", got)
        }
        if got := extractIntFieldDefault(m, "float_val", 0); got != 3 {
                t.Errorf("float_val: got %d", got)
        }
        if got := extractIntFieldDefault(m, "missing", 99); got != 99 {
                t.Errorf("missing: got %d", got)
        }
        if got := extractIntFieldDefault(nil, "key", 10); got != 10 {
                t.Errorf("nil map: got %d", got)
        }
}

func TestGenerateAuthBigQuestions_AllPass_SpamAndSubjectBoost(t *testing.T) {
        result := &EmailHeaderAnalysis{
                SPFResult:          AuthResult{Result: "pass"},
                DMARCResult:        AuthResult{Result: "pass"},
                DKIMResults:        []AuthResult{{Result: "pass"}},
                SpamFlagged:        true,
                HasSubjectAnalysis: true,
        }
        generateAuthBigQuestions(result, true)
        if len(result.BigQuestions) == 0 {
                t.Error("expected big questions for spam+subject+allpass")
        }
}

func TestGenerateAuthBigQuestions_AllPass_SpamOnlyBoost(t *testing.T) {
        result := &EmailHeaderAnalysis{
                SPFResult:   AuthResult{Result: "pass"},
                DMARCResult: AuthResult{Result: "pass"},
                DKIMResults: []AuthResult{{Result: "pass"}},
                SpamFlagged: true,
        }
        generateAuthBigQuestions(result, true)
        found := false
        for _, bq := range result.BigQuestions {
                if strings.Contains(bq.Question, "spam") {
                        found = true
                }
        }
        if !found {
                t.Error("expected spam-related big question")
        }
}

func TestGenerateAuthBigQuestions_AllPass_SubjectOnlyBoost(t *testing.T) {
        result := &EmailHeaderAnalysis{
                SPFResult:          AuthResult{Result: "pass"},
                DMARCResult:        AuthResult{Result: "pass"},
                DKIMResults:        []AuthResult{{Result: "pass"}},
                HasSubjectAnalysis: true,
        }
        generateAuthBigQuestions(result, true)
        if len(result.BigQuestions) == 0 {
                t.Error("expected big question for subject analysis + all pass")
        }
}

func TestGenerateAuthBigQuestions_NotAllPassBoost(t *testing.T) {
        result := &EmailHeaderAnalysis{
                SpamFlagged: true,
        }
        generateAuthBigQuestions(result, false)
        if len(result.BigQuestions) != 0 {
                t.Error("expected no questions when not all pass")
        }
}

func TestExportFunctions(t *testing.T) {
        t.Run("ClassifyAllQualifier", func(t *testing.T) {
                p := ExportClassifyAllQualifier("v=spf1 +all")
                if p == nil {
                        t.Error("expected non-nil")
                }
        })
        t.Run("CountSPFLookups", func(t *testing.T) {
                count := ExportCountSPFLookups("v=spf1 include:_spf.google.com ~all")
                if count < 1 {
                        t.Errorf("expected at least 1 lookup, got %d", count)
                }
        })
        t.Run("ClassifySPFRecords", func(t *testing.T) {
                valid, spfLike := ExportClassifySPFRecords([]string{"v=spf1 ~all", "not-spf"})
                if len(valid) != 1 {
                        t.Errorf("expected 1 valid, got %d", len(valid))
                }
                _ = spfLike
        })
        t.Run("BuildEmailAnswer", func(t *testing.T) {
                answer := ExportBuildEmailAnswer(false, "reject", 100, false, true, true)
                if answer == "" {
                        t.Error("expected non-empty answer")
                }
        })
        t.Run("BuildEmailAnswerStructured", func(t *testing.T) {
                m := ExportBuildEmailAnswerStructured(false, "reject", 100, false, true, true)
                if m[mapKeyAnswer] == "" {
                        t.Error("expected answer")
                }
        })
        t.Run("ClassifyNSProvider", func(t *testing.T) {
                got := ExportClassifyNSProvider("ns1.cloudflare.com")
                if got == "" {
                        t.Error("expected provider")
                }
        })
        t.Run("RegistrableDomain", func(t *testing.T) {
                got := ExportRegistrableDomain("sub.example.com")
                if got == "" {
                        t.Error("expected domain")
                }
        })
        t.Run("ClassifySelectorProvider", func(t *testing.T) {
                got := ExportClassifySelectorProvider("google", "")
                if got == "" {
                        t.Error("expected non-empty provider classification for 'google' selector")
                }
        })
        t.Run("FilterSTSRecords", func(t *testing.T) {
                got := ExportFilterSTSRecords([]string{"v=STSv1; id=123", "not-sts"})
                if len(got) != 1 {
                        t.Errorf("expected 1, got %d", len(got))
                }
        })
        t.Run("ExtractSTSID", func(t *testing.T) {
                got := ExportExtractSTSID("v=STSv1; id=abc123")
                if got == nil || *got != "abc123" {
                        t.Error("expected abc123")
                }
        })
        t.Run("ParseMTASTSPolicyLines", func(t *testing.T) {
                mode, maxAge, mx, hasVersion := ExportParseMTASTSPolicyLines("version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 86400\n")
                if mode != "enforce" {
                        t.Errorf("mode = %q", mode)
                }
                if maxAge != 86400 {
                        t.Errorf("maxAge = %d", maxAge)
                }
                if len(mx) != 1 {
                        t.Errorf("mx count = %d", len(mx))
                }
                if !hasVersion {
                        t.Error("expected hasVersion")
                }
        })
        t.Run("FilterBIMIRecords", func(t *testing.T) {
                got := ExportFilterBIMIRecords([]string{"v=BIMI1; l=https://example.com/logo.svg", "not-bimi"})
                if len(got) != 1 {
                        t.Errorf("expected 1, got %d", len(got))
                }
        })
        t.Run("ExtractBIMIURLs", func(t *testing.T) {
                logo, auth := ExportExtractBIMIURLs("v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/cert.pem")
                if logo == nil || !strings.Contains(*logo, "logo.svg") {
                        t.Error("expected logo URL")
                }
                if auth == nil || !strings.Contains(*auth, "cert.pem") {
                        t.Error("expected auth URL")
                }
        })
        t.Run("IsHostedEmailProvider", func(t *testing.T) {
                if !ExportIsHostedEmailProvider("gmail.com") {
                        t.Error("gmail.com should be hosted")
                }
        })
        t.Run("IsBIMICapableProvider", func(t *testing.T) {
                _ = ExportIsBIMICapableProvider("gmail.com")
        })
        t.Run("ClassifyDMARCRecords", func(t *testing.T) {
                valid, dmarcLike := ExportClassifyDMARCRecords([]string{"v=DMARC1; p=reject", "not-dmarc"})
                if len(valid) != 1 {
                        t.Errorf("expected 1 valid, got %d", len(valid))
                }
                _ = dmarcLike
        })
        t.Run("ParseDMARCPolicy", func(t *testing.T) {
                policy, pct, hasRUA := ExportParseDMARCPolicy("v=DMARC1; p=quarantine; pct=50; rua=mailto:dmarc@example.com")
                if policy != "quarantine" {
                        t.Errorf("policy = %q", policy)
                }
                if pct != 50 {
                        t.Errorf("pct = %d", pct)
                }
                if !hasRUA {
                        t.Error("expected hasRUA")
                }
        })
        t.Run("ExtractTLSRPTURIs", func(t *testing.T) {
                uris := ExportExtractTLSRPTURIs("v=TLSRPTv1; rua=mailto:tls@example.com")
                if len(uris) != 1 {
                        t.Errorf("expected 1 URI, got %d", len(uris))
                }
        })
        t.Run("BuildBrandVerdict", func(t *testing.T) {
                v := ExportBuildBrandVerdict(true, "", false, false)
                if v == nil {
                        t.Error("expected non-nil verdict")
                }
        })
        t.Run("BuildDNSVerdict", func(t *testing.T) {
                v := ExportBuildDNSVerdict(true, false)
                if v[mapKeyLabel] != strProtected {
                        t.Errorf("got %v", v[mapKeyLabel])
                }
        })
        t.Run("BuildSPFVerdict", func(t *testing.T) {
                q := "~all"
                status, msg := ExportBuildSPFVerdict(3, &q, false, []string{"v=spf1 ~all"}, nil)
                if status == "" || msg == "" {
                        t.Error("expected non-empty verdict")
                }
        })
        t.Run("ParseSPFMechanisms", func(t *testing.T) {
                count, lookupMechs, includes, perm, allMech, issues, noMail := ExportParseSPFMechanisms("v=spf1 include:_spf.google.com -all")
                if count < 1 {
                        t.Error("expected lookups")
                }
                if len(lookupMechs) == 0 {
                        t.Error("expected lookup mechanisms")
                }
                if len(includes) == 0 {
                        t.Error("expected includes")
                }
                _ = perm
                _ = allMech
                _ = issues
                if noMail {
                        t.Error("expected noMail=false")
                }
        })
        t.Run("ClassifyEnterpriseDNS", func(t *testing.T) {
                result := ExportClassifyEnterpriseDNS("example.com", []string{"ns1.cloudflare.com"})
                if result == nil {
                        t.Error("expected non-nil")
                }
        })
        t.Run("AnalyzeDKIMKey", func(t *testing.T) {
                result := ExportAnalyzeDKIMKey("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC")
                if result == nil {
                        t.Error("expected non-nil")
                }
        })
        t.Run("IdentifyCAIssuer", func(t *testing.T) {
                got := ExportIdentifyCAIssuer("0 issue \"letsencrypt.org\"")
                if got == "" {
                        t.Error("expected non-empty CA issuer for letsencrypt")
                }
        })
        t.Run("ParseCAARecords", func(t *testing.T) {
                issuers, wildcardIssuers, hasWildcard, hasIodef := ExportParseCAARecords([]string{
                        "0 issue \"letsencrypt.org\"",
                        "0 issuewild \"digicert.com\"",
                        "0 iodef \"mailto:caa@example.com\"",
                })
                if len(issuers) != 1 {
                        t.Errorf("issuers count = %d", len(issuers))
                }
                if len(wildcardIssuers) != 1 {
                        t.Errorf("wildcardIssuers count = %d", len(wildcardIssuers))
                }
                if !hasWildcard {
                        t.Error("expected hasWildcard")
                }
                if !hasIodef {
                        t.Error("expected hasIodef")
                }
        })
        t.Run("BuildCAAMessage", func(t *testing.T) {
                msg := ExportBuildCAAMessage([]string{"letsencrypt.org"}, []string{"digicert.com"}, true)
                if msg == "" {
                        t.Error("expected non-empty message")
                }
        })
        t.Run("DetermineMTASTSModeStatus", func(t *testing.T) {
                status, mode := ExportDetermineMTASTSModeStatus("enforce", map[string]any{
                        "mx": []string{"mx1.example.com"},
                })
                if status == "" || mode == "" {
                        t.Error("expected non-empty results")
                }
        })
        t.Run("ExtractMXHosts", func(t *testing.T) {
                hosts := ExportExtractMXHosts([]string{"10 mx1.example.com.", "20 mx2.example.com."})
                if len(hosts) < 1 {
                        t.Errorf("expected hosts, got %d", len(hosts))
                }
        })
}

func TestEvaluateDeliberateMonitoring_Boost(t *testing.T) {
        t.Run("none_policy_high_config", func(t *testing.T) {
                isMonitoring, _ := evaluateDeliberateMonitoring(protocolState{dmarcOK: true, dmarcHasRua: true, spfOK: true, dmarcPolicy: "none"}, 2)
                if !isMonitoring {
                        t.Error("expected monitoring for none policy with 2+ configured")
                }
        })
        t.Run("quarantine_partial_high_config", func(t *testing.T) {
                isMonitoring, _ := evaluateDeliberateMonitoring(protocolState{dmarcOK: true, dmarcHasRua: true, spfOK: true, dmarcPolicy: "quarantine", dmarcPct: 50}, 2)
                if !isMonitoring {
                        t.Error("expected monitoring for quarantine pct<100 with 2+ configured")
                }
        })
        t.Run("quarantine_full_high_config", func(t *testing.T) {
                isMonitoring, _ := evaluateDeliberateMonitoring(protocolState{dmarcOK: true, dmarcHasRua: true, spfOK: true, dmarcPolicy: "quarantine", dmarcPct: 100}, 2)
                if !isMonitoring {
                        t.Error("expected monitoring for quarantine pct>=100 with 2+ configured")
                }
        })
        t.Run("reject_low_config", func(t *testing.T) {
                isMonitoring, _ := evaluateDeliberateMonitoring(protocolState{dmarcOK: true, dmarcHasRua: true, spfOK: true, dmarcPolicy: "reject"}, 1)
                if isMonitoring {
                        t.Error("should not be monitoring for reject with low config count")
                }
        })
}

func TestClassifySPF_Boost(t *testing.T) {
        t.Run("ok", func(t *testing.T) {
                acc := &postureAccumulator{}
                classifySPF(protocolState{spfOK: true, spfHardFail: true}, acc)
                if len(acc.configured) == 0 {
                        t.Error("expected SPF in configured")
                }
        })
        t.Run("warning", func(t *testing.T) {
                acc := &postureAccumulator{}
                classifySPF(protocolState{spfWarning: true}, acc)
                if len(acc.monitoring) == 0 {
                        t.Error("expected SPF in monitoring")
                }
        })
        t.Run("missing", func(t *testing.T) {
                acc := &postureAccumulator{}
                classifySPF(protocolState{spfMissing: true}, acc)
                if len(acc.absent) == 0 {
                        t.Error("expected SPF in absent")
                }
        })
        t.Run("dangerous", func(t *testing.T) {
                acc := &postureAccumulator{}
                classifySPF(protocolState{spfOK: true, spfDangerous: true}, acc)
                if len(acc.issues) == 0 {
                        t.Error("expected issue for dangerous SPF")
                }
        })
        t.Run("lookup_exceeded", func(t *testing.T) {
                acc := &postureAccumulator{}
                classifySPF(protocolState{spfOK: true, spfLookupExceeded: true, spfLookupCount: 15}, acc)
                if len(acc.issues) == 0 {
                        t.Error("expected issue for lookup exceeded")
                }
        })
}

func TestClassifyDMARC_Boost(t *testing.T) {
        t.Run("missing", func(t *testing.T) {
                acc := &postureAccumulator{}
                classifyDMARC(protocolState{dmarcMissing: true}, acc)
                if len(acc.absent) == 0 {
                        t.Error("expected DMARC in absent")
                }
        })
        t.Run("ok", func(t *testing.T) {
                acc := &postureAccumulator{}
                classifyDMARC(protocolState{dmarcOK: true, dmarcPolicy: "reject"}, acc)
                if len(acc.configured) == 0 {
                        t.Error("expected DMARC in configured")
                }
        })
        t.Run("warning", func(t *testing.T) {
                acc := &postureAccumulator{}
                classifyDMARC(protocolState{dmarcWarning: true, dmarcPolicy: "none"}, acc)
                if len(acc.monitoring) == 0 {
                        t.Error("expected DMARC in monitoring")
                }
        })
}

func TestClassifyPresence_Boost(t *testing.T) {
        t.Run("present", func(t *testing.T) {
                acc := &postureAccumulator{}
                classifyPresence(true, "MTA-STS", acc)
                if len(acc.configured) != 1 || acc.configured[0] != "MTA-STS" {
                        t.Error("expected MTA-STS in configured")
                }
        })
        t.Run("absent", func(t *testing.T) {
                acc := &postureAccumulator{}
                classifyPresence(false, "MTA-STS", acc)
                if len(acc.absent) != 1 || acc.absent[0] != "MTA-STS" {
                        t.Error("expected MTA-STS in absent")
                }
        })
}

func TestClassifyDANE_Boost(t *testing.T) {
        t.Run("dane_ok", func(t *testing.T) {
                acc := &postureAccumulator{}
                classifyDANE(protocolState{daneOK: true}, acc)
                if len(acc.configured) == 0 {
                        t.Error("expected DANE in configured")
                }
        })
        t.Run("provider_limited", func(t *testing.T) {
                acc := &postureAccumulator{}
                classifyDANE(protocolState{daneProviderLimited: true}, acc)
                if len(acc.providerLimited) == 0 {
                        t.Error("expected DANE in providerLimited")
                }
        })
        t.Run("absent", func(t *testing.T) {
                acc := &postureAccumulator{}
                classifyDANE(protocolState{}, acc)
                if len(acc.absent) == 0 {
                        t.Error("expected DANE in absent")
                }
        })
}

func TestClassifyDNSSEC_Boost(t *testing.T) {
        t.Run("ok", func(t *testing.T) {
                acc := &postureAccumulator{}
                classifyDNSSEC(protocolState{dnssecOK: true}, acc)
                if len(acc.configured) == 0 {
                        t.Error("expected DNSSEC in configured")
                }
        })
        t.Run("broken", func(t *testing.T) {
                acc := &postureAccumulator{}
                classifyDNSSEC(protocolState{dnssecBroken: true}, acc)
                if len(acc.issues) == 0 {
                        t.Error("expected issue for broken DNSSEC")
                }
        })
        t.Run("absent", func(t *testing.T) {
                acc := &postureAccumulator{}
                classifyDNSSEC(protocolState{}, acc)
                if len(acc.absent) == 0 {
                        t.Error("expected DNSSEC in absent")
                }
        })
}

func TestScanDKIMIssueStrings_Boost(t *testing.T) {
        t.Run("weak_keys", func(t *testing.T) {
                weak, third := scanDKIMIssueStrings([]any{"Weak key detected (512-bit RSA)"})
                if !weak {
                        t.Error("expected weak keys detected")
                }
                if third {
                        t.Error("should not be third party")
                }
        })
        t.Run("third_party", func(t *testing.T) {
                weak, third := scanDKIMIssueStrings([]any{"Only third-party selectors found"})
                if weak {
                        t.Error("should not be weak")
                }
                if !third {
                        t.Error("expected third party")
                }
        })
        t.Run("none", func(t *testing.T) {
                weak, third := scanDKIMIssueStrings([]any{"some other issue"})
                if weak || third {
                        t.Error("expected neither weak nor third party")
                }
        })
}

func TestApplyMonitoringSuffix_Boost(t *testing.T) {
        if got := applyMonitoringSuffix("Good", []string{"DKIM"}); got != "Good" {
                t.Errorf("got %q with monitoring", got)
        }
        if got := applyMonitoringSuffix("Good", nil); got != "Good" {
                t.Errorf("got %q without monitoring", got)
        }
}

func TestExtractExternalDomainMaps_Boost(t *testing.T) {
        t.Run("slice_of_maps", func(t *testing.T) {
                raw := []any{
                        map[string]any{"domain": "a.com"},
                        map[string]any{"domain": "b.com"},
                }
                got := extractExternalDomainMaps(raw)
                if len(got) != 2 {
                        t.Errorf("expected 2 maps, got %d", len(got))
                }
        })
        t.Run("nil", func(t *testing.T) {
                got := extractExternalDomainMaps(nil)
                if len(got) != 0 {
                        t.Errorf("expected 0 for nil, got %d", len(got))
                }
        })
        t.Run("non_map_items", func(t *testing.T) {
                raw := []any{"not a map", 42}
                got := extractExternalDomainMaps(raw)
                if len(got) != 0 {
                        t.Errorf("expected 0 for non-map items, got %d", len(got))
                }
        })
        t.Run("wrong_type", func(t *testing.T) {
                if got := extractExternalDomainMaps("not a slice"); len(got) != 0 {
                        t.Errorf("expected 0 for wrong type, got %d", len(got))
                }
        })
}

func TestMatchesFreeCertAuthority_Boost(t *testing.T) {
        if !matchesFreeCertAuthority("Let's Encrypt") {
                t.Error("Let's Encrypt should be free")
        }
        if !matchesFreeCertAuthority("ZeroSSL") {
                t.Error("ZeroSSL should be free")
        }
        if matchesFreeCertAuthority("DigiCert") {
                t.Error("DigiCert should not be free")
        }
}
