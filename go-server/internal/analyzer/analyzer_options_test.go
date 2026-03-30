package analyzer

import (
        "testing"
)

func TestWithMaxConcurrent(t *testing.T) {
        a := New(WithMaxConcurrent(5), WithInitialIANAFetch(false))
        if a == nil {
                t.Fatal("expected non-nil analyzer")
        }
        inUse, total := a.ConcurrentCapacity()
        if total != 5 {
                t.Errorf("total = %d, want 5", total)
        }
        if inUse != 0 {
                t.Errorf("inUse = %d, want 0", inUse)
        }
}

func TestBackpressureRejections(t *testing.T) {
        a := New(WithInitialIANAFetch(false))
        if a.BackpressureRejections() != 0 {
                t.Errorf("expected 0 rejections initially")
        }
}

func TestConcurrentCapacity_Default(t *testing.T) {
        a := New(WithInitialIANAFetch(false))
        _, total := a.ConcurrentCapacity()
        if total <= 0 {
                t.Errorf("expected positive capacity, got %d", total)
        }
}

func TestGetCTCache_Empty(t *testing.T) {
        a := New(WithInitialIANAFetch(false))
        result, ok := a.GetCTCache("example.com")
        if ok {
                t.Error("expected cache miss for new analyzer")
        }
        if result != nil {
                t.Error("expected nil result for cache miss")
        }
}

func TestSetAndGetCTCache(t *testing.T) {
        a := New(WithInitialIANAFetch(false))
        data := []map[string]any{{"issuer": "test"}}
        a.setCTCache("example.com", data)
        result, ok := a.getCTCache("example.com")
        if !ok {
                t.Error("expected cache hit after set")
        }
        if len(result) != 1 {
                t.Errorf("expected 1 entry, got %d", len(result))
        }
}

func TestGetCTCache_PublicWrapper(t *testing.T) {
        a := New(WithInitialIANAFetch(false))
        data := []map[string]any{{"cn": "test.com"}}
        a.setCTCache("test.com", data)
        result, ok := a.GetCTCache("test.com")
        if !ok {
                t.Error("expected cache hit via public GetCTCache")
        }
        if len(result) != 1 {
                t.Errorf("expected 1 entry, got %d", len(result))
        }
}

func TestWithMaxConcurrent_Zero(t *testing.T) {
        a := New(WithMaxConcurrent(0), WithInitialIANAFetch(false))
        if a == nil {
                t.Fatal("expected non-nil analyzer")
        }
}

func TestBuildEmailAnswer_AllBranches(t *testing.T) {
        tests := []struct {
                name     string
                ps       protocolState
                hasSPF   bool
                hasDMARC bool
        }{
                {"reject_spf_dmarc", protocolState{dmarcPolicy: mapKeyReject}, true, true},
                {"quarantine_full", protocolState{dmarcPolicy: mapKeyQuarantine, dmarcPct: 100}, true, true},
                {"quarantine_partial", protocolState{dmarcPolicy: mapKeyQuarantine, dmarcPct: 50}, true, true},
                {"none_policy", protocolState{dmarcPolicy: statusNone}, true, true},
                {"null_mx", protocolState{isNoMailDomain: true}, false, false},
                {"no_mail", protocolState{probableNoMail: true}, false, false},
                {"no_spf_no_dmarc", protocolState{}, false, false},
                {"spf_only", protocolState{spfOK: true}, true, false},
                {"dmarc_only", protocolState{dmarcOK: true, dmarcPolicy: mapKeyReject}, false, true},
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        answer := buildEmailAnswer(tc.ps, tc.hasSPF, tc.hasDMARC)
                        if answer == "" {
                                t.Error("expected non-empty answer")
                        }
                })
        }
}

func TestBuildEmailAnswerStructured_AllBranches(t *testing.T) {
        tests := []struct {
                name     string
                ps       protocolState
                hasSPF   bool
                hasDMARC bool
        }{
                {"reject", protocolState{dmarcPolicy: mapKeyReject}, true, true},
                {"quarantine", protocolState{dmarcPolicy: mapKeyQuarantine, dmarcPct: 100}, true, true},
                {"none", protocolState{dmarcPolicy: statusNone}, true, true},
                {"no_mail", protocolState{isNoMailDomain: true}, false, false},
                {"empty", protocolState{}, false, false},
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        result := buildEmailAnswerStructured(tc.ps, tc.hasSPF, tc.hasDMARC)
                        if result == nil {
                                t.Error("expected non-nil structured result")
                        }
                })
        }
}

func TestExtractIntFieldDefault_Opts(t *testing.T) {
        m := map[string]any{"count": float64(42), "str": "hello", "zero": float64(0)}
        if got := extractIntFieldDefault(m, "count", 0); got != 42 {
                t.Errorf("expected 42, got %d", got)
        }
        if got := extractIntFieldDefault(m, "missing", 99); got != 99 {
                t.Errorf("expected default 99, got %d", got)
        }
        if got := extractIntFieldDefault(m, "str", 5); got != 5 {
                t.Errorf("expected default 5 for non-number, got %d", got)
        }
}

func TestClassifyDMARCSuccess_AllBranches(t *testing.T) {
        tests := []struct {
                name string
                ps   protocolState
        }{
                {"reject", protocolState{dmarcOK: true, dmarcPolicy: mapKeyReject}},
                {"quarantine_full", protocolState{dmarcOK: true, dmarcPolicy: mapKeyQuarantine, dmarcPct: 100}},
                {"quarantine_partial", protocolState{dmarcOK: true, dmarcPolicy: mapKeyQuarantine, dmarcPct: 50}},
                {"none", protocolState{dmarcOK: true, dmarcPolicy: statusNone}},
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        acc := &postureAccumulator{configured: []string{}, monitoring: []string{}}
                        classifyDMARCSuccess(tc.ps, acc)
                })
        }
}

func TestComputeInternalScore_Opts(t *testing.T) {
        tests := []struct {
                name string
                ps   protocolState
                ds   DKIMState
        }{
                {"all_ok", protocolState{spfOK: true, dmarcOK: true, dmarcPolicy: mapKeyReject, dnssecOK: true, mtaStsOK: true, tlsrptOK: true, caaOK: true, bimiOK: true, daneOK: true}, DKIMSuccess},
                {"all_missing", protocolState{spfMissing: true, dmarcMissing: true}, DKIMAbsent},
                {"mixed", protocolState{spfOK: true, spfDangerous: true, dmarcOK: true, dmarcPolicy: statusNone}, DKIMInconclusive},
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        score := computeInternalScore(tc.ps, tc.ds)
                        if score < 0 || score > 100 {
                                t.Errorf("score = %d, want 0-100", score)
                        }
                })
        }
}

func TestClassifyEmailSpoofability_Opts(t *testing.T) {
        tests := []struct {
                name     string
                ps       protocolState
                hasSPF   bool
                hasDMARC bool
        }{
                {"reject", protocolState{dmarcPolicy: mapKeyReject, dmarcPct: 100}, true, true},
                {"quarantine_full", protocolState{dmarcPolicy: mapKeyQuarantine, dmarcPct: 100}, true, true},
                {"quarantine_partial", protocolState{dmarcPolicy: mapKeyQuarantine, dmarcPct: 50}, true, true},
                {"none_policy", protocolState{dmarcPolicy: statusNone}, true, true},
                {"no_spf_no_dmarc", protocolState{}, false, false},
                {"spf_only", protocolState{}, true, false},
                {"null_mx", protocolState{isNoMailDomain: true}, false, false},
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        class := classifyEmailSpoofability(tc.ps, tc.hasSPF, tc.hasDMARC)
                        if class < 0 {
                                t.Errorf("unexpected negative class %d", class)
                        }
                })
        }
}

func TestDKIMState_Methods(t *testing.T) {
        states := []DKIMState{DKIMAbsent, DKIMSuccess, DKIMProviderInferred, DKIMThirdPartyOnly, DKIMInconclusive, DKIMWeakKeysOnly, DKIMNoMailDomain}
        for _, s := range states {
                name := s.String()
                if name == "" {
                        t.Errorf("expected non-empty string for state %d", s)
                }
                _ = s.IsPresent()
                _ = s.IsConfigured()
                _ = s.NeedsAction()
                _ = s.NeedsMonitoring()
        }
}

func TestClassifyDKIMState_AllBranches(t *testing.T) {
        tests := []struct {
                name string
                ps   protocolState
                want DKIMState
        }{
                {"no_mail", protocolState{isNoMailDomain: true}, DKIMNoMailDomain},
                {"dkim_ok", protocolState{dkimOK: true}, DKIMSuccess},
                {"dkim_provider", protocolState{dkimProvider: true}, DKIMProviderInferred},
                {"dkim_partial", protocolState{dkimPartial: true}, DKIMThirdPartyOnly},
                {"dkim_third_party", protocolState{dkimThirdPartyOnly: true}, DKIMThirdPartyOnly},
                {"dkim_weak", protocolState{dkimWeakKeys: true}, DKIMWeakKeysOnly},
                {"absent", protocolState{}, DKIMAbsent},
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        got := classifyDKIMState(tc.ps)
                        if got != tc.want {
                                t.Errorf("got %v, want %v", got, tc.want)
                        }
                })
        }
}
