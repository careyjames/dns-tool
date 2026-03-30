package analyzer

import (
	"context"
	"net/http"
	"testing"
)

func TestAnalyzeSMTPTransport_CB4(t *testing.T) {
	a := newMockAnalyzer()
	result := a.AnalyzeSMTPTransport(context.Background(), "example.com", []string{"10 mx1.example.com.", "20 mx2.example.com."})
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result[mapKeyVersion] != 2 {
		t.Errorf("expected version 2, got %v", result[mapKeyVersion])
	}
	if result["policy"] == nil {
		t.Error("expected policy section")
	}
	if result["telemetry"] == nil {
		t.Error("expected telemetry section")
	}
	if result["probe"] == nil {
		t.Error("expected probe section")
	}
}

func TestAnalyzeSMTPTransport_NoMX_CB4(t *testing.T) {
	a := newMockAnalyzer()
	result := a.AnalyzeSMTPTransport(context.Background(), "example.com", nil)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	msg, _ := result["message"].(string)
	if msg != "No MX records found" {
		t.Errorf("expected 'No MX records found', got %q", msg)
	}
}

func TestAnalyzeSMTPTransport_WithInputs_CB4(t *testing.T) {
	a := newMockAnalyzer()
	ai := AnalysisInputs{
		MTASTSResult: map[string]any{
			mapKeyStatus: mapKeySuccess,
			"mode":       "enforce",
			"mx":         []string{"mx1.example.com"},
		},
		TLSRPTResult: map[string]any{
			mapKeyStatus: mapKeySuccess,
			"record":     "v=TLSRPTv1; rua=mailto:tls@example.com",
		},
	}
	result := a.AnalyzeSMTPTransport(context.Background(), "example.com", []string{"10 mx1.example.com."}, ai)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestBuildPolicyAssessment_CB4(t *testing.T) {
	a := newMockAnalyzer()
	ai := AnalysisInputs{
		MTASTSResult: map[string]any{
			mapKeyStatus: mapKeySuccess,
			"mode":       "enforce",
			"mx":         []string{"mx1.example.com"},
		},
	}
	policy := buildPolicyAssessment(a, context.Background(), "example.com", []string{"mx1.example.com"}, ai)
	if policy == nil {
		t.Fatal("expected non-nil policy")
	}
	verdict, _ := policy[mapKeyVerdict].(string)
	if verdict != mapKeyEnforced {
		t.Errorf("expected enforced verdict with MTA-STS enforce, got %q", verdict)
	}
}

func TestAssessMTASTS_CB4(t *testing.T) {
	a := newMockAnalyzer()
	t.Run("no MTA-STS result", func(t *testing.T) {
		policy := map[string]any{
			mapKeyMtaSts: map[string]any{mapKeyPresent: false, mapKeyMode: verdictNone},
		}
		signals := assessMTASTS(a, context.Background(), "example.com", AnalysisInputs{}, policy, nil)
		if len(signals) != 0 {
			t.Errorf("expected no signals without MTA-STS, got %d", len(signals))
		}
	})
	t.Run("MTA-STS enforce", func(t *testing.T) {
		ai := AnalysisInputs{
			MTASTSResult: map[string]any{
				mapKeyStatus: mapKeySuccess,
				"mode":       "enforce",
				"mx":         []string{"mx1.example.com"},
			},
		}
		policy := map[string]any{
			mapKeyMtaSts: map[string]any{mapKeyPresent: false, mapKeyMode: verdictNone},
		}
		signals := assessMTASTS(a, context.Background(), "example.com", ai, policy, nil)
		if len(signals) == 0 {
			t.Error("expected signals with MTA-STS enforce")
		}
		mtasts, _ := policy[mapKeyMtaSts].(map[string]any)
		if present, _ := mtasts[mapKeyPresent].(bool); !present {
			t.Error("expected MTA-STS present=true")
		}
	})
	t.Run("MTA-STS testing mode", func(t *testing.T) {
		ai := AnalysisInputs{
			MTASTSResult: map[string]any{
				mapKeyStatus: mapKeySuccess,
				"mode":       "testing",
				"mx":         []string{"mx1.example.com"},
			},
		}
		policy := map[string]any{
			mapKeyMtaSts: map[string]any{mapKeyPresent: false, mapKeyMode: verdictNone},
		}
		signals := assessMTASTS(a, context.Background(), "example.com", ai, policy, nil)
		if len(signals) == 0 {
			t.Error("expected signals with MTA-STS testing")
		}
		mtasts, _ := policy[mapKeyMtaSts].(map[string]any)
		mode, _ := mtasts["mode"].(string)
		if mode != "testing" {
			t.Errorf("expected mode testing, got %q", mode)
		}
	})
}

func TestAssessDANE_CB4(t *testing.T) {
	a := newMockAnalyzer()
	t.Run("no DANE result", func(t *testing.T) {
		ai := AnalysisInputs{}
		policy := map[string]any{
			mapKeyDane: map[string]any{mapKeyPresent: false},
		}
		signals := assessDANE(a, context.Background(), []string{"mx1.example.com"}, ai, policy, nil)
		if len(signals) != 0 {
			t.Errorf("expected no signals without DANE, got %d", len(signals))
		}
	})
	t.Run("DANE present", func(t *testing.T) {
		ai := AnalysisInputs{
			DANEResult: map[string]any{
				mapKeyStatus: mapKeySuccess,
				"has_dane":   true,
			},
		}
		policy := map[string]any{
			mapKeyDane: map[string]any{mapKeyPresent: false},
		}
		signals := assessDANE(a, context.Background(), []string{"mx1.example.com"}, ai, policy, nil)
		if len(signals) == 0 {
			t.Error("expected signals with DANE present")
		}
	})
}

func TestAssessTLSRPT_CB4(t *testing.T) {
	a := newMockAnalyzer()
	t.Run("no TLS-RPT result", func(t *testing.T) {
		ai := AnalysisInputs{}
		policy := map[string]any{
			"tlsrpt": map[string]any{mapKeyPresent: false},
		}
		signals := assessTLSRPT(a, context.Background(), "example.com", ai, policy, nil)
		if len(signals) != 0 {
			t.Errorf("expected no signals without TLS-RPT, got %d", len(signals))
		}
	})
	t.Run("TLS-RPT present", func(t *testing.T) {
		ai := AnalysisInputs{
			TLSRPTResult: map[string]any{
				mapKeyStatus: mapKeySuccess,
				"record":     "v=TLSRPTv1; rua=mailto:tls@example.com",
			},
		}
		policy := map[string]any{
			"tlsrpt": map[string]any{mapKeyPresent: false},
		}
		signals := assessTLSRPT(a, context.Background(), "example.com", ai, policy, nil)
		if len(signals) == 0 {
			t.Error("expected signals with TLS-RPT present")
		}
	})
}

func TestAssessProvider_CB4(t *testing.T) {
	t.Run("Google provider", func(t *testing.T) {
		policy := map[string]any{}
		signals := assessProvider([]string{"alt1.aspmx.l.google.com"}, policy, nil)
		if len(signals) == 0 {
			t.Error("expected provider signal for Google")
		}
		prov, _ := policy["provider"].(map[string]any)
		if prov == nil {
			t.Fatal("expected provider info")
		}
		if name, _ := prov["name"].(string); name != "Google Workspace" {
			t.Errorf("expected Google Workspace, got %q", name)
		}
	})
	t.Run("unknown provider", func(t *testing.T) {
		policy := map[string]any{}
		signals := assessProvider([]string{"mx.unknown-provider.example"}, policy, nil)
		if len(signals) != 0 {
			t.Errorf("expected no signals for unknown provider, got %d", len(signals))
		}
	})
}

func TestBackfillLegacyFields_CB4(t *testing.T) {
	t.Run("observed probe", func(t *testing.T) {
		result := map[string]any{}
		probe := map[string]any{
			mapKeyStatus:       mapKeyObserved,
			mapKeyObservations: []map[string]any{{"host": "mx1"}},
			mapKeySummary:      map[string]any{"total": 1},
		}
		backfillLegacyFields(result, map[string]any{}, probe)
		if result[mapKeyServers] == nil {
			t.Error("expected servers to be set")
		}
		if result[mapKeySummary] == nil {
			t.Error("expected summary to be set")
		}
	})
	t.Run("unobserved probe", func(t *testing.T) {
		result := map[string]any{}
		probe := map[string]any{mapKeyStatus: "inferred"}
		backfillLegacyFields(result, map[string]any{}, probe)
		servers, _ := result[mapKeyServers].([]map[string]any)
		if len(servers) != 0 {
			t.Error("expected empty servers for unobserved probe")
		}
	})
}

func TestApplyRemoteProbeMetadata_CB4(t *testing.T) {
	probe := map[string]any{}
	apiResp := &remoteProbeAPIResp{
		ProbeHost:      "probe-1.example.com",
		ElapsedSeconds: 1.5,
		AllPorts:       []map[string]any{{"port": 25}},
	}
	applyRemoteProbeMetadata(probe, apiResp)
	if probe[mapKeyProbeHost] != "probe-1.example.com" {
		t.Errorf("expected probe host, got %v", probe[mapKeyProbeHost])
	}
	if probe[mapKeyProbeElapsed] != 1.5 {
		t.Errorf("expected elapsed 1.5, got %v", probe[mapKeyProbeElapsed])
	}
	if probe["multi_port"] == nil {
		t.Error("expected multi_port to be set")
	}
}

func TestApplyRemoteProbeMetadata_NoPorts(t *testing.T) {
	probe := map[string]any{}
	apiResp := &remoteProbeAPIResp{
		ProbeHost:      "probe-1.example.com",
		ElapsedSeconds: 0.5,
	}
	applyRemoteProbeMetadata(probe, apiResp)
	if _, ok := probe["multi_port"]; ok {
		t.Error("multi_port should not be set when no ports")
	}
}

func TestApplyPrimaryResult_CB4(t *testing.T) {
	probe := map[string]any{}
	primary := map[string]any{
		mapKeyProbeVerdict: mapKeyAllTls,
		mapKeySummary:      map[string]any{"total": 2},
		mapKeyObservations: []map[string]any{{"host": "mx1"}},
		mapKeyProbeHost:    "probe1",
		mapKeyProbeElapsed: 1.0,
	}
	applyPrimaryResult(probe, primary)
	if probe[mapKeyProbeVerdict] != mapKeyAllTls {
		t.Errorf("expected all_tls verdict, got %v", probe[mapKeyProbeVerdict])
	}
	if probe[mapKeyProbeHost] != "probe1" {
		t.Errorf("expected probe1, got %v", probe[mapKeyProbeHost])
	}
}

func TestApplyPrimaryResult_Nil(t *testing.T) {
	probe := map[string]any{"existing": "value"}
	applyPrimaryResult(probe, nil)
	if probe["existing"] != "value" {
		t.Error("nil primary should not modify probe")
	}
}

func TestBuildMultiProbeEntry_CB4(t *testing.T) {
	result := smtpProbeResult{
		id:    "p1",
		label: "Probe 1",
		data: map[string]any{
			mapKeyProbeVerdict: mapKeyAllTls,
			mapKeySummary:      map[string]any{"total": 1},
			mapKeyProbeHost:    "h1",
			mapKeyProbeElapsed: 0.5,
		},
	}
	entry := buildMultiProbeEntry(result)
	if entry["probe_id"] != "p1" {
		t.Errorf("expected p1, got %v", entry["probe_id"])
	}
}

func TestClassifyRemoteProbeStatus_CB4(t *testing.T) {
	tests := []struct {
		code   int
		expect string
	}{
		{http.StatusOK, ""},
		{http.StatusUnauthorized, "authentication failed (401)"},
		{http.StatusTooManyRequests, "rate limited (429)"},
		{http.StatusInternalServerError, "HTTP 500"},
	}
	for _, tt := range tests {
		if got := classifyRemoteProbeStatus(tt.code); got != tt.expect {
			t.Errorf("classifyRemoteProbeStatus(%d) = %q, want %q", tt.code, got, tt.expect)
		}
	}
}

func TestDerivePrimaryStatus_CB4(t *testing.T) {
	tests := []struct {
		name   string
		policy map[string]any
		probe  map[string]any
		expect string
	}{
		{
			"observed all TLS enforced",
			map[string]any{mapKeyVerdict: mapKeyEnforced},
			map[string]any{mapKeyStatus: mapKeyObserved, mapKeyProbeVerdict: mapKeyAllTls},
			mapKeySuccess,
		},
		{
			"observed all TLS no policy",
			map[string]any{mapKeyVerdict: verdictNone},
			map[string]any{mapKeyStatus: mapKeyObserved, mapKeyProbeVerdict: mapKeyAllTls},
			mapKeySuccess,
		},
		{
			"observed partial TLS",
			map[string]any{mapKeyVerdict: verdictNone},
			map[string]any{mapKeyStatus: mapKeyObserved, mapKeyProbeVerdict: mapKeyPartialTls},
			"warning",
		},
		{
			"observed no TLS",
			map[string]any{mapKeyVerdict: verdictNone},
			map[string]any{mapKeyStatus: mapKeyObserved, mapKeyProbeVerdict: mapKeyNoTls},
			mapKeyError,
		},
		{
			"no probe enforced policy",
			map[string]any{mapKeyVerdict: mapKeyEnforced},
			map[string]any{mapKeyStatus: "inferred"},
			mapKeySuccess,
		},
		{
			"no probe monitored",
			map[string]any{mapKeyVerdict: mapKeyMonitored},
			map[string]any{mapKeyStatus: "inferred"},
			"info",
		},
		{
			"no probe opportunistic",
			map[string]any{mapKeyVerdict: mapKeyOpportunistic},
			map[string]any{mapKeyStatus: "inferred"},
			"inferred",
		},
		{
			"no probe no verdict",
			map[string]any{mapKeyVerdict: verdictNone},
			map[string]any{mapKeyStatus: "inferred"},
			"info",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := derivePrimaryStatus(tt.policy, tt.probe)
			if got != tt.expect {
				t.Errorf("derivePrimaryStatus() = %q, want %q", got, tt.expect)
			}
		})
	}
}

func TestDerivePrimaryMessage_CB4(t *testing.T) {
	t.Run("no MX", func(t *testing.T) {
		got := derivePrimaryMessage(map[string]any{}, map[string]any{}, nil)
		if got != "No MX records found" {
			t.Errorf("expected 'No MX records found', got %q", got)
		}
	})
	t.Run("observed with summary", func(t *testing.T) {
		probe := map[string]any{
			mapKeyStatus: mapKeyObserved,
			mapKeySummary: map[string]any{
				mapKeyReachable:         float64(2),
				mapKeyStarttlsSupported: float64(2),
			},
		}
		got := derivePrimaryMessage(map[string]any{}, probe, []string{"mx1", "mx2"})
		if got == "No MX records found" {
			t.Error("should not say no MX records found")
		}
	})
	t.Run("enforced no probe", func(t *testing.T) {
		policy := map[string]any{
			mapKeyVerdict: mapKeyEnforced,
			mapKeySignals: []string{"MTA-STS enforce"},
		}
		got := derivePrimaryMessage(policy, map[string]any{}, []string{"mx1"})
		if got == "No MX records found" {
			t.Error("should not say no MX records found")
		}
	})
}
