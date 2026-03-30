package analyzer

import (
	"testing"
)

func TestBuildBrandRejectVerdict(t *testing.T) {
	tests := []struct {
		name      string
		ps        protocolState
		wantLabel string
		wantColor string
		wantAns   string
	}{
		{
			name:      "bimi+caa => Protected",
			ps:        protocolState{bimiOK: true, caaOK: true},
			wantLabel: "Protected",
			wantColor: "success",
			wantAns:   "No",
		},
		{
			name:      "bimi only => Well Protected",
			ps:        protocolState{bimiOK: true, caaOK: false},
			wantLabel: "Well Protected",
			wantColor: "success",
			wantAns:   "Unlikely",
		},
		{
			name:      "caa only => Mostly Protected",
			ps:        protocolState{bimiOK: false, caaOK: true},
			wantLabel: "Mostly Protected",
			wantColor: "info",
			wantAns:   "Possible",
		},
		{
			name:      "neither => Partially Protected",
			ps:        protocolState{bimiOK: false, caaOK: false},
			wantLabel: "Partially Protected",
			wantColor: "warning",
			wantAns:   "Possible",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildBrandRejectVerdict(tc.ps)
			if got["label"] != tc.wantLabel {
				t.Errorf("label = %v, want %v", got["label"], tc.wantLabel)
			}
			if got["color"] != tc.wantColor {
				t.Errorf("color = %v, want %v", got["color"], tc.wantColor)
			}
			if got["answer"] != tc.wantAns {
				t.Errorf("answer = %v, want %v", got["answer"], tc.wantAns)
			}
		})
	}
}

func TestBuildBrandQuarantineVerdict(t *testing.T) {
	tests := []struct {
		name      string
		ps        protocolState
		wantLabel string
		wantColor string
		wantAns   string
	}{
		{
			name:      "bimi+caa => Well Protected",
			ps:        protocolState{bimiOK: true, caaOK: true},
			wantLabel: "Well Protected",
			wantColor: "success",
			wantAns:   "Unlikely",
		},
		{
			name:      "bimi only => Mostly Protected",
			ps:        protocolState{bimiOK: true, caaOK: false},
			wantLabel: "Mostly Protected",
			wantColor: "info",
			wantAns:   "Possible",
		},
		{
			name:      "caa only => Partially Protected",
			ps:        protocolState{bimiOK: false, caaOK: true},
			wantLabel: "Partially Protected",
			wantColor: "warning",
			wantAns:   "Likely",
		},
		{
			name:      "neither => Basic",
			ps:        protocolState{bimiOK: false, caaOK: false},
			wantLabel: "Basic",
			wantColor: "warning",
			wantAns:   "Likely",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildBrandQuarantineVerdict(tc.ps)
			if got["label"] != tc.wantLabel {
				t.Errorf("label = %v, want %v", got["label"], tc.wantLabel)
			}
			if got["color"] != tc.wantColor {
				t.Errorf("color = %v, want %v", got["color"], tc.wantColor)
			}
			if got["answer"] != tc.wantAns {
				t.Errorf("answer = %v, want %v", got["answer"], tc.wantAns)
			}
		})
	}
}

func TestBuildBrandWeakVerdict(t *testing.T) {
	tests := []struct {
		name      string
		ps        protocolState
		wantLabel string
		wantColor string
		wantAns   string
		reasonSub string
	}{
		{
			name:      "policy none => monitor-only message",
			ps:        protocolState{dmarcPolicy: "none"},
			wantLabel: "Basic",
			wantColor: "warning",
			wantAns:   "Likely",
			reasonSub: "monitor-only",
		},
		{
			name:      "empty policy => partial protection message",
			ps:        protocolState{dmarcPolicy: ""},
			wantLabel: "Basic",
			wantColor: "warning",
			wantAns:   "Likely",
			reasonSub: "partial protection",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildBrandWeakVerdict(tc.ps)
			if got["label"] != tc.wantLabel {
				t.Errorf("label = %v, want %v", got["label"], tc.wantLabel)
			}
			if got["color"] != tc.wantColor {
				t.Errorf("color = %v, want %v", got["color"], tc.wantColor)
			}
			if got["answer"] != tc.wantAns {
				t.Errorf("answer = %v, want %v", got["answer"], tc.wantAns)
			}
			reason, _ := got["reason"].(string)
			if tc.reasonSub != "" && !contains(reason, tc.reasonSub) {
				t.Errorf("reason %q should contain %q", reason, tc.reasonSub)
			}
		})
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || findSubstring(s, sub))
}

func findSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestBuildLlmsTxtVerdict(t *testing.T) {
	tests := []struct {
		name    string
		input   map[string]any
		wantKey bool
		wantAns string
		wantClr string
	}{
		{
			name:    "nil input => no verdict",
			input:   nil,
			wantKey: false,
		},
		{
			name:    "found+full => success",
			input:   map[string]any{"found": true, "full_found": true},
			wantKey: true,
			wantAns: "Yes",
			wantClr: "success",
		},
		{
			name:    "found only => success",
			input:   map[string]any{"found": true, "full_found": false},
			wantKey: true,
			wantAns: "Yes",
			wantClr: "success",
		},
		{
			name:    "not found => secondary",
			input:   map[string]any{"found": false},
			wantKey: true,
			wantAns: "No",
			wantClr: "secondary",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			verdicts := map[string]any{}
			buildLlmsTxtVerdict(tc.input, verdicts)
			v, ok := verdicts["ai_llms_txt"]
			if !tc.wantKey {
				if ok {
					t.Error("expected no verdict key")
				}
				return
			}
			if !ok {
				t.Fatal("expected verdict key ai_llms_txt")
			}
			m := v.(map[string]any)
			if m["answer"] != tc.wantAns {
				t.Errorf("answer = %v, want %v", m["answer"], tc.wantAns)
			}
			if m["color"] != tc.wantClr {
				t.Errorf("color = %v, want %v", m["color"], tc.wantClr)
			}
		})
	}
}

func TestBuildRobotsTxtVerdict(t *testing.T) {
	tests := []struct {
		name    string
		input   map[string]any
		wantKey bool
		wantAns string
		wantClr string
	}{
		{
			name:    "nil => no verdict",
			input:   nil,
			wantKey: false,
		},
		{
			name:    "found+blocks => success",
			input:   map[string]any{"found": true, "blocks_ai_crawlers": true},
			wantKey: true,
			wantAns: "Yes",
			wantClr: "success",
		},
		{
			name:    "found no blocks => warning",
			input:   map[string]any{"found": true, "blocks_ai_crawlers": false},
			wantKey: true,
			wantAns: "No",
			wantClr: "warning",
		},
		{
			name:    "not found => secondary",
			input:   map[string]any{"found": false},
			wantKey: true,
			wantAns: "No",
			wantClr: "secondary",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			verdicts := map[string]any{}
			buildRobotsTxtVerdict(tc.input, verdicts)
			v, ok := verdicts["ai_crawler_governance"]
			if !tc.wantKey {
				if ok {
					t.Error("expected no verdict key")
				}
				return
			}
			if !ok {
				t.Fatal("expected verdict key ai_crawler_governance")
			}
			m := v.(map[string]any)
			if m["answer"] != tc.wantAns {
				t.Errorf("answer = %v, want %v", m["answer"], tc.wantAns)
			}
			if m["color"] != tc.wantClr {
				t.Errorf("color = %v, want %v", m["color"], tc.wantClr)
			}
		})
	}
}

func TestBuildPoisoningVerdict(t *testing.T) {
	tests := []struct {
		name    string
		input   map[string]any
		wantKey bool
		wantAns string
		wantClr string
	}{
		{
			name:    "nil => no verdict",
			input:   nil,
			wantKey: false,
		},
		{
			name:    "ioc_count > 0 => danger",
			input:   map[string]any{"ioc_count": float64(3)},
			wantKey: true,
			wantAns: "Yes",
			wantClr: "danger",
		},
		{
			name:    "ioc_count 0 => success",
			input:   map[string]any{"ioc_count": float64(0)},
			wantKey: true,
			wantAns: "No",
			wantClr: "success",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			verdicts := map[string]any{}
			buildPoisoningVerdict(tc.input, verdicts)
			v, ok := verdicts["ai_poisoning"]
			if !tc.wantKey {
				if ok {
					t.Error("expected no verdict key")
				}
				return
			}
			if !ok {
				t.Fatal("expected verdict key ai_poisoning")
			}
			m := v.(map[string]any)
			if m["answer"] != tc.wantAns {
				t.Errorf("answer = %v, want %v", m["answer"], tc.wantAns)
			}
			if m["color"] != tc.wantClr {
				t.Errorf("color = %v, want %v", m["color"], tc.wantClr)
			}
		})
	}
}

func TestBuildHiddenPromptsVerdict(t *testing.T) {
	tests := []struct {
		name    string
		input   map[string]any
		wantKey bool
		wantAns string
		wantClr string
	}{
		{
			name:    "nil => no verdict",
			input:   nil,
			wantKey: false,
		},
		{
			name:    "artifacts > 0 => danger",
			input:   map[string]any{"artifact_count": float64(2)},
			wantKey: true,
			wantAns: "Yes",
			wantClr: "danger",
		},
		{
			name:    "artifacts 0 => success",
			input:   map[string]any{"artifact_count": float64(0)},
			wantKey: true,
			wantAns: "No",
			wantClr: "success",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			verdicts := map[string]any{}
			buildHiddenPromptsVerdict(tc.input, verdicts)
			v, ok := verdicts["ai_hidden_prompts"]
			if !tc.wantKey {
				if ok {
					t.Error("expected no verdict key")
				}
				return
			}
			if !ok {
				t.Fatal("expected verdict key ai_hidden_prompts")
			}
			m := v.(map[string]any)
			if m["answer"] != tc.wantAns {
				t.Errorf("answer = %v, want %v", m["answer"], tc.wantAns)
			}
			if m["color"] != tc.wantClr {
				t.Errorf("color = %v, want %v", m["color"], tc.wantClr)
			}
		})
	}
}

func TestBuildCAAVerdict(t *testing.T) {
	tests := []struct {
		name      string
		ps        protocolState
		wantLabel string
		wantColor string
		wantAns   string
	}{
		{
			name:      "caa ok => Configured",
			ps:        protocolState{caaOK: true},
			wantLabel: "Configured",
			wantColor: "success",
			wantAns:   "Yes",
		},
		{
			name:      "caa missing => Not Configured",
			ps:        protocolState{caaOK: false},
			wantLabel: "Not Configured",
			wantColor: "secondary",
			wantAns:   "No",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			verdicts := map[string]any{}
			buildCAAVerdict(tc.ps, verdicts)
			v, ok := verdicts["certificate_control"]
			if !ok {
				t.Fatal("expected verdict key certificate_control")
			}
			m := v.(map[string]any)
			if m["label"] != tc.wantLabel {
				t.Errorf("label = %v, want %v", m["label"], tc.wantLabel)
			}
			if m["color"] != tc.wantColor {
				t.Errorf("color = %v, want %v", m["color"], tc.wantColor)
			}
			if m["answer"] != tc.wantAns {
				t.Errorf("answer = %v, want %v", m["answer"], tc.wantAns)
			}
		})
	}
}

func TestBuildDNSVerdict(t *testing.T) {
	tests := []struct {
		name      string
		ps        protocolState
		wantLabel string
		wantColor string
	}{
		{
			name:      "dnssec ok",
			ps:        protocolState{dnssecOK: true},
			wantLabel: "Protected",
			wantColor: "success",
		},
		{
			name:      "dnssec broken",
			ps:        protocolState{dnssecBroken: true},
			wantLabel: "Exposed",
			wantColor: "danger",
		},
		{
			name:      "no dnssec",
			ps:        protocolState{},
			wantLabel: "Not Configured",
			wantColor: "secondary",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			verdicts := map[string]any{}
			buildDNSVerdict(tc.ps, verdicts)
			v := verdicts["dns_tampering"].(map[string]any)
			if v["label"] != tc.wantLabel {
				t.Errorf("label = %v, want %v", v["label"], tc.wantLabel)
			}
			if v["color"] != tc.wantColor {
				t.Errorf("color = %v, want %v", v["color"], tc.wantColor)
			}
		})
	}
}

func TestBuildTransportVerdict(t *testing.T) {
	tests := []struct {
		name      string
		ps        protocolState
		wantLabel string
	}{
		{
			name:      "mta-sts+dane",
			ps:        protocolState{mtaStsOK: true, daneOK: true},
			wantLabel: "Fully Protected",
		},
		{
			name:      "mta-sts only",
			ps:        protocolState{mtaStsOK: true},
			wantLabel: "Protected",
		},
		{
			name:      "dane only",
			ps:        protocolState{daneOK: true},
			wantLabel: "Protected",
		},
		{
			name:      "tlsrpt only",
			ps:        protocolState{tlsrptOK: true},
			wantLabel: "Monitoring",
		},
		{
			name:      "nothing",
			ps:        protocolState{},
			wantLabel: "Not Enforced",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			verdicts := map[string]any{}
			buildTransportVerdict(tc.ps, verdicts)
			v := verdicts["transport"].(map[string]any)
			if v["label"] != tc.wantLabel {
				t.Errorf("label = %v, want %v", v["label"], tc.wantLabel)
			}
		})
	}
}

func TestVerdictInputUsage(t *testing.T) {
	vi := verdictInput{
		ps:       protocolState{spfOK: true, dmarcOK: true, dmarcPolicy: "reject"},
		ds:       DKIMSuccess,
		hasSPF:   true,
		hasDMARC: true,
		hasDKIM:  true,
	}
	verdicts := buildVerdicts(vi)
	if verdicts == nil {
		t.Fatal("buildVerdicts returned nil")
	}
	requiredKeys := []string{"email_spoofing", "brand_impersonation", "dns_tampering", "certificate_control", "transport"}
	for _, k := range requiredKeys {
		if _, ok := verdicts[k]; !ok {
			t.Errorf("missing expected verdict key %q", k)
		}
	}
}

func TestBuildBrandVerdict_DmarcMissing(t *testing.T) {
	verdicts := map[string]any{}
	ps := protocolState{dmarcMissing: true}
	buildBrandVerdict(ps, verdicts)
	v, ok := verdicts["brand_impersonation"]
	if !ok {
		t.Fatal("expected brand_impersonation key")
	}
	m := v.(map[string]any)
	if m["label"] != "Exposed" {
		t.Errorf("label = %v, want Exposed", m["label"])
	}
	if m["color"] != "danger" {
		t.Errorf("color = %v, want danger", m["color"])
	}
}

func TestBuildBrandVerdict_Reject(t *testing.T) {
	verdicts := map[string]any{}
	ps := protocolState{dmarcOK: true, dmarcPolicy: "reject", bimiOK: true, caaOK: true}
	buildBrandVerdict(ps, verdicts)
	v := verdicts["brand_impersonation"].(map[string]any)
	if v["label"] != "Protected" {
		t.Errorf("label = %v, want Protected", v["label"])
	}
}

func TestBuildBrandVerdict_Quarantine(t *testing.T) {
	verdicts := map[string]any{}
	ps := protocolState{dmarcOK: true, dmarcPolicy: "quarantine"}
	buildBrandVerdict(ps, verdicts)
	v := verdicts["brand_impersonation"].(map[string]any)
	if v["label"] != "Basic" {
		t.Errorf("label = %v, want Basic", v["label"])
	}
}

func TestBuildBrandVerdict_WeakDefault(t *testing.T) {
	verdicts := map[string]any{}
	ps := protocolState{dmarcOK: true, dmarcPolicy: "none"}
	buildBrandVerdict(ps, verdicts)
	v := verdicts["brand_impersonation"].(map[string]any)
	if v["label"] != "Basic" {
		t.Errorf("label = %v, want Basic", v["label"])
	}
}

func TestBuildEmailVerdict_Variations(t *testing.T) {
	tests := []struct {
		name      string
		vi        verdictInput
		wantLabel string
		wantColor string
	}{
		{
			name: "enforcing reject",
			vi: verdictInput{
				ps:       protocolState{dmarcPolicy: "reject"},
				ds:       DKIMSuccess,
				hasSPF:   true,
				hasDMARC: true,
			},
			wantLabel: "Protected",
			wantColor: "success",
		},
		{
			name: "enforcing quarantine 100",
			vi: verdictInput{
				ps:       protocolState{dmarcPolicy: "quarantine", dmarcPct: 100},
				ds:       DKIMSuccess,
				hasSPF:   true,
				hasDMARC: true,
			},
			wantLabel: "Protected",
			wantColor: "success",
		},
		{
			name: "spf only",
			vi: verdictInput{
				ps:     protocolState{},
				hasSPF: true,
			},
			wantLabel: "Basic",
			wantColor: "warning",
		},
		{
			name: "no spf no dmarc",
			vi: verdictInput{
				ps: protocolState{},
			},
			wantLabel: "Exposed",
			wantColor: "danger",
		},
		{
			name: "spf+dmarc none",
			vi: verdictInput{
				ps:       protocolState{dmarcPolicy: "none"},
				hasSPF:   true,
				hasDMARC: true,
			},
			wantLabel: "Basic",
			wantColor: "warning",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			verdicts := map[string]any{}
			buildEmailVerdict(tc.vi, verdicts)
			v := verdicts["email_spoofing"].(map[string]any)
			if v["label"] != tc.wantLabel {
				t.Errorf("label = %v, want %v", v["label"], tc.wantLabel)
			}
			if v["color"] != tc.wantColor {
				t.Errorf("color = %v, want %v", v["color"], tc.wantColor)
			}
		})
	}
}

func TestBuildAISurfaceVerdicts(t *testing.T) {
	results := map[string]any{
		"ai_surface": map[string]any{
			"llms_txt": map[string]any{
				"found":      true,
				"full_found": false,
			},
			"robots_txt": map[string]any{
				"found":              true,
				"blocks_ai_crawlers": true,
			},
			"poisoning": map[string]any{
				"ioc_count": float64(0),
			},
			"hidden_prompts": map[string]any{
				"artifact_count": float64(1),
			},
		},
	}
	verdicts := map[string]any{}
	buildAISurfaceVerdicts(results, verdicts)

	if _, ok := verdicts["ai_llms_txt"]; !ok {
		t.Error("missing ai_llms_txt")
	}
	if _, ok := verdicts["ai_crawler_governance"]; !ok {
		t.Error("missing ai_crawler_governance")
	}
	if _, ok := verdicts["ai_poisoning"]; !ok {
		t.Error("missing ai_poisoning")
	}
	if _, ok := verdicts["ai_hidden_prompts"]; !ok {
		t.Error("missing ai_hidden_prompts")
	}
}

func TestBuildAISurfaceVerdicts_NoAISurface(t *testing.T) {
	results := map[string]any{}
	verdicts := map[string]any{}
	buildAISurfaceVerdicts(results, verdicts)
	if len(verdicts) != 0 {
		t.Errorf("expected empty verdicts, got %d", len(verdicts))
	}
}

func TestGetNumericValue(t *testing.T) {
	tests := []struct {
		name string
		m    map[string]any
		key  string
		want float64
	}{
		{"float64", map[string]any{"x": float64(3.5)}, "x", 3.5},
		{"int", map[string]any{"x": 7}, "x", 7.0},
		{"int64", map[string]any{"x": int64(42)}, "x", 42.0},
		{"missing key", map[string]any{}, "x", 0},
		{"string val", map[string]any{"x": "abc"}, "x", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := getNumericValue(tc.m, tc.key)
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBuildEmailAnswer(t *testing.T) {
	tests := []struct {
		name     string
		ps       protocolState
		hasSPF   bool
		hasDMARC bool
		wantSub  string
	}{
		{"no-mail domain", protocolState{isNoMailDomain: true}, false, false, "null MX"},
		{"no protections", protocolState{}, false, false, "no SPF or DMARC"},
		{"reject", protocolState{dmarcPolicy: "reject"}, true, true, "reject policy enforced"},
		{"quarantine 100", protocolState{dmarcPolicy: "quarantine", dmarcPct: 100}, true, true, "quarantine policy enforced"},
		{"quarantine partial", protocolState{dmarcPolicy: "quarantine", dmarcPct: 50}, true, true, "limited percentage"},
		{"none", protocolState{dmarcPolicy: "none"}, true, true, "monitor-only"},
		{"spf only", protocolState{}, true, false, "SPF alone"},
		{"dmarc only", protocolState{}, false, true, "no SPF"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildEmailAnswer(tc.ps, tc.hasSPF, tc.hasDMARC)
			if !findSubstring(got, tc.wantSub) {
				t.Errorf("got %q, want substring %q", got, tc.wantSub)
			}
		})
	}
}

func TestBuildEmailAnswerStructured(t *testing.T) {
	tests := []struct {
		name     string
		ps       protocolState
		hasSPF   bool
		hasDMARC bool
		wantAns  string
		wantClr  string
	}{
		{"no-mail", protocolState{isNoMailDomain: true}, false, false, "No", "success"},
		{"no protections", protocolState{}, false, false, "Yes", "danger"},
		{"reject", protocolState{dmarcPolicy: "reject"}, true, true, "No", "success"},
		{"quarantine 100", protocolState{dmarcPolicy: "quarantine", dmarcPct: 100}, true, true, "Unlikely", "success"},
		{"quarantine partial", protocolState{dmarcPolicy: "quarantine", dmarcPct: 50}, true, true, "Partially", "warning"},
		{"none", protocolState{dmarcPolicy: "none"}, true, true, "Yes", "danger"},
		{"spf only", protocolState{}, true, false, "Likely", "danger"},
		{"dmarc only", protocolState{}, false, true, "Partially", "warning"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildEmailAnswerStructured(tc.ps, tc.hasSPF, tc.hasDMARC)
			if got["answer"] != tc.wantAns {
				t.Errorf("answer = %v, want %v", got["answer"], tc.wantAns)
			}
			if got["color"] != tc.wantClr {
				t.Errorf("color = %v, want %v", got["color"], tc.wantClr)
			}
		})
	}
}
