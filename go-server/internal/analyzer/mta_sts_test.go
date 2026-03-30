package analyzer

import (
	"testing"
)

func TestFilterSTSRecords(t *testing.T) {
	tests := []struct {
		name    string
		records []string
		want    int
	}{
		{"valid", []string{"v=STSv1; id=20240101"}, 1},
		{"case insensitive", []string{"V=STSV1; id=abc"}, 1},
		{"invalid", []string{"v=spf1 include:example.com"}, 0},
		{"mixed", []string{"v=STSv1; id=1", "other"}, 1},
		{"empty", []string{}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterSTSRecords(tt.records)
			if len(got) != tt.want {
				t.Errorf("filterSTSRecords() len = %d, want %d", len(got), tt.want)
			}
		})
	}
}

func TestExtractSTSID(t *testing.T) {
	tests := []struct {
		name   string
		record string
		wantID bool
	}{
		{"with id", "v=STSv1; id=20240101", true},
		{"no id", "v=STSv1;", false},
		{"case insensitive", "v=STSv1; ID=abc123", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSTSID(tt.record)
			if (got != nil) != tt.wantID {
				t.Errorf("extractSTSID() nil = %v, want present = %v", got == nil, tt.wantID)
			}
		})
	}
}

func TestExtractPolicyMode(t *testing.T) {
	fetched := map[string]any{mapKeyFetched: true, mapKeyMtaMode: "enforce"}
	mode := extractPolicyMode(fetched)
	if mode == nil || *mode != "enforce" {
		t.Errorf("expected enforce, got %v", mode)
	}

	notFetched := map[string]any{mapKeyFetched: false, mapKeyMtaMode: "enforce"}
	mode2 := extractPolicyMode(notFetched)
	if mode2 != nil {
		t.Error("expected nil for not fetched")
	}

	emptyMode := map[string]any{mapKeyFetched: true, mapKeyMtaMode: ""}
	mode3 := extractPolicyMode(emptyMode)
	if mode3 != nil {
		t.Error("expected nil for empty mode")
	}
}

func TestDetermineMTASTSModeStatus(t *testing.T) {
	tests := []struct {
		name       string
		mode       string
		policyData map[string]any
		wantStatus string
	}{
		{"enforce with mx", "enforce", map[string]any{"mx": []string{"mx1.example.com"}}, mapKeySuccess},
		{"enforce no mx", "enforce", map[string]any{"mx": []string{}}, mapKeySuccess},
		{"testing", "testing", map[string]any{}, mapKeyWarning},
		{"none", "none", map[string]any{}, mapKeyWarning},
		{"unknown", "custom", map[string]any{}, mapKeySuccess},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, msg := determineMTASTSModeStatus(tt.mode, tt.policyData)
			if status != tt.wantStatus {
				t.Errorf("status = %q, want %q", status, tt.wantStatus)
			}
			if msg == "" {
				t.Error("expected non-empty message")
			}
		})
	}
}

func TestDetermineMTASTSFallbackStatus(t *testing.T) {
	withError := map[string]any{mapKeyError: "connection error"}
	status, _, _ := determineMTASTSFallbackStatus(withError)
	if status != mapKeyWarning {
		t.Errorf("expected warning, got %q", status)
	}

	noError := map[string]any{mapKeyError: nil}
	status2, _, _ := determineMTASTSFallbackStatus(noError)
	if status2 != mapKeySuccess {
		t.Errorf("expected success, got %q", status2)
	}
}

func TestDetermineMTASTSStatus(t *testing.T) {
	enforce := "enforce"
	policyData := map[string]any{
		mapKeyFetched: true,
		mapKeyMtaMode: "enforce",
		"has_version": true,
		"mx":          []string{"mx1.example.com"},
	}
	status, msg, issues := determineMTASTSStatus(policyData, &enforce)
	if status != mapKeySuccess {
		t.Errorf("expected success, got %q", status)
	}
	if msg == "" {
		t.Error("expected non-empty message")
	}
	if len(issues) != 0 {
		t.Errorf("expected no issues, got %d", len(issues))
	}

	policyDataNoVersion := map[string]any{
		mapKeyFetched: true,
		mapKeyMtaMode: "enforce",
		"has_version": false,
		"mx":          []string{"mx1.example.com"},
	}
	status2, _, issues2 := determineMTASTSStatus(policyDataNoVersion, &enforce)
	if status2 != mapKeyWarning {
		t.Errorf("expected warning for missing version, got %q", status2)
	}
	if len(issues2) != 1 {
		t.Errorf("expected 1 issue, got %d", len(issues2))
	}

	notFetched := map[string]any{mapKeyFetched: false, mapKeyError: nil}
	status3, _, _ := determineMTASTSStatus(notFetched, nil)
	if status3 != mapKeySuccess {
		t.Errorf("expected success for fallback, got %q", status3)
	}
}

func TestParseMTASTSPolicyLines(t *testing.T) {
	policy := "version: STSv1\nmode: enforce\nmax_age: 86400\nmx: mx1.example.com\nmx: mx2.example.com\n"
	fields := parseMTASTSPolicyLines(policy)

	if !fields.hasVersion {
		t.Error("expected hasVersion")
	}
	if fields.mode != "enforce" {
		t.Errorf("mode = %q, want enforce", fields.mode)
	}
	if fields.maxAge != 86400 {
		t.Errorf("maxAge = %d, want 86400", fields.maxAge)
	}
	if len(fields.mx) != 2 {
		t.Errorf("mx count = %d, want 2", len(fields.mx))
	}
}

func TestParseMTASTSPolicyLine(t *testing.T) {
	fields := &mtaSTSPolicyFields{}

	parseMTASTSPolicyLine("version: stsv1", "version: STSv1", fields)
	if !fields.hasVersion {
		t.Error("expected hasVersion")
	}

	parseMTASTSPolicyLine("mode: testing", "mode: testing", fields)
	if fields.mode != "testing" {
		t.Errorf("mode = %q, want testing", fields.mode)
	}

	parseMTASTSPolicyLine("max_age: 604800", "max_age: 604800", fields)
	if fields.maxAge != 604800 {
		t.Errorf("maxAge = %d, want 604800", fields.maxAge)
	}

	parseMTASTSPolicyLine("mx: mail.example.com", "mx: mail.example.com", fields)
	if len(fields.mx) != 1 {
		t.Errorf("mx count = %d, want 1", len(fields.mx))
	}

	fields2 := &mtaSTSPolicyFields{}
	parseMTASTSPolicyLine("max_age: 0", "max_age: 0", fields2)
	if fields2.maxAge != 0 {
		t.Errorf("maxAge = %d, want 0 for invalid", fields2.maxAge)
	}

	fields3 := &mtaSTSPolicyFields{}
	parseMTASTSPolicyLine("mx: ", "mx: ", fields3)
	if len(fields3.mx) != 0 {
		t.Errorf("mx count = %d, want 0 for empty", len(fields3.mx))
	}
}
