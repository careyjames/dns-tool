package analyzer

import (
	"strings"
	"testing"
)

func TestFilterSTSRecordsMultipleValid(t *testing.T) {
	records := []string{
		"v=STSv1; id=abc",
		"v=STSv1; id=def",
	}
	got := filterSTSRecords(records)
	if len(got) != 2 {
		t.Errorf("expected 2, got %d", len(got))
	}
}

func TestFilterSTSRecordsNoMatch(t *testing.T) {
	records := []string{
		"v=DMARC1; p=reject",
		"v=BIMI1; l=https://example.com/logo.svg",
	}
	got := filterSTSRecords(records)
	if len(got) != 0 {
		t.Errorf("expected 0, got %d", len(got))
	}
}

func TestExtractSTSIDValue(t *testing.T) {
	got := extractSTSID("v=STSv1; id=20240315T120000")
	if got == nil {
		t.Fatal("expected non-nil")
	}
	if *got != "20240315T120000" {
		t.Errorf("id = %q", *got)
	}
}

func TestExtractSTSIDMissing(t *testing.T) {
	got := extractSTSID("v=STSv1;")
	if got != nil {
		t.Error("expected nil for missing id")
	}
}

func TestExtractPolicyModeEnforce(t *testing.T) {
	data := map[string]any{mapKeyFetched: true, mapKeyMtaMode: "enforce"}
	mode := extractPolicyMode(data)
	if mode == nil || *mode != "enforce" {
		t.Errorf("expected enforce, got %v", mode)
	}
}

func TestExtractPolicyModeTesting(t *testing.T) {
	data := map[string]any{mapKeyFetched: true, mapKeyMtaMode: "testing"}
	mode := extractPolicyMode(data)
	if mode == nil || *mode != "testing" {
		t.Errorf("expected testing, got %v", mode)
	}
}

func TestExtractPolicyModeNotFetched(t *testing.T) {
	data := map[string]any{mapKeyFetched: false, mapKeyMtaMode: "enforce"}
	mode := extractPolicyMode(data)
	if mode != nil {
		t.Error("expected nil when not fetched")
	}
}

func TestDetermineMTASTSModeStatusEnforceEmptyMX(t *testing.T) {
	status, msg := determineMTASTSModeStatus("enforce", map[string]any{"mx": []string{}})
	if status != mapKeySuccess {
		t.Errorf("expected success, got %q", status)
	}
	if !strings.Contains(msg, "enforced") {
		t.Errorf("expected 'enforced' in msg, got %q", msg)
	}
}

func TestDetermineMTASTSModeStatusTesting(t *testing.T) {
	status, msg := determineMTASTSModeStatus("testing", map[string]any{})
	if status != mapKeyWarning {
		t.Errorf("expected warning, got %q", status)
	}
	if !strings.Contains(msg, "testing") {
		t.Errorf("expected 'testing' in msg, got %q", msg)
	}
}

func TestDetermineMTASTSModeStatusNone(t *testing.T) {
	status, msg := determineMTASTSModeStatus("none", map[string]any{})
	if status != mapKeyWarning {
		t.Errorf("expected warning, got %q", status)
	}
	if !strings.Contains(msg, "disabled") {
		t.Errorf("expected 'disabled' in msg, got %q", msg)
	}
}

func TestDetermineMTASTSStatusNotFetchedWithError(t *testing.T) {
	data := map[string]any{mapKeyFetched: false, mapKeyError: "connection refused"}
	status, msg, _ := determineMTASTSStatus(data, nil)
	if status != mapKeyWarning {
		t.Errorf("expected warning, got %q", status)
	}
	if !strings.Contains(msg, "inaccessible") {
		t.Errorf("expected 'inaccessible' in msg, got %q", msg)
	}
}

func TestDetermineMTASTSStatusMissingVersion(t *testing.T) {
	enforce := "enforce"
	data := map[string]any{
		mapKeyFetched: true,
		mapKeyMtaMode: "enforce",
		"has_version": false,
		"mx":          []string{"mx.example.com"},
	}
	status, msg, issues := determineMTASTSStatus(data, &enforce)
	if status != mapKeyWarning {
		t.Errorf("expected warning for missing version, got %q", status)
	}
	if !strings.Contains(msg, "missing version") {
		t.Errorf("expected 'missing version' in msg, got %q", msg)
	}
	if len(issues) != 1 {
		t.Errorf("expected 1 issue, got %d", len(issues))
	}
}

func TestDetermineMTASTSFallbackStatusNoError(t *testing.T) {
	data := map[string]any{mapKeyError: nil}
	status, msg, issues := determineMTASTSFallbackStatus(data)
	if status != mapKeySuccess {
		t.Errorf("expected success, got %q", status)
	}
	if msg == "" {
		t.Error("expected non-empty message")
	}
	if issues != nil {
		t.Errorf("expected nil issues, got %v", issues)
	}
}

func TestParseMTASTSPolicyLinesMinimal(t *testing.T) {
	fields := parseMTASTSPolicyLines("version: STSv1\nmode: testing\n")
	if !fields.hasVersion {
		t.Error("expected hasVersion")
	}
	if fields.mode != "testing" {
		t.Errorf("mode = %q, want testing", fields.mode)
	}
	if fields.maxAge != 0 {
		t.Errorf("maxAge = %d, want 0", fields.maxAge)
	}
	if len(fields.mx) != 0 {
		t.Errorf("mx count = %d, want 0", len(fields.mx))
	}
}

func TestParseMTASTSPolicyLinesFullPolicy(t *testing.T) {
	policy := "version: STSv1\nmode: enforce\nmax_age: 604800\nmx: *.example.com\nmx: backup.example.com\n"
	fields := parseMTASTSPolicyLines(policy)
	if fields.mode != "enforce" {
		t.Errorf("mode = %q, want enforce", fields.mode)
	}
	if fields.maxAge != 604800 {
		t.Errorf("maxAge = %d, want 604800", fields.maxAge)
	}
	if len(fields.mx) != 2 {
		t.Errorf("mx count = %d, want 2", len(fields.mx))
	}
}

func TestParseMTASTSPolicyLineInvalidVersion(t *testing.T) {
	fields := &mtaSTSPolicyFields{}
	parseMTASTSPolicyLine("version: stsv2", "version: STSv2", fields)
	if fields.hasVersion {
		t.Error("expected hasVersion false for STSv2")
	}
	if fields.version != "STSv2" {
		t.Errorf("version = %q, want STSv2", fields.version)
	}
}

func TestParseMTASTSPolicyLineMaxAgeZero(t *testing.T) {
	fields := &mtaSTSPolicyFields{}
	parseMTASTSPolicyLine("max_age: 0", "max_age: 0", fields)
	if fields.maxAge != 0 {
		t.Errorf("maxAge = %d, expected 0 for invalid/zero", fields.maxAge)
	}
}

func TestParseMTASTSPolicyLineEmptyMX(t *testing.T) {
	fields := &mtaSTSPolicyFields{}
	parseMTASTSPolicyLine("mx:", "mx:", fields)
	if len(fields.mx) != 0 {
		t.Errorf("expected 0 mx entries for empty, got %d", len(fields.mx))
	}
}

func TestParseMTASTSPolicyLineUnknownField(t *testing.T) {
	fields := &mtaSTSPolicyFields{}
	parseMTASTSPolicyLine("custom: value", "custom: value", fields)
	if fields.mode != "" || fields.hasVersion || fields.maxAge != 0 || len(fields.mx) != 0 {
		t.Error("expected no fields set for unknown line")
	}
}
