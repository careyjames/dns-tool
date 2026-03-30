package models

import (
	"encoding/json"
	"testing"
	"time"
)

func strPtr(s string) *string        { return &s }
func floatPtr(f float64) *float64    { return &f }
func timePtr(t time.Time) *time.Time { return &t }

func TestSchemaVersion(t *testing.T) {
	if SchemaVersion != 2 {
		t.Errorf("SchemaVersion = %d, want 2", SchemaVersion)
	}
}

func TestRequiredSections(t *testing.T) {
	expected := []string{
		"basic_records", "spf_analysis", "dmarc_analysis",
		"dkim_analysis", "registrar_info", "posture",
		"dane_analysis", "mta_sts_analysis", "tlsrpt_analysis",
		"bimi_analysis", "caa_analysis", "dnssec_analysis",
	}
	if len(RequiredSections) != len(expected) {
		t.Fatalf("RequiredSections length = %d, want %d", len(RequiredSections), len(expected))
	}
	for i, s := range expected {
		if RequiredSections[i] != s {
			t.Errorf("RequiredSections[%d] = %q, want %q", i, RequiredSections[i], s)
		}
	}
}

func TestToDict_FullyPopulated(t *testing.T) {
	now := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	updated := time.Date(2025, 6, 15, 13, 0, 0, 0, time.UTC)

	da := &DomainAnalysis{
		ID:                   42,
		Domain:               "example.com",
		ASCIIDomain:          "example.com",
		BasicRecords:         json.RawMessage(`{"a":"1.2.3.4"}`),
		AuthoritativeRecords: json.RawMessage(`{"ns":"ns1.example.com"}`),
		SPFStatus:            strPtr("pass"),
		SPFRecords:           json.RawMessage(`["v=spf1 -all"]`),
		DMARCStatus:          strPtr("pass"),
		DMARCPolicy:          strPtr("reject"),
		DMARCRecords:         json.RawMessage(`["v=DMARC1; p=reject"]`),
		DKIMStatus:           strPtr("pass"),
		DKIMSelectors:        json.RawMessage(`["selector1"]`),
		RegistrarName:        strPtr("Example Registrar"),
		RegistrarSource:      strPtr("rdap"),
		AnalysisSuccess:      true,
		ErrorMessage:         nil,
		AnalysisDuration:     floatPtr(1.23),
		CreatedAt:            now,
		UpdatedAt:            timePtr(updated),
	}

	result := da.ToDict()

	if result["id"] != 42 {
		t.Errorf("id = %v, want 42", result["id"])
	}
	if result["domain"] != "example.com" {
		t.Errorf("domain = %v, want example.com", result["domain"])
	}
	if result["ascii_domain"] != "example.com" {
		t.Errorf("ascii_domain = %v, want example.com", result["ascii_domain"])
	}
	if result["analysis_success"] != true {
		t.Errorf("analysis_success = %v, want true", result["analysis_success"])
	}
	if em, ok := result["error_message"].(*string); ok && em != nil {
		t.Errorf("error_message = %v, want nil", result["error_message"])
	}
	dur := result["analysis_duration"]
	if dur == nil || *dur.(*float64) != 1.23 {
		t.Errorf("analysis_duration = %v, want 1.23", dur)
	}

	spf, ok := result["spf_analysis"].(map[string]interface{})
	if !ok {
		t.Fatal("spf_analysis not a map")
	}
	if *spf["status"].(*string) != "pass" {
		t.Errorf("spf status = %v, want pass", spf["status"])
	}

	dmarc, ok := result["dmarc_analysis"].(map[string]interface{})
	if !ok {
		t.Fatal("dmarc_analysis not a map")
	}
	if *dmarc["status"].(*string) != "pass" {
		t.Errorf("dmarc status = %v, want pass", dmarc["status"])
	}
	if *dmarc["policy"].(*string) != "reject" {
		t.Errorf("dmarc policy = %v, want reject", dmarc["policy"])
	}

	dkim, ok := result["dkim_analysis"].(map[string]interface{})
	if !ok {
		t.Fatal("dkim_analysis not a map")
	}
	if *dkim["status"].(*string) != "pass" {
		t.Errorf("dkim status = %v, want pass", dkim["status"])
	}

	reg, ok := result["registrar_info"].(map[string]interface{})
	if !ok {
		t.Fatal("registrar_info not a map")
	}
	if *reg["registrar"].(*string) != "Example Registrar" {
		t.Errorf("registrar = %v, want Example Registrar", reg["registrar"])
	}
	if *reg["source"].(*string) != "rdap" {
		t.Errorf("source = %v, want rdap", reg["source"])
	}

	if result["created_at"] != "2025-06-15T12:00:00Z" {
		t.Errorf("created_at = %v, want 2025-06-15T12:00:00Z", result["created_at"])
	}
	if result["updated_at"] != "2025-06-15T13:00:00Z" {
		t.Errorf("updated_at = %v, want 2025-06-15T13:00:00Z", result["updated_at"])
	}
}

func TestToDict_ZeroCreatedAt(t *testing.T) {
	da := &DomainAnalysis{}
	result := da.ToDict()

	if _, exists := result["created_at"]; exists {
		t.Error("created_at should not be set for zero time")
	}
	if _, exists := result["updated_at"]; exists {
		t.Error("updated_at should not be set for nil UpdatedAt")
	}
}

func TestToDict_NilOptionalFields(t *testing.T) {
	da := &DomainAnalysis{
		Domain:          "test.org",
		CreatedAt:       time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		AnalysisSuccess: false,
	}
	result := da.ToDict()

	spf := result["spf_analysis"].(map[string]interface{})
	if s, ok := spf["status"].(*string); ok && s != nil {
		t.Errorf("spf status should be nil, got %v", s)
	}

	dmarc := result["dmarc_analysis"].(map[string]interface{})
	if s, ok := dmarc["status"].(*string); ok && s != nil {
		t.Errorf("dmarc status should be nil, got %v", s)
	}
	if s, ok := dmarc["policy"].(*string); ok && s != nil {
		t.Errorf("dmarc policy should be nil, got %v", s)
	}

	dkim := result["dkim_analysis"].(map[string]interface{})
	if s, ok := dkim["status"].(*string); ok && s != nil {
		t.Errorf("dkim status should be nil, got %v", s)
	}

	reg := result["registrar_info"].(map[string]interface{})
	if s, ok := reg["registrar"].(*string); ok && s != nil {
		t.Errorf("registrar should be nil, got %v", s)
	}

	if result["analysis_success"] != false {
		t.Errorf("analysis_success = %v, want false", result["analysis_success"])
	}
	if d, ok := result["analysis_duration"].(*float64); ok && d != nil {
		t.Errorf("analysis_duration should be nil, got %v", d)
	}
}

func TestToDict_WithErrorMessage(t *testing.T) {
	errMsg := "lookup failed"
	da := &DomainAnalysis{
		Domain:          "fail.example",
		AnalysisSuccess: false,
		ErrorMessage:    &errMsg,
		CreatedAt:       time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC),
	}
	result := da.ToDict()

	if result["error_message"] == nil {
		t.Fatal("error_message should not be nil")
	}
	if *result["error_message"].(*string) != "lookup failed" {
		t.Errorf("error_message = %v, want 'lookup failed'", result["error_message"])
	}
}

func TestDomainAnalysis_JSONTags(t *testing.T) {
	da := DomainAnalysis{
		ID:              1,
		Domain:          "json-test.com",
		ASCIIDomain:     "json-test.com",
		AnalysisSuccess: true,
		CreatedAt:       time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	data, err := json.Marshal(da)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	requiredKeys := []string{"id", "domain", "ascii_domain", "analysis_success", "created_at"}
	for _, k := range requiredKeys {
		if _, ok := m[k]; !ok {
			t.Errorf("expected JSON key %q not found", k)
		}
	}
}

func TestAnalysisStats_JSONTags(t *testing.T) {
	stats := AnalysisStats{
		ID:                 1,
		TotalAnalyses:      100,
		SuccessfulAnalyses: 95,
		FailedAnalyses:     5,
		UniqueDomains:      50,
		AvgAnalysisTime:    2.5,
		Date:               time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		CreatedAt:          time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	data, err := json.Marshal(stats)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	requiredKeys := []string{"id", "date", "total_analyses", "successful_analyses",
		"failed_analyses", "unique_domains", "avg_analysis_time", "created_at"}
	for _, k := range requiredKeys {
		if _, ok := m[k]; !ok {
			t.Errorf("expected JSON key %q not found", k)
		}
	}

	if m["total_analyses"].(float64) != 100 {
		t.Errorf("total_analyses = %v, want 100", m["total_analyses"])
	}
}

func TestDomainAnalysis_JSONRoundTrip(t *testing.T) {
	original := DomainAnalysis{
		ID:               7,
		Domain:           "roundtrip.dev",
		ASCIIDomain:      "roundtrip.dev",
		BasicRecords:     json.RawMessage(`{"mx":"mail.roundtrip.dev"}`),
		SPFStatus:        strPtr("fail"),
		DMARCStatus:      strPtr("none"),
		DMARCPolicy:      strPtr("none"),
		DKIMStatus:       strPtr("missing"),
		AnalysisSuccess:  false,
		ErrorMessage:     strPtr("timeout"),
		AnalysisDuration: floatPtr(30.0),
		CreatedAt:        time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded DomainAnalysis
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if decoded.ID != original.ID {
		t.Errorf("ID = %d, want %d", decoded.ID, original.ID)
	}
	if decoded.Domain != original.Domain {
		t.Errorf("Domain = %q, want %q", decoded.Domain, original.Domain)
	}
	if *decoded.SPFStatus != *original.SPFStatus {
		t.Errorf("SPFStatus = %q, want %q", *decoded.SPFStatus, *original.SPFStatus)
	}
	if decoded.AnalysisSuccess != original.AnalysisSuccess {
		t.Errorf("AnalysisSuccess = %v, want %v", decoded.AnalysisSuccess, original.AnalysisSuccess)
	}
}
