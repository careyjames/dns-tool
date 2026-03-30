//go:build intel

package analyzer

import (
	"fmt"
	"testing"
)

func TestExtractSaaSTXTFootprint_Intel_NoBasicRecords(t *testing.T) {
	got := ExtractSaaSTXTFootprint(map[string]any{})
	if got["status"] != "success" {
		t.Errorf("status = %v", got["status"])
	}
	if got["service_count"] != 0 {
		t.Errorf("service_count = %v", got["service_count"])
	}
}

func TestExtractSaaSTXTFootprint_Intel_NoTXT(t *testing.T) {
	results := map[string]any{
		"basic_records": map[string]any{},
	}
	got := ExtractSaaSTXTFootprint(results)
	if got["service_count"] != 0 {
		t.Errorf("service_count = %v", got["service_count"])
	}
}

func TestExtractSaaSTXTFootprint_Intel_GoogleVerification(t *testing.T) {
	results := map[string]any{
		"basic_records": map[string]any{
			"TXT": []string{"google-site-verification=abc123"},
		},
	}
	got := ExtractSaaSTXTFootprint(results)
	if got["service_count"] != 1 {
		t.Errorf("service_count = %v, want 1", got["service_count"])
	}
	services := got["services"].([]map[string]any)
	if services[0]["name"] != "Google" {
		t.Errorf("service name = %v, want Google", services[0]["name"])
	}
}

func TestExtractSaaSTXTFootprint_Intel_MultipleServices(t *testing.T) {
	results := map[string]any{
		"basic_records": map[string]any{
			"TXT": []string{
				"google-site-verification=abc",
				"facebook-domain-verification=xyz",
				"MS=ms123",
			},
		},
	}
	got := ExtractSaaSTXTFootprint(results)
	count := got["service_count"].(int)
	if count != 3 {
		t.Errorf("service_count = %d, want 3", count)
	}
}

func TestExtractSaaSTXTFootprint_Intel_Deduplication(t *testing.T) {
	results := map[string]any{
		"basic_records": map[string]any{
			"TXT": []string{
				"google-site-verification=abc",
				"google-site-verification=xyz",
			},
		},
	}
	got := ExtractSaaSTXTFootprint(results)
	count := got["service_count"].(int)
	if count != 1 {
		t.Errorf("service_count = %d, want 1 (deduplicated)", count)
	}
}

func TestExtractSaaSTXTFootprint_Intel_TXTAsAnySlice(t *testing.T) {
	results := map[string]any{
		"basic_records": map[string]any{
			"TXT": []any{"google-site-verification=abc", "MS=ms123"},
		},
	}
	got := ExtractSaaSTXTFootprint(results)
	count := got["service_count"].(int)
	if count != 2 {
		t.Errorf("service_count = %d, want 2", count)
	}
}

func TestExtractSaaSTXTFootprint_Intel_QuotedRecords(t *testing.T) {
	results := map[string]any{
		"basic_records": map[string]any{
			"TXT": []string{`"google-site-verification=abc"`},
		},
	}
	got := ExtractSaaSTXTFootprint(results)
	if got["service_count"] != 1 {
		t.Errorf("service_count = %v, want 1 (should strip quotes)", got["service_count"])
	}
}

func TestExtractSaaSTXTFootprint_Intel_EmptyTXT(t *testing.T) {
	results := map[string]any{
		"basic_records": map[string]any{
			"TXT": []string{},
		},
	}
	got := ExtractSaaSTXTFootprint(results)
	if got["service_count"] != 0 {
		t.Errorf("service_count = %v, want 0", got["service_count"])
	}
}

func TestExtractSaaSTXTFootprint_Intel_MessageFormat(t *testing.T) {
	results := map[string]any{
		"basic_records": map[string]any{
			"TXT": []string{
				"google-site-verification=abc",
				"facebook-domain-verification=xyz",
			},
		},
	}
	got := ExtractSaaSTXTFootprint(results)
	msg := got["message"].(string)
	expected := fmt.Sprintf("Detected %d SaaS verification records", 2)
	if msg != expected {
		t.Errorf("message = %q, want %q", msg, expected)
	}
}

func TestSaaSPatterns_Intel_NonEmpty(t *testing.T) {
	if len(saasPatterns) == 0 {
		t.Error("saasPatterns should be non-empty in intel build")
	}
}

func TestMatchSaaSPatterns_Intel_NoMatch(t *testing.T) {
	seen := make(map[string]bool)
	var services []map[string]any
	matchSaaSPatterns("v=spf1 include:example.com ~all", seen, &services)
	if len(services) != 0 {
		t.Errorf("expected no match for SPF record, got %d", len(services))
	}
}

func TestMatchSaaSPatterns_Intel_WithMatch(t *testing.T) {
	seen := make(map[string]bool)
	var services []map[string]any
	matchSaaSPatterns("google-site-verification=abc123", seen, &services)
	if len(services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(services))
	}
	if services[0]["name"] != "Google" {
		t.Errorf("service name = %v", services[0]["name"])
	}
}

func TestMatchSaaSPatterns_Intel_SeenSkipped(t *testing.T) {
	seen := map[string]bool{"Google": true}
	var services []map[string]any
	matchSaaSPatterns("google-site-verification=abc123", seen, &services)
	if len(services) != 0 {
		t.Errorf("expected 0 services for already-seen, got %d", len(services))
	}
}

func TestExtractSaaSTXTFootprint_Intel_NonStringInAnySlice(t *testing.T) {
	results := map[string]any{
		"basic_records": map[string]any{
			"TXT": []any{42, true, nil, "google-site-verification=abc"},
		},
	}
	got := ExtractSaaSTXTFootprint(results)
	count := got["service_count"].(int)
	if count != 1 {
		t.Errorf("service_count = %d, want 1 (should skip non-string items)", count)
	}
}

func TestExtractSaaSTXTFootprint_Intel_AllKnownPatterns(t *testing.T) {
	patternCount := len(saasPatterns)
	if patternCount < 30 {
		t.Errorf("expected at least 30 saas patterns in intel build, got %d", patternCount)
	}
}
