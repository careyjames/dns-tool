package analyzer

import (
	"testing"
)

func TestTruncateRecord_Short(t *testing.T) {
	got := truncateRecord("short", 80)
	if got != "short" {
		t.Errorf("truncateRecord('short', 80) = %q", got)
	}
}

func TestTruncateRecord_ExactLength(t *testing.T) {
	s := "12345"
	got := truncateRecord(s, 5)
	if got != s {
		t.Errorf("truncateRecord at exact length = %q", got)
	}
}

func TestTruncateRecord_Long(t *testing.T) {
	s := "abcdefghij"
	got := truncateRecord(s, 5)
	if got != "abcde..." {
		t.Errorf("truncateRecord('%s', 5) = %q, want 'abcde...'", s, got)
	}
}

func TestExtractSaaSTXTFromRecords_Empty(t *testing.T) {
	result := extractSaaSTXTFromRecords(nil, commoditySaaSPatterns)
	count, ok := result["service_count"].(int)
	if !ok || count != 0 {
		t.Errorf("service_count = %v", result["service_count"])
	}
	msg := result["message"].(string)
	if msg != "No SaaS services detected" {
		t.Errorf("message = %q", msg)
	}
}

func TestExtractSaaSTXTFromRecords_GoogleWorkspace(t *testing.T) {
	records := []any{"google-site-verification=abc123"}
	result := extractSaaSTXTFromRecords(records, commoditySaaSPatterns)
	count := result["service_count"].(int)
	if count != 1 {
		t.Errorf("service_count = %d, want 1", count)
	}
	services := result["services"].([]map[string]any)
	if services[0]["name"] != "Google Workspace" {
		t.Errorf("service name = %q", services[0]["name"])
	}
}

func TestExtractSaaSTXTFromRecords_MultipleServices(t *testing.T) {
	records := []any{
		"google-site-verification=abc",
		"MS=ms12345",
		"facebook-domain-verification=xyz",
	}
	result := extractSaaSTXTFromRecords(records, commoditySaaSPatterns)
	count := result["service_count"].(int)
	if count != 3 {
		t.Errorf("service_count = %d, want 3", count)
	}
}

func TestExtractSaaSTXTFromRecords_DeduplicatesSameService(t *testing.T) {
	records := []any{
		"google-site-verification=abc",
		"google-site-verification=xyz",
	}
	result := extractSaaSTXTFromRecords(records, commoditySaaSPatterns)
	count := result["service_count"].(int)
	if count != 1 {
		t.Errorf("service_count = %d, want 1 (should deduplicate)", count)
	}
}

func TestExtractSaaSTXTFromRecords_NonStringRecords(t *testing.T) {
	records := []any{42, true, nil}
	result := extractSaaSTXTFromRecords(records, commoditySaaSPatterns)
	count := result["service_count"].(int)
	if count != 0 {
		t.Errorf("service_count = %d, want 0", count)
	}
}

func TestExtractSaaSTXTFromRecords_Truncation(t *testing.T) {
	longRecord := "google-site-verification=" + string(make([]byte, 200))
	records := []any{longRecord}
	result := extractSaaSTXTFromRecords(records, commoditySaaSPatterns)
	services := result["services"].([]map[string]any)
	rec := services[0]["record"].(string)
	if len(rec) > 84 {
		t.Errorf("record should be truncated, len = %d", len(rec))
	}
}

func TestExtractSaaSTXTFromRecords_AllCommodityPatterns(t *testing.T) {
	patterns := map[string]string{
		"Google Workspace":  "google-site-verification=abc",
		"Microsoft 365":     "MS=ms123",
		"Facebook / Meta":   "facebook-domain-verification=xyz",
		"Apple":             "apple-domain-verification=abc",
		"DocuSign":          "docusign=abc",
		"Atlassian":         "atlassian-domain-verification=abc",
		"Slack":             "slack-domain-verification=abc",
		"Zoom":              "zoom-verification=abc",
		"GitHub":            "_github-challenge-abc",
		"Stripe":            "stripe-verification=abc",
		"Amazon SES":        "amazonses:abc",
		"Cloudflare":        "cloudflare-domain-verification=abc",
		"Salesforce":        "salesforce-domainkey=abc",
		"Twilio / SendGrid": "sendgrid-verification=abc",
	}
	for name, record := range patterns {
		records := []any{record}
		result := extractSaaSTXTFromRecords(records, commoditySaaSPatterns)
		count := result["service_count"].(int)
		if count != 1 {
			t.Errorf("pattern %q: service_count = %d, want 1", name, count)
		}
		services := result["services"].([]map[string]any)
		if services[0]["name"] != name {
			t.Errorf("pattern %q: got name %q", name, services[0]["name"])
		}
	}
}

func TestPluralS(t *testing.T) {
	if pluralS(0) != "s" {
		t.Error("pluralS(0) should return 's'")
	}
	if pluralS(1) != "" {
		t.Error("pluralS(1) should return ''")
	}
	if pluralS(2) != "s" {
		t.Error("pluralS(2) should return 's'")
	}
}

func TestExtractSaaSTXTFootprint_NoBasicRecords(t *testing.T) {
	result := ExtractSaaSTXTFootprint(map[string]any{})
	count := result["service_count"].(int)
	if count != 0 {
		t.Errorf("service_count = %d, want 0", count)
	}
}

func TestExtractSaaSTXTFootprint_NoTXT(t *testing.T) {
	result := ExtractSaaSTXTFootprint(map[string]any{
		"basic_records": map[string]any{},
	})
	count := result["service_count"].(int)
	if count != 0 {
		t.Errorf("service_count = %d, want 0", count)
	}
}

func TestExtractSaaSTXTFootprint_WithTXTRecords(t *testing.T) {
	result := ExtractSaaSTXTFootprint(map[string]any{
		"basic_records": map[string]any{
			"TXT": []any{"google-site-verification=abc123"},
		},
	})
	count := result["service_count"].(int)
	if count != 1 {
		t.Errorf("service_count = %d, want 1", count)
	}
}

func TestExtractSaaSTXTFootprint_StringSliceTXT(t *testing.T) {
	result := ExtractSaaSTXTFootprint(map[string]any{
		"basic_records": map[string]any{
			"TXT": []string{"MS=ms12345"},
		},
	})
	count := result["service_count"].(int)
	if count != 1 {
		t.Errorf("service_count = %d, want 1", count)
	}
}

func TestExtractSaaSTXTFootprint_EmptyTXT(t *testing.T) {
	result := ExtractSaaSTXTFootprint(map[string]any{
		"basic_records": map[string]any{
			"TXT": []any{},
		},
	})
	count := result["service_count"].(int)
	if count != 0 {
		t.Errorf("service_count = %d, want 0", count)
	}
}

func TestExtractSaaSTXTFootprint_InvalidTXTType(t *testing.T) {
	result := ExtractSaaSTXTFootprint(map[string]any{
		"basic_records": map[string]any{
			"TXT": 42,
		},
	})
	count := result["service_count"].(int)
	if count != 0 {
		t.Errorf("service_count = %d, want 0", count)
	}
}
