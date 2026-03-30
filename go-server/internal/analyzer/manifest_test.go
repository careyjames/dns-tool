package analyzer

import (
	"testing"
)

func TestManifestEntry_Fields(t *testing.T) {
	entry := ManifestEntry{
		Feature:          "SPF",
		Category:         "email_security",
		Description:      "SPF record validation",
		SchemaKey:        "spf_analysis",
		DetectionMethods: []string{"DNS TXT lookup"},
		RFC:              "RFC 7208",
	}
	if entry.Feature != "SPF" {
		t.Errorf("Feature = %q", entry.Feature)
	}
	if entry.Category != "email_security" {
		t.Errorf("Category = %q", entry.Category)
	}
	if entry.SchemaKey != "spf_analysis" {
		t.Errorf("SchemaKey = %q", entry.SchemaKey)
	}
	if len(entry.DetectionMethods) != 1 {
		t.Errorf("DetectionMethods len = %d, want 1", len(entry.DetectionMethods))
	}
	if entry.DetectionMethods[0] != "DNS TXT lookup" {
		t.Errorf("DetectionMethods[0] = %q", entry.DetectionMethods[0])
	}
	if entry.RFC != "RFC 7208" {
		t.Errorf("RFC = %q", entry.RFC)
	}
}

func TestManifestEntry_ZeroValue(t *testing.T) {
	var entry ManifestEntry
	if entry.Feature != "" {
		t.Errorf("zero value Feature = %q, want empty", entry.Feature)
	}
	if entry.Category != "" {
		t.Errorf("zero value Category = %q, want empty", entry.Category)
	}
	if entry.DetectionMethods != nil {
		t.Errorf("zero value DetectionMethods = %v, want nil", entry.DetectionMethods)
	}
}

func TestGetManifestByCategory_NoMatchForUnknownCategory(t *testing.T) {
	result := GetManifestByCategory("nonexistent_category_xyz_12345")
	if len(result) != 0 {
		t.Errorf("expected 0 entries for unknown category, got %d", len(result))
	}
}

func TestGetManifestByCategory_EmptyCategory(t *testing.T) {
	result := GetManifestByCategory("")
	if len(result) != 0 {
		t.Errorf("expected 0 entries for empty category, got %d", len(result))
	}
}

func TestGetManifestByCategory_FiltersCorrectly(t *testing.T) {
	original := FeatureParityManifest
	defer func() { FeatureParityManifest = original }()

	FeatureParityManifest = []ManifestEntry{
		{Feature: "SPF", Category: "email_security", SchemaKey: "spf"},
		{Feature: "DMARC", Category: "email_security", SchemaKey: "dmarc"},
		{Feature: "CDN", Category: "infrastructure", SchemaKey: "cdn"},
	}

	emailResults := GetManifestByCategory("email_security")
	if len(emailResults) != 2 {
		t.Fatalf("expected 2 email_security entries, got %d", len(emailResults))
	}
	if emailResults[0].Feature != "SPF" {
		t.Errorf("first entry Feature = %q, want SPF", emailResults[0].Feature)
	}
	if emailResults[1].Feature != "DMARC" {
		t.Errorf("second entry Feature = %q, want DMARC", emailResults[1].Feature)
	}

	infraResults := GetManifestByCategory("infrastructure")
	if len(infraResults) != 1 {
		t.Fatalf("expected 1 infrastructure entry, got %d", len(infraResults))
	}
	if infraResults[0].SchemaKey != "cdn" {
		t.Errorf("SchemaKey = %q, want cdn", infraResults[0].SchemaKey)
	}

	noResults := GetManifestByCategory("dns")
	if len(noResults) != 0 {
		t.Errorf("expected 0 dns entries, got %d", len(noResults))
	}
}

func TestGetManifestByCategory_ReturnsNewSlice(t *testing.T) {
	original := FeatureParityManifest
	defer func() { FeatureParityManifest = original }()

	FeatureParityManifest = []ManifestEntry{
		{Feature: "SPF", Category: "email", SchemaKey: "spf"},
	}

	r1 := GetManifestByCategory("email")
	r2 := GetManifestByCategory("email")
	if len(r1) != 1 || len(r2) != 1 {
		t.Fatalf("expected 1 entry each, got %d and %d", len(r1), len(r2))
	}
	r1[0].Feature = "MODIFIED"
	if r2[0].Feature == "MODIFIED" {
		t.Error("modifying one result should not affect another call's result")
	}
}

func TestFeatureParityManifest_Initialized(t *testing.T) {
	if FeatureParityManifest == nil && len(FeatureParityManifest) != 0 {
		t.Error("FeatureParityManifest should not be both nil and non-zero length")
	}
}

func TestRequiredSchemaKeys_Initialized(t *testing.T) {
	for i, key := range RequiredSchemaKeys {
		if key == "" {
			t.Errorf("RequiredSchemaKeys[%d] is empty", i)
		}
	}
}
