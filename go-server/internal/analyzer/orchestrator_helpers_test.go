// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
	"testing"
)

func TestDetectNullMX_Standard(t *testing.T) {
	basic := map[string]any{
		"MX": []string{"10 mail.example.com."},
	}
	if detectNullMX(basic) {
		t.Error("standard MX should not be null MX")
	}
}

func TestDetectNullMX_NullRecord(t *testing.T) {
	tests := []struct {
		name string
		mx   []string
	}{
		{"dot only", []string{"0 ."}},
		{"zero dot", []string{"0."}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			basic := map[string]any{"MX": tt.mx}
			if !detectNullMX(basic) {
				t.Errorf("expected null MX detection for %v", tt.mx)
			}
		})
	}
}

func TestDetectNullMX_Empty(t *testing.T) {
	basic := map[string]any{"MX": []string{}}
	if detectNullMX(basic) {
		t.Error("empty MX should not be null MX")
	}
}

func TestDetectNullMX_MissingKey(t *testing.T) {
	basic := map[string]any{}
	if detectNullMX(basic) {
		t.Error("missing MX key should not be null MX")
	}
}

func TestGetMapResult_Exists(t *testing.T) {
	m := map[string]any{
		"test": map[string]any{"status": "ok"},
	}
	result := getMapResult(m, "test")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result["status"] != "ok" {
		t.Error("expected status ok")
	}
}

func TestGetMapResult_Missing(t *testing.T) {
	m := map[string]any{}
	result := getMapResult(m, "test")
	if len(result) != 0 {
		t.Error("expected empty map for missing key")
	}
}

func TestGetOrDefault_Exists(t *testing.T) {
	m := map[string]any{
		"test": map[string]any{"status": "found"},
	}
	defaultVal := map[string]any{"status": "default"}
	result := getOrDefault(m, "test", defaultVal)
	r, ok := result.(map[string]any)
	if !ok {
		t.Fatal("expected map result")
	}
	if r["status"] != "found" {
		t.Error("expected 'found' status")
	}
}

func TestGetOrDefault_Missing(t *testing.T) {
	m := map[string]any{}
	defaultVal := map[string]any{"status": "default"}
	result := getOrDefault(m, "missing", defaultVal)
	r, ok := result.(map[string]any)
	if !ok {
		t.Fatal("expected map result")
	}
	if r["status"] != "default" {
		t.Error("expected default status")
	}
}

func TestExtractAndRemove(t *testing.T) {
	m := map[string]any{
		"keep":   "value1",
		"remove": "value2",
	}
	extracted := extractAndRemove(m, "remove")
	if extracted != "value2" {
		t.Error("expected extracted value")
	}
	if _, ok := m["remove"]; ok {
		t.Error("key should be removed from map")
	}
	if _, ok := m["keep"]; !ok {
		t.Error("other keys should remain")
	}
}

func TestExtractAndRemove_MissingKey(t *testing.T) {
	m := map[string]any{"keep": "value"}
	extracted := extractAndRemove(m, "missing")
	if extracted != nil {
		t.Error("expected nil for missing key")
	}
}

func TestMakeStringSet(t *testing.T) {
	set := makeStringSet([]string{"a", "b", "a", "c"})
	if len(set) != 3 {
		t.Errorf("expected 3 unique entries, got %d", len(set))
	}
	if !set["a"] || !set["b"] || !set["c"] {
		t.Error("missing expected entries")
	}
}

func TestKeysOf(t *testing.T) {
	m := map[string]bool{"x": true, "y": true}
	keys := keysOf(m)
	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(keys))
	}
}

func TestAdjustHostingSummary_NoMail(t *testing.T) {
	results := map[string]any{
		"is_no_mail_domain": true,
		"has_null_mx":       false,
		"hosting_summary":   map[string]any{"email_hosting": "Unknown"},
	}
	adjustHostingSummary(results)

	hs := results["hosting_summary"].(map[string]any)
	if hs["email_hosting"] != "No Mail Domain" {
		t.Errorf("expected 'No Mail Domain', got '%v'", hs["email_hosting"])
	}
}

func TestAdjustHostingSummary_NullMX(t *testing.T) {
	results := map[string]any{
		"is_no_mail_domain": false,
		"has_null_mx":       true,
		"hosting_summary":   map[string]any{"email_hosting": ""},
	}
	adjustHostingSummary(results)

	hs := results["hosting_summary"].(map[string]any)
	if hs["email_hosting"] != "No Mail Domain" {
		t.Errorf("expected 'No Mail Domain', got '%v'", hs["email_hosting"])
	}
}

func TestInferEmailFromDKIM(t *testing.T) {
	hs := map[string]any{"email_hosting": "Unknown"}
	results := map[string]any{
		"dkim_analysis": map[string]any{
			"primary_provider": "Google Workspace",
		},
	}
	inferEmailFromDKIM(hs, results)
	if hs["email_hosting"] != "Google Workspace" {
		t.Errorf("expected 'Google Workspace', got '%v'", hs["email_hosting"])
	}
}

func TestInferEmailFromDKIM_UnknownProvider(t *testing.T) {
	hs := map[string]any{"email_hosting": "Unknown"}
	results := map[string]any{
		"dkim_analysis": map[string]any{
			"primary_provider": "Unknown",
		},
	}
	inferEmailFromDKIM(hs, results)
	if hs["email_hosting"] != "Unknown" {
		t.Errorf("expected 'Unknown' (unchanged), got '%v'", hs["email_hosting"])
	}
}

func TestBuildSectionStatus(t *testing.T) {
	resultsMap := map[string]any{
		"spf":   map[string]any{"status": "success"},
		"dmarc": map[string]any{"status": "warning"},
		"dkim":  map[string]any{"status": "error"},
	}
	status := buildSectionStatus(resultsMap)
	if status == nil {
		t.Fatal("expected non-nil section status")
	}
}
