package analyzer

import (
	"testing"
)

func TestCollectExternalDomains(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		rua    string
		ruf    string
		want   int
	}{
		{"no external", "example.com", "mailto:dmarc@example.com", "", 0},
		{"one external in rua", "example.com", "mailto:dmarc@external.com", "", 1},
		{"one external in ruf", "example.com", "", "mailto:dmarc@external.com", 1},
		{"same external in both", "example.com", "mailto:dmarc@external.com", "mailto:dmarc@external.com", 1},
		{"multiple externals", "example.com", "mailto:a@ext1.com,mailto:b@ext2.com", "", 2},
		{"empty strings", "example.com", "", "", 0},
		{"case insensitive same domain", "Example.COM", "mailto:dmarc@example.com", "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := collectExternalDomains(tt.domain, tt.rua, tt.ruf)
			if len(got) != tt.want {
				t.Errorf("collectExternalDomains() returned %d domains, want %d", len(got), tt.want)
			}
		})
	}
}

func TestCollectExternalDomains_Sources(t *testing.T) {
	result := collectExternalDomains("example.com", "mailto:a@ext.com", "mailto:b@ext.com")
	if sources, ok := result["ext.com"]; ok {
		if len(sources) != 2 {
			t.Errorf("expected 2 sources for ext.com, got %d", len(sources))
		}
	} else {
		t.Error("expected ext.com in results")
	}
}

func TestAppendUnique(t *testing.T) {
	tests := []struct {
		name  string
		slice []string
		val   string
		want  int
	}{
		{"append to empty", nil, "a", 1},
		{"append new value", []string{"a"}, "b", 2},
		{"skip duplicate", []string{"a", "b"}, "a", 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := appendUnique(tt.slice, tt.val)
			if len(got) != tt.want {
				t.Errorf("appendUnique() length = %d, want %d", len(got), tt.want)
			}
		})
	}
}
