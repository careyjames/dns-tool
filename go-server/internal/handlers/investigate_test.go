package handlers

import (
	"errors"
	"strings"
	"testing"
)

func TestSecurityTrailsErrorMessageCases(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		contains string
	}{
		{"rate limited", "rate_limited", "rate limit"},
		{"auth failed", "auth_failed", "rejected"},
		{"connection error", "connection_error", "Could not connect"},
		{"unknown error", "some_random_error", "unexpected"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := securityTrailsErrorMessage(errors.New(tt.errMsg))
			if got == "" {
				t.Fatal("expected non-empty error message")
			}
		})
	}
}

func TestIPInfoErrorMessageCases(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		contains string
	}{
		{"rate limit", "rate limit exceeded", "rate limit"},
		{"invalid token", "invalid token", "rejected"},
		{"expired token", "token has expired", "rejected"},
		{"generic error", "connection failed", "temporarily unavailable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ipInfoErrorMessage(errors.New(tt.errMsg))
			if got == "" {
				t.Fatal("expected non-empty error message")
			}
		})
	}
}

func TestApplySecurityTrailsNeighborhood(t *testing.T) {
	t.Run("filters out target domain", func(t *testing.T) {
		results := map[string]any{}
		stDomains := []string{"example.com", "neighbor1.com", "neighbor2.com"}
		applySecurityTrailsNeighborhood(stDomains, "example.com", "example.com", results)

		neighborhood, ok := results["neighborhood"].([]map[string]any)
		if !ok {
			t.Fatal("expected neighborhood to be []map[string]any")
		}
		if len(neighborhood) != 2 {
			t.Errorf("expected 2 neighbors, got %d", len(neighborhood))
		}
		for _, n := range neighborhood {
			if n["domain"] == "example.com" {
				t.Error("should not include target domain in neighborhood")
			}
			if n["source"] != "securitytrails" {
				t.Errorf("source = %v, want securitytrails", n["source"])
			}
		}
		if results["neighborhood_total"] != 3 {
			t.Errorf("neighborhood_total = %v, want 3", results["neighborhood_total"])
		}
		if results["neighborhood_source"] != "SecurityTrails" {
			t.Errorf("neighborhood_source = %v", results["neighborhood_source"])
		}
		if results["st_enabled"] != true {
			t.Errorf("st_enabled = %v", results["st_enabled"])
		}
	})

	t.Run("case insensitive domain filtering", func(t *testing.T) {
		results := map[string]any{}
		stDomains := []string{"Example.COM", "other.com"}
		applySecurityTrailsNeighborhood(stDomains, "example.com", "example.com", results)

		neighborhood := results["neighborhood"].([]map[string]any)
		if len(neighborhood) != 1 {
			t.Errorf("expected 1 neighbor, got %d", len(neighborhood))
		}
	})

	t.Run("caps at 10 neighbors", func(t *testing.T) {
		results := map[string]any{}
		stDomains := make([]string, 15)
		for i := range stDomains {
			stDomains[i] = "n" + string(rune('a'+i)) + ".com"
		}
		applySecurityTrailsNeighborhood(stDomains, "target.com", "target.com", results)

		neighborhood := results["neighborhood"].([]map[string]any)
		if len(neighborhood) > 10 {
			t.Errorf("expected at most 10 neighbors, got %d", len(neighborhood))
		}
	})

	t.Run("filters ascii domain variant", func(t *testing.T) {
		results := map[string]any{}
		stDomains := []string{"xn--example.com", "other.com"}
		applySecurityTrailsNeighborhood(stDomains, "ëxample.com", "xn--example.com", results)

		neighborhood := results["neighborhood"].([]map[string]any)
		if len(neighborhood) != 1 {
			t.Errorf("expected 1 neighbor, got %d", len(neighborhood))
		}
		if neighborhood[0]["domain"] != "other.com" {
			t.Errorf("expected other.com, got %v", neighborhood[0]["domain"])
		}
	})
}

func TestSecurityTrailsErrorMessageContent(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		contains string
	}{
		{"rate limited mentions rate limit", "rate_limited", "rate limit"},
		{"auth failed mentions rejected", "auth_failed", "rejected"},
		{"connection error mentions connect", "connection_error", "Could not connect"},
		{"unknown mentions unexpected", "anything_else", "unexpected"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := securityTrailsErrorMessage(errors.New(tt.errMsg))
			if !strings.Contains(strings.ToLower(got), strings.ToLower(tt.contains)) {
				t.Errorf("expected message containing %q, got %q", tt.contains, got)
			}
		})
	}
}

func TestIPInfoErrorMessageContent(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		contains string
	}{
		{"rate limit mentions rate limit", "rate limit exceeded", "rate limit"},
		{"invalid mentions rejected", "invalid token", "rejected"},
		{"expired mentions rejected", "token expired", "rejected"},
		{"other mentions unavailable", "something broke", "unavailable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ipInfoErrorMessage(errors.New(tt.errMsg))
			if !strings.Contains(strings.ToLower(got), strings.ToLower(tt.contains)) {
				t.Errorf("expected message containing %q, got %q", tt.contains, got)
			}
		})
	}
}

func TestApplySecurityTrailsNeighborhoodEmptyDomains(t *testing.T) {
	results := map[string]any{}
	applySecurityTrailsNeighborhood([]string{}, "example.com", "example.com", results)

	neighborhood, ok := results["neighborhood"].([]map[string]any)
	if !ok {
		t.Fatal("expected neighborhood to be []map[string]any")
	}
	if len(neighborhood) != 0 {
		t.Errorf("expected 0 neighbors for empty input, got %d", len(neighborhood))
	}
	if results["neighborhood_total"] != 0 {
		t.Errorf("neighborhood_total = %v, want 0", results["neighborhood_total"])
	}
}

func TestApplySecurityTrailsNeighborhoodAllSameDomain(t *testing.T) {
	results := map[string]any{}
	stDomains := []string{"example.com", "EXAMPLE.COM", "Example.Com"}
	applySecurityTrailsNeighborhood(stDomains, "example.com", "example.com", results)

	neighborhood := results["neighborhood"].([]map[string]any)
	if len(neighborhood) != 0 {
		t.Errorf("expected 0 neighbors when all match target, got %d", len(neighborhood))
	}
}

func TestApplySecurityTrailsNeighborhoodExactly10(t *testing.T) {
	results := map[string]any{}
	stDomains := make([]string, 10)
	for i := range stDomains {
		stDomains[i] = "neighbor" + string(rune('a'+i)) + ".com"
	}
	applySecurityTrailsNeighborhood(stDomains, "target.com", "target.com", results)

	neighborhood := results["neighborhood"].([]map[string]any)
	if len(neighborhood) != 10 {
		t.Errorf("expected exactly 10 neighbors, got %d", len(neighborhood))
	}
}

func TestInvestigateConstants(t *testing.T) {
	if mapKeyInvestigate != "investigate" {
		t.Errorf("unexpected mapKeyInvestigate: %q", mapKeyInvestigate)
	}
	if investigateTemplate != "investigate.html" {
		t.Errorf("unexpected investigateTemplate: %q", investigateTemplate)
	}
}
