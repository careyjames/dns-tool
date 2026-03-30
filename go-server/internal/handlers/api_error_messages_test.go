package handlers

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"testing"
)

func TestSecurityTrailsErrorMessage_CB14(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		contain string
	}{
		{"rate limited", errors.New("rate_limited"), "rate limit"},
		{"auth failed", errors.New("auth_failed"), "API key was rejected"},
		{"connection error", errors.New("connection_error"), "Could not connect"},
		{"unknown error", errors.New("something_else"), "unexpected error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := securityTrailsErrorMessage(tt.err)
			if msg == "" {
				t.Fatal("expected non-empty message")
			}
			if !containsSubstring(msg, tt.contain) {
				t.Errorf("message %q does not contain %q", msg, tt.contain)
			}
		})
	}
}

func TestIPInfoErrorMessage_CB14(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		contain string
	}{
		{"rate limit", errors.New("rate limit exceeded"), "rate limit"},
		{"invalid token", errors.New("invalid token"), "Token was rejected"},
		{"expired token", errors.New("token expired"), "Token was rejected"},
		{"generic error", errors.New("network timeout"), "Could not retrieve"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := ipInfoErrorMessage(tt.err)
			if msg == "" {
				t.Fatal("expected non-empty message")
			}
			if !containsSubstring(msg, tt.contain) {
				t.Errorf("message %q does not contain %q", msg, tt.contain)
			}
		})
	}
}

func TestValidateBIMIResponse_CB14(t *testing.T) {
	t.Run("non-200 status", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 404,
			Header:     http.Header{},
			Body:       io.NopCloser(bytes.NewReader(nil)),
		}
		_, _, err := validateBIMIResponse(resp)
		if err == nil {
			t.Fatal("expected error for non-200 status")
		}
		if ve, ok := err.(*bimiFetchError); ok {
			if ve.status != http.StatusBadGateway {
				t.Errorf("status = %d, want %d", ve.status, http.StatusBadGateway)
			}
		} else {
			t.Error("expected bimiFetchError type")
		}
	})

	t.Run("non-image content type", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": []string{"text/html"}},
			Body:       io.NopCloser(bytes.NewReader([]byte("<html></html>"))),
		}
		_, _, err := validateBIMIResponse(resp)
		if err == nil {
			t.Fatal("expected error for non-image content type")
		}
		if ve, ok := err.(*bimiFetchError); ok {
			if ve.msg != "Response is not an image" {
				t.Errorf("msg = %q", ve.msg)
			}
		} else {
			t.Error("expected bimiFetchError type")
		}
	})

	t.Run("body too large", func(t *testing.T) {
		bigBody := make([]byte, bimiMaxResponseBytes+10)
		resp := &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": []string{"image/svg+xml"}},
			Body:       io.NopCloser(bytes.NewReader(bigBody)),
		}
		_, _, err := validateBIMIResponse(resp)
		if err == nil {
			t.Fatal("expected error for oversized body")
		}
		if ve, ok := err.(*bimiFetchError); ok {
			if ve.msg != "Response too large" {
				t.Errorf("msg = %q", ve.msg)
			}
		} else {
			t.Error("expected bimiFetchError type")
		}
	})

	t.Run("valid SVG response", func(t *testing.T) {
		svgData := []byte(`<svg xmlns="http://www.w3.org/2000/svg"></svg>`)
		resp := &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": []string{"image/svg+xml; charset=utf-8"}},
			Body:       io.NopCloser(bytes.NewReader(svgData)),
		}
		body, ct, err := validateBIMIResponse(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ct != "image/svg+xml" {
			t.Errorf("content type = %q, want image/svg+xml", ct)
		}
		if !bytes.Equal(body, svgData) {
			t.Error("body mismatch")
		}
	})

	t.Run("valid PNG response", func(t *testing.T) {
		pngData := []byte{0x89, 0x50, 0x4E, 0x47}
		resp := &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": []string{"image/png"}},
			Body:       io.NopCloser(bytes.NewReader(pngData)),
		}
		body, ct, err := validateBIMIResponse(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ct != "image/png" {
			t.Errorf("content type = %q, want image/png", ct)
		}
		if !bytes.Equal(body, pngData) {
			t.Error("body mismatch")
		}
	})
}

func TestApplySecurityTrailsNeighborhood_CB14(t *testing.T) {
	t.Run("empty domains", func(t *testing.T) {
		results := map[string]any{}
		applySecurityTrailsNeighborhood([]string{}, "example.com", "example.com", results)
		neighborhood := results["neighborhood"].([]map[string]any)
		if len(neighborhood) != 0 {
			t.Errorf("expected empty neighborhood, got %d", len(neighborhood))
		}
		if results["neighborhood_total"] != 0 {
			t.Errorf("total = %v, want 0", results["neighborhood_total"])
		}
	})

	t.Run("self domain excluded", func(t *testing.T) {
		domains := []string{"example.com", "other.com", "another.com"}
		results := map[string]any{}
		applySecurityTrailsNeighborhood(domains, "example.com", "example.com", results)
		neighborhood := results["neighborhood"].([]map[string]any)
		if len(neighborhood) != 2 {
			t.Errorf("expected 2 neighbors (self excluded), got %d", len(neighborhood))
		}
		for _, n := range neighborhood {
			if n["domain"] == "example.com" {
				t.Error("self domain should be excluded")
			}
		}
		if results["neighborhood_total"] != 3 {
			t.Errorf("total = %v, want 3", results["neighborhood_total"])
		}
	})

	t.Run("cap at 10", func(t *testing.T) {
		domains := make([]string, 15)
		for i := range domains {
			domains[i] = "domain" + string(rune('a'+i)) + ".com"
		}
		results := map[string]any{}
		applySecurityTrailsNeighborhood(domains, "notinlist.com", "notinlist.com", results)
		neighborhood := results["neighborhood"].([]map[string]any)
		if len(neighborhood) != 10 {
			t.Errorf("expected capped at 10, got %d", len(neighborhood))
		}
		if results["neighborhood_total"] != 15 {
			t.Errorf("total = %v, want 15", results["neighborhood_total"])
		}
		if results["st_enabled"] != true {
			t.Error("st_enabled should be true")
		}
	})
}

func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && bytes.Contains([]byte(s), []byte(sub))
}
