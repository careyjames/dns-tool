// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
	"context"
	"testing"
	"time"

	"dnstool/go-server/internal/dnsclient"
	"dnstool/go-server/internal/telemetry"
)

func newTestAnalyzer() *Analyzer {
	return &Analyzer{
		DNS:         dnsclient.New(),
		HTTP:        dnsclient.NewSafeHTTPClient(),
		SlowHTTP:    dnsclient.NewSafeHTTPClientWithTimeout(75 * time.Second),
		RDAPHTTP:    dnsclient.NewRDAPHTTPClient(),
		IANARDAPMap: make(map[string][]string),
		Telemetry:   telemetry.NewRegistry(),
		RDAPCache:   telemetry.NewTTLCache[map[string]any]("rdap_test", 100, 1*time.Hour),
	}
}

func TestIsValidRDAPEndpoint(t *testing.T) {
	tests := []struct {
		endpoint string
		valid    bool
	}{
		{"https://rdap.verisign.com/com/v1/", true},
		{"https://rdap.org/", true},
		{"https://rdap.centralnic.com/tech/", true},
		{"http://rdap.verisign.com/com/v1/", false},
		{"ftp://rdap.example.com/", false},
		{"", false},
		{"rdap.verisign.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.endpoint, func(t *testing.T) {
			got := isValidRDAPEndpoint(tt.endpoint)
			if got != tt.valid {
				t.Errorf("isValidRDAPEndpoint(%q) = %v, want %v", tt.endpoint, got, tt.valid)
			}
		})
	}
}

func TestBuildRDAPEndpoints_AlwaysIncludesFallback(t *testing.T) {
	a := newTestAnalyzer()

	endpoints := a.buildRDAPEndpoints("nonexistenttld12345")
	if len(endpoints) == 0 {
		t.Fatal("expected at least rdap.org fallback")
	}
	last := endpoints[len(endpoints)-1]
	if last != "https://rdap.org/" {
		t.Errorf("last endpoint should be rdap.org fallback, got %q", last)
	}
}

func TestBuildRDAPEndpoints_KnownTLD(t *testing.T) {
	a := newTestAnalyzer()

	endpoints := a.buildRDAPEndpoints("com")
	if len(endpoints) < 1 {
		t.Fatal("expected at least one endpoint for .com")
	}
	if endpoints[0] != "https://rdap.verisign.com/com/v1/" {
		t.Errorf("first .com endpoint should be VeriSign, got %q", endpoints[0])
	}
}

func TestBuildRDAPEndpoints_Deduplicates(t *testing.T) {
	a := newTestAnalyzer()
	a.IANARDAPMap["com"] = []string{"https://rdap.verisign.com/com/v1/", "https://rdap.extra.example.com/"}

	endpoints := a.buildRDAPEndpoints("com")
	seen := make(map[string]int)
	for _, ep := range endpoints {
		seen[ep]++
	}
	for ep, count := range seen {
		if count > 1 {
			t.Errorf("endpoint %q appears %d times, should be deduplicated", ep, count)
		}
	}
}

func TestBuildRDAPEndpoints_RejectsHTTP(t *testing.T) {
	a := newTestAnalyzer()
	a.IANARDAPMap["badtld"] = []string{"http://insecure-rdap.example.com/"}

	endpoints := a.buildRDAPEndpoints("badtld")
	for _, ep := range endpoints {
		if ep == "http://insecure-rdap.example.com/" {
			t.Error("HTTP endpoint should be rejected, but was included")
		}
	}
}

func TestRDAPLookup_CancelledContext(t *testing.T) {
	a := newTestAnalyzer()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := a.rdapLookup(ctx, "example.com")
	if result != nil {
		t.Error("expected nil result for cancelled context")
	}
}

func TestTryRDAPEndpointWithRetry_CancelledContext(t *testing.T) {
	a := newTestAnalyzer()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := a.tryRDAPEndpointWithRetry(ctx, "example.com", "https://rdap.verisign.com/com/v1/", "rdap:com", 1, 1)
	if result != nil {
		t.Error("expected nil result for cancelled context in retry")
	}
}
