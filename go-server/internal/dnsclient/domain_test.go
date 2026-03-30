// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package dnsclient

import (
	"strings"
	"testing"
)

func TestValidateDomain_Basic(t *testing.T) {
	valid := []string{
		"example.com",
		"sub.example.com",
		"deep.sub.example.com",
		"ietf.org",
		"apple.com",
		"whitehouse.gov",
		"münchen.de",
		"nlnetlabs.nl",
		"a.b.c.d.e.f.g.example.com",
	}
	for _, d := range valid {
		if !ValidateDomain(d) {
			t.Errorf("expected valid: %s", d)
		}
	}

	nowValid := []string{
		"localhost",
		".example.com",
	}
	for _, d := range nowValid {
		if !ValidateDomain(d) {
			t.Errorf("expected valid (single-label TLD or leading-dot strip): %s", d)
		}
	}

	invalid := []string{
		"",
		"-example.com",
		"example..com",
	}
	for _, d := range invalid {
		if ValidateDomain(d) {
			t.Errorf("expected invalid: %s", d)
		}
	}
}

func TestValidateDomain_LabelDepth(t *testing.T) {
	if ValidateDomain("a.b.c.d.e.f.g.h.i.j.k.example.com") {
		t.Error("expected >10 labels to be rejected")
	}
	if !ValidateDomain("a.b.c.d.e.f.g.h.example.com") {
		t.Error("expected 10 labels to be accepted")
	}
}

func TestValidateDomain_ScannerDomainsAccepted(t *testing.T) {
	scannerDomains := []string{
		"3bb082.2351459410758711703.103661431.ssrf02.ssrf.us3.qualysperiscope.com",
		"test.oastify.com",
		"abc123.burpcollaborator.net",
	}
	for _, d := range scannerDomains {
		if !ValidateDomain(d) {
			t.Errorf("scanner domain should be accepted for analysis: %s", d)
		}
	}
}

func TestValidateDomain_LegitDomains(t *testing.T) {
	legit := []string{
		"apple.com",
		"westcappowerequipment.com",
		"sportcommunities.group",
		"imobr-bucuresti.ro",
		"nsfnow.com",
		"red.com",
		"xn--mnchen-3ya.de",
		"cdn-123456.example.com",
		"mail01.example.com",
	}
	for _, d := range legit {
		if !ValidateDomain(d) {
			t.Errorf("false positive — should be valid: %s", d)
		}
	}
}

func TestValidateDomain_EdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   bool
	}{
		{"trailing dot stripped", "example.com.", true},
		{"spaces only", "   ", false},
		{"single dot", ".", false},
		{"only dots", "...", false},
		{"too long domain", strings.Repeat("a", 254), false},
		{"label exactly 63 chars", strings.Repeat("a", 63) + ".com", true},
		{"label 64 chars too long", strings.Repeat("a", 64) + ".com", false},
		{"trailing hyphen label", "example-.com", false},
		{"numeric TLD rejected", "example.123", false},
		{"single char TLD rejected", "example.a", false},
		{"underscore rejected", "ex_ample.com", false},
		{"space in domain", "exa mple.com", false},
		{"IP address numeric TLD", "192.168.1.1", false},
		{"max depth exactly 10", "a.b.c.d.e.f.g.h.i.com", true},
		{"exceeds max depth 11", "a.b.c.d.e.f.g.h.i.j.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateDomain(tt.domain)
			if got != tt.want {
				t.Errorf("ValidateDomain(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

func TestIsTLDInput_Extra(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   bool
	}{
		{"spaces only", "   ", false},
		{"long TLD", "museum", true},
		{"punycode TLD xn--lgbbat1ad8j", "xn--lgbbat1ad8j", true},
		{"only dots stripped to empty", "...", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsTLDInput(tt.domain)
			if got != tt.want {
				t.Errorf("IsTLDInput(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

func TestGetTLD_Extra(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   string
	}{
		{"deep subdomain", "a.b.c.example.net", "net"},
		{"mixed case", "Example.CoM", "com"},
		{"trailing dot gives empty", "example.com.", ""},
		{"TLD only", "com", "com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetTLD(tt.domain)
			if got != tt.want {
				t.Errorf("GetTLD(%q) = %q, want %q", tt.domain, got, tt.want)
			}
		})
	}
}

func TestDomainToASCII_Extra(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		want    string
		wantErr bool
	}{
		{"empty label passes through", "example..com", "example..com", false},
		{"leading hyphen error", "-example.com", "", true},
		{"trailing hyphen error", "example-.com", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DomainToASCII(tt.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("DomainToASCII(%q) error = %v, wantErr %v", tt.domain, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("DomainToASCII(%q) = %q, want %q", tt.domain, got, tt.want)
			}
		})
	}
}

func TestValidateLabels_Extra(t *testing.T) {
	tests := []struct {
		name   string
		labels []string
		want   bool
	}{
		{"underscore rejected", []string{"under_score"}, false},
		{"space in label rejected", []string{"has space"}, false},
		{"valid with hyphens", []string{"my-site", "com"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validateLabels(tt.labels)
			if got != tt.want {
				t.Errorf("validateLabels(%v) = %v, want %v", tt.labels, got, tt.want)
			}
		})
	}
}

func TestValidateTLD_Extra(t *testing.T) {
	tests := []struct {
		name string
		tld  string
		want bool
	}{
		{"digit in TLD rejected", "c0m", false},
		{"long TLD valid", "museum", true},
		{"hyphen in TLD rejected", "co-m", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validateTLD(tt.tld)
			if got != tt.want {
				t.Errorf("validateTLD(%q) = %v, want %v", tt.tld, got, tt.want)
			}
		})
	}
}
