package analyzer

import (
	"testing"
)

func TestIsValidFQDNUnder(t *testing.T) {
	tests := []struct {
		fqdn   string
		domain string
		valid  bool
	}{
		{"mail.example.com", "example.com", true},
		{"sub.mail.example.com", "example.com", true},
		{"a.example.com", "example.com", true},
		{"example.com", "example.com", false},
		{"evil.com", "example.com", false},
		{"notexample.com", "example.com", false},
		{"*.example.com", "example.com", false},
		{"", "example.com", false},
		{"mail.example.com", "", false},
		{"  mail.example.com  ", "example.com", true},
		{"MAIL.EXAMPLE.COM", "example.com", true},
		{"-invalid.example.com", "example.com", false},
		{"valid-sub.example.com", "example.com", true},
		{"123.example.com", "example.com", true},
		{"a" + string(make([]byte, 70)) + ".example.com", "example.com", false},
	}
	for _, tt := range tests {
		got := isValidFQDNUnder(tt.fqdn, tt.domain)
		if got != tt.valid {
			t.Errorf("isValidFQDNUnder(%q, %q) = %v, want %v", tt.fqdn, tt.domain, got, tt.valid)
		}
	}
}

func TestValidDomainRe(t *testing.T) {
	tests := []struct {
		input string
		match bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"a.b.c.example.com", true},
		{"example", false},
		{"-bad.com", false},
		{"good-name.co.uk", true},
		{"123.456.com", true},
		{"", false},
	}
	for _, tt := range tests {
		got := validDomainRe.MatchString(tt.input)
		if got != tt.match {
			t.Errorf("validDomainRe.MatchString(%q) = %v, want %v", tt.input, got, tt.match)
		}
	}
}

func TestRunSubfinder_InvalidDomain(t *testing.T) {
	results := runSubfinder(t.Context(), "not a valid domain!!!")
	if len(results) != 0 {
		t.Errorf("expected nil/empty for invalid domain, got %v", results)
	}
}

func TestRunAmass_InvalidDomain(t *testing.T) {
	results := runAmass(t.Context(), "not a valid domain!!!")
	if len(results) != 0 {
		t.Errorf("expected nil/empty for invalid domain, got %v", results)
	}
}

func TestFetchHackerTarget_InvalidDomain(t *testing.T) {
	results := fetchHackerTarget(t.Context(), "not a valid domain!!!")
	if len(results) != 0 {
		t.Errorf("expected nil/empty for invalid domain, got %v", results)
	}
}
