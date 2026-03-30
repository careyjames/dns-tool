package dnsclient

import (
	"strings"
	"testing"
)

func TestValidateDomain_Unicode(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   bool
	}{
		{"german umlaut", "münchen.de", true},
		{"chinese domain", "中文.com", true},
		{"arabic domain", "مثال.com", true},
		{"japanese domain", "日本語.jp", true},
		{"punycode direct", "xn--mnchen-3ya.de", true},
		{"punycode with subdomain", "sub.xn--mnchen-3ya.de", true},
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

func TestValidateDomain_BoundaryLengths(t *testing.T) {
	exactly253 := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + "." + strings.Repeat("d", 60) + ".com"
	if len(exactly253) > 253 && ValidateDomain(exactly253) {
		t.Error("expected rejection for domain > 253 chars")
	}

	shortDomain := "a.co"
	if !ValidateDomain(shortDomain) {
		t.Errorf("expected valid for %q", shortDomain)
	}
}

func TestValidateDomain_SpecialCharacters(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   bool
	}{
		{"at sign", "user@example.com", false},
		{"exclamation", "test!.com", false},
		{"hash", "test#.com", false},
		{"percent", "test%.com", false},
		{"ampersand", "test&.com", false},
		{"asterisk", "test*.com", false},
		{"plus", "test+.com", false},
		{"equals", "test=.com", false},
		{"slash", "test/.com", false},
		{"backslash", "test\\.com", false},
		{"pipe", "test|.com", false},
		{"bracket", "test[.com", false},
		{"comma", "test,.com", false},
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

func TestDomainToASCII_VariousInputs(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"simple", "example.com", "example.com", false},
		{"uppercase", "EXAMPLE.COM", "example.com", false},
		{"with trailing dot", "example.com.", "example.com", false},
		{"with spaces", "  example.com  ", "example.com", false},
		{"empty", "", "", false},
		{"punycode", "münchen.de", "xn--mnchen-3ya.de", false},
		{"subdomain", "sub.example.com", "sub.example.com", false},
		{"deep subdomain", "a.b.c.example.com", "a.b.c.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DomainToASCII(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("DomainToASCII(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("DomainToASCII(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsTLDInput_Comprehensive(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"com", "com", true},
		{"org", "org", true},
		{"net", "net", true},
		{"de", "de", true},
		{"museum", "museum", true},
		{"with leading dot", ".com", true},
		{"with trailing dot", "com.", true},
		{"with both dots", ".com.", true},
		{"subdomain", "example.com", false},
		{"empty", "", false},
		{"numeric", "123", false},
		{"single char", "a", false},
		{"punycode TLD", "xn--lgbbat1ad8j", true},
		{"with space", " com ", true},
		{"only spaces", "   ", false},
		{"only dots", "...", false},
		{"dot only", ".", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsTLDInput(tt.input)
			if got != tt.want {
				t.Errorf("IsTLDInput(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestGetTLD_MoreCases(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   string
	}{
		{"simple com", "example.com", "com"},
		{"deep subdomain", "a.b.c.d.e.example.com", "com"},
		{"uppercase", "EXAMPLE.COM", "com"},
		{"mixed case", "Example.Org", "org"},
		{"empty", "", ""},
		{"single label", "localhost", "localhost"},
		{"with trailing dot", "example.com.", ""},
		{"co.uk style", "example.co.uk", "uk"},
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

func TestValidateLabels_MoreEdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		labels []string
		want   bool
	}{
		{"single valid label", []string{"example"}, true},
		{"numeric label", []string{"123"}, true},
		{"mixed alphanumeric", []string{"abc123"}, true},
		{"with hyphen middle", []string{"my-example"}, true},
		{"leading hyphen", []string{"-bad"}, false},
		{"trailing hyphen", []string{"bad-"}, false},
		{"empty label", []string{""}, false},
		{"underscore", []string{"under_score"}, false},
		{"at sign", []string{"at@sign"}, false},
		{"63 char exactly", []string{strings.Repeat("x", 63)}, true},
		{"64 char too long", []string{strings.Repeat("x", 64)}, false},
		{"multiple valid", []string{"sub", "example", "com"}, true},
		{"one invalid among valid", []string{"sub", "-bad", "com"}, false},
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

func TestValidateTLD_MoreCases(t *testing.T) {
	tests := []struct {
		name string
		tld  string
		want bool
	}{
		{"com", "com", true},
		{"org", "org", true},
		{"de", "de", true},
		{"museum", "museum", true},
		{"single char", "a", false},
		{"empty", "", false},
		{"with digit", "c0m", false},
		{"with hyphen", "co-m", false},
		{"all digits", "123", false},
		{"punycode", "xn--mnchen-3ya", true},
		{"xn-- prefix", "xn--lgbbat1ad8j", true},
		{"long TLD", "technology", true},
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
