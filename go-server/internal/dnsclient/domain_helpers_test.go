// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package dnsclient

import "testing"

func TestDomainToASCII(t *testing.T) {
	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{"example.com", "example.com", false},
		{"EXAMPLE.COM", "example.com", false},
		{"münchen.de", "xn--mnchen-3ya.de", false},
		{"example.com.", "example.com", false},
		{" example.com ", "example.com", false},
		{"sub.example.com", "sub.example.com", false},
		{"", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
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

func TestIsTLDInput(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"com", true},
		{"org", true},
		{"de", true},
		{"example.com", false},
		{"sub.example.com", false},
		{"", false},
		{".", false},
		{".com", true},
		{"com.", true},
		{"123", false},
		{"xn--mnchen-3ya", true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := IsTLDInput(tt.input)
			if got != tt.want {
				t.Errorf("IsTLDInput(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestGetTLD(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com", "com"},
		{"sub.example.org", "org"},
		{"deep.sub.example.co.uk", "uk"},
		{"example.COM", "com"},
		{"localhost", "localhost"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := GetTLD(tt.input)
			if got != tt.want {
				t.Errorf("GetTLD(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateLabels(t *testing.T) {
	tests := []struct {
		name   string
		labels []string
		want   bool
	}{
		{"valid", []string{"example", "com"}, true},
		{"empty_label", []string{"example", "", "com"}, false},
		{"leading_hyphen", []string{"-example", "com"}, false},
		{"trailing_hyphen", []string{"example-", "com"}, false},
		{"with_numbers", []string{"test123", "com"}, true},
		{"long_label", []string{string(make([]byte, 64)), "com"}, false},
		{"63_char_label", []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "com"}, true},
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

func TestValidateTLD(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"com", true},
		{"org", true},
		{"de", true},
		{"xn--mnchen-3ya", true},
		{"123", false},
		{"a", false},
		{"", false},
		{"c-m", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := validateTLD(tt.input)
			if got != tt.want {
				t.Errorf("validateTLD(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
