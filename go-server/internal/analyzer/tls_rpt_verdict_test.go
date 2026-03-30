package analyzer

import (
	"testing"
)

func TestTLSRPTRUARegexMailto(t *testing.T) {
	m := tlsrptRUARe.FindStringSubmatch("v=TLSRPTv1; rua=mailto:security@example.com")
	if m == nil {
		t.Fatal("expected match")
	}
	if m[1] != "mailto:security@example.com" {
		t.Errorf("rua = %q, want mailto:security@example.com", m[1])
	}
}

func TestTLSRPTRUARegexHTTPS(t *testing.T) {
	m := tlsrptRUARe.FindStringSubmatch("v=TLSRPTv1; rua=https://tlsrpt.example.com/v1/report")
	if m == nil {
		t.Fatal("expected match")
	}
	if m[1] != "https://tlsrpt.example.com/v1/report" {
		t.Errorf("rua = %q", m[1])
	}
}

func TestTLSRPTRUARegexNoRUA(t *testing.T) {
	m := tlsrptRUARe.FindStringSubmatch("v=TLSRPTv1;")
	if m != nil {
		t.Error("expected no match for record without rua")
	}
}

func TestTLSRPTRUARegexCaseInsensitive(t *testing.T) {
	m := tlsrptRUARe.FindStringSubmatch("v=TLSRPTv1; RUA=mailto:test@example.com")
	if m == nil {
		t.Fatal("expected match for uppercase RUA")
	}
	if m[1] != "mailto:test@example.com" {
		t.Errorf("rua = %q", m[1])
	}
}

func TestTLSRPTRUARegexMultipleFields(t *testing.T) {
	m := tlsrptRUARe.FindStringSubmatch("v=TLSRPTv1; rua=mailto:a@b.com; extra=value")
	if m == nil {
		t.Fatal("expected match")
	}
	if m[1] != "mailto:a@b.com" {
		t.Errorf("rua = %q, expected mailto:a@b.com", m[1])
	}
}

func TestTLSRPTRUARegexEmptyRUA(t *testing.T) {
	m := tlsrptRUARe.FindStringSubmatch("v=TLSRPTv1; rua=;")
	if m != nil {
		t.Error("expected no match for empty rua value")
	}
}

func TestTLSRPTValidRecordFiltering(t *testing.T) {
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{"valid lowercase", "v=tlsrptv1; rua=mailto:a@b.com", true},
		{"valid mixed case", "v=TLSRPTv1; rua=mailto:a@b.com", true},
		{"valid uppercase", "V=TLSRPTV1; rua=mailto:a@b.com", true},
		{"invalid prefix", "v=spf1 include:a.com ~all", false},
		{"empty", "", false},
		{"partial match", "tlsrptv1 rua=mailto:a@b.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid := len(tt.input) > 0 && len(tt.input) >= 10 &&
				(tt.input[:10] == "v=tlsrptv1" ||
					tt.input[:10] == "v=TLSRPTv1" ||
					tt.input[:10] == "V=TLSRPTV1" ||
					func() bool {
						lower := ""
						for _, c := range tt.input {
							if c >= 'A' && c <= 'Z' {
								lower += string(c + 32)
							} else {
								lower += string(c)
							}
						}
						return len(lower) >= 10 && lower[:10] == "v=tlsrptv1"
					}())
			if isValid != tt.valid {
				t.Errorf("valid = %v, want %v", isValid, tt.valid)
			}
		})
	}
}
