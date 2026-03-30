package analyzer

import (
	"testing"
)

func TestTLSRPTRUARegex(t *testing.T) {
	tests := []struct {
		name   string
		record string
		want   bool
	}{
		{"with rua", "v=TLSRPTv1; rua=mailto:reports@example.com", true},
		{"no rua", "v=TLSRPTv1;", false},
		{"case insensitive", "v=TLSRPTv1; RUA=mailto:reports@example.com", true},
		{"https rua", "v=TLSRPTv1; rua=https://example.com/report", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := tlsrptRUARe.FindStringSubmatch(tt.record)
			if (m != nil) != tt.want {
				t.Errorf("match = %v, want %v", m != nil, tt.want)
			}
		})
	}
}

func TestTLSRPTRUAExtraction(t *testing.T) {
	m := tlsrptRUARe.FindStringSubmatch("v=TLSRPTv1; rua=mailto:tls-reports@example.com")
	if m == nil || m[1] != "mailto:tls-reports@example.com" {
		t.Errorf("expected mailto:tls-reports@example.com, got %v", m)
	}
}
