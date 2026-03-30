package analyzer

import (
	"testing"
)

func TestHasHTTP3(t *testing.T) {
	tests := []struct {
		name     string
		alpnList []string
		want     bool
	}{
		{"h3 present", []string{"h2", "h3"}, true},
		{"h3 draft", []string{"h3-29"}, true},
		{"no h3", []string{"h2", "http/1.1"}, false},
		{"empty", []string{}, false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasHTTP3(tt.alpnList)
			if got != tt.want {
				t.Errorf("hasHTTP3(%v) = %v, want %v", tt.alpnList, got, tt.want)
			}
		})
	}
}

func TestUpdateSVCBCapabilities(t *testing.T) {
	tests := []struct {
		name      string
		parsed    []map[string]any
		wantHTTP3 bool
		wantECH   bool
	}{
		{
			"http3 and ech",
			[]map[string]any{{"http3": true, "ech": true}},
			true, true,
		},
		{
			"http3 only",
			[]map[string]any{{"http3": true}},
			true, false,
		},
		{
			"ech only",
			[]map[string]any{{"ech": true}},
			false, true,
		},
		{
			"neither",
			[]map[string]any{{"priority": 1}},
			false, false,
		},
		{
			"empty",
			[]map[string]any{},
			false, false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := map[string]any{
				"supports_http3": false,
				"supports_ech":   false,
			}
			updateSVCBCapabilities(result, tt.parsed)
			if result["supports_http3"] != tt.wantHTTP3 {
				t.Errorf("supports_http3 = %v, want %v", result["supports_http3"], tt.wantHTTP3)
			}
			if result["supports_ech"] != tt.wantECH {
				t.Errorf("supports_ech = %v, want %v", result["supports_ech"], tt.wantECH)
			}
		})
	}
}

func TestBuildHTTPSMessage(t *testing.T) {
	tests := []struct {
		name   string
		result map[string]any
		want   string
	}{
		{
			"https only",
			map[string]any{"has_https": true, "supports_http3": false, "supports_ech": false},
			"HTTPS records found",
		},
		{
			"https and http3",
			map[string]any{"has_https": true, "supports_http3": true, "supports_ech": false},
			"HTTPS records found, HTTP/3 supported",
		},
		{
			"all features",
			map[string]any{"has_https": true, "supports_http3": true, "supports_ech": true},
			"HTTPS records found, HTTP/3 supported, ECH (Encrypted Client Hello) enabled",
		},
		{
			"svcb only",
			map[string]any{"has_https": false, "supports_http3": false, "supports_ech": false},
			"SVCB records found",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildHTTPSMessage(tt.result)
			if got != tt.want {
				t.Errorf("buildHTTPSMessage() = %q, want %q", got, tt.want)
			}
		})
	}
}
