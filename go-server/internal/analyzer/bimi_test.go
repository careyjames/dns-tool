package analyzer

import (
	"testing"
)

func TestFilterBIMIRecords(t *testing.T) {
	tests := []struct {
		name    string
		records []string
		want    int
	}{
		{"valid", []string{"v=BIMI1; l=https://example.com/logo.svg"}, 1},
		{"case insensitive", []string{"V=BIMI1; l=https://example.com/logo.svg"}, 1},
		{"invalid prefix", []string{"v=spf1 include:example.com"}, 0},
		{"mixed", []string{"v=BIMI1; l=https://a.com/logo.svg", "v=spf1"}, 1},
		{"empty", []string{}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterBIMIRecords(tt.records)
			if len(got) != tt.want {
				t.Errorf("filterBIMIRecords() len = %d, want %d", len(got), tt.want)
			}
		})
	}
}

func TestExtractBIMIURLs(t *testing.T) {
	tests := []struct {
		name     string
		record   string
		wantLogo bool
		wantVMC  bool
	}{
		{"logo and vmc", "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem", true, true},
		{"logo only", "v=BIMI1; l=https://example.com/logo.svg", true, false},
		{"vmc only", "v=BIMI1; a=https://example.com/vmc.pem", false, true},
		{"neither", "v=BIMI1;", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logo, vmc := extractBIMIURLs(tt.record)
			if (logo != nil) != tt.wantLogo {
				t.Errorf("logo nil = %v, want present = %v", logo == nil, tt.wantLogo)
			}
			if (vmc != nil) != tt.wantVMC {
				t.Errorf("vmc nil = %v, want present = %v", vmc == nil, tt.wantVMC)
			}
		})
	}
}

func TestBuildBIMIMessage(t *testing.T) {
	logoURL := "https://example.com/logo.svg"
	vmcURL := "https://example.com/vmc.pem"

	status, msg := buildBIMIMessage(&logoURL, &vmcURL, map[string]any{mapKeyValid: true}, map[string]any{mapKeyValid: true, mapKeyIssuer: "DigiCert"})
	if status != "success" {
		t.Errorf("expected success, got %q", status)
	}
	if msg == "" {
		t.Error("expected non-empty message")
	}

	status2, _ := buildBIMIMessage(&logoURL, nil, map[string]any{mapKeyValid: true}, map[string]any{})
	if status2 != "success" {
		t.Errorf("expected success, got %q", status2)
	}

	status3, _ := buildBIMIMessage(nil, nil, map[string]any{}, map[string]any{})
	if status3 != mapKeyWarning {
		t.Errorf("expected warning, got %q", status3)
	}
}

func TestBuildBIMICoreMessage(t *testing.T) {
	vmcURL := "https://example.com/vmc.pem"

	status, parts := buildBIMICoreMessage(nil, &vmcURL, map[string]any{}, map[string]any{mapKeyValid: false, mapKeyError: "cert error"})
	if status != mapKeyWarning {
		t.Errorf("expected warning, got %q", status)
	}
	if len(parts) == 0 {
		t.Error("expected parts")
	}
}

func TestAppendBIMILogoIssue(t *testing.T) {
	logoURL := "https://example.com/logo.svg"
	status := "success"

	parts := appendBIMILogoIssue(&logoURL, map[string]any{mapKeyValid: false, mapKeyError: "bad format"}, &status, []string{"existing"})
	if status != mapKeyWarning {
		t.Error("expected status changed to warning")
	}
	if len(parts) != 2 {
		t.Errorf("expected 2 parts, got %d", len(parts))
	}

	status2 := "success"
	parts2 := appendBIMILogoIssue(&logoURL, map[string]any{mapKeyValid: true}, &status2, []string{"existing"})
	if status2 != "success" {
		t.Error("expected status unchanged")
	}
	if len(parts2) != 1 {
		t.Errorf("expected 1 part, got %d", len(parts2))
	}
}

func TestClassifyBIMILogoFormat(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        []byte
		wantValid   bool
		wantFormat  string
	}{
		{"svg content type", "image/svg+xml", []byte("<svg></svg>"), true, "SVG"},
		{"image png", "image/png", []byte{}, false, "PNG"},
		{"svg in body", "text/html", []byte("<svg xmlns='...'></svg>"), true, "SVG"},
		{"not svg", "text/plain", []byte("hello world"), false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := map[string]any{mapKeyValid: false, mapKeyFormat: nil, mapKeyError: nil}
			classifyBIMILogoFormat(tt.contentType, tt.body, result)
			if result[mapKeyValid] != tt.wantValid {
				t.Errorf("valid = %v, want %v", result[mapKeyValid], tt.wantValid)
			}
			if tt.wantFormat != "" && result[mapKeyFormat] != tt.wantFormat {
				t.Errorf("format = %v, want %v", result[mapKeyFormat], tt.wantFormat)
			}
		})
	}
}

func TestClassifyVMCCertificate(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		wantValid  bool
		wantIssuer string
	}{
		{"digicert", "-----BEGIN CERTIFICATE-----\nDigiCert\n-----END CERTIFICATE-----", true, "DigiCert"},
		{"entrust", "-----BEGIN CERTIFICATE-----\nEntrust\n-----END CERTIFICATE-----", true, "Entrust"},
		{"globalsign", "-----BEGIN CERTIFICATE-----\nGlobalSign\n-----END CERTIFICATE-----", true, "GlobalSign"},
		{"unknown ca", "-----BEGIN CERTIFICATE-----\nSomethingElse\n-----END CERTIFICATE-----", true, "Verified CA"},
		{"invalid", "not a certificate", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := map[string]any{mapKeyValid: false, mapKeyIssuer: nil, "subject": nil, mapKeyError: nil}
			classifyVMCCertificate(tt.content, result)
			if result[mapKeyValid] != tt.wantValid {
				t.Errorf("valid = %v, want %v", result[mapKeyValid], tt.wantValid)
			}
			if tt.wantValid && result[mapKeyIssuer] != tt.wantIssuer {
				t.Errorf("issuer = %v, want %v", result[mapKeyIssuer], tt.wantIssuer)
			}
		})
	}
}
