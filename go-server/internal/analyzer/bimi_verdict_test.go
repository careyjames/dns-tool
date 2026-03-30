package analyzer

import (
	"strings"
	"testing"
)

func TestBuildBIMIMessageLogoOnly(t *testing.T) {
	logo := "https://example.com/logo.svg"
	status, msg := buildBIMIMessage(&logo, nil, map[string]any{mapKeyValid: true}, map[string]any{})
	if status != "success" {
		t.Errorf("expected success, got %q", status)
	}
	if !strings.Contains(msg, "BIMI configured") {
		t.Errorf("expected 'BIMI configured', got %q", msg)
	}
	if !strings.Contains(msg, "VMC recommended") {
		t.Errorf("expected VMC recommendation, got %q", msg)
	}
}

func TestBuildBIMIMessageVMCValidWithIssuer(t *testing.T) {
	logo := "https://example.com/logo.svg"
	vmc := "https://example.com/vmc.pem"
	status, msg := buildBIMIMessage(&logo, &vmc,
		map[string]any{mapKeyValid: true},
		map[string]any{mapKeyValid: true, mapKeyIssuer: "Entrust"})
	if status != "success" {
		t.Errorf("expected success, got %q", status)
	}
	if !strings.Contains(msg, "Entrust") {
		t.Errorf("expected issuer in message, got %q", msg)
	}
}

func TestBuildBIMIMessageVMCInvalidError(t *testing.T) {
	logo := "https://example.com/logo.svg"
	vmc := "https://example.com/vmc.pem"
	status, msg := buildBIMIMessage(&logo, &vmc,
		map[string]any{mapKeyValid: true},
		map[string]any{mapKeyValid: false, mapKeyError: "expired cert"})
	if status != mapKeyWarning {
		t.Errorf("expected warning, got %q", status)
	}
	if !strings.Contains(msg, "VMC issue") {
		t.Errorf("expected VMC issue note, got %q", msg)
	}
}

func TestBuildBIMIMessageNoLogoNoVMC(t *testing.T) {
	status, msg := buildBIMIMessage(nil, nil, map[string]any{}, map[string]any{})
	if status != mapKeyWarning {
		t.Errorf("expected warning, got %q", status)
	}
	if !strings.Contains(msg, "missing logo") {
		t.Errorf("expected missing logo note, got %q", msg)
	}
}

func TestBuildBIMIMessageLogoInvalid(t *testing.T) {
	logo := "https://example.com/logo.png"
	status, msg := buildBIMIMessage(&logo, nil,
		map[string]any{mapKeyValid: false, mapKeyError: "Not SVG format"},
		map[string]any{})
	if status != mapKeyWarning {
		t.Errorf("expected warning, got %q", status)
	}
	if !strings.Contains(msg, "Logo issue") {
		t.Errorf("expected logo issue in message, got %q", msg)
	}
}

func TestFilterBIMIRecordsCaseVariants(t *testing.T) {
	records := []string{
		"v=bimi1; l=https://a.com/logo.svg",
		"V=BIMI1; l=https://b.com/logo.svg",
		"v=BIMI1; L=https://c.com/logo.svg",
	}
	got := filterBIMIRecords(records)
	if len(got) != 3 {
		t.Errorf("expected 3, got %d", len(got))
	}
}

func TestFilterBIMIRecordsNonBIMI(t *testing.T) {
	records := []string{
		"v=DMARC1; p=none",
		"v=spf1 include:example.com ~all",
		"some random text",
	}
	got := filterBIMIRecords(records)
	if len(got) != 0 {
		t.Errorf("expected 0, got %d", len(got))
	}
}

func TestExtractBIMIURLsLogoValue(t *testing.T) {
	logo, _ := extractBIMIURLs("v=BIMI1; l=https://example.com/brand.svg")
	if logo == nil {
		t.Fatal("expected logo URL")
	}
	if *logo != "https://example.com/brand.svg" {
		t.Errorf("logo = %q", *logo)
	}
}

func TestExtractBIMIURLsVMCValue(t *testing.T) {
	_, vmc := extractBIMIURLs("v=BIMI1; a=https://example.com/cert.pem")
	if vmc == nil {
		t.Fatal("expected VMC URL")
	}
	if *vmc != "https://example.com/cert.pem" {
		t.Errorf("vmc = %q", *vmc)
	}
}

func TestClassifyBIMILogoFormatImageJPEG(t *testing.T) {
	result := map[string]any{mapKeyValid: false, mapKeyFormat: nil, mapKeyError: nil}
	classifyBIMILogoFormat("image/jpeg", []byte{}, result)
	if result[mapKeyValid] != false {
		t.Error("expected invalid for image/jpeg (BIMI requires SVG)")
	}
	if result[mapKeyFormat] != "JPEG" {
		t.Errorf("format = %v, want JPEG", result[mapKeyFormat])
	}
}

func TestClassifyBIMILogoFormatSVGInBody(t *testing.T) {
	result := map[string]any{mapKeyValid: false, mapKeyFormat: nil, mapKeyError: nil}
	body := []byte(`<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"></svg>`)
	classifyBIMILogoFormat("application/octet-stream", body, result)
	if result[mapKeyValid] != true {
		t.Error("expected valid when SVG detected in body")
	}
	if result[mapKeyFormat] != "SVG" {
		t.Errorf("format = %v, want SVG", result[mapKeyFormat])
	}
}

func TestClassifyBIMILogoFormatNotSVG(t *testing.T) {
	result := map[string]any{mapKeyValid: false, mapKeyFormat: nil, mapKeyError: nil}
	classifyBIMILogoFormat("text/plain", []byte("just text"), result)
	if result[mapKeyValid] != false {
		t.Error("expected invalid for plain text")
	}
	errStr, _ := result[mapKeyError].(string)
	if errStr == "" {
		t.Error("expected non-empty error for non-SVG content")
	}
}

func TestClassifyVMCCertificateValid(t *testing.T) {
	result := map[string]any{mapKeyValid: false, mapKeyIssuer: nil, "subject": nil, mapKeyError: nil}
	classifyVMCCertificate("-----BEGIN CERTIFICATE-----\nSomeDataDigiCertMore\n-----END CERTIFICATE-----", result)
	if result[mapKeyValid] != true {
		t.Error("expected valid")
	}
	if result[mapKeyIssuer] != "DigiCert" {
		t.Errorf("issuer = %v", result[mapKeyIssuer])
	}
}

func TestClassifyVMCCertificateNoBeginMarker(t *testing.T) {
	result := map[string]any{mapKeyValid: false, mapKeyIssuer: nil, "subject": nil, mapKeyError: nil}
	classifyVMCCertificate("random data without cert markers", result)
	if result[mapKeyValid] != false {
		t.Error("expected invalid")
	}
	if result[mapKeyError] != "Invalid certificate format" {
		t.Errorf("error = %v", result[mapKeyError])
	}
}

func TestAppendBIMILogoIssueNoError(t *testing.T) {
	logo := "https://example.com/logo.svg"
	status := "success"
	parts := appendBIMILogoIssue(&logo, map[string]any{mapKeyValid: false, mapKeyError: ""}, &status, []string{})
	if status != "success" {
		t.Error("expected status unchanged when error is empty string")
	}
	if len(parts) != 0 {
		t.Errorf("expected 0 parts, got %d", len(parts))
	}
}

func TestAppendBIMILogoIssueNilLogo(t *testing.T) {
	status := "success"
	parts := appendBIMILogoIssue(nil, map[string]any{mapKeyValid: false, mapKeyError: "test"}, &status, []string{})
	if status != "success" {
		t.Error("expected status unchanged for nil logo")
	}
	if len(parts) != 0 {
		t.Errorf("expected 0 parts, got %d", len(parts))
	}
}
