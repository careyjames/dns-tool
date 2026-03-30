package analyzer

import (
	"encoding/json"
	"testing"
)

func TestParseTestSSLJSON_BasicProtocols(t *testing.T) {
	findings := []TestSSLFinding{
		{ID: "tls1_3", Severity: "OK", Finding: "offered (OK)"},
		{ID: "tls1_2", Severity: "OK", Finding: "offered (OK)"},
		{ID: "tls1_1", Severity: "LOW", Finding: "not offered"},
		{ID: "tls1", Severity: "LOW", Finding: "not offered"},
		{ID: "sslv3", Severity: "OK", Finding: "not offered (OK)"},
		{ID: "sslv2", Severity: "OK", Finding: "not offered (OK)"},
	}
	data, _ := json.Marshal(findings)
	result, err := ParseTestSSLJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.TLS13Supported {
		t.Error("expected TLS 1.3 supported")
	}
	if !result.TLS12Supported {
		t.Error("expected TLS 1.2 supported")
	}
	if result.TLS11Supported {
		t.Error("expected TLS 1.1 not supported")
	}
	if result.TLS10Supported {
		t.Error("expected TLS 1.0 not supported")
	}
	if result.SSL3Supported {
		t.Error("expected SSLv3 not supported")
	}
	if result.SSL2Supported {
		t.Error("expected SSLv2 not supported")
	}
	if result.OverallRating != "good" {
		t.Errorf("expected overall rating 'good', got %q", result.OverallRating)
	}
}

func TestParseTestSSLJSON_Vulnerabilities(t *testing.T) {
	findings := []TestSSLFinding{
		{ID: "tls1_3", Severity: "OK", Finding: "offered (OK)"},
		{ID: "tls1_2", Severity: "OK", Finding: "offered (OK)"},
		{ID: "heartbleed", Severity: "CRITICAL", Finding: "VULNERABLE (CVE-2014-0160)", CVE: "CVE-2014-0160"},
		{ID: "poodle_ssl", Severity: "HIGH", Finding: "VULNERABLE -- SSLv3 POODLE", CVE: "CVE-2014-3566"},
	}
	data, _ := json.Marshal(findings)
	result, err := ParseTestSSLJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.VulnIDs) != 2 {
		t.Errorf("expected 2 vulns, got %d", len(result.VulnIDs))
	}
	if result.OverallRating != "critical" {
		t.Errorf("expected 'critical' rating, got %q", result.OverallRating)
	}
}

func TestParseTestSSLJSON_DeprecatedProtocols(t *testing.T) {
	findings := []TestSSLFinding{
		{ID: "tls1_3", Severity: "OK", Finding: "offered (OK)"},
		{ID: "tls1_2", Severity: "OK", Finding: "offered (OK)"},
		{ID: "tls1_1", Severity: "LOW", Finding: "offered"},
		{ID: "tls1", Severity: "LOW", Finding: "offered"},
		{ID: "sslv3", Severity: "CRITICAL", Finding: "offered"},
	}
	data, _ := json.Marshal(findings)
	result, err := ParseTestSSLJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.TLS11Supported {
		t.Error("expected TLS 1.1 supported")
	}
	if !result.TLS10Supported {
		t.Error("expected TLS 1.0 supported")
	}
	if !result.SSL3Supported {
		t.Error("expected SSLv3 supported")
	}
	if result.OverallRating != "critical" {
		t.Errorf("expected 'critical' for SSLv3, got %q", result.OverallRating)
	}
	if len(result.Issues) < 3 {
		t.Errorf("expected at least 3 issues for deprecated protocols, got %d", len(result.Issues))
	}
}

func TestParseTestSSLJSON_CertInfo(t *testing.T) {
	findings := []TestSSLFinding{
		{ID: "cert_notAfter", Severity: "OK", Finding: "2026-12-31"},
		{ID: "cert_chain_of_trust", Severity: "OK", Finding: "passed"},
	}
	data, _ := json.Marshal(findings)
	result, err := ParseTestSSLJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.CertInfo) != 2 {
		t.Errorf("expected 2 cert findings, got %d", len(result.CertInfo))
	}
}

func TestParseTestSSLJSON_EmptyArray(t *testing.T) {
	result, err := ParseTestSSLJSON([]byte("[]"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.OverallRating != "warning" {
		t.Errorf("expected 'warning' for empty findings, got %q", result.OverallRating)
	}
}

func TestParseTestSSLJSON_InvalidJSON(t *testing.T) {
	_, err := ParseTestSSLJSON([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestComputeProbeConsensus_Unanimous(t *testing.T) {
	results := []map[string]any{
		{"status": "observed", "probe_verdict": "all_tls"},
		{"status": "observed", "probe_verdict": "all_tls"},
	}
	c := computeProbeConsensus(results)
	if c["agreement"] != "unanimous_tls" {
		t.Errorf("expected unanimous_tls, got %v", c["agreement"])
	}
}

func TestComputeProbeConsensus_Split(t *testing.T) {
	results := []map[string]any{
		{"status": "observed", "probe_verdict": "all_tls"},
		{"status": "observed", "probe_verdict": "partial_tls"},
	}
	c := computeProbeConsensus(results)
	if c["agreement"] != "split" {
		t.Errorf("expected split, got %v", c["agreement"])
	}
}

func TestComputeProbeConsensus_NoData(t *testing.T) {
	results := []map[string]any{
		{"status": "skipped"},
		{"status": "skipped"},
	}
	c := computeProbeConsensus(results)
	if c["agreement"] != "no_data" {
		t.Errorf("expected no_data, got %v", c["agreement"])
	}
}

func TestComputeProbeConsensus_Empty(t *testing.T) {
	c := computeProbeConsensus(nil)
	if c["agreement"] != "unknown" {
		t.Errorf("expected unknown, got %v", c["agreement"])
	}
}
