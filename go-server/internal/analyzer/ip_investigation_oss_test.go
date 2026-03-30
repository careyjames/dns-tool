//go:build !intel

package analyzer

import (
	"context"
	"testing"
)

func TestFindSPFTXTRecord_OSS_ReturnsEmpty(t *testing.T) {
	got := findSPFTXTRecord([]string{"v=spf1 include:_spf.google.com ~all"})
	if got != "" {
		t.Errorf("OSS findSPFTXTRecord should return empty, got %q", got)
	}
}

func TestFindSPFTXTRecord_OSS_EmptyInput(t *testing.T) {
	got := findSPFTXTRecord(nil)
	if got != "" {
		t.Errorf("OSS findSPFTXTRecord(nil) should return empty, got %q", got)
	}
}

func TestCheckIPInSPFRecord_OSS_ReturnsFalse(t *testing.T) {
	got := checkIPInSPFRecord("v=spf1 ip4:1.2.3.4 ~all", "1.2.3.4")
	if got {
		t.Error("OSS checkIPInSPFRecord should return false")
	}
}

func TestCheckASNForCDNDirect_OSS_ReturnsFalse(t *testing.T) {
	provider, isCDN := checkASNForCDNDirect(map[string]any{"number": "AS13335"}, []string{"ptr.cloudflare.com"})
	if provider != "" {
		t.Errorf("OSS checkASNForCDNDirect provider = %q, want empty", provider)
	}
	if isCDN {
		t.Error("OSS checkASNForCDNDirect should return false")
	}
}

func TestClassifyOverall_OSS_ReturnsUnrelated(t *testing.T) {
	classification, summary := classifyOverall(
		[]map[string]any{{"classification": classDirectA}},
		[]map[string]any{},
		"",
		map[string]any{},
	)
	if classification != "Unrelated" {
		t.Errorf("OSS classifyOverall classification = %q, want 'Unrelated'", classification)
	}
	if summary != "" {
		t.Errorf("OSS classifyOverall summary = %q, want empty", summary)
	}
}

func TestFetchNeighborhoodDomains_OSS_ReturnsNil(t *testing.T) {
	domains, total := fetchNeighborhoodDomains(context.Background(), "1.2.3.4", "example.com")
	if domains != nil {
		t.Errorf("OSS fetchNeighborhoodDomains should return nil, got %v", domains)
	}
	if total != 0 {
		t.Errorf("OSS fetchNeighborhoodDomains total = %d, want 0", total)
	}
}

func TestBuildNeighborhoodContext_OSS_ReturnsEmpty(t *testing.T) {
	got := buildNeighborhoodContext("Cloudflare", 100)
	if got != "" {
		t.Errorf("OSS buildNeighborhoodContext = %q, want empty", got)
	}
}

func TestBuildExecutiveVerdict_OSS_ReturnsEmpty(t *testing.T) {
	got := buildExecutiveVerdict("Direct", "", "example.com", "1.2.3.4", nil, nil, nil)
	if got != "" {
		t.Errorf("OSS buildExecutiveVerdict = %q, want empty", got)
	}
}

func TestVerdictSeverity_OSS_ReturnsInfo(t *testing.T) {
	classifications := []string{"Direct", "CDN/Edge", "Unrelated", ""}
	for _, c := range classifications {
		got := verdictSeverity(c)
		if got != "info" {
			t.Errorf("OSS verdictSeverity(%q) = %q, want 'info'", c, got)
		}
	}
}

func TestInvestigateIP_OSS_IPv4(t *testing.T) {
	a := &Analyzer{}
	result := a.InvestigateIP(context.Background(), "example.com", "1.2.3.4")
	if result["status"] != "success" {
		t.Errorf("status = %v", result["status"])
	}
	if result["ip_version"] != "IPv4" {
		t.Errorf("ip_version = %v, want IPv4", result["ip_version"])
	}
	if result["domain"] != "example.com" {
		t.Errorf("domain = %v", result["domain"])
	}
	if result["ip"] != "1.2.3.4" {
		t.Errorf("ip = %v", result["ip"])
	}
	if result["classification"] != "Unrelated" {
		t.Errorf("classification = %v", result["classification"])
	}
}

func TestInvestigateIP_OSS_IPv6(t *testing.T) {
	a := &Analyzer{}
	result := a.InvestigateIP(context.Background(), "example.com", "::1")
	if result["ip_version"] != "IPv6" {
		t.Errorf("ip_version = %v, want IPv6", result["ip_version"])
	}
}
