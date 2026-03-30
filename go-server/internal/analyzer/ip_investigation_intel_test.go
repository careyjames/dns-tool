//go:build intel

package analyzer

import (
	"context"
	"testing"
)

func TestInvestigateIP_Intel_IPv4(t *testing.T) {
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
}

func TestInvestigateIP_Intel_IPv6(t *testing.T) {
	a := &Analyzer{}
	result := a.InvestigateIP(context.Background(), "example.com", "2001:db8::1")
	if result["ip_version"] != "IPv6" {
		t.Errorf("ip_version = %v, want IPv6", result["ip_version"])
	}
}

func TestInvestigateIP_Intel_DefaultClassification(t *testing.T) {
	a := &Analyzer{}
	result := a.InvestigateIP(context.Background(), "example.com", "1.2.3.4")
	if result["classification"] != "Unrelated" {
		t.Errorf("classification = %v, want Unrelated", result["classification"])
	}
	if result["is_cdn"] != false {
		t.Error("expected is_cdn=false by default")
	}
}

func TestFetchNeighborhoodDomains_Intel_ReturnsNil(t *testing.T) {
	domains, total := fetchNeighborhoodDomains(context.Background(), "1.2.3.4", "example.com")
	if domains != nil {
		t.Errorf("expected nil domains, got %v", domains)
	}
	if total != 0 {
		t.Errorf("total = %d, want 0", total)
	}
}

func TestBuildNeighborhoodContext_Intel_ReturnsEmpty(t *testing.T) {
	got := buildNeighborhoodContext("Cloudflare", 100)
	if got != "" {
		t.Errorf("buildNeighborhoodContext = %q, want empty", got)
	}
}

func TestBuildExecutiveVerdict_Intel_ReturnsEmpty(t *testing.T) {
	got := buildExecutiveVerdict("Direct", "", "example.com", "1.2.3.4", nil, nil, nil)
	if got != "" {
		t.Errorf("buildExecutiveVerdict = %q, want empty", got)
	}
}

func TestVerdictSeverity_Intel_ReturnsInfo(t *testing.T) {
	cases := []string{"Direct", "CDN/Edge", "Unrelated", ""}
	for _, c := range cases {
		got := verdictSeverity(c)
		if got != "info" {
			t.Errorf("verdictSeverity(%q) = %q, want 'info'", c, got)
		}
	}
}

func TestFindSPFTXTRecord_Intel_ReturnsEmpty(t *testing.T) {
	got := findSPFTXTRecord([]string{"v=spf1 include:_spf.google.com ~all"})
	if got != "" {
		t.Errorf("findSPFTXTRecord = %q, want empty", got)
	}
}

func TestCheckIPInSPFRecord_Intel_ReturnsFalse(t *testing.T) {
	got := checkIPInSPFRecord("v=spf1 ip4:1.2.3.4 ~all", "1.2.3.4")
	if got {
		t.Error("checkIPInSPFRecord should return false")
	}
}

func TestCheckASNForCDNDirect_Intel_ReturnsFalse(t *testing.T) {
	provider, isCDN := checkASNForCDNDirect(map[string]any{}, nil)
	if provider != "" {
		t.Errorf("provider = %q, want empty", provider)
	}
	if isCDN {
		t.Error("expected isCDN=false")
	}
}

func TestClassifyOverall_Intel_ReturnsUnrelated(t *testing.T) {
	classification, summary := classifyOverall(nil, nil, "", map[string]any{})
	if classification != "Unrelated" {
		t.Errorf("classification = %q, want Unrelated", classification)
	}
	if summary != "" {
		t.Errorf("summary = %q, want empty", summary)
	}
}
