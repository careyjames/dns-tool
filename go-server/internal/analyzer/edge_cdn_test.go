package analyzer

import (
	"testing"
)

func TestDetectEdgeCDN(t *testing.T) {
	result := DetectEdgeCDN(map[string]any{})
	if result["status"] != "success" {
		t.Errorf("status = %v, want success", result["status"])
	}
	if result["is_behind_cdn"] != false {
		t.Error("expected is_behind_cdn=false for OSS stub")
	}
	if result["origin_visible"] != true {
		t.Error("expected origin_visible=true for OSS stub")
	}
}

func TestCheckASNForCDN(t *testing.T) {
	provider, indicators := checkASNForCDN(map[string]any{}, nil)
	if provider != "" {
		t.Errorf("provider = %q, want empty", provider)
	}
	if len(indicators) != 0 {
		t.Errorf("indicators = %v, want empty", indicators)
	}
}

func TestCheckCNAMEForCDN(t *testing.T) {
	provider, indicators := checkCNAMEForCDN(map[string]any{}, nil)
	if provider != "" {
		t.Errorf("provider = %q, want empty", provider)
	}
	if len(indicators) != 0 {
		t.Errorf("indicators = %v, want empty", indicators)
	}
}

func TestCheckPTRForCDN(t *testing.T) {
	provider, indicators := checkPTRForCDN(map[string]any{}, nil)
	if provider != "" {
		t.Errorf("provider = %q, want empty", provider)
	}
	if len(indicators) != 0 {
		t.Errorf("indicators = %v, want empty", indicators)
	}
}

func TestMatchASNEntries(t *testing.T) {
	provider, indicators := matchASNEntries(map[string]any{}, "asn", nil)
	if provider != "" {
		t.Errorf("provider = %q, want empty", provider)
	}
	if len(indicators) != 0 {
		t.Errorf("indicators = %v, want empty", indicators)
	}
}

func TestClassifyCloudIP(t *testing.T) {
	provider, isCDN := classifyCloudIP("AS13335", nil)
	if provider != "" {
		t.Errorf("provider = %q, want empty", provider)
	}
	if isCDN {
		t.Error("expected isCDN=false for OSS stub")
	}
}

func TestIsOriginVisible(t *testing.T) {
	if isOriginVisible("cloudflare") {
		t.Error("expected false for OSS stub")
	}
}

func TestEdgeCDNMapsEmpty(t *testing.T) {
	if len(cdnASNs) != 0 {
		t.Error("expected cdnASNs to be empty in OSS build")
	}
	if len(cloudASNs) != 0 {
		t.Error("expected cloudASNs to be empty in OSS build")
	}
	if len(cloudCDNPTRPatterns) != 0 {
		t.Error("expected cloudCDNPTRPatterns to be empty in OSS build")
	}
	if len(cdnCNAMEPatterns) != 0 {
		t.Error("expected cdnCNAMEPatterns to be empty in OSS build")
	}
}

func TestDetectEdgeCDNResultFields(t *testing.T) {
	result := DetectEdgeCDN(map[string]any{
		"some_key": "some_value",
	})
	if result["status"] != "success" {
		t.Errorf("status = %v, want success", result["status"])
	}
	if result["cdn_provider"] != "" {
		t.Errorf("cdn_provider = %v, want empty", result["cdn_provider"])
	}
	indicators, ok := result["cdn_indicators"].([]string)
	if !ok {
		t.Fatal("cdn_indicators should be []string")
	}
	if len(indicators) != 0 {
		t.Errorf("indicators = %v, want empty", indicators)
	}
	if result["message"] != "Domain appears to use direct origin hosting" {
		t.Errorf("message = %v", result["message"])
	}
	issues, ok := result["issues"].([]string)
	if !ok {
		t.Fatal("issues should be []string")
	}
	if len(issues) != 0 {
		t.Errorf("issues should be empty, got %v", issues)
	}
}

func TestCheckASNForCDNWithData(t *testing.T) {
	results := map[string]any{
		"asn": map[string]any{
			"number": "AS13335",
		},
	}
	provider, indicators := checkASNForCDN(results, []string{"existing"})
	if provider != "" {
		t.Errorf("provider = %q, want empty for OSS stub", provider)
	}
	if len(indicators) != 1 || indicators[0] != "existing" {
		t.Errorf("indicators = %v, want [existing]", indicators)
	}
}

func TestMatchASNEntriesWithData(t *testing.T) {
	asnData := map[string]any{
		"number": "AS13335",
		"name":   "Cloudflare",
	}
	provider, indicators := matchASNEntries(asnData, "number", []string{"test"})
	if provider != "" {
		t.Errorf("provider = %q, want empty for OSS stub", provider)
	}
	if len(indicators) != 1 || indicators[0] != "test" {
		t.Errorf("indicators = %v, want [test]", indicators)
	}
}

func TestCheckCNAMEForCDNWithData(t *testing.T) {
	results := map[string]any{
		"cname": "cdn.cloudflare.net",
	}
	provider, indicators := checkCNAMEForCDN(results, nil)
	if provider != "" {
		t.Errorf("provider = %q, want empty for OSS stub", provider)
	}
	if indicators != nil {
		t.Errorf("indicators = %v, want nil", indicators)
	}
}

func TestCheckPTRForCDNWithData(t *testing.T) {
	results := map[string]any{
		"ptr_records": []string{"server.cloudflare.com"},
	}
	provider, indicators := checkPTRForCDN(results, []string{})
	if provider != "" {
		t.Errorf("provider = %q, want empty for OSS stub", provider)
	}
	if len(indicators) != 0 {
		t.Errorf("indicators = %v, want empty", indicators)
	}
}

func TestClassifyCloudIPVariousASNs(t *testing.T) {
	asns := []string{"AS16509", "AS15169", "AS8075", "AS14618"}
	for _, asn := range asns {
		provider, isCDN := classifyCloudIP(asn, []string{"server.example.com"})
		if provider != "" {
			t.Errorf("classifyCloudIP(%q) provider = %q, want empty for OSS stub", asn, provider)
		}
		if isCDN {
			t.Errorf("classifyCloudIP(%q) isCDN = true, want false for OSS stub", asn)
		}
	}
}

func TestIsOriginVisibleVariousProviders(t *testing.T) {
	providers := []string{"cloudflare", "akamai", "fastly", "aws", ""}
	for _, p := range providers {
		if isOriginVisible(p) {
			t.Errorf("isOriginVisible(%q) = true, want false for OSS stub", p)
		}
	}
}
