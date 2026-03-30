//go:build !intel

package analyzer

import (
	"testing"
)

func TestDetectEdgeCDN_OSS_AlwaysNoCDN(t *testing.T) {
	results := map[string]any{
		"asn_info": map[string]any{
			"ipv4_asn": []map[string]any{{"asn": "13335"}},
		},
	}
	got := DetectEdgeCDN(results)
	if got["is_behind_cdn"] != false {
		t.Error("OSS stub should return is_behind_cdn=false")
	}
	if got["cdn_provider"] != "" {
		t.Errorf("OSS cdn_provider = %v, want empty", got["cdn_provider"])
	}
	if got["status"] != "success" {
		t.Errorf("status = %v", got["status"])
	}
}

func TestCheckASNForCDN_OSS_ReturnsEmpty(t *testing.T) {
	provider, indicators := checkASNForCDN(map[string]any{}, nil)
	if provider != "" {
		t.Errorf("OSS checkASNForCDN provider = %q", provider)
	}
	if indicators != nil {
		t.Errorf("OSS checkASNForCDN indicators = %v", indicators)
	}
}

func TestMatchASNEntries_OSS_ReturnsEmpty(t *testing.T) {
	provider, indicators := matchASNEntries(map[string]any{}, "key", nil)
	if provider != "" {
		t.Errorf("OSS matchASNEntries provider = %q", provider)
	}
	if indicators != nil {
		t.Errorf("OSS matchASNEntries indicators = %v", indicators)
	}
}

func TestCheckCNAMEForCDN_OSS_ReturnsEmpty(t *testing.T) {
	provider, indicators := checkCNAMEForCDN(map[string]any{}, nil)
	if provider != "" {
		t.Errorf("OSS checkCNAMEForCDN provider = %q", provider)
	}
	if indicators != nil {
		t.Errorf("OSS checkCNAMEForCDN indicators = %v", indicators)
	}
}

func TestCheckPTRForCDN_OSS_ReturnsEmpty(t *testing.T) {
	provider, indicators := checkPTRForCDN(map[string]any{}, nil)
	if provider != "" {
		t.Errorf("OSS checkPTRForCDN provider = %q", provider)
	}
	if indicators != nil {
		t.Errorf("OSS checkPTRForCDN indicators = %v", indicators)
	}
}

func TestClassifyCloudIP_OSS_AlwaysEmpty(t *testing.T) {
	provider, isCDN := classifyCloudIP("13335", []string{"ptr.cloudflare.com"})
	if provider != "" {
		t.Errorf("OSS classifyCloudIP provider = %q", provider)
	}
	if isCDN {
		t.Error("OSS classifyCloudIP should return isCDN=false")
	}
}

func TestIsOriginVisible_OSS_AlwaysFalse(t *testing.T) {
	if isOriginVisible("anything") {
		t.Error("OSS isOriginVisible should return false")
	}
	if isOriginVisible("") {
		t.Error("OSS isOriginVisible('') should return false")
	}
}

func TestCDNASNs_OSS_Empty(t *testing.T) {
	if len(cdnASNs) != 0 {
		t.Errorf("OSS cdnASNs should be empty, got %d entries", len(cdnASNs))
	}
}

func TestCloudASNs_OSS_Empty(t *testing.T) {
	if len(cloudASNs) != 0 {
		t.Errorf("OSS cloudASNs should be empty, got %d entries", len(cloudASNs))
	}
}

func TestCloudCDNPTRPatterns_OSS_Empty(t *testing.T) {
	if len(cloudCDNPTRPatterns) != 0 {
		t.Errorf("OSS cloudCDNPTRPatterns should be empty, got %d entries", len(cloudCDNPTRPatterns))
	}
}

func TestCDNCNAMEPatterns_OSS_Empty(t *testing.T) {
	if len(cdnCNAMEPatterns) != 0 {
		t.Errorf("OSS cdnCNAMEPatterns should be empty, got %d entries", len(cdnCNAMEPatterns))
	}
}
