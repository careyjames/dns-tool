//go:build intel

package analyzer

import (
	"testing"
)

func TestDetectEdgeCDN_NoCDN(t *testing.T) {
	results := map[string]any{}
	got := DetectEdgeCDN(results)
	if got["is_behind_cdn"] != false {
		t.Error("expected is_behind_cdn=false for empty results")
	}
	if got["cdn_provider"] != "" {
		t.Errorf("cdn_provider = %q, want empty", got["cdn_provider"])
	}
	if got["origin_visible"] != true {
		t.Error("expected origin_visible=true for no CDN")
	}
	if got["status"] != "success" {
		t.Errorf("status = %v", got["status"])
	}
}

func TestDetectEdgeCDN_ByASN(t *testing.T) {
	results := map[string]any{
		"asn_info": map[string]any{
			"ipv4_asn": []map[string]any{
				{"asn": "13335"},
			},
		},
	}
	got := DetectEdgeCDN(results)
	if got["is_behind_cdn"] != true {
		t.Error("expected is_behind_cdn=true for Cloudflare ASN")
	}
	if got["cdn_provider"] != "Cloudflare" {
		t.Errorf("cdn_provider = %v, want Cloudflare", got["cdn_provider"])
	}
}

func TestDetectEdgeCDN_ByCNAME(t *testing.T) {
	results := map[string]any{
		"basic_records": map[string]any{
			"CNAME": []string{"example.cloudfront.net"},
		},
	}
	got := DetectEdgeCDN(results)
	if got["is_behind_cdn"] != true {
		t.Error("expected is_behind_cdn=true for CloudFront CNAME")
	}
	if got["cdn_provider"] != provAmazonCF {
		t.Errorf("cdn_provider = %v, want %s", got["cdn_provider"], provAmazonCF)
	}
}

func TestDetectEdgeCDN_ByPTR(t *testing.T) {
	results := map[string]any{
		"basic_records": map[string]any{
			"PTR": []string{"server.akamaiedge.net"},
		},
	}
	got := DetectEdgeCDN(results)
	if got["is_behind_cdn"] != true {
		t.Error("expected is_behind_cdn=true for Akamai PTR")
	}
}

func TestCheckASNForCDN_NoASNData(t *testing.T) {
	provider, indicators := checkASNForCDN(map[string]any{}, nil)
	if provider != "" {
		t.Errorf("provider = %q, want empty", provider)
	}
	if len(indicators) != 0 {
		t.Errorf("indicators = %v, want empty", indicators)
	}
}

func TestCheckASNForCDN_IPv6ASN(t *testing.T) {
	results := map[string]any{
		"asn_info": map[string]any{
			"ipv6_asn": []map[string]any{
				{"asn": "54113"},
			},
		},
	}
	provider, indicators := checkASNForCDN(results, nil)
	if provider != "Fastly" {
		t.Errorf("provider = %q, want Fastly", provider)
	}
	if len(indicators) != 1 {
		t.Errorf("expected 1 indicator, got %d", len(indicators))
	}
}

func TestMatchASNEntries_EmptyASN(t *testing.T) {
	data := map[string]any{
		"ipv4_asn": []map[string]any{
			{"asn": ""},
		},
	}
	provider, indicators := matchASNEntries(data, "ipv4_asn", nil)
	if provider != "" {
		t.Errorf("provider = %q, want empty for blank ASN", provider)
	}
	if len(indicators) != 0 {
		t.Errorf("indicators len = %d, want 0", len(indicators))
	}
}

func TestMatchASNEntries_UnknownASN(t *testing.T) {
	data := map[string]any{
		"ipv4_asn": []map[string]any{
			{"asn": "99999"},
		},
	}
	provider, _ := matchASNEntries(data, "ipv4_asn", nil)
	if provider != "" {
		t.Errorf("provider = %q, want empty for unknown ASN", provider)
	}
}

func TestMatchASNEntries_WrongType(t *testing.T) {
	data := map[string]any{
		"ipv4_asn": "not-a-slice",
	}
	provider, indicators := matchASNEntries(data, "ipv4_asn", nil)
	if provider != "" {
		t.Errorf("provider = %q for wrong type", provider)
	}
	if indicators != nil {
		t.Errorf("indicators = %v for wrong type", indicators)
	}
}

func TestCheckCNAMEForCDN_NoCNAME(t *testing.T) {
	results := map[string]any{
		"basic_records": map[string]any{},
	}
	provider, _ := checkCNAMEForCDN(results, nil)
	if provider != "" {
		t.Errorf("provider = %q, want empty", provider)
	}
}

func TestCheckCNAMEForCDN_NoBasicRecords(t *testing.T) {
	provider, _ := checkCNAMEForCDN(map[string]any{}, nil)
	if provider != "" {
		t.Errorf("provider = %q, want empty", provider)
	}
}

func TestCheckPTRForCDN_NoPTR(t *testing.T) {
	results := map[string]any{
		"basic_records": map[string]any{},
	}
	provider, _ := checkPTRForCDN(results, nil)
	if provider != "" {
		t.Errorf("provider = %q, want empty", provider)
	}
}

func TestCheckPTRForCDN_NoBasicRecords(t *testing.T) {
	provider, _ := checkPTRForCDN(map[string]any{}, nil)
	if provider != "" {
		t.Errorf("provider = %q, want empty", provider)
	}
}

func TestClassifyCloudIP_CDN(t *testing.T) {
	provider, isCDN := classifyCloudIP("13335", nil)
	if provider != "Cloudflare" || !isCDN {
		t.Errorf("classifyCloudIP('13335') = (%q, %v), want (Cloudflare, true)", provider, isCDN)
	}
}

func TestClassifyCloudIP_CloudNotCDN(t *testing.T) {
	provider, isCDN := classifyCloudIP("16509", nil)
	if isCDN {
		if provider == "" {
			t.Error("expected non-empty provider for CDN ASN")
		}
	} else {
		if provider == "" {
			t.Error("expected non-empty provider for cloud ASN")
		}
	}
}

func TestClassifyCloudIP_ByPTR(t *testing.T) {
	provider, isCDN := classifyCloudIP("99999", []string{"server.cloudfront.net"})
	if provider != provAmazonCF || !isCDN {
		t.Errorf("classifyCloudIP by PTR = (%q, %v)", provider, isCDN)
	}
}

func TestClassifyCloudIP_Unknown(t *testing.T) {
	provider, isCDN := classifyCloudIP("99999", nil)
	if provider != "" || isCDN {
		t.Errorf("classifyCloudIP unknown = (%q, %v)", provider, isCDN)
	}
}

func TestIsOriginVisible_Hidden(t *testing.T) {
	hidden := []string{"Cloudflare", "Akamai", "Fastly", provAzureCDN, provAzureFrontDoor, "Sucuri", provImperva, "Imperva"}
	for _, p := range hidden {
		if isOriginVisible(p) {
			t.Errorf("isOriginVisible(%q) = true, want false", p)
		}
	}
}

func TestIsOriginVisible_Visible(t *testing.T) {
	visible := []string{"AWS", "Heroku", "DigitalOcean", "Hetzner", ""}
	for _, p := range visible {
		if !isOriginVisible(p) {
			t.Errorf("isOriginVisible(%q) = false, want true", p)
		}
	}
}

func TestCDNASNs_KnownEntries(t *testing.T) {
	if _, ok := cdnASNs["13335"]; !ok {
		t.Error("cdnASNs should contain Cloudflare ASN 13335")
	}
	if _, ok := cdnASNs["20940"]; !ok {
		t.Error("cdnASNs should contain Akamai ASN 20940")
	}
}

func TestCDNCNAMEPatterns_KnownEntries(t *testing.T) {
	if _, ok := cdnCNAMEPatterns["cloudfront.net"]; !ok {
		t.Error("cdnCNAMEPatterns should contain cloudfront.net")
	}
	if _, ok := cdnCNAMEPatterns["edgekey.net"]; !ok {
		t.Error("cdnCNAMEPatterns should contain edgekey.net")
	}
}

func TestDetectEdgeCDN_ASNAndCNAMEBothPresent(t *testing.T) {
	results := map[string]any{
		"asn_info": map[string]any{
			"ipv4_asn": []map[string]any{
				{"asn": "13335"},
			},
		},
		"basic_records": map[string]any{
			"CNAME": []string{"example.fastly.net"},
		},
	}
	got := DetectEdgeCDN(results)
	if got["is_behind_cdn"] != true {
		t.Error("expected is_behind_cdn=true")
	}
	if got["cdn_provider"] != "Cloudflare" {
		t.Errorf("cdn_provider = %v, want Cloudflare (ASN takes priority)", got["cdn_provider"])
	}
}
