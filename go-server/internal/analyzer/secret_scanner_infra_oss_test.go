//go:build !intel

package analyzer

import "testing"

func TestToStringSlice_CB8(t *testing.T) {
	m := map[string]any{"NS": []string{"ns1.example.com", "ns2.example.com"}}
	result := toStringSlice(m, "NS")
	if len(result) != 2 {
		t.Fatalf("expected 2, got %d", len(result))
	}
	nilResult := toStringSlice(nil, "NS")
	if nilResult != nil {
		t.Fatal("expected nil for nil map")
	}
	emptyResult := toStringSlice(m, "MX")
	if emptyResult != nil {
		t.Fatal("expected nil for missing key")
	}
}

func TestIdentifyWebHostingOSS_CB8(t *testing.T) {
	result := identifyWebHostingOSS(nil)
	if result != strUnknown {
		t.Errorf("expected Unknown, got %q", result)
	}
	result2 := identifyWebHostingOSS([]string{"something.cloudfront.net"})
	if result2 == strUnknown {
		t.Error("expected identified web hosting for cloudfront")
	}
}

func TestIdentifyDNSProviderOSS_CB8(t *testing.T) {
	result := identifyDNSProviderOSS(nil)
	if result != strUnknown {
		t.Errorf("expected Unknown, got %q", result)
	}
	result2 := identifyDNSProviderOSS([]string{"ns1.google.com"})
	if result2 == strUnknown {
		t.Error("expected identified DNS provider for google")
	}
}

func TestIdentifyEmailProviderOSS_CB8(t *testing.T) {
	result := identifyEmailProviderOSS(nil)
	if result != strUnknown {
		t.Errorf("expected Unknown, got %q", result)
	}
	result2 := identifyEmailProviderOSS([]string{"aspmx.l.google.com"})
	if result2 == strUnknown {
		t.Error("expected identified email provider for google")
	}
}
