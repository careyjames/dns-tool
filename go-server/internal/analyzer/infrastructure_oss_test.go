//go:build !intel

package analyzer

import (
        "testing"
)

func TestToStringSlice(t *testing.T) {
        tests := []struct {
                name string
                m    map[string]any
                key  string
                want int
        }{
                {"found", map[string]any{"ns": []string{"ns1.com", "ns2.com"}}, "ns", 2},
                {"missing", map[string]any{}, "ns", 0},
                {"wrong_type", map[string]any{"ns": 42}, "ns", 0},
        }
        for _, tt := range tests {
                got := toStringSlice(tt.m, tt.key)
                if len(got) != tt.want {
                        t.Errorf("%s: len = %d, want %d", tt.name, len(got), tt.want)
                }
        }
}

func TestIdentifyWebHostingOSS(t *testing.T) {
        got := identifyWebHostingOSS(nil)
        if got != strUnknown {
                t.Errorf("identifyWebHostingOSS(nil) = %q, want %q", got, strUnknown)
        }

        got = identifyWebHostingOSS([]string{})
        if got != strUnknown {
                t.Errorf("identifyWebHostingOSS([]) = %q, want %q", got, strUnknown)
        }
}

func TestIdentifyDNSProviderOSS(t *testing.T) {
        got := identifyDNSProviderOSS(nil)
        if got != strUnknown {
                t.Errorf("identifyDNSProviderOSS(nil) = %q, want %q", got, strUnknown)
        }

        got = identifyDNSProviderOSS([]string{})
        if got != strUnknown {
                t.Errorf("identifyDNSProviderOSS([]) = %q, want %q", got, strUnknown)
        }
}

func TestIdentifyEmailProviderOSS(t *testing.T) {
        got := identifyEmailProviderOSS(nil)
        if got != strUnknown {
                t.Errorf("identifyEmailProviderOSS(nil) = %q, want %q", got, strUnknown)
        }

        got = identifyEmailProviderOSS([]string{"aspmx.l.google.com"})
        if got == "" {
                t.Error("identifyEmailProviderOSS with Google MX should not return empty")
        }
}

func TestMatchEnterpriseProvider_OSS(t *testing.T) {
        if got := matchEnterpriseProvider([]string{"ns1.cloudflare.com"}); got != nil {
                t.Error("OSS stub should return nil")
        }
}

func TestMatchSelfHostedProvider_OSS(t *testing.T) {
        if got := matchSelfHostedProvider("ns1.example.com"); got != nil {
                t.Error("OSS stub should return nil")
        }
}

func TestMatchManagedProvider_OSS(t *testing.T) {
        if got := matchManagedProvider("ns1.cloudflare.com"); got != nil {
                t.Error("OSS stub should return nil")
        }
}

func TestMatchGovernmentDomain_OSS(t *testing.T) {
        im, isGov := matchGovernmentDomain("example.gov")
        if im != nil || isGov {
                t.Error("OSS stub should return nil, false")
        }
}

func TestCollectAltSecurityItems_OSS(t *testing.T) {
        if got := collectAltSecurityItems(map[string]any{}); got != nil {
                t.Error("OSS stub should return nil")
        }
}

func TestAssessTier_OSS(t *testing.T) {
        got := assessTier("enterprise")
        if got != "Standard DNS" {
                t.Errorf("assessTier = %q, want 'Standard DNS'", got)
        }
}

func TestMatchAllProviders_OSS(t *testing.T) {
        if got := matchAllProviders([]string{"ns1.cloudflare.com"}, "ns1.cloudflare.com"); got != nil {
                t.Error("OSS stub should return nil")
        }
}

func TestMatchMonitoringProvider_OSS(t *testing.T) {
        if got := matchMonitoringProvider("example.com"); got != nil {
                t.Error("OSS stub should return nil")
        }
}

func TestDetectEmailProviderFromSPF_OSS(t *testing.T) {
        if got := detectEmailProviderFromSPF(map[string]any{}); got != "" {
                t.Errorf("OSS stub should return empty, got %q", got)
        }
}

func TestDetectProvider_OSS(t *testing.T) {
        if got := detectProvider([]string{"ns1.google.com"}, map[string]string{"google": "Google"}); got != "" {
                t.Errorf("OSS stub should return empty, got %q", got)
        }
}

func TestHostingConfidence_OSS(t *testing.T) {
        got := hostingConfidence("AWS", false)
        if got == nil {
                t.Error("should return non-nil map")
        }
}

func TestDNSConfidence_OSS(t *testing.T) {
        got := dnsConfidence(true)
        if got == nil {
                t.Error("should return non-nil map")
        }
}

func TestEmailConfidence_OSS(t *testing.T) {
        got := emailConfidence(true, false)
        if got == nil {
                t.Error("should return non-nil map")
        }
}

func TestEnrichHostingFromEdgeCDN_NoOp(t *testing.T) {
        results := map[string]any{}
        enrichHostingFromEdgeCDN(results)
}
