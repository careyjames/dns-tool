package analyzer

import (
	"testing"
)

func TestParentZone(t *testing.T) {
	tests := []struct {
		domain, want string
	}{
		{"sub.example.com", "example.com"},
		{"a.b.example.com", "b.example.com"},
		{"example.com", ""},
		{"com", ""},
		{"", ""},
	}
	for _, tt := range tests {
		got := parentZone(tt.domain)
		if got != tt.want {
			t.Errorf("parentZone(%q) = %q, want %q", tt.domain, got, tt.want)
		}
	}
}

func TestApplyHostingDefaults_AllEmpty(t *testing.T) {
	h, d, e := applyHostingDefaults("", "", "", false)
	if h != "Unknown" {
		t.Errorf("hosting = %q, want 'Unknown'", h)
	}
	if d != "Unknown" {
		t.Errorf("dnsHosting = %q, want 'Unknown'", d)
	}
	if e != "Unknown" {
		t.Errorf("emailHosting = %q, want 'Unknown'", e)
	}
}

func TestApplyHostingDefaults_NoMail(t *testing.T) {
	h, d, e := applyHostingDefaults("", "", "", true)
	if e != "No Mail Domain" {
		t.Errorf("emailHosting = %q, want 'No Mail Domain'", e)
	}
	if h != "Unknown" {
		t.Errorf("hosting = %q", h)
	}
	if d != "Unknown" {
		t.Errorf("dnsHosting = %q", d)
	}
}

func TestApplyHostingDefaults_PreserveExisting(t *testing.T) {
	h, d, e := applyHostingDefaults("AWS", "Cloudflare", "Google", false)
	if h != "AWS" {
		t.Errorf("hosting = %q, want 'AWS'", h)
	}
	if d != "Cloudflare" {
		t.Errorf("dnsHosting = %q, want 'Cloudflare'", d)
	}
	if e != "Google" {
		t.Errorf("emailHosting = %q, want 'Google'", e)
	}
}

func TestApplyHostingDefaults_NoMailWithExisting(t *testing.T) {
	_, _, e := applyHostingDefaults("", "", "Gmail", true)
	if e != "Gmail" {
		t.Errorf("emailHosting = %q, want 'Gmail' (should keep existing)", e)
	}
}

func TestContainsStr(t *testing.T) {
	tests := []struct {
		ss   []string
		s    string
		want bool
	}{
		{[]string{"a", "b", "c"}, "b", true},
		{[]string{"a", "b", "c"}, "d", false},
		{nil, "a", false},
		{[]string{}, "a", false},
	}
	for _, tt := range tests {
		got := containsStr(tt.ss, tt.s)
		if got != tt.want {
			t.Errorf("containsStr(%v, %q) = %v, want %v", tt.ss, tt.s, got, tt.want)
		}
	}
}

func TestZoneCapability(t *testing.T) {
	got := zoneCapability("DNS")
	if got != "DNS management" {
		t.Errorf("zoneCapability('DNS') = %q, want 'DNS management'", got)
	}
}

func TestExtractMailtoDomains_ReturnsNil(t *testing.T) {
	got := extractMailtoDomains("mailto:admin@example.com")
	if got != nil {
		t.Errorf("extractMailtoDomains = %v (OSS stub should return nil)", got)
	}
}

func TestInfrastructureConstants(t *testing.T) {
	if featDDoSProtection != "DDoS protection" {
		t.Errorf("featDDoSProtection = %q", featDDoSProtection)
	}
	if tierEnterprise != "enterprise" {
		t.Errorf("tierEnterprise = %q", tierEnterprise)
	}
	if strUnknown != "Unknown" {
		t.Errorf("strUnknown = %q", strUnknown)
	}
}

func TestProviderInfo_Struct(t *testing.T) {
	p := providerInfo{
		Name:     "Cloudflare",
		Tier:     tierEnterprise,
		Features: []string{featDDoSProtection, featAnycast},
	}
	if p.Name != "Cloudflare" {
		t.Errorf("Name = %q", p.Name)
	}
	if len(p.Features) != 2 {
		t.Errorf("Features len = %d", len(p.Features))
	}
}

func TestInfraMatch_Struct(t *testing.T) {
	im := &infraMatch{
		provider: &providerInfo{Name: "AWS", Tier: tierManaged},
		tier:     tierManaged,
	}
	if im.provider.Name != "AWS" {
		t.Errorf("provider.Name = %q", im.provider.Name)
	}
}
