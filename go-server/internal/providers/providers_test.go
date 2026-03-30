package providers

import (
	"testing"
)

func TestCNAMEProviderMap_NonEmpty(t *testing.T) {
	if len(CNAMEProviderMap) == 0 {
		t.Fatal("CNAMEProviderMap is empty")
	}
}

func TestCNAMEProviderMap_WellKnownEntries(t *testing.T) {
	tests := []struct {
		domain   string
		name     string
		category string
	}{
		{"shopify.com", "Shopify", catEcommerce},
		{"cloudfront.net", "AWS CloudFront", catCDN},
		{"vercel.app", "Vercel", catWebsite},
		{"herokuapp.com", "Heroku", catPaaS},
		{"azurewebsites.net", "Azure App Service", catCloud},
		{"zendesk.com", "Zendesk", catSupport},
	}
	for _, tt := range tests {
		info, ok := CNAMEProviderMap[tt.domain]
		if !ok {
			t.Errorf("CNAMEProviderMap missing key %q", tt.domain)
			continue
		}
		if info.Name != tt.name {
			t.Errorf("CNAMEProviderMap[%q].Name = %q, want %q", tt.domain, info.Name, tt.name)
		}
		if info.Category != tt.category {
			t.Errorf("CNAMEProviderMap[%q].Category = %q, want %q", tt.domain, info.Category, tt.category)
		}
	}
}

func TestCNAMEProviderMap_NoEmptyFields(t *testing.T) {
	for domain, info := range CNAMEProviderMap {
		if domain == "" {
			t.Error("empty key in CNAMEProviderMap")
		}
		if info.Name == "" {
			t.Errorf("CNAMEProviderMap[%q].Name is empty", domain)
		}
		if info.Category == "" {
			t.Errorf("CNAMEProviderMap[%q].Category is empty", domain)
		}
	}
}

func TestDANEMXCapability_NonEmpty(t *testing.T) {
	if len(DANEMXCapability) == 0 {
		t.Fatal("DANEMXCapability is empty")
	}
}

func TestDANEMXCapability_WellKnownEntries(t *testing.T) {
	tests := []struct {
		key         string
		name        string
		daneIn      bool
		daneOut     bool
		hasReason   bool
		hasPatterns bool
	}{
		{"microsoft365", "Microsoft 365", false, false, true, true},
		{"google_workspace", "Google Workspace", false, true, true, true},
		{"fastmail", "Fastmail", true, true, true, true},
		{"postfix_default", "Self-Hosted (Postfix)", true, true, true, false},
	}
	for _, tt := range tests {
		cap, ok := DANEMXCapability[tt.key]
		if !ok {
			t.Errorf("DANEMXCapability missing key %q", tt.key)
			continue
		}
		if cap.Name != tt.name {
			t.Errorf("DANEMXCapability[%q].Name = %q, want %q", tt.key, cap.Name, tt.name)
		}
		if cap.DANEInbound != tt.daneIn {
			t.Errorf("DANEMXCapability[%q].DANEInbound = %v, want %v", tt.key, cap.DANEInbound, tt.daneIn)
		}
		if cap.DANEOutbound != tt.daneOut {
			t.Errorf("DANEMXCapability[%q].DANEOutbound = %v, want %v", tt.key, cap.DANEOutbound, tt.daneOut)
		}
		if tt.hasReason && cap.Reason == "" {
			t.Errorf("DANEMXCapability[%q].Reason is empty", tt.key)
		}
		if tt.hasPatterns && len(cap.Patterns) == 0 && tt.key != "postfix_default" {
			t.Errorf("DANEMXCapability[%q].Patterns is empty", tt.key)
		}
	}
}

func TestDANEMXCapability_AlternativesPresent(t *testing.T) {
	for key, cap := range DANEMXCapability {
		if !cap.DANEInbound && cap.Alternative == "" && key != "postfix_default" {
			t.Errorf("DANEMXCapability[%q] has DANEInbound=false but no Alternative", key)
		}
	}
}

func TestDMARCMonitoringProviders_NonEmpty(t *testing.T) {
	if len(DMARCMonitoringProviders) == 0 {
		t.Fatal("DMARCMonitoringProviders is empty")
	}
}

func TestDMARCMonitoringProviders_HaveCapabilities(t *testing.T) {
	for domain, prov := range DMARCMonitoringProviders {
		if prov.Name == "" {
			t.Errorf("DMARCMonitoringProviders[%q].Name is empty", domain)
		}
		if len(prov.Capabilities) == 0 {
			t.Errorf("DMARCMonitoringProviders[%q].Capabilities is empty", domain)
		}
	}
}

func TestSPFFlatteningProviders_NonEmpty(t *testing.T) {
	if len(SPFFlatteningProviders) == 0 {
		t.Fatal("SPFFlatteningProviders is empty")
	}
}

func TestSPFFlatteningProviders_HavePatterns(t *testing.T) {
	for _, prov := range SPFFlatteningProviders {
		if prov.Name == "" {
			t.Error("SPFFlatteningProvider with empty Name")
		}
		if len(prov.Patterns) == 0 {
			t.Errorf("SPFFlatteningProvider %q has no patterns", prov.Name)
		}
	}
}

func TestDynamicServicesProviders_NonEmpty(t *testing.T) {
	if len(DynamicServicesProviders) == 0 {
		t.Fatal("DynamicServicesProviders is empty")
	}
}

func TestDynamicServicesProviders_AllDynamicDNS(t *testing.T) {
	for domain, prov := range DynamicServicesProviders {
		if prov.Name == "" {
			t.Errorf("DynamicServicesProviders[%q].Name is empty", domain)
		}
		if prov.Category != catDynamicDNS {
			t.Errorf("DynamicServicesProviders[%q].Category = %q, want %q", domain, prov.Category, catDynamicDNS)
		}
	}
}

func TestDynamicServicesZones_NonEmpty(t *testing.T) {
	if len(DynamicServicesZones) == 0 {
		t.Fatal("DynamicServicesZones is empty")
	}
	for i, z := range DynamicServicesZones {
		if z == "" {
			t.Errorf("DynamicServicesZones[%d] is empty", i)
		}
	}
}

func TestHostedDKIMProviders_NonEmpty(t *testing.T) {
	if len(HostedDKIMProviders) == 0 {
		t.Fatal("HostedDKIMProviders is empty")
	}
}

func TestHostedDKIMProviders_HavePatterns(t *testing.T) {
	for _, prov := range HostedDKIMProviders {
		if prov.Name == "" {
			t.Error("HostedDKIMProvider with empty Name")
		}
		if len(prov.Patterns) == 0 {
			t.Errorf("HostedDKIMProvider %q has no patterns", prov.Name)
		}
	}
}

func TestProviderInfoFields(t *testing.T) {
	p := ProviderInfo{Name: "Test", Category: "TestCat"}
	if p.Name != "Test" {
		t.Errorf("ProviderInfo.Name = %q, want Test", p.Name)
	}
	if p.Category != "TestCat" {
		t.Errorf("ProviderInfo.Category = %q, want TestCat", p.Category)
	}
}

func TestDANECapabilityFields(t *testing.T) {
	d := DANECapability{
		Name: "Test", DANEInbound: true, DANEOutbound: false,
		Reason: "test reason", Alternative: "test alt",
		Patterns: []string{"example.com"},
	}
	if d.Name != "Test" {
		t.Errorf("DANECapability.Name = %q", d.Name)
	}
	if !d.DANEInbound {
		t.Error("expected DANEInbound=true")
	}
	if d.DANEOutbound {
		t.Error("expected DANEOutbound=false")
	}
}
