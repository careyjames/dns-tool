package icuae

import (
	"testing"
)

func TestDetectDNSProvider(t *testing.T) {
	tests := []struct {
		name         string
		dnsProviders []string
		nsRecords    []string
		want         string
	}{
		{"cloudflare NS", nil, []string{"ada.ns.cloudflare.com.", "bob.ns.cloudflare.com."}, "Cloudflare"},
		{"route53 NS", nil, []string{"ns-123.awsdns-45.com.", "ns-678.awsdns-90.net."}, "AWS Route 53"},
		{"godaddy NS", nil, []string{"ns01.domaincontrol.com.", "ns02.domaincontrol.com."}, "GoDaddy"},
		{"namecheap NS", nil, []string{"dns1.registrar-servers.com."}, "Namecheap"},
		{"hostinger NS", nil, []string{"ns1.dns-parking.com.", "ns2.dns-parking.com."}, "Hostinger"},
		{"gandi NS", nil, []string{"ns-123-a.gandi.net.", "ns-456-b.gandi.net."}, "Gandi"},
		{"porkbun NS", nil, []string{"maceio.porkbun.com.", "fortaleza.porkbun.com."}, "Porkbun"},
		{"digitalocean NS", nil, []string{"ns1.digitalocean.com.", "ns2.digitalocean.com."}, "DigitalOcean"},
		{"google NS", nil, []string{"ns-cloud-a1.googledomains.com."}, "Google Cloud DNS"},
		{"hetzner NS", nil, []string{"helium.ns.hetzner.de.", "hydrogen.ns.hetzner.com."}, "Hetzner"},
		{"ovh NS", nil, []string{"dns11.ovh.net.", "ns11.ovh.net."}, "OVH"},
		{"provider list cloudflare", []string{"Cloudflare"}, nil, "Cloudflare"},
		{"unknown", nil, []string{"ns1.example.com."}, ""},
		{"empty", nil, nil, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectDNSProvider(tt.dnsProviders, tt.nsRecords)
			if got != tt.want {
				t.Errorf("DetectDNSProvider(%v, %v) = %q, want %q", tt.dnsProviders, tt.nsRecords, got, tt.want)
			}
		})
	}
}

func TestAnalyzeSOACompliance_CloudflareDefaults(t *testing.T) {
	soa := "ada.ns.cloudflare.com. dns.cloudflare.com. 2349732246 10000 2400 604800 3600"
	report := AnalyzeSOACompliance(soa, "Cloudflare")

	if !report.HasSOA {
		t.Fatal("expected HasSOA=true")
	}
	if report.PrimaryNS != "ada.ns.cloudflare.com" {
		t.Errorf("PrimaryNS = %q", report.PrimaryNS)
	}
	if report.Expire != 604800 {
		t.Errorf("Expire = %d, want 604800", report.Expire)
	}
	if !report.HasFindings() {
		t.Error("expected findings for Cloudflare SOA (expire below RFC 1912)")
	}

	foundExpire := false
	for _, f := range report.Findings {
		if f.Field == "Expire" {
			foundExpire = true
			if f.Severity != "warning" {
				t.Errorf("Expire severity = %q, want warning", f.Severity)
			}
		}
	}
	if !foundExpire {
		t.Error("expected Expire finding")
	}
}

func TestAnalyzeSOACompliance_CompliantSOA(t *testing.T) {
	soa := "ns1.example.com. admin.example.com. 2026022501 86400 7200 1209600 3600"
	report := AnalyzeSOACompliance(soa, "")

	if !report.HasSOA {
		t.Fatal("expected HasSOA=true")
	}
	if report.HasFindings() {
		t.Errorf("expected no findings for compliant SOA, got %d", len(report.Findings))
	}
}

func TestAnalyzeSOACompliance_BadExpire(t *testing.T) {
	soa := "ns1.bad.com. admin.bad.com. 1 10000 2400 86400 3600"
	report := AnalyzeSOACompliance(soa, "")

	if !report.HasFindings() {
		t.Fatal("expected findings for 86400s expire")
	}

	var found bool
	for _, f := range report.Findings {
		if f.Field == "Expire" {
			found = true
			if f.Severity != "error" {
				t.Errorf("severity = %q, want error for 1-day expire", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected Expire finding")
	}
}

func TestAnnotateFindingForProvider_CloudflareProxied(t *testing.T) {
	f := TTLFinding{
		RecordType:  "A",
		ObservedTTL: 300,
		TypicalTTL:  300,
	}
	AnnotateFindingForProvider(&f, "Cloudflare")
	if f.ProviderNote == "" {
		t.Error("expected provider note for Cloudflare proxied A record")
	}
}

func TestAnnotateFindingForProvider_Route53Alias(t *testing.T) {
	f := TTLFinding{
		RecordType:  "A",
		ObservedTTL: 60,
		TypicalTTL:  300,
	}
	AnnotateFindingForProvider(&f, "AWS Route 53")
	if f.ProviderNote == "" {
		t.Error("expected provider note for Route 53 alias A record")
	}
}

func TestAnnotateFindingForProvider_UnknownProvider(t *testing.T) {
	f := TTLFinding{
		RecordType:  "A",
		ObservedTTL: 300,
		TypicalTTL:  300,
	}
	AnnotateFindingForProvider(&f, "SomeProvider")
	if f.ProviderNote != "" {
		t.Errorf("expected no provider note for unknown provider, got %q", f.ProviderNote)
	}
}

func TestGetProviderProfile(t *testing.T) {
	p, ok := GetProviderProfile("Cloudflare")
	if !ok {
		t.Fatal("expected Cloudflare profile")
	}
	if len(p.Notes) == 0 {
		t.Error("expected compliance notes for Cloudflare")
	}
	if p.SOAExpire != 604800 {
		t.Errorf("SOAExpire = %d, want 604800", p.SOAExpire)
	}

	_, ok = GetProviderProfile("NonexistentProvider")
	if ok {
		t.Error("expected no profile for unknown provider")
	}
}
