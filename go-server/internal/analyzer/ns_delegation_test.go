package analyzer

import (
	"testing"
)

func TestNormalizeNSList(t *testing.T) {
	tests := []struct {
		name   string
		input  []string
		expect []string
	}{
		{"empty", nil, nil},
		{"trims dots and lowercases", []string{"NS1.Example.COM.", "ns2.example.com"}, []string{"ns1.example.com", "ns2.example.com"}},
		{"filters empty strings", []string{"ns1.example.com", "", "ns2.example.com"}, []string{"ns1.example.com", "ns2.example.com"}},
		{"sorts alphabetically", []string{"z.example.com", "a.example.com"}, []string{"a.example.com", "z.example.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeNSList(tt.input)
			if len(got) != len(tt.expect) {
				t.Fatalf("normalizeNSList() returned %d items, want %d", len(got), len(tt.expect))
			}
			for i := range got {
				if got[i] != tt.expect[i] {
					t.Errorf("normalizeNSList()[%d] = %q, want %q", i, got[i], tt.expect[i])
				}
			}
		})
	}
}

func TestParentZoneFromDomain(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		{"sub.example.com", "example.com"},
		{"example.com", "com"},
		{"com", ""},
		{"a.b.c.d.example.com", "b.c.d.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := parentZoneFromDomain(tt.domain)
			if got != tt.want {
				t.Errorf("parentZoneFromDomain(%q) = %q, want %q", tt.domain, got, tt.want)
			}
		})
	}
}

func TestClassifyNSProvider(t *testing.T) {
	tests := []struct {
		ns   string
		want string
	}{
		{"ns-123.awsdns-45.com", "Amazon Route 53"},
		{"coco.cloudflare.com", "Cloudflare"},
		{"ns1.domaincontrol.com", "GoDaddy"},
		{"dns1.registrar-servers.com", "Namecheap"},
		{"ns.azure-dns.com", "Microsoft Azure DNS"},
		{"unknown-ns.custom.org", ""},
		{"ns1.google.com", "Google Cloud DNS"},
	}
	for _, tt := range tests {
		t.Run(tt.ns, func(t *testing.T) {
			got := classifyNSProvider(tt.ns)
			if got != tt.want {
				t.Errorf("classifyNSProvider(%q) = %q, want %q", tt.ns, got, tt.want)
			}
		})
	}
}

func TestRegistrableDomain(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		{"example.com", "example.com"},
		{"sub.example.com", "example.com"},
		{"deep.sub.example.com", "example.com"},
		{"example.co.uk", "example.co.uk"},
		{"sub.example.co.uk", "example.co.uk"},
		{"com", ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := registrableDomain(tt.domain)
			if got != tt.want {
				t.Errorf("registrableDomain(%q) = %q, want %q", tt.domain, got, tt.want)
			}
		})
	}
}

func TestStringSetEqual(t *testing.T) {
	tests := []struct {
		name string
		a    []string
		b    []string
		want bool
	}{
		{"equal same order", []string{"a", "b"}, []string{"a", "b"}, true},
		{"equal diff order", []string{"b", "a"}, []string{"a", "b"}, true},
		{"different length", []string{"a"}, []string{"a", "b"}, false},
		{"different content", []string{"a", "c"}, []string{"a", "b"}, false},
		{"both empty", []string{}, []string{}, true},
		{"both nil", nil, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stringSetEqual(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("stringSetEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNsDelegationResult(t *testing.T) {
	result := nsDelegationResult("success", "test message", []string{"ns1.example.com"}, []string{"ns1.example.com"}, true, true, map[string]any{"extra": "val"})
	if result["status"] != "success" {
		t.Errorf("status = %v, want success", result["status"])
	}
	if result["message"] != "test message" {
		t.Errorf("message = %v, want test message", result["message"])
	}
	if result["delegation_ok"] != true {
		t.Error("delegation_ok should be true")
	}
	if result["extra"] != "val" {
		t.Error("extra key should be set from extras map")
	}
}

func TestNsDelegationResult_NilSlices(t *testing.T) {
	result := nsDelegationResult("error", "msg", nil, nil, false, false, nil)
	childNS, ok := result["child_ns"].([]string)
	if !ok || childNS == nil {
		t.Error("child_ns should be non-nil empty slice")
	}
	parentNS, ok := result["parent_ns"].([]string)
	if !ok || parentNS == nil {
		t.Error("parent_ns should be non-nil empty slice")
	}
}

func TestClassifyEnterpriseDNS(t *testing.T) {
	tests := []struct {
		name        string
		domain      string
		nameservers []string
		wantPattern string
	}{
		{
			"empty nameservers",
			"example.com",
			nil,
			"",
		},
		{
			"all managed single provider",
			"example.com",
			[]string{"ns-123.awsdns-45.com", "ns-456.awsdns-78.net"},
			"managed",
		},
		{
			"all dedicated",
			"example.com",
			[]string{"ns1.example.com", "ns2.example.com"},
			"dedicated",
		},
		{
			"mixed dedicated and managed",
			"example.com",
			[]string{"ns1.example.com", "ns-123.awsdns-45.com"},
			"mixed",
		},
		{
			"multi-provider",
			"example.com",
			[]string{"ns-123.awsdns-45.com", "ns1.cloudflare.com"},
			"multi-provider",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifyEnterpriseDNS(tt.domain, tt.nameservers)
			if tt.wantPattern == "" {
				if result != nil {
					t.Errorf("expected nil result for empty nameservers")
				}
				return
			}
			if result == nil {
				t.Fatal("expected non-nil result")
			}
			gotPattern, _ := result[mapKeyEnterprisePattern].(string)
			if gotPattern != tt.wantPattern {
				t.Errorf("enterprise_pattern = %q, want %q", gotPattern, tt.wantPattern)
			}
		})
	}
}
