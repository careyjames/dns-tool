package analyzer

import (
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

func TestClassifyCDSAutomation(t *testing.T) {
	tests := []struct {
		name    string
		cds     []*dns.CDS
		cdnskey []*dns.CDNSKEY
		want    string
	}{
		{"none", nil, nil, "none"},
		{"cds only", []*dns.CDS{{DS: dns.DS{DS: rdata.DS{KeyTag: 12345, Algorithm: 13, DigestType: 2}}}}, nil, "cds_only"},
		{"cdnskey only", nil, []*dns.CDNSKEY{{DNSKEY: dns.DNSKEY{DNSKEY: rdata.DNSKEY{Flags: 257, Protocol: 3, Algorithm: 13}}}}, "cdnskey_only"},
		{"full automation",
			[]*dns.CDS{{DS: dns.DS{DS: rdata.DS{KeyTag: 12345, Algorithm: 13, DigestType: 2}}}},
			[]*dns.CDNSKEY{{DNSKEY: dns.DNSKEY{DNSKEY: rdata.DNSKEY{Flags: 257, Protocol: 3, Algorithm: 13}}}},
			"full_automation"},
		{"cds delete signal", []*dns.CDS{{DS: dns.DS{DS: rdata.DS{KeyTag: 0, Algorithm: 0, DigestType: 0}}}}, nil, "delete_signaled"},
		{"cdnskey delete signal", nil, []*dns.CDNSKEY{{DNSKEY: dns.DNSKEY{DNSKEY: rdata.DNSKEY{Flags: 0, Protocol: 3, Algorithm: 0}}}}, "delete_signaled"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyCDSAutomation(tt.cds, tt.cdnskey)
			if got != tt.want {
				t.Errorf("classifyCDSAutomation() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildCDSMessage(t *testing.T) {
	tests := []struct {
		name       string
		automation string
		wantSub    string
	}{
		{"full automation", "full_automation", "Full RFC 8078"},
		{"cds only", "cds_only", "CDS records present"},
		{"cdnskey only", "cdnskey_only", "CDNSKEY records present"},
		{"delete signaled", "delete_signaled", "DNSSEC deletion signaled"},
		{"none", "none", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := map[string]any{"automation": tt.automation}
			got := buildCDSMessage(result)
			if tt.wantSub == "" && got != "" {
				t.Errorf("expected empty, got %q", got)
			}
			if tt.wantSub != "" && !strings.Contains(got, tt.wantSub) {
				t.Errorf("buildCDSMessage() = %q, want substring %q", got, tt.wantSub)
			}
		})
	}
}
