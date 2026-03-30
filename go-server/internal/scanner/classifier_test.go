// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package scanner

import (
	"testing"
)

func TestClassify_KnownDomains(t *testing.T) {
	tests := []struct {
		domain string
		source string
	}{
		{"test.qualysperiscope.com", "Qualys Periscope"},
		{"payload.burpcollaborator.net", "Burp Collaborator"},
		{"abc123.oastify.com", "Burp Suite OAST"},
		{"test.interact.sh", "Interactsh"},
		{"probe.bxss.me", "Blind XSS Hunter"},
		{"token.canarytokens.com", "Canary Tokens"},
		{"dns.dnslog.cn", "DNSLog"},
		{"test.ceye.io", "CEYE"},
		{"scan.shodan.io", "Shodan"},
		{"host.censys.io", "Censys"},
	}

	for _, tt := range tests {
		c := Classify(tt.domain, "1.2.3.4")
		if !c.IsScan {
			t.Errorf("expected %q to be classified as scan", tt.domain)
		}
		if c.Source != tt.source {
			t.Errorf("expected source %q for %q, got %q", tt.source, tt.domain, c.Source)
		}
	}
}

func TestClassify_LegitDomains(t *testing.T) {
	legit := []string{
		"google.com",
		"example.org",
		"mail.yahoo.com",
		"dns-tool.com",
		"sec.gov",
	}

	for _, domain := range legit {
		c := Classify(domain, "1.2.3.4")
		if c.IsScan {
			t.Errorf("expected %q NOT to be classified as scan, got source=%q", domain, c.Source)
		}
	}
}

func TestClassify_HexHeuristic(t *testing.T) {
	deep := "abcdef1234567890.fedcba0987654321.sub.evil.example.com"
	c := Classify(deep, "1.2.3.4")
	if !c.IsScan {
		t.Errorf("expected deep hex domain to be flagged as scan")
	}

	short := "abc.example.com"
	c2 := Classify(short, "1.2.3.4")
	if c2.IsScan {
		t.Errorf("expected short domain NOT to be flagged")
	}
}
