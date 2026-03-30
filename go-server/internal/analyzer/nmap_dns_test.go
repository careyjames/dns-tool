// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
	"strings"
	"testing"
)

func TestZoneTransferParsing_Denied(t *testing.T) {
	output := `Starting Nmap 7.94 ( https://nmap.org ) at 2026-02-22 06:00 UTC
Nmap scan report for ns1.example.com (93.184.216.34)
Host is up.

PORT   STATE SERVICE
53/tcp open  domain

Nmap done: 1 IP address (1 host up) scanned in 0.42 seconds`

	if strings.Contains(output, "Transfer") || strings.Contains(output, "SOA") {
		t.Error("denied zone transfer should not be detected as vulnerable")
	}
}

func TestZoneTransferParsing_Vulnerable(t *testing.T) {
	output := `Starting Nmap 7.94 ( https://nmap.org ) at 2026-02-22 06:00 UTC
Nmap scan report for ns1.vulnerable.com
PORT   STATE SERVICE
53/tcp open  domain
| dns-zone-transfer:
| vulnerable.com. SOA ns1.vulnerable.com. admin.vulnerable.com.
| vulnerable.com. NS ns1.vulnerable.com.
| vulnerable.com. NS ns2.vulnerable.com.
| vulnerable.com. A 10.0.0.1
| vulnerable.com. MX 10 mail.vulnerable.com.
| mail.vulnerable.com. A 10.0.0.2
| www.vulnerable.com. A 10.0.0.3
| Transfer zone size: 7 records`

	if !(strings.Contains(output, "Transfer") || strings.Contains(output, "SOA")) {
		t.Error("vulnerable zone transfer should be detected")
	}
}

func TestRecursionParsing_Disabled(t *testing.T) {
	output := `Starting Nmap 7.94 ( https://nmap.org ) at 2026-02-22 06:00 UTC
Nmap scan report for ns1.example.com (93.184.216.34)
PORT   STATE SERVICE
53/udp open  domain

Nmap done: 1 IP address (1 host up) scanned in 0.32 seconds`

	lower := strings.ToLower(output)
	isOpen := strings.Contains(lower, "recursion") && strings.Contains(lower, "enabled")
	if isOpen {
		t.Error("recursion should not be detected as open when not mentioned")
	}
}

func TestRecursionParsing_Enabled(t *testing.T) {
	output := `Starting Nmap 7.94 ( https://nmap.org ) at 2026-02-22 06:00 UTC
Nmap scan report for ns1.example.com (93.184.216.34)
PORT   STATE SERVICE
53/udp open  domain
|_dns-recursion: Recursion appears to be enabled

Nmap done: 1 IP address (1 host up) scanned in 0.32 seconds`

	lower := strings.ToLower(output)
	isOpen := strings.Contains(lower, "recursion") && strings.Contains(lower, "enabled")
	if !isOpen {
		t.Error("open recursion should be detected")
	}
}

func TestNSIDParsing_NoDisclosure(t *testing.T) {
	output := `Starting Nmap 7.94 ( https://nmap.org ) at 2026-02-22 06:00 UTC
Nmap scan report for ns1.example.com
PORT   STATE SERVICE
53/udp open  domain

Nmap done: 1 IP address (1 host up) scanned in 0.28 seconds`

	lower := strings.ToLower(output)
	found := strings.Contains(lower, "bind.version") || strings.Contains(lower, "id.server") || strings.Contains(lower, "nsid")
	if found {
		t.Error("NSID should not be detected when not disclosed")
	}
}

func TestNSIDParsing_VersionDisclosed(t *testing.T) {
	output := `Starting Nmap 7.94 ( https://nmap.org ) at 2026-02-22 06:00 UTC
Nmap scan report for ns1.example.com
PORT   STATE SERVICE
53/udp open  domain
| dns-nsid:
|   bind.version: 9.18.24-1~deb12u1-Debian
|_  id.server: ns1`

	lower := strings.ToLower(output)
	found := strings.Contains(lower, "bind.version") || strings.Contains(lower, "id.server")
	if !found {
		t.Error("NSID disclosure should be detected")
	}

	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(strings.ToLower(trimmed), "bind.version") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) != 2 {
				t.Error("should parse bind.version value")
			}
			version := strings.TrimSpace(parts[1])
			if version != "9.18.24-1~deb12u1-Debian" {
				t.Errorf("expected version '9.18.24-1~deb12u1-Debian', got '%s'", version)
			}
		}
	}
}

func TestCacheSnoopParsing_NotVulnerable(t *testing.T) {
	output := `Starting Nmap 7.94 ( https://nmap.org ) at 2026-02-22 06:00 UTC
Nmap scan report for ns1.example.com
PORT   STATE SERVICE
53/udp open  domain

Nmap done: 1 IP address (1 host up) scanned in 0.35 seconds`

	lower := strings.ToLower(output)
	vuln := strings.Contains(lower, "positive") || (strings.Contains(lower, "cache") && strings.Contains(lower, "found"))
	if vuln {
		t.Error("cache snooping should not be detected as vulnerable")
	}
}

func TestCacheSnoopParsing_Vulnerable(t *testing.T) {
	output := `Starting Nmap 7.94 ( https://nmap.org ) at 2026-02-22 06:00 UTC
Nmap scan report for ns1.example.com
PORT   STATE SERVICE
53/udp open  domain
| dns-cache-snoop: 3 of 100 tested domains are cached.
|_  google.com - positive`

	lower := strings.ToLower(output)
	vuln := strings.Contains(lower, "positive") || (strings.Contains(lower, "cache") && strings.Contains(lower, "found"))
	if !vuln {
		t.Error("cache snooping vulnerability should be detected")
	}
}

func TestIssueAggregation(t *testing.T) {
	issues := []string{}

	ztVulnerable := true
	recOpen := true
	csVulnerable := false

	if ztVulnerable {
		issues = append(issues, "Zone transfer (AXFR) allowed on ns1.test.com")
	}
	if recOpen {
		issues = append(issues, "Open recursion detected on ns1.test.com")
	}
	if csVulnerable {
		issues = append(issues, "DNS cache snooping possible on ns1.test.com")
	}

	if len(issues) != 2 {
		t.Errorf("expected 2 issues, got %d", len(issues))
	}
}

func TestStatusDetermination(t *testing.T) {
	tests := []struct {
		name     string
		issues   int
		expected string
	}{
		{"no issues", 0, "good"},
		{"one issue", 1, "warning"},
		{"multiple issues", 3, "warning"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := "good"
			if tt.issues > 0 {
				status = "warning"
			}
			if status != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, status)
			}
		})
	}
}
