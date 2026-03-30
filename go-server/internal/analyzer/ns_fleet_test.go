// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
	"strings"
	"testing"
)

func TestExtractPrefix24(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected string
	}{
		{"valid IPv4", "192.168.1.100", "192.168.1.0/24"},
		{"another valid", "10.0.0.1", "10.0.0.0/24"},
		{"public IP", "93.184.216.34", "93.184.216.0/24"},
		{"invalid short", "192.168.1", ""},
		{"empty", "", ""},
		{"IPv6 address", "2001:db8::1", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractPrefix24(tt.ip)
			if got != tt.expected {
				t.Errorf("extractPrefix24(%q) = %q, want %q", tt.ip, got, tt.expected)
			}
		})
	}
}

func TestComputeDiversityScore(t *testing.T) {
	tests := []struct {
		name           string
		uniqueASNs     int
		uniqueOps      int
		uniquePrefixes int
		totalNS        int
		wantScore      string
	}{
		{"no nameservers", 0, 0, 0, 0, "unknown"},
		{"excellent diversity", 3, 2, 3, 4, "excellent"},
		{"good diversity", 2, 1, 2, 3, "good"},
		{"fair diversity", 2, 1, 1, 2, "fair"},
		{"poor diversity", 1, 1, 1, 4, "poor"},
		{"excellent high count", 4, 3, 5, 6, "excellent"},
		{"fair single ASN two prefixes", 1, 1, 2, 2, "fair"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, _ := computeDiversityScore(tt.uniqueASNs, tt.uniqueOps, tt.uniquePrefixes, tt.totalNS)
			if score != tt.wantScore {
				t.Errorf("computeDiversityScore(%d,%d,%d,%d) score = %q, want %q",
					tt.uniqueASNs, tt.uniqueOps, tt.uniquePrefixes, tt.totalNS, score, tt.wantScore)
			}
		})
	}
}

func TestCheckSerialConsensus(t *testing.T) {
	tests := []struct {
		name    string
		entries []NSFleetEntry
		want    bool
	}{
		{
			"empty",
			[]NSFleetEntry{},
			true,
		},
		{
			"single entry",
			[]NSFleetEntry{{SOASerial: 2024010101, SOASerialOK: true}},
			true,
		},
		{
			"all match",
			[]NSFleetEntry{
				{SOASerial: 2024010101, SOASerialOK: true},
				{SOASerial: 2024010101, SOASerialOK: true},
				{SOASerial: 2024010101, SOASerialOK: true},
			},
			true,
		},
		{
			"mismatch",
			[]NSFleetEntry{
				{SOASerial: 2024010101, SOASerialOK: true},
				{SOASerial: 2024010102, SOASerialOK: true},
			},
			false,
		},
		{
			"skip entries without serial",
			[]NSFleetEntry{
				{SOASerial: 2024010101, SOASerialOK: true},
				{SOASerial: 0, SOASerialOK: false},
				{SOASerial: 2024010101, SOASerialOK: true},
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkSerialConsensus(tt.entries)
			if got != tt.want {
				t.Errorf("checkSerialConsensus() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScoreFleetDiversity(t *testing.T) {
	entries := []NSFleetEntry{
		{ASN: "13335", ASName: "Cloudflare, Inc.", IPv4: []string{"104.18.1.1"}},
		{ASN: "13335", ASName: "Cloudflare, Inc.", IPv4: []string{"104.18.1.2"}},
		{ASN: "15169", ASName: "Google LLC", IPv4: []string{"216.239.32.10"}},
	}

	d := scoreFleetDiversity(entries)
	if d.UniqueASNs != 2 {
		t.Errorf("UniqueASNs = %d, want 2", d.UniqueASNs)
	}
	if d.UniqueOperators != 2 {
		t.Errorf("UniqueOperators = %d, want 2", d.UniqueOperators)
	}
	if d.UniquePrefix24s != 2 {
		t.Errorf("UniquePrefix24s = %d, want 2", d.UniquePrefix24s)
	}
}

func TestScoreFleetDiversity_SingleProvider(t *testing.T) {
	entries := []NSFleetEntry{
		{ASN: "13335", ASName: "Cloudflare, Inc.", IPv4: []string{"104.18.1.1"}},
		{ASN: "13335", ASName: "Cloudflare, Inc.", IPv4: []string{"104.18.1.2"}},
	}

	d := scoreFleetDiversity(entries)
	if d.UniqueASNs != 1 {
		t.Errorf("UniqueASNs = %d, want 1", d.UniqueASNs)
	}
	if d.Score != "poor" {
		t.Errorf("Score = %q, want 'poor'", d.Score)
	}
}

func TestCollectFleetIssues_LameDelegation(t *testing.T) {
	entries := []NSFleetEntry{
		{Hostname: "ns1.example.com", IPv4: []string{"1.2.3.4"}, UDPReach: true, AAFlag: true, IsLame: false, SOASerial: 100, SOASerialOK: true},
		{Hostname: "ns2.example.com", IPv4: []string{"5.6.7.8"}, UDPReach: true, AAFlag: false, IsLame: true, SOASerial: 100, SOASerialOK: true},
	}
	diversity := scoreFleetDiversity(entries)
	issues := collectFleetIssues(entries, diversity, true)

	found := false
	for _, issue := range issues {
		if strings.Contains(issue, "lame delegation") {
			found = true
		}
	}
	if !found {
		t.Error("expected lame delegation issue for ns2.example.com")
	}
}

func TestCollectFleetIssues_NoIPs(t *testing.T) {
	entries := []NSFleetEntry{
		{Hostname: "ns1.gone.example.com", IPv4: []string{}, IPv6: []string{}},
	}
	diversity := scoreFleetDiversity(entries)
	issues := collectFleetIssues(entries, diversity, true)

	found := false
	for _, issue := range issues {
		if strings.Contains(issue, "no IP addresses") {
			found = true
		}
	}
	if !found {
		t.Error("expected 'no IP addresses' issue")
	}
}

func TestCollectFleetIssues_UDPUnreachable(t *testing.T) {
	entries := []NSFleetEntry{
		{Hostname: "ns1.example.com", IPv4: []string{"1.2.3.4"}, UDPReach: false, TCPReach: true, AAFlag: false, SOASerial: 0, SOASerialOK: false},
	}
	diversity := scoreFleetDiversity(entries)
	issues := collectFleetIssues(entries, diversity, true)

	found := false
	for _, issue := range issues {
		if strings.Contains(issue, "UDP unreachable") {
			found = true
		}
	}
	if !found {
		t.Error("expected UDP unreachable issue")
	}
}

func TestCollectFleetIssues_SerialMismatch(t *testing.T) {
	entries := []NSFleetEntry{
		{Hostname: "ns1.example.com", IPv4: []string{"1.2.3.4"}, UDPReach: true, AAFlag: true, SOASerial: 100, SOASerialOK: true},
		{Hostname: "ns2.example.com", IPv4: []string{"5.6.7.8"}, UDPReach: true, AAFlag: true, SOASerial: 99, SOASerialOK: true},
	}
	diversity := scoreFleetDiversity(entries)
	serialOK := checkSerialConsensus(entries)
	issues := collectFleetIssues(entries, diversity, serialOK)

	found := false
	for _, issue := range issues {
		if strings.Contains(issue, "SOA serial") {
			found = true
		}
	}
	if !found {
		t.Error("expected SOA serial mismatch issue")
	}
}

func TestCollectFleetIssues_NetworkRestricted(t *testing.T) {
	entries := []NSFleetEntry{
		{Hostname: "a.gtld-servers.net", IPv4: []string{"192.5.6.30"}, UDPReach: false, TCPReach: false},
		{Hostname: "b.gtld-servers.net", IPv4: []string{"192.33.14.30"}, UDPReach: false, TCPReach: false},
		{Hostname: "c.gtld-servers.net", IPv4: []string{"192.26.92.30"}, UDPReach: false, TCPReach: false},
	}
	diversity := scoreFleetDiversity(entries)
	issues := collectFleetIssues(entries, diversity, true)

	networkRestricted := false
	for _, issue := range issues {
		if strings.Contains(issue, "scanning environment") {
			networkRestricted = true
		}
		if strings.Contains(issue, "UDP unreachable") || strings.Contains(issue, "TCP unreachable") {
			t.Error("should not list individual unreachable issues when network is restricted")
		}
	}
	if !networkRestricted {
		t.Error("expected network restriction notice when all nameservers fail both UDP and TCP")
	}
}

func TestCollectFleetIssues_PartialUnreachable(t *testing.T) {
	entries := []NSFleetEntry{
		{Hostname: "ns1.example.com", IPv4: []string{"1.2.3.4"}, UDPReach: true, TCPReach: true},
		{Hostname: "ns2.example.com", IPv4: []string{"5.6.7.8"}, UDPReach: false, TCPReach: false},
	}
	diversity := scoreFleetDiversity(entries)
	issues := collectFleetIssues(entries, diversity, true)

	hasUDP := false
	hasNetworkRestricted := false
	for _, issue := range issues {
		if strings.Contains(issue, "UDP unreachable") {
			hasUDP = true
		}
		if strings.Contains(issue, "scanning environment") {
			hasNetworkRestricted = true
		}
	}
	if !hasUDP {
		t.Error("expected individual unreachable issues when only some nameservers fail")
	}
	if hasNetworkRestricted {
		t.Error("should not show network restriction notice when some nameservers are reachable")
	}
}

func TestNSFleetToMap(t *testing.T) {
	result := NSFleetResult{
		Status:          "success",
		Message:         "Analyzed 2 nameserver(s)",
		SerialConsensus: true,
		Issues:          []string{},
		Nameservers: []NSFleetEntry{
			{Hostname: "ns1.example.com", IPv4: []string{"1.2.3.4"}, IPv6: []string{}, ASN: "13335", UDPReach: true, TCPReach: true, AAFlag: true},
		},
		Diversity: FleetDiversity{
			UniqueASNs:      1,
			UniqueOperators: 1,
			UniquePrefix24s: 1,
			Score:           "poor",
			ScoreDetail:     "test",
		},
	}

	m := nsFleetToMap(result)
	if m["status"] != "success" {
		t.Errorf("status = %v, want 'success'", m["status"])
	}
	ns, ok := m["nameservers"].([]map[string]any)
	if !ok || len(ns) != 1 {
		t.Error("expected 1 nameserver entry in map")
	}
	div, ok := m["diversity"].(map[string]any)
	if !ok {
		t.Error("expected diversity map")
	}
	if div["score"] != "poor" {
		t.Errorf("diversity score = %v, want 'poor'", div["score"])
	}
}

func TestFirstIP(t *testing.T) {
	tests := []struct {
		name string
		ipv4 []string
		ipv6 []string
		want string
	}{
		{"ipv4 first", []string{"1.2.3.4", "5.6.7.8"}, []string{"2001:db8::1"}, "1.2.3.4"},
		{"ipv6 fallback", []string{}, []string{"2001:db8::1", "2001:db8::2"}, "2001:db8::1"},
		{"both empty", []string{}, []string{}, ""},
		{"nil slices", nil, nil, ""},
		{"ipv4 nil ipv6 present", nil, []string{"::1"}, "::1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := firstIP(tt.ipv4, tt.ipv6)
			if got != tt.want {
				t.Errorf("firstIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDetectNetworkRestriction(t *testing.T) {
	tests := []struct {
		name           string
		entries        []NSFleetEntry
		wantResolved   int
		wantRestricted bool
	}{
		{
			"empty entries",
			[]NSFleetEntry{},
			0, false,
		},
		{
			"all unreachable with IPs",
			[]NSFleetEntry{
				{IPv4: []string{"1.2.3.4"}, UDPReach: false, TCPReach: false},
				{IPv4: []string{"5.6.7.8"}, UDPReach: false, TCPReach: false},
			},
			2, true,
		},
		{
			"some reachable",
			[]NSFleetEntry{
				{IPv4: []string{"1.2.3.4"}, UDPReach: true, TCPReach: true},
				{IPv4: []string{"5.6.7.8"}, UDPReach: false, TCPReach: false},
			},
			2, false,
		},
		{
			"single unreachable not restricted",
			[]NSFleetEntry{
				{IPv4: []string{"1.2.3.4"}, UDPReach: false, TCPReach: false},
			},
			1, false,
		},
		{
			"no IPs resolved",
			[]NSFleetEntry{
				{IPv4: []string{}, IPv6: []string{}},
				{IPv4: []string{}, IPv6: []string{}},
			},
			0, false,
		},
		{
			"ipv6 only unreachable",
			[]NSFleetEntry{
				{IPv6: []string{"2001:db8::1"}, UDPReach: false, TCPReach: false},
				{IPv6: []string{"2001:db8::2"}, UDPReach: false, TCPReach: false},
			},
			2, true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolved, restricted := detectNetworkRestriction(tt.entries)
			if resolved != tt.wantResolved {
				t.Errorf("resolvedCount = %d, want %d", resolved, tt.wantResolved)
			}
			if restricted != tt.wantRestricted {
				t.Errorf("networkRestricted = %v, want %v", restricted, tt.wantRestricted)
			}
		})
	}
}

func TestCollectPerEntryIssues(t *testing.T) {
	t.Run("no IPs", func(t *testing.T) {
		entries := []NSFleetEntry{
			{Hostname: "ns1.example.com", IPv4: []string{}, IPv6: []string{}},
		}
		issues := collectPerEntryIssues(entries, false)
		if len(issues) == 0 {
			t.Error("expected issue for no IP addresses")
		}
	})

	t.Run("lame delegation", func(t *testing.T) {
		entries := []NSFleetEntry{
			{Hostname: "ns1.example.com", IPv4: []string{"1.2.3.4"}, IsLame: true, UDPReach: true},
		}
		issues := collectPerEntryIssues(entries, false)
		found := false
		for _, i := range issues {
			if strings.Contains(i, "lame delegation") {
				found = true
			}
		}
		if !found {
			t.Error("expected lame delegation issue")
		}
	})

	t.Run("skips reachability when network restricted", func(t *testing.T) {
		entries := []NSFleetEntry{
			{Hostname: "ns1.example.com", IPv4: []string{"1.2.3.4"}, UDPReach: false, TCPReach: false},
		}
		issues := collectPerEntryIssues(entries, true)
		for _, i := range issues {
			if strings.Contains(i, "UDP unreachable") || strings.Contains(i, "TCP unreachable") {
				t.Error("should skip reachability issues when network restricted")
			}
		}
	})

	t.Run("reports UDP and TCP unreachable", func(t *testing.T) {
		entries := []NSFleetEntry{
			{Hostname: "ns1.example.com", IPv4: []string{"1.2.3.4"}, UDPReach: false, TCPReach: false},
		}
		issues := collectPerEntryIssues(entries, false)
		hasUDP, hasTCP := false, false
		for _, i := range issues {
			if strings.Contains(i, "UDP unreachable") {
				hasUDP = true
			}
			if strings.Contains(i, "TCP unreachable") {
				hasTCP = true
			}
		}
		if !hasUDP {
			t.Error("expected UDP unreachable issue")
		}
		if !hasTCP {
			t.Error("expected TCP unreachable issue")
		}
	})
}

func TestCollectSerialInconsistencyIssues(t *testing.T) {
	t.Run("consistent serials", func(t *testing.T) {
		entries := []NSFleetEntry{
			{Hostname: "ns1.example.com", SOASerial: 100, SOASerialOK: true},
			{Hostname: "ns2.example.com", SOASerial: 100, SOASerialOK: true},
		}
		issues := collectSerialInconsistencyIssues(entries)
		if len(issues) != 1 {
			t.Errorf("expected 1 serial group, got %d", len(issues))
		}
	})

	t.Run("inconsistent serials", func(t *testing.T) {
		entries := []NSFleetEntry{
			{Hostname: "ns1.example.com", SOASerial: 100, SOASerialOK: true},
			{Hostname: "ns2.example.com", SOASerial: 200, SOASerialOK: true},
		}
		issues := collectSerialInconsistencyIssues(entries)
		if len(issues) != 2 {
			t.Errorf("expected 2 serial groups, got %d", len(issues))
		}
	})

	t.Run("skips entries without serial", func(t *testing.T) {
		entries := []NSFleetEntry{
			{Hostname: "ns1.example.com", SOASerial: 100, SOASerialOK: true},
			{Hostname: "ns2.example.com", SOASerial: 0, SOASerialOK: false},
		}
		issues := collectSerialInconsistencyIssues(entries)
		if len(issues) != 1 {
			t.Errorf("expected 1 serial group, got %d", len(issues))
		}
	})

	t.Run("empty entries", func(t *testing.T) {
		issues := collectSerialInconsistencyIssues([]NSFleetEntry{})
		if len(issues) != 0 {
			t.Errorf("expected 0 issues, got %d", len(issues))
		}
	})
}

func TestCollectFleetIssues_Clean(t *testing.T) {
	entries := []NSFleetEntry{
		{Hostname: "ns1.example.com", IPv4: []string{"1.2.3.4"}, UDPReach: true, TCPReach: true, AAFlag: true, SOASerial: 100, SOASerialOK: true, ASN: "13335"},
		{Hostname: "ns2.example.com", IPv4: []string{"5.6.7.8"}, UDPReach: true, TCPReach: true, AAFlag: true, SOASerial: 100, SOASerialOK: true, ASN: "15169"},
	}
	diversity := FleetDiversity{UniqueASNs: 2, UniqueOperators: 2, UniquePrefix24s: 2, Score: "good"}
	issues := collectFleetIssues(entries, diversity, true)

	if len(issues) != 0 {
		t.Errorf("expected 0 issues for clean fleet, got %d: %v", len(issues), issues)
	}
}

func TestScoreFleetDiversity_Empty(t *testing.T) {
	d := scoreFleetDiversity([]NSFleetEntry{})
	if d.UniqueASNs != 0 {
		t.Errorf("UniqueASNs = %d, want 0", d.UniqueASNs)
	}
	if d.UniqueOperators != 0 {
		t.Errorf("UniqueOperators = %d, want 0", d.UniqueOperators)
	}
	if d.UniquePrefix24s != 0 {
		t.Errorf("UniquePrefix24s = %d, want 0", d.UniquePrefix24s)
	}
	if d.Score != "unknown" {
		t.Errorf("Score = %q, want unknown", d.Score)
	}
}

func TestScoreFleetDiversity_NoASNInfo(t *testing.T) {
	entries := []NSFleetEntry{
		{Hostname: "ns1.example.com", IPv4: []string{"1.2.3.4"}},
		{Hostname: "ns2.example.com", IPv4: []string{"5.6.7.8"}},
	}
	d := scoreFleetDiversity(entries)
	if d.UniqueASNs != 0 {
		t.Errorf("UniqueASNs = %d, want 0", d.UniqueASNs)
	}
	if d.UniquePrefix24s != 2 {
		t.Errorf("UniquePrefix24s = %d, want 2", d.UniquePrefix24s)
	}
}

func TestScoreFleetDiversity_IPv6Only(t *testing.T) {
	entries := []NSFleetEntry{
		{ASN: "13335", ASName: "Cloudflare", IPv6: []string{"2001:db8::1"}},
		{ASN: "15169", ASName: "Google", IPv6: []string{"2001:db8::2"}},
	}
	d := scoreFleetDiversity(entries)
	if d.UniqueASNs != 2 {
		t.Errorf("UniqueASNs = %d, want 2", d.UniqueASNs)
	}
	if d.UniquePrefix24s != 0 {
		t.Errorf("UniquePrefix24s = %d, want 0 (IPv6 not counted)", d.UniquePrefix24s)
	}
}

func TestComputeDiversityScore_Detail(t *testing.T) {
	tests := []struct {
		name         string
		asns         int
		ops          int
		prefixes     int
		total        int
		wantScore    string
		wantNonEmpty bool
	}{
		{"excellent includes counts", 3, 2, 3, 4, "excellent", true},
		{"good includes counts", 2, 1, 2, 3, "good", true},
		{"fair includes counts", 2, 1, 1, 2, "fair", true},
		{"poor includes total", 1, 1, 1, 4, "poor", true},
		{"unknown no detail", 0, 0, 0, 0, "unknown", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, detail := computeDiversityScore(tt.asns, tt.ops, tt.prefixes, tt.total)
			if score != tt.wantScore {
				t.Errorf("score = %q, want %q", score, tt.wantScore)
			}
			if tt.wantNonEmpty && detail == "" {
				t.Error("expected non-empty detail string")
			}
		})
	}
}

func TestNSFleetToMap_EmptyNameservers(t *testing.T) {
	result := NSFleetResult{
		Status:          "info",
		Message:         "No NS records found",
		SerialConsensus: true,
		Issues:          []string{},
		Nameservers:     []NSFleetEntry{},
		Diversity:       FleetDiversity{Score: "unknown"},
	}
	m := nsFleetToMap(result)
	if m["status"] != "info" {
		t.Errorf("status = %v, want info", m["status"])
	}
	ns, ok := m["nameservers"].([]map[string]any)
	if !ok {
		t.Fatal("expected nameservers to be []map[string]any")
	}
	if len(ns) != 0 {
		t.Errorf("expected 0 nameservers, got %d", len(ns))
	}
}

func TestNSFleetToMap_AllFields(t *testing.T) {
	result := NSFleetResult{
		Status:  "warning",
		Message: "test",
		Nameservers: []NSFleetEntry{
			{
				Hostname:    "ns1.example.com",
				IPv4:        []string{"1.2.3.4"},
				IPv6:        []string{"2001:db8::1"},
				ASN:         "13335",
				ASName:      "Cloudflare",
				Prefix:      "1.2.3.0/24",
				UDPReach:    true,
				TCPReach:    false,
				AAFlag:      true,
				IsLame:      false,
				SOASerial:   2024010101,
				SOASerialOK: true,
			},
		},
		Diversity:       FleetDiversity{UniqueASNs: 1, Score: "poor", ScoreDetail: "detail"},
		SerialConsensus: false,
		Issues:          []string{"issue1"},
	}
	m := nsFleetToMap(result)
	ns := m["nameservers"].([]map[string]any)
	entry := ns[0]
	if entry["hostname"] != "ns1.example.com" {
		t.Errorf("hostname = %v", entry["hostname"])
	}
	if entry["udp_reachable"] != true {
		t.Errorf("udp_reachable = %v", entry["udp_reachable"])
	}
	if entry["tcp_reachable"] != false {
		t.Errorf("tcp_reachable = %v", entry["tcp_reachable"])
	}
	if entry["aa_flag"] != true {
		t.Errorf("aa_flag = %v", entry["aa_flag"])
	}
	if entry["soa_serial"] != uint32(2024010101) {
		t.Errorf("soa_serial = %v", entry["soa_serial"])
	}
	if m["serial_consensus"] != false {
		t.Errorf("serial_consensus = %v", m["serial_consensus"])
	}
}

func TestCollectFleetIssues_PoorDiversity(t *testing.T) {
	entries := []NSFleetEntry{
		{Hostname: "ns1.example.com", IPv4: []string{"1.2.3.4"}, UDPReach: true, TCPReach: true, AAFlag: true, SOASerial: 100, SOASerialOK: true},
	}
	diversity := FleetDiversity{UniqueASNs: 1, UniqueOperators: 1, UniquePrefix24s: 1, Score: "poor"}
	issues := collectFleetIssues(entries, diversity, true)

	found := false
	for _, issue := range issues {
		if strings.Contains(issue, "Low nameserver diversity") {
			found = true
		}
	}
	if !found {
		t.Error("expected low diversity issue for poor score")
	}
}

func TestCheckSerialConsensus_AllWithoutSerial(t *testing.T) {
	entries := []NSFleetEntry{
		{SOASerial: 0, SOASerialOK: false},
		{SOASerial: 0, SOASerialOK: false},
	}
	if !checkSerialConsensus(entries) {
		t.Error("expected consensus when no serials are valid")
	}
}

func TestScoreFleetDiversity_MixedASNs(t *testing.T) {
	entries := []NSFleetEntry{
		{ASN: "13335", ASName: "Cloudflare, Inc.", IPv4: []string{"104.18.1.1"}},
		{ASN: "15169", ASName: "Google LLC", IPv4: []string{"216.239.32.10"}},
		{ASN: "16509", ASName: "Amazon.com, Inc.", IPv4: []string{"205.251.192.1"}},
	}
	d := scoreFleetDiversity(entries)
	if d.UniqueASNs != 3 {
		t.Errorf("UniqueASNs = %d, want 3", d.UniqueASNs)
	}
	if d.UniqueOperators != 3 {
		t.Errorf("UniqueOperators = %d, want 3", d.UniqueOperators)
	}
	if d.UniquePrefix24s != 3 {
		t.Errorf("UniquePrefix24s = %d, want 3", d.UniquePrefix24s)
	}
	if d.Score != "excellent" {
		t.Errorf("Score = %q, want excellent", d.Score)
	}
}

func TestCollectFleetIssues_TCPUnreachable(t *testing.T) {
	entries := []NSFleetEntry{
		{Hostname: "ns1.example.com", IPv4: []string{"1.2.3.4"}, UDPReach: true, TCPReach: false, AAFlag: true, SOASerial: 100, SOASerialOK: true},
	}
	diversity := scoreFleetDiversity(entries)
	issues := collectFleetIssues(entries, diversity, true)

	found := false
	for _, issue := range issues {
		if strings.Contains(issue, "TCP unreachable") {
			found = true
		}
	}
	if !found {
		t.Error("expected TCP unreachable issue")
	}
}

func TestNSFleetToMap_VerifyDiversityFields(t *testing.T) {
	result := NSFleetResult{
		Status:          "success",
		Message:         "test",
		Nameservers:     []NSFleetEntry{},
		SerialConsensus: true,
		Issues:          []string{},
		Diversity: FleetDiversity{
			UniqueASNs:      3,
			UniqueOperators: 2,
			UniquePrefix24s: 4,
			ASNList:         []string{"13335", "15169", "16509"},
			OperatorList:    []string{"Cloudflare", "Google"},
			Score:           "excellent",
			ScoreDetail:     "3 ASNs, 2 operators, 4 /24 prefixes across 4 nameservers",
		},
	}
	m := nsFleetToMap(result)
	div := m["diversity"].(map[string]any)
	if div["unique_asns"] != 3 {
		t.Errorf("unique_asns = %v, want 3", div["unique_asns"])
	}
	if div["unique_operators"] != 2 {
		t.Errorf("unique_operators = %v, want 2", div["unique_operators"])
	}
	if div["unique_prefix24s"] != 4 {
		t.Errorf("unique_prefix24s = %v, want 4", div["unique_prefix24s"])
	}
	if div["score"] != "excellent" {
		t.Errorf("score = %v, want excellent", div["score"])
	}
	if div["score_detail"] == nil || div["score_detail"] == "" {
		t.Error("score_detail should not be empty")
	}
	asnList := div["asn_list"].([]string)
	if len(asnList) != 3 {
		t.Errorf("asn_list length = %d, want 3", len(asnList))
	}
}

func TestDetectNetworkRestriction_MixedIPVersions(t *testing.T) {
	entries := []NSFleetEntry{
		{IPv4: []string{"1.2.3.4"}, IPv6: []string{"2001:db8::1"}, UDPReach: false, TCPReach: false},
		{IPv4: []string{}, IPv6: []string{"2001:db8::2"}, UDPReach: false, TCPReach: false},
	}
	resolved, restricted := detectNetworkRestriction(entries)
	if resolved != 2 {
		t.Errorf("resolvedCount = %d, want 2", resolved)
	}
	if !restricted {
		t.Error("expected network restricted when all fail")
	}
}

func TestCheckSerialConsensus_LargeSerials(t *testing.T) {
	entries := []NSFleetEntry{
		{SOASerial: 4294967295, SOASerialOK: true},
		{SOASerial: 4294967295, SOASerialOK: true},
	}
	if !checkSerialConsensus(entries) {
		t.Error("expected consensus for max uint32 serials")
	}
}

func TestExtractPrefix24_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected string
	}{
		{"five octets", "1.2.3.4.5", ""},
		{"two octets", "1.2", ""},
		{"with spaces", "1.2.3 .4", "1.2.3 .0/24"},
		{"zeros", "0.0.0.0", "0.0.0.0/24"},
		{"max values", "255.255.255.255", "255.255.255.0/24"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractPrefix24(tt.ip)
			if got != tt.expected {
				t.Errorf("extractPrefix24(%q) = %q, want %q", tt.ip, got, tt.expected)
			}
		})
	}
}
