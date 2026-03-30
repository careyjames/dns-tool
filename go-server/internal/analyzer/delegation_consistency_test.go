// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
	"testing"
)

func TestCheckDSKeyAlignment_BothMatch(t *testing.T) {
	ds := []DSRecord{
		{KeyTag: 12345, Algorithm: 13, DigestType: 2, Digest: "abc123"},
	}
	keys := []DNSKEYRecord{
		{Flags: 257, Protocol: 3, Algorithm: 13, KeyTag: 12345, IsKSK: true},
		{Flags: 256, Protocol: 3, Algorithm: 13, KeyTag: 54321, IsZSK: true},
	}

	result := CheckDSKeyAlignment(ds, keys)

	if !result.Aligned {
		t.Error("expected aligned DS/DNSKEY")
	}
	if len(result.MatchedPairs) != 1 {
		t.Errorf("expected 1 matched pair, got %d", len(result.MatchedPairs))
	}
	if len(result.UnmatchedDS) != 0 {
		t.Errorf("expected 0 unmatched DS, got %d", len(result.UnmatchedDS))
	}
	if len(result.Issues) != 0 {
		t.Errorf("expected 0 issues, got %d: %v", len(result.Issues), result.Issues)
	}
}

func TestCheckDSKeyAlignment_Mismatched(t *testing.T) {
	ds := []DSRecord{
		{KeyTag: 12345, Algorithm: 13, DigestType: 2, Digest: "abc123"},
	}
	keys := []DNSKEYRecord{
		{Flags: 257, Protocol: 3, Algorithm: 8, KeyTag: 12345, IsKSK: true},
	}

	result := CheckDSKeyAlignment(ds, keys)

	if len(result.Issues) == 0 {
		t.Error("expected issues for algorithm mismatch")
	}
}

func TestCheckDSKeyAlignment_MissingDS(t *testing.T) {
	ds := []DSRecord{}
	keys := []DNSKEYRecord{
		{Flags: 257, Protocol: 3, Algorithm: 13, KeyTag: 12345, IsKSK: true},
	}

	result := CheckDSKeyAlignment(ds, keys)

	if result.Aligned {
		t.Error("expected not aligned when DS is missing")
	}
	if len(result.UnmatchedKeys) != 1 {
		t.Errorf("expected 1 unmatched key, got %d", len(result.UnmatchedKeys))
	}
}

func TestCheckDSKeyAlignment_MissingDNSKEY(t *testing.T) {
	ds := []DSRecord{
		{KeyTag: 12345, Algorithm: 13, DigestType: 2, Digest: "abc123"},
	}
	keys := []DNSKEYRecord{}

	result := CheckDSKeyAlignment(ds, keys)

	if result.Aligned {
		t.Error("expected not aligned when DNSKEY is missing")
	}
	if len(result.UnmatchedDS) != 1 {
		t.Errorf("expected 1 unmatched DS, got %d", len(result.UnmatchedDS))
	}
}

func TestCheckDSKeyAlignment_BothEmpty(t *testing.T) {
	result := CheckDSKeyAlignment([]DSRecord{}, []DNSKEYRecord{})

	if !result.Aligned {
		t.Error("expected aligned when both empty (no DNSSEC)")
	}
	if len(result.Issues) != 0 {
		t.Errorf("expected 0 issues, got %d", len(result.Issues))
	}
}

func TestCheckDSKeyAlignment_NoKeyTagMatch(t *testing.T) {
	ds := []DSRecord{
		{KeyTag: 11111, Algorithm: 13, DigestType: 2, Digest: "abc"},
	}
	keys := []DNSKEYRecord{
		{Flags: 257, Protocol: 3, Algorithm: 13, KeyTag: 65535, IsKSK: true},
	}

	result := CheckDSKeyAlignment(ds, keys)

	if result.Aligned {
		t.Error("expected not aligned when key tags don't match")
	}
	if len(result.UnmatchedDS) != 1 {
		t.Errorf("expected 1 unmatched DS, got %d", len(result.UnmatchedDS))
	}
	if len(result.UnmatchedKeys) != 1 {
		t.Errorf("expected 1 unmatched key, got %d", len(result.UnmatchedKeys))
	}
}

func TestIsInBailiwick(t *testing.T) {
	tests := []struct {
		ns, domain string
		expected   bool
	}{
		{"ns1.example.com.", "example.com", true},
		{"ns1.example.com", "example.com", true},
		{"ns1.dns.example.com", "example.com", true},
		{"ns1.cloudflare.com", "example.com", false},
		{"ns1.example.com", "other.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.ns+"_"+tt.domain, func(t *testing.T) {
			got := isInBailiwick(tt.ns, tt.domain)
			if got != tt.expected {
				t.Errorf("isInBailiwick(%q, %q) = %v, want %v", tt.ns, tt.domain, got, tt.expected)
			}
		})
	}
}

func TestCheckGlueCompleteness_AllPresent(t *testing.T) {
	nameservers := []string{"ns1.example.com.", "ns2.example.com."}
	domain := "example.com"
	glueIPv4 := map[string][]string{
		"ns1.example.com": {"1.2.3.4"},
		"ns2.example.com": {"5.6.7.8"},
	}
	glueIPv6 := map[string][]string{
		"ns1.example.com": {"2001:db8::1"},
		"ns2.example.com": {"2001:db8::2"},
	}

	result := CheckGlueCompleteness(nameservers, domain, glueIPv4, glueIPv6)

	if !result.Complete {
		t.Error("expected complete glue")
	}
	if result.InBailiwickCount != 2 {
		t.Errorf("expected 2 in-bailiwick, got %d", result.InBailiwickCount)
	}
	if result.GluePresent != 2 {
		t.Errorf("expected 2 glue present, got %d", result.GluePresent)
	}
	if len(result.Issues) != 0 {
		t.Errorf("expected 0 issues, got %d: %v", len(result.Issues), result.Issues)
	}
}

func TestCheckGlueCompleteness_MissingGlue(t *testing.T) {
	nameservers := []string{"ns1.example.com."}
	domain := "example.com"
	glueIPv4 := map[string][]string{}
	glueIPv6 := map[string][]string{}

	result := CheckGlueCompleteness(nameservers, domain, glueIPv4, glueIPv6)

	if result.Complete {
		t.Error("expected incomplete when glue is missing")
	}
	if result.GlueMissing != 1 {
		t.Errorf("expected 1 glue missing, got %d", result.GlueMissing)
	}
	if len(result.Issues) == 0 {
		t.Error("expected issues for missing glue")
	}
}

func TestCheckGlueCompleteness_OutOfBailiwick(t *testing.T) {
	nameservers := []string{"ns1.cloudflare.com.", "ns2.cloudflare.com."}
	domain := "example.com"
	glueIPv4 := map[string][]string{}
	glueIPv6 := map[string][]string{}

	result := CheckGlueCompleteness(nameservers, domain, glueIPv4, glueIPv6)

	if !result.Complete {
		t.Error("expected complete when all NS are out of bailiwick (no glue needed)")
	}
	if result.InBailiwickCount != 0 {
		t.Errorf("expected 0 in-bailiwick, got %d", result.InBailiwickCount)
	}
}

func TestCheckGlueCompleteness_PartialGlue(t *testing.T) {
	nameservers := []string{"ns1.example.com."}
	domain := "example.com"
	glueIPv4 := map[string][]string{
		"ns1.example.com": {"1.2.3.4"},
	}
	glueIPv6 := map[string][]string{}

	result := CheckGlueCompleteness(nameservers, domain, glueIPv4, glueIPv6)

	if result.GluePresent != 1 {
		t.Errorf("expected 1 glue present, got %d", result.GluePresent)
	}
	found := false
	for _, issue := range result.Issues {
		if len(issue) > 0 {
			found = true
		}
	}
	if !found {
		t.Error("expected issues for partial glue (missing IPv6)")
	}
}

func TestCompareTTLs_Match(t *testing.T) {
	parent := uint32(3600)
	child := uint32(3600)

	result := CompareTTLs(&parent, &child)

	if !result.Match {
		t.Error("expected TTLs to match")
	}
	if result.DriftSecs != 0 {
		t.Errorf("expected 0 drift, got %d", result.DriftSecs)
	}
	if len(result.Issues) != 0 {
		t.Errorf("expected 0 issues, got %d", len(result.Issues))
	}
}

func TestCompareTTLs_Mismatch(t *testing.T) {
	parent := uint32(3600)
	child := uint32(300)

	result := CompareTTLs(&parent, &child)

	if result.Match {
		t.Error("expected TTLs not to match")
	}
	if result.DriftSecs != 3300 {
		t.Errorf("expected drift 3300, got %d", result.DriftSecs)
	}
	if len(result.Issues) == 0 {
		t.Error("expected issues for TTL mismatch")
	}
}

func TestCompareTTLs_NilParent(t *testing.T) {
	child := uint32(3600)

	result := CompareTTLs(nil, &child)

	if result.Match {
		t.Error("expected no match when parent TTL is nil")
	}
	if len(result.Issues) == 0 {
		t.Error("expected issues when parent TTL missing")
	}
}

func TestCompareTTLs_BothNil(t *testing.T) {
	result := CompareTTLs(nil, nil)

	if result.Match {
		t.Error("expected no match when both TTLs are nil")
	}
	if len(result.Issues) == 0 {
		t.Error("expected issues when both TTLs missing")
	}
}

func TestCheckSOAConsistency_Consistent(t *testing.T) {
	serials := map[string]uint32{
		"ns1.example.com": 2026022201,
		"ns2.example.com": 2026022201,
		"ns3.example.com": 2026022201,
	}

	result := CheckSOAConsistency(serials)

	if !result.Consistent {
		t.Error("expected consistent SOA serials")
	}
	if result.UniqueCount != 1 {
		t.Errorf("expected 1 unique serial, got %d", result.UniqueCount)
	}
	if len(result.Issues) != 0 {
		t.Errorf("expected 0 issues, got %d", len(result.Issues))
	}
}

func TestCheckSOAConsistency_Inconsistent(t *testing.T) {
	serials := map[string]uint32{
		"ns1.example.com": 2026022201,
		"ns2.example.com": 2026022200,
	}

	result := CheckSOAConsistency(serials)

	if result.Consistent {
		t.Error("expected inconsistent SOA serials")
	}
	if result.UniqueCount != 2 {
		t.Errorf("expected 2 unique serials, got %d", result.UniqueCount)
	}
	if len(result.Issues) == 0 {
		t.Error("expected issues for SOA inconsistency")
	}
}

func TestCheckSOAConsistency_Empty(t *testing.T) {
	serials := map[string]uint32{}

	result := CheckSOAConsistency(serials)

	if len(result.Issues) == 0 {
		t.Error("expected issues when no serials available")
	}
}

func TestParseSOASerial(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		serial uint32
		ok     bool
	}{
		{"valid SOA", "ns1.example.com. admin.example.com. 2026022201 3600 900 604800 86400", 2026022201, true},
		{"too short", "ns1.example.com. admin.example.com.", 0, false},
		{"invalid serial", "ns1.example.com. admin.example.com. notanumber 3600", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serial, ok := parseSOASerial(tt.input)
			if ok != tt.ok {
				t.Errorf("parseSOASerial(%q) ok=%v, want %v", tt.input, ok, tt.ok)
			}
			if serial != tt.serial {
				t.Errorf("parseSOASerial(%q) serial=%d, want %d", tt.input, serial, tt.serial)
			}
		})
	}
}

func TestStructToMap_DSKeyAlignment(t *testing.T) {
	align := DSKeyAlignment{
		Aligned: true,
		MatchedPairs: []DSKeyPair{
			{DSKeyTag: 100, DSAlgorithm: 13, DNSKEYKeyTag: 100, DNSKEYAlgorithm: 13},
		},
		UnmatchedDS:   []DSRecord{},
		UnmatchedKeys: []DNSKEYRecord{},
		Issues:        []string{},
	}

	m := structToMap(align)
	if m["aligned"] != true {
		t.Error("expected aligned=true in map")
	}
	pairs, ok := m["matched_pairs"].([]map[string]any)
	if !ok || len(pairs) != 1 {
		t.Error("expected 1 matched pair in map")
	}
}

func TestStructToMap_TTLComparison(t *testing.T) {
	p := uint32(3600)
	c := uint32(300)
	comp := TTLComparison{
		ParentTTL: &p,
		ChildTTL:  &c,
		Match:     false,
		DriftSecs: 3300,
		Issues:    []string{"mismatch"},
	}

	m := structToMap(comp)
	if m["match"] != false {
		t.Error("expected match=false")
	}
	if m["parent_ttl"] != uint32(3600) {
		t.Error("expected parent_ttl=3600")
	}
}

func TestStructToMap_SOAConsistency(t *testing.T) {
	soa := SOAConsistency{
		Consistent:  false,
		Serials:     map[string]uint32{"ns1": 100, "ns2": 200},
		UniqueCount: 2,
		Issues:      []string{"mismatch"},
	}

	m := structToMap(soa)
	if m["consistent"] != false {
		t.Error("expected consistent=false")
	}
	if m["unique_count"] != 2 {
		t.Error("expected unique_count=2")
	}
}

func TestStructToMap_GlueAnalysis(t *testing.T) {
	ga := GlueAnalysis{
		Complete:         true,
		InBailiwickCount: 2,
		GluePresent:      2,
		GlueMissing:      0,
		Nameservers: []GlueStatus{
			{NS: "ns1.example.com", InBailiwick: true, HasIPv4Glue: true, HasIPv6Glue: true, Complete: true, IPv4Addrs: []string{"1.2.3.4"}, IPv6Addrs: []string{"2001:db8::1"}},
		},
		Issues: []string{},
	}

	m := structToMap(ga)
	if m["complete"] != true {
		t.Error("expected complete=true")
	}
	if m["in_bailiwick_count"] != 2 {
		t.Errorf("expected in_bailiwick_count=2, got %v", m["in_bailiwick_count"])
	}
	nsList, ok := m["nameservers"].([]map[string]any)
	if !ok || len(nsList) != 1 {
		t.Error("expected 1 nameserver in map")
	}
}

func TestStructToMap_Unknown(t *testing.T) {
	m := structToMap("unknown type")
	if len(m) != 0 {
		t.Errorf("expected empty map for unknown type, got %d entries", len(m))
	}
}

func TestCollectKSKKeys(t *testing.T) {
	keys := []DNSKEYRecord{
		{Flags: 257, Protocol: 3, Algorithm: 13, KeyTag: 100, IsKSK: true},
		{Flags: 256, Protocol: 3, Algorithm: 13, KeyTag: 200, IsZSK: true},
		{Flags: 257, Protocol: 3, Algorithm: 8, KeyTag: 300, IsKSK: true},
	}

	kskMap := collectKSKKeys(keys)

	if len(kskMap) != 2 {
		t.Errorf("expected 2 KSK keys, got %d", len(kskMap))
	}
	if _, ok := kskMap[100]; !ok {
		t.Error("expected key tag 100 in KSK map")
	}
	if _, ok := kskMap[300]; !ok {
		t.Error("expected key tag 300 in KSK map")
	}
	if _, ok := kskMap[200]; ok {
		t.Error("ZSK key tag 200 should not be in KSK map")
	}
}

func TestCollectKSKKeys_Empty(t *testing.T) {
	kskMap := collectKSKKeys([]DNSKEYRecord{})
	if len(kskMap) != 0 {
		t.Errorf("expected empty KSK map, got %d", len(kskMap))
	}
}

func TestMatchDSKeyPairs_Match(t *testing.T) {
	dsRecords := []DSRecord{
		{KeyTag: 100, Algorithm: 13},
	}
	kskKeys := map[uint16]DNSKEYRecord{
		100: {Flags: 257, Algorithm: 13, KeyTag: 100, IsKSK: true},
	}
	result := &DSKeyAlignment{
		MatchedPairs: []DSKeyPair{},
		Issues:       []string{},
	}

	dsMatched, keyMatched := matchDSKeyPairs(dsRecords, kskKeys, result)

	if len(result.MatchedPairs) != 1 {
		t.Errorf("expected 1 matched pair, got %d", len(result.MatchedPairs))
	}
	if !dsMatched[0] {
		t.Error("expected DS index 0 to be matched")
	}
	if !keyMatched[100] {
		t.Error("expected key tag 100 to be matched")
	}
}

func TestMatchDSKeyPairs_AlgoMismatch(t *testing.T) {
	dsRecords := []DSRecord{
		{KeyTag: 100, Algorithm: 13},
	}
	kskKeys := map[uint16]DNSKEYRecord{
		100: {Flags: 257, Algorithm: 8, KeyTag: 100, IsKSK: true},
	}
	result := &DSKeyAlignment{
		MatchedPairs: []DSKeyPair{},
		Issues:       []string{},
	}

	dsMatched, keyMatched := matchDSKeyPairs(dsRecords, kskKeys, result)

	if len(result.MatchedPairs) != 0 {
		t.Errorf("expected 0 matched pairs for algo mismatch, got %d", len(result.MatchedPairs))
	}
	if dsMatched[0] {
		t.Error("DS should not be matched for algo mismatch")
	}
	if keyMatched[100] {
		t.Error("key should not be matched for algo mismatch")
	}
	if len(result.Issues) == 0 {
		t.Error("expected issues for algorithm mismatch")
	}
}

func TestMatchDSKeyPairs_NoKeyTagMatch(t *testing.T) {
	dsRecords := []DSRecord{
		{KeyTag: 100, Algorithm: 13},
	}
	kskKeys := map[uint16]DNSKEYRecord{
		200: {Flags: 257, Algorithm: 13, KeyTag: 200, IsKSK: true},
	}
	result := &DSKeyAlignment{
		MatchedPairs: []DSKeyPair{},
		Issues:       []string{},
	}

	dsMatched, keyMatched := matchDSKeyPairs(dsRecords, kskKeys, result)

	if len(result.MatchedPairs) != 0 {
		t.Errorf("expected 0 matched pairs, got %d", len(result.MatchedPairs))
	}
	if dsMatched[0] {
		t.Error("DS should not be matched")
	}
	if keyMatched[200] {
		t.Error("key should not be matched")
	}
}

func TestCollectUnmatchedRecords(t *testing.T) {
	dsRecords := []DSRecord{
		{KeyTag: 100, Algorithm: 13},
		{KeyTag: 200, Algorithm: 8},
	}
	dnskeyRecords := []DNSKEYRecord{
		{Flags: 257, Algorithm: 13, KeyTag: 100, IsKSK: true},
		{Flags: 257, Algorithm: 8, KeyTag: 300, IsKSK: true},
		{Flags: 256, Algorithm: 13, KeyTag: 400, IsZSK: true},
	}
	dsMatched := map[int]bool{0: true}
	keyMatched := map[uint16]bool{100: true}

	result := &DSKeyAlignment{
		UnmatchedDS:   []DSRecord{},
		UnmatchedKeys: []DNSKEYRecord{},
	}

	collectUnmatchedRecords(dsRecords, dnskeyRecords, dsMatched, keyMatched, result)

	if len(result.UnmatchedDS) != 1 {
		t.Errorf("expected 1 unmatched DS, got %d", len(result.UnmatchedDS))
	}
	if result.UnmatchedDS[0].KeyTag != 200 {
		t.Errorf("expected unmatched DS key tag 200, got %d", result.UnmatchedDS[0].KeyTag)
	}
	if len(result.UnmatchedKeys) != 1 {
		t.Errorf("expected 1 unmatched key (KSK only), got %d", len(result.UnmatchedKeys))
	}
	if result.UnmatchedKeys[0].KeyTag != 300 {
		t.Errorf("expected unmatched key tag 300, got %d", result.UnmatchedKeys[0].KeyTag)
	}
}

func TestEvaluateInBailiwickGlue_BothPresent(t *testing.T) {
	status := &GlueStatus{}
	result := &GlueAnalysis{Issues: []string{}}

	glueIPv4 := map[string][]string{"ns1.example.com": {"1.2.3.4"}}
	glueIPv6 := map[string][]string{"ns1.example.com": {"2001:db8::1"}}

	evaluateInBailiwickGlue("ns1.example.com", glueIPv4, glueIPv6, status, result)

	if !status.HasIPv4Glue {
		t.Error("expected IPv4 glue")
	}
	if !status.HasIPv6Glue {
		t.Error("expected IPv6 glue")
	}
	if !status.Complete {
		t.Error("expected complete status")
	}
	if result.GluePresent != 1 {
		t.Errorf("expected 1 glue present, got %d", result.GluePresent)
	}
	if len(result.Issues) != 0 {
		t.Errorf("expected 0 issues, got %v", result.Issues)
	}
}

func TestEvaluateInBailiwickGlue_IPv4Only(t *testing.T) {
	status := &GlueStatus{}
	result := &GlueAnalysis{Issues: []string{}}

	glueIPv4 := map[string][]string{"ns1.example.com": {"1.2.3.4"}}
	glueIPv6 := map[string][]string{}

	evaluateInBailiwickGlue("ns1.example.com", glueIPv4, glueIPv6, status, result)

	if !status.HasIPv4Glue {
		t.Error("expected IPv4 glue")
	}
	if status.HasIPv6Glue {
		t.Error("expected no IPv6 glue")
	}
	if status.Complete {
		t.Error("expected incomplete status (missing IPv6)")
	}
	if len(result.Issues) == 0 {
		t.Error("expected issues for missing IPv6 glue")
	}
}

func TestEvaluateInBailiwickGlue_NoGlue(t *testing.T) {
	status := &GlueStatus{}
	result := &GlueAnalysis{Complete: true, Issues: []string{}}

	evaluateInBailiwickGlue("ns1.example.com", map[string][]string{}, map[string][]string{}, status, result)

	if result.Complete {
		t.Error("expected incomplete when no glue")
	}
	if result.GlueMissing != 1 {
		t.Errorf("expected 1 glue missing, got %d", result.GlueMissing)
	}
	if len(result.Issues) == 0 {
		t.Error("expected issues for no glue")
	}
}

func TestGlueStatusToMap(t *testing.T) {
	gs := GlueStatus{
		NS:          "ns1.example.com",
		InBailiwick: true,
		HasIPv4Glue: true,
		HasIPv6Glue: false,
		IPv4Addrs:   []string{"1.2.3.4"},
		IPv6Addrs:   nil,
		Complete:    false,
	}

	m := glueStatusToMap(gs)

	if m["ns"] != "ns1.example.com" {
		t.Errorf("expected ns=ns1.example.com, got %v", m["ns"])
	}
	if m["in_bailiwick"] != true {
		t.Error("expected in_bailiwick=true")
	}
	if m["has_ipv4_glue"] != true {
		t.Error("expected has_ipv4_glue=true")
	}
	if m["has_ipv6_glue"] != false {
		t.Error("expected has_ipv6_glue=false")
	}
	if _, ok := m["ipv4_addrs"]; !ok {
		t.Error("expected ipv4_addrs present")
	}
	if _, ok := m["ipv6_addrs"]; ok {
		t.Error("expected ipv6_addrs absent when nil")
	}
}

func TestGlueStatusToMap_NoAddrs(t *testing.T) {
	gs := GlueStatus{
		NS:          "ns1.cloudflare.com",
		InBailiwick: false,
		Complete:    true,
	}

	m := glueStatusToMap(gs)

	if _, ok := m["ipv4_addrs"]; ok {
		t.Error("expected no ipv4_addrs")
	}
	if _, ok := m["ipv6_addrs"]; ok {
		t.Error("expected no ipv6_addrs")
	}
}

func TestCompareTTLs_NilChild(t *testing.T) {
	parent := uint32(3600)

	result := CompareTTLs(&parent, nil)

	if result.Match {
		t.Error("expected no match when child TTL is nil")
	}
	if len(result.Issues) == 0 {
		t.Error("expected issues when child TTL missing")
	}
}

func TestCheckSOAConsistency_SingleServer(t *testing.T) {
	serials := map[string]uint32{
		"ns1.example.com": 2026022201,
	}

	result := CheckSOAConsistency(serials)

	if !result.Consistent {
		t.Error("expected consistent with single server")
	}
	if result.UniqueCount != 1 {
		t.Errorf("expected 1 unique serial, got %d", result.UniqueCount)
	}
}

func TestDsKeyAlignmentToMap_WithUnmatched(t *testing.T) {
	val := DSKeyAlignment{
		Aligned:      false,
		MatchedPairs: []DSKeyPair{},
		UnmatchedDS: []DSRecord{
			{KeyTag: 100, Algorithm: 13, DigestType: 2, Digest: "abc", Raw: "DS 100 13 2 abc"},
		},
		UnmatchedKeys: []DNSKEYRecord{
			{Flags: 257, Algorithm: 8, KeyTag: 200, IsKSK: true, Raw: "DNSKEY 257 3 8 ..."},
		},
		Issues: []string{"broken chain"},
	}

	m := dsKeyAlignmentToMap(val)

	if m["aligned"] != false {
		t.Error("expected aligned=false")
	}
	unmatchedDS, ok := m["unmatched_ds"].([]map[string]any)
	if !ok || len(unmatchedDS) != 1 {
		t.Error("expected 1 unmatched DS in map")
	}
	unmatchedKeys, ok := m["unmatched_keys"].([]map[string]any)
	if !ok || len(unmatchedKeys) != 1 {
		t.Error("expected 1 unmatched key in map")
	}
	issues, ok := m["issues"].([]string)
	if !ok || len(issues) != 1 {
		t.Error("expected 1 issue in map")
	}
}

func TestTtlComparisonToMap_NilValues(t *testing.T) {
	comp := TTLComparison{
		ParentTTL: nil,
		ChildTTL:  nil,
		Match:     false,
		DriftSecs: 0,
		Issues:    []string{"missing"},
	}

	m := ttlComparisonToMap(comp)

	if _, ok := m["parent_ttl"]; ok {
		t.Error("expected no parent_ttl when nil")
	}
	if _, ok := m["child_ttl"]; ok {
		t.Error("expected no child_ttl when nil")
	}
}

func TestSoaConsistencyToMap(t *testing.T) {
	soa := SOAConsistency{
		Consistent:  true,
		Serials:     map[string]uint32{"ns1": 100, "ns2": 100},
		UniqueCount: 1,
		Issues:      []string{},
	}

	m := soaConsistencyToMap(soa)

	if m["consistent"] != true {
		t.Error("expected consistent=true")
	}
	if m["unique_count"] != 1 {
		t.Errorf("expected unique_count=1, got %v", m["unique_count"])
	}
	serials, ok := m["serials"].(map[string]any)
	if !ok || len(serials) != 2 {
		t.Error("expected 2 serials in map")
	}
}

func TestCheckDSKeyAlignment_MultipleMatches(t *testing.T) {
	ds := []DSRecord{
		{KeyTag: 100, Algorithm: 13, DigestType: 2, Digest: "abc"},
		{KeyTag: 200, Algorithm: 8, DigestType: 2, Digest: "def"},
	}
	keys := []DNSKEYRecord{
		{Flags: 257, Protocol: 3, Algorithm: 13, KeyTag: 100, IsKSK: true},
		{Flags: 257, Protocol: 3, Algorithm: 8, KeyTag: 200, IsKSK: true},
		{Flags: 256, Protocol: 3, Algorithm: 13, KeyTag: 300, IsZSK: true},
	}

	result := CheckDSKeyAlignment(ds, keys)

	if !result.Aligned {
		t.Error("expected aligned with multiple matches")
	}
	if len(result.MatchedPairs) != 2 {
		t.Errorf("expected 2 matched pairs, got %d", len(result.MatchedPairs))
	}
	if len(result.UnmatchedDS) != 0 {
		t.Errorf("expected 0 unmatched DS, got %d", len(result.UnmatchedDS))
	}
	if len(result.UnmatchedKeys) != 0 {
		t.Errorf("expected 0 unmatched KSK keys, got %d", len(result.UnmatchedKeys))
	}
}

func TestCheckGlueCompleteness_MixedBailiwick(t *testing.T) {
	nameservers := []string{"ns1.example.com.", "ns1.cloudflare.com."}
	domain := "example.com"
	glueIPv4 := map[string][]string{
		"ns1.example.com": {"1.2.3.4"},
	}
	glueIPv6 := map[string][]string{
		"ns1.example.com": {"2001:db8::1"},
	}

	result := CheckGlueCompleteness(nameservers, domain, glueIPv4, glueIPv6)

	if result.InBailiwickCount != 1 {
		t.Errorf("expected 1 in-bailiwick, got %d", result.InBailiwickCount)
	}
	if result.GluePresent != 1 {
		t.Errorf("expected 1 glue present, got %d", result.GluePresent)
	}
	if len(result.Nameservers) != 2 {
		t.Errorf("expected 2 nameservers, got %d", len(result.Nameservers))
	}
}

func TestIsInBailiwick_ExactDomainMatch(t *testing.T) {
	if !isInBailiwick("example.com", "example.com") {
		t.Error("expected exact domain match to be in bailiwick")
	}
	if !isInBailiwick("example.com.", "example.com.") {
		t.Error("expected exact match with trailing dots to be in bailiwick")
	}
}

func TestEvaluateInBailiwickGlue_IPv6Only(t *testing.T) {
	status := &GlueStatus{}
	result := &GlueAnalysis{Issues: []string{}}

	glueIPv4 := map[string][]string{}
	glueIPv6 := map[string][]string{"ns1.example.com": {"2001:db8::1"}}

	evaluateInBailiwickGlue("ns1.example.com", glueIPv4, glueIPv6, status, result)

	if status.HasIPv4Glue {
		t.Error("expected no IPv4 glue")
	}
	if !status.HasIPv6Glue {
		t.Error("expected IPv6 glue")
	}
	if status.Complete {
		t.Error("expected incomplete (missing IPv4)")
	}
	if result.GluePresent != 1 {
		t.Errorf("expected 1 glue present, got %d", result.GluePresent)
	}
	if len(result.Issues) == 0 {
		t.Error("expected issues for missing IPv4 glue")
	}
}

func TestTtlComparisonToMap_WithValues(t *testing.T) {
	p := uint32(3600)
	c := uint32(3600)
	comp := TTLComparison{
		ParentTTL: &p,
		ChildTTL:  &c,
		Match:     true,
		DriftSecs: 0,
		Issues:    []string{},
	}

	m := ttlComparisonToMap(comp)

	if m["parent_ttl"] != uint32(3600) {
		t.Errorf("expected parent_ttl=3600, got %v", m["parent_ttl"])
	}
	if m["child_ttl"] != uint32(3600) {
		t.Errorf("expected child_ttl=3600, got %v", m["child_ttl"])
	}
	if m["match"] != true {
		t.Error("expected match=true")
	}
}

func TestParseSOASerial_LargeSerial(t *testing.T) {
	serial, ok := parseSOASerial("ns1.example.com. admin.example.com. 4294967295 3600 900 604800 86400")
	if !ok {
		t.Error("expected ok for max uint32 serial")
	}
	if serial != 4294967295 {
		t.Errorf("expected serial 4294967295, got %d", serial)
	}
}

func TestParseSOASerial_ZeroSerial(t *testing.T) {
	serial, ok := parseSOASerial("ns1.example.com. admin.example.com. 0 3600 900 604800 86400")
	if !ok {
		t.Error("expected ok for zero serial")
	}
	if serial != 0 {
		t.Errorf("expected serial 0, got %d", serial)
	}
}

func TestParseSOASerial_EmptyString(t *testing.T) {
	_, ok := parseSOASerial("")
	if ok {
		t.Error("expected not ok for empty string")
	}
}

func TestCheckSOAConsistency_ThreeWaySplit(t *testing.T) {
	serials := map[string]uint32{
		"ns1.example.com": 100,
		"ns2.example.com": 200,
		"ns3.example.com": 300,
	}

	result := CheckSOAConsistency(serials)

	if result.Consistent {
		t.Error("expected inconsistent with 3-way split")
	}
	if result.UniqueCount != 3 {
		t.Errorf("expected 3 unique serials, got %d", result.UniqueCount)
	}
}

func TestGlueStatusToMap_BothAddrs(t *testing.T) {
	gs := GlueStatus{
		NS:          "ns1.example.com",
		InBailiwick: true,
		HasIPv4Glue: true,
		HasIPv6Glue: true,
		IPv4Addrs:   []string{"1.2.3.4"},
		IPv6Addrs:   []string{"2001:db8::1"},
		Complete:    true,
	}

	m := glueStatusToMap(gs)

	if _, ok := m["ipv4_addrs"]; !ok {
		t.Error("expected ipv4_addrs present")
	}
	if _, ok := m["ipv6_addrs"]; !ok {
		t.Error("expected ipv6_addrs present")
	}
	if m["complete"] != true {
		t.Error("expected complete=true")
	}
}

func TestCheckGlueCompleteness_Empty(t *testing.T) {
	result := CheckGlueCompleteness([]string{}, "example.com", map[string][]string{}, map[string][]string{})

	if !result.Complete {
		t.Error("expected complete for empty nameservers")
	}
	if len(result.Nameservers) != 0 {
		t.Errorf("expected 0 nameservers, got %d", len(result.Nameservers))
	}
}

func TestCollectUnmatchedRecords_AllMatched(t *testing.T) {
	dsRecords := []DSRecord{
		{KeyTag: 100, Algorithm: 13},
	}
	dnskeyRecords := []DNSKEYRecord{
		{Flags: 257, Algorithm: 13, KeyTag: 100, IsKSK: true},
	}
	dsMatched := map[int]bool{0: true}
	keyMatched := map[uint16]bool{100: true}

	result := &DSKeyAlignment{
		UnmatchedDS:   []DSRecord{},
		UnmatchedKeys: []DNSKEYRecord{},
	}

	collectUnmatchedRecords(dsRecords, dnskeyRecords, dsMatched, keyMatched, result)

	if len(result.UnmatchedDS) != 0 {
		t.Errorf("expected 0 unmatched DS, got %d", len(result.UnmatchedDS))
	}
	if len(result.UnmatchedKeys) != 0 {
		t.Errorf("expected 0 unmatched keys, got %d", len(result.UnmatchedKeys))
	}
}

func TestCheckDSKeyAlignment_OnlyZSKKeys(t *testing.T) {
	ds := []DSRecord{
		{KeyTag: 100, Algorithm: 13, DigestType: 2, Digest: "abc"},
	}
	keys := []DNSKEYRecord{
		{Flags: 256, Protocol: 3, Algorithm: 13, KeyTag: 100, IsZSK: true},
	}

	result := CheckDSKeyAlignment(ds, keys)

	if result.Aligned {
		t.Error("expected not aligned when only ZSK keys exist (no KSK)")
	}
	if len(result.UnmatchedDS) != 1 {
		t.Errorf("expected 1 unmatched DS, got %d", len(result.UnmatchedDS))
	}
}

func TestCompareTTLs_ReverseDrift(t *testing.T) {
	parent := uint32(300)
	child := uint32(3600)

	result := CompareTTLs(&parent, &child)

	if result.Match {
		t.Error("expected no match")
	}
	if result.DriftSecs != 3300 {
		t.Errorf("expected drift 3300, got %d", result.DriftSecs)
	}
}

func TestGlueAnalysisToMap(t *testing.T) {
	ga := GlueAnalysis{
		Complete:         false,
		InBailiwickCount: 1,
		GluePresent:      0,
		GlueMissing:      1,
		Nameservers: []GlueStatus{
			{NS: "ns1.example.com", InBailiwick: true, Complete: false},
		},
		Issues: []string{"missing glue"},
	}

	m := glueAnalysisToMap(ga)

	if m["complete"] != false {
		t.Error("expected complete=false")
	}
	if m["in_bailiwick_count"] != 1 {
		t.Errorf("expected in_bailiwick_count=1, got %v", m["in_bailiwick_count"])
	}
	if m["glue_present"] != 0 {
		t.Errorf("expected glue_present=0, got %v", m["glue_present"])
	}
	if m["glue_missing"] != 1 {
		t.Errorf("expected glue_missing=1, got %v", m["glue_missing"])
	}
	nsList, ok := m["nameservers"].([]map[string]any)
	if !ok || len(nsList) != 1 {
		t.Error("expected 1 nameserver in map")
	}
	issues, ok := m["issues"].([]string)
	if !ok || len(issues) != 1 {
		t.Error("expected 1 issue")
	}
}

func TestGlueAnalysisToMap_Empty(t *testing.T) {
	ga := GlueAnalysis{
		Complete:    true,
		Nameservers: []GlueStatus{},
		Issues:      []string{},
	}

	m := glueAnalysisToMap(ga)

	nsList, ok := m["nameservers"].([]map[string]any)
	if !ok || len(nsList) != 0 {
		t.Error("expected 0 nameservers in map")
	}
}

func TestIsInBailiwick_CaseInsensitive(t *testing.T) {
	if !isInBailiwick("NS1.EXAMPLE.COM.", "example.com") {
		t.Error("expected case-insensitive match")
	}
	if !isInBailiwick("ns1.example.com", "EXAMPLE.COM") {
		t.Error("expected case-insensitive match")
	}
}

func TestCheckGlueCompleteness_MultipleInBailiwick(t *testing.T) {
	nameservers := []string{"ns1.example.com.", "ns2.example.com.", "ns3.example.com."}
	domain := "example.com"
	glueIPv4 := map[string][]string{
		"ns1.example.com": {"1.2.3.4"},
		"ns2.example.com": {"5.6.7.8"},
	}
	glueIPv6 := map[string][]string{
		"ns1.example.com": {"2001:db8::1"},
		"ns2.example.com": {"2001:db8::2"},
	}

	result := CheckGlueCompleteness(nameservers, domain, glueIPv4, glueIPv6)

	if result.InBailiwickCount != 3 {
		t.Errorf("expected 3 in-bailiwick, got %d", result.InBailiwickCount)
	}
	if result.GluePresent != 2 {
		t.Errorf("expected 2 glue present, got %d", result.GluePresent)
	}
	if result.GlueMissing != 1 {
		t.Errorf("expected 1 glue missing, got %d", result.GlueMissing)
	}
	if result.Complete {
		t.Error("expected incomplete when one NS has no glue")
	}
}

func TestSoaConsistencyToMap_Empty(t *testing.T) {
	soa := SOAConsistency{
		Consistent:  true,
		Serials:     map[string]uint32{},
		UniqueCount: 0,
		Issues:      []string{},
	}

	m := soaConsistencyToMap(soa)

	serials, ok := m["serials"].(map[string]any)
	if !ok || len(serials) != 0 {
		t.Error("expected empty serials map")
	}
}

func TestDsKeyAlignmentToMap_Empty(t *testing.T) {
	val := DSKeyAlignment{
		Aligned:       true,
		MatchedPairs:  []DSKeyPair{},
		UnmatchedDS:   []DSRecord{},
		UnmatchedKeys: []DNSKEYRecord{},
		Issues:        []string{},
	}

	m := dsKeyAlignmentToMap(val)

	pairs, ok := m["matched_pairs"].([]map[string]any)
	if !ok || len(pairs) != 0 {
		t.Error("expected 0 matched pairs")
	}
	unmatchedDS, ok := m["unmatched_ds"].([]map[string]any)
	if !ok || len(unmatchedDS) != 0 {
		t.Error("expected 0 unmatched DS")
	}
	unmatchedKeys, ok := m["unmatched_keys"].([]map[string]any)
	if !ok || len(unmatchedKeys) != 0 {
		t.Error("expected 0 unmatched keys")
	}
}

func TestParseSOASerial_ExtraWhitespace(t *testing.T) {
	serial, ok := parseSOASerial("ns1.example.com.  admin.example.com.  2026022201  3600  900")
	if !ok {
		t.Error("expected ok for SOA with extra whitespace")
	}
	if serial != 2026022201 {
		t.Errorf("expected serial 2026022201, got %d", serial)
	}
}

func TestParseSOASerial_OverflowUint32(t *testing.T) {
	_, ok := parseSOASerial("ns1.example.com. admin.example.com. 9999999999999 3600 900")
	if ok {
		t.Error("expected not ok for serial exceeding uint32 range")
	}
}
