// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

func TestClassifyKeyRole(t *testing.T) {
	tests := []struct {
		name     string
		flags    uint16
		expected string
	}{
		{"KSK flag 257", 257, "KSK"},
		{"ZSK flag 256", 256, "ZSK"},
		{"odd flag with SEP bit", 259, "KSK-like"},
		{"zero flags", 0, "unknown"},
		{"even non-256", 512, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyKeyRole(tt.flags)
			if got != tt.expected {
				t.Errorf("classifyKeyRole(%d) = %q, want %q", tt.flags, got, tt.expected)
			}
		})
	}
}

func TestEstimateKeySize(t *testing.T) {
	tests := []struct {
		name      string
		algorithm uint8
		pubKey    string
		expected  int
	}{
		{"ECDSA P-256", 13, "AAAA", 256},
		{"ECDSA P-384", 14, "AAAA", 384},
		{"Ed25519", 15, "AAAA", 256},
		{"Ed448", 16, "AAAA", 456},
		{"RSA/SHA-256 2048-bit", 8, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa", 2088},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := estimateKeySize(tt.algorithm, tt.pubKey)
			if got != tt.expected {
				t.Errorf("estimateKeySize(%d, ...) = %d, want %d", tt.algorithm, got, tt.expected)
			}
		})
	}
}

func TestDnssecAlgorithmName(t *testing.T) {
	tests := []struct {
		alg      uint8
		expected string
	}{
		{8, "RSA/SHA-256"},
		{13, "ECDSA P-256/SHA-256"},
		{15, "Ed25519"},
		{99, "Algorithm 99"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := dnssecAlgorithmName(tt.alg)
			if got != tt.expected {
				t.Errorf("dnssecAlgorithmName(%d) = %q, want %q", tt.alg, got, tt.expected)
			}
		})
	}
}

func TestParseDNSSECKeys(t *testing.T) {
	records := []*dns.DNSKEY{
		{
			DNSKEY: rdata.DNSKEY{
				Flags:     257,
				Protocol:  3,
				Algorithm: 13,
				PublicKey: "testkey1",
			},
		},
		{
			DNSKEY: rdata.DNSKEY{
				Flags:     256,
				Protocol:  3,
				Algorithm: 8,
				PublicKey: "testkey2",
			},
		},
	}

	keys := parseDNSSECKeys(records)
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}

	if keys[0].KeyRole != "KSK" {
		t.Errorf("expected first key role KSK, got %s", keys[0].KeyRole)
	}
	if keys[0].AlgName != "ECDSA P-256/SHA-256" {
		t.Errorf("expected algorithm name 'ECDSA P-256/SHA-256', got %s", keys[0].AlgName)
	}
	if keys[1].KeyRole != "ZSK" {
		t.Errorf("expected second key role ZSK, got %s", keys[1].KeyRole)
	}
}

func timeToUint32(t time.Time) uint32 {
	return uint32(t.Unix())
}

func TestParseRRSIGRecords_Active(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	future := now.Add(30 * 24 * time.Hour)
	past := now.Add(-30 * 24 * time.Hour)

	records := []*dns.RRSIG{
		{
			RRSIG: rdata.RRSIG{
				TypeCovered: dns.TypeDNSKEY,
				Algorithm:   13,
				Labels:      2,
				OrigTTL:     3600,
				Expiration:  timeToUint32(future),
				Inception:   timeToUint32(past),
				KeyTag:      12345,
				SignerName:  "example.com.",
			},
		},
	}

	sigs := parseRRSIGRecords(records, now)
	if len(sigs) != 1 {
		t.Fatalf("expected 1 sig, got %d", len(sigs))
	}
	if sigs[0].ExpiringSoon {
		t.Error("expected not expiring soon")
	}
	if sigs[0].Expired {
		t.Error("expected not expired")
	}
	if sigs[0].KeyTag != 12345 {
		t.Errorf("expected key tag 12345, got %d", sigs[0].KeyTag)
	}
}

func TestParseRRSIGRecords_ExpiringSoon(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	soonExpiry := now.Add(3 * 24 * time.Hour)
	past := now.Add(-30 * 24 * time.Hour)

	records := []*dns.RRSIG{
		{
			RRSIG: rdata.RRSIG{
				TypeCovered: dns.TypeA,
				Algorithm:   13,
				Labels:      2,
				OrigTTL:     3600,
				Expiration:  timeToUint32(soonExpiry),
				Inception:   timeToUint32(past),
				KeyTag:      11111,
				SignerName:  "example.com.",
			},
		},
	}

	sigs := parseRRSIGRecords(records, now)
	if !sigs[0].ExpiringSoon {
		t.Error("expected expiring soon")
	}
	if sigs[0].Expired {
		t.Error("expected not expired")
	}
}

func TestParseRRSIGRecords_Expired(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	pastExpiry := now.Add(-1 * 24 * time.Hour)
	pastInception := now.Add(-30 * 24 * time.Hour)

	records := []*dns.RRSIG{
		{
			RRSIG: rdata.RRSIG{
				TypeCovered: dns.TypeA,
				Algorithm:   13,
				Labels:      2,
				OrigTTL:     3600,
				Expiration:  timeToUint32(pastExpiry),
				Inception:   timeToUint32(pastInception),
				KeyTag:      22222,
				SignerName:  "example.com.",
			},
		},
	}

	sigs := parseRRSIGRecords(records, now)
	if !sigs[0].Expired {
		t.Error("expected expired")
	}
}

func TestDetectDenialOfExistence_NSEC(t *testing.T) {
	nsecRecords := []*dns.NSEC{
		{
			NSEC: rdata.NSEC{
				NextDomain: "b.example.com.",
			},
		},
	}
	doe := detectDenialOfExistence(nsecRecords, nil)
	if doe.Method != "NSEC" {
		t.Errorf("expected method NSEC, got %s", doe.Method)
	}
	if doe.NSEC3Params != nil {
		t.Error("expected no NSEC3 params for NSEC")
	}
}

func TestDetectDenialOfExistence_NSEC3_LowIterations(t *testing.T) {
	nsec3Records := []*dns.NSEC3{
		{
			NSEC3: rdata.NSEC3{
				Hash:       1,
				Flags:      0,
				Iterations: 10,
				SaltLength: 0,
				Salt:       "",
			},
		},
	}
	doe := detectDenialOfExistence(nil, nsec3Records)
	if doe.Method != "NSEC3" {
		t.Errorf("expected method NSEC3, got %s", doe.Method)
	}
	if doe.NSEC3Params == nil {
		t.Fatal("expected NSEC3 params")
	}
	if doe.NSEC3Params.HighIterations {
		t.Error("expected low iterations to not flag")
	}
	if len(doe.Issues) != 0 {
		t.Errorf("expected no issues, got %v", doe.Issues)
	}
}

func TestDetectDenialOfExistence_NSEC3_HighIterations(t *testing.T) {
	nsec3Records := []*dns.NSEC3{
		{
			NSEC3: rdata.NSEC3{
				Hash:       1,
				Flags:      0,
				Iterations: 150,
				SaltLength: 2,
				Salt:       "AABB",
			},
		},
	}
	doe := detectDenialOfExistence(nil, nsec3Records)
	if !doe.NSEC3Params.HighIterations {
		t.Error("expected high iterations flag")
	}
	if len(doe.Issues) != 2 {
		t.Errorf("expected 2 issues (high iterations + salt), got %d: %v", len(doe.Issues), doe.Issues)
	}
}

func TestDetectDenialOfExistence_None(t *testing.T) {
	doe := detectDenialOfExistence(nil, nil)
	if doe.Method != "none" {
		t.Errorf("expected method none, got %s", doe.Method)
	}
}

func TestDetectDenialOfExistence_NSEC3_WithSalt(t *testing.T) {
	nsec3Records := []*dns.NSEC3{
		{
			NSEC3: rdata.NSEC3{
				Hash:       1,
				Flags:      0,
				Iterations: 5,
				SaltLength: 3,
				Salt:       "AABBCC",
			},
		},
	}
	doe := detectDenialOfExistence(nil, nsec3Records)
	if len(doe.Issues) != 1 {
		t.Errorf("expected 1 issue (salt), got %d: %v", len(doe.Issues), doe.Issues)
	}
}

func TestAssessRolloverReadiness_FullyReady(t *testing.T) {
	keys := []DNSSECKeyInfo{
		{Flags: 257, KeyRole: "KSK"},
		{Flags: 257, KeyRole: "KSK"},
		{Flags: 256, KeyRole: "ZSK"},
	}

	rr := assessRolloverReadiness(keys, true, true)
	if rr.ReadinessLevel != "ready" {
		t.Errorf("expected readiness 'ready', got %s", rr.ReadinessLevel)
	}
	if rr.AutomationLevel != "full" {
		t.Errorf("expected automation 'full', got %s", rr.AutomationLevel)
	}
	if !rr.MultipleKSKs {
		t.Error("expected multiple KSKs")
	}
	if rr.KSKCount != 2 {
		t.Errorf("expected 2 KSKs, got %d", rr.KSKCount)
	}
}

func TestAssessRolloverReadiness_NotReady(t *testing.T) {
	keys := []DNSSECKeyInfo{
		{Flags: 257, KeyRole: "KSK"},
		{Flags: 256, KeyRole: "ZSK"},
	}

	rr := assessRolloverReadiness(keys, false, false)
	if rr.ReadinessLevel != "not_ready" {
		t.Errorf("expected readiness 'not_ready', got %s", rr.ReadinessLevel)
	}
	if rr.AutomationLevel != "none" {
		t.Errorf("expected automation 'none', got %s", rr.AutomationLevel)
	}
}

func TestAssessRolloverReadiness_PartialMultipleKSKs(t *testing.T) {
	keys := []DNSSECKeyInfo{
		{Flags: 257, KeyRole: "KSK"},
		{Flags: 257, KeyRole: "KSK"},
		{Flags: 256, KeyRole: "ZSK"},
	}

	rr := assessRolloverReadiness(keys, false, false)
	if rr.ReadinessLevel != "partial" {
		t.Errorf("expected readiness 'partial', got %s", rr.ReadinessLevel)
	}
	if len(rr.Issues) == 0 {
		t.Error("expected issues for partial readiness")
	}
}

func TestAssessRolloverReadiness_PartialCDSOnly(t *testing.T) {
	keys := []DNSSECKeyInfo{
		{Flags: 257, KeyRole: "KSK"},
		{Flags: 256, KeyRole: "ZSK"},
	}

	rr := assessRolloverReadiness(keys, true, false)
	if rr.ReadinessLevel != "partial" {
		t.Errorf("expected readiness 'partial', got %s", rr.ReadinessLevel)
	}
	if rr.AutomationLevel != "partial" {
		t.Errorf("expected automation 'partial', got %s", rr.AutomationLevel)
	}
}

func TestAssessRolloverReadiness_CSKScheme(t *testing.T) {
	keys := []DNSSECKeyInfo{
		{Flags: 257, KeyRole: "KSK"},
	}

	rr := assessRolloverReadiness(keys, false, false)
	found := false
	for _, iss := range rr.Issues {
		if iss == "No separate ZSK found — single-key signing scheme (CSK) detected" {
			found = true
		}
	}
	if !found {
		t.Error("expected CSK detection issue")
	}
}

func TestCollectDNSSECOpsIssues_ExpiredSigs(t *testing.T) {
	sigs := []RRSIGInfo{
		{TypeCovered: "A", KeyTag: 111, Expired: true},
		{TypeCovered: "MX", KeyTag: 222, ExpiringSoon: true},
	}
	doe := DenialOfExistence{Issues: []string{"test doe issue"}}
	rollover := RolloverReadiness{Issues: []string{"test rollover issue"}}

	issues := collectDNSSECOpsIssues(sigs, doe, rollover)
	if len(issues) != 4 {
		t.Errorf("expected 4 issues, got %d: %v", len(issues), issues)
	}
}

func TestBuildDNSSECOpsStatus_NoKeys(t *testing.T) {
	status, msg := buildDNSSECOpsStatus(nil, nil)
	if status != "info" {
		t.Errorf("expected 'info', got %s", status)
	}
	if msg == "" {
		t.Error("expected non-empty message")
	}
}

func TestBuildDNSSECOpsStatus_Healthy(t *testing.T) {
	keys := []DNSSECKeyInfo{{Flags: 257, KeyRole: "KSK"}}
	status, _ := buildDNSSECOpsStatus(keys, nil)
	if status != "success" {
		t.Errorf("expected 'success', got %s", status)
	}
}

func TestBuildDNSSECOpsStatus_WithExpiredIssue(t *testing.T) {
	keys := []DNSSECKeyInfo{{Flags: 257, KeyRole: "KSK"}}
	issues := []string{"RRSIG for A (key tag 111) has expired"}
	status, _ := buildDNSSECOpsStatus(keys, issues)
	if status != "error" {
		t.Errorf("expected 'error', got %s", status)
	}
}

func TestBuildDNSSECOpsStatus_WithWarningIssue(t *testing.T) {
	keys := []DNSSECKeyInfo{{Flags: 257, KeyRole: "KSK"}}
	issues := []string{"NSEC3 iterations too high"}
	status, _ := buildDNSSECOpsStatus(keys, issues)
	if status != "warning" {
		t.Errorf("expected 'warning', got %s", status)
	}
}

func TestParseDNSSECKeys_Empty(t *testing.T) {
	keys := parseDNSSECKeys(nil)
	if keys != nil {
		t.Errorf("expected nil for empty input, got %v", keys)
	}
}

func TestParseRRSIGRecords_Empty(t *testing.T) {
	sigs := parseRRSIGRecords(nil, time.Now())
	if sigs != nil {
		t.Errorf("expected nil for empty input, got %v", sigs)
	}
}

func TestCollectDNSSECOpsIssues_NoIssues(t *testing.T) {
	sigs := []RRSIGInfo{
		{TypeCovered: "A", KeyTag: 111, Expired: false, ExpiringSoon: false},
	}
	doe := DenialOfExistence{Issues: []string{}}
	rollover := RolloverReadiness{Issues: []string{}}

	issues := collectDNSSECOpsIssues(sigs, doe, rollover)
	if len(issues) != 0 {
		t.Errorf("expected 0 issues, got %d: %v", len(issues), issues)
	}
}

func TestUint32ToTime(t *testing.T) {
	ts := uint32(1709251200)
	result := uint32ToTime(ts)
	if result.Year() != 2024 {
		t.Errorf("expected year 2024, got %d", result.Year())
	}
}
