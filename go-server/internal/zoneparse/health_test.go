// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package zoneparse

import (
	"testing"
)

func TestAnalyzeHealthEmpty(t *testing.T) {
	h := AnalyzeHealth(nil)
	if h.TotalRecords != 0 {
		t.Errorf("expected 0 records, got %d", h.TotalRecords)
	}
	if h.StructuralScore != 0 {
		t.Errorf("expected 0 structural score, got %d", h.StructuralScore)
	}
}

func TestAnalyzeHealthBasicZone(t *testing.T) {
	records := []ParsedRecord{
		{Name: "example.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400"},
		{Name: "example.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns1.example.com."},
		{Name: "example.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns2.example.com."},
		{Name: "example.com.", TTL: 300, Class: "IN", Type: "A", RData: "93.184.216.34"},
		{Name: "example.com.", TTL: 300, Class: "IN", Type: "AAAA", RData: "2606:2800:220:1:248:1893:25c8:1946"},
		{Name: "example.com.", TTL: 3600, Class: "IN", Type: "MX", RData: "10 mail.example.com."},
		{Name: "example.com.", TTL: 3600, Class: "IN", Type: "TXT", RData: "v=spf1 include:_spf.example.com ~all"},
		{Name: "_dmarc.example.com.", TTL: 3600, Class: "IN", Type: "TXT", RData: "v=DMARC1; p=reject"},
		{Name: "example.com.", TTL: 3600, Class: "IN", Type: "CAA", RData: "0 issue \"letsencrypt.org\""},
	}

	h := AnalyzeHealth(records)

	if h.TotalRecords != 9 {
		t.Errorf("expected 9 records, got %d", h.TotalRecords)
	}
	if !h.HasSOA {
		t.Error("expected HasSOA")
	}
	if !h.HasNS {
		t.Error("expected HasNS")
	}
	if !h.HasA {
		t.Error("expected HasA")
	}
	if !h.HasAAAA {
		t.Error("expected HasAAAA")
	}
	if !h.HasMX {
		t.Error("expected HasMX")
	}
	if !h.HasSPF {
		t.Error("expected HasSPF")
	}
	if !h.HasDMARC {
		t.Error("expected HasDMARC")
	}
	if !h.HasCAA {
		t.Error("expected HasCAA")
	}
	if h.NSCount != 2 {
		t.Errorf("expected 2 NS targets, got %d", h.NSCount)
	}
	if h.MinTTL != 300 {
		t.Errorf("expected min TTL 300, got %d", h.MinTTL)
	}
	if h.MaxTTL != 3600 {
		t.Errorf("expected max TTL 3600, got %d", h.MaxTTL)
	}
	if len(h.TypeDistribution) == 0 {
		t.Error("expected type distribution")
	}
	if len(h.TTLByType) == 0 {
		t.Error("expected TTL by type")
	}
	if len(h.RecordsByType) == 0 {
		t.Error("expected records by type map")
	}
}

func TestAnalyzeHealthDNSSEC(t *testing.T) {
	records := []ParsedRecord{
		{Name: "example.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.example.com. admin.example.com. 1 3600 900 604800 86400"},
		{Name: "example.com.", TTL: 3600, Class: "IN", Type: "DNSKEY", RData: "257 3 13 base64key=="},
		{Name: "example.com.", TTL: 3600, Class: "IN", Type: "DNSKEY", RData: "256 3 13 base64zsk=="},
		{Name: "example.com.", TTL: 3600, Class: "IN", Type: "RRSIG", RData: "SOA 13 2 3600 20250101000000 20240101000000 12345 example.com. sig=="},
		{Name: "example.com.", TTL: 3600, Class: "IN", Type: "RRSIG", RData: "NS 13 2 3600 20250101000000 20240101000000 12345 example.com. sig=="},
		{Name: "example.com.", TTL: 3600, Class: "IN", Type: "RRSIG", RData: "DNSKEY 13 2 3600 20250101000000 20240101000000 12345 example.com. sig=="},
		{Name: "example.com.", TTL: 0, Class: "IN", Type: "NSEC3PARAM", RData: "1 0 0 -"},
	}

	h := AnalyzeHealth(records)

	if !h.HasDNSSEC {
		t.Error("expected HasDNSSEC")
	}
	if h.DNSKEYCount != 2 {
		t.Errorf("expected 2 DNSKEYs, got %d", h.DNSKEYCount)
	}
	if h.RRSIGCount != 3 {
		t.Errorf("expected 3 RRSIGs, got %d", h.RRSIGCount)
	}
	if h.NSEC3Count != 0 {
		t.Errorf("expected 0 NSEC3 (only NSEC3PARAM present), got %d", h.NSEC3Count)
	}
	if h.NSEC3ParamCount != 1 {
		t.Errorf("expected 1 NSEC3PARAM, got %d", h.NSEC3ParamCount)
	}
}

func TestStructuralScoreWellFormed(t *testing.T) {
	records := []ParsedRecord{
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.ex.com. a.ex.com. 2025010101 3600 900 1209600 86400"},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns1.ex.com."},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns2.ex.com."},
		{Name: "ex.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"},
		{Name: "ex.com.", TTL: 300, Class: "IN", Type: "AAAA", RData: "::1"},
	}
	h := AnalyzeHealth(records)
	if h.StructuralVerdict != "Well-Formed" {
		t.Errorf("expected Well-Formed, got %s (score %d)", h.StructuralVerdict, h.StructuralScore)
	}
	if h.StructuralScore < 90 {
		t.Errorf("expected structural score >= 90, got %d", h.StructuralScore)
	}
}

func TestStructuralScoreMinimal(t *testing.T) {
	records := []ParsedRecord{
		{Name: "ex.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"},
	}
	h := AnalyzeHealth(records)
	if h.StructuralVerdict == "Well-Formed" {
		t.Errorf("expected non-Well-Formed verdict for A-only zone, got %s", h.StructuralVerdict)
	}
	if h.StructuralScore >= 50 {
		t.Errorf("expected structural score < 50, got %d", h.StructuralScore)
	}
}

func TestOperationalSignalsNotScored(t *testing.T) {
	withEmail := []ParsedRecord{
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.ex.com. a.ex.com. 2025010101 3600 900 1209600 86400"},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns1.ex.com."},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns2.ex.com."},
		{Name: "ex.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "TXT", RData: "v=spf1 -all"},
		{Name: "_dmarc.ex.com.", TTL: 3600, Class: "IN", Type: "TXT", RData: "v=DMARC1; p=reject"},
	}
	withoutEmail := []ParsedRecord{
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.ex.com. a.ex.com. 2025010101 3600 900 1209600 86400"},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns1.ex.com."},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns2.ex.com."},
		{Name: "ex.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"},
	}

	hWith := AnalyzeHealth(withEmail)
	hWithout := AnalyzeHealth(withoutEmail)

	if hWith.StructuralScore != hWithout.StructuralScore {
		t.Errorf("structural score should NOT change based on SPF/DMARC presence: with=%d, without=%d",
			hWith.StructuralScore, hWithout.StructuralScore)
	}

	if !hWith.HasSPF {
		t.Error("expected HasSPF when SPF TXT present")
	}
	if !hWith.HasDMARC {
		t.Error("expected HasDMARC when DMARC TXT present")
	}
	if hWithout.HasSPF {
		t.Error("expected no HasSPF when SPF TXT absent")
	}
}

func TestSOATimerAnalysis(t *testing.T) {
	records := []ParsedRecord{
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.ex.com. admin.ex.com. 2025010101 3600 900 1209600 86400"},
	}
	h := AnalyzeHealth(records)
	if h.SOATimers == nil {
		t.Fatal("expected SOA timer analysis")
	}
	if h.SOATimers.Serial != 2025010101 {
		t.Errorf("expected serial 2025010101, got %d", h.SOATimers.Serial)
	}
	if h.SOATimers.Refresh != 3600 {
		t.Errorf("expected refresh 3600, got %d", h.SOATimers.Refresh)
	}
	if len(h.SOATimers.Findings) != 0 {
		t.Errorf("expected 0 SOA findings for well-formed SOA, got %d: %v", len(h.SOATimers.Findings), h.SOATimers.Findings)
	}
}

func TestSOATimerBadValues(t *testing.T) {
	records := []ParsedRecord{
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.ex.com. admin.ex.com. 0 60 60 3600 172800"},
	}
	h := AnalyzeHealth(records)
	if h.SOATimers == nil {
		t.Fatal("expected SOA timer analysis")
	}
	if len(h.SOATimers.Findings) == 0 {
		t.Error("expected findings for bad SOA timers")
	}
	foundSerial := false
	foundRefresh := false
	foundRetry := false
	for _, f := range h.SOATimers.Findings {
		if f.Field == "serial" {
			foundSerial = true
		}
		if f.Field == "refresh" {
			foundRefresh = true
		}
		if f.Field == "retry" {
			foundRetry = true
		}
	}
	if !foundSerial {
		t.Error("expected serial=0 finding")
	}
	if !foundRefresh {
		t.Error("expected low refresh finding")
	}
	if !foundRetry {
		t.Error("expected retry >= refresh finding")
	}
}

func TestDuplicateDetection(t *testing.T) {
	records := []ParsedRecord{
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "A", RData: "1.2.3.4"},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "A", RData: "1.2.3.4"},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "A", RData: "5.6.7.8"},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.ex.com. a.ex.com. 1 3600 900 1209600 86400"},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns1.ex.com."},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns2.ex.com."},
	}
	h := AnalyzeHealth(records)
	if len(h.Duplicates) != 1 {
		t.Errorf("expected 1 duplicate RRset, got %d", len(h.Duplicates))
	}
	if len(h.Duplicates) > 0 && h.Duplicates[0].Count != 2 {
		t.Errorf("expected duplicate count 2, got %d", h.Duplicates[0].Count)
	}
}

func TestZoneProfileDelegationOnly(t *testing.T) {
	records := []ParsedRecord{
		{Name: "com.", TTL: 86400, Class: "IN", Type: "SOA", RData: "a.gtld-servers.net. nstld.verisign-grs.com. 1 1800 900 604800 86400"},
		{Name: "com.", TTL: 172800, Class: "IN", Type: "NS", RData: "a.gtld-servers.net."},
		{Name: "com.", TTL: 172800, Class: "IN", Type: "NS", RData: "b.gtld-servers.net."},
		{Name: "example.com.", TTL: 86400, Class: "IN", Type: "DS", RData: "12345 8 2 abc123"},
	}
	h := AnalyzeHealth(records)
	if h.ZoneProfile != "Delegation-Only" {
		t.Errorf("expected Delegation-Only profile, got %s", h.ZoneProfile)
	}
	if len(h.PolicySignals) != 0 {
		t.Errorf("expected no policy signals for delegation-only zone, got %d", len(h.PolicySignals))
	}
}

func TestZoneProfileFullService(t *testing.T) {
	records := []ParsedRecord{
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.ex.com. a.ex.com. 2025010101 3600 900 1209600 86400"},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns1.ex.com."},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns2.ex.com."},
		{Name: "ex.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "MX", RData: "10 mail.ex.com."},
	}
	h := AnalyzeHealth(records)
	if h.ZoneProfile != "Full-Service" {
		t.Errorf("expected Full-Service profile, got %s", h.ZoneProfile)
	}
}

func TestPolicySignalsMXWithoutSPF(t *testing.T) {
	records := []ParsedRecord{
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.ex.com. a.ex.com. 2025010101 3600 900 1209600 86400"},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns1.ex.com."},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns2.ex.com."},
		{Name: "ex.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "MX", RData: "10 mail.ex.com."},
	}
	h := AnalyzeHealth(records)

	var spfSignal *PolicySignal
	for i, s := range h.PolicySignals {
		if s.Label == "SPF" {
			spfSignal = &h.PolicySignals[i]
			break
		}
	}
	if spfSignal == nil {
		t.Fatal("expected SPF policy signal when MX present without SPF")
	}
	if spfSignal.Status != "missing" {
		t.Errorf("expected SPF status 'missing', got '%s'", spfSignal.Status)
	}
}

func TestPolicySignalsMXWithSPF(t *testing.T) {
	records := []ParsedRecord{
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.ex.com. a.ex.com. 2025010101 3600 900 1209600 86400"},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns1.ex.com."},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns2.ex.com."},
		{Name: "ex.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "MX", RData: "10 mail.ex.com."},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "TXT", RData: "v=spf1 include:_spf.google.com ~all"},
	}
	h := AnalyzeHealth(records)

	var spfSignal *PolicySignal
	for i, s := range h.PolicySignals {
		if s.Label == "SPF" {
			spfSignal = &h.PolicySignals[i]
			break
		}
	}
	if spfSignal == nil {
		t.Fatal("expected SPF policy signal when SPF present")
	}
	if spfSignal.Status != "detected" {
		t.Errorf("expected SPF status 'detected', got '%s'", spfSignal.Status)
	}
}

func TestPolicySignalsSuppressedForDelegation(t *testing.T) {
	records := []ParsedRecord{
		{Name: "com.", TTL: 86400, Class: "IN", Type: "SOA", RData: "a.gtld-servers.net. nstld.verisign-grs.com. 1 1800 900 604800 86400"},
		{Name: "com.", TTL: 172800, Class: "IN", Type: "NS", RData: "a.gtld-servers.net."},
		{Name: "com.", TTL: 172800, Class: "IN", Type: "NS", RData: "b.gtld-servers.net."},
	}
	h := AnalyzeHealth(records)

	for _, s := range h.PolicySignals {
		if s.Status == "missing" {
			t.Errorf("delegation-only zone should not have 'missing' signals, found: %s", s.Label)
		}
	}
}

func TestPolicySignalsWebOnlyNoCAA(t *testing.T) {
	records := []ParsedRecord{
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.ex.com. a.ex.com. 2025010101 3600 900 1209600 86400"},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns1.ex.com."},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns2.ex.com."},
		{Name: "ex.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"},
	}
	h := AnalyzeHealth(records)
	if h.ZoneProfile != "Web-Only" {
		t.Errorf("expected Web-Only profile, got %s", h.ZoneProfile)
	}

	var caaSignal *PolicySignal
	for i, s := range h.PolicySignals {
		if s.Label == "CAA" {
			caaSignal = &h.PolicySignals[i]
			break
		}
	}
	if caaSignal == nil {
		t.Fatal("expected CAA info signal for web-only zone without CAA")
	}
	if caaSignal.Status != "info" {
		t.Errorf("expected CAA status 'info', got '%s'", caaSignal.Status)
	}
}

func TestPolicySignalsMinimalZoneStillWarns(t *testing.T) {
	records := []ParsedRecord{
		{Name: "ex.com.", TTL: 300, Class: "IN", Type: "CNAME", RData: "other.example.net."},
	}
	h := AnalyzeHealth(records)
	if h.ZoneProfile != "Minimal" {
		t.Errorf("expected Minimal profile, got %s", h.ZoneProfile)
	}
	var hasSPFMissing, hasDMARCMissing bool
	for _, s := range h.PolicySignals {
		if s.Label == "SPF" && s.Status == "missing" {
			hasSPFMissing = true
		}
		if s.Label == "DMARC" && s.Status == "missing" {
			hasDMARCMissing = true
		}
	}
	if !hasSPFMissing {
		t.Error("minimal zone (owned domain) must still warn about missing SPF — domain is spoofable (RFC 7208)")
	}
	if !hasDMARCMissing {
		t.Error("minimal zone (owned domain) must still warn about missing DMARC — no enforcement policy (RFC 7489)")
	}
}

func TestPolicySignalsParkedDomainSpoofable(t *testing.T) {
	records := []ParsedRecord{
		{Name: "parked.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.parked.com. admin.parked.com. 2025010101 3600 900 1209600 86400"},
		{Name: "parked.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns1.parked.com."},
		{Name: "parked.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns2.parked.com."},
		{Name: "parked.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"},
	}
	h := AnalyzeHealth(records)
	var hasSPFMissing, hasDMARCMissing bool
	for _, s := range h.PolicySignals {
		if s.Label == "SPF" && s.Status == "missing" {
			hasSPFMissing = true
		}
		if s.Label == "DMARC" && s.Status == "missing" {
			hasDMARCMissing = true
		}
	}
	if !hasSPFMissing {
		t.Error("parked domain with no email infrastructure must warn about missing SPF — attackers can spoof FROM this domain without needing MX")
	}
	if !hasDMARCMissing {
		t.Error("parked domain with no email infrastructure must warn about missing DMARC — no policy enforcement for spoofed emails")
	}
}

func TestDANEAbsenceNotFlagged(t *testing.T) {
	records := []ParsedRecord{
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.ex.com. a.ex.com. 2025010101 3600 900 1209600 86400"},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns1.ex.com."},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns2.ex.com."},
		{Name: "ex.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "MX", RData: "10 mail.ex.com."},
	}
	h := AnalyzeHealth(records)

	for _, s := range h.PolicySignals {
		if s.Label == "TLSA/DANE" && s.Status == "missing" {
			t.Error("DANE absence should never be flagged as missing — it's per-service and often managed elsewhere")
		}
	}
}

// ============================================================================
// GOLDEN RULES — Zone Health Policy Signals
//
// These tests encode RFC-mandated behaviors that MUST NEVER be weakened.
// If a test here fails, the code change is wrong — not the test.
//
// Core principles:
//   1. SPF absence = spoofable (RFC 7208 §2.1) — attackers send FROM the
//      domain, they do not need the domain to receive mail.
//   2. DMARC absence = no enforcement (RFC 7489 §4) — receiving servers
//      have no policy to act on.
//   3. Both MUST be flagged for ALL non-delegation zones, including parked,
//      web-only, minimal, and zones with zero email infrastructure.
//   4. Only TLD/delegation-only zones are exempt (SPF/DMARC do not apply
//      at the TLD level).
//   5. DANE/TLSA absence is NEVER flagged — it is per-service
//      (_443._tcp.host) and typically managed externally.
//   6. Policy signals MUST NEVER affect the structural score.
// ============================================================================

func TestGoldenRuleSPFAlwaysFlaggedNonDelegation(t *testing.T) {
	profiles := []struct {
		name    string
		records []ParsedRecord
	}{
		{"Full-Service (MX present)", []ParsedRecord{
			{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.ex.com. a.ex.com. 2025010101 3600 900 1209600 86400"},
			{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns1.ex.com."},
			{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns2.ex.com."},
			{Name: "ex.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"},
			{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "MX", RData: "10 mail.ex.com."},
		}},
		{"Web-Only (no MX)", []ParsedRecord{
			{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.ex.com. a.ex.com. 2025010101 3600 900 1209600 86400"},
			{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns1.ex.com."},
			{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns2.ex.com."},
			{Name: "ex.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"},
		}},
		{"Minimal (CNAME only)", []ParsedRecord{
			{Name: "ex.com.", TTL: 300, Class: "IN", Type: "CNAME", RData: "other.example.net."},
		}},
		{"Parked domain (SOA+NS+A, zero email)", []ParsedRecord{
			{Name: "parked.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.parked.com. admin.parked.com. 1 3600 900 1209600 86400"},
			{Name: "parked.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns1.parked.com."},
			{Name: "parked.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns2.parked.com."},
			{Name: "parked.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"},
		}},
	}

	for _, tc := range profiles {
		t.Run(tc.name, func(t *testing.T) {
			h := AnalyzeHealth(tc.records)
			if h.ZoneProfile == "Delegation-Only" {
				t.Fatalf("test case %q should NOT be Delegation-Only", tc.name)
			}
			var hasSPFMissing bool
			for _, s := range h.PolicySignals {
				if s.Label == "SPF" && s.Status == "missing" {
					hasSPFMissing = true
				}
			}
			if !hasSPFMissing {
				t.Errorf("RFC 7208: %s zone without SPF MUST flag missing — any server can spoof this domain. Profile=%s", tc.name, h.ZoneProfile)
			}
		})
	}
}

func TestGoldenRuleDMARCAlwaysFlaggedNonDelegation(t *testing.T) {
	profiles := []struct {
		name    string
		records []ParsedRecord
	}{
		{"Full-Service (MX present)", []ParsedRecord{
			{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.ex.com. a.ex.com. 2025010101 3600 900 1209600 86400"},
			{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns1.ex.com."},
			{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns2.ex.com."},
			{Name: "ex.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"},
			{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "MX", RData: "10 mail.ex.com."},
		}},
		{"Web-Only (no email at all)", []ParsedRecord{
			{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.ex.com. a.ex.com. 2025010101 3600 900 1209600 86400"},
			{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns1.ex.com."},
			{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns2.ex.com."},
			{Name: "ex.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"},
		}},
		{"Minimal (bare domain)", []ParsedRecord{
			{Name: "ex.com.", TTL: 300, Class: "IN", Type: "CNAME", RData: "other.example.net."},
		}},
	}

	for _, tc := range profiles {
		t.Run(tc.name, func(t *testing.T) {
			h := AnalyzeHealth(tc.records)
			if h.ZoneProfile == "Delegation-Only" {
				t.Fatalf("test case %q should NOT be Delegation-Only", tc.name)
			}
			var hasDMARCMissing bool
			for _, s := range h.PolicySignals {
				if s.Label == "DMARC" && s.Status == "missing" {
					hasDMARCMissing = true
				}
			}
			if !hasDMARCMissing {
				t.Errorf("RFC 7489: %s zone without DMARC MUST flag missing — no enforcement policy for spoofed email. Profile=%s", tc.name, h.ZoneProfile)
			}
		})
	}
}

func TestGoldenRuleDelegationOnlySuppressesSPFDMARC(t *testing.T) {
	records := []ParsedRecord{
		{Name: "com.", TTL: 86400, Class: "IN", Type: "SOA", RData: "a.gtld-servers.net. nstld.verisign-grs.com. 1 1800 900 604800 86400"},
		{Name: "com.", TTL: 172800, Class: "IN", Type: "NS", RData: "a.gtld-servers.net."},
		{Name: "com.", TTL: 172800, Class: "IN", Type: "NS", RData: "b.gtld-servers.net."},
		{Name: "example.com.", TTL: 86400, Class: "IN", Type: "DS", RData: "12345 8 2 abc123"},
	}
	h := AnalyzeHealth(records)
	if h.ZoneProfile != "Delegation-Only" {
		t.Fatalf("expected Delegation-Only, got %s", h.ZoneProfile)
	}
	for _, s := range h.PolicySignals {
		if s.Label == "SPF" || s.Label == "DMARC" {
			t.Errorf("TLD/delegation-only zone MUST NOT flag SPF/DMARC — they do not apply at TLD level. Found: %s (%s)", s.Label, s.Status)
		}
	}
}

func TestGoldenRuleDANENeverFlaggedMissing(t *testing.T) {
	scenarios := []struct {
		name    string
		records []ParsedRecord
	}{
		{"Full-Service with MX", []ParsedRecord{
			{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.ex.com. a.ex.com. 2025010101 3600 900 1209600 86400"},
			{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns1.ex.com."},
			{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns2.ex.com."},
			{Name: "ex.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"},
			{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "MX", RData: "10 mail.ex.com."},
		}},
		{"Web-Only", []ParsedRecord{
			{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.ex.com. a.ex.com. 2025010101 3600 900 1209600 86400"},
			{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns1.ex.com."},
			{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns2.ex.com."},
			{Name: "ex.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"},
		}},
		{"Delegation-Only", []ParsedRecord{
			{Name: "com.", TTL: 86400, Class: "IN", Type: "SOA", RData: "a.gtld-servers.net. nstld.verisign-grs.com. 1 1800 900 604800 86400"},
			{Name: "com.", TTL: 172800, Class: "IN", Type: "NS", RData: "a.gtld-servers.net."},
		}},
	}

	for _, tc := range scenarios {
		t.Run(tc.name, func(t *testing.T) {
			h := AnalyzeHealth(tc.records)
			for _, s := range h.PolicySignals {
				if s.Label == "TLSA/DANE" && s.Status == "missing" {
					t.Errorf("DANE/TLSA absence MUST NEVER be flagged as missing — it is per-service (_443._tcp) and typically managed outside the zone file")
				}
			}
		})
	}
}

func TestGoldenRuleDANEPresentIsDetected(t *testing.T) {
	records := []ParsedRecord{
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.ex.com. a.ex.com. 2025010101 3600 900 1209600 86400"},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns1.ex.com."},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns2.ex.com."},
		{Name: "ex.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"},
		{Name: "_443._tcp.ex.com.", TTL: 3600, Class: "IN", Type: "TLSA", RData: "3 1 1 abc123"},
	}
	h := AnalyzeHealth(records)
	if !h.HasTLSA {
		t.Fatal("expected HasTLSA when TLSA record present")
	}
	var found bool
	for _, s := range h.PolicySignals {
		if s.Label == "TLSA/DANE" && s.Status == "detected" {
			found = true
		}
	}
	if !found {
		t.Error("DANE/TLSA present in zone MUST appear as 'detected' signal")
	}
}

func TestGoldenRulePolicySignalsNeverAffectStructuralScore(t *testing.T) {
	base := []ParsedRecord{
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.ex.com. a.ex.com. 2025010101 3600 900 1209600 86400"},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns1.ex.com."},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns2.ex.com."},
		{Name: "ex.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"},
		{Name: "ex.com.", TTL: 300, Class: "IN", Type: "AAAA", RData: "::1"},
	}

	full := make([]ParsedRecord, len(base))
	copy(full, base)
	full = append(full,
		ParsedRecord{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "MX", RData: "10 mail.ex.com."},
		ParsedRecord{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "TXT", RData: "v=spf1 -all"},
		ParsedRecord{Name: "_dmarc.ex.com.", TTL: 3600, Class: "IN", Type: "TXT", RData: "v=DMARC1; p=reject"},
		ParsedRecord{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "CAA", RData: "0 issue \"letsencrypt.org\""},
		ParsedRecord{Name: "_443._tcp.ex.com.", TTL: 3600, Class: "IN", Type: "TLSA", RData: "3 1 1 abc123"},
	)

	hBare := AnalyzeHealth(base)
	hFull := AnalyzeHealth(full)

	if hBare.StructuralScore != hFull.StructuralScore {
		t.Errorf("structural score MUST NOT change based on policy records: bare=%d, full=%d — SPF/DMARC/CAA/TLSA are operational, not structural",
			hBare.StructuralScore, hFull.StructuralScore)
	}
}

func TestGoldenRuleSPFPresentIsDetected(t *testing.T) {
	records := []ParsedRecord{
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.ex.com. a.ex.com. 2025010101 3600 900 1209600 86400"},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns1.ex.com."},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns2.ex.com."},
		{Name: "ex.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "TXT", RData: "v=spf1 include:_spf.google.com ~all"},
	}
	h := AnalyzeHealth(records)
	var found bool
	for _, s := range h.PolicySignals {
		if s.Label == "SPF" && s.Status == "detected" {
			found = true
		}
	}
	if !found {
		t.Error("SPF present in zone MUST appear as 'detected' signal — not 'missing'")
	}
}

func TestGoldenRuleDMARCPresentIsDetected(t *testing.T) {
	records := []ParsedRecord{
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.ex.com. a.ex.com. 2025010101 3600 900 1209600 86400"},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns1.ex.com."},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns2.ex.com."},
		{Name: "ex.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"},
		{Name: "_dmarc.ex.com.", TTL: 3600, Class: "IN", Type: "TXT", RData: "v=DMARC1; p=reject"},
	}
	h := AnalyzeHealth(records)
	var found bool
	for _, s := range h.PolicySignals {
		if s.Label == "DMARC" && s.Status == "detected" {
			found = true
		}
	}
	if !found {
		t.Error("DMARC present in zone MUST appear as 'detected' signal — not 'missing'")
	}
}

func TestGoldenRuleMissingSPFMessage(t *testing.T) {
	records := []ParsedRecord{
		{Name: "ex.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"},
	}
	h := AnalyzeHealth(records)
	for _, s := range h.PolicySignals {
		if s.Label == "SPF" && s.Status == "missing" {
			if s.Detail == "" {
				t.Error("missing SPF signal must have non-empty detail explaining the risk")
			}
			return
		}
	}
	t.Error("expected missing SPF signal for A-only zone")
}

func TestTTLSpreadHigh(t *testing.T) {
	records := []ParsedRecord{
		{Name: "ex.com.", TTL: 60, Class: "IN", Type: "A", RData: "1.2.3.4"},
		{Name: "ex.com.", TTL: 86400, Class: "IN", Type: "SOA", RData: "ns1.ex.com. a.ex.com. 1 3600 900 1209600 86400"},
		{Name: "ex.com.", TTL: 86400, Class: "IN", Type: "NS", RData: "ns1.ex.com."},
		{Name: "ex.com.", TTL: 86400, Class: "IN", Type: "NS", RData: "ns2.ex.com."},
	}
	h := AnalyzeHealth(records)
	if !h.TTLSpreadHigh {
		t.Error("expected TTLSpreadHigh for 60s vs 86400s")
	}
}
