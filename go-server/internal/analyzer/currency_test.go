// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
	"testing"
)

func TestComputeRescanInterval_WithObservedTTL(t *testing.T) {
	result := computeRescanInterval(300, 3600)
	if result != 330 {
		t.Errorf("expected 330 (300 * 1.1), got %d", result)
	}
}

func TestComputeRescanInterval_FallsBackToTypical(t *testing.T) {
	result := computeRescanInterval(0, 3600)
	if result < 3960 || result > 3961 {
		t.Errorf("expected ~3960 (3600 * 1.1), got %d", result)
	}
}

func TestComputeRescanInterval_DefaultWhenBothZero(t *testing.T) {
	result := computeRescanInterval(0, 0)
	if result != 330 {
		t.Errorf("expected 330 (300 default * 1.1), got %d", result)
	}
}

func TestComputeRescanInterval_FloorEnforced(t *testing.T) {
	result := computeRescanInterval(10, 0)
	if result != currencyFloorSeconds {
		t.Errorf("expected floor %d, got %d", currencyFloorSeconds, result)
	}
}

func TestComputeRescanInterval_CeilingEnforced(t *testing.T) {
	result := computeRescanInterval(100000, 0)
	if result != currencyCeilingSeconds {
		t.Errorf("expected ceiling %d, got %d", currencyCeilingSeconds, result)
	}
}

func TestFormatRescanLabel_Seconds(t *testing.T) {
	label := formatRescanLabel(45)
	if label != "45 seconds" {
		t.Errorf("expected '45 seconds', got '%s'", label)
	}
}

func TestFormatRescanLabel_OneMinute(t *testing.T) {
	label := formatRescanLabel(60)
	if label != "1 minute" {
		t.Errorf("expected '1 minute', got '%s'", label)
	}
}

func TestFormatRescanLabel_Minutes(t *testing.T) {
	label := formatRescanLabel(300)
	if label != "5 minutes" {
		t.Errorf("expected '5 minutes', got '%s'", label)
	}
}

func TestFormatRescanLabel_OneHour(t *testing.T) {
	label := formatRescanLabel(3600)
	if label != "1 hour" {
		t.Errorf("expected '1 hour', got '%s'", label)
	}
}

func TestFormatRescanLabel_Hours(t *testing.T) {
	label := formatRescanLabel(7200)
	if label != "2 hours" {
		t.Errorf("expected '2 hours', got '%s'", label)
	}
}

func TestFormatRescanLabel_MaxDay(t *testing.T) {
	label := formatRescanLabel(86400)
	if label != "24 hours" {
		t.Errorf("expected '24 hours', got '%s'", label)
	}
}

func TestBuildCurrencyMatrix_WithResolverTTLs(t *testing.T) {
	resolverTTL := map[string]uint32{
		"A":   60,
		"MX":  1800,
		"TXT": 900,
	}
	authTTL := map[string]uint32{}

	result := BuildCurrencyMatrix(resolverTTL, authTTL)

	entries, ok := result["entries"].([]CurrencyEntry)
	if !ok {
		t.Fatal("expected entries to be []CurrencyEntry")
	}

	if len(entries) == 0 {
		t.Fatal("expected non-empty entries")
	}

	count, ok := result["entry_count"].(int)
	if !ok || count != len(entries) {
		t.Errorf("entry_count mismatch: got %v, expected %d", result["entry_count"], len(entries))
	}

	for _, entry := range entries {
		if entry.RecordType == "A" {
			if entry.ObservedTTL != 60 {
				t.Errorf("A record: expected observed TTL 60, got %d", entry.ObservedTTL)
			}
			if entry.RescanAfter != 66 {
				t.Errorf("A record: expected rescan 66, got %d", entry.RescanAfter)
			}
		}
		if entry.RecordType == "MX" {
			if entry.ObservedTTL != 1800 {
				t.Errorf("MX record: expected observed TTL 1800, got %d", entry.ObservedTTL)
			}
		}
		if entry.PropagationNote == "" {
			t.Errorf("%s: expected non-empty propagation note", entry.RecordType)
		}
	}
}

func TestBuildCurrencyMatrix_FallsBackToAuthTTL(t *testing.T) {
	resolverTTL := map[string]uint32{}
	authTTL := map[string]uint32{
		"A": 120,
	}

	result := BuildCurrencyMatrix(resolverTTL, authTTL)
	entries := result["entries"].([]CurrencyEntry)

	for _, entry := range entries {
		if entry.RecordType == "A" {
			if entry.ObservedTTL != 120 {
				t.Errorf("A record: expected observed TTL 120 from auth, got %d", entry.ObservedTTL)
			}
			return
		}
	}
	t.Error("A record entry not found")
}

func TestBuildCurrencyMatrix_EmptyTTLs(t *testing.T) {
	result := BuildCurrencyMatrix(map[string]uint32{}, map[string]uint32{})

	entries := result["entries"].([]CurrencyEntry)
	if len(entries) == 0 {
		t.Fatal("expected entries even with empty TTLs")
	}

	for _, entry := range entries {
		if entry.ObservedTTL != 0 {
			t.Errorf("%s: expected 0 observed TTL, got %d", entry.RecordType, entry.ObservedTTL)
		}
		if entry.RescanAfter < currencyFloorSeconds {
			t.Errorf("%s: rescan below floor", entry.RecordType)
		}
	}
}

func TestBuildCurrencyMatrix_AllRecordTypesPresent(t *testing.T) {
	result := BuildCurrencyMatrix(map[string]uint32{}, map[string]uint32{})
	entries := result["entries"].([]CurrencyEntry)

	expected := map[string]bool{
		"A": true, "AAAA": true, "MX": true, "TXT": true, "NS": true,
		"CNAME": true, "CAA": true, "SOA": true, "SPF": true, "DMARC": true,
		"DKIM": true, "MTA-STS": true, "TLS-RPT": true, "BIMI": true,
		"TLSA": true, "DNSSEC": true, "DANE": true,
	}

	found := map[string]bool{}
	for _, entry := range entries {
		found[entry.RecordType] = true
	}

	for rt := range expected {
		if !found[rt] {
			t.Errorf("missing record type %s in currency matrix", rt)
		}
	}
}
