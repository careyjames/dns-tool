package zoneparse

import (
	"testing"
)

func TestBuildRecordMap(t *testing.T) {
	records := []ParsedRecord{
		{Name: "example.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"},
		{Name: "example.com.", TTL: 300, Class: "IN", Type: "A", RData: "5.6.7.8"},
		{Name: "example.com.", TTL: 3600, Class: "IN", Type: "MX", RData: "10 mail.example.com."},
	}
	m := buildRecordMap(records)
	if len(m) != 2 {
		t.Errorf("expected 2 keys, got %d", len(m))
	}
	aRecs := m["example.com.|A"]
	if len(aRecs) != 2 {
		t.Errorf("expected 2 A records, got %d", len(aRecs))
	}
	mxRecs := m["example.com.|MX"]
	if len(mxRecs) != 1 {
		t.Errorf("expected 1 MX record, got %d", len(mxRecs))
	}
}

func TestBuildRecordMap_Empty(t *testing.T) {
	m := buildRecordMap(nil)
	if len(m) != 0 {
		t.Errorf("expected empty map, got %d entries", len(m))
	}
}

func TestNormalizeRData(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"  Hello World  ", "hello world"},
		{`"quoted"`, "quoted"},
		{"UPPER", "upper"},
		{"", ""},
		{`"v=spf1 include:_spf.google.com ~all"`, "v=spf1 include:_spf.google.com ~all"},
	}
	for _, tc := range tests {
		got := normalizeRData(tc.input)
		if got != tc.expected {
			t.Errorf("normalizeRData(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestExtractTTLs(t *testing.T) {
	results := map[string]any{
		"resolver_ttl": map[string]any{
			"A":    float64(300),
			"AAAA": float64(600),
			"MX":   float64(3600),
		},
	}
	ttls := extractTTLs(results)
	if ttls["A"] != 300 {
		t.Errorf("expected A TTL 300, got %d", ttls["A"])
	}
	if ttls["AAAA"] != 600 {
		t.Errorf("expected AAAA TTL 600, got %d", ttls["AAAA"])
	}
	if ttls["MX"] != 3600 {
		t.Errorf("expected MX TTL 3600, got %d", ttls["MX"])
	}
}

func TestExtractTTLs_NoResolverTTL(t *testing.T) {
	results := map[string]any{
		"domain": "example.com",
	}
	ttls := extractTTLs(results)
	if len(ttls) != 0 {
		t.Errorf("expected empty TTLs, got %d", len(ttls))
	}
}

func TestExtractLiveRecords(t *testing.T) {
	results := map[string]any{
		"domain": "example.com",
		"basic_records": map[string]any{
			"A":    []any{"1.2.3.4", "5.6.7.8"},
			"AAAA": []any{"2001:db8::1"},
			"MX":   []any{"10 mail.example.com."},
		},
		"resolver_ttl": map[string]any{
			"A":    float64(300),
			"AAAA": float64(600),
			"MX":   float64(3600),
		},
	}
	records := extractLiveRecords(results)
	if len(records) != 4 {
		t.Errorf("expected 4 records, got %d", len(records))
	}
	for _, r := range records {
		if r.Name != "example.com." {
			t.Errorf("expected name example.com., got %s", r.Name)
		}
		if r.Class != "IN" {
			t.Errorf("expected class IN, got %s", r.Class)
		}
	}
}

func TestExtractLiveRecords_NoBasicRecords(t *testing.T) {
	results := map[string]any{
		"domain": "example.com",
	}
	records := extractLiveRecords(results)
	if len(records) != 0 {
		t.Errorf("expected 0 records, got %d", len(records))
	}
}

func TestExtractLiveRecords_EmptyArrays(t *testing.T) {
	results := map[string]any{
		"domain": "example.com",
		"basic_records": map[string]any{
			"A": []any{},
		},
	}
	records := extractLiveRecords(results)
	if len(records) != 0 {
		t.Errorf("expected 0 records, got %d", len(records))
	}
}

func TestExtractLiveRecords_SkipsEmptyStrings(t *testing.T) {
	results := map[string]any{
		"domain": "example.com",
		"basic_records": map[string]any{
			"A": []any{"1.2.3.4", ""},
		},
	}
	records := extractLiveRecords(results)
	if len(records) != 1 {
		t.Errorf("expected 1 record (skip empty), got %d", len(records))
	}
}

func TestFindAddedEntries(t *testing.T) {
	zoneMap := map[string][]ParsedRecord{
		"example.com.|A": {
			{Name: "example.com.", Type: "A", RData: "1.2.3.4", TTL: 300},
		},
		"example.com.|MX": {
			{Name: "example.com.", Type: "MX", RData: "10 mail.example.com.", TTL: 3600},
		},
	}
	liveMap := map[string][]ParsedRecord{
		"example.com.|A": {
			{Name: "example.com.", Type: "A", RData: "1.2.3.4", TTL: 300},
		},
	}
	entries := findAddedEntries(zoneMap, liveMap)
	if len(entries) != 1 {
		t.Fatalf("expected 1 added entry, got %d", len(entries))
	}
	if entries[0].Category != DriftAdded {
		t.Errorf("expected category added, got %s", entries[0].Category)
	}
	if entries[0].Type != "MX" {
		t.Errorf("expected type MX, got %s", entries[0].Type)
	}
}

func TestFindAddedEntries_NoAdded(t *testing.T) {
	m := map[string][]ParsedRecord{
		"example.com.|A": {{Name: "example.com.", Type: "A", RData: "1.2.3.4"}},
	}
	entries := findAddedEntries(m, m)
	if len(entries) != 0 {
		t.Errorf("expected 0 added entries, got %d", len(entries))
	}
}

func TestFindMissingEntries(t *testing.T) {
	zoneMap := map[string][]ParsedRecord{
		"example.com.|A": {
			{Name: "example.com.", Type: "A", RData: "1.2.3.4"},
		},
	}
	liveMap := map[string][]ParsedRecord{
		"example.com.|A": {
			{Name: "example.com.", Type: "A", RData: "1.2.3.4"},
		},
		"example.com.|AAAA": {
			{Name: "example.com.", Type: "AAAA", RData: "2001:db8::1", TTL: 600},
		},
	}
	entries := findMissingEntries(zoneMap, liveMap)
	if len(entries) != 1 {
		t.Fatalf("expected 1 missing entry, got %d", len(entries))
	}
	if entries[0].Category != DriftMissing {
		t.Errorf("expected category missing, got %s", entries[0].Category)
	}
	if entries[0].Type != "AAAA" {
		t.Errorf("expected type AAAA, got %s", entries[0].Type)
	}
}

func TestFindMissingEntries_NoMissing(t *testing.T) {
	m := map[string][]ParsedRecord{
		"example.com.|A": {{Name: "example.com.", Type: "A", RData: "1.2.3.4"}},
	}
	entries := findMissingEntries(m, m)
	if len(entries) != 0 {
		t.Errorf("expected 0 missing entries, got %d", len(entries))
	}
}

func TestFindChangedAndTTLEntries_TTLDiff(t *testing.T) {
	zoneMap := map[string][]ParsedRecord{
		"example.com.|A": {
			{Name: "example.com.", Type: "A", RData: "1.2.3.4", TTL: 300},
		},
	}
	liveMap := map[string][]ParsedRecord{
		"example.com.|A": {
			{Name: "example.com.", Type: "A", RData: "1.2.3.4", TTL: 600},
		},
	}
	changed, ttlOnly := findChangedAndTTLEntries(zoneMap, liveMap)
	if len(changed) != 0 {
		t.Errorf("expected 0 changed, got %d", len(changed))
	}
	if len(ttlOnly) != 1 {
		t.Fatalf("expected 1 ttl_only, got %d", len(ttlOnly))
	}
	if ttlOnly[0].Category != DriftTTLOnly {
		t.Errorf("expected category ttl_only, got %s", ttlOnly[0].Category)
	}
	if ttlOnly[0].ZoneTTL != 300 || ttlOnly[0].LiveTTL != 600 {
		t.Errorf("expected TTLs 300/600, got %d/%d", ttlOnly[0].ZoneTTL, ttlOnly[0].LiveTTL)
	}
}

func TestFindChangedAndTTLEntries_ValueDiff(t *testing.T) {
	zoneMap := map[string][]ParsedRecord{
		"example.com.|A": {
			{Name: "example.com.", Type: "A", RData: "1.2.3.4", TTL: 300},
		},
	}
	liveMap := map[string][]ParsedRecord{
		"example.com.|A": {
			{Name: "example.com.", Type: "A", RData: "9.9.9.9", TTL: 300},
		},
	}
	changed, ttlOnly := findChangedAndTTLEntries(zoneMap, liveMap)
	if len(ttlOnly) != 0 {
		t.Errorf("expected 0 ttl_only, got %d", len(ttlOnly))
	}
	if len(changed) != 1 {
		t.Fatalf("expected 1 changed, got %d", len(changed))
	}
	if changed[0].Category != DriftChanged {
		t.Errorf("expected category changed, got %s", changed[0].Category)
	}
}

func TestFindChangedAndTTLEntries_NoOverlap(t *testing.T) {
	zoneMap := map[string][]ParsedRecord{
		"example.com.|A": {
			{Name: "example.com.", Type: "A", RData: "1.2.3.4", TTL: 300},
		},
	}
	liveMap := map[string][]ParsedRecord{
		"example.com.|MX": {
			{Name: "example.com.", Type: "MX", RData: "10 mail.example.com.", TTL: 3600},
		},
	}
	changed, ttlOnly := findChangedAndTTLEntries(zoneMap, liveMap)
	if len(changed) != 0 {
		t.Errorf("expected 0 changed, got %d", len(changed))
	}
	if len(ttlOnly) != 0 {
		t.Errorf("expected 0 ttl_only, got %d", len(ttlOnly))
	}
}

func TestFindChangedAndTTLEntries_MatchingRecords(t *testing.T) {
	m := map[string][]ParsedRecord{
		"example.com.|A": {
			{Name: "example.com.", Type: "A", RData: "1.2.3.4", TTL: 300},
		},
	}
	changed, ttlOnly := findChangedAndTTLEntries(m, m)
	if len(changed) != 0 {
		t.Errorf("expected 0 changed, got %d", len(changed))
	}
	if len(ttlOnly) != 0 {
		t.Errorf("expected 0 ttl_only, got %d", len(ttlOnly))
	}
}

func TestCompareDrift_NoLiveData(t *testing.T) {
	zone := []ParsedRecord{
		{Name: "example.com.", Type: "A", RData: "1.2.3.4", TTL: 300, Class: "IN"},
	}
	live := map[string]any{}
	report := CompareDrift(zone, live)
	if report.ZoneRecords != 1 {
		t.Errorf("expected 1 zone record, got %d", report.ZoneRecords)
	}
	if report.LiveRecords != 0 {
		t.Errorf("expected 0 live records, got %d", report.LiveRecords)
	}
	if len(report.Added) != 1 {
		t.Errorf("expected 1 added entry, got %d", len(report.Added))
	}
}

func TestCompareDrift_MatchingRecords(t *testing.T) {
	zone := []ParsedRecord{
		{Name: "example.com.", Type: "A", RData: "1.2.3.4", TTL: 300, Class: "IN"},
	}
	live := map[string]any{
		"domain": "example.com",
		"basic_records": map[string]any{
			"A": []any{"1.2.3.4"},
		},
		"resolver_ttl": map[string]any{
			"A": float64(300),
		},
	}
	report := CompareDrift(zone, live)
	if report.TotalDrifts != 0 {
		t.Errorf("expected 0 drifts for matching records, got %d", report.TotalDrifts)
	}
}

func TestCompareDrift_MixedDrifts(t *testing.T) {
	zone := []ParsedRecord{
		{Name: "example.com.", Type: "A", RData: "1.2.3.4", TTL: 300, Class: "IN"},
		{Name: "example.com.", Type: "MX", RData: "10 mail.example.com.", TTL: 3600, Class: "IN"},
	}
	live := map[string]any{
		"domain": "example.com",
		"basic_records": map[string]any{
			"A":    []any{"1.2.3.4"},
			"AAAA": []any{"2001:db8::1"},
		},
		"resolver_ttl": map[string]any{
			"A":    float64(300),
			"AAAA": float64(300),
		},
	}
	report := CompareDrift(zone, live)
	if len(report.Added) == 0 {
		t.Error("expected at least 1 added entry (MX in zone but not in live)")
	}
	if len(report.Missing) == 0 {
		t.Error("expected at least 1 missing entry (AAAA in live but not in zone)")
	}
	if report.TotalDrifts != len(report.Added)+len(report.Missing)+len(report.Changed)+len(report.TTLOnly) {
		t.Errorf("TotalDrifts mismatch")
	}
}

func TestCompareDrift_TTLDifference(t *testing.T) {
	zone := []ParsedRecord{
		{Name: "example.com.", Type: "A", RData: "1.2.3.4", TTL: 300, Class: "IN"},
	}
	live := map[string]any{
		"domain": "example.com",
		"basic_records": map[string]any{
			"A": []any{"1.2.3.4"},
		},
		"resolver_ttl": map[string]any{
			"A": float64(600),
		},
	}
	report := CompareDrift(zone, live)
	if len(report.TTLOnly) != 1 {
		t.Errorf("expected 1 TTL-only drift, got %d", len(report.TTLOnly))
	}
}

func TestCompareDrift_ValueChanged(t *testing.T) {
	zone := []ParsedRecord{
		{Name: "example.com.", Type: "A", RData: "1.2.3.4", TTL: 300, Class: "IN"},
	}
	live := map[string]any{
		"domain": "example.com",
		"basic_records": map[string]any{
			"A": []any{"9.9.9.9"},
		},
		"resolver_ttl": map[string]any{
			"A": float64(300),
		},
	}
	report := CompareDrift(zone, live)
	if len(report.Changed) != 1 {
		t.Errorf("expected 1 changed drift, got %d", len(report.Changed))
	}
}

func TestCompareDrift_EmptyInput(t *testing.T) {
	report := CompareDrift(nil, map[string]any{})
	if report.TotalDrifts != 0 {
		t.Errorf("expected 0 drifts, got %d", report.TotalDrifts)
	}
	if report.ZoneRecords != 0 {
		t.Errorf("expected 0 zone records, got %d", report.ZoneRecords)
	}
	if report.LiveRecords != 0 {
		t.Errorf("expected 0 live records, got %d", report.LiveRecords)
	}
}
