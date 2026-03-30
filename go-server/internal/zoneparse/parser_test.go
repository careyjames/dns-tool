package zoneparse

import (
	"strings"
	"testing"
)

func TestParseZoneFile_ValidZone(t *testing.T) {
	zone := `$ORIGIN example.com.
@  3600 IN SOA ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400
@  3600 IN NS  ns1.example.com.
@  3600 IN NS  ns2.example.com.
@  3600 IN A   93.184.216.34
@  3600 IN MX  10 mail.example.com.
@  3600 IN TXT "v=spf1 include:_spf.example.com ~all"
`
	r := strings.NewReader(zone)
	result, raw, err := ParseZoneFile(r, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
	if len(raw) == 0 {
		t.Fatal("raw bytes are empty")
	}
	if result.Domain != "example.com" {
		t.Errorf("expected domain example.com, got %s", result.Domain)
	}
	if result.RecordCount < 6 {
		t.Errorf("expected at least 6 records, got %d", result.RecordCount)
	}
	if result.RecordCount != len(result.Records) {
		t.Errorf("RecordCount %d != len(Records) %d", result.RecordCount, len(result.Records))
	}
	if result.IntegrityHash == "" {
		t.Error("integrity hash is empty")
	}
	if len(result.IntegrityHash) != 128 {
		t.Errorf("expected 128-char hex hash, got %d chars", len(result.IntegrityHash))
	}
	if len(result.ParseErrors) != 0 {
		t.Errorf("unexpected parse errors: %v", result.ParseErrors)
	}
}

func TestParseZoneFile_EmptyInput(t *testing.T) {
	r := strings.NewReader("")
	result, raw, err := ParseZoneFile(r, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RecordCount != 0 {
		t.Errorf("expected 0 records for empty input, got %d", result.RecordCount)
	}
	if len(raw) != 0 {
		t.Errorf("expected empty raw bytes, got %d", len(raw))
	}
}

func TestParseZoneFile_OriginWithoutTrailingDot(t *testing.T) {
	zone := `@ 300 IN A 1.2.3.4
`
	r := strings.NewReader(zone)
	result, _, err := ParseZoneFile(r, "test.org")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Domain != "test.org" {
		t.Errorf("expected domain test.org, got %s", result.Domain)
	}
}

func TestParseZoneFile_OriginWithTrailingDot(t *testing.T) {
	zone := `@ 300 IN A 1.2.3.4
`
	r := strings.NewReader(zone)
	result, _, err := ParseZoneFile(r, "test.org.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Domain != "test.org" {
		t.Errorf("expected domain test.org, got %s", result.Domain)
	}
}

func TestParseZoneFile_NoOriginInfersFromSOA(t *testing.T) {
	zone := `inferred.com. 3600 IN SOA ns1.inferred.com. admin.inferred.com. 1 3600 900 604800 86400
inferred.com. 300 IN A 1.2.3.4
`
	r := strings.NewReader(zone)
	result, _, err := ParseZoneFile(r, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Domain != "inferred.com" {
		t.Errorf("expected domain inferred.com, got %s", result.Domain)
	}
}

func TestParseZoneFile_NoOriginNoSOAInfersFromFirst(t *testing.T) {
	zone := `fallback.com. 300 IN A 1.2.3.4
`
	r := strings.NewReader(zone)
	result, _, err := ParseZoneFile(r, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Domain != "fallback.com" {
		t.Errorf("expected domain fallback.com, got %s", result.Domain)
	}
}

func TestParseZoneFile_SortedByTypeAndName(t *testing.T) {
	zone := `$ORIGIN sort.com.
@ 300 IN TXT "hello"
@ 300 IN A 1.2.3.4
b.sort.com. 300 IN A 5.6.7.8
a.sort.com. 300 IN A 9.10.11.12
`
	r := strings.NewReader(zone)
	result, _, err := ParseZoneFile(r, "sort.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Records) < 3 {
		t.Fatalf("expected at least 3 records, got %d", len(result.Records))
	}
	for i := 1; i < len(result.Records); i++ {
		prev := result.Records[i-1]
		curr := result.Records[i]
		if prev.Type > curr.Type {
			t.Errorf("records not sorted by type: %s > %s", prev.Type, curr.Type)
		}
		if prev.Type == curr.Type && prev.Name > curr.Name {
			t.Errorf("records not sorted by name within same type: %s > %s", prev.Name, curr.Name)
		}
	}
}

func TestParseZoneFile_RecordFields(t *testing.T) {
	zone := `$ORIGIN example.com.
@ 3600 IN A 93.184.216.34
`
	r := strings.NewReader(zone)
	result, _, err := ParseZoneFile(r, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Records) == 0 {
		t.Fatal("no records parsed")
	}
	rec := result.Records[0]
	if rec.Name != "example.com." {
		t.Errorf("expected name example.com., got %s", rec.Name)
	}
	if rec.TTL != 3600 {
		t.Errorf("expected TTL 3600, got %d", rec.TTL)
	}
	if rec.Class != "IN" {
		t.Errorf("expected class IN, got %s", rec.Class)
	}
	if rec.Type != "A" {
		t.Errorf("expected type A, got %s", rec.Type)
	}
	if rec.RData != "93.184.216.34" {
		t.Errorf("expected rdata 93.184.216.34, got %s", rec.RData)
	}
}

func TestParseZoneFile_MalformedRecords(t *testing.T) {
	zone := `$ORIGIN broken.com.
this is not a valid record
@ 300 IN A 1.2.3.4
`
	r := strings.NewReader(zone)
	result, _, err := ParseZoneFile(r, "broken.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("result should not be nil even with malformed input")
	}
}

func TestParseZoneFile_MultipleRecordTypes(t *testing.T) {
	zone := `$ORIGIN multi.com.
@ 3600 IN SOA ns1.multi.com. admin.multi.com. 1 3600 900 604800 86400
@ 300 IN A 1.1.1.1
@ 300 IN AAAA 2001:db8::1
@ 300 IN MX 10 mail.multi.com.
@ 300 IN NS ns1.multi.com.
@ 300 IN TXT "v=spf1 -all"
`
	r := strings.NewReader(zone)
	result, _, err := ParseZoneFile(r, "multi.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	typeSet := make(map[string]bool)
	for _, rec := range result.Records {
		typeSet[rec.Type] = true
	}
	expected := []string{"SOA", "A", "AAAA", "MX", "NS", "TXT"}
	for _, e := range expected {
		if !typeSet[e] {
			t.Errorf("expected record type %s not found", e)
		}
	}
}
