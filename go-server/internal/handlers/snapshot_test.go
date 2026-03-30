package handlers

import (
	"strings"
	"testing"
)

func TestExtractMapSafe(t *testing.T) {
	tests := []struct {
		name   string
		input  map[string]any
		key    string
		hasKey bool
	}{
		{"existing map key", map[string]any{"basic_records": map[string]any{"A": []any{"1.2.3.4"}}}, "basic_records", true},
		{"missing key", map[string]any{}, "basic_records", false},
		{"non-map value", map[string]any{"basic_records": "not a map"}, "basic_records", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractMapSafe(tc.input, tc.key)
			if got == nil {
				t.Fatal("expected non-nil map")
			}
			if tc.hasKey && len(got) == 0 {
				t.Error("expected non-empty map for existing key")
			}
			if !tc.hasKey && len(got) != 0 {
				t.Error("expected empty map for missing/invalid key")
			}
		})
	}
}

func TestExtractStringSlice(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]any
		key      string
		expected int
	}{
		{"string slice", map[string]any{"A": []string{"1.2.3.4", "5.6.7.8"}}, "A", 2},
		{"any slice", map[string]any{"A": []any{"1.2.3.4", "5.6.7.8"}}, "A", 2},
		{"missing key", map[string]any{}, "A", 0},
		{"non-slice value", map[string]any{"A": "single"}, "A", 0},
		{"empty slice", map[string]any{"A": []any{}}, "A", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractStringSlice(tc.input, tc.key)
			if len(got) != tc.expected {
				t.Errorf("extractStringSlice() returned %d items, want %d", len(got), tc.expected)
			}
		})
	}
}

func TestEscapeTXT(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{`hello`, `hello`},
		{`say "hi"`, `say \"hi\"`},
		{`no quotes here`, `no quotes here`},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := escapeTXT(tc.input)
			if got != tc.expected {
				t.Errorf("escapeTXT(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestGetTTL(t *testing.T) {
	ttls := map[string]uint32{"A": 300, "MX": 3600}

	if got := getTTL(ttls, "A"); got != "300" {
		t.Errorf("getTTL for A = %q, want 300", got)
	}
	if got := getTTL(ttls, "MX"); got != "3600" {
		t.Errorf("getTTL for MX = %q, want 3600", got)
	}
	if got := getTTL(ttls, "AAAA"); got != "; TTL unknown" {
		t.Errorf("getTTL for missing = %q, want '; TTL unknown'", got)
	}
}

func TestExtractTTLMap(t *testing.T) {
	results := map[string]any{
		"resolver_ttl": map[string]any{
			"A":  float64(300),
			"MX": float64(3600),
		},
		"basic_records": map[string]any{
			"_ttl": map[string]any{
				"NS": float64(86400),
				"A":  float64(600),
			},
		},
	}

	ttls := extractTTLMap(results)
	if ttls["A"] != 300 {
		t.Errorf("A TTL = %d, want 300 (resolver_ttl takes precedence)", ttls["A"])
	}
	if ttls["MX"] != 3600 {
		t.Errorf("MX TTL = %d, want 3600", ttls["MX"])
	}
	if ttls["NS"] != 86400 {
		t.Errorf("NS TTL = %d, want 86400", ttls["NS"])
	}
}

func TestExtractTTLMapEmpty(t *testing.T) {
	ttls := extractTTLMap(map[string]any{})
	if len(ttls) != 0 {
		t.Errorf("expected empty TTL map, got %d entries", len(ttls))
	}
}

func TestMergeTTLValues(t *testing.T) {
	ttls := map[string]uint32{"A": 300}
	m := map[string]any{"A": float64(600), "MX": float64(3600)}

	mergeTTLValues(ttls, m, true)
	if ttls["A"] != 300 {
		t.Errorf("A should not be overwritten when skipExisting=true, got %d", ttls["A"])
	}
	if ttls["MX"] != 3600 {
		t.Errorf("MX should be added, got %d", ttls["MX"])
	}

	mergeTTLValues(ttls, m, false)
	if ttls["A"] != 600 {
		t.Errorf("A should be overwritten when skipExisting=false, got %d", ttls["A"])
	}
}

func TestExtractEmailSubdomainRecords(t *testing.T) {
	auth := map[string]any{
		"DMARC": []any{"v=DMARC1; p=reject"},
	}
	results := map[string]any{}

	recs := extractEmailSubdomainRecords(auth, results, "DMARC", "_dmarc", "example.com")
	if len(recs) != 1 {
		t.Fatalf("expected 1 DMARC record, got %d", len(recs))
	}
	if recs[0] != "v=DMARC1; p=reject" {
		t.Errorf("unexpected DMARC record: %q", recs[0])
	}
}

func TestExtractEmailSubdomainRecordsFallback(t *testing.T) {
	auth := map[string]any{}
	results := map[string]any{
		"dmarc_analysis": map[string]any{
			"record": "v=DMARC1; p=none",
		},
	}

	recs := extractEmailSubdomainRecords(auth, results, "DMARC", "_dmarc", "example.com")
	if len(recs) != 1 || recs[0] != "v=DMARC1; p=none" {
		t.Errorf("expected fallback DMARC record, got %v", recs)
	}
}

func TestExtractEmailSubdomainRecordsUnknownKey(t *testing.T) {
	recs := extractEmailSubdomainRecords(map[string]any{}, map[string]any{}, "UNKNOWN", "_unknown", "example.com")
	if len(recs) != 0 {
		t.Errorf("expected nil for unknown auth key, got %v", recs)
	}
}

func TestGenerateObservedSnapshot(t *testing.T) {
	results := map[string]any{
		"basic_records": map[string]any{
			"A":     []any{"1.2.3.4"},
			"AAAA":  []any{"::1"},
			"MX":    []any{"10 mail.example.com."},
			"NS":    []any{"ns1.example.com."},
			"TXT":   []any{"v=spf1 -all"},
			"SOA":   []any{"ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400"},
			"CAA":   []any{"0 issue \"letsencrypt.org\""},
			"CNAME": []any{},
			"SRV":   []any{},
		},
		"authoritative_records": map[string]any{},
		"resolver_ttl": map[string]any{
			"A": float64(300),
		},
	}

	snapshot := GenerateObservedSnapshot("example.com", results, "1.0.0")

	if !strings.Contains(snapshot, "$ORIGIN example.com.") {
		t.Error("expected $ORIGIN line")
	}
	if !strings.Contains(snapshot, "OBSERVED RECORDS SNAPSHOT") {
		t.Error("expected header")
	}
	if !strings.Contains(snapshot, "1.2.3.4") {
		t.Error("expected A record value")
	}
	if !strings.Contains(snapshot, "v=spf1 -all") {
		t.Error("expected SPF TXT record")
	}
	if !strings.Contains(snapshot, "DNS Tool v1.0.0") {
		t.Error("expected tool version")
	}
}

func TestWriteRecordSection(t *testing.T) {
	var sb strings.Builder
	ttls := map[string]uint32{"A": 300}
	writeRecordSection(&sb, "A Records", "example.com.", []string{"1.2.3.4"}, ttls, "A")
	got := sb.String()
	if !strings.Contains(got, "A Records") {
		t.Error("expected label in section header")
	}
	if !strings.Contains(got, "1.2.3.4") {
		t.Error("expected record value")
	}
}

func TestWriteRecordSectionEmpty(t *testing.T) {
	var sb strings.Builder
	writeRecordSection(&sb, "A Records", "example.com.", nil, nil, "A")
	got := sb.String()
	if !strings.Contains(got, snapshotNoneDiscovered) {
		t.Error("expected none discovered message for empty records")
	}
}

func TestWriteSRVSection(t *testing.T) {
	var sb strings.Builder
	writeSRVSection(&sb, "example.com.", []string{"_sip._tcp: 10 60 5060 sip.example.com."})
	got := sb.String()
	if !strings.Contains(got, "_sip._tcp") {
		t.Error("expected SRV record name")
	}
	if !strings.Contains(got, "SRV") {
		t.Error("expected SRV record type")
	}
}

func TestWriteSRVSectionEmpty(t *testing.T) {
	var sb strings.Builder
	writeSRVSection(&sb, "example.com.", nil)
	got := sb.String()
	if !strings.Contains(got, snapshotNoneDiscovered) {
		t.Error("expected none discovered for empty SRV")
	}
}

func TestWriteSRVSectionNoColon(t *testing.T) {
	var sb strings.Builder
	writeSRVSection(&sb, "example.com.", []string{"10 60 5060 sip.example.com."})
	got := sb.String()
	if !strings.Contains(got, "example.com.") {
		t.Error("expected fqdn in output")
	}
}

func TestWriteTXTSection(t *testing.T) {
	var sb strings.Builder
	basic := map[string]any{
		"TXT": []any{"v=spf1 -all"},
	}
	auth := map[string]any{
		"DMARC": []any{"v=DMARC1; p=reject"},
	}
	results := map[string]any{}
	ttls := map[string]uint32{"TXT": 3600}
	writeTXTSection(&sb, "example.com.", basic, auth, results, "example.com", ttls)
	got := sb.String()
	if !strings.Contains(got, "v=spf1 -all") {
		t.Error("expected SPF TXT record")
	}
	if !strings.Contains(got, "_dmarc") {
		t.Error("expected DMARC subdomain record")
	}
}

func TestWriteTXTSectionEmpty(t *testing.T) {
	var sb strings.Builder
	writeTXTSection(&sb, "example.com.", map[string]any{}, map[string]any{}, map[string]any{}, "example.com", nil)
	got := sb.String()
	if got != "" {
		t.Errorf("expected empty output for no TXT records, got %q", got)
	}
}

func TestWriteTXTSectionMTASTS(t *testing.T) {
	var sb strings.Builder
	basic := map[string]any{}
	auth := map[string]any{
		"MTA-STS": []any{"v=STSv1; id=20240101"},
	}
	results := map[string]any{}
	writeTXTSection(&sb, "example.com.", basic, auth, results, "example.com", nil)
	got := sb.String()
	if !strings.Contains(got, "_mta-sts") {
		t.Error("expected MTA-STS subdomain record")
	}
}

func TestWriteTXTSectionTLSRPT(t *testing.T) {
	var sb strings.Builder
	basic := map[string]any{}
	auth := map[string]any{
		"TLS-RPT": []any{"v=TLSRPTv1; rua=mailto:tls@example.com"},
	}
	results := map[string]any{}
	writeTXTSection(&sb, "example.com.", basic, auth, results, "example.com", nil)
	got := sb.String()
	if !strings.Contains(got, "_smtp._tls") {
		t.Error("expected TLS-RPT subdomain record")
	}
}

func TestExtractEmailSubdomainRecordsMTASTS(t *testing.T) {
	auth := map[string]any{}
	results := map[string]any{
		"mta_sts_analysis": map[string]any{
			"record": "v=STSv1; id=abc",
		},
	}
	recs := extractEmailSubdomainRecords(auth, results, "MTA-STS", "_mta-sts", "example.com")
	if len(recs) != 1 || recs[0] != "v=STSv1; id=abc" {
		t.Errorf("expected MTA-STS fallback record, got %v", recs)
	}
}

func TestExtractEmailSubdomainRecordsTLSRPT(t *testing.T) {
	auth := map[string]any{}
	results := map[string]any{
		"tlsrpt_analysis": map[string]any{
			"valid_records": []any{"v=TLSRPTv1; rua=mailto:tls@example.com"},
		},
	}
	recs := extractEmailSubdomainRecords(auth, results, "TLS-RPT", "_smtp._tls", "example.com")
	if len(recs) != 1 {
		t.Errorf("expected TLS-RPT fallback record, got %v", recs)
	}
}

func TestExtractEmailSubdomainRecordsEmptyRecord(t *testing.T) {
	auth := map[string]any{}
	results := map[string]any{
		"dmarc_analysis": map[string]any{
			"record": "",
		},
	}
	recs := extractEmailSubdomainRecords(auth, results, "DMARC", "_dmarc", "example.com")
	if len(recs) != 0 {
		t.Errorf("expected no records for empty record string, got %v", recs)
	}
}

func TestGenerateObservedSnapshotEmpty(t *testing.T) {
	results := map[string]any{}
	snapshot := GenerateObservedSnapshot("empty.com", results, "2.0.0")
	if !strings.Contains(snapshot, "$ORIGIN empty.com.") {
		t.Error("expected $ORIGIN line")
	}
	if !strings.Contains(snapshot, "DNS Tool v2.0.0") {
		t.Error("expected tool version")
	}
}

func TestGenerateObservedSnapshotWithSRV(t *testing.T) {
	results := map[string]any{
		"basic_records": map[string]any{
			"SRV": []any{"_sip._tcp: 10 60 5060 sip.example.com."},
		},
	}
	snapshot := GenerateObservedSnapshot("example.com", results, "1.0.0")
	if !strings.Contains(snapshot, "_sip._tcp") {
		t.Error("expected SRV record in snapshot")
	}
}

func TestMergeTTLValuesJsonNumber(t *testing.T) {
	ttls := map[string]uint32{}
	m := map[string]any{"A": float64(300)}
	mergeTTLValues(ttls, m, false)
	if ttls["A"] != 300 {
		t.Errorf("expected A=300, got %d", ttls["A"])
	}
}

func TestExtractStringSliceNonStringItems(t *testing.T) {
	m := map[string]any{
		"A": []any{"1.2.3.4", 42, "5.6.7.8"},
	}
	got := extractStringSlice(m, "A")
	if len(got) != 2 {
		t.Errorf("expected 2 string items, got %d", len(got))
	}
}

func TestEscapeTXTMultipleQuotes(t *testing.T) {
	input := `"hello" "world"`
	expected := `\"hello\" \"world\"`
	got := escapeTXT(input)
	if got != expected {
		t.Errorf("escapeTXT(%q) = %q, want %q", input, got, expected)
	}
}

func TestWriteRecordSectionWithMultipleRecords(t *testing.T) {
	var sb strings.Builder
	ttls := map[string]uint32{"MX": 1800}
	writeRecordSection(&sb, "MX Records", "example.com.", []string{"10 mail1.example.com.", "20 mail2.example.com."}, ttls, "MX")
	got := sb.String()
	if !strings.Contains(got, "mail1.example.com.") {
		t.Error("expected first MX record")
	}
	if !strings.Contains(got, "mail2.example.com.") {
		t.Error("expected second MX record")
	}
	if !strings.Contains(got, "1800") {
		t.Error("expected TTL value")
	}
}
