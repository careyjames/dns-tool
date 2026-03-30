package handlers

import (
	"encoding/json"
	"testing"
	"time"

	"dnstool/go-server/internal/dbq"
	"dnstool/go-server/internal/scanner"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestExtractScanFields(t *testing.T) {
	t.Run("scan with source and IP", func(t *testing.T) {
		sc := scanner.Classification{IsScan: true, Source: "cisa", IP: "1.2.3.4"}
		src, ip := extractScanFields(sc)
		if src == nil || *src != "cisa" {
			t.Errorf("expected source 'cisa', got %v", src)
		}
		if ip == nil || *ip != "1.2.3.4" {
			t.Errorf("expected ip '1.2.3.4', got %v", ip)
		}
	})

	t.Run("not a scan", func(t *testing.T) {
		sc := scanner.Classification{IsScan: false, Source: "", IP: ""}
		src, ip := extractScanFields(sc)
		if src != nil {
			t.Error("expected nil source for non-scan")
		}
		if ip != nil {
			t.Error("expected nil ip for empty IP")
		}
	})

	t.Run("scan without IP", func(t *testing.T) {
		sc := scanner.Classification{IsScan: true, Source: "qualys", IP: ""}
		src, ip := extractScanFields(sc)
		if src == nil || *src != "qualys" {
			t.Errorf("expected source 'qualys', got %v", src)
		}
		if ip != nil {
			t.Error("expected nil ip for empty IP")
		}
	})
}

func TestProtocolRawConfidence(t *testing.T) {
	tests := []struct {
		name   string
		status string
		want   float64
	}{
		{"secure", "secure", 1.0},
		{"pass", "pass", 1.0},
		{"valid", "valid", 1.0},
		{"good", "good", 1.0},
		{"warning", "warning", 0.7},
		{"info", "info", 0.7},
		{"partial", "partial", 0.7},
		{"fail", "fail", 0.3},
		{"danger", "danger", 0.3},
		{"critical", "critical", 0.3},
		{"error", "error", 0.0},
		{"n/a", "n/a", 0.0},
		{"empty", "", 0.0},
		{"other", "something_else", 0.5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := map[string]any{
				"test_section": map[string]any{"status": tt.status},
			}
			got := protocolRawConfidence(results, "test_section")
			if got != tt.want {
				t.Errorf("protocolRawConfidence status=%q = %f, want %f", tt.status, got, tt.want)
			}
		})
	}

	t.Run("missing_section", func(t *testing.T) {
		got := protocolRawConfidence(map[string]any{}, "nonexistent")
		if got != 0.0 {
			t.Errorf("expected 0.0 for missing section, got %f", got)
		}
	})

	t.Run("non_map_section", func(t *testing.T) {
		got := protocolRawConfidence(map[string]any{"test": "not a map"}, "test")
		if got != 0.0 {
			t.Errorf("expected 0.0 for non-map section, got %f", got)
		}
	})
}

func TestAggregateResolverAgreement(t *testing.T) {
	t.Run("no consensus data", func(t *testing.T) {
		agree, total := aggregateResolverAgreement(map[string]any{})
		if agree != 0 || total != 0 {
			t.Errorf("expected (0,0), got (%d,%d)", agree, total)
		}
	})

	t.Run("with consensus", func(t *testing.T) {
		results := map[string]any{
			"resolver_consensus": map[string]any{
				"per_record_consensus": map[string]any{
					"A": map[string]any{
						"resolver_count": 4,
						"consensus":      true,
					},
					"MX": map[string]any{
						"resolver_count": 3,
						"consensus":      false,
					},
				},
			},
		}
		agree, total := aggregateResolverAgreement(results)
		if total != 7 {
			t.Errorf("expected total=7, got %d", total)
		}
		if agree != 6 {
			t.Errorf("expected agree=6 (4 all agree + 3-1 disagree), got %d", agree)
		}
	})

	t.Run("zero resolvers no consensus", func(t *testing.T) {
		results := map[string]any{
			"resolver_consensus": map[string]any{
				"per_record_consensus": map[string]any{
					"A": map[string]any{
						"resolver_count": 0,
						"consensus":      false,
					},
				},
			},
		}
		agree, total := aggregateResolverAgreement(results)
		if agree != 0 || total != 0 {
			t.Errorf("expected (0,0), got (%d,%d)", agree, total)
		}
	})

	t.Run("missing per_record_consensus", func(t *testing.T) {
		results := map[string]any{
			"resolver_consensus": map[string]any{},
		}
		agree, total := aggregateResolverAgreement(results)
		if agree != 0 || total != 0 {
			t.Errorf("expected (0,0), got (%d,%d)", agree, total)
		}
	})

	t.Run("non-map record entry", func(t *testing.T) {
		results := map[string]any{
			"resolver_consensus": map[string]any{
				"per_record_consensus": map[string]any{
					"A": "not a map",
				},
			},
		}
		agree, total := aggregateResolverAgreement(results)
		if agree != 0 || total != 0 {
			t.Errorf("expected (0,0), got (%d,%d)", agree, total)
		}
	})
}

func TestGetStringFromResults(t *testing.T) {
	results := map[string]any{
		"spf_analysis": map[string]any{
			"status": "pass",
			"count":  42,
		},
		"simple_key": "simple_value",
	}

	t.Run("nested key", func(t *testing.T) {
		got := getStringFromResults(results, "spf_analysis", "status")
		if got == nil || *got != "pass" {
			t.Errorf("expected 'pass', got %v", got)
		}
	})

	t.Run("nested non-string value", func(t *testing.T) {
		got := getStringFromResults(results, "spf_analysis", "count")
		if got != nil {
			t.Errorf("expected nil for non-string value, got %v", *got)
		}
	})

	t.Run("missing section", func(t *testing.T) {
		got := getStringFromResults(results, "nonexistent", "status")
		if got != nil {
			t.Error("expected nil for missing section")
		}
	})

	t.Run("missing key", func(t *testing.T) {
		got := getStringFromResults(results, "spf_analysis", "nonexistent")
		if got != nil {
			t.Error("expected nil for missing key")
		}
	})

	t.Run("top-level string with empty key", func(t *testing.T) {
		got := getStringFromResults(results, "simple_key", "")
		if got == nil || *got != "simple_value" {
			t.Errorf("expected 'simple_value', got %v", got)
		}
	})

	t.Run("top-level non-string with empty key", func(t *testing.T) {
		r := map[string]any{"numbers": 42}
		got := getStringFromResults(r, "numbers", "")
		if got != nil {
			t.Error("expected nil for non-string top-level value")
		}
	})
}

func TestGetJSONFromResults(t *testing.T) {
	results := map[string]any{
		"spf_analysis": map[string]any{
			"records": []string{"v=spf1 include:example.com ~all"},
		},
		"basic_records": map[string]any{
			"A": []string{"1.2.3.4"},
		},
	}

	t.Run("nested key", func(t *testing.T) {
		got := getJSONFromResults(results, "spf_analysis", "records")
		if got == nil {
			t.Fatal("expected non-nil JSON")
		}
		var arr []string
		if err := json.Unmarshal(got, &arr); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}
		if len(arr) != 1 {
			t.Errorf("expected 1 record, got %d", len(arr))
		}
	})

	t.Run("top-level section with empty key", func(t *testing.T) {
		got := getJSONFromResults(results, "basic_records", "")
		if got == nil {
			t.Fatal("expected non-nil JSON")
		}
	})

	t.Run("missing section", func(t *testing.T) {
		got := getJSONFromResults(results, "nonexistent", "key")
		if got != nil {
			t.Error("expected nil for missing section")
		}
	})

	t.Run("nil data value", func(t *testing.T) {
		r := map[string]any{"section": map[string]any{"key": nil}}
		got := getJSONFromResults(r, "section", "key")
		if got != nil {
			t.Error("expected nil for nil data")
		}
	})
}

func TestLookupCountry_LocalIPs(t *testing.T) {
	tests := []struct {
		ip string
	}{
		{""},
		{"127.0.0.1"},
		{"::1"},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			code, name := lookupCountry(tt.ip)
			if code != "" || name != "" {
				t.Errorf("expected empty for local IP %q, got (%q, %q)", tt.ip, code, name)
			}
		})
	}
}

func TestProtocolResultKeys(t *testing.T) {
	expectedKeys := []string{"SPF", "DKIM", "DMARC", "DANE", "DNSSEC", "BIMI", "MTA_STS", "TLS_RPT", "CAA"}
	for _, key := range expectedKeys {
		if _, ok := protocolResultKeys[key]; !ok {
			t.Errorf("expected protocolResultKeys to contain %q", key)
		}
	}
}

func TestApplyDevNullHeaders(t *testing.T) {
}

func TestLogEphemeralReason_DoesNotPanic(t *testing.T) {
	logEphemeralReason("example.com", true, true)
	logEphemeralReason("example.com", false, false)
	logEphemeralReason("example.com", false, true)
}

func TestComputeDriftFromPrev(t *testing.T) {
	t.Run("nil prev hash", func(t *testing.T) {
		di := computeDriftFromPrev("abc123", prevAnalysisSnapshot{Hash: nil}, nil)
		if di.Detected {
			t.Error("expected no drift for nil prev hash")
		}
	})

	t.Run("empty prev hash", func(t *testing.T) {
		empty := ""
		di := computeDriftFromPrev("abc123", prevAnalysisSnapshot{Hash: &empty}, nil)
		if di.Detected {
			t.Error("expected no drift for empty prev hash")
		}
	})

	t.Run("same hash", func(t *testing.T) {
		h := "abc123"
		di := computeDriftFromPrev("abc123", prevAnalysisSnapshot{Hash: &h}, nil)
		if di.Detected {
			t.Error("expected no drift for same hash")
		}
	})

	t.Run("different hash detects drift", func(t *testing.T) {
		prevHash := "old_hash"
		di := computeDriftFromPrev("new_hash", prevAnalysisSnapshot{
			Hash: &prevHash,
			ID:   42,
		}, nil)
		if !di.Detected {
			t.Error("expected drift detected")
		}
		if di.PrevHash != "old_hash" {
			t.Errorf("PrevHash = %q, want old_hash", di.PrevHash)
		}
		if di.PrevID != 42 {
			t.Errorf("PrevID = %d, want 42", di.PrevID)
		}
	})

	t.Run("drift with valid created_at", func(t *testing.T) {
		prevHash := "old_hash"
		ts := time.Date(2026, 2, 15, 14, 30, 0, 0, time.UTC)
		di := computeDriftFromPrev("new_hash", prevAnalysisSnapshot{
			Hash:           &prevHash,
			ID:             10,
			CreatedAtValid: true,
			CreatedAt:      ts,
		}, nil)
		if !di.Detected {
			t.Error("expected drift detected")
		}
		if di.PrevTime != "15 Feb 2026 14:30 UTC" {
			t.Errorf("PrevTime = %q", di.PrevTime)
		}
	})

	t.Run("drift with prev results computes diff", func(t *testing.T) {
		prevHash := "old_hash"
		prevResults := map[string]any{
			"spf_analysis": map[string]any{"status": "success"},
		}
		prevJSON, _ := json.Marshal(prevResults)
		currentResults := map[string]any{
			"spf_analysis": map[string]any{"status": "fail"},
		}
		di := computeDriftFromPrev("new_hash", prevAnalysisSnapshot{
			Hash:        &prevHash,
			ID:          5,
			FullResults: prevJSON,
		}, currentResults)
		if !di.Detected {
			t.Error("expected drift detected")
		}
	})
}

func TestAnalysisDuration(t *testing.T) {
	t.Run("with duration", func(t *testing.T) {
		dur := 3.5
		a := dbq.DomainAnalysis{AnalysisDuration: &dur}
		got := analysisDuration(a)
		if got != 3.5 {
			t.Errorf("got %f, want 3.5", got)
		}
	})

	t.Run("nil duration", func(t *testing.T) {
		a := dbq.DomainAnalysis{AnalysisDuration: nil}
		got := analysisDuration(a)
		if got != 0.0 {
			t.Errorf("got %f, want 0.0", got)
		}
	})
}

func TestAnalysisTimestamp(t *testing.T) {
	t.Run("uses updated_at when valid", func(t *testing.T) {
		a := dbq.DomainAnalysis{
			CreatedAt: pgtype.Timestamp{
				Time:  time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC),
				Valid: true,
			},
			UpdatedAt: pgtype.Timestamp{
				Time:  time.Date(2026, 2, 15, 14, 30, 0, 0, time.UTC),
				Valid: true,
			},
		}
		got := analysisTimestamp(a)
		if got != "15 Feb 2026, 14:30 UTC" {
			t.Errorf("got %q", got)
		}
	})

	t.Run("falls back to created_at", func(t *testing.T) {
		a := dbq.DomainAnalysis{
			CreatedAt: pgtype.Timestamp{
				Time:  time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC),
				Valid: true,
			},
			UpdatedAt: pgtype.Timestamp{Valid: false},
		}
		got := analysisTimestamp(a)
		if got != "1 Jan 2026, 10:00 UTC" {
			t.Errorf("got %q", got)
		}
	})

	t.Run("both invalid", func(t *testing.T) {
		a := dbq.DomainAnalysis{
			CreatedAt: pgtype.Timestamp{Valid: false},
			UpdatedAt: pgtype.Timestamp{Valid: false},
		}
		got := analysisTimestamp(a)
		if got != "" {
			t.Errorf("expected empty, got %q", got)
		}
	})
}

func TestComputeIntegrityHash(t *testing.T) {
	a := dbq.DomainAnalysis{
		AsciiDomain: "example.com",
		ID:          1,
	}
	results := map[string]any{"spf_analysis": map[string]any{"status": "pass"}}

	t.Run("uses tool version when present", func(t *testing.T) {
		hash := computeIntegrityHash(a, "2026-01-01", "v1.0", "v2.0", results)
		if hash == "" {
			t.Error("expected non-empty hash")
		}
	})

	t.Run("falls back to app version", func(t *testing.T) {
		hash := computeIntegrityHash(a, "2026-01-01", "", "v2.0", results)
		if hash == "" {
			t.Error("expected non-empty hash")
		}
	})
}

func TestDriftInfoStruct(t *testing.T) {
	di := driftInfo{}
	if di.Detected {
		t.Error("expected zero-value Detected to be false")
	}
	if di.PrevHash != "" {
		t.Error("expected empty PrevHash")
	}
	if di.PrevID != 0 {
		t.Error("expected zero PrevID")
	}
}

func TestIcuaeToDimChart(t *testing.T) {
	if len(icuaeToDimChart) == 0 {
		t.Error("expected non-empty icuaeToDimChart mapping")
	}
	for dimKey, chartKey := range icuaeToDimChart {
		if dimKey == "" {
			t.Error("dimension key should not be empty")
		}
		if chartKey == "" {
			t.Errorf("chart key for dimension %q should not be empty", dimKey)
		}
	}
}
