package handlers

import (
	"encoding/json"
	"testing"
)

func TestCoverageBoost16_isAnalysisFailure(t *testing.T) {
	t.Run("success true", func(t *testing.T) {
		results := map[string]any{"analysis_success": true}
		failed, msg := isAnalysisFailure(results)
		if failed {
			t.Error("expected not failed")
		}
		if msg != "" {
			t.Errorf("expected empty msg, got %q", msg)
		}
	})

	t.Run("success false with error", func(t *testing.T) {
		results := map[string]any{
			"analysis_success": false,
			"error":            "DNS resolution failed",
		}
		failed, msg := isAnalysisFailure(results)
		if !failed {
			t.Error("expected failed")
		}
		if msg != "DNS resolution failed" {
			t.Errorf("msg = %q", msg)
		}
	})

	t.Run("success false without error string", func(t *testing.T) {
		results := map[string]any{
			"analysis_success": false,
		}
		failed, _ := isAnalysisFailure(results)
		if failed {
			t.Error("expected not failed when error key missing")
		}
	})

	t.Run("success false with non-string error", func(t *testing.T) {
		results := map[string]any{
			"analysis_success": false,
			"error":            42,
		}
		failed, _ := isAnalysisFailure(results)
		if failed {
			t.Error("expected not failed when error is not a string")
		}
	})

	t.Run("missing analysis_success key", func(t *testing.T) {
		results := map[string]any{}
		failed, msg := isAnalysisFailure(results)
		if failed {
			t.Error("expected not failed")
		}
		if msg != "" {
			t.Errorf("expected empty msg, got %q", msg)
		}
	})

	t.Run("analysis_success wrong type", func(t *testing.T) {
		results := map[string]any{"analysis_success": "yes"}
		failed, _ := isAnalysisFailure(results)
		if failed {
			t.Error("expected not failed for non-bool")
		}
	})

	t.Run("nil map", func(t *testing.T) {
		failed, msg := isAnalysisFailure(nil)
		if failed {
			t.Error("expected not failed for nil")
		}
		if msg != "" {
			t.Error("expected empty msg for nil")
		}
	})
}

func TestCoverageBoost16_unmarshalRawJSON(t *testing.T) {
	t.Run("valid JSON object", func(t *testing.T) {
		raw := json.RawMessage(`{"key":"value"}`)
		result := unmarshalRawJSON(raw, "example.com", "test")
		m, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("expected map")
		}
		if m["key"] != "value" {
			t.Errorf("got %v", m["key"])
		}
	})

	t.Run("valid JSON string", func(t *testing.T) {
		raw := json.RawMessage(`"hello"`)
		result := unmarshalRawJSON(raw, "example.com", "test")
		s, ok := result.(string)
		if !ok {
			t.Fatal("expected string")
		}
		if s != "hello" {
			t.Errorf("got %q", s)
		}
	})

	t.Run("valid JSON number", func(t *testing.T) {
		raw := json.RawMessage(`42`)
		result := unmarshalRawJSON(raw, "example.com", "test")
		n, ok := result.(float64)
		if !ok {
			t.Fatal("expected float64")
		}
		if n != 42 {
			t.Errorf("got %f", n)
		}
	})

	t.Run("empty raw message", func(t *testing.T) {
		raw := json.RawMessage(``)
		result := unmarshalRawJSON(raw, "example.com", "test")
		if result != nil {
			t.Error("expected nil for empty")
		}
	})

	t.Run("nil raw message", func(t *testing.T) {
		result := unmarshalRawJSON(nil, "example.com", "test")
		if result != nil {
			t.Error("expected nil for nil")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		raw := json.RawMessage(`{invalid}`)
		result := unmarshalRawJSON(raw, "example.com", "test")
		if result != nil {
			t.Error("expected nil for invalid JSON")
		}
	})

	t.Run("JSON array", func(t *testing.T) {
		raw := json.RawMessage(`[1,2,3]`)
		result := unmarshalRawJSON(raw, "example.com", "test")
		arr, ok := result.([]interface{})
		if !ok {
			t.Fatal("expected slice")
		}
		if len(arr) != 3 {
			t.Errorf("expected 3 elements, got %d", len(arr))
		}
	})

	t.Run("JSON null", func(t *testing.T) {
		raw := json.RawMessage(`null`)
		result := unmarshalRawJSON(raw, "example.com", "test")
		if result != nil {
			t.Error("expected nil for JSON null")
		}
	})
}

func TestCoverageBoost16_extractCurrencyFromResults(t *testing.T) {
	t.Run("with currency_report", func(t *testing.T) {
		full := map[string]interface{}{
			"currency_report": map[string]interface{}{"score": 0.95},
		}
		result := extractCurrencyFromResults(full)
		if result == nil {
			t.Fatal("expected non-nil")
		}
		m, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("expected map")
		}
		if m["score"] != 0.95 {
			t.Errorf("score = %v", m["score"])
		}
	})

	t.Run("without currency_report", func(t *testing.T) {
		full := map[string]interface{}{"other": "data"}
		result := extractCurrencyFromResults(full)
		if result != nil {
			t.Error("expected nil")
		}
	})

	t.Run("nil input", func(t *testing.T) {
		result := extractCurrencyFromResults(nil)
		if result != nil {
			t.Error("expected nil for nil input")
		}
	})

	t.Run("non-map input", func(t *testing.T) {
		result := extractCurrencyFromResults("not a map")
		if result != nil {
			t.Error("expected nil for non-map")
		}
	})

	t.Run("empty map", func(t *testing.T) {
		result := extractCurrencyFromResults(map[string]interface{}{})
		if result != nil {
			t.Error("expected nil for empty map")
		}
	})
}

func TestCoverageBoost16_marshalOrderedJSON(t *testing.T) {
	t.Run("empty entries", func(t *testing.T) {
		buf := marshalOrderedJSON(nil)
		if string(buf) != "{}" {
			t.Errorf("got %q", string(buf))
		}
	})

	t.Run("single entry", func(t *testing.T) {
		entries := []orderedKV{{Key: "name", Value: "test"}}
		buf := marshalOrderedJSON(entries)
		var m map[string]interface{}
		if err := json.Unmarshal(buf, &m); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if m["name"] != "test" {
			t.Errorf("got %v", m["name"])
		}
	})

	t.Run("multiple entries preserve order", func(t *testing.T) {
		entries := []orderedKV{
			{Key: "b", Value: 2},
			{Key: "a", Value: 1},
			{Key: "c", Value: 3},
		}
		buf := marshalOrderedJSON(entries)
		var m map[string]interface{}
		if err := json.Unmarshal(buf, &m); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if m["a"] != float64(1) || m["b"] != float64(2) || m["c"] != float64(3) {
			t.Errorf("unexpected values: %v", m)
		}
	})

	t.Run("nested values", func(t *testing.T) {
		entries := []orderedKV{
			{Key: "obj", Value: map[string]string{"inner": "val"}},
		}
		buf := marshalOrderedJSON(entries)
		var m map[string]interface{}
		if err := json.Unmarshal(buf, &m); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		inner, ok := m["obj"].(map[string]interface{})
		if !ok {
			t.Fatal("expected nested map")
		}
		if inner["inner"] != "val" {
			t.Errorf("got %v", inner["inner"])
		}
	})

	t.Run("null value", func(t *testing.T) {
		entries := []orderedKV{{Key: "x", Value: nil}}
		buf := marshalOrderedJSON(entries)
		var m map[string]interface{}
		if err := json.Unmarshal(buf, &m); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if m["x"] != nil {
			t.Errorf("expected nil, got %v", m["x"])
		}
	})

	t.Run("boolean value", func(t *testing.T) {
		entries := []orderedKV{{Key: "flag", Value: true}}
		buf := marshalOrderedJSON(entries)
		var m map[string]interface{}
		if err := json.Unmarshal(buf, &m); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if m["flag"] != true {
			t.Errorf("expected true, got %v", m["flag"])
		}
	})

	t.Run("unmarshalable value skipped gracefully", func(t *testing.T) {
		entries := []orderedKV{
			{Key: "good", Value: "ok"},
			{Key: "bad", Value: func() {}},
			{Key: "also_good", Value: 42},
		}
		buf := marshalOrderedJSON(entries)
		if len(buf) == 0 {
			t.Error("expected non-empty output")
		}
	})
}

func TestCoverageBoost16_protocolRawConfidence(t *testing.T) {
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
		{"unknown status", "something_else", 0.5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := map[string]any{
				"test_section": map[string]any{
					"status": tt.status,
				},
			}
			got := protocolRawConfidence(results, "test_section")
			if got != tt.want {
				t.Errorf("protocolRawConfidence status=%q: got %f, want %f", tt.status, got, tt.want)
			}
		})
	}

	t.Run("missing section", func(t *testing.T) {
		results := map[string]any{}
		got := protocolRawConfidence(results, "nonexistent")
		if got != 0.0 {
			t.Errorf("expected 0.0, got %f", got)
		}
	})

	t.Run("section not a map", func(t *testing.T) {
		results := map[string]any{"section": "string"}
		got := protocolRawConfidence(results, "section")
		if got != 0.0 {
			t.Errorf("expected 0.0, got %f", got)
		}
	})

	t.Run("nil results", func(t *testing.T) {
		got := protocolRawConfidence(nil, "any")
		if got != 0.0 {
			t.Errorf("expected 0.0, got %f", got)
		}
	})

	t.Run("section without status key", func(t *testing.T) {
		results := map[string]any{
			"section": map[string]any{"other": "value"},
		}
		got := protocolRawConfidence(results, "section")
		if got != 0.0 {
			t.Errorf("expected 0.0 for missing status, got %f", got)
		}
	})
}

func TestCoverageBoost16_aggregateResolverAgreement(t *testing.T) {
	t.Run("no resolver_consensus", func(t *testing.T) {
		results := map[string]any{}
		agree, total := aggregateResolverAgreement(results)
		if agree != 0 || total != 0 {
			t.Errorf("got agree=%d total=%d", agree, total)
		}
	})

	t.Run("no per_record_consensus", func(t *testing.T) {
		results := map[string]any{
			"resolver_consensus": map[string]any{},
		}
		agree, total := aggregateResolverAgreement(results)
		if agree != 0 || total != 0 {
			t.Errorf("got agree=%d total=%d", agree, total)
		}
	})

	t.Run("all consensus true", func(t *testing.T) {
		results := map[string]any{
			"resolver_consensus": map[string]any{
				"per_record_consensus": map[string]any{
					"A": map[string]any{
						"resolver_count": 4,
						"consensus":      true,
					},
					"AAAA": map[string]any{
						"resolver_count": 3,
						"consensus":      true,
					},
				},
			},
		}
		agree, total := aggregateResolverAgreement(results)
		if agree != 7 {
			t.Errorf("agree = %d, want 7", agree)
		}
		if total != 7 {
			t.Errorf("total = %d, want 7", total)
		}
	})

	t.Run("mixed consensus", func(t *testing.T) {
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
		if agree != 6 {
			t.Errorf("agree = %d, want 6 (4 + 2)", agree)
		}
		if total != 7 {
			t.Errorf("total = %d, want 7", total)
		}
	})

	t.Run("consensus false with resolver_count 0", func(t *testing.T) {
		results := map[string]any{
			"resolver_consensus": map[string]any{
				"per_record_consensus": map[string]any{
					"TXT": map[string]any{
						"resolver_count": 0,
						"consensus":      false,
					},
				},
			},
		}
		agree, total := aggregateResolverAgreement(results)
		if agree != 0 {
			t.Errorf("agree = %d, want 0", agree)
		}
		if total != 0 {
			t.Errorf("total = %d, want 0", total)
		}
	})

	t.Run("non-map entry in per_record", func(t *testing.T) {
		results := map[string]any{
			"resolver_consensus": map[string]any{
				"per_record_consensus": map[string]any{
					"bad": "not a map",
					"A": map[string]any{
						"resolver_count": 2,
						"consensus":      true,
					},
				},
			},
		}
		agree, total := aggregateResolverAgreement(results)
		if agree != 2 {
			t.Errorf("agree = %d, want 2", agree)
		}
		if total != 2 {
			t.Errorf("total = %d, want 2", total)
		}
	})

	t.Run("nil results", func(t *testing.T) {
		agree, total := aggregateResolverAgreement(nil)
		if agree != 0 || total != 0 {
			t.Errorf("got agree=%d total=%d for nil", agree, total)
		}
	})

	t.Run("resolver_consensus not a map", func(t *testing.T) {
		results := map[string]any{
			"resolver_consensus": "string",
		}
		agree, total := aggregateResolverAgreement(results)
		if agree != 0 || total != 0 {
			t.Errorf("got agree=%d total=%d", agree, total)
		}
	})
}
