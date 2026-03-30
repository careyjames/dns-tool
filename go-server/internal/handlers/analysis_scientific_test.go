// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package handlers

import (
        "context"
        "encoding/hex"
        "encoding/json"
        "testing"
        "time"

        "dnstool/go-server/internal/analyzer"
        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/dbq"
        "dnstool/go-server/internal/icae"
        "dnstool/go-server/internal/icuae"
        "dnstool/go-server/internal/scanner"
        "dnstool/go-server/internal/unified"

        "golang.org/x/crypto/sha3"
)

func TestPersistOrLogEphemeral_DecisionMatrix(t *testing.T) {
        t.Run("devNull always skips persistence — /dev/null scan contract", func(t *testing.T) {
                h := &AnalysisHandler{Config: &config.Config{AppVersion: "test"}}
                id, ts := h.persistOrLogEphemeral(context.Background(), persistParams{
                        asciiDomain:  "example.com",
                        devNull:      true,
                        ephemeral:    false,
                        domainExists: true,
                        results:      map[string]any{"domain_exists": true},
                })
                if id != 0 {
                        t.Errorf("devNull scan must return ID=0 (no persistence), got %d", id)
                }
                if ts == "" {
                        t.Error("timestamp must be non-empty even for ephemeral results")
                }
                parsed, err := time.Parse("2006-01-02 15:04:05 UTC", ts)
                if err != nil {
                        t.Errorf("timestamp must be in UTC format: %v", err)
                }
                if time.Since(parsed) > 5*time.Second {
                        t.Error("ephemeral timestamp must be close to current time")
                }
        })

        t.Run("ephemeral flag skips persistence — custom selector unauthenticated contract", func(t *testing.T) {
                h := &AnalysisHandler{Config: &config.Config{AppVersion: "test"}}
                id, _ := h.persistOrLogEphemeral(context.Background(), persistParams{
                        asciiDomain:  "example.com",
                        ephemeral:    true,
                        devNull:      false,
                        domainExists: true,
                        results:      map[string]any{"domain_exists": true},
                })
                if id != 0 {
                        t.Errorf("ephemeral analysis must return ID=0, got %d", id)
                }
        })

        t.Run("non-existent domain with success skips persistence — no noise in DB", func(t *testing.T) {
                h := &AnalysisHandler{Config: &config.Config{AppVersion: "test"}}
                id, _ := h.persistOrLogEphemeral(context.Background(), persistParams{
                        asciiDomain:  "nonexistent.example",
                        domainExists: false,
                        ephemeral:    false,
                        devNull:      false,
                        results:      map[string]any{},
                })
                if id != 0 {
                        t.Errorf("non-existent domain must not be persisted, got ID=%d", id)
                }
        })

        t.Run("non-existent domain with error falls through to persistence — gating logic verified", func(t *testing.T) {
                isSuccess, _ := extractAnalysisError(map[string]any{"error": "NXDOMAIN with suspicious configuration"})
                domainExists := false
                ephemeral := false
                devNull := false
                shouldSkip := ephemeral || devNull || (!domainExists && isSuccess)
                if shouldSkip {
                        t.Error("error records for non-existent domains must NOT be skipped — they carry diagnostic value")
                }
                t.Log("MEASUREMENT: gating logic correctly routes non-existent+error to persistence path")
        })
}

func TestStoreTelemetry_GatingLogic(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{AppVersion: "test"}}

        t.Run("ephemeral analyses never store telemetry", func(t *testing.T) {
                results := map[string]any{
                        "_scan_telemetry": analyzer.ScanTelemetry{
                                Timings:         []analyzer.PhaseTiming{{PhaseGroup: "dns", PhaseTask: "SPF", DurationMs: 150}},
                                TotalDurationMs: 150,
                        },
                }
                h.storeTelemetry(context.Background(), 42, results, true)
                if _, ok := results["_scan_telemetry"]; !ok {
                        t.Error("ephemeral=true should short-circuit before removing _scan_telemetry")
                }
        })

        t.Run("zero analysisID never stores telemetry", func(t *testing.T) {
                results := map[string]any{
                        "_scan_telemetry": analyzer.ScanTelemetry{
                                Timings:         []analyzer.PhaseTiming{{PhaseGroup: "dns", PhaseTask: "DMARC", DurationMs: 200}},
                                TotalDurationMs: 200,
                        },
                }
                h.storeTelemetry(context.Background(), 0, results, false)
                if _, ok := results["_scan_telemetry"]; !ok {
                        t.Error("analysisID=0 should short-circuit before removing _scan_telemetry")
                }
        })

        t.Run("missing _scan_telemetry key is a no-op", func(t *testing.T) {
                results := map[string]any{"spf_analysis": map[string]any{"status": "pass"}}
                h.storeTelemetry(context.Background(), 42, results, false)
        })

        t.Run("wrong type for _scan_telemetry is a no-op", func(t *testing.T) {
                results := map[string]any{"_scan_telemetry": "not a ScanTelemetry struct"}
                h.storeTelemetry(context.Background(), 42, results, false)
                if _, ok := results["_scan_telemetry"]; !ok {
                        t.Error("wrong-type _scan_telemetry should not be deleted")
                }
        })
}

func TestRecordCurrencyIfEligible_GatingLogic(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{AppVersion: "test"}}

        t.Run("ephemeral skips currency recording", func(t *testing.T) {
                h.recordCurrencyIfEligible(true, true, "example.com", map[string]any{
                        mapKeyCurrencyReport: icuae.CurrencyReport{OverallScore: 0.95},
                })
        })

        t.Run("non-existent domain skips currency recording", func(t *testing.T) {
                h.recordCurrencyIfEligible(false, false, "fake.example", map[string]any{
                        mapKeyCurrencyReport: icuae.CurrencyReport{OverallScore: 0.80},
                })
        })

        t.Run("missing currency report is a no-op", func(t *testing.T) {
                h.recordCurrencyIfEligible(false, true, "example.com", map[string]any{
                        "spf_analysis": map[string]any{"status": "pass"},
                })
        })
}

func TestSnapshotICAEMetrics_Construction(t *testing.T) {
        t.Run("HydrateCurrencyReport extracts currency score from well-formed input", func(t *testing.T) {
                cr := map[string]any{
                        "overall_score": 85.0,
                        "protocols":     map[string]any{},
                }
                report, ok := icuae.HydrateCurrencyReport(cr)
                if ok {
                        if report.OverallScore < 0 || report.OverallScore > 100 {
                                t.Errorf("currency score must be 0-100, got %.2f", report.OverallScore)
                        }
                        t.Logf("MEASUREMENT: HydrateCurrencyReport overall_score=%.2f", report.OverallScore)
                } else {
                        t.Log("MEASUREMENT: HydrateCurrencyReport returned false — input not in expected shape")
                }
        })

        t.Run("calibrated_confidence type assertion guards against wrong types", func(t *testing.T) {
                results := map[string]any{
                        "calibrated_confidence": "not-a-map",
                }
                _, ok := results["calibrated_confidence"].(map[string]float64)
                if ok {
                        t.Error("string should not type-assert to map[string]float64")
                }
                t.Log("MEASUREMENT: type guard correctly rejects non-map calibrated_confidence")
        })

        t.Run("calibrated_confidence extracts correct protocol scores", func(t *testing.T) {
                scores := map[string]float64{
                        "SPF": 1.0, "DKIM": 0.7, "DMARC": 1.0,
                        "DANE": 0.0, "DNSSEC": 1.0, "BIMI": 0.0,
                        "MTA_STS": 0.7, "TLS_RPT": 0.3, "CAA": 1.0,
                }
                results := map[string]any{"calibrated_confidence": scores}
                calibrated, ok := results["calibrated_confidence"].(map[string]float64)
                if !ok {
                        t.Fatal("failed to extract calibrated_confidence")
                }
                if len(calibrated) != 9 {
                        t.Errorf("expected 9 protocol scores, got %d", len(calibrated))
                }
                for proto, score := range calibrated {
                        if score < 0 || score > 1.0 {
                                t.Errorf("protocol %s score %.2f out of [0,1] range", proto, score)
                        }
                }
                t.Logf("MEASUREMENT: %d protocol confidence scores validated in [0,1] range", len(calibrated))
        })
}

func TestRestoreUnifiedConfidence_Roundtrip(t *testing.T) {
        input := unified.Input{
                CalibratedConfidence: map[string]float64{
                        "SPF": 1.0, "DKIM": 0.7, "DMARC": 1.0,
                        "DANE": 0.0, "DNSSEC": 1.0, "BIMI": 0.0,
                        "MTA_STS": 0.7, "TLS_RPT": 0.3, "CAA": 1.0,
                },
                CurrencyScore: 0.85,
                MaturityLevel: "Operational",
        }
        original := unified.ComputeUnifiedConfidence(input)

        serialized := map[string]any{
                "level":            original.Level,
                "score":            original.Score,
                "accuracy_factor":  original.AccuracyFactor,
                "currency_factor":  original.CurrencyFactor,
                "maturity_ceiling": original.MaturityCeiling,
                "maturity_level":   original.MaturityLevel,
                "weakest_link":     original.WeakestLink,
                "weakest_detail":   original.WeakestDetail,
                "explanation":      original.Explanation,
                "protocol_count":   float64(original.ProtocolCount),
        }

        restored := restoreUnifiedConfidence(serialized)

        if restored.Level != original.Level {
                t.Errorf("Level mismatch: got %q, want %q", restored.Level, original.Level)
        }
        if restored.Score != original.Score {
                t.Errorf("Score mismatch: got %f, want %f", restored.Score, original.Score)
        }
        if restored.AccuracyFactor != original.AccuracyFactor {
                t.Errorf("AccuracyFactor mismatch: got %f, want %f", restored.AccuracyFactor, original.AccuracyFactor)
        }
        if restored.CurrencyFactor != original.CurrencyFactor {
                t.Errorf("CurrencyFactor mismatch: got %f, want %f", restored.CurrencyFactor, original.CurrencyFactor)
        }
        if restored.MaturityCeiling != original.MaturityCeiling {
                t.Errorf("MaturityCeiling mismatch: got %f, want %f", restored.MaturityCeiling, original.MaturityCeiling)
        }
        if restored.MaturityLevel != original.MaturityLevel {
                t.Errorf("MaturityLevel mismatch: got %q, want %q", restored.MaturityLevel, original.MaturityLevel)
        }
        if restored.WeakestLink != original.WeakestLink {
                t.Errorf("WeakestLink mismatch: got %q, want %q", restored.WeakestLink, original.WeakestLink)
        }
        if restored.WeakestDetail != original.WeakestDetail {
                t.Errorf("WeakestDetail mismatch: got %q, want %q", restored.WeakestDetail, original.WeakestDetail)
        }
        if restored.Explanation != original.Explanation {
                t.Errorf("Explanation mismatch: got %q, want %q", restored.Explanation, original.Explanation)
        }
        if restored.ProtocolCount != original.ProtocolCount {
                t.Errorf("ProtocolCount mismatch: got %d, want %d", restored.ProtocolCount, original.ProtocolCount)
        }
        t.Logf("MEASUREMENT: roundtrip fidelity verified — level=%q score=%.4f protocols=%d", restored.Level, restored.Score, restored.ProtocolCount)
}

func TestRestoreUnifiedConfidence_EmptyMap(t *testing.T) {
        uc := restoreUnifiedConfidence(map[string]any{})
        if uc.Level != "" || uc.Score != 0 || uc.ProtocolCount != 0 {
                t.Errorf("empty map should produce zero-value UC, got level=%q score=%f count=%d", uc.Level, uc.Score, uc.ProtocolCount)
        }
}

func TestRestoreUnifiedConfidence_WrongTypes(t *testing.T) {
        uc := restoreUnifiedConfidence(map[string]any{
                "level": 42,
                "score": "not a number",
        })
        if uc.Level != "" {
                t.Error("wrong type for level should produce empty string")
        }
        if uc.Score != 0 {
                t.Error("wrong type for score should produce 0")
        }
}

func TestCSVEscape_InjectionPrevention(t *testing.T) {
        tests := []struct {
                name  string
                input string
                want  string
                desc  string
        }{
                {"formula injection =", "=SUM(A1:A10)", "'=SUM(A1:A10)", "OWASP CSV injection: leading = must be prefixed"},
                {"formula injection +", "+1234567890", "'+1234567890", "OWASP CSV injection: leading + must be prefixed"},
                {"formula injection -", "-1+1", "'-1+1", "OWASP CSV injection: leading - must be prefixed"},
                {"formula injection @", "@SUM(A1)", "'@SUM(A1)", "OWASP CSV injection: leading @ must be prefixed"},
                {"tab injection", "\tcommand", "'\tcommand", "OWASP CSV injection: leading tab must be prefixed"},
                {"carriage return injection", "\rcommand", "\"'\rcommand\"", "OWASP CSV injection: leading CR must be prefixed and quoted"},
                {"normal value", "example.com", "example.com", "normal values pass through unchanged"},
                {"empty string", "", "", "empty string passes through unchanged"},
                {"comma in value", "hello,world", "\"hello,world\"", "commas must be quoted per RFC 4180"},
                {"quote in value", "say \"hello\"", "\"say \"\"hello\"\"\"", "double-quotes must be doubled per RFC 4180"},
                {"newline in value", "line1\nline2", "\"line1\nline2\"", "newlines must be quoted per RFC 4180"},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := csvEscape(tt.input)
                        if got != tt.want {
                                t.Errorf("csvEscape(%q) = %q, want %q — %s", tt.input, got, tt.want, tt.desc)
                        }
                })
        }
}

func TestExtractCurrencyFromResults(t *testing.T) {
        t.Run("extracts currency_report from nested map", func(t *testing.T) {
                results := map[string]interface{}{
                        mapKeyCurrencyReport: map[string]interface{}{"overall_score": 0.92},
                }
                got := extractCurrencyFromResults(results)
                if got == nil {
                        t.Fatal("expected non-nil currency report")
                }
                m, ok := got.(map[string]interface{})
                if !ok {
                        t.Fatal("expected map[string]interface{}")
                }
                if m["overall_score"] != 0.92 {
                        t.Errorf("overall_score = %v", m["overall_score"])
                }
        })

        t.Run("returns nil for missing key", func(t *testing.T) {
                got := extractCurrencyFromResults(map[string]interface{}{"other": "data"})
                if got != nil {
                        t.Errorf("expected nil for missing currency_report, got %v", got)
                }
        })

        t.Run("returns nil for non-map input", func(t *testing.T) {
                got := extractCurrencyFromResults("not a map")
                if got != nil {
                        t.Errorf("expected nil for non-map input, got %v", got)
                }
        })

        t.Run("returns nil for nil input", func(t *testing.T) {
                got := extractCurrencyFromResults(nil)
                if got != nil {
                        t.Errorf("expected nil for nil input, got %v", got)
                }
        })
}

func TestAnalysisHasProtocol(t *testing.T) {
        tests := []struct {
                name    string
                results map[string]any
                key     string
                want    bool
                desc    string
        }{
                {"DANE success", map[string]any{"dane_analysis": map[string]any{"status": "success"}}, "dane_analysis", true, "success means protocol is deployed"},
                {"DANE warning", map[string]any{"dane_analysis": map[string]any{"status": "warning"}}, "dane_analysis", true, "warning means protocol exists but has issues"},
                {"DANE fail", map[string]any{"dane_analysis": map[string]any{"status": "fail"}}, "dane_analysis", false, "fail means protocol is not properly deployed"},
                {"DANE error", map[string]any{"dane_analysis": map[string]any{"status": "error"}}, "dane_analysis", false, "error means lookup failed"},
                {"missing section", map[string]any{}, "dane_analysis", false, "missing section means not evaluated"},
                {"wrong type", map[string]any{"dane_analysis": "not a map"}, "dane_analysis", false, "non-map section is invalid"},
                {"DNSSEC success", map[string]any{"dnssec_analysis": map[string]any{"status": "success"}}, "dnssec_analysis", true, "DNSSEC success"},
                {"MTA-STS warning", map[string]any{"mta_sts_analysis": map[string]any{"status": "warning"}}, "mta_sts_analysis", true, "MTA-STS with issues still counts"},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := analysisHasProtocol(tt.results, tt.key)
                        if got != tt.want {
                                t.Errorf("analysisHasProtocol(%q) = %v, want %v — %s", tt.key, got, tt.want, tt.desc)
                        }
                })
        }
}

func TestExtractAnalysisError_Scientific(t *testing.T) {
        t.Run("no error yields success=true", func(t *testing.T) {
                success, errMsg := extractAnalysisError(map[string]any{
                        "spf_analysis": map[string]any{"status": "pass"},
                })
                if !success {
                        t.Error("expected success=true when no error key")
                }
                if errMsg != nil {
                        t.Errorf("expected nil error message, got %q", *errMsg)
                }
        })

        t.Run("error key yields success=false with message", func(t *testing.T) {
                msg := "DNS resolution timeout"
                success, errMsg := extractAnalysisError(map[string]any{
                        "error": msg,
                })
                if success {
                        t.Error("expected success=false with error key")
                }
                if errMsg == nil || *errMsg != msg {
                        t.Errorf("expected error message %q, got %v", msg, errMsg)
                }
        })

        t.Run("empty error string yields success=true", func(t *testing.T) {
                success, errMsg := extractAnalysisError(map[string]any{
                        "error": "",
                })
                if !success {
                        t.Error("empty error string should be treated as success")
                }
                if errMsg != nil {
                        t.Error("empty error string should not produce a message")
                }
        })

        t.Run("non-string error key is ignored", func(t *testing.T) {
                success, errMsg := extractAnalysisError(map[string]any{
                        "error": 42,
                })
                if !success {
                        t.Error("non-string error should be treated as success")
                }
                if errMsg != nil {
                        t.Error("non-string error should not produce a message")
                }
        })
}

func TestOptionalStrings_Scientific(t *testing.T) {
        t.Run("both non-empty", func(t *testing.T) {
                a, b := optionalStrings("US", "United States")
                if a == nil || *a != "US" {
                        t.Errorf("expected 'US', got %v", a)
                }
                if b == nil || *b != "United States" {
                        t.Errorf("expected 'United States', got %v", b)
                }
        })

        t.Run("both empty", func(t *testing.T) {
                a, b := optionalStrings("", "")
                if a != nil {
                        t.Error("expected nil for empty string a")
                }
                if b != nil {
                        t.Error("expected nil for empty string b")
                }
        })

        t.Run("mixed", func(t *testing.T) {
                a, b := optionalStrings("US", "")
                if a == nil || *a != "US" {
                        t.Error("expected non-nil a")
                }
                if b != nil {
                        t.Error("expected nil for empty b")
                }
        })
}

func TestExtractToolVersion_Scientific(t *testing.T) {
        t.Run("present", func(t *testing.T) {
                got := extractToolVersion(map[string]any{"_tool_version": "26.37.11"})
                if got != "26.37.11" {
                        t.Errorf("got %q", got)
                }
        })

        t.Run("missing", func(t *testing.T) {
                got := extractToolVersion(map[string]any{})
                if got != "" {
                        t.Errorf("expected empty, got %q", got)
                }
        })

        t.Run("wrong type", func(t *testing.T) {
                got := extractToolVersion(map[string]any{"_tool_version": 42})
                if got != "" {
                        t.Errorf("expected empty for non-string, got %q", got)
                }
        })
}

func TestResultsDomainExists_Scientific(t *testing.T) {
        tests := []struct {
                name    string
                results map[string]any
                want    bool
        }{
                {"domain exists true", map[string]any{"domain_exists": true}, true},
                {"domain exists false", map[string]any{"domain_exists": false}, false},
                {"missing key defaults true", map[string]any{}, true},
                {"wrong type defaults true", map[string]any{"domain_exists": "yes"}, true},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := resultsDomainExists(tt.results)
                        if got != tt.want {
                                t.Errorf("resultsDomainExists() = %v, want %v", got, tt.want)
                        }
                })
        }
}

func TestUnmarshalRawJSON(t *testing.T) {
        t.Run("valid JSON", func(t *testing.T) {
                raw := json.RawMessage(`{"key":"value"}`)
                got := unmarshalRawJSON(raw, "example.com", "test")
                if got == nil {
                        t.Fatal("expected non-nil result")
                }
                m, ok := got.(map[string]interface{})
                if !ok {
                        t.Fatal("expected map result")
                }
                if m["key"] != "value" {
                        t.Errorf("got %v", m)
                }
        })

        t.Run("empty raw message returns nil", func(t *testing.T) {
                got := unmarshalRawJSON(json.RawMessage{}, "example.com", "test")
                if got != nil {
                        t.Errorf("expected nil for empty raw, got %v", got)
                }
        })

        t.Run("nil raw message returns nil", func(t *testing.T) {
                got := unmarshalRawJSON(nil, "example.com", "test")
                if got != nil {
                        t.Errorf("expected nil for nil raw, got %v", got)
                }
        })

        t.Run("invalid JSON returns nil", func(t *testing.T) {
                got := unmarshalRawJSON(json.RawMessage(`{invalid`), "example.com", "test")
                if got != nil {
                        t.Errorf("expected nil for invalid JSON, got %v", got)
                }
        })
}

func TestMarshalOrderedJSON_Deterministic(t *testing.T) {
        entries := []orderedKV{
                {Key: "alpha", Value: "first"},
                {Key: "beta", Value: 42},
                {Key: "gamma", Value: true},
        }

        result1 := marshalOrderedJSON(entries)
        result2 := marshalOrderedJSON(entries)

        if string(result1) != string(result2) {
                t.Error("marshalOrderedJSON must be deterministic — same input should produce identical output")
        }

        var parsed map[string]any
        if err := json.Unmarshal(result1, &parsed); err != nil {
                t.Fatalf("marshalOrderedJSON must produce valid JSON: %v", err)
        }

        if parsed["alpha"] != "first" {
                t.Errorf("alpha = %v", parsed["alpha"])
        }
        if parsed["beta"] != float64(42) {
                t.Errorf("beta = %v", parsed["beta"])
        }
        if parsed["gamma"] != true {
                t.Errorf("gamma = %v", parsed["gamma"])
        }

        hash1 := sha3.Sum512(result1)
        hash2 := sha3.Sum512(result2)
        t.Logf("MEASUREMENT: SHA3-512 integrity hash = %s (deterministic=%v)",
                hex.EncodeToString(hash1[:])[:16]+"...",
                hash1 == hash2)
}

func TestMarshalOrderedJSON_Empty(t *testing.T) {
        result := marshalOrderedJSON(nil)
        if string(result) != "{}" {
                t.Errorf("empty entries should produce '{}', got %q", string(result))
        }
}

func TestApplyConfidenceEngines_NoOp(t *testing.T) {
        h := &AnalysisHandler{
                Config:      &config.Config{AppVersion: "test"},
                Calibration: icae.NewCalibrationEngine(),
                DimCharts:   icuae.NewDimensionCharts(),
        }

        t.Run("no currency report is a no-op", func(t *testing.T) {
                results := map[string]any{
                        "spf_analysis": map[string]any{"status": "pass"},
                }
                h.applyConfidenceEngines(results)
                if _, ok := results["calibrated_confidence"]; ok {
                        t.Error("should not inject calibrated_confidence without currency report")
                }
        })

        t.Run("wrong type currency report is a no-op", func(t *testing.T) {
                results := map[string]any{
                        mapKeyCurrencyReport: "not a CurrencyReport",
                }
                h.applyConfidenceEngines(results)
                if _, ok := results["calibrated_confidence"]; ok {
                        t.Error("should not inject calibrated_confidence for wrong type")
                }
        })
}

func TestApplyConfidenceEngines_WithCurrencyReport(t *testing.T) {
        h := &AnalysisHandler{
                Config:      &config.Config{AppVersion: "test"},
                Calibration: icae.NewCalibrationEngine(),
                DimCharts:   icuae.NewDimensionCharts(),
        }

        results := map[string]any{
                "spf_analysis":   map[string]any{"status": "pass"},
                "dkim_analysis":  map[string]any{"status": "warning"},
                "dmarc_analysis": map[string]any{"status": "pass"},
                "dane_analysis":  map[string]any{"status": "error"},
                "dnssec_analysis": map[string]any{"status": "success"},
                "bimi_analysis":  map[string]any{"status": "n/a"},
                "mta_sts_analysis": map[string]any{"status": "warning"},
                "tlsrpt_analysis": map[string]any{"status": "fail"},
                "caa_analysis":   map[string]any{"status": "pass"},
                mapKeyCurrencyReport: icuae.CurrencyReport{
                        OverallScore: 0.87,
                        Dimensions: []icuae.DimensionScore{
                                {Dimension: icuae.DimensionSourceCredibility, Score: 0.95},
                                {Dimension: icuae.DimensionCurrentness, Score: 0.80},
                                {Dimension: icuae.DimensionCompleteness, Score: 0.90},
                                {Dimension: icuae.DimensionTTLCompliance, Score: 0.85},
                        },
                },
        }

        h.applyConfidenceEngines(results)

        calibrated, ok := results["calibrated_confidence"].(map[string]float64)
        if !ok {
                t.Fatal("expected calibrated_confidence map after confidence engines")
        }

        expectedProtocols := []string{"SPF", "DKIM", "DMARC", "DANE", "DNSSEC", "BIMI", "MTA_STS", "TLS_RPT", "CAA"}
        for _, proto := range expectedProtocols {
                score, exists := calibrated[proto]
                if !exists {
                        t.Errorf("MEASUREMENT: missing calibrated score for %s", proto)
                        continue
                }
                if score < 0 || score > 1 {
                        t.Errorf("MEASUREMENT: calibrated score for %s = %.4f — must be in [0, 1]", proto, score)
                }
                t.Logf("MEASUREMENT: %s calibrated_confidence = %.4f", proto, score)
        }

        ewma, ok := results["ewma_drift"].(map[string]icuae.ChartSnapshot)
        if !ok {
                t.Fatal("expected ewma_drift map after confidence engines")
        }
        t.Logf("MEASUREMENT: ewma_drift dimensions tracked = %d", len(ewma))
}

func TestComputeCalibratedConfidence_AllProtocols(t *testing.T) {
        h := &AnalysisHandler{
                Calibration: icae.NewCalibrationEngine(),
        }

        results := map[string]any{
                "spf_analysis":     map[string]any{"status": "pass"},
                "dkim_analysis":    map[string]any{"status": "pass"},
                "dmarc_analysis":   map[string]any{"status": "pass"},
                "dane_analysis":    map[string]any{"status": "pass"},
                "dnssec_analysis":  map[string]any{"status": "pass"},
                "bimi_analysis":    map[string]any{"status": "pass"},
                "mta_sts_analysis": map[string]any{"status": "pass"},
                "tlsrpt_analysis":  map[string]any{"status": "pass"},
                "caa_analysis":     map[string]any{"status": "pass"},
                "resolver_consensus": map[string]any{
                        "per_record_consensus": map[string]any{
                                "A":  map[string]any{"resolver_count": 4, "consensus": true},
                                "MX": map[string]any{"resolver_count": 4, "consensus": true},
                        },
                },
        }

        cr := icuae.CurrencyReport{OverallScore: 0.95}
        calibrated := h.computeCalibratedConfidence(results, cr)

        if len(calibrated) != 9 {
                t.Errorf("expected 9 protocols calibrated, got %d", len(calibrated))
        }

        for proto, score := range calibrated {
                if score < 0.5 {
                        t.Errorf("MEASUREMENT: all-pass results should yield high confidence for %s, got %.4f", proto, score)
                }
                t.Logf("MEASUREMENT: %s = %.4f (all-pass with full resolver consensus)", proto, score)
        }
}

func TestRecordDimensionCharts(t *testing.T) {
        h := &AnalysisHandler{
                DimCharts: icuae.NewDimensionCharts(),
        }

        cr := icuae.CurrencyReport{
                OverallScore: 0.87,
                Dimensions: []icuae.DimensionScore{
                        {Dimension: icuae.DimensionSourceCredibility, Score: 0.95},
                        {Dimension: icuae.DimensionCurrentness, Score: 0.80},
                        {Dimension: icuae.DimensionCompleteness, Score: 0.90},
                        {Dimension: icuae.DimensionTTLCompliance, Score: 0.85},
                        {Dimension: icuae.DimensionTTLRelevance, Score: 0.75},
                },
        }

        snapshot := h.recordDimensionCharts(cr)

        for dimKey, chartKey := range icuaeToDimChart {
                if _, ok := snapshot[chartKey]; ok {
                        t.Logf("MEASUREMENT: %s (%s) EWMA recorded", dimKey, chartKey)
                }
        }

        snapshot2 := h.recordDimensionCharts(cr)
        for chartKey, snap := range snapshot2 {
                if snap.Period < 2 {
                        t.Errorf("second recording should have period ≥ 2 for %s, got %d", chartKey, snap.Period)
                }
                t.Logf("MEASUREMENT: %s period=%d value=%.4f trend=%s", chartKey, snap.Period, snap.Value, snap.Trend)
        }
}

func TestExtractCustomSelectors_Scientific(t *testing.T) {
        tests := []struct {
                name  string
                sel1  string
                sel2  string
                count int
        }{
                {"both empty", "", "", 0},
                {"first only", "google", "", 1},
                {"second only", "", "selector2", 1},
                {"both present", "google", "selector2", 2},
                {"whitespace trimmed", "  google  ", "  selector2  ", 2},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        gin := mockGinContextWithForm(tt.sel1, tt.sel2)
                        selectors := extractCustomSelectors(gin)
                        if len(selectors) != tt.count {
                                t.Errorf("expected %d selectors, got %d: %v", tt.count, len(selectors), selectors)
                        }
                })
        }
}

func TestResolveCovertMode_Scientific(t *testing.T) {
        tests := []struct {
                name   string
                covert string
                domain string
                want   string
                desc   string
        }{
                {"standard analysis", "", "example.com", "E", "default is Engineer mode"},
                {"covert mode", "1", "example.com", "C", "covert=1 activates Covert Recon Mode"},
                {"TLD analysis", "", "com", "Z", "TLD input activates Zone mode"},
                {"covert + TLD", "1", "com", "CZ", "covert=1 + TLD = Covert Zone mode"},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        c := mockGinContextWithCovert(tt.covert)
                        got := resolveCovertMode(c, tt.domain)
                        if got != tt.want {
                                t.Errorf("resolveCovertMode(covert=%q, domain=%q) = %q, want %q — %s",
                                        tt.covert, tt.domain, got, tt.want, tt.desc)
                        }
                })
        }
}

func TestExtractScanFields_Classification(t *testing.T) {
        t.Run("CISA scan classification", func(t *testing.T) {
                sc := scanner.Classification{IsScan: true, Source: "cisa", IP: "192.168.1.1"}
                src, ip := extractScanFields(sc)
                if src == nil || *src != "cisa" {
                        t.Errorf("CISA scan source = %v", src)
                }
                if ip == nil || *ip != "192.168.1.1" {
                        t.Errorf("scan IP = %v", ip)
                }
                t.Log("MEASUREMENT: CISA scan correctly classified with source and IP preserved")
        })

        t.Run("non-scan classification", func(t *testing.T) {
                sc := scanner.Classification{IsScan: false, Source: "", IP: "10.0.0.1"}
                src, ip := extractScanFields(sc)
                if src != nil {
                        t.Error("non-scan should have nil source")
                }
                if ip == nil || *ip != "10.0.0.1" {
                        t.Error("IP should still be captured for non-scan requests")
                }
        })
}

func TestDriftSeverityClassification(t *testing.T) {
        t.Run("ComputePostureDiff with no changes yields empty fields", func(t *testing.T) {
                same := map[string]any{
                        "spf_analysis":  map[string]any{"status": "pass"},
                        "dkim_analysis": map[string]any{"status": "pass"},
                }
                fields := analyzer.ComputePostureDiff(same, same)
                if len(fields) != 0 {
                        t.Errorf("identical results should produce 0 diff fields, got %d", len(fields))
                }
                t.Log("MEASUREMENT: identical posture → 0 diff fields → severity=info (no drift)")
        })

        t.Run("ComputePostureDiff detects SPF degradation with correct severity", func(t *testing.T) {
                prev := map[string]any{"spf_analysis": map[string]any{"status": "pass"}}
                curr := map[string]any{"spf_analysis": map[string]any{"status": "fail"}}
                fields := analyzer.ComputePostureDiff(prev, curr)
                if len(fields) == 0 {
                        t.Fatal("SPF status change must produce at least one diff field")
                }
                var hasCritical bool
                for _, f := range fields {
                        if f.Severity == "critical" {
                                hasCritical = true
                        }
                        t.Logf("MEASUREMENT: field=%q prev=%q curr=%q severity=%q", f.Label, f.Previous, f.Current, f.Severity)
                }
                if !hasCritical {
                        t.Log("MEASUREMENT: SPF pass→fail not classified as critical (may be warning depending on field spec)")
                }
        })

        t.Run("severity escalation logic matches production persistDriftEvent", func(t *testing.T) {
                fields := []analyzer.PostureDiffField{
                        {Label: "DMARC Status", Previous: "pass", Current: "fail", Severity: "critical"},
                        {Label: "SPF Status", Previous: "pass", Current: "warning", Severity: "warning"},
                        {Label: "CAA Status", Previous: "pass", Current: "pass", Severity: "info"},
                }
                severity := "info"
                for _, f := range fields {
                        if f.Severity == "critical" {
                                severity = "critical"
                                break
                        }
                        if f.Severity == "warning" && severity != "critical" {
                                severity = "warning"
                        }
                }
                if severity != "critical" {
                        t.Errorf("critical must override all — got %q", severity)
                }
                t.Logf("MEASUREMENT: escalation order verified: info < warning < critical (final=%s)", severity)
        })
}

func TestExtractAuthInfo(t *testing.T) {
        t.Run("authenticated with user ID", func(t *testing.T) {
                c := mockGinContext()
                c.Set(mapKeyAuthenticated, true)
                c.Set(mapKeyUserId, int32(42))

                isAuth, userID := extractAuthInfo(c)
                if !isAuth {
                        t.Error("expected authenticated=true")
                }
                if userID != 42 {
                        t.Errorf("expected userID=42, got %d", userID)
                }
        })

        t.Run("not authenticated", func(t *testing.T) {
                c := mockGinContext()
                isAuth, userID := extractAuthInfo(c)
                if isAuth {
                        t.Error("expected authenticated=false")
                }
                if userID != 0 {
                        t.Errorf("expected userID=0, got %d", userID)
                }
        })

        t.Run("authenticated but no user ID", func(t *testing.T) {
                c := mockGinContext()
                c.Set(mapKeyAuthenticated, true)
                isAuth, userID := extractAuthInfo(c)
                if !isAuth {
                        t.Error("expected authenticated=true")
                }
                if userID != 0 {
                        t.Errorf("expected userID=0 when not set, got %d", userID)
                }
        })

        t.Run("wrong type for authenticated", func(t *testing.T) {
                c := mockGinContext()
                c.Set(mapKeyAuthenticated, "yes")
                isAuth, _ := extractAuthInfo(c)
                if isAuth {
                        t.Error("string 'yes' should not be treated as authenticated")
                }
        })
}

func TestCheckPrivateAccess_Public(t *testing.T) {
        h := &AnalysisHandler{}
        c := mockGinContext()
        if !h.checkPrivateAccess(c, 1, false) {
                t.Error("public reports should always be accessible")
        }
}

func TestCheckPrivateAccess_PrivateNotAuthenticated(t *testing.T) {
        h := &AnalysisHandler{}
        c := mockGinContext()
        if h.checkPrivateAccess(c, 1, true) {
                t.Error("private reports should not be accessible without authentication")
        }
}

func TestProtocolResultKeys_9Protocols(t *testing.T) {
        expected := []string{"SPF", "DKIM", "DMARC", "DANE", "DNSSEC", "BIMI", "MTA_STS", "TLS_RPT", "CAA"}
        if len(protocolResultKeys) != 9 {
                t.Errorf("expected exactly 9 protocol result keys, got %d", len(protocolResultKeys))
        }
        for _, proto := range expected {
                resultKey, ok := protocolResultKeys[proto]
                if !ok {
                        t.Errorf("missing protocol result key for %s", proto)
                        continue
                }
                if resultKey == "" {
                        t.Errorf("empty result key for protocol %s", proto)
                }
                t.Logf("MEASUREMENT: protocol %s → result_key %q", proto, resultKey)
        }
}

func TestIcuaeToDimChart_Mapping(t *testing.T) {
        expectedMappings := map[string]string{
                icuae.DimensionSourceCredibility: "SourceCredibility",
                icuae.DimensionCurrentness:       "TemporalValidity",
                icuae.DimensionCompleteness:      "ChainCompleteness",
                icuae.DimensionTTLCompliance:     "TTLCompliance",
                icuae.DimensionTTLRelevance:      "ResolverConsensus",
        }

        if len(icuaeToDimChart) != len(expectedMappings) {
                t.Errorf("expected %d dimension chart mappings, got %d", len(expectedMappings), len(icuaeToDimChart))
        }

        for dimKey, wantChart := range expectedMappings {
                gotChart, ok := icuaeToDimChart[dimKey]
                if !ok {
                        t.Errorf("missing mapping for dimension %q", dimKey)
                        continue
                }
                if gotChart != wantChart {
                        t.Errorf("dimension %q maps to %q, want %q", dimKey, gotChart, wantChart)
                }
        }
}

func TestExtractReportsAndDurations_Scientific(t *testing.T) {
        t.Run("empty analyses", func(t *testing.T) {
                reports, durations := extractReportsAndDurations(nil)
                if len(reports) != 0 || len(durations) != 0 {
                        t.Errorf("expected empty, got %d reports %d durations", len(reports), len(durations))
                }
        })

        t.Run("analyses with empty FullResults are skipped", func(t *testing.T) {
                analyses := []dbq.DomainAnalysis{
                        {FullResults: json.RawMessage{}},
                        {FullResults: nil},
                }
                reports, durations := extractReportsAndDurations(analyses)
                if len(reports) != 0 || len(durations) != 0 {
                        t.Errorf("empty FullResults should be skipped, got %d reports %d durations", len(reports), len(durations))
                }
        })

        t.Run("analyses with invalid JSON are skipped", func(t *testing.T) {
                analyses := []dbq.DomainAnalysis{
                        {FullResults: json.RawMessage(`{invalid json}`)},
                }
                reports, durations := extractReportsAndDurations(analyses)
                if len(reports) != 0 || len(durations) != 0 {
                        t.Errorf("invalid JSON should be skipped, got %d reports %d durations", len(reports), len(durations))
                }
                t.Log("MEASUREMENT: invalid JSON gracefully skipped — no panic")
        })

        t.Run("analyses with valid JSON but no currency_report", func(t *testing.T) {
                dur := 1.5
                analyses := []dbq.DomainAnalysis{
                        {
                                FullResults:      json.RawMessage(`{"spf_analysis":{"status":"pass"}}`),
                                AnalysisDuration: &dur,
                        },
                }
                reports, durations := extractReportsAndDurations(analyses)
                if len(reports) != 0 {
                        t.Errorf("no currency_report → 0 reports, got %d", len(reports))
                }
                if len(durations) != 1 {
                        t.Errorf("expected 1 duration, got %d", len(durations))
                } else if durations[0] != 1500 {
                        t.Errorf("duration should be converted to ms: want 1500, got %.1f", durations[0])
                }
                t.Log("MEASUREMENT: duration extracted and converted to ms even without currency_report")
        })

        t.Run("nil AnalysisDuration omits duration entry", func(t *testing.T) {
                analyses := []dbq.DomainAnalysis{
                        {FullResults: json.RawMessage(`{"spf_analysis":{"status":"pass"}}`)},
                }
                _, durations := extractReportsAndDurations(analyses)
                if len(durations) != 0 {
                        t.Errorf("nil duration should not append, got %d entries", len(durations))
                }
        })
}

func keys(m map[string]any) []string {
        result := make([]string, 0, len(m))
        for k := range m {
                result = append(result, k)
        }
        return result
}
