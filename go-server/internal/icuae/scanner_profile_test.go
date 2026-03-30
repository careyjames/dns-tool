// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package icuae

import (
        "testing"
)

func TestGenerateSuggestedConfig_InsufficientData(t *testing.T) {
        stats := RollingStats{ScanCount: 2}
        config := GenerateSuggestedConfig(stats, DefaultProfile)
        if config.HasSuggestions() {
                t.Error("expected no suggestions with < 3 scans")
        }
        if config.Confidence != "low" {
                t.Errorf("expected 'low' confidence, got %q", config.Confidence)
        }
}

func TestGenerateSuggestedConfig_HealthyDomain(t *testing.T) {
        stats := RollingStats{
                ScanCount:            5,
                AvgResolverAgreement: 95,
                TTLDeviations:        map[string]float64{},
                RecordTypeErrors:     map[string]int{},
                AvgScanDuration:      8000,
        }
        config := GenerateSuggestedConfig(stats, DefaultProfile)
        if config.HasSuggestions() {
                t.Errorf("expected no suggestions for healthy domain, got %d", len(config.Suggestions))
        }
        if config.Confidence != "medium" {
                t.Errorf("expected 'medium' confidence with 5 scans, got %q", config.Confidence)
        }
}

func TestGenerateSuggestedConfig_HighConfidence(t *testing.T) {
        stats := RollingStats{
                ScanCount:            15,
                AvgResolverAgreement: 95,
                AvgScanDuration:      8000,
        }
        config := GenerateSuggestedConfig(stats, DefaultProfile)
        if config.Confidence != "high" {
                t.Errorf("expected 'high' confidence with 15 scans, got %q", config.Confidence)
        }
}

func TestGenerateSuggestedConfig_LowResolverAgreement(t *testing.T) {
        stats := RollingStats{
                ScanCount:            5,
                AvgResolverAgreement: 55,
                AvgScanDuration:      8000,
        }
        config := GenerateSuggestedConfig(stats, DefaultProfile)
        if !config.HasSuggestions() {
                t.Fatal("expected resolver suggestions for 55% agreement")
        }
        found := false
        for _, s := range config.Suggestions {
                if s.Category == "resolver" {
                        found = true
                        if s.Severity != "medium" {
                                t.Errorf("expected 'medium' severity for 55%% agreement, got %q", s.Severity)
                        }
                }
        }
        if !found {
                t.Error("expected resolver suggestion not found")
        }
}

func TestGenerateSuggestedConfig_VeryLowResolverAgreement(t *testing.T) {
        stats := RollingStats{
                ScanCount:            5,
                AvgResolverAgreement: 40,
                AvgScanDuration:      8000,
        }
        config := GenerateSuggestedConfig(stats, DefaultProfile)
        found := false
        for _, s := range config.Suggestions {
                if s.Category == "resolver" && s.Severity == "high" {
                        found = true
                }
        }
        if !found {
                t.Error("expected high-severity resolver suggestion for 40% agreement")
        }
}

func TestGenerateSuggestedConfig_SlowScans(t *testing.T) {
        stats := RollingStats{
                ScanCount:            5,
                AvgResolverAgreement: 90,
                AvgScanDuration:      35000,
        }
        config := GenerateSuggestedConfig(stats, DefaultProfile)
        found := false
        for _, s := range config.Suggestions {
                if s.Category == "timeout" {
                        found = true
                }
        }
        if !found {
                t.Error("expected timeout suggestion for 35s avg scan duration")
        }
}

func TestBuildRollingStats_Empty(t *testing.T) {
        stats := BuildRollingStats(nil, nil)
        if stats.ScanCount != 0 {
                t.Errorf("expected 0 scans, got %d", stats.ScanCount)
        }
}

func TestBuildRollingStats_WithReports(t *testing.T) {
        reports := []CurrencyReport{
                {
                        Dimensions: []DimensionScore{
                                {Dimension: DimensionSourceCredibility, Score: 90},
                                {Dimension: DimensionTTLRelevance, Score: 50, Findings: []TTLFinding{
                                        {RecordType: "MX", Ratio: 0.083},
                                }},
                        },
                },
                {
                        Dimensions: []DimensionScore{
                                {Dimension: DimensionSourceCredibility, Score: 80},
                                {Dimension: DimensionTTLRelevance, Score: 60},
                        },
                },
        }
        durations := []float64{5000, 7000}
        stats := BuildRollingStats(reports, durations)

        if stats.ScanCount != 2 {
                t.Errorf("expected 2 scans, got %d", stats.ScanCount)
        }
        if stats.AvgResolverAgreement != 85 {
                t.Errorf("expected 85%% avg agreement, got %.1f", stats.AvgResolverAgreement)
        }
        if stats.AvgScanDuration != 6000 {
                t.Errorf("expected 6000ms avg duration, got %.1f", stats.AvgScanDuration)
        }
        if _, ok := stats.TTLDeviations["MX"]; !ok {
                t.Error("expected MX TTL deviation tracked")
        }
}

func TestProfileSuggestion_SeverityClass(t *testing.T) {
        tests := []struct {
                severity string
                want     string
        }{
                {"high", "danger"},
                {"medium", "warning"},
                {"low", "info"},
        }
        for _, tt := range tests {
                s := ProfileSuggestion{Severity: tt.severity}
                if got := s.SeverityClass(); got != tt.want {
                        t.Errorf("SeverityClass(%q) = %q, want %q", tt.severity, got, tt.want)
                }
        }
}

func TestProfileSuggestion_CategoryIcon(t *testing.T) {
        tests := []struct {
                category string
                want     string
        }{
                {"resolver", "server"},
                {"retry", "arrows-rotate"},
                {"timeout", "clock"},
                {"priority", "cogs"},
                {"unknown", "cogs"},
        }
        for _, tt := range tests {
                s := ProfileSuggestion{Category: tt.category}
                if got := s.CategoryIcon(); got != tt.want {
                        t.Errorf("CategoryIcon(%q) = %q, want %q", tt.category, got, tt.want)
                }
        }
}

func TestSuggestedConfig_ConfidenceClass(t *testing.T) {
        tests := []struct {
                conf string
                want string
        }{
                {"high", "success"},
                {"medium", "info"},
                {"low", "secondary"},
        }
        for _, tt := range tests {
                sc := SuggestedConfig{Confidence: tt.conf}
                if got := sc.ConfidenceClass(); got != tt.want {
                        t.Errorf("ConfidenceClass(%q) = %q, want %q", tt.conf, got, tt.want)
                }
        }
}

func TestBuildPriorityOrder(t *testing.T) {
        stats := RollingStats{
                RecordTypeErrors: map[string]int{
                        "TLSA": 5,
                        "A":    0,
                        "MX":   1,
                },
        }
        order := buildPriorityOrder(stats)
        if len(order) == 0 {
                t.Fatal("expected non-empty priority order")
        }
        if order[0] == "TLSA" {
                t.Error("TLSA should not be first (highest errors)")
        }
}

func TestTotalErrorRate_ZeroScans(t *testing.T) {
        stats := RollingStats{ScanCount: 0}
        rate := totalErrorRate(stats)
        if rate != 0 {
                t.Errorf("expected 0, got %.1f", rate)
        }
}

func TestTotalErrorRate_WithErrors(t *testing.T) {
        stats := RollingStats{
                ScanCount:        10,
                RecordTypeErrors: map[string]int{"A": 5, "MX": 3},
        }
        rate := totalErrorRate(stats)
        if rate <= 0 {
                t.Errorf("expected positive error rate, got %.1f", rate)
        }
}

func TestSuggestRetryChanges_HighErrorRate(t *testing.T) {
        stats := RollingStats{
                ScanCount:        10,
                RecordTypeErrors: map[string]int{"A": 8, "MX": 6},
        }
        current := ScannerProfile{RetryCount: 2}
        suggestions := suggestRetryChanges(stats, current)
        if len(suggestions) == 0 {
                t.Error("expected retry suggestions for high error rate")
        }
}

func TestSuggestRetryChanges_VeryHighErrorRate(t *testing.T) {
        stats := RollingStats{
                ScanCount:        3,
                RecordTypeErrors: map[string]int{"A": 3, "MX": 3, "TXT": 3},
        }
        current := ScannerProfile{RetryCount: 2}
        suggestions := suggestRetryChanges(stats, current)
        found := false
        for _, s := range suggestions {
                if s.Parameter == "retry_count" {
                        found = true
                }
        }
        if !found {
                t.Error("expected retry_count suggestion for very high error rate")
        }
}

func TestSuggestRetryChanges_NoSuggestionWhenAlreadyHigh(t *testing.T) {
        stats := RollingStats{
                ScanCount:        10,
                RecordTypeErrors: map[string]int{"A": 5},
        }
        current := ScannerProfile{RetryCount: 5}
        suggestions := suggestRetryChanges(stats, current)
        if len(suggestions) != 0 {
                t.Errorf("expected no suggestions when retry count already exceeds suggested, got %d", len(suggestions))
        }
}

func TestSuggestTimeoutChanges_ReduceTimeout(t *testing.T) {
        stats := RollingStats{
                ScanCount:       5,
                AvgScanDuration: 3000,
        }
        current := ScannerProfile{TimeoutSeconds: 10}
        suggestions := suggestTimeoutChanges(stats, current)
        if len(suggestions) == 0 {
                t.Error("expected timeout reduction suggestion for fast scans with high timeout")
        }
}

func TestSuggestTimeoutChanges_NoChange(t *testing.T) {
        stats := RollingStats{
                ScanCount:       5,
                AvgScanDuration: 15000,
        }
        current := ScannerProfile{TimeoutSeconds: 5}
        suggestions := suggestTimeoutChanges(stats, current)
        if len(suggestions) != 0 {
                t.Errorf("expected no timeout suggestions for moderate duration, got %d", len(suggestions))
        }
}

func TestSuggestRecordPriority_HighErrorTypes(t *testing.T) {
        stats := RollingStats{
                ScanCount:        9,
                RecordTypeErrors: map[string]int{"TLSA": 5, "DANE": 4},
        }
        current := DefaultProfile
        suggestions := suggestRecordPriority(stats, current)
        if len(suggestions) == 0 {
                t.Error("expected priority suggestions for error-prone record types")
        }
}

func TestSuggestRecordPriority_NoErrors(t *testing.T) {
        stats := RollingStats{
                ScanCount:        10,
                RecordTypeErrors: map[string]int{},
        }
        current := DefaultProfile
        suggestions := suggestRecordPriority(stats, current)
        if len(suggestions) != 0 {
                t.Errorf("expected no priority suggestions, got %d", len(suggestions))
        }
}

func TestApplyRetryCount_LowAgreement(t *testing.T) {
        suggested := ScannerProfile{RetryCount: 2}
        sug := []ProfileSuggestion{{Parameter: "retry_count"}}
        applyRetryCount(&suggested, sug, 50)
        if suggested.RetryCount != 4 {
                t.Errorf("expected retry count 4 for agreement < 60, got %d", suggested.RetryCount)
        }
}

func TestApplyRetryCount_ModerateAgreement(t *testing.T) {
        suggested := ScannerProfile{RetryCount: 2}
        sug := []ProfileSuggestion{{Parameter: "retry_count"}}
        applyRetryCount(&suggested, sug, 70)
        if suggested.RetryCount != 3 {
                t.Errorf("expected retry count 3 for agreement 70, got %d", suggested.RetryCount)
        }
}

func TestApplyRetryCount_HighAgreement(t *testing.T) {
        suggested := ScannerProfile{RetryCount: 2}
        sug := []ProfileSuggestion{{Parameter: "retry_count"}}
        applyRetryCount(&suggested, sug, 90)
        if suggested.RetryCount != 2 {
                t.Errorf("expected retry count unchanged for agreement >= 80, got %d", suggested.RetryCount)
        }
}

func TestApplyRetryCount_NoSuggestions(t *testing.T) {
        suggested := ScannerProfile{RetryCount: 2}
        applyRetryCount(&suggested, nil, 50)
        if suggested.RetryCount != 2 {
                t.Errorf("expected retry count unchanged with no suggestions, got %d", suggested.RetryCount)
        }
}

func TestApplyRetryCount_WrongParameter(t *testing.T) {
        suggested := ScannerProfile{RetryCount: 2}
        sug := []ProfileSuggestion{{Parameter: "resolver_set"}}
        applyRetryCount(&suggested, sug, 50)
        if suggested.RetryCount != 2 {
                t.Errorf("expected retry count unchanged for wrong parameter, got %d", suggested.RetryCount)
        }
}

func TestSuggestRetryChanges_ErrorRateAbove30(t *testing.T) {
        stats := RollingStats{
                ScanCount:        3,
                RecordTypeErrors: map[string]int{"A": 3},
        }
        current := ScannerProfile{RetryCount: 1}
        suggestions := suggestRetryChanges(stats, current)
        if len(suggestions) == 0 {
                t.Fatal("expected retry suggestions for error rate > 30")
        }
        if suggestions[0].Suggested != "4 retries" {
                t.Errorf("expected 4 retries for >30%% error rate, got %q", suggestions[0].Suggested)
        }
}

func TestSuggestRetryChanges_ErrorRateBetween10And30(t *testing.T) {
        stats := RollingStats{
                ScanCount:        10,
                RecordTypeErrors: map[string]int{"A": 2},
        }
        current := ScannerProfile{RetryCount: 1}
        suggestions := suggestRetryChanges(stats, current)
        if len(suggestions) == 0 {
                t.Fatal("expected retry suggestions for error rate > 10")
        }
        if suggestions[0].Suggested != "3 retries" {
                t.Errorf("expected 3 retries for 10-30%% error rate, got %q", suggestions[0].Suggested)
        }
}

func TestApplySuggestedProfile_WithAllSuggestions(t *testing.T) {
        current := DefaultProfile
        suggested := current
        stats := RollingStats{
                ScanCount:            5,
                AvgResolverAgreement: 50,
                AvgScanDuration:      35000,
                RecordTypeErrors:     map[string]int{"TLSA": 5},
        }
        resolverSugs := []ProfileSuggestion{{Parameter: "resolver_set", Category: "resolver"}}
        retrySugs := []ProfileSuggestion{{Parameter: "retry_count", Category: "retry"}}
        timeoutSugs := []ProfileSuggestion{{Parameter: "timeout_seconds", Category: "timeout"}}
        prioritySugs := []ProfileSuggestion{{Parameter: "record_type_priority", Category: "priority"}}

        applySuggestedProfile(&suggested, current, stats, resolverSugs, retrySugs, timeoutSugs, prioritySugs)

        if suggested.TimeoutSeconds != 8 {
                t.Errorf("expected timeout 8 for slow scans, got %d", suggested.TimeoutSeconds)
        }
        if suggested.RetryCount != 4 {
                t.Errorf("expected retry 4 for low agreement, got %d", suggested.RetryCount)
        }
}

func TestGenerateSuggestedConfig_WithRecordPriority(t *testing.T) {
        stats := RollingStats{
                ScanCount:            5,
                AvgResolverAgreement: 90,
                AvgScanDuration:      8000,
                TTLDeviations:        map[string]float64{},
                DimensionTrends:      map[string][]float64{},
                RecordTypeErrors:     map[string]int{"TLSA": 4},
        }
        config := GenerateSuggestedConfig(stats, DefaultProfile)
        found := false
        for _, s := range config.Suggestions {
                if s.Category == "priority" {
                        found = true
                }
        }
        if !found {
                t.Error("expected priority suggestion for error-prone TLSA type")
        }
}
