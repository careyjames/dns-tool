package icuae

import (
        "encoding/json"
        "testing"
)

func TestHydrateCurrencyReport_UnmarshalError(t *testing.T) {
        _, ok := HydrateCurrencyReport(make(chan int))
        if ok {
                t.Error("expected hydration to fail for unmarshalable type")
        }
}

func TestHydrateCurrencyReport_EmptyMap(t *testing.T) {
        cr, ok := HydrateCurrencyReport(map[string]interface{}{})
        if !ok {
                t.Fatal("expected hydration to succeed for empty map")
        }
        if cr.OverallGrade != "" {
                t.Errorf("expected empty grade, got %q", cr.OverallGrade)
        }
}

func TestHydrateCurrencyReport_WithDimensions(t *testing.T) {
        original := CurrencyReport{
                OverallGrade:  GradeGood,
                OverallScore:  80.0,
                ResolverCount: 3,
                RecordCount:   5,
                Guidance:      "Looking good",
                Dimensions: []DimensionScore{
                        {Dimension: DimensionCurrentness, Grade: GradeExcellent, Score: 95},
                        {Dimension: DimensionTTLCompliance, Grade: GradeGood, Score: 80},
                },
        }
        b, _ := json.Marshal(original)
        var m map[string]interface{}
        json.Unmarshal(b, &m)

        cr, ok := HydrateCurrencyReport(m)
        if !ok {
                t.Fatal("expected hydration to succeed")
        }
        if len(cr.Dimensions) != 2 {
                t.Fatalf("expected 2 dimensions, got %d", len(cr.Dimensions))
        }
        if cr.ResolverCount != 3 {
                t.Errorf("ResolverCount = %d, want 3", cr.ResolverCount)
        }
}

func TestDimensionTuningHint_AllDimensions(t *testing.T) {
        dimensions := []string{
                DimensionCurrentness, DimensionTTLCompliance,
                DimensionCompleteness, DimensionSourceCredibility, DimensionTTLRelevance,
        }

        for _, dim := range dimensions {
                hint, icon := dimensionTuningHint(dim, 30.0)
                if hint == "" || icon == "" {
                        t.Errorf("expected tuning hint for %q at score 30, got hint=%q icon=%q", dim, hint, icon)
                }
        }

        for _, dim := range dimensions {
                hint, icon := dimensionTuningHint(dim, 95.0)
                if hint != "" || icon != "" {
                        t.Errorf("expected no tuning hint for %q at score 95, got hint=%q icon=%q", dim, hint, icon)
                }
        }
}

func TestDimensionTuningHint_GoodRange(t *testing.T) {
        hint, icon := dimensionTuningHint(DimensionCurrentness, 80.0)
        if hint == "" || icon == "" {
                t.Error("expected tuning hint for score 80")
        }
        if icon != "lightbulb text-success" {
                t.Errorf("expected lightbulb icon for good range, got %q", icon)
        }
}

func TestEvaluateCurrentness_DataAgeBetween1xAnd2xTTL(t *testing.T) {
        records := []RecordCurrency{
                {RecordType: "A", ObservedTTL: 300, DataAgeS: 450},
        }
        result := EvaluateCurrentness(records)
        if result.Score != 50 {
                t.Errorf("expected score 50 for data age between 1x-2x TTL, got %.1f", result.Score)
        }
        if result.Grade != GradeAdequate {
                t.Errorf("expected adequate grade, got %q", result.Grade)
        }
}

func TestEvaluateCurrentness_DataAgeAbove2xTTL(t *testing.T) {
        records := []RecordCurrency{
                {RecordType: "A", ObservedTTL: 300, DataAgeS: 900},
        }
        result := EvaluateCurrentness(records)
        if result.Score != 0 {
                t.Errorf("expected score 0 for data age > 2x TTL, got %.1f", result.Score)
        }
}

func TestEvaluateTTLCompliance_ResolverMissingEntry(t *testing.T) {
        resolver := map[string]uint32{"MX": 3600}
        auth := map[string]uint32{"A": 300, "MX": 3600}
        result := EvaluateTTLCompliance(resolver, auth)
        if result.Score != 100 {
                t.Errorf("expected 100 when resolver has only matching entry, got %.1f", result.Score)
        }
}

func TestEvaluateCompleteness_AllExpected(t *testing.T) {
        observed := map[string]bool{}
        for _, rt := range expectedRecordTypes {
                observed[rt] = true
        }
        observed["EXTRA"] = true
        result := EvaluateCompleteness(observed)
        if result.Score != 100 {
                t.Errorf("expected 100 with all expected types, got %.1f", result.Score)
        }
}

func TestEvaluateSourceCredibility_SingleResolver(t *testing.T) {
        agreements := []ResolverAgreement{
                {RecordType: "A", AgreeCount: 1, TotalResolvers: 1, Unanimous: true},
        }
        result := EvaluateSourceCredibility(agreements)
        if result.Score != 100 {
                t.Errorf("expected 100 for 1/1 agreement, got %.1f", result.Score)
        }
}

func TestBuildCurrencyReport_GuidanceMessages(t *testing.T) {
        freshRecords := []RecordCurrency{
                {RecordType: "A", ObservedTTL: 3600, DataAgeS: 100},
        }
        report := BuildCurrencyReport(freshRecords, nil, nil, nil, nil, 1)
        if report.Guidance == "" {
                t.Error("guidance should not be empty")
        }
}

func TestScoreToGrade_Boundaries(t *testing.T) {
        tests := []struct {
                score float64
                want  string
        }{
                {90, GradeExcellent},
                {89.99, GradeGood},
                {75, GradeGood},
                {74.99, GradeAdequate},
                {50, GradeAdequate},
                {49.99, GradeDegraded},
                {25, GradeDegraded},
                {24.99, GradeStale},
                {0, GradeStale},
                {-1, GradeStale},
        }
        for _, tt := range tests {
                got := scoreToGrade(tt.score)
                if got != tt.want {
                        t.Errorf("scoreToGrade(%v) = %q, want %q", tt.score, got, tt.want)
                }
        }
}

func TestTTLFindingSeverityClass_AllSeverities(t *testing.T) {
        tests := []struct {
                severity string
                want     string
        }{
                {"high", "danger"},
                {"medium", "warning"},
                {"low", "info"},
        }
        for _, tt := range tests {
                f := TTLFinding{Severity: tt.severity}
                if got := f.SeverityClass(); got != tt.want {
                        t.Errorf("SeverityClass(%q) = %q, want %q", tt.severity, got, tt.want)
                }
        }
}

func TestFormatTTLDuration_EdgeCases(t *testing.T) {
        tests := []struct {
                ttl  uint32
                want string
        }{
                {0, "0s"},
                {59, "59s"},
                {60, "1 minute (60s)"},
                {120, "2 minutes (120s)"},
                {3599, "3599s"},
                {3600, "1 hour (3600s)"},
                {86399, "86399s"},
                {86400, "1 day (86400s)"},
        }
        for _, tt := range tests {
                got := formatTTLDuration(tt.ttl)
                if got != tt.want {
                        t.Errorf("formatTTLDuration(%d) = %q, want %q", tt.ttl, got, tt.want)
                }
        }
}
