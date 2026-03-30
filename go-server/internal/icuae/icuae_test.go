// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package icuae

import (
        "encoding/json"
        "testing"
)

func TestScoreToGrade(t *testing.T) {
        tests := []struct {
                score float64
                want  string
        }{
                {100, GradeExcellent},
                {95, GradeExcellent},
                {90, GradeExcellent},
                {89.9, GradeGood},
                {75, GradeGood},
                {74.9, GradeAdequate},
                {50, GradeAdequate},
                {49.9, GradeDegraded},
                {25, GradeDegraded},
                {24.9, GradeStale},
                {0, GradeStale},
        }
        for _, tt := range tests {
                got := scoreToGrade(tt.score)
                if got != tt.want {
                        t.Errorf("scoreToGrade(%v) = %q, want %q", tt.score, got, tt.want)
                }
        }
}

func TestEvaluateCurrentness_AllFresh(t *testing.T) {
        records := []RecordCurrency{
                {RecordType: "A", ObservedTTL: 300, DataAgeS: 100},
                {RecordType: "MX", ObservedTTL: 3600, DataAgeS: 1000},
                {RecordType: "TXT", ObservedTTL: 3600, DataAgeS: 500},
        }
        result := EvaluateCurrentness(records)
        if result.Grade != GradeExcellent {
                t.Errorf("all fresh records: expected %q, got %q (score: %.1f)", GradeExcellent, result.Grade, result.Score)
        }
        if result.Score != 100 {
                t.Errorf("all fresh records: expected score 100, got %.1f", result.Score)
        }
        if result.RecordTypes != 3 {
                t.Errorf("expected 3 record types, got %d", result.RecordTypes)
        }
}

func TestEvaluateCurrentness_AllStale(t *testing.T) {
        records := []RecordCurrency{
                {RecordType: "A", ObservedTTL: 300, DataAgeS: 700},
                {RecordType: "MX", ObservedTTL: 3600, DataAgeS: 8000},
        }
        result := EvaluateCurrentness(records)
        if result.Grade != GradeStale {
                t.Errorf("all stale records: expected %q, got %q (score: %.1f)", GradeStale, result.Grade, result.Score)
        }
        if result.Score != 0 {
                t.Errorf("all stale records: expected score 0, got %.1f", result.Score)
        }
}

func TestEvaluateCurrentness_Mixed(t *testing.T) {
        records := []RecordCurrency{
                {RecordType: "A", ObservedTTL: 300, DataAgeS: 100},
                {RecordType: "MX", ObservedTTL: 3600, DataAgeS: 5000},
        }
        result := EvaluateCurrentness(records)
        if result.Score != 75 {
                t.Errorf("mixed: expected score 75 (100+50)/2, got %.1f", result.Score)
        }
        if result.Grade != GradeGood {
                t.Errorf("mixed: expected %q, got %q", GradeGood, result.Grade)
        }
}

func TestEvaluateCurrentness_Empty(t *testing.T) {
        result := EvaluateCurrentness(nil)
        if result.Grade != GradeStale {
                t.Errorf("empty: expected %q, got %q", GradeStale, result.Grade)
        }
        if result.Score != 0 {
                t.Errorf("empty: expected score 0, got %.1f", result.Score)
        }
}

func TestEvaluateCurrentness_ZeroTTLFallback(t *testing.T) {
        records := []RecordCurrency{
                {RecordType: "A", ObservedTTL: 0, TypicalTTL: 300, DataAgeS: 100},
        }
        result := EvaluateCurrentness(records)
        if result.Score != 100 {
                t.Errorf("zero TTL fallback to typical: expected score 100, got %.1f", result.Score)
        }
}

func TestEvaluateCurrentness_BothTTLZeroDefaultsFallback(t *testing.T) {
        records := []RecordCurrency{
                {RecordType: "CUSTOM", ObservedTTL: 0, TypicalTTL: 0, DataAgeS: 100},
        }
        result := EvaluateCurrentness(records)
        if result.Score != 100 {
                t.Errorf("both TTLs zero, default 300, age 100: expected score 100, got %.1f", result.Score)
        }
}

func TestEvaluateTTLCompliance_AllCompliant(t *testing.T) {
        resolver := map[string]uint32{"A": 200, "MX": 3000}
        auth := map[string]uint32{"A": 300, "MX": 3600}
        result := EvaluateTTLCompliance(resolver, auth)
        if result.Score != 100 {
                t.Errorf("all compliant: expected 100, got %.1f", result.Score)
        }
        if result.Grade != GradeExcellent {
                t.Errorf("all compliant: expected %q, got %q", GradeExcellent, result.Grade)
        }
}

func TestEvaluateTTLCompliance_OneViolation(t *testing.T) {
        resolver := map[string]uint32{"A": 500, "MX": 3000}
        auth := map[string]uint32{"A": 300, "MX": 3600}
        result := EvaluateTTLCompliance(resolver, auth)
        if result.Score != 50 {
                t.Errorf("one violation: expected 50, got %.1f", result.Score)
        }
}

func TestEvaluateTTLCompliance_NoAuthData(t *testing.T) {
        resolver := map[string]uint32{"A": 300}
        result := EvaluateTTLCompliance(resolver, map[string]uint32{})
        if result.Grade != GradeAdequate {
                t.Errorf("no auth data: expected %q, got %q", GradeAdequate, result.Grade)
        }
        if result.Score != 50 {
                t.Errorf("no auth data: expected 50, got %.1f", result.Score)
        }
}

func TestEvaluateTTLCompliance_EqualTTL(t *testing.T) {
        resolver := map[string]uint32{"A": 300}
        auth := map[string]uint32{"A": 300}
        result := EvaluateTTLCompliance(resolver, auth)
        if result.Score != 100 {
                t.Errorf("equal TTL should be compliant: expected 100, got %.1f", result.Score)
        }
}

func TestEvaluateCompleteness_AllPresent(t *testing.T) {
        observed := map[string]bool{}
        for _, rt := range expectedRecordTypes {
                observed[rt] = true
        }
        result := EvaluateCompleteness(observed)
        if result.Score != 100 {
                t.Errorf("all present: expected 100, got %.1f", result.Score)
        }
        if result.Grade != GradeExcellent {
                t.Errorf("all present: expected %q, got %q", GradeExcellent, result.Grade)
        }
}

func TestEvaluateCompleteness_NonePresent(t *testing.T) {
        result := EvaluateCompleteness(map[string]bool{})
        if result.Score != 0 {
                t.Errorf("none present: expected 0, got %.1f", result.Score)
        }
        if result.Grade != GradeStale {
                t.Errorf("none present: expected %q, got %q", GradeStale, result.Grade)
        }
}

func TestEvaluateCompleteness_Partial(t *testing.T) {
        observed := map[string]bool{
                "A": true, "AAAA": true, "MX": true, "TXT": true,
                "NS": true, "SOA": true, "SPF": true, "DMARC": true,
        }
        result := EvaluateCompleteness(observed)
        expected := (float64(8) / float64(len(expectedRecordTypes))) * 100
        if result.Score != expected {
                t.Errorf("partial: expected %.1f, got %.1f", expected, result.Score)
        }
}

func TestEvaluateSourceCredibility_AllUnanimous(t *testing.T) {
        agreements := []ResolverAgreement{
                {RecordType: "A", AgreeCount: 5, TotalResolvers: 5, Unanimous: true},
                {RecordType: "MX", AgreeCount: 5, TotalResolvers: 5, Unanimous: true},
        }
        result := EvaluateSourceCredibility(agreements)
        if result.Score != 100 {
                t.Errorf("all unanimous: expected 100, got %.1f", result.Score)
        }
        if result.Grade != GradeExcellent {
                t.Errorf("all unanimous: expected %q, got %q", GradeExcellent, result.Grade)
        }
}

func TestEvaluateSourceCredibility_PartialAgreement(t *testing.T) {
        agreements := []ResolverAgreement{
                {RecordType: "A", AgreeCount: 3, TotalResolvers: 5, Unanimous: false},
        }
        result := EvaluateSourceCredibility(agreements)
        if result.Score != 60 {
                t.Errorf("3/5 agreement: expected 60, got %.1f", result.Score)
        }
}

func TestEvaluateSourceCredibility_Empty(t *testing.T) {
        result := EvaluateSourceCredibility(nil)
        if result.Grade != GradeStale {
                t.Errorf("empty: expected %q, got %q", GradeStale, result.Grade)
        }
}

func TestEvaluateTTLRelevance_AllNormal(t *testing.T) {
        ttls := map[string]uint32{"A": 3600, "MX": 3600, "NS": 86400}
        result := EvaluateTTLRelevance(ttls)
        if result.Score != 100 {
                t.Errorf("all normal: expected 100, got %.1f", result.Score)
        }
}

func TestEvaluateTTLRelevance_SlightlyOff(t *testing.T) {
        ttls := map[string]uint32{"A": 1800}
        result := EvaluateTTLRelevance(ttls)
        if result.Score != 100 {
                t.Errorf("A=1800 (ratio 0.5): expected 100, got %.1f", result.Score)
        }
}

func TestEvaluateTTLRelevance_VeryLow(t *testing.T) {
        ttls := map[string]uint32{"A": 10}
        result := EvaluateTTLRelevance(ttls)
        if result.Score != 0 {
                t.Errorf("A=10 (ratio 0.033, below 0.1 threshold): expected 0, got %.1f", result.Score)
        }
}

func TestEvaluateTTLRelevance_ExtremeMismatch(t *testing.T) {
        ttls := map[string]uint32{"A": 1}
        result := EvaluateTTLRelevance(ttls)
        if result.Score != 0 {
                t.Errorf("A=1 (ratio 0.003): expected 0, got %.1f", result.Score)
        }
}

func TestEvaluateTTLRelevance_Empty(t *testing.T) {
        result := EvaluateTTLRelevance(map[string]uint32{})
        if result.Grade != GradeAdequate {
                t.Errorf("empty: expected %q, got %q", GradeAdequate, result.Grade)
        }
}

func TestBuildCurrencyReport_Integration(t *testing.T) {
        records := []RecordCurrency{
                {RecordType: "A", ObservedTTL: 3600, DataAgeS: 100},
                {RecordType: "MX", ObservedTTL: 3600, DataAgeS: 1000},
        }
        resolver := map[string]uint32{"A": 3600, "MX": 3600}
        auth := map[string]uint32{"A": 3600, "MX": 3600}
        observed := map[string]bool{"A": true, "MX": true}
        agreements := []ResolverAgreement{
                {RecordType: "A", AgreeCount: 5, TotalResolvers: 5, Unanimous: true},
        }

        report := BuildCurrencyReport(records, resolver, auth, observed, agreements, 5)

        if len(report.Dimensions) != 5 {
                t.Fatalf("expected 5 dimensions, got %d", len(report.Dimensions))
        }

        if report.ResolverCount != 5 {
                t.Errorf("expected resolver count 5, got %d", report.ResolverCount)
        }

        if report.RecordCount != 2 {
                t.Errorf("expected record count 2, got %d", report.RecordCount)
        }

        if report.OverallGrade == "" {
                t.Error("overall grade should not be empty")
        }

        if report.OverallScore <= 0 {
                t.Errorf("overall score should be positive, got %.1f", report.OverallScore)
        }

        if report.Guidance == "" {
                t.Error("guidance should not be empty")
        }

        dimNames := map[string]bool{}
        for _, d := range report.Dimensions {
                dimNames[d.Dimension] = true
                if d.Standard == "" {
                        t.Errorf("dimension %q missing standard citation", d.Dimension)
                }
                if d.Grade == "" {
                        t.Errorf("dimension %q missing grade", d.Dimension)
                }
                if d.Details == "" {
                        t.Errorf("dimension %q missing details", d.Dimension)
                }
        }

        expectedDims := []string{
                DimensionCurrentness, DimensionTTLCompliance,
                DimensionCompleteness, DimensionSourceCredibility, DimensionTTLRelevance,
        }
        for _, d := range expectedDims {
                if !dimNames[d] {
                        t.Errorf("missing dimension %q in report", d)
                }
        }
}

func TestBuildCurrencyReport_EmptyInputs(t *testing.T) {
        report := BuildCurrencyReport(nil, nil, nil, nil, nil, 0)

        if len(report.Dimensions) != 5 {
                t.Fatalf("expected 5 dimensions even with nil inputs, got %d", len(report.Dimensions))
        }

        if report.OverallGrade == "" {
                t.Error("grade should not be empty even with nil inputs")
        }

        if report.Guidance == "" {
                t.Error("guidance should not be empty even with nil inputs")
        }
}

func TestGradeConstants(t *testing.T) {
        if len(GradeOrder) != 5 {
                t.Errorf("expected 5 grades, got %d", len(GradeOrder))
        }
        if len(GradeDisplayNames) != 5 {
                t.Errorf("expected 5 grade display names, got %d", len(GradeDisplayNames))
        }
        if len(GradeBootstrapClass) != 5 {
                t.Errorf("expected 5 grade bootstrap classes, got %d", len(GradeBootstrapClass))
        }
}

func TestDimensionConstants(t *testing.T) {
        if len(DimensionDisplayNames) != 5 {
                t.Errorf("expected 5 dimension display names, got %d", len(DimensionDisplayNames))
        }
        if len(DimensionStandards) != 5 {
                t.Errorf("expected 5 dimension standards, got %d", len(DimensionStandards))
        }
}

func TestEvaluateTTLCompliance_NilMaps(t *testing.T) {
        result := EvaluateTTLCompliance(nil, nil)
        if result.Grade != GradeAdequate {
                t.Errorf("nil maps: expected %q, got %q", GradeAdequate, result.Grade)
        }
}

func TestEvaluateCompleteness_NilMap(t *testing.T) {
        result := EvaluateCompleteness(nil)
        if result.Grade != GradeStale {
                t.Errorf("nil map: expected %q, got %q", GradeStale, result.Grade)
        }
}

func TestDimensionTuningHint(t *testing.T) {
        hint, icon := dimensionTuningHint(DimensionCurrentness, 95.0)
        if hint != "" || icon != "" {
                t.Error("score >=90 should return empty hint")
        }

        hint, icon = dimensionTuningHint(DimensionCurrentness, 73.0)
        if hint == "" || icon == "" {
                t.Error("score 73 (adequate) should return a tuning hint")
        }
        if icon != "info-circle text-info" {
                t.Errorf("score 73 expected info icon, got %q", icon)
        }

        hint, icon = dimensionTuningHint(DimensionTTLCompliance, 40.0)
        if hint == "" || icon == "" {
                t.Error("score 40 (degraded) should return a tuning hint")
        }
        if icon != "exclamation-triangle text-warning" {
                t.Errorf("score 40 expected warning icon, got %q", icon)
        }

        hint, icon = dimensionTuningHint(DimensionCompleteness, 85.0)
        if hint == "" || icon == "" {
                t.Error("score 85 (good) should return a tuning hint")
        }
        if icon != "lightbulb text-success" {
                t.Errorf("score 85 expected lightbulb icon, got %q", icon)
        }

        for _, dim := range []string{DimensionCurrentness, DimensionTTLCompliance, DimensionCompleteness, DimensionSourceCredibility, DimensionTTLRelevance} {
                if _, ok := dimensionTuningThresholds[dim]; !ok {
                        t.Errorf("missing tuning thresholds for dimension %q", dim)
                }
        }
}

func TestEvaluateTTLRelevance_UnknownRecordType(t *testing.T) {
        ttls := map[string]uint32{"CUSTOM": 500}
        result := EvaluateTTLRelevance(ttls)
        if result.Grade != GradeAdequate {
                t.Errorf("unknown type: expected %q, got %q", GradeAdequate, result.Grade)
        }
}

func TestEvaluateTTLRelevance_FindingsGenerated(t *testing.T) {
        ttls := map[string]uint32{"MX": 300, "A": 3600, "NS": 86400}
        result := EvaluateTTLRelevance(ttls)
        if len(result.Findings) == 0 {
                t.Fatal("expected findings for MX=300 (typical 3600, ratio 0.083)")
        }
        found := false
        for _, f := range result.Findings {
                if f.RecordType == "MX" {
                        found = true
                        if f.ObservedTTL != 300 {
                                t.Errorf("MX finding ObservedTTL = %d, want 300", f.ObservedTTL)
                        }
                        if f.TypicalTTL != 3600 {
                                t.Errorf("MX finding TypicalTTL = %d, want 3600", f.TypicalTTL)
                        }
                        if f.Severity != "high" {
                                t.Errorf("MX finding severity = %q, want 'high' (ratio < 0.1)", f.Severity)
                        }
                        if f.Standard != "NIST SP 800-53 SI-7" {
                                t.Errorf("MX finding standard = %q, want 'NIST SP 800-53 SI-7'", f.Standard)
                        }
                        if f.Recommendation == "" {
                                t.Error("MX finding recommendation is empty")
                        }
                }
        }
        if !found {
                t.Error("expected MX finding but none found")
        }
}

func TestEvaluateTTLRelevance_NoFindingsWhenCompliant(t *testing.T) {
        ttls := map[string]uint32{"A": 3600, "MX": 3600, "NS": 86400}
        result := EvaluateTTLRelevance(ttls)
        if len(result.Findings) != 0 {
                t.Errorf("expected 0 findings for compliant TTLs, got %d", len(result.Findings))
        }
}

func TestEvaluateTTLRelevance_MediumSeverity(t *testing.T) {
        ttls := map[string]uint32{"MX": 900}
        result := EvaluateTTLRelevance(ttls)
        if len(result.Findings) != 1 {
                t.Fatalf("expected 1 finding for MX=900 (ratio 0.25), got %d", len(result.Findings))
        }
        if result.Findings[0].Severity != "medium" {
                t.Errorf("MX=900 severity = %q, want 'medium' (ratio 0.25 in 0.1-0.5 range)", result.Findings[0].Severity)
        }
}

func TestBuildTTLFinding(t *testing.T) {
        f := buildTTLFinding("MX", 300, 3600, 0.083, "high")
        if f.RecordType != "MX" {
                t.Errorf("RecordType = %q, want 'MX'", f.RecordType)
        }
        if f.SeverityClass() != "danger" {
                t.Errorf("SeverityClass() = %q, want 'danger'", f.SeverityClass())
        }
        if f.ObservedDisplay() == "" {
                t.Error("ObservedDisplay() is empty")
        }
        if f.TypicalDisplay() != "1 hour (3600s)" {
                t.Errorf("TypicalDisplay() = %q, want '1 hour (3600s)'", f.TypicalDisplay())
        }
}

func TestFormatTTLDuration(t *testing.T) {
        tests := []struct {
                ttl  uint32
                want string
        }{
                {86400, "1 day (86400s)"},
                {172800, "2 days (172800s)"},
                {3600, "1 hour (3600s)"},
                {7200, "2 hours (7200s)"},
                {60, "1 minute (60s)"},
                {300, "5 minutes (300s)"},
                {45, "45s"},
                {1, "1s"},
        }
        for _, tt := range tests {
                got := formatTTLDuration(tt.ttl)
                if got != tt.want {
                        t.Errorf("formatTTLDuration(%d) = %q, want %q", tt.ttl, got, tt.want)
                }
        }
}

func TestCurrencyReport_HasFindings(t *testing.T) {
        noFindings := CurrencyReport{
                Dimensions: []DimensionScore{
                        {Dimension: DimensionTTLRelevance, Findings: nil},
                },
        }
        if noFindings.HasFindings() {
                t.Error("expected HasFindings() false when no findings")
        }

        withFindings := CurrencyReport{
                Dimensions: []DimensionScore{
                        {Dimension: DimensionTTLRelevance, Findings: []TTLFinding{
                                {RecordType: "MX", ObservedTTL: 300, TypicalTTL: 3600},
                        }},
                },
        }
        if !withFindings.HasFindings() {
                t.Error("expected HasFindings() true when findings present")
        }
}

func TestCurrencyReport_AllFindings(t *testing.T) {
        report := CurrencyReport{
                Dimensions: []DimensionScore{
                        {Dimension: DimensionCurrentness, Findings: nil},
                        {Dimension: DimensionTTLRelevance, Findings: []TTLFinding{
                                {RecordType: "MX"},
                                {RecordType: "TXT"},
                        }},
                },
        }
        all := report.AllFindings()
        if len(all) != 2 {
                t.Errorf("AllFindings() returned %d, want 2", len(all))
        }
}

func TestHydrateCurrencyReport_Struct(t *testing.T) {
        original := CurrencyReport{
                OverallGrade: GradeGood,
                OverallScore: 78.5,
                Guidance:     "test guidance",
        }
        cr, ok := HydrateCurrencyReport(original)
        if !ok {
                t.Fatal("expected hydration to succeed for struct input")
        }
        if cr.OverallScore != 78.5 {
                t.Errorf("OverallScore = %v, want 78.5", cr.OverallScore)
        }
        if cr.OverallGrade != GradeGood {
                t.Errorf("OverallGrade = %q, want %q", cr.OverallGrade, GradeGood)
        }
}

func TestHydrateCurrencyReport_Map(t *testing.T) {
        original := CurrencyReport{
                OverallGrade:  GradeExcellent,
                OverallScore:  92.3,
                ResolverCount: 4,
                RecordCount:   7,
                Guidance:      "All dimensions excellent",
                Dimensions: []DimensionScore{
                        {Dimension: DimensionCurrentness, Grade: GradeExcellent, Score: 100},
                },
        }
        b, _ := json.Marshal(original)
        var m map[string]interface{}
        json.Unmarshal(b, &m)

        cr, ok := HydrateCurrencyReport(m)
        if !ok {
                t.Fatal("expected hydration to succeed for map input")
        }
        if cr.OverallScore != 92.3 {
                t.Errorf("OverallScore = %v, want 92.3", cr.OverallScore)
        }
        if cr.OverallGrade != GradeExcellent {
                t.Errorf("OverallGrade = %q, want %q", cr.OverallGrade, GradeExcellent)
        }
        if len(cr.Dimensions) != 1 {
                t.Fatalf("Dimensions len = %d, want 1", len(cr.Dimensions))
        }
        if cr.BootstrapClass() != "success" {
                t.Errorf("BootstrapClass() = %q, want 'success'", cr.BootstrapClass())
        }
}

func TestHydrateCurrencyReport_Nil(t *testing.T) {
        _, ok := HydrateCurrencyReport(nil)
        if ok {
                t.Error("expected hydration to fail for nil input")
        }
}

func TestDetectTrafficEngineering_GooglePattern(t *testing.T) {
        ttls := map[string]uint32{
                "A":   28,
                "MX":  148,
                "TXT": 248,
                "SOA": 50,
                "NS":  11697,
                "CAA": 16815,
        }
        te := detectTrafficEngineering(ttls)
        if te == nil {
                t.Fatal("expected traffic engineering detection for Google-like TTLs")
        }
        if !te.Detected {
                t.Error("Detected should be true")
        }
        if te.ShortCount < 3 {
                t.Errorf("ShortCount = %d, want >= 3", te.ShortCount)
        }
        if te.Pattern == "" {
                t.Error("Pattern should not be empty")
        }
}

func TestDetectTrafficEngineering_NormalDomain(t *testing.T) {
        ttls := map[string]uint32{
                "A":   300,
                "MX":  3600,
                "TXT": 3600,
                "SOA": 3600,
                "NS":  86400,
        }
        te := detectTrafficEngineering(ttls)
        if te != nil {
                t.Error("expected no traffic engineering detection for normal TTLs")
        }
}

func TestDetectTrafficEngineering_LowAOnly(t *testing.T) {
        ttls := map[string]uint32{
                "A":   30,
                "MX":  3600,
                "TXT": 3600,
                "SOA": 3600,
        }
        te := detectTrafficEngineering(ttls)
        if te != nil {
                t.Error("expected no detection when only A is low (below threshold of 3 short types)")
        }
}

func TestDetectTrafficEngineering_NoARecord(t *testing.T) {
        ttls := map[string]uint32{
                "MX":  100,
                "TXT": 100,
                "SOA": 50,
        }
        te := detectTrafficEngineering(ttls)
        if te != nil {
                t.Error("expected no detection without an A record")
        }
}

func TestDetectTrafficEngineering_HighARecord(t *testing.T) {
        ttls := map[string]uint32{
                "A":   300,
                "MX":  100,
                "TXT": 100,
                "SOA": 50,
        }
        te := detectTrafficEngineering(ttls)
        if te != nil {
                t.Error("expected no detection when A TTL is above threshold (120s)")
        }
}

func TestBuildCurrencyReport_TrafficEngineering(t *testing.T) {
        input := CurrencyReportInput{
                ResolverTTLs:  map[string]uint32{"A": 28, "MX": 148, "TXT": 248, "SOA": 50},
                AuthTTLs:      map[string]uint32{"A": 300, "MX": 300, "TXT": 300, "SOA": 60},
                ObservedTypes: map[string]bool{"A": true, "MX": true, "TXT": true, "SOA": true},
                ResolverCount: 5,
        }
        report := BuildCurrencyReportWithProvider(input)
        if report.TrafficEngineering == nil {
                t.Fatal("expected TrafficEngineering to be set")
        }
        if !report.TrafficEngineering.Detected {
                t.Error("expected traffic engineering Detected = true")
        }
}

func TestOverallGuidance_AllGrades(t *testing.T) {
        tests := []struct {
                score    float64
                contains string
        }{
                {95, "fresh, consistent"},
                {80, "mostly current"},
                {60, "some aging"},
                {30, "degraded"},
                {10, "stale"},
        }
        for _, tt := range tests {
                g := overallGuidance(tt.score)
                if g == "" {
                        t.Errorf("overallGuidance(%.0f) returned empty string", tt.score)
                }
        }
}

func TestCurrentnessDetails_AllBranches(t *testing.T) {
        tests := []struct {
                score float64
                want  string
        }{
                {95, "All record data is within its TTL validity window"},
                {80, "Most record data is within its TTL validity window"},
                {60, "Some records may have aged beyond their TTL windows"},
                {30, "Multiple records have aged beyond TTL validity — consider re-scanning"},
                {10, "Record data has significantly aged beyond TTL windows — re-scan recommended"},
        }
        for _, tt := range tests {
                got := currentnessDetails(tt.score, 5)
                if got != tt.want {
                        t.Errorf("currentnessDetails(%.0f) = %q, want %q", tt.score, got, tt.want)
                }
        }
}

func TestTTLComplianceDetails_AllBranches(t *testing.T) {
        got := ttlComplianceDetails(5, 5)
        if got != "All resolver TTLs are within authoritative limits (RFC 8767 compliant)" {
                t.Errorf("all compliant: got %q", got)
        }

        got = ttlComplianceDetails(4, 5)
        if got != "1 resolver TTL exceeds its authoritative value — possible serve-stale (RFC 8767), timing skew, or cache misconfiguration" {
                t.Errorf("1 violation: got %q", got)
        }

        got = ttlComplianceDetails(3, 5)
        if got != "2 of 5 resolver TTLs exceed authoritative values — possible serve-stale (RFC 8767), timing skew, or cache misconfiguration" {
                t.Errorf("2 violations: got %q", got)
        }
}

func TestCompletenessDetails_AllBranches(t *testing.T) {
        total := len(expectedRecordTypes)

        got := completenessDetails(total, total)
        if got != "All expected record types have authoritative TTL data" {
                t.Errorf("all present: got %q", got)
        }

        got = completenessDetails(total-1, total)
        if got != "1 expected record type is missing TTL data" {
                t.Errorf("1 missing: got %q", got)
        }

        got = completenessDetails(total-3, total)
        if got == "" {
                t.Error("multiple missing: got empty string")
        }
}

func TestCredibilityDetails_AllBranches(t *testing.T) {
        tests := []struct {
                score float64
                want  string
        }{
                {95, "All resolvers return consistent data — high source credibility"},
                {80, "Most resolvers agree — good source credibility"},
                {60, "Some resolver disagreements detected — moderate credibility"},
                {30, "Significant resolver disagreements — credibility concerns"},
                {10, "Resolvers return conflicting data — investigate DNS propagation"},
        }
        for _, tt := range tests {
                got := credibilityDetails(tt.score)
                if got != tt.want {
                        t.Errorf("credibilityDetails(%.0f) = %q, want %q", tt.score, got, tt.want)
                }
        }
}

func TestTTLRelevanceDetails_AllBranches(t *testing.T) {
        tests := []struct {
                score float64
                want  string
        }{
                {95, "All observed TTLs are within typical ranges for their record types"},
                {80, "Most TTLs are within expected ranges"},
                {60, "Some TTLs deviate from typical ranges — may indicate custom configuration"},
                {30, "Multiple TTLs significantly deviate from standards — review DNS configuration"},
                {10, "TTL values are far outside expected ranges — possible misconfiguration"},
        }
        for _, tt := range tests {
                got := ttlRelevanceDetails(tt.score)
                if got != tt.want {
                        t.Errorf("ttlRelevanceDetails(%.0f) = %q, want %q", tt.score, got, tt.want)
                }
        }
}

func TestTTLRecommendation_AboveTypical(t *testing.T) {
        got := ttlRecommendation("MX", 7200, 3600)
        if got == "" {
                t.Error("expected non-empty recommendation for above-typical TTL")
        }
}

func TestTTLRecommendation_BelowTypical(t *testing.T) {
        got := ttlRecommendation("MX", 300, 3600)
        if got == "" {
                t.Error("expected non-empty recommendation for below-typical TTL")
        }
}

func TestTTLFindingHasProviderNote(t *testing.T) {
        f := TTLFinding{ProviderNote: ""}
        if f.HasProviderNote() {
                t.Error("empty note: expected false")
        }

        f.ProviderNote = "test note"
        if !f.HasProviderNote() {
                t.Error("non-empty note: expected true")
        }
}

func TestTTLFindingSeverityClass_AllBranches(t *testing.T) {
        tests := []struct {
                severity string
                want     string
        }{
                {"high", "danger"},
                {"medium", "warning"},
                {"low", "info"},
                {"", "info"},
        }
        for _, tt := range tests {
                f := TTLFinding{Severity: tt.severity}
                if got := f.SeverityClass(); got != tt.want {
                        t.Errorf("SeverityClass(%q) = %q, want %q", tt.severity, got, tt.want)
                }
        }
}

func TestCurrencyReportHasProviderIntel(t *testing.T) {
        r := CurrencyReport{}
        if r.HasProviderIntel() {
                t.Error("empty report should not have provider intel")
        }

        r.ProviderName = "Cloudflare"
        if !r.HasProviderIntel() {
                t.Error("report with provider should have provider intel")
        }

        r2 := CurrencyReport{
                SOACompliance: &SOAComplianceReport{
                        Findings: []SOAComplianceFinding{{Field: "Expire"}},
                },
        }
        if !r2.HasProviderIntel() {
                t.Error("report with SOA findings should have provider intel")
        }
}

func TestCurrencyReportProviderComplianceNotes(t *testing.T) {
        r := CurrencyReport{ProviderName: ""}
        if r.ProviderComplianceNotes() != nil {
                t.Error("empty provider should return nil notes")
        }

        r2 := CurrencyReport{ProviderName: "nonexistent_provider_xyz"}
        if r2.ProviderComplianceNotes() != nil {
                t.Error("unknown provider should return nil notes")
        }

        r3 := CurrencyReport{ProviderName: "Cloudflare"}
        notes := r3.ProviderComplianceNotes()
        if len(notes) == 0 {
                t.Error("Cloudflare should have compliance notes")
        }
}

func TestCurrencyReportHasProviderComplianceNotes(t *testing.T) {
        r := CurrencyReport{ProviderName: "Cloudflare"}
        if !r.HasProviderComplianceNotes() {
                t.Error("Cloudflare report should have compliance notes")
        }

        r2 := CurrencyReport{}
        if r2.HasProviderComplianceNotes() {
                t.Error("empty report should not have compliance notes")
        }
}

func TestEvaluateTTLCompliance_NoOverlap(t *testing.T) {
        resolver := map[string]uint32{"A": 300}
        auth := map[string]uint32{"MX": 3600}
        result := EvaluateTTLCompliance(resolver, auth)
        if result.Grade != GradeAdequate {
                t.Errorf("no overlap: expected %q, got %q", GradeAdequate, result.Grade)
        }
}

func TestEvaluateSourceCredibility_ZeroTotalResolvers(t *testing.T) {
        agreements := []ResolverAgreement{
                {RecordType: "A", AgreeCount: 0, TotalResolvers: 0, Unanimous: false},
        }
        result := EvaluateSourceCredibility(agreements)
        if result.Score != 0 {
                t.Errorf("zero resolvers: expected 0, got %.1f", result.Score)
        }
}

func TestBuildCurrencyReportWithProvider_SOA(t *testing.T) {
        input := CurrencyReportInput{
                Records:       []RecordCurrency{{RecordType: "A", ObservedTTL: 3600, DataAgeS: 100}},
                ResolverTTLs:  map[string]uint32{"A": 3600},
                AuthTTLs:      map[string]uint32{"A": 3600},
                ObservedTypes: map[string]bool{"A": true},
                Agreements:    []ResolverAgreement{{RecordType: "A", AgreeCount: 5, TotalResolvers: 5, Unanimous: true}},
                ResolverCount: 5,
                SOARaw:        "ns1.example.com. admin.example.com. 2025010101 3600 900 1209600 86400",
        }
        report := BuildCurrencyReportWithProvider(input)
        if report.SOACompliance == nil {
                t.Fatal("expected SOACompliance to be populated")
        }
        if !report.SOACompliance.HasSOA {
                t.Error("expected HasSOA = true")
        }
}

func TestBuildCurrencyReportWithProvider_WithDNSProvider(t *testing.T) {
        input := CurrencyReportInput{
                Records:       []RecordCurrency{{RecordType: "A", ObservedTTL: 60, DataAgeS: 10}},
                ResolverTTLs:  map[string]uint32{"A": 60},
                AuthTTLs:      map[string]uint32{"A": 300},
                ObservedTypes: map[string]bool{"A": true},
                DNSProviders:  []string{"cloudflare"},
                NSRecords:     []string{"ns1.cloudflare.com"},
                ResolverCount: 3,
        }
        report := BuildCurrencyReportWithProvider(input)
        if report.ProviderName == "" {
                t.Error("expected provider detection for cloudflare")
        }
}

func TestAnalyzeSOACompliance_ShortSOA(t *testing.T) {
        report := AnalyzeSOACompliance("ns1.example.com. admin", "")
        if report.HasSOA {
                t.Error("short SOA string should not parse")
        }
}

func TestAnalyzeSOACompliance_LowExpire(t *testing.T) {
        report := AnalyzeSOACompliance("ns1.example.com. admin.example.com. 2025010101 3600 900 604000 300", "")
        if !report.HasSOA {
                t.Fatal("expected HasSOA = true")
        }
        if len(report.Findings) == 0 {
                t.Error("expected findings for low expire value")
        }
}

func TestAnalyzeSOACompliance_LowRefresh(t *testing.T) {
        report := AnalyzeSOACompliance("ns1.example.com. admin.example.com. 2025010101 600 900 1209600 300", "")
        found := false
        for _, f := range report.Findings {
                if f.Field == "Refresh" {
                        found = true
                }
        }
        if !found {
                t.Error("expected a Refresh finding for value < 1200")
        }
}

func TestAnalyzeSOACompliance_ExpireVsRefreshRetry(t *testing.T) {
        report := AnalyzeSOACompliance("ns1.example.com. admin.example.com. 2025010101 3600 900 4500 300", "")
        found := false
        for _, f := range report.Findings {
                if f.Field == "Expire vs Refresh+Retry" {
                        found = true
                }
        }
        if !found {
                t.Error("expected Expire vs Refresh+Retry finding when expire <= refresh + retry")
        }
}

func TestAnalyzeSOACompliance_HighMinTTL(t *testing.T) {
        report := AnalyzeSOACompliance("ns1.example.com. admin.example.com. 2025010101 3600 900 1209600 100000", "")
        found := false
        for _, f := range report.Findings {
                if f.Field == "Minimum (Negative Cache TTL)" {
                        found = true
                }
        }
        if !found {
                t.Error("expected finding for min TTL > 86400")
        }
}

func TestSOAComplianceFindingSeverityClass(t *testing.T) {
        tests := []struct {
                severity string
                want     string
        }{
                {"warning", "warning"},
                {"info", "info"},
                {"error", "danger"},
                {"", "danger"},
        }
        for _, tt := range tests {
                f := SOAComplianceFinding{Severity: tt.severity}
                if got := f.SeverityClass(); got != tt.want {
                        t.Errorf("SeverityClass(%q) = %q, want %q", tt.severity, got, tt.want)
                }
        }
}

func TestAnnotateFindingForProvider_CloudflareSOA(t *testing.T) {
        f := &TTLFinding{RecordType: "SOA", ObservedTTL: 300}
        AnnotateFindingForProvider(f, "Cloudflare")
        if f.ProviderNote == "" {
                t.Error("expected provider note for Cloudflare SOA")
        }
}

func TestAnnotateFindingForProvider_CloudflareProxiedA(t *testing.T) {
        f := &TTLFinding{RecordType: "A", ObservedTTL: 300}
        AnnotateFindingForProvider(f, "Cloudflare")
        if f.ProviderNote == "" {
                t.Error("expected provider note for Cloudflare proxied A record with TTL 300")
        }
}

func TestAnnotateFindingForProvider_DefaultMinAllowed(t *testing.T) {
        f := &TTLFinding{RecordType: "TXT", ObservedTTL: 300, TypicalTTL: 10}
        AnnotateFindingForProvider(f, "Cloudflare")
        if f.ProviderNote == "" {
                t.Error("expected min TTL note for Cloudflare when typical < min allowed")
        }
}

func TestHydrateCurrencyReport_InvalidJSON(t *testing.T) {
        _, ok := HydrateCurrencyReport("not a valid json object at all")
        if ok {
                t.Error("expected hydration to fail for invalid input")
        }
}

func TestCurrencyReportOverallGradeDisplay(t *testing.T) {
        r := CurrencyReport{OverallGrade: GradeExcellent}
        if r.OverallGradeDisplay() == "" || r.OverallGradeDisplay() == "Unknown" {
                t.Errorf("expected display name for Excellent, got %q", r.OverallGradeDisplay())
        }

        r2 := CurrencyReport{OverallGrade: "nonexistent"}
        if r2.OverallGradeDisplay() != "Unknown" {
                t.Errorf("expected Unknown for bad grade, got %q", r2.OverallGradeDisplay())
        }
}

func TestDimensionScoreDisplayName(t *testing.T) {
        d := DimensionScore{Dimension: DimensionCurrentness}
        if d.DisplayName() == "" || d.DisplayName() == DimensionCurrentness {
                t.Errorf("expected human-readable display name, got %q", d.DisplayName())
        }

        d2 := DimensionScore{Dimension: "unknown_dim"}
        if d2.DisplayName() != "unknown_dim" {
                t.Errorf("unknown dimension should return raw name, got %q", d2.DisplayName())
        }
}

func TestDimensionScoreGradeDisplay(t *testing.T) {
        d := DimensionScore{Grade: GradeGood}
        if d.GradeDisplay() == "Unknown" {
                t.Error("expected valid grade display for Good")
        }

        d2 := DimensionScore{Grade: "bad_grade"}
        if d2.GradeDisplay() != "Unknown" {
                t.Errorf("expected Unknown for bad grade, got %q", d2.GradeDisplay())
        }
}

func TestDimensionScoreBootstrapClass_Unknown(t *testing.T) {
        d := DimensionScore{Grade: "bad_grade"}
        if d.BootstrapClass() != "secondary" {
                t.Errorf("expected secondary for unknown grade, got %q", d.BootstrapClass())
        }
}

func TestCurrencyReportBootstrapClass_Unknown(t *testing.T) {
        r := CurrencyReport{OverallGrade: "bad_grade"}
        if r.BootstrapClass() != "secondary" {
                t.Errorf("expected secondary for unknown grade, got %q", r.BootstrapClass())
        }
}

func TestTypicalTTLFor_Known(t *testing.T) {
        got := TypicalTTLFor("A")
        if got != 3600 {
                t.Errorf("TypicalTTLFor(A) = %d, want 3600", got)
        }
}

func TestTypicalTTLFor_Unknown(t *testing.T) {
        got := TypicalTTLFor("UNKNOWN_TYPE")
        if got != 300 {
                t.Errorf("TypicalTTLFor(UNKNOWN_TYPE) = %d, want 300", got)
        }
}

func TestRecordTypesList_WithFindings(t *testing.T) {
        d := DimensionScore{
                RecordTypes: 3,
                Findings: []TTLFinding{
                        {RecordType: "A"},
                        {RecordType: "MX"},
                        {RecordType: ""},
                        {RecordType: "TXT"},
                },
        }
        types := d.RecordTypesList()
        if len(types) != 3 {
                t.Errorf("expected 3 record types (empty excluded), got %d: %v", len(types), types)
        }
}

func TestRecordTypesList_NoFindings(t *testing.T) {
        d := DimensionScore{RecordTypes: 0}
        types := d.RecordTypesList()
        if len(types) != 0 {
                t.Errorf("expected 0 record types, got %d", len(types))
        }
}

func TestRecordTypesList_AllEmpty(t *testing.T) {
        d := DimensionScore{
                RecordTypes: 2,
                Findings: []TTLFinding{
                        {RecordType: ""},
                        {RecordType: ""},
                },
        }
        types := d.RecordTypesList()
        if len(types) != 0 {
                t.Errorf("expected 0 record types (all empty), got %d", len(types))
        }
}

func TestSOAComplianceReport_HasFindings(t *testing.T) {
        r := SOAComplianceReport{}
        if r.HasFindings() {
                t.Error("empty findings should return false")
        }

        r.Findings = []SOAComplianceFinding{{Field: "test"}}
        if !r.HasFindings() {
                t.Error("non-empty findings should return true")
        }
}
