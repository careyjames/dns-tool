package icuae

import (
        "testing"

        "dnstool/go-server/internal/dbq"
)

func TestComputeStability(t *testing.T) {
        tests := []struct {
                stddev    float64
                wantGrade string
                wantLabel string
        }{
                {0.0, "high", "High Stability"},
                {2.5, "high", "High Stability"},
                {4.9, "high", "High Stability"},
                {5.0, "good", "Good Stability"},
                {7.5, "good", "Good Stability"},
                {9.9, "good", "Good Stability"},
                {10.0, "moderate", "Moderate Stability"},
                {15.0, "moderate", "Moderate Stability"},
                {19.9, "moderate", "Moderate Stability"},
                {20.0, "variable", "Variable"},
                {50.0, "variable", "Variable"},
        }
        for _, tt := range tests {
                grade, label := computeStability(tt.stddev)
                if grade != tt.wantGrade {
                        t.Errorf("computeStability(%v) grade = %q, want %q", tt.stddev, grade, tt.wantGrade)
                }
                if label != tt.wantLabel {
                        t.Errorf("computeStability(%v) label = %q, want %q", tt.stddev, label, tt.wantLabel)
                }
        }
}

func TestComputeTrend_Improving(t *testing.T) {
        points := []dbq.ICuAEGetRecentTrendRow{
                {OverallScore: 90},
                {OverallScore: 85},
                {OverallScore: 50},
                {OverallScore: 40},
        }
        dir, arrow := computeTrend(points)
        if dir != "improving" {
                t.Errorf("expected improving, got %q", dir)
        }
        if arrow != "arrow-trend-up" {
                t.Errorf("unexpected arrow %q", arrow)
        }
}

func TestComputeTrend_Declining(t *testing.T) {
        points := []dbq.ICuAEGetRecentTrendRow{
                {OverallScore: 40},
                {OverallScore: 45},
                {OverallScore: 85},
                {OverallScore: 90},
        }
        dir, arrow := computeTrend(points)
        if dir != "declining" {
                t.Errorf("expected declining, got %q", dir)
        }
        if arrow != "arrow-trend-down" {
                t.Errorf("unexpected arrow %q", arrow)
        }
}

func TestComputeTrend_Stable(t *testing.T) {
        points := []dbq.ICuAEGetRecentTrendRow{
                {OverallScore: 80},
                {OverallScore: 81},
                {OverallScore: 79},
                {OverallScore: 80},
        }
        dir, arrow := computeTrend(points)
        if dir != "stable" {
                t.Errorf("expected stable, got %q", dir)
        }
        if arrow != "equals" {
                t.Errorf("unexpected arrow %q", arrow)
        }
}

func TestComputeTrend_Insufficient(t *testing.T) {
        dir, arrow := computeTrend(nil)
        if dir != "insufficient" {
                t.Errorf("expected insufficient for nil, got %q", dir)
        }
        if arrow != "minus" {
                t.Errorf("unexpected arrow %q", arrow)
        }

        dir, arrow = computeTrend([]dbq.ICuAEGetRecentTrendRow{{OverallScore: 50}})
        if dir != "insufficient" {
                t.Errorf("expected insufficient for single point, got %q", dir)
        }
}

func TestAvgScores(t *testing.T) {
        tests := []struct {
                name string
                rows []dbq.ICuAEGetRecentTrendRow
                want float64
        }{
                {"empty", nil, 0},
                {"single", []dbq.ICuAEGetRecentTrendRow{{OverallScore: 80}}, 80},
                {"multiple", []dbq.ICuAEGetRecentTrendRow{
                        {OverallScore: 60},
                        {OverallScore: 80},
                        {OverallScore: 100},
                }, 80},
        }
        for _, tt := range tests {
                got := avgScores(tt.rows)
                if got != tt.want {
                        t.Errorf("avgScores(%s) = %v, want %v", tt.name, got, tt.want)
                }
        }
}

func TestGetTestInventory(t *testing.T) {
        inv := GetTestInventory()
        if inv == nil {
                t.Fatal("GetTestInventory returned nil")
        }

        if inv.TotalDimensions != 5 {
                t.Errorf("expected 5 dimensions, got %d", inv.TotalDimensions)
        }

        if len(inv.Categories) == 0 {
                t.Fatal("expected non-empty categories")
        }

        sum := 0
        for _, c := range inv.Categories {
                sum += c.Cases
                if c.Name == "" {
                        t.Error("category has empty name")
                }
                if c.Standard == "" {
                        t.Error("category has empty standard")
                }
                if c.Cases <= 0 {
                        t.Errorf("category %q has non-positive cases: %d", c.Name, c.Cases)
                }
                if c.Icon == "" {
                        t.Errorf("category %q has empty icon", c.Name)
                }
        }

        if inv.TotalCases != sum {
                t.Errorf("TotalCases (%d) != sum of category cases (%d)", inv.TotalCases, sum)
        }
}

func TestDimensionTuningHint_UnknownDimension(t *testing.T) {
        hint, icon := dimensionTuningHint("unknown_dim", 30.0)
        if hint != "" || icon != "" {
                t.Error("unknown dimension should return empty hint and icon")
        }
}

func TestDimensionTuningHint_SourceCredibility(t *testing.T) {
        hint, icon := dimensionTuningHint(DimensionSourceCredibility, 40.0)
        if hint == "" || icon == "" {
                t.Error("score 40 for source credibility should return a tuning hint")
        }
}

func TestDimensionTuningHint_TTLRelevance(t *testing.T) {
        hint, icon := dimensionTuningHint(DimensionTTLRelevance, 60.0)
        if hint == "" || icon == "" {
                t.Error("score 60 for TTL relevance should return a tuning hint")
        }
}

func TestCurrencyReportMethods(t *testing.T) {
        r := CurrencyReport{OverallGrade: GradeExcellent}
        if r.BootstrapClass() != "success" {
                t.Errorf("expected success, got %q", r.BootstrapClass())
        }
        if r.OverallGradeDisplay() != "Excellent" {
                t.Errorf("expected Excellent, got %q", r.OverallGradeDisplay())
        }

        r2 := CurrencyReport{OverallGrade: "unknown"}
        if r2.BootstrapClass() != "secondary" {
                t.Errorf("unknown grade bootstrap: expected secondary, got %q", r2.BootstrapClass())
        }
        if r2.OverallGradeDisplay() != "Unknown" {
                t.Errorf("unknown grade display: expected Unknown, got %q", r2.OverallGradeDisplay())
        }
}

func TestDimensionScoreMethods(t *testing.T) {
        d := DimensionScore{Dimension: DimensionCurrentness, Grade: GradeGood}
        if d.BootstrapClass() != "success" {
                t.Errorf("expected success, got %q", d.BootstrapClass())
        }
        if d.GradeDisplay() != "Good" {
                t.Errorf("expected Good, got %q", d.GradeDisplay())
        }
        if d.DisplayName() != "Currentness" {
                t.Errorf("expected Currentness, got %q", d.DisplayName())
        }

        d2 := DimensionScore{Dimension: "unknown", Grade: "unknown"}
        if d2.BootstrapClass() != "secondary" {
                t.Errorf("unknown grade: expected secondary, got %q", d2.BootstrapClass())
        }
        if d2.GradeDisplay() != "Unknown" {
                t.Errorf("unknown grade display: expected Unknown, got %q", d2.GradeDisplay())
        }
        if d2.DisplayName() != "unknown" {
                t.Errorf("unknown dimension display: expected 'unknown', got %q", d2.DisplayName())
        }
}

func TestTypicalTTLFor(t *testing.T) {
        if ttl := TypicalTTLFor("A"); ttl != 3600 {
                t.Errorf("A: expected 3600, got %d", ttl)
        }
        if ttl := TypicalTTLFor("NS"); ttl != 86400 {
                t.Errorf("NS: expected 86400, got %d", ttl)
        }
        if ttl := TypicalTTLFor("NONEXISTENT"); ttl != 300 {
                t.Errorf("unknown: expected default 300, got %d", ttl)
        }
}
