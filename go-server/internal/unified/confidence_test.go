package unified

import (
        "math"
        "testing"
)

func approxEqual(a, b, tolerance float64) bool {
        return math.Abs(a-b) <= tolerance
}

func TestComputeUnifiedConfidence_HighConfidence(t *testing.T) {
        input := Input{
                CalibratedConfidence: map[string]float64{
                        "spf": 1.0, "dkim": 1.0, "dmarc": 1.0,
                        "dane": 1.0, "dnssec": 1.0, "caa": 1.0,
                        "mta_sts": 1.0, "tls_rpt": 1.0, "bimi": 1.0,
                },
                CurrencyScore: 92.0,
                MaturityLevel: "gold_master",
        }
        uc := ComputeUnifiedConfidence(input)
        if uc.Level != LevelHigh {
                t.Errorf("expected HIGH, got %s (score=%.1f)", uc.Level, uc.Score)
        }
        if uc.Score < 75 {
                t.Errorf("expected score >= 75, got %.1f", uc.Score)
        }
        if uc.AccuracyFactor != 100 {
                t.Errorf("expected accuracy 100, got %.1f", uc.AccuracyFactor)
        }
        if uc.MaturityCeiling != 100 {
                t.Errorf("expected ceiling 100, got %.0f", uc.MaturityCeiling)
        }
}

func TestComputeUnifiedConfidence_LowAccuracy(t *testing.T) {
        input := Input{
                CalibratedConfidence: map[string]float64{
                        "spf": 0.3, "dkim": 0.0, "dmarc": 0.3,
                        "dane": 0.0, "dnssec": 0.0, "caa": 0.0,
                        "mta_sts": 0.0, "tls_rpt": 0.0, "bimi": 0.0,
                },
                CurrencyScore: 90.0,
                MaturityLevel: "gold_master",
        }
        uc := ComputeUnifiedConfidence(input)
        if uc.Level != LevelLow {
                t.Errorf("expected LOW, got %s (score=%.1f)", uc.Level, uc.Score)
        }
        if uc.WeakestLink != "accuracy" {
                t.Errorf("expected weakest=accuracy, got %s", uc.WeakestLink)
        }
}

func TestComputeUnifiedConfidence_LowCurrency(t *testing.T) {
        input := Input{
                CalibratedConfidence: map[string]float64{
                        "spf": 1.0, "dkim": 1.0, "dmarc": 1.0,
                },
                CurrencyScore: 15.0,
                MaturityLevel: "gold",
        }
        uc := ComputeUnifiedConfidence(input)
        if uc.Level == LevelHigh {
                t.Errorf("should not be HIGH with currency=15")
        }
        if uc.WeakestLink != "currency" {
                t.Errorf("expected weakest=currency, got %s", uc.WeakestLink)
        }
}

func TestComputeUnifiedConfidence_MaturityCeiling(t *testing.T) {
        input := Input{
                CalibratedConfidence: map[string]float64{
                        "spf": 1.0, "dkim": 1.0, "dmarc": 1.0,
                },
                CurrencyScore: 95.0,
                MaturityLevel: "development",
        }
        uc := ComputeUnifiedConfidence(input)
        if uc.Score > 60 {
                t.Errorf("development ceiling should cap score at 60, got %.1f", uc.Score)
        }
        if uc.MaturityCeiling != 60 {
                t.Errorf("expected ceiling=60, got %.0f", uc.MaturityCeiling)
        }
        if uc.WeakestLink != "maturity" {
                t.Errorf("expected weakest=maturity when ceiling caps score, got %s", uc.WeakestLink)
        }
}

func TestComputeUnifiedConfidence_VerifiedCeiling(t *testing.T) {
        input := Input{
                CalibratedConfidence: map[string]float64{"spf": 1.0, "dkim": 1.0},
                CurrencyScore:        90.0,
                MaturityLevel:        "verified",
        }
        uc := ComputeUnifiedConfidence(input)
        if uc.Score > 75 {
                t.Errorf("verified ceiling should cap score at 75, got %.1f", uc.Score)
        }
}

func TestComputeUnifiedConfidence_ConsistentCeiling(t *testing.T) {
        input := Input{
                CalibratedConfidence: map[string]float64{"spf": 1.0, "dkim": 1.0},
                CurrencyScore:        95.0,
                MaturityLevel:        "consistent",
        }
        uc := ComputeUnifiedConfidence(input)
        if uc.Score > 85 {
                t.Errorf("consistent ceiling should cap score at 85, got %.1f", uc.Score)
        }
}

func TestComputeUnifiedConfidence_EmptyCalibration(t *testing.T) {
        input := Input{
                CalibratedConfidence: map[string]float64{},
                CurrencyScore:        80.0,
                MaturityLevel:        "gold",
        }
        uc := ComputeUnifiedConfidence(input)
        if uc.Score != 0 {
                t.Errorf("expected 0 with empty calibration, got %.1f", uc.Score)
        }
        if uc.Level != LevelLow {
                t.Errorf("expected LOW with empty calibration, got %s", uc.Level)
        }
}

func TestComputeUnifiedConfidence_ZeroCurrency(t *testing.T) {
        input := Input{
                CalibratedConfidence: map[string]float64{"spf": 1.0},
                CurrencyScore:        0,
                MaturityLevel:        "gold_master",
        }
        uc := ComputeUnifiedConfidence(input)
        if uc.Score != 0 {
                t.Errorf("expected 0 with zero currency, got %.1f", uc.Score)
        }
}

func TestGeometricMean(t *testing.T) {
        tests := []struct {
                a, b, want float64
        }{
                {100, 100, 100},
                {100, 0, 0},
                {0, 100, 0},
                {80, 80, 80},
                {100, 50, 70.71},
                {36, 81, 54.0},
        }
        for _, tc := range tests {
                got := geometricMean(tc.a, tc.b)
                if !approxEqual(got, tc.want, 0.1) {
                        t.Errorf("geometricMean(%.0f, %.0f) = %.2f, want %.2f", tc.a, tc.b, got, tc.want)
                }
        }
}

func TestScoreToLevel(t *testing.T) {
        tests := []struct {
                score float64
                want  string
        }{
                {95, LevelHigh},
                {75, LevelHigh},
                {74.9, LevelModerate},
                {50, LevelModerate},
                {49.9, LevelLow},
                {0, LevelLow},
        }
        for _, tc := range tests {
                got := scoreToLevel(tc.score)
                if got != tc.want {
                        t.Errorf("scoreToLevel(%.1f) = %s, want %s", tc.score, got, tc.want)
                }
        }
}

func TestMaturityCeiling_UnknownLevel(t *testing.T) {
        if got := maturityCeiling("unknown_tier"); got != 60 {
                t.Errorf("unknown maturity should default to 60, got %.0f", got)
        }
}

func TestBootstrapClass(t *testing.T) {
        tests := []struct {
                level string
                want  string
        }{
                {LevelHigh, "success"},
                {LevelModerate, "warning"},
                {LevelLow, "danger"},
                {"UNKNOWN", "secondary"},
        }
        for _, tc := range tests {
                uc := UnifiedConfidence{Level: tc.level}
                if got := uc.BootstrapClass(); got != tc.want {
                        t.Errorf("BootstrapClass(%s) = %s, want %s", tc.level, got, tc.want)
                }
        }
}

func TestIcon(t *testing.T) {
        uc := UnifiedConfidence{Level: LevelHigh}
        if got := uc.Icon(); got != "shield-alt" {
                t.Errorf("expected shield-alt, got %s", got)
        }
}

func TestDisplayMethods(t *testing.T) {
        uc := UnifiedConfidence{
                Score:          82.3,
                AccuracyFactor: 91.5,
                CurrencyFactor: 74.2,
        }
        if got := uc.ScoreDisplay(); got != "82" {
                t.Errorf("ScoreDisplay = %s, want 82", got)
        }
        if got := uc.AccuracyDisplay(); got != "92%" {
                t.Errorf("AccuracyDisplay = %s, want 92%%", got)
        }
        if got := uc.CurrencyDisplay(); got != "74" {
                t.Errorf("CurrencyDisplay = %s, want 74", got)
        }
}

func TestWeakestLinkIdentification(t *testing.T) {
        tests := []struct {
                name           string
                accuracy       float64
                currency       float64
                maturityCapped bool
                want           string
        }{
                {"accuracy weakest", 30, 80, false, "accuracy"},
                {"currency weakest", 90, 25, false, "currency"},
                {"maturity caps score", 90, 90, true, "maturity"},
                {"equal factors", 80, 80, false, "accuracy"},
                {"maturity takes priority", 30, 25, true, "maturity"},
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        got, _ := identifyWeakestLink(tc.accuracy, tc.currency, tc.maturityCapped)
                        if got != tc.want {
                                t.Errorf("identifyWeakestLink(%.0f,%.0f,%v) = %s, want %s",
                                        tc.accuracy, tc.currency, tc.maturityCapped, got, tc.want)
                        }
                })
        }
}

func TestExplanationContent(t *testing.T) {
        high := ComputeUnifiedConfidence(Input{
                CalibratedConfidence: map[string]float64{"spf": 1.0, "dkim": 1.0, "dmarc": 1.0},
                CurrencyScore:        90,
                MaturityLevel:        "gold_master",
        })
        if high.Explanation == "" {
                t.Error("HIGH explanation should not be empty")
        }

        low := ComputeUnifiedConfidence(Input{
                CalibratedConfidence: map[string]float64{"spf": 0.0},
                CurrencyScore:        10,
                MaturityLevel:        "development",
        })
        if low.Explanation == "" {
                t.Error("LOW explanation should not be empty")
        }
}

func TestProtocolCount(t *testing.T) {
        input := Input{
                CalibratedConfidence: map[string]float64{"spf": 1.0, "dkim": 0.7, "dmarc": 1.0},
                CurrencyScore:        80,
                MaturityLevel:        "gold",
        }
        uc := ComputeUnifiedConfidence(input)
        if uc.ProtocolCount != 3 {
                t.Errorf("expected ProtocolCount=3, got %d", uc.ProtocolCount)
        }
}

func TestNegativeCurrencyClamp(t *testing.T) {
        input := Input{
                CalibratedConfidence: map[string]float64{"spf": 1.0},
                CurrencyScore:        -10,
                MaturityLevel:        "gold",
        }
        uc := ComputeUnifiedConfidence(input)
        if uc.CurrencyFactor != 0 {
                t.Errorf("expected currency clamped to 0, got %.1f", uc.CurrencyFactor)
        }
}

func TestOverflowCurrencyClamp(t *testing.T) {
        input := Input{
                CalibratedConfidence: map[string]float64{"spf": 1.0},
                CurrencyScore:        150,
                MaturityLevel:        "gold",
        }
        uc := ComputeUnifiedConfidence(input)
        if uc.CurrencyFactor != 100 {
                t.Errorf("expected currency clamped to 100, got %.1f", uc.CurrencyFactor)
        }
}

func TestIconUnknownLevel(t *testing.T) {
        uc := UnifiedConfidence{Level: "UNKNOWN"}
        if got := uc.Icon(); got != "question-circle" {
                t.Errorf("unknown level Icon() = %q, want question-circle", got)
        }
}

func TestIconModerateLevel(t *testing.T) {
        uc := UnifiedConfidence{Level: LevelModerate}
        if got := uc.Icon(); got == "fa-question-circle" {
                t.Error("MODERATE should have a specific icon, not the default")
        }
}

func TestIconLowLevel(t *testing.T) {
        uc := UnifiedConfidence{Level: LevelLow}
        if got := uc.Icon(); got == "fa-question-circle" {
                t.Error("LOW should have a specific icon, not the default")
        }
}

func TestBuildExplanation_ModerateAccuracy(t *testing.T) {
        if got := buildExplanation(LevelModerate, 60, 80, "verified", mapKeyAccuracy); got == "" {
                t.Error("expected non-empty explanation for moderate accuracy")
        }
}

func TestBuildExplanation_ModerateCurrency(t *testing.T) {
        got := buildExplanation(LevelModerate, 80, 60, "verified", mapKeyCurrency)
        if got == "" {
                t.Error("expected non-empty explanation for moderate currency")
        }
}

func TestBuildExplanation_ModerateMaturity(t *testing.T) {
        got := buildExplanation(LevelModerate, 80, 80, "verified", mapKeyMaturity)
        if got == "" {
                t.Error("expected non-empty explanation for moderate maturity")
        }
}

func TestBuildExplanation_ModerateDefault(t *testing.T) {
        got := buildExplanation(LevelModerate, 80, 80, "verified", "unknown")
        if got == "" {
                t.Error("expected non-empty explanation for moderate default case")
        }
}

func TestBuildExplanation_LowAccuracy(t *testing.T) {
        got := buildExplanation(LevelLow, 20, 80, "dev", mapKeyAccuracy)
        if got == "" {
                t.Error("expected non-empty explanation for low accuracy")
        }
}

func TestBuildExplanation_LowCurrency(t *testing.T) {
        got := buildExplanation(LevelLow, 80, 20, "dev", mapKeyCurrency)
        if got == "" {
                t.Error("expected non-empty explanation for low currency")
        }
}

func TestBuildExplanation_LowMaturity(t *testing.T) {
        got := buildExplanation(LevelLow, 80, 80, "development", mapKeyMaturity)
        if got == "" {
                t.Error("expected non-empty explanation for low maturity")
        }
}

func TestBuildExplanation_LowDefault(t *testing.T) {
        got := buildExplanation(LevelLow, 20, 20, "dev", "unknown")
        if got == "" {
                t.Error("expected non-empty explanation for low default case")
        }
}

func TestComputeUnifiedConfidence_ModerateLevel(t *testing.T) {
        input := Input{
                CalibratedConfidence: map[string]float64{
                        "spf": 0.7, "dkim": 0.8, "dmarc": 0.6,
                },
                CurrencyScore: 70.0,
                MaturityLevel: "gold_master",
        }
        uc := ComputeUnifiedConfidence(input)
        if uc.Level != LevelModerate {
                t.Errorf("expected MODERATE, got %s (score=%.1f)", uc.Level, uc.Score)
        }
        if uc.Explanation == "" {
                t.Error("explanation should not be empty")
        }
}
