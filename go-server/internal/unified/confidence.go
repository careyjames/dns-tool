// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.

// dns-tool:scrutiny science
package unified

import (
        "fmt"
        "math"
)

const (
        LevelHigh     = "HIGH"
        LevelModerate = "MODERATE"
        LevelLow      = "LOW"

        ThresholdHigh     = 75.0
        ThresholdModerate = 50.0

        mapKeyAccuracy = "accuracy"
        mapKeyCurrency = "currency"
        mapKeyMaturity = "maturity"
)

var maturityCeilings = map[string]float64{
        "development": 60,
        "verified":    75,
        "consistent":  85,
        "gold":        95,
        "gold_master": 100,
}

var levelBootstrapClass = map[string]string{
        LevelHigh:     "success",
        LevelModerate: "warning",
        LevelLow:      "danger",
}

var levelIcons = map[string]string{
        LevelHigh:     "shield-alt",
        LevelModerate: "exclamation-triangle",
        LevelLow:      "times-circle",
}

type UnifiedConfidence struct {
        Level           string  `json:"level"`
        Score           float64 `json:"score"`
        AccuracyFactor  float64 `json:"accuracy_factor"`
        CurrencyFactor  float64 `json:"currency_factor"`
        MaturityCeiling float64 `json:"maturity_ceiling"`
        MaturityLevel   string  `json:"maturity_level"`
        WeakestLink     string  `json:"weakest_link"`
        WeakestDetail   string  `json:"weakest_detail"`
        Explanation     string  `json:"explanation"`
        ProtocolCount   int     `json:"protocol_count"`
}

func (uc UnifiedConfidence) BootstrapClass() string {
        if c, ok := levelBootstrapClass[uc.Level]; ok {
                return c
        }
        return "secondary"
}

func (uc UnifiedConfidence) Icon() string {
        if i, ok := levelIcons[uc.Level]; ok {
                return i
        }
        return "question-circle"
}

func (uc UnifiedConfidence) ScoreDisplay() string {
        return fmt.Sprintf("%.0f", uc.Score)
}

func (uc UnifiedConfidence) AccuracyDisplay() string {
        return fmt.Sprintf("%.0f%%", uc.AccuracyFactor)
}

func (uc UnifiedConfidence) CurrencyDisplay() string {
        return fmt.Sprintf("%.0f", uc.CurrencyFactor)
}

type Input struct {
        CalibratedConfidence map[string]float64
        CurrencyScore        float64
        MaturityLevel        string
}

func ComputeUnifiedConfidence(input Input) UnifiedConfidence {
        accuracyFactor := computeAccuracyFactor(input.CalibratedConfidence)

        currencyFactor := input.CurrencyScore
        if currencyFactor < 0 {
                currencyFactor = 0
        }
        if currencyFactor > 100 {
                currencyFactor = 100
        }

        ceiling := maturityCeiling(input.MaturityLevel)

        rawScore := geometricMean(accuracyFactor, currencyFactor)

        capped := rawScore > ceiling
        score := math.Min(rawScore, ceiling)

        score = math.Round(score*10) / 10

        level := scoreToLevel(score)

        weakest, weakestDetail := identifyWeakestLink(accuracyFactor, currencyFactor, capped)

        explanation := buildExplanation(level, accuracyFactor, currencyFactor, input.MaturityLevel, weakest)

        return UnifiedConfidence{
                Level:           level,
                Score:           score,
                AccuracyFactor:  math.Round(accuracyFactor*10) / 10,
                CurrencyFactor:  math.Round(currencyFactor*10) / 10,
                MaturityCeiling: ceiling,
                MaturityLevel:   input.MaturityLevel,
                WeakestLink:     weakest,
                WeakestDetail:   weakestDetail,
                Explanation:     explanation,
                ProtocolCount:   len(input.CalibratedConfidence),
        }
}

func computeAccuracyFactor(calibrated map[string]float64) float64 {
        if len(calibrated) == 0 {
                return 0
        }
        sum := 0.0
        for _, v := range calibrated {
                sum += v
        }
        mean := sum / float64(len(calibrated))
        return mean * 100
}

func maturityCeiling(level string) float64 {
        if c, ok := maturityCeilings[level]; ok {
                return c
        }
        return 60
}

func geometricMean(a, b float64) float64 {
        if a <= 0 || b <= 0 {
                return 0
        }
        return math.Sqrt(a * b)
}

func scoreToLevel(score float64) string {
        if score >= ThresholdHigh {
                return LevelHigh
        }
        if score >= ThresholdModerate {
                return LevelModerate
        }
        return LevelLow
}

func identifyWeakestLink(accuracy, currency float64, maturityCapped bool) (string, string) {
        if maturityCapped {
                return mapKeyMaturity, "System maturity is capping the confidence score — the scan data is strong but more scan history is needed to unlock higher tiers"
        }
        if accuracy <= currency {
                return mapKeyAccuracy, "Resolver agreement is low for this scan — some protocols returned inconsistent results across resolvers"
        }
        return mapKeyCurrency, "Data currency is degraded — some records may be stale, incomplete, or inconsistent with authoritative sources"
}

func buildExplanation(level string, accuracy, currency float64, maturity, weakest string) string {
        switch level {
        case LevelHigh:
                return "Strong resolver agreement, fresh and complete data, and proven measurement tooling support high confidence in this analysis."
        case LevelModerate:
                switch weakest {
                case mapKeyAccuracy:
                        return "Resolver agreement is inconsistent for some protocols, limiting confidence. Data currency and system maturity are adequate."
                case mapKeyCurrency:
                        return "Some DNS data may be stale or incomplete, limiting confidence. Resolver agreement and system maturity are adequate."
                case mapKeyMaturity:
                        return "The measurement system is still accumulating scan history. Accuracy and currency are adequate but the system has not yet reached full maturity."
                default:
                        return "Confidence is moderate — one or more factors are below the high-confidence threshold."
                }
        default:
                switch weakest {
                case mapKeyAccuracy:
                        return "Significant disagreement between resolvers undermines confidence in the analysis results."
                case mapKeyCurrency:
                        return "DNS data appears stale or substantially incomplete, undermining confidence in the analysis results."
                case mapKeyMaturity:
                        return "The measurement system is in early development with limited scan history."
                default:
                        return "Multiple factors are below the confidence threshold."
                }
        }
}
