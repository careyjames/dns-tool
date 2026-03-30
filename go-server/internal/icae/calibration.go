// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
//
// Calibration Validation — empirical accuracy of the confidence scoring system.
//
// Computes Brier score and Expected Calibration Error (ECE) from golden fixture
// test results. These metrics answer: "When we assign X% confidence, are we
// correct approximately X% of the time?"
//
// Brier score: Mean squared error between predicted probability and binary outcome.
//   - Perfect: 0.0 (every prediction was 0 or 1 and correct)
//   - No skill: 0.25 (equivalent to always predicting 0.5)
//   - Worse than random: >0.25
//
// ECE: Mean absolute gap between predicted confidence and observed accuracy,
// weighted by bin population. Measures reliability — how well the system's
// stated confidence matches its actual performance.
//
// Reference: Brier (1950), Naeini et al. (2015) for ECE.
// dns-tool:scrutiny science
package icae

import (
        "fmt"
        "math"
        "sort"
)

type CalibrationResult struct {
        BrierScore          float64                       `json:"brier_score"`
        BrierDisplay        string                        `json:"brier_display"`
        BrierInterpretation string                        `json:"brier_interpretation"`
        BrierRating         string                        `json:"brier_rating"`
        ECE                 float64                       `json:"ece"`
        ECEDisplay          string                        `json:"ece_display"`
        ECEInterpretation   string                        `json:"ece_interpretation"`
        ECERating           string                        `json:"ece_rating"`
        TotalPredictions    int                           `json:"total_predictions"`
        TotalCases          int                           `json:"total_cases"`
        ResolverScenarios   int                           `json:"resolver_scenarios"`
        Bins                []CalibrationBin              `json:"bins"`
        PopulatedBins       []CalibrationBin              `json:"populated_bins"`
        PerProtocol         map[string]ProtocolCalibration `json:"per_protocol"`
        SortedProtocols     []ProtocolCalibration         `json:"sorted_protocols"`
}

type CalibrationBin struct {
        BinStart          float64 `json:"bin_start"`
        BinEnd            float64 `json:"bin_end"`
        BinLabel          string  `json:"bin_label"`
        Count             int     `json:"count"`
        MeanPredicted     float64 `json:"mean_predicted"`
        MeanObserved      float64 `json:"mean_observed"`
        Gap               float64 `json:"gap"`
        GapDisplay        string  `json:"gap_display"`
        PredictedDisplay  string  `json:"predicted_display"`
        ObservedDisplay   string  `json:"observed_display"`
        BarWidthPct       int     `json:"bar_width_pct"`
}

type ProtocolCalibration struct {
        Protocol       string  `json:"protocol"`
        DisplayName    string  `json:"display_name"`
        BrierScore     float64 `json:"brier_score"`
        BrierDisplay   string  `json:"brier_display"`
        TotalCases     int     `json:"total_cases"`
        PassRate       float64 `json:"pass_rate"`
        PassRatePct    string  `json:"pass_rate_pct"`
        MeanConfidence float64 `json:"mean_confidence"`
        MeanConfPct    string  `json:"mean_conf_pct"`
        CalibrationGap float64 `json:"calibration_gap"`
        GapDisplay     string  `json:"gap_display"`
        GapRating      string  `json:"gap_rating"`
}

type PredictionOutcome struct {
        Protocol   string
        Confidence float64
        Outcome    float64
}

func ComputeCalibration(predictions []PredictionOutcome, numBins int) CalibrationResult {
        if len(predictions) == 0 {
                return CalibrationResult{
                        BrierScore:          0,
                        BrierInterpretation: "No predictions to evaluate",
                        ECE:                 0,
                        ECEInterpretation:   "No predictions to evaluate",
                }
        }

        if numBins <= 0 {
                numBins = 10
        }

        brier := computeBrierScore(predictions)
        bins := computeCalibrationBins(predictions, numBins)
        ece := computeECE(bins, len(predictions))
        perProto := computePerProtocolCalibration(predictions)

        var populatedBins []CalibrationBin
        for _, bin := range bins {
                if bin.Count > 0 {
                        populatedBins = append(populatedBins, bin)
                }
        }

        var sortedProtos []ProtocolCalibration
        for _, pc := range perProto {
                sortedProtos = append(sortedProtos, pc)
        }
        sort.Slice(sortedProtos, func(i, j int) bool {
                return sortedProtos[i].CalibrationGap < sortedProtos[j].CalibrationGap
        })

        return CalibrationResult{
                BrierScore:          brier,
                BrierDisplay:        fmt.Sprintf("%.4f", brier),
                BrierInterpretation: interpretBrier(brier),
                BrierRating:         ratingFromBrier(brier),
                ECE:                 ece,
                ECEDisplay:          fmt.Sprintf("%.4f", ece),
                ECEInterpretation:   interpretECE(ece),
                ECERating:           ratingFromECE(ece),
                TotalPredictions:    len(predictions),
                Bins:                bins,
                PopulatedBins:       populatedBins,
                PerProtocol:         perProto,
                SortedProtocols:     sortedProtos,
        }
}

func computeBrierScore(predictions []PredictionOutcome) float64 {
        sumSqErr := 0.0
        for _, p := range predictions {
                diff := p.Confidence - p.Outcome
                sumSqErr += diff * diff
        }
        return sumSqErr / float64(len(predictions))
}

func computeCalibrationBins(predictions []PredictionOutcome, numBins int) []CalibrationBin {
        binWidth := 1.0 / float64(numBins)
        bins := initBinBoundaries(numBins, binWidth)
        accumulatePredictions(bins, predictions, binWidth, numBins)
        maxCount := finalizeBinDisplays(bins)
        applyBarWidths(bins, maxCount)
        return bins
}

func initBinBoundaries(numBins int, binWidth float64) []CalibrationBin {
        bins := make([]CalibrationBin, numBins)
        for i := range bins {
                bins[i].BinStart = float64(i) * binWidth
                bins[i].BinEnd = float64(i+1) * binWidth
        }
        return bins
}

func accumulatePredictions(bins []CalibrationBin, predictions []PredictionOutcome, binWidth float64, numBins int) {
        for _, p := range predictions {
                idx := int(p.Confidence / binWidth)
                if idx >= numBins {
                        idx = numBins - 1
                }
                if idx < 0 {
                        idx = 0
                }
                bins[idx].Count++
                bins[idx].MeanPredicted += p.Confidence
                bins[idx].MeanObserved += p.Outcome
        }
}

const pctDisplayFmt = "%.1f%%"

func finalizeBinDisplays(bins []CalibrationBin) int {
        maxCount := 0
        for i := range bins {
                if bins[i].Count > 0 {
                        bins[i].MeanPredicted /= float64(bins[i].Count)
                        bins[i].MeanObserved /= float64(bins[i].Count)
                        bins[i].Gap = math.Abs(bins[i].MeanPredicted - bins[i].MeanObserved)
                        bins[i].GapDisplay = fmt.Sprintf("%.4f", bins[i].Gap)
                        bins[i].PredictedDisplay = fmt.Sprintf(pctDisplayFmt, bins[i].MeanPredicted*100)
                        bins[i].ObservedDisplay = fmt.Sprintf(pctDisplayFmt, bins[i].MeanObserved*100)
                        if bins[i].Count > maxCount {
                                maxCount = bins[i].Count
                        }
                }
                bins[i].BinLabel = fmt.Sprintf("%.0f–%.0f%%", bins[i].BinStart*100, bins[i].BinEnd*100)
        }
        return maxCount
}

func applyBarWidths(bins []CalibrationBin, maxCount int) {
        for i := range bins {
                if maxCount > 0 && bins[i].Count > 0 {
                        bins[i].BarWidthPct = (bins[i].Count * 100) / maxCount
                }
        }
}

func computeECE(bins []CalibrationBin, totalPredictions int) float64 {
        if totalPredictions == 0 {
                return 0
        }
        ece := 0.0
        for _, bin := range bins {
                if bin.Count > 0 {
                        weight := float64(bin.Count) / float64(totalPredictions)
                        ece += weight * bin.Gap
                }
        }
        return ece
}

func computePerProtocolCalibration(predictions []PredictionOutcome) map[string]ProtocolCalibration {
        grouped := make(map[string][]PredictionOutcome)
        for _, p := range predictions {
                grouped[p.Protocol] = append(grouped[p.Protocol], p)
        }

        result := make(map[string]ProtocolCalibration)
        for proto, preds := range grouped {
                sumConf := 0.0
                sumOutcome := 0.0
                sumSqErr := 0.0
                for _, p := range preds {
                        sumConf += p.Confidence
                        sumOutcome += p.Outcome
                        diff := p.Confidence - p.Outcome
                        sumSqErr += diff * diff
                }
                n := float64(len(preds))
                meanConf := sumConf / n
                meanOutcome := sumOutcome / n
                gap := math.Abs(meanConf - meanOutcome)
                bs := sumSqErr / n

                displayName := proto
                if dn, ok := ProtocolDisplayNames[proto]; ok {
                        displayName = dn
                }

                result[proto] = ProtocolCalibration{
                        Protocol:       proto,
                        DisplayName:    displayName,
                        BrierScore:     bs,
                        BrierDisplay:   fmt.Sprintf("%.4f", bs),
                        TotalCases:     len(preds),
                        PassRate:       meanOutcome,
                        PassRatePct:    fmt.Sprintf("%.0f%%", meanOutcome*100),
                        MeanConfidence: meanConf,
                        MeanConfPct:    fmt.Sprintf(pctDisplayFmt, meanConf*100),
                        CalibrationGap: gap,
                        GapDisplay:     fmt.Sprintf("%.4f", gap),
                        GapRating:      ratingFromGap(gap),
                }
        }
        return result
}

func interpretBrier(score float64) string {
        switch {
        case score < 0.01:
                return "Excellent — near-perfect probabilistic accuracy"
        case score < 0.05:
                return "Good — strong calibration, minor deviations"
        case score < 0.10:
                return "Adequate — reasonable accuracy with room for improvement"
        case score < 0.25:
                return "Weak — systematic over- or under-confidence detected"
        default:
                return "Poor — worse than random baseline (0.25)"
        }
}

func ratingFromBrier(score float64) string {
        switch {
        case score < 0.01:
                return "excellent"
        case score < 0.05:
                return "good"
        case score < 0.10:
                return "adequate"
        case score < 0.25:
                return "weak"
        default:
                return "poor"
        }
}

func ratingFromECE(ece float64) string {
        switch {
        case ece < 0.02:
                return "excellent"
        case ece < 0.05:
                return "good"
        case ece < 0.10:
                return "adequate"
        case ece < 0.20:
                return "weak"
        default:
                return "poor"
        }
}

func ratingFromGap(gap float64) string {
        switch {
        case gap < 0.02:
                return "excellent"
        case gap < 0.05:
                return "good"
        case gap < 0.10:
                return "adequate"
        default:
                return "weak"
        }
}

func interpretECE(ece float64) string {
        switch {
        case ece < 0.02:
                return "Excellent — stated confidence closely matches observed accuracy"
        case ece < 0.05:
                return "Good — minor calibration gap, operationally reliable"
        case ece < 0.10:
                return "Adequate — noticeable gap between confidence and accuracy"
        case ece < 0.20:
                return "Weak — significant miscalibration, confidence scores unreliable"
        default:
                return "Poor — severe miscalibration, confidence scores misleading"
        }
}

func RunFixtureCalibration(ce *CalibrationEngine) CalibrationResult {
        fixtures := FixtureTestCases()

        var predictions []PredictionOutcome
        for _, tc := range fixtures {
                _, passed := tc.RunFn()

                outcome := 0.0
                if passed {
                        outcome = 1.0
                }

                protoKey := mapProtocolToCalibrationKey(tc.Protocol)
                confidence := ce.CalibratedConfidence(protoKey, 1.0, 5, 5)

                predictions = append(predictions, PredictionOutcome{
                        Protocol:   tc.Protocol,
                        Confidence: confidence,
                        Outcome:    outcome,
                })
        }

        return ComputeCalibration(predictions, 10)
}

func RunFullCalibration(ce *CalibrationEngine) CalibrationResult {
        var allCases []TestCase
        allCases = append(allCases, AnalysisTestCases()...)
        allCases = append(allCases, CollectionTestCases()...)

        var predictions []PredictionOutcome
        for _, tc := range allCases {
                _, passed := tc.RunFn()

                outcome := 0.0
                if passed {
                        outcome = 1.0
                }

                protoKey := mapProtocolToCalibrationKey(tc.Protocol)
                confidence := ce.CalibratedConfidence(protoKey, 1.0, 5, 5)

                predictions = append(predictions, PredictionOutcome{
                        Protocol:   tc.Protocol,
                        Confidence: confidence,
                        Outcome:    outcome,
                })
        }

        sort.Slice(predictions, func(i, j int) bool {
                return predictions[i].Confidence < predictions[j].Confidence
        })

        return ComputeCalibration(predictions, 10)
}

func RunDegradedCalibration(ce *CalibrationEngine) CalibrationResult {
        var allCases []TestCase
        allCases = append(allCases, AnalysisTestCases()...)
        allCases = append(allCases, CollectionTestCases()...)

        resolverScenarios := []struct {
                agree int
                total int
        }{
                {5, 5},
                {4, 5},
                {3, 5},
                {2, 5},
                {1, 5},
        }

        var predictions []PredictionOutcome
        for _, tc := range allCases {
                _, passed := tc.RunFn()

                outcome := 0.0
                if passed {
                        outcome = 1.0
                }

                protoKey := mapProtocolToCalibrationKey(tc.Protocol)

                for _, scenario := range resolverScenarios {
                        confidence := ce.CalibratedConfidence(protoKey, 1.0, scenario.agree, scenario.total)

                        predictions = append(predictions, PredictionOutcome{
                                Protocol:   tc.Protocol,
                                Confidence: confidence,
                                Outcome:    outcome,
                        })
                }
        }

        sort.Slice(predictions, func(i, j int) bool {
                return predictions[i].Confidence < predictions[j].Confidence
        })

        result := ComputeCalibration(predictions, 10)
        result.TotalCases = len(allCases)
        result.ResolverScenarios = len(resolverScenarios)
        return result
}

func mapProtocolToCalibrationKey(protocol string) string {
        keyMap := map[string]string{
                "spf":     "SPF",
                "dkim":    "DKIM",
                "dmarc":   "DMARC",
                "dane":    "DANE",
                "dnssec":  "DNSSEC",
                "bimi":    "BIMI",
                "mta_sts": "MTA_STS",
                "tlsrpt":  "TLS_RPT",
                "caa":     "CAA",
        }
        if k, ok := keyMap[protocol]; ok {
                return k
        }
        return protocol
}
