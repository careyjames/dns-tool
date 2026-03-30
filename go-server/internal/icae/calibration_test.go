// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package icae

import (
        "encoding/json"
        "fmt"
        "math"
        "strings"
        "testing"
)

func TestBrierScorePerfect(t *testing.T) {
        predictions := []PredictionOutcome{
                {Protocol: "spf", Confidence: 1.0, Outcome: 1.0},
                {Protocol: "spf", Confidence: 0.0, Outcome: 0.0},
                {Protocol: "dkim", Confidence: 1.0, Outcome: 1.0},
        }
        result := ComputeCalibration(predictions, 10)
        if result.BrierScore != 0.0 {
                t.Errorf("perfect predictions: expected Brier=0.0, got %v", result.BrierScore)
        }
}

func TestBrierScoreWorstCase(t *testing.T) {
        predictions := []PredictionOutcome{
                {Protocol: "spf", Confidence: 1.0, Outcome: 0.0},
                {Protocol: "spf", Confidence: 0.0, Outcome: 1.0},
        }
        result := ComputeCalibration(predictions, 10)
        if math.Abs(result.BrierScore-1.0) > 1e-9 {
                t.Errorf("worst-case predictions: expected Brier=1.0, got %v", result.BrierScore)
        }
}

func TestBrierScoreNoSkill(t *testing.T) {
        predictions := []PredictionOutcome{
                {Protocol: "spf", Confidence: 0.5, Outcome: 1.0},
                {Protocol: "spf", Confidence: 0.5, Outcome: 0.0},
        }
        result := ComputeCalibration(predictions, 10)
        if math.Abs(result.BrierScore-0.25) > 1e-9 {
                t.Errorf("no-skill predictions: expected Brier=0.25, got %v", result.BrierScore)
        }
}

func TestECEPerfectCalibration(t *testing.T) {
        var predictions []PredictionOutcome
        for i := 0; i < 100; i++ {
                predictions = append(predictions, PredictionOutcome{
                        Protocol:   "spf",
                        Confidence: 0.95,
                        Outcome:    1.0,
                })
        }
        for i := 0; i < 5; i++ {
                predictions = append(predictions, PredictionOutcome{
                        Protocol:   "spf",
                        Confidence: 0.95,
                        Outcome:    0.0,
                })
        }
        result := ComputeCalibration(predictions, 10)
        if result.ECE > 0.01 {
                t.Errorf("near-perfectly calibrated: expected ECE < 0.01, got %v", result.ECE)
        }
}

func TestCalibrationBinsCount(t *testing.T) {
        predictions := []PredictionOutcome{
                {Protocol: "spf", Confidence: 0.15, Outcome: 1.0},
                {Protocol: "spf", Confidence: 0.85, Outcome: 1.0},
                {Protocol: "dkim", Confidence: 0.95, Outcome: 1.0},
        }
        result := ComputeCalibration(predictions, 10)
        if len(result.Bins) != 10 {
                t.Errorf("expected 10 bins, got %d", len(result.Bins))
        }

        totalInBins := 0
        for _, bin := range result.Bins {
                totalInBins += bin.Count
        }
        if totalInBins != 3 {
                t.Errorf("expected 3 total in bins, got %d", totalInBins)
        }
}

func TestPerProtocolCalibration(t *testing.T) {
        predictions := []PredictionOutcome{
                {Protocol: "spf", Confidence: 0.95, Outcome: 1.0},
                {Protocol: "spf", Confidence: 0.95, Outcome: 1.0},
                {Protocol: "dkim", Confidence: 0.90, Outcome: 0.0},
        }
        result := ComputeCalibration(predictions, 10)

        spf, ok := result.PerProtocol["spf"]
        if !ok {
                t.Fatal("missing SPF in per-protocol results")
        }
        if spf.TotalCases != 2 {
                t.Errorf("SPF: expected 2 cases, got %d", spf.TotalCases)
        }
        if spf.PassRate != 1.0 {
                t.Errorf("SPF: expected pass rate 1.0, got %v", spf.PassRate)
        }

        dkim, ok := result.PerProtocol["dkim"]
        if !ok {
                t.Fatal("missing DKIM in per-protocol results")
        }
        if dkim.TotalCases != 1 {
                t.Errorf("DKIM: expected 1 case, got %d", dkim.TotalCases)
        }
        if dkim.PassRate != 0.0 {
                t.Errorf("DKIM: expected pass rate 0.0, got %v", dkim.PassRate)
        }
}

func TestEmptyPredictions(t *testing.T) {
        result := ComputeCalibration(nil, 10)
        if result.BrierScore != 0 {
                t.Errorf("empty: expected Brier=0, got %v", result.BrierScore)
        }
        if result.TotalPredictions != 0 {
                t.Errorf("empty: expected 0 predictions, got %d", result.TotalPredictions)
        }
}

func TestInterpretations(t *testing.T) {
        tests := []struct {
                score float64
                fn    func(float64) string
                want  string
        }{
                {0.005, interpretBrier, "Excellent"},
                {0.03, interpretBrier, "Good"},
                {0.07, interpretBrier, "Adequate"},
                {0.15, interpretBrier, "Weak"},
                {0.30, interpretBrier, "Poor"},
                {0.01, interpretECE, "Excellent"},
                {0.03, interpretECE, "Good"},
                {0.07, interpretECE, "Adequate"},
                {0.15, interpretECE, "Weak"},
                {0.25, interpretECE, "Poor"},
        }
        for _, tt := range tests {
                got := tt.fn(tt.score)
                if !strings.HasPrefix(got, tt.want) {
                        t.Errorf("interpret(%v) = %q, want prefix %q", tt.score, got, tt.want)
                }
        }
}

func TestMapProtocolToCalibrationKey(t *testing.T) {
        tests := map[string]string{
                "spf":     "SPF",
                "dkim":    "DKIM",
                "dmarc":   "DMARC",
                "dane":    "DANE",
                "dnssec":  "DNSSEC",
                "bimi":    "BIMI",
                "mta_sts": "MTA_STS",
                "tlsrpt":  "TLS_RPT",
                "caa":     "CAA",
                "unknown": "unknown",
        }
        for input, expected := range tests {
                got := mapProtocolToCalibrationKey(input)
                if got != expected {
                        t.Errorf("mapProtocolToCalibrationKey(%q) = %q, want %q", input, got, expected)
                }
        }
}

func TestRunFixtureCalibrationProducesResults(t *testing.T) {
        ce := NewCalibrationEngine()
        result := RunFixtureCalibration(ce)

        if result.TotalPredictions == 0 {
                t.Fatal("expected predictions from fixture cases, got 0")
        }

        t.Logf("Fixture Calibration Results:")
        t.Logf("  Total predictions: %d", result.TotalPredictions)
        t.Logf("  Brier score: %.6f (%s)", result.BrierScore, result.BrierInterpretation)
        t.Logf("  ECE: %.6f (%s)", result.ECE, result.ECEInterpretation)

        if result.BrierScore > 0.25 {
                t.Errorf("Brier score %.4f exceeds no-skill baseline 0.25 — calibration is worse than random", result.BrierScore)
        }

        if result.ECE > 0.20 {
                t.Errorf("ECE %.4f exceeds 0.20 — severe miscalibration", result.ECE)
        }

        for proto, cal := range result.PerProtocol {
                t.Logf("  %s: Brier=%.4f, passRate=%.2f, meanConf=%.4f, gap=%.4f",
                        proto, cal.BrierScore, cal.PassRate, cal.MeanConfidence, cal.CalibrationGap)
        }
}

func TestRunFullCalibrationProducesResults(t *testing.T) {
        ce := NewCalibrationEngine()
        result := RunFullCalibration(ce)

        if result.TotalPredictions == 0 {
                t.Fatal("expected predictions from all cases, got 0")
        }

        t.Logf("Full Calibration Results:")
        t.Logf("  Total predictions: %d", result.TotalPredictions)
        t.Logf("  Brier score: %.6f (%s)", result.BrierScore, result.BrierInterpretation)
        t.Logf("  ECE: %.6f (%s)", result.ECE, result.ECEInterpretation)

        if result.BrierScore > 0.25 {
                t.Errorf("Brier score %.4f exceeds no-skill baseline 0.25", result.BrierScore)
        }

        resultJSON, err := json.MarshalIndent(result, "", "  ")
        if err != nil {
                t.Fatalf("failed to marshal result: %v", err)
        }
        t.Logf("Full calibration JSON:\n%s", string(resultJSON))
}

func TestCalibrationGapPerProtocol(t *testing.T) {
        ce := NewCalibrationEngine()
        result := RunFullCalibration(ce)

        for proto, cal := range result.PerProtocol {
                if cal.CalibrationGap > 0.20 {
                        t.Errorf("protocol %s: calibration gap %.4f > 0.20 (meanConf=%.4f, passRate=%.2f)",
                                proto, cal.CalibrationGap, cal.MeanConfidence, cal.PassRate)
                }
        }
}

func TestDegradedCalibrationStress(t *testing.T) {
        ce := NewCalibrationEngine()
        result := RunDegradedCalibration(ce)

        if result.TotalPredictions == 0 {
                t.Fatal("expected predictions from degraded scenarios, got 0")
        }

        t.Logf("Degraded Calibration (5 resolver scenarios × %d cases):", result.TotalPredictions/5)
        t.Logf("  Total predictions: %d", result.TotalPredictions)
        t.Logf("  Brier score: %.6f (%s)", result.BrierScore, result.BrierInterpretation)
        t.Logf("  ECE: %.6f (%s)", result.ECE, result.ECEInterpretation)

        if result.BrierScore > 0.10 {
                t.Errorf("Degraded Brier score %.4f > 0.10 — calibration degrades too sharply under measurement noise", result.BrierScore)
        }

        if result.ECE > 0.10 {
                t.Errorf("Degraded ECE %.4f > 0.10 — significant miscalibration under measurement noise", result.ECE)
        }

        t.Logf("Reliability Diagram (degraded):")
        t.Logf("%-12s %-12s %-12s %-10s %-10s %-8s", "Bin Start", "Bin End", "Count", "Predicted", "Observed", "Gap")
        for _, bin := range result.Bins {
                if bin.Count > 0 {
                        t.Logf("%-12.2f %-12.2f %-12d %-10.4f %-10.4f %-8.4f",
                                bin.BinStart, bin.BinEnd, bin.Count, bin.MeanPredicted, bin.MeanObserved, bin.Gap)
                }
        }

        for proto, cal := range result.PerProtocol {
                t.Logf("  %s: Brier=%.4f, passRate=%.2f, meanConf=%.4f, gap=%.4f",
                        proto, cal.BrierScore, cal.PassRate, cal.MeanConfidence, cal.CalibrationGap)
        }

        fmt.Println("--- DEGRADED CALIBRATION ARTIFACT ---")
        out, _ := json.MarshalIndent(result, "", "  ")
        fmt.Println(string(out))
        fmt.Println("--- END ARTIFACT ---")
}

func TestReliabilityDiagramData(t *testing.T) {
        ce := NewCalibrationEngine()
        result := RunFullCalibration(ce)

        t.Logf("Reliability Diagram Data (for plotting):")
        t.Logf("%-12s %-12s %-12s %-8s %-8s", "Bin Start", "Bin End", "Count", "Predicted", "Observed")
        for _, bin := range result.Bins {
                if bin.Count > 0 {
                        t.Logf("%-12.2f %-12.2f %-12d %-8.4f %-8.4f",
                                bin.BinStart, bin.BinEnd, bin.Count, bin.MeanPredicted, bin.MeanObserved)
                }
        }

        populatedBins := 0
        for _, bin := range result.Bins {
                if bin.Count > 0 {
                        populatedBins++
                }
        }
        t.Logf("Populated bins: %d/%d", populatedBins, len(result.Bins))

        fmt.Println("--- CALIBRATION VALIDATION ARTIFACT ---")
        out, _ := json.MarshalIndent(result, "", "  ")
        fmt.Println(string(out))
        fmt.Println("--- END ARTIFACT ---")
}
