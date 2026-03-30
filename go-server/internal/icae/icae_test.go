// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package icae

import (
	"fmt"
	"testing"
	"time"

	"dnstool/go-server/internal/dbq"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestICAEAnalysisCases(t *testing.T) {
	cases := AnalysisTestCases()
	if len(cases) == 0 {
		t.Fatal("expected analysis test cases, got 0")
	}

	runner := NewRunner("test", "000000", "unit")
	runner.Register(cases...)

	summary := runner.Run()

	t.Logf("ICAE Analysis: %d cases, %d passed, %d failed (%.1f%%)",
		summary.TotalCases, summary.TotalPassed, summary.TotalFailed,
		float64(summary.TotalPassed)/float64(summary.TotalCases)*100)

	for _, r := range summary.Results {
		if !r.Passed {
			t.Errorf("FAIL [%s] %s: expected %q, got %q",
				r.CaseID, r.CaseName, r.Expected, r.Actual)
		}
	}
}

func TestICAECollectionCases(t *testing.T) {
	cases := CollectionTestCases()
	if len(cases) == 0 {
		t.Fatal("expected collection test cases, got 0")
	}

	runner := NewRunner("test", "000000", "unit")
	runner.Register(cases...)

	summary := runner.Run()

	t.Logf("ICAE Collection: %d cases, %d passed, %d failed (%.1f%%)",
		summary.TotalCases, summary.TotalPassed, summary.TotalFailed,
		float64(summary.TotalPassed)/float64(summary.TotalCases)*100)

	for _, r := range summary.Results {
		if !r.Passed {
			t.Errorf("FAIL [%s] %s: expected %q, got %q",
				r.CaseID, r.CaseName, r.Expected, r.Actual)
		}
	}
}

func TestComputeMaturity(t *testing.T) {
	tests := []struct {
		name              string
		consecutivePasses int
		daysSinceFirst    int
		hasFirstPass      bool
		daysSinceRegress  int
		hasRegression     bool
		expected          string
	}{
		{"zero passes", 0, 0, false, 0, false, MaturityDevelopment},
		{"50 passes", 50, 10, true, 0, false, MaturityDevelopment},
		{"100 passes, 5 days", 100, 5, true, 0, false, MaturityVerified},
		{"500 passes, 30 days", 500, 30, true, 0, false, MaturityConsistent},
		{"1000 passes, 90 days", 1000, 90, true, 0, false, MaturityGold},
		{"5000 passes, 180 days", 5000, 180, true, 0, false, MaturityGoldMaster},
		{"1000 passes but recent regression", 1000, 90, true, 10, true, MaturityVerified},
		{"recent regression low passes", 50, 90, true, 10, true, MaturityDevelopment},
		{"nil firstPassAt above threshold", 100, 0, false, 0, false, MaturityVerified},
		{"500 passes, only 15 days", 500, 15, true, 0, false, MaturityVerified},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var fp, lr *time.Time

			if tt.hasFirstPass {
				firstPass := time.Now().Add(-time.Duration(tt.daysSinceFirst) * 24 * time.Hour)
				fp = &firstPass
			}

			if tt.hasRegression {
				regress := time.Now().Add(-time.Duration(tt.daysSinceRegress) * 24 * time.Hour)
				lr = &regress
			}

			got := ComputeMaturity(tt.consecutivePasses, fp, lr)
			if got != tt.expected {
				t.Errorf("ComputeMaturity(%d passes, %d days) = %q, want %q",
					tt.consecutivePasses, tt.daysSinceFirst, got, tt.expected)
			}
		})
	}
}

func makeProto(colLevel string, hasCol bool, analLevel string, hasAnal bool) ProtocolReport {
	pr := ProtocolReport{
		CollectionLevel: colLevel, HasCollection: hasCol,
		AnalysisLevel: analLevel, HasAnalysis: hasAnal,
	}
	pr.HasRuns = hasCol || hasAnal
	pr.EffectiveLevel = CombinedMaturity(analLevel, colLevel)
	pr.EffectiveDisplay = MaturityDisplayNames[pr.EffectiveLevel]
	return pr
}

func TestCombinedMaturity(t *testing.T) {
	tests := []struct {
		name     string
		analysis string
		collect  string
		want     string
	}{
		{"both gold", MaturityGold, MaturityGold, MaturityGold},
		{"analysis higher", MaturityGold, MaturityDevelopment, MaturityDevelopment},
		{"collection higher", MaturityDevelopment, MaturityGold, MaturityDevelopment},
		{"equal verified", MaturityVerified, MaturityVerified, MaturityVerified},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CombinedMaturity(tt.analysis, tt.collect)
			if got != tt.want {
				t.Errorf("CombinedMaturity(%q, %q) = %q, want %q", tt.analysis, tt.collect, got, tt.want)
			}
		})
	}
}

func TestOverallMaturity(t *testing.T) {
	t.Run("both layers present", func(t *testing.T) {
		protocols := []ProtocolReport{
			makeProto(MaturityGold, true, MaturityGold, true),
			makeProto(MaturityGold, true, MaturityVerified, true),
		}
		got := OverallMaturity(protocols)
		if got != MaturityVerified {
			t.Errorf("expected %q, got %q", MaturityVerified, got)
		}
	})

	t.Run("analysis only no collection", func(t *testing.T) {
		protocols := []ProtocolReport{
			makeProto(MaturityDevelopment, false, MaturityVerified, true),
			makeProto(MaturityDevelopment, false, MaturityVerified, true),
		}
		got := OverallMaturity(protocols)
		if got != MaturityDevelopment {
			t.Errorf("expected %q, got %q (effective = min(verified, development) = development)", MaturityDevelopment, got)
		}
	})

	t.Run("no data at all", func(t *testing.T) {
		protocols := []ProtocolReport{
			makeProto(MaturityDevelopment, false, MaturityDevelopment, false),
		}
		got := OverallMaturity(protocols)
		if got != MaturityDevelopment {
			t.Errorf("expected %q, got %q", MaturityDevelopment, got)
		}
	})

	t.Run("mixed layers one protocol has collection", func(t *testing.T) {
		protocols := []ProtocolReport{
			makeProto(MaturityConsistent, true, MaturityGold, true),
			makeProto(MaturityDevelopment, false, MaturityVerified, true),
		}
		got := OverallMaturity(protocols)
		if got != MaturityDevelopment {
			t.Errorf("expected %q, got %q (second protocol effective = min(verified, dev) = dev)", MaturityDevelopment, got)
		}
	})

	t.Run("all layers at same level", func(t *testing.T) {
		protocols := []ProtocolReport{
			makeProto(MaturityVerified, true, MaturityVerified, true),
			makeProto(MaturityVerified, true, MaturityVerified, true),
		}
		got := OverallMaturity(protocols)
		if got != MaturityVerified {
			t.Errorf("expected %q, got %q", MaturityVerified, got)
		}
	})
}

func TestComputeNextTier(t *testing.T) {
	tests := []struct {
		name     string
		level    string
		passes   int
		days     int
		wantName string
		wantMax  bool
		wantPMet bool
		wantDMet bool
	}{
		{"dev to verified", MaturityDevelopment, 50, 0, "Verified", false, false, true},
		{"dev passes met", MaturityDevelopment, 100, 0, "Verified", false, true, true},
		{"verified needs time", MaturityVerified, 510, 1, "Consistent", false, true, false},
		{"verified both met", MaturityVerified, 510, 30, "Consistent", false, true, true},
		{"consistent needs passes", MaturityConsistent, 800, 90, "Gold", false, false, true},
		{"gold master is max", MaturityGoldMaster, 10000, 365, "", true, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, _, _, _, pMet, dMet, atMax := ComputeNextTier(tt.level, tt.passes, tt.days)
			if name != tt.wantName {
				t.Errorf("nextName: got %q, want %q", name, tt.wantName)
			}
			if atMax != tt.wantMax {
				t.Errorf("atMax: got %v, want %v", atMax, tt.wantMax)
			}
			if pMet != tt.wantPMet {
				t.Errorf("passesMet: got %v, want %v", pMet, tt.wantPMet)
			}
			if dMet != tt.wantDMet {
				t.Errorf("daysMet: got %v, want %v", dMet, tt.wantDMet)
			}
		})
	}
}

func TestIsDegraded(t *testing.T) {
	if !IsDegraded(MaturityGold, MaturityVerified) {
		t.Error("Gold -> Verified should be degraded")
	}
	if IsDegraded(MaturityVerified, MaturityGold) {
		t.Error("Verified -> Gold should not be degraded")
	}
}

func TestRunnerBasics(t *testing.T) {
	runner := NewRunner("1.0.0", "abc123", "test")

	runner.Register(TestCase{
		CaseID:   "test-001",
		CaseName: "always pass",
		Protocol: "spf",
		Layer:    LayerAnalysis,
		Expected: "ok",
		RunFn:    func() (string, bool) { return "ok", true },
	}, TestCase{
		CaseID:   "test-002",
		CaseName: "always fail",
		Protocol: "spf",
		Layer:    LayerAnalysis,
		Expected: "ok",
		RunFn:    func() (string, bool) { return "nope", false },
	})

	summary := runner.Run()

	if summary.TotalCases != 2 {
		t.Errorf("expected 2 cases, got %d", summary.TotalCases)
	}
	if summary.TotalPassed != 1 {
		t.Errorf("expected 1 passed, got %d", summary.TotalPassed)
	}
	if summary.TotalFailed != 1 {
		t.Errorf("expected 1 failed, got %d", summary.TotalFailed)
	}
}

func TestRunsToBarPct(t *testing.T) {
	tests := []struct {
		name  string
		runs  int
		check func(int) bool
	}{
		{"zero", 0, func(p int) bool { return p == 0 }},
		{"negative", -5, func(p int) bool { return p == 0 }},
		{"1 run", 1, func(p int) bool { return p >= 1 && p <= 20 }},
		{"50 runs", 50, func(p int) bool { return p >= 1 && p <= 20 }},
		{"99 runs", 99, func(p int) bool { return p >= 1 && p < 20 }},
		{"100 runs (verified threshold)", ThresholdVerified, func(p int) bool { return p == 20 }},
		{"300 runs", 300, func(p int) bool { return p > 20 && p < 40 }},
		{"500 runs (consistent threshold)", ThresholdConsistent, func(p int) bool { return p == 40 }},
		{"750 runs", 750, func(p int) bool { return p > 40 && p < 60 }},
		{"1000 runs (gold threshold)", ThresholdGold, func(p int) bool { return p == 60 }},
		{"3000 runs", 3000, func(p int) bool { return p > 60 && p < 80 }},
		{"5000 runs (gold master threshold)", ThresholdGoldMaster, func(p int) bool { return p == 80 }},
		{"10000 runs", 10000, func(p int) bool { return p > 80 && p <= 100 }},
		{"very large", 100000, func(p int) bool { return p == 100 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runsToBarPct(tt.runs)
			if !tt.check(got) {
				t.Errorf("runsToBarPct(%d) = %d", tt.runs, got)
			}
		})
	}
}

func TestNextTierPct(t *testing.T) {
	tests := []struct {
		name    string
		level   string
		passes  int
		days    int
		wantPct int
	}{
		{"gold master is 100%", MaturityGoldMaster, 10000, 365, 100},
		{"dev at 0 passes", MaturityDevelopment, 0, 0, 0},
		{"dev at 50 passes", MaturityDevelopment, 50, 0, 50},
		{"dev at 100 passes", MaturityDevelopment, 100, 0, 100},
		{"verified at 250 passes 15 days", MaturityVerified, 250, 15, 50},
		{"consistent at 500 passes 45 days", MaturityConsistent, 500, 45, 50},
		{"gold at 2500 passes 90 days", MaturityGold, 2500, 90, 50},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NextTierPct(tt.level, tt.passes, tt.days)
			if got != tt.wantPct {
				t.Errorf("NextTierPct(%q, %d, %d) = %d, want %d", tt.level, tt.passes, tt.days, got, tt.wantPct)
			}
		})
	}
}

func TestNextTierPct_PassesExceedThreshold(t *testing.T) {
	got := NextTierPct(MaturityDevelopment, 200, 0)
	if got != 100 {
		t.Errorf("expected 100 when passes exceed threshold, got %d", got)
	}
}

func TestNextTierPct_DaysExceedThreshold(t *testing.T) {
	got := NextTierPct(MaturityVerified, 600, 60)
	if got != 100 {
		t.Errorf("expected 100 when both exceed threshold, got %d", got)
	}
}

func TestCountCasesByProtocol(t *testing.T) {
	counts := CountCasesByProtocol()
	if len(counts) == 0 {
		t.Fatal("expected non-empty case counts")
	}

	for proto, cc := range counts {
		if cc.Total != cc.Collection+cc.Analysis {
			t.Errorf("protocol %s: Total(%d) != Collection(%d) + Analysis(%d)", proto, cc.Total, cc.Collection, cc.Analysis)
		}
		if cc.Total <= 0 {
			t.Errorf("protocol %s: expected positive total, got %d", proto, cc.Total)
		}
	}
}

func TestCaseCount(t *testing.T) {
	runner := NewRunner("1.0", "abc", "test")
	if runner.CaseCount() != 0 {
		t.Errorf("expected 0 before register, got %d", runner.CaseCount())
	}
	runner.Register(TestCase{CaseID: "t1", RunFn: func() (string, bool) { return "", true }})
	if runner.CaseCount() != 1 {
		t.Errorf("expected 1 after register, got %d", runner.CaseCount())
	}
}

func TestSummarizeByProtocol(t *testing.T) {
	results := []TestResult{
		{Protocol: "spf", Layer: LayerAnalysis, Passed: true},
		{Protocol: "spf", Layer: LayerAnalysis, Passed: false},
		{Protocol: "spf", Layer: LayerCollection, Passed: true},
		{Protocol: "dmarc", Layer: LayerAnalysis, Passed: true},
	}

	summary := SummarizeByProtocol(results)

	spfAnalysis := summary["spf"][LayerAnalysis]
	if spfAnalysis.Total != 2 {
		t.Errorf("spf analysis total = %d, want 2", spfAnalysis.Total)
	}
	if spfAnalysis.Passed != 1 {
		t.Errorf("spf analysis passed = %d, want 1", spfAnalysis.Passed)
	}
	if spfAnalysis.Failed != 1 {
		t.Errorf("spf analysis failed = %d, want 1", spfAnalysis.Failed)
	}

	spfCollection := summary["spf"][LayerCollection]
	if spfCollection.Total != 1 || spfCollection.Passed != 1 {
		t.Errorf("spf collection = %+v", spfCollection)
	}

	dmarcAnalysis := summary["dmarc"][LayerAnalysis]
	if dmarcAnalysis.Total != 1 || dmarcAnalysis.Passed != 1 {
		t.Errorf("dmarc analysis = %+v", dmarcAnalysis)
	}
}

func TestSummarizeByProtocol_Empty(t *testing.T) {
	summary := SummarizeByProtocol(nil)
	if len(summary) != 0 {
		t.Errorf("expected empty summary, got %d", len(summary))
	}
}

func TestFormatPassRate(t *testing.T) {
	tests := []struct {
		passes int
		runs   int
		want   string
	}{
		{0, 0, "0"},
		{0, -1, "0"},
		{100, 100, "100"},
		{50, 100, "50"},
		{1, 3, "33.3"},
		{2, 3, "66.7"},
		{75, 100, "75"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := formatPassRate(tt.passes, tt.runs)
			if got != tt.want {
				t.Errorf("formatPassRate(%d, %d) = %q, want %q", tt.passes, tt.runs, got, tt.want)
			}
		})
	}
}

func TestTimestampToTimePtr(t *testing.T) {
	t.Run("valid timestamp", func(t *testing.T) {
		ts := pgtype.Timestamp{Time: time.Date(2025, 3, 15, 0, 0, 0, 0, time.UTC), Valid: true}
		result := TimestampToTimePtr(ts)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if *result != "2025-03-15" {
			t.Errorf("got %q, want 2025-03-15", *result)
		}
	})

	t.Run("invalid timestamp", func(t *testing.T) {
		ts := pgtype.Timestamp{Valid: false}
		result := TimestampToTimePtr(ts)
		if result != nil {
			t.Errorf("expected nil, got %q", *result)
		}
	})
}

func TestComputeReportAggregates(t *testing.T) {
	protocols := []ProtocolReport{
		{
			HasRuns:          true,
			AnalysisPasses:   50,
			AnalysisRuns:     60,
			CollectionPasses: 30,
			CollectionRuns:   40,
			FirstPassAt:      "2025-01-01",
			DaysElapsed:      10,
		},
		{
			HasRuns:          true,
			AnalysisPasses:   20,
			AnalysisRuns:     25,
			CollectionPasses: 10,
			CollectionRuns:   15,
			FirstPassAt:      "2024-12-01",
			DaysElapsed:      40,
		},
		{
			HasRuns:        false,
			AnalysisPasses: 0,
			AnalysisRuns:   0,
		},
	}

	agg := computeReportAggregates(protocols)

	if agg.evaluatedCount != 2 {
		t.Errorf("evaluatedCount = %d, want 2", agg.evaluatedCount)
	}
	if agg.totalPasses != 70 {
		t.Errorf("totalPasses = %d, want 70", agg.totalPasses)
	}
	if agg.totalRuns != 85 {
		t.Errorf("totalRuns = %d, want 85", agg.totalRuns)
	}
	if agg.collectionPasses != 40 {
		t.Errorf("collectionPasses = %d, want 40", agg.collectionPasses)
	}
	if agg.collectionRuns != 55 {
		t.Errorf("collectionRuns = %d, want 55", agg.collectionRuns)
	}
	if agg.earliestFirstPass != "2024-12-01" {
		t.Errorf("earliestFirstPass = %q, want 2024-12-01", agg.earliestFirstPass)
	}
	if agg.maxDays != 40 {
		t.Errorf("maxDays = %d, want 40", agg.maxDays)
	}
}

func TestComputeReportAggregates_Empty(t *testing.T) {
	agg := computeReportAggregates(nil)
	if agg.evaluatedCount != 0 || agg.totalPasses != 0 || agg.totalRuns != 0 {
		t.Errorf("expected all zeros, got %+v", agg)
	}
}

func TestCollectRegressionEvents(t *testing.T) {
	regTime := time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC)
	rows := []dbq.ICAEGetAllMaturityRow{
		{
			Protocol:          "spf",
			Layer:             LayerAnalysis,
			ConsecutivePasses: 5,
			LastRegressionAt:  pgtype.Timestamp{Time: regTime, Valid: true},
		},
		{
			Protocol:         "dmarc",
			Layer:            LayerAnalysis,
			LastRegressionAt: pgtype.Timestamp{Valid: false},
		},
	}

	regressions := collectRegressionEvents(rows)
	if len(regressions) != 1 {
		t.Fatalf("expected 1 regression, got %d", len(regressions))
	}
	if regressions[0].Protocol != "spf" {
		t.Errorf("protocol = %q", regressions[0].Protocol)
	}
	if regressions[0].RunsSince != 5 {
		t.Errorf("runsSince = %d, want 5", regressions[0].RunsSince)
	}
	if regressions[0].OccurredAt != "2025-02-01" {
		t.Errorf("occurredAt = %q", regressions[0].OccurredAt)
	}
}

func TestCollectRegressionEvents_Empty(t *testing.T) {
	regressions := collectRegressionEvents(nil)
	if len(regressions) != 0 {
		t.Errorf("expected 0, got %d", len(regressions))
	}
}

func TestComputeRunStats(t *testing.T) {
	t.Run("first run all passed", func(t *testing.T) {
		totalRuns, consecutivePasses, firstPassAt, lastRegressionAt := computeRunStats(
			fmt.Errorf("not found"), dbq.ICAEGetMaturityRow{}, true,
		)
		if totalRuns != 1 {
			t.Errorf("totalRuns = %d, want 1", totalRuns)
		}
		if consecutivePasses != 1 {
			t.Errorf("consecutivePasses = %d, want 1", consecutivePasses)
		}
		if !firstPassAt.Valid {
			t.Error("firstPassAt should be valid")
		}
		if lastRegressionAt.Valid {
			t.Error("lastRegressionAt should not be valid")
		}
	})

	t.Run("first run not all passed", func(t *testing.T) {
		totalRuns, consecutivePasses, firstPassAt, lastRegressionAt := computeRunStats(
			fmt.Errorf("not found"), dbq.ICAEGetMaturityRow{}, false,
		)
		if totalRuns != 1 {
			t.Errorf("totalRuns = %d", totalRuns)
		}
		if consecutivePasses != 0 {
			t.Errorf("consecutivePasses = %d", consecutivePasses)
		}
		if firstPassAt.Valid {
			t.Error("firstPassAt should not be valid on failure")
		}
		if !lastRegressionAt.Valid {
			t.Error("lastRegressionAt should be valid on failure")
		}
	})

	t.Run("existing run all passed", func(t *testing.T) {
		existing := dbq.ICAEGetMaturityRow{
			TotalRuns:         10,
			ConsecutivePasses: 5,
			FirstPassAt:       pgtype.Timestamp{Time: time.Now().Add(-48 * time.Hour), Valid: true},
		}
		totalRuns, consecutivePasses, firstPassAt, _ := computeRunStats(nil, existing, true)
		if totalRuns != 11 {
			t.Errorf("totalRuns = %d, want 11", totalRuns)
		}
		if consecutivePasses != 6 {
			t.Errorf("consecutivePasses = %d, want 6", consecutivePasses)
		}
		if !firstPassAt.Valid {
			t.Error("firstPassAt should remain valid")
		}
	})

	t.Run("existing run failed", func(t *testing.T) {
		existing := dbq.ICAEGetMaturityRow{
			TotalRuns:         10,
			ConsecutivePasses: 5,
		}
		totalRuns, consecutivePasses, _, lastRegressionAt := computeRunStats(nil, existing, false)
		if totalRuns != 11 {
			t.Errorf("totalRuns = %d", totalRuns)
		}
		if consecutivePasses != 0 {
			t.Errorf("consecutivePasses should reset to 0, got %d", consecutivePasses)
		}
		if !lastRegressionAt.Valid {
			t.Error("lastRegressionAt should be set on failure")
		}
	})
}

func TestComputeMaturity_NoFirstPass(t *testing.T) {
	got := ComputeMaturity(200, nil, nil)
	if got != MaturityVerified {
		t.Errorf("expected verified with nil firstPassAt, got %q", got)
	}
}

func TestComputeMaturity_RecentRegressionBelowVerified(t *testing.T) {
	fp := time.Now().Add(-100 * 24 * time.Hour)
	lr := time.Now().Add(-5 * 24 * time.Hour)
	got := ComputeMaturity(50, &fp, &lr)
	if got != MaturityDevelopment {
		t.Errorf("expected development with recent regression and low passes, got %q", got)
	}
}

func TestOverallMaturity_UnknownLevel(t *testing.T) {
	protocols := []ProtocolReport{
		{HasRuns: true, EffectiveLevel: "unknown_bogus_level"},
	}
	got := OverallMaturity(protocols)
	if got != MaturityDevelopment {
		t.Errorf("expected development for unknown level, got %q", got)
	}
}

func TestComputeNextTier_GoldToGoldMaster(t *testing.T) {
	name, key, passes, days, _, _, atMax := ComputeNextTier(MaturityGold, 2500, 100)
	if name != "Gold Master" {
		t.Errorf("nextName = %q, want Gold Master", name)
	}
	if key != "gold-master" {
		t.Errorf("nextKey = %q", key)
	}
	if passes != ThresholdGoldMaster {
		t.Errorf("nextPasses = %d", passes)
	}
	if days != GoldMasterDays {
		t.Errorf("nextDays = %d", days)
	}
	if atMax {
		t.Error("should not be at max")
	}
}

func TestRunnerFields(t *testing.T) {
	runner := NewRunner("2.0.0", "def456", "daily")
	runner.Register(TestCase{
		CaseID: "t1", Protocol: "spf", Layer: LayerAnalysis, Expected: "ok",
		RunFn: func() (string, bool) { return "ok", true },
	})
	summary := runner.Run()
	if summary.AppVersion != "2.0.0" {
		t.Errorf("AppVersion = %q", summary.AppVersion)
	}
	if summary.GitCommit != "def456" {
		t.Errorf("GitCommit = %q", summary.GitCommit)
	}
	if summary.RunType != "daily" {
		t.Errorf("RunType = %q", summary.RunType)
	}
	if summary.DurationMs < 0 {
		t.Errorf("DurationMs = %d", summary.DurationMs)
	}
	if summary.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}
	if len(summary.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(summary.Results))
	}
	r := summary.Results[0]
	if r.CaseID != "t1" || r.Actual != "ok" || !r.Passed {
		t.Errorf("result = %+v", r)
	}
}
