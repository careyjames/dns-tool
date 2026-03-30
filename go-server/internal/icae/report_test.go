package icae

import (
	"testing"
	"time"

	"dnstool/go-server/internal/dbq"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestBuildProtocolReport_NoData(t *testing.T) {
	caseCounts := map[string]ProtocolCaseCounts{
		"spf": {Collection: 5, Analysis: 10, Total: 15},
	}
	maturityMap := make(map[string]map[string]dbq.ICAEGetAllMaturityRow)

	pr := buildProtocolReport("spf", caseCounts, maturityMap)

	if pr.Protocol != "spf" {
		t.Errorf("Protocol = %q, want spf", pr.Protocol)
	}
	if pr.DisplayName != "SPF" {
		t.Errorf("DisplayName = %q, want SPF", pr.DisplayName)
	}
	if pr.CollectionCases != 5 {
		t.Errorf("CollectionCases = %d, want 5", pr.CollectionCases)
	}
	if pr.AnalysisCases != 10 {
		t.Errorf("AnalysisCases = %d, want 10", pr.AnalysisCases)
	}
	if pr.TotalCases != 15 {
		t.Errorf("TotalCases = %d, want 15", pr.TotalCases)
	}
	if pr.HasRuns {
		t.Error("HasRuns should be false with no data")
	}
	if pr.CollectionLevel != MaturityDevelopment {
		t.Errorf("CollectionLevel = %q, want development", pr.CollectionLevel)
	}
	if pr.AnalysisLevel != MaturityDevelopment {
		t.Errorf("AnalysisLevel = %q, want development", pr.AnalysisLevel)
	}
	if pr.EffectiveLevel != MaturityDevelopment {
		t.Errorf("EffectiveLevel = %q, want development", pr.EffectiveLevel)
	}
}

func TestBuildProtocolReport_WithCollectionOnly(t *testing.T) {
	caseCounts := map[string]ProtocolCaseCounts{
		"dmarc": {Collection: 3, Analysis: 7, Total: 10},
	}
	firstPass := time.Now().Add(-50 * 24 * time.Hour)
	maturityMap := map[string]map[string]dbq.ICAEGetAllMaturityRow{
		"dmarc": {
			LayerCollection: {
				Protocol:          "dmarc",
				Layer:             LayerCollection,
				Maturity:          MaturityVerified,
				TotalRuns:         150,
				ConsecutivePasses: 120,
				FirstPassAt:       pgtype.Timestamp{Time: firstPass, Valid: true},
				LastEvaluatedAt:   pgtype.Timestamp{Time: time.Now(), Valid: true},
			},
		},
	}

	pr := buildProtocolReport("dmarc", caseCounts, maturityMap)

	if !pr.HasCollection {
		t.Error("HasCollection should be true")
	}
	if pr.HasAnalysis {
		t.Error("HasAnalysis should be false (no analysis data)")
	}
	if pr.HasRuns != true {
		t.Error("HasRuns should be true when collection exists")
	}
	if pr.CollectionLevel != MaturityVerified {
		t.Errorf("CollectionLevel = %q, want verified", pr.CollectionLevel)
	}
	if pr.CollectionRuns != 150 {
		t.Errorf("CollectionRuns = %d, want 150", pr.CollectionRuns)
	}
	if pr.CollectionPasses != 120 {
		t.Errorf("CollectionPasses = %d, want 120", pr.CollectionPasses)
	}
	if pr.CollectionBarPct <= 0 {
		t.Errorf("CollectionBarPct should be positive, got %d", pr.CollectionBarPct)
	}
}

func TestBuildProtocolReport_WithAnalysisOnly(t *testing.T) {
	caseCounts := map[string]ProtocolCaseCounts{
		"spf": {Collection: 5, Analysis: 10, Total: 15},
	}
	firstPass := time.Now().Add(-100 * 24 * time.Hour)
	regress := time.Now().Add(-60 * 24 * time.Hour)
	maturityMap := map[string]map[string]dbq.ICAEGetAllMaturityRow{
		"spf": {
			LayerAnalysis: {
				Protocol:          "spf",
				Layer:             LayerAnalysis,
				Maturity:          MaturityGold,
				TotalRuns:         1200,
				ConsecutivePasses: 1100,
				FirstPassAt:       pgtype.Timestamp{Time: firstPass, Valid: true},
				LastRegressionAt:  pgtype.Timestamp{Time: regress, Valid: true},
				LastEvaluatedAt:   pgtype.Timestamp{Time: time.Now(), Valid: true},
			},
		},
	}

	pr := buildProtocolReport("spf", caseCounts, maturityMap)

	if !pr.HasAnalysis {
		t.Error("HasAnalysis should be true")
	}
	if pr.HasCollection {
		t.Error("HasCollection should be false")
	}
	if pr.AnalysisLevel != MaturityGold {
		t.Errorf("AnalysisLevel = %q, want gold", pr.AnalysisLevel)
	}
	if pr.AnalysisRuns != 1200 {
		t.Errorf("AnalysisRuns = %d, want 1200", pr.AnalysisRuns)
	}
	if pr.LastRegressionAt == "" {
		t.Error("LastRegressionAt should be set")
	}
	if pr.FirstPassAt == "" {
		t.Error("FirstPassAt should be set")
	}
	if pr.LastEvaluatedAt == "" {
		t.Error("LastEvaluatedAt should be set")
	}
	if pr.DaysElapsed < 90 {
		t.Errorf("DaysElapsed should be >= 90, got %d", pr.DaysElapsed)
	}
}

func TestBuildProtocolReport_BothLayers(t *testing.T) {
	caseCounts := map[string]ProtocolCaseCounts{
		"dkim": {Collection: 4, Analysis: 8, Total: 12},
	}
	firstPass := time.Now().Add(-200 * 24 * time.Hour)
	maturityMap := map[string]map[string]dbq.ICAEGetAllMaturityRow{
		"dkim": {
			LayerCollection: {
				Maturity:          MaturityGold,
				TotalRuns:         2000,
				ConsecutivePasses: 1500,
				FirstPassAt:       pgtype.Timestamp{Time: firstPass, Valid: true},
				LastEvaluatedAt:   pgtype.Timestamp{Time: time.Now(), Valid: true},
			},
			LayerAnalysis: {
				Maturity:          MaturityVerified,
				TotalRuns:         200,
				ConsecutivePasses: 150,
				FirstPassAt:       pgtype.Timestamp{Time: firstPass, Valid: true},
				LastEvaluatedAt:   pgtype.Timestamp{Time: time.Now(), Valid: true},
			},
		},
	}

	pr := buildProtocolReport("dkim", caseCounts, maturityMap)

	if !pr.HasCollection || !pr.HasAnalysis {
		t.Error("both layers should be present")
	}
	if pr.EffectiveLevel != MaturityVerified {
		t.Errorf("EffectiveLevel = %q, want verified (min of gold and verified)", pr.EffectiveLevel)
	}
}

func TestBuildProtocolReport_NoCaseCounts(t *testing.T) {
	caseCounts := map[string]ProtocolCaseCounts{}
	maturityMap := make(map[string]map[string]dbq.ICAEGetAllMaturityRow)

	pr := buildProtocolReport("bimi", caseCounts, maturityMap)

	if pr.CollectionCases != 0 {
		t.Errorf("CollectionCases = %d, want 0", pr.CollectionCases)
	}
	if pr.AnalysisCases != 0 {
		t.Errorf("AnalysisCases = %d, want 0", pr.AnalysisCases)
	}
}

func TestPopulateCollectionData_ZeroRuns(t *testing.T) {
	pr := &ProtocolReport{}
	colData := dbq.ICAEGetAllMaturityRow{
		TotalRuns: 0,
	}
	populateCollectionData(pr, colData, true)

	if pr.HasCollection {
		t.Error("HasCollection should be false for 0 runs")
	}
	if pr.CollectionLevel != MaturityDevelopment {
		t.Errorf("CollectionLevel = %q, want development", pr.CollectionLevel)
	}
}

func TestPopulateAnalysisData_ZeroRuns(t *testing.T) {
	pr := &ProtocolReport{}
	analData := dbq.ICAEGetAllMaturityRow{
		TotalRuns: 0,
	}
	populateAnalysisData(pr, analData, true)

	if pr.HasAnalysis {
		t.Error("HasAnalysis should be false for 0 runs")
	}
	if pr.AnalysisLevel != MaturityDevelopment {
		t.Errorf("AnalysisLevel = %q, want development", pr.AnalysisLevel)
	}
}

func TestPopulateCollectionData_NoFirstPass(t *testing.T) {
	pr := &ProtocolReport{}
	colData := dbq.ICAEGetAllMaturityRow{
		Maturity:          MaturityVerified,
		TotalRuns:         100,
		ConsecutivePasses: 80,
		FirstPassAt:       pgtype.Timestamp{Valid: false},
	}
	populateCollectionData(pr, colData, true)

	if pr.ColDaysElapsed != 0 {
		t.Errorf("ColDaysElapsed = %d, want 0 when no first pass", pr.ColDaysElapsed)
	}
}

func TestPopulateAnalysisData_NoFirstPass(t *testing.T) {
	pr := &ProtocolReport{}
	analData := dbq.ICAEGetAllMaturityRow{
		Maturity:          MaturityVerified,
		TotalRuns:         100,
		ConsecutivePasses: 80,
		FirstPassAt:       pgtype.Timestamp{Valid: false},
	}
	populateAnalysisData(pr, analData, true)

	if pr.DaysElapsed != 0 {
		t.Errorf("DaysElapsed = %d, want 0 when no first pass", pr.DaysElapsed)
	}
	if pr.FirstPassAt != "" {
		t.Errorf("FirstPassAt should be empty, got %q", pr.FirstPassAt)
	}
}

func TestCollectRegressionEvents_MultipleProtocols(t *testing.T) {
	regTime1 := time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC)
	regTime2 := time.Date(2025, 2, 20, 0, 0, 0, 0, time.UTC)
	rows := []dbq.ICAEGetAllMaturityRow{
		{
			Protocol:          "spf",
			Layer:             LayerAnalysis,
			ConsecutivePasses: 10,
			LastRegressionAt:  pgtype.Timestamp{Time: regTime1, Valid: true},
		},
		{
			Protocol:          "dmarc",
			Layer:             LayerCollection,
			ConsecutivePasses: 3,
			LastRegressionAt:  pgtype.Timestamp{Time: regTime2, Valid: true},
		},
		{
			Protocol:         "dkim",
			Layer:            LayerAnalysis,
			LastRegressionAt: pgtype.Timestamp{Valid: false},
		},
	}

	regressions := collectRegressionEvents(rows)
	if len(regressions) != 2 {
		t.Fatalf("expected 2 regressions, got %d", len(regressions))
	}
	if regressions[0].Protocol != "spf" || regressions[0].RunsSince != 10 {
		t.Errorf("first regression: %+v", regressions[0])
	}
	if regressions[1].Protocol != "dmarc" || regressions[1].RunsSince != 3 {
		t.Errorf("second regression: %+v", regressions[1])
	}
	if regressions[0].DisplayName != "SPF" {
		t.Errorf("DisplayName = %q, want SPF", regressions[0].DisplayName)
	}
}

func TestFormatPassRate_FractionalPercentage(t *testing.T) {
	tests := []struct {
		passes int
		runs   int
		want   string
	}{
		{0, 0, "0"},
		{100, 100, "100"},
		{1, 3, "33.3"},
		{2, 3, "66.7"},
		{75, 100, "75"},
		{0, 10, "0"},
		{10, 10, "100"},
	}
	for _, tt := range tests {
		got := formatPassRate(tt.passes, tt.runs)
		if got != tt.want {
			t.Errorf("formatPassRate(%d, %d) = %q, want %q", tt.passes, tt.runs, got, tt.want)
		}
	}
}

func TestComputeReportAggregates_SingleProtocol(t *testing.T) {
	protocols := []ProtocolReport{
		{
			HasRuns:          true,
			AnalysisPasses:   100,
			AnalysisRuns:     110,
			CollectionPasses: 50,
			CollectionRuns:   55,
			FirstPassAt:      "2025-03-01",
			DaysElapsed:      30,
		},
	}

	agg := computeReportAggregates(protocols)

	if agg.evaluatedCount != 1 {
		t.Errorf("evaluatedCount = %d, want 1", agg.evaluatedCount)
	}
	if agg.totalPasses != 100 {
		t.Errorf("totalPasses = %d, want 100", agg.totalPasses)
	}
	if agg.totalRuns != 110 {
		t.Errorf("totalRuns = %d, want 110", agg.totalRuns)
	}
	if agg.collectionPasses != 50 {
		t.Errorf("collectionPasses = %d, want 50", agg.collectionPasses)
	}
	if agg.earliestFirstPass != "2025-03-01" {
		t.Errorf("earliestFirstPass = %q, want 2025-03-01", agg.earliestFirstPass)
	}
}

func TestComputeMaturity_GoldMaster(t *testing.T) {
	fp := time.Now().Add(-200 * 24 * time.Hour)
	got := ComputeMaturity(5500, &fp, nil)
	if got != MaturityGoldMaster {
		t.Errorf("expected gold_master, got %q", got)
	}
}

func TestComputeMaturity_GoldExact(t *testing.T) {
	fp := time.Now().Add(-95 * 24 * time.Hour)
	got := ComputeMaturity(1000, &fp, nil)
	if got != MaturityGold {
		t.Errorf("expected gold, got %q", got)
	}
}

func TestComputeMaturity_ConsistentExact(t *testing.T) {
	fp := time.Now().Add(-35 * 24 * time.Hour)
	got := ComputeMaturity(500, &fp, nil)
	if got != MaturityConsistent {
		t.Errorf("expected consistent, got %q", got)
	}
}

func TestComputeMaturity_BelowThreshold(t *testing.T) {
	got := ComputeMaturity(50, nil, nil)
	if got != MaturityDevelopment {
		t.Errorf("expected development, got %q", got)
	}
}

func TestTimestampToTimePtr_Valid(t *testing.T) {
	ts := pgtype.Timestamp{Time: time.Date(2025, 6, 15, 0, 0, 0, 0, time.UTC), Valid: true}
	result := TimestampToTimePtr(ts)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if *result != "2025-06-15" {
		t.Errorf("got %q, want 2025-06-15", *result)
	}
}

func TestTimestampToTimePtr_Invalid(t *testing.T) {
	ts := pgtype.Timestamp{Valid: false}
	result := TimestampToTimePtr(ts)
	if result != nil {
		t.Errorf("expected nil, got %q", *result)
	}
}
