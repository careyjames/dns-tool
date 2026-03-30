// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package icae

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"dnstool/go-server/internal/dbq"

	"github.com/jackc/pgx/v5/pgtype"
)

type MaturityQuerier interface {
	ICAEGetAllMaturity(ctx context.Context) ([]dbq.ICAEGetAllMaturityRow, error)
}

func LoadReportMetrics(ctx context.Context, queries MaturityQuerier) *ReportMetrics {
	rows, err := queries.ICAEGetAllMaturity(ctx)
	if err != nil {
		slog.Warn("ICAE: failed to load maturity data", "error", err)
		return nil
	}

	maturityMap := make(map[string]map[string]dbq.ICAEGetAllMaturityRow)
	for _, row := range rows {
		if maturityMap[row.Protocol] == nil {
			maturityMap[row.Protocol] = make(map[string]dbq.ICAEGetAllMaturityRow)
		}
		maturityMap[row.Protocol][row.Layer] = row
	}

	caseCounts := CountCasesByProtocol()

	var protocols []ProtocolReport
	for _, proto := range Protocols {
		pr := buildProtocolReport(proto, caseCounts, maturityMap)
		protocols = append(protocols, pr)
	}

	agg := computeReportAggregates(protocols)
	regressions := collectRegressionEvents(rows)

	passRate := formatPassRate(agg.totalPasses, agg.totalRuns)

	overall := OverallMaturity(protocols)

	byKey := make(map[string]ProtocolReport, len(protocols))
	for _, p := range protocols {
		byKey[p.Protocol] = p
	}

	totalCollectionCases := len(CollectionTestCases())
	totalAnalysisCases := len(AnalysisTestCases())

	metrics := &ReportMetrics{
		Protocols:              protocols,
		ByKey:                  byKey,
		TotalProtocols:         len(protocols),
		EvaluatedCount:         agg.evaluatedCount,
		OverallMaturity:        overall,
		OverallMaturityDisplay: MaturityDisplayNames[overall],
		TotalPasses:            agg.totalPasses,
		TotalRuns:              agg.totalRuns,
		CollectionPasses:       agg.collectionPasses,
		CollectionRuns:         agg.collectionRuns,
		PassRate:               passRate,
		FirstPassAt:            agg.earliestFirstPass,
		DaysRunning:            agg.maxDays,
		Regressions:            regressions,
		TotalCollectionCases:   totalCollectionCases,
		TotalAnalysisCases:     totalAnalysisCases,
		TotalAllCases:          totalCollectionCases + totalAnalysisCases,
	}

	return metrics
}

func TimestampToTimePtr(ts pgtype.Timestamp) *string {
	if !ts.Valid {
		return nil
	}
	s := ts.Time.Format("2006-01-02")
	return &s
}

func buildProtocolReport(proto string, caseCounts map[string]ProtocolCaseCounts, maturityMap map[string]map[string]dbq.ICAEGetAllMaturityRow) ProtocolReport {
	pr := ProtocolReport{
		Protocol:    proto,
		DisplayName: ProtocolDisplayNames[proto],
	}

	if cc, ok := caseCounts[proto]; ok {
		pr.CollectionCases = cc.Collection
		pr.AnalysisCases = cc.Analysis
		pr.TotalCases = cc.Total
	}

	colData, hasCol := maturityMap[proto][LayerCollection]
	analData, hasAnal := maturityMap[proto][LayerAnalysis]

	populateCollectionData(&pr, colData, hasCol)
	populateAnalysisData(&pr, analData, hasAnal)

	pr.HasRuns = pr.HasCollection || pr.HasAnalysis
	pr.EffectiveLevel = CombinedMaturity(pr.AnalysisLevel, pr.CollectionLevel)
	pr.EffectiveDisplay = MaturityDisplayNames[pr.EffectiveLevel]

	return pr
}

func populateCollectionData(pr *ProtocolReport, colData dbq.ICAEGetAllMaturityRow, hasCol bool) {
	if hasCol && colData.TotalRuns > 0 {
		pr.HasCollection = true
		pr.CollectionLevel = colData.Maturity
		pr.CollectionDisplay = MaturityDisplayNames[colData.Maturity]
		pr.CollectionRuns = int(colData.TotalRuns)
		pr.CollectionPasses = int(colData.ConsecutivePasses)
		pr.CollectionBarPct = runsToBarPct(int(colData.ConsecutivePasses))

		colDaysElapsed := 0
		if colData.FirstPassAt.Valid {
			colDaysElapsed = int(time.Since(colData.FirstPassAt.Time).Hours() / 24)
		}
		pr.ColDaysElapsed = colDaysElapsed
		pr.ColNextTierName, pr.ColNextTierKey, pr.ColNextTierPasses, pr.ColNextTierDays, pr.ColPassesMet, pr.ColDaysMet, pr.ColAtMaxTier = ComputeNextTier(colData.Maturity, int(colData.ConsecutivePasses), colDaysElapsed)
		pr.ColNextTierPct = NextTierPct(colData.Maturity, int(colData.ConsecutivePasses), colDaysElapsed)
	} else {
		pr.CollectionLevel = MaturityDevelopment
		pr.CollectionDisplay = MaturityDisplayNames[MaturityDevelopment]
		pr.ColNextTierName = MaturityDisplayNames[MaturityVerified]
		pr.ColNextTierKey = "verified"
		pr.ColNextTierPasses = ThresholdVerified
	}
}

func populateAnalysisData(pr *ProtocolReport, analData dbq.ICAEGetAllMaturityRow, hasAnal bool) {
	if hasAnal && analData.TotalRuns > 0 {
		pr.HasAnalysis = true
		pr.AnalysisLevel = analData.Maturity
		pr.AnalysisDisplay = MaturityDisplayNames[analData.Maturity]
		pr.AnalysisRuns = int(analData.TotalRuns)
		pr.AnalysisPasses = int(analData.ConsecutivePasses)
		pr.AnalysisBarPct = runsToBarPct(int(analData.ConsecutivePasses))
		if t := TimestampToTimePtr(analData.LastRegressionAt); t != nil {
			pr.LastRegressionAt = *t
		}
		if t := TimestampToTimePtr(analData.LastEvaluatedAt); t != nil {
			pr.LastEvaluatedAt = *t
		}
		if t := TimestampToTimePtr(analData.FirstPassAt); t != nil {
			pr.FirstPassAt = *t
		}

		daysElapsed := 0
		if analData.FirstPassAt.Valid {
			daysElapsed = int(time.Since(analData.FirstPassAt.Time).Hours() / 24)
		}
		pr.DaysElapsed = daysElapsed
		pr.NextTierName, pr.NextTierKey, pr.NextTierPasses, pr.NextTierDays, pr.PassesMet, pr.DaysMet, pr.AtMaxTier = ComputeNextTier(analData.Maturity, int(analData.ConsecutivePasses), daysElapsed)
		pr.NextTierPct = NextTierPct(analData.Maturity, int(analData.ConsecutivePasses), daysElapsed)
	} else {
		pr.AnalysisLevel = MaturityDevelopment
		pr.AnalysisDisplay = MaturityDisplayNames[MaturityDevelopment]
		pr.NextTierName = MaturityDisplayNames[MaturityVerified]
		pr.NextTierKey = "verified"
		pr.NextTierPasses = ThresholdVerified
	}
}

type reportAggregates struct {
	evaluatedCount    int
	totalPasses       int
	totalRuns         int
	collectionPasses  int
	collectionRuns    int
	earliestFirstPass string
	maxDays           int
}

func computeReportAggregates(protocols []ProtocolReport) reportAggregates {
	var agg reportAggregates
	for _, p := range protocols {
		if p.HasRuns {
			agg.evaluatedCount++
		}
		agg.totalPasses += p.AnalysisPasses
		agg.totalRuns += p.AnalysisRuns
		agg.collectionPasses += p.CollectionPasses
		agg.collectionRuns += p.CollectionRuns
		if p.FirstPassAt != "" {
			if agg.earliestFirstPass == "" || p.FirstPassAt < agg.earliestFirstPass {
				agg.earliestFirstPass = p.FirstPassAt
			}
		}
		if p.DaysElapsed > agg.maxDays {
			agg.maxDays = p.DaysElapsed
		}
	}
	return agg
}

func collectRegressionEvents(rows []dbq.ICAEGetAllMaturityRow) []RegressionEvent {
	var regressions []RegressionEvent
	for _, row := range rows {
		if row.LastRegressionAt.Valid {
			runsSince := int(row.ConsecutivePasses)
			regressions = append(regressions, RegressionEvent{
				Protocol:    row.Protocol,
				DisplayName: ProtocolDisplayNames[row.Protocol],
				OccurredAt:  row.LastRegressionAt.Time.Format("2006-01-02"),
				RunsSince:   runsSince,
			})
		}
	}
	return regressions
}

func formatPassRate(totalPasses, totalRuns int) string {
	if totalRuns <= 0 {
		return "0"
	}
	pct := float64(totalPasses) / float64(totalRuns) * 100
	if pct == float64(int(pct)) {
		return fmt.Sprintf("%d", int(pct))
	}
	return fmt.Sprintf("%.1f", pct)
}
