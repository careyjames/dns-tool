// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package icuae

import (
        "context"
        "fmt"
        "log/slog"
        "math"
        "time"

        "dnstool/go-server/internal/dbq"
)

const (
        iconWarning     = "exclamation-triangle text-warning"
        iconInfo        = "info-circle text-info"
        iconSuccess     = "lightbulb text-success"
        iconTrendMinus  = "minus"
        iconTrendEquals = "equals"
        iconTrendUp     = "arrow-trend-up"
        iconTrendDown   = "arrow-trend-down"

        mapKeyError = "error"
)

type DBTX interface {
        ICuAEInsertScanScore(ctx context.Context, arg dbq.ICuAEInsertScanScoreParams) (dbq.ICuAEInsertScanScoreRow, error)
        ICuAEInsertDimensionScore(ctx context.Context, arg dbq.ICuAEInsertDimensionScoreParams) error
        ICuAEGetAggregateStats(ctx context.Context) (dbq.ICuAEGetAggregateStatsRow, error)
        ICuAEGetGradeDistribution(ctx context.Context) ([]dbq.ICuAEGetGradeDistributionRow, error)
        ICuAEGetDimensionAverages(ctx context.Context) ([]dbq.ICuAEGetDimensionAveragesRow, error)
        ICuAEGetRecentTrend(ctx context.Context, limit int32) ([]dbq.ICuAEGetRecentTrendRow, error)
}

func RecordScanResult(ctx context.Context, queries DBTX, domain string, report CurrencyReport, appVersion string) {
        row, err := queries.ICuAEInsertScanScore(ctx, dbq.ICuAEInsertScanScoreParams{
                Domain:        domain,
                OverallScore:  float32(report.OverallScore),
                OverallGrade:  report.OverallGrade,
                ResolverCount: int32(report.ResolverCount),
                RecordCount:   int32(report.RecordCount),
                AppVersion:    appVersion,
        })
        if err != nil {
                slog.Warn("ICuAE: failed to record scan score", "domain", domain, mapKeyError, err)
                return
        }

        for _, dim := range report.Dimensions {
                rtList := dim.RecordTypesList()
                if err := queries.ICuAEInsertDimensionScore(ctx, dbq.ICuAEInsertDimensionScoreParams{
                        ScanID:               row.ID,
                        Dimension:            dim.Dimension,
                        Score:                float32(dim.Score),
                        Grade:                dim.Grade,
                        RecordTypesEvaluated: int32(len(rtList)),
                        RecordTypesList:      rtList,
                }); err != nil {
                        slog.Warn("ICuAE: failed to record dimension score", "dimension", dim.Dimension, mapKeyError, err)
                }
        }
}

type RuntimeMetrics struct {
        TotalScans      int
        AvgScore        float64
        AvgScoreDisplay string
        AvgGrade        string
        AvgGradeDisplay string
        AvgGradeClass   string
        StddevScore     float64
        StabilityGrade  string
        StabilityLabel  string
        LastEvaluatedAt string
        TrendDirection  string
        TrendArrow      string
        GradeDist       []GradeDistItem
        DimensionStats  []DimensionStat
        HasData         bool
}

type GradeDistItem struct {
        Grade      string
        Display    string
        Count      int
        Pct        float64
        PctDisplay string
        BootClass  string
}

type DimensionStat struct {
        Dimension   string
        Display     string
        Standard    string
        AvgScore    float64
        AvgDisplay  string
        Stddev      float64
        Grade       string
        BootClass   string
        SampleCount int
        TuningHint  string
        TuningIcon  string
}

var dimensionTuningThresholds = map[string][]struct {
        MaxScore float64
        Hint     string
        Icon     string
}{
        DimensionCurrentness: {
                {49, "Data age exceeds TTL validity windows consistently. Consider increasing scan frequency or scheduling scans during low-cache-age periods.", iconWarning},
                {74, "Some records are collected near or past their TTL expiry. Tighter scan cadence alignment with authoritative TTLs would improve freshness.", iconInfo},
                {89, "Minor freshness gaps detected. Fine-tuning scan timing to align with the shortest TTLs in the record set can push scores toward Excellent.", iconSuccess},
        },
        DimensionTTLCompliance: {
                {49, "Resolver caches frequently exceed authoritative TTL limits, indicating serve-stale behavior (RFC 8767). Consider prioritizing resolvers with stricter TTL compliance.", iconWarning},
                {74, "Some resolvers serve records past their authoritative TTL. Increasing resolver diversity or weighting TTL-compliant resolvers more heavily would help.", iconInfo},
                {89, "Near-compliant TTL behavior with minor deviations. Monitoring resolver-specific TTL overrides can identify the remaining outliers.", iconSuccess},
        },
        DimensionCompleteness: {
                {49, "Multiple expected record types are consistently missing. Expanding the query set or adding retry logic for failed lookups would improve coverage.", iconWarning},
                {74, "Some optional record types (DANE/TLSA, BIMI, CAA) are absent. These are domain-dependent but adding fallback queries can capture more when present.", iconInfo},
                {89, "Nearly complete record coverage with minor gaps. Review which specific record types are missing to determine if they are domain-absent or collection-absent.", iconSuccess},
        },
        DimensionSourceCredibility: {
                {49, "Resolvers frequently disagree on fundamental records. Consider adding more resolver endpoints or investigating whether split-horizon DNS is in play.", iconWarning},
                {74, "Partial resolver agreement on some record types. Weighting results by resolver reliability history could improve consensus scoring.", iconInfo},
                {89, "Strong multi-resolver consensus with minor disagreements. Identifying which specific resolvers diverge can help refine the weighting model.", iconSuccess},
        },
        DimensionTTLRelevance: {
                {49, "Observed TTLs deviate significantly from expected ranges for their record types. This often indicates domain-side misconfiguration rather than collection issues.", iconWarning},
                {74, "Some TTL values fall outside typical ranges. This is informational — extreme TTLs may be intentional but affect cache behavior across resolvers.", iconInfo},
                {89, "TTL values are within expected ranges with minor outliers. Domain operators may benefit from TTL tuning recommendations in the report.", iconSuccess},
        },
}

func LoadRuntimeMetrics(ctx context.Context, queries DBTX) *RuntimeMetrics {
        stats, err := queries.ICuAEGetAggregateStats(ctx)
        if err != nil {
                slog.Warn("ICuAE: failed to load aggregate stats", mapKeyError, err)
                return nil
        }

        if stats.TotalScans == 0 {
                return &RuntimeMetrics{HasData: false}
        }

        avgGrade := scoreToGrade(float64(stats.AvgScore))
        m := &RuntimeMetrics{
                TotalScans:      int(stats.TotalScans),
                AvgScore:        float64(stats.AvgScore),
                AvgScoreDisplay: fmt.Sprintf("%.1f", stats.AvgScore),
                AvgGrade:        avgGrade,
                AvgGradeDisplay: GradeDisplayNames[avgGrade],
                AvgGradeClass:   GradeBootstrapClass[avgGrade],
                StddevScore:     float64(stats.StddevScore),
                HasData:         true,
        }

        if t, ok := stats.LastEvaluatedAt.(time.Time); ok {
                m.LastEvaluatedAt = t.Format("2006-01-02 15:04 UTC")
        }

        m.StabilityGrade, m.StabilityLabel = computeStability(float64(stats.StddevScore))

        m.GradeDist = loadGradeDistribution(ctx, queries)
        m.DimensionStats = loadDimensionStats(ctx, queries)
        m.TrendDirection, m.TrendArrow = loadTrendData(ctx, queries)

        return m
}

func loadDimensionStats(ctx context.Context, queries DBTX) []DimensionStat {
        dimAvgs, err := queries.ICuAEGetDimensionAverages(ctx)
        if err != nil {
                return nil
        }
        stats := make([]DimensionStat, 0, len(dimAvgs))
        for _, d := range dimAvgs {
                avgGrade := scoreToGrade(float64(d.AvgScore))
                hint, icon := dimensionTuningHint(d.Dimension, float64(d.AvgScore))
                stats = append(stats, DimensionStat{
                        Dimension:   d.Dimension,
                        Display:     DimensionDisplayNames[d.Dimension],
                        Standard:    DimensionStandards[d.Dimension],
                        AvgScore:    float64(d.AvgScore),
                        AvgDisplay:  fmt.Sprintf("%.1f", d.AvgScore),
                        Stddev:      float64(d.StddevScore),
                        Grade:       avgGrade,
                        BootClass:   GradeBootstrapClass[avgGrade],
                        SampleCount: int(d.SampleCount),
                        TuningHint:  hint,
                        TuningIcon:  icon,
                })
        }
        return stats
}

func loadTrendData(ctx context.Context, queries DBTX) (string, string) {
        trend, err := queries.ICuAEGetRecentTrend(ctx, 20)
        if err == nil && len(trend) >= 2 {
                return computeTrend(trend)
        }
        return "insufficient", iconTrendMinus
}

func loadGradeDistribution(ctx context.Context, queries DBTX) []GradeDistItem {
        gradeDist, err := queries.ICuAEGetGradeDistribution(ctx)
        if err != nil {
                return nil
        }
        total := 0
        for _, g := range gradeDist {
                total += int(g.Count)
        }
        items := make([]GradeDistItem, 0, len(gradeDist))
        for _, g := range gradeDist {
                pct := 0.0
                if total > 0 {
                        pct = float64(g.Count) / float64(total) * 100
                }
                items = append(items, GradeDistItem{
                        Grade:      g.Grade,
                        Display:    GradeDisplayNames[g.Grade],
                        Count:      int(g.Count),
                        Pct:        pct,
                        PctDisplay: fmt.Sprintf("%.0f", pct),
                        BootClass:  GradeBootstrapClass[g.Grade],
                })
        }
        return items
}

func dimensionTuningHint(dimension string, avgScore float64) (string, string) {
        thresholds, ok := dimensionTuningThresholds[dimension]
        if !ok {
                return "", ""
        }
        if avgScore >= 90 {
                return "", ""
        }
        for _, t := range thresholds {
                if avgScore <= t.MaxScore {
                        return t.Hint, t.Icon
                }
        }
        return "", ""
}

func computeStability(stddev float64) (string, string) {
        switch {
        case stddev < 5:
                return "high", "High Stability"
        case stddev < 10:
                return "good", "Good Stability"
        case stddev < 20:
                return "moderate", "Moderate Stability"
        default:
                return "variable", "Variable"
        }
}

func computeTrend(points []dbq.ICuAEGetRecentTrendRow) (string, string) {
        n := len(points)
        if n < 2 {
                return "insufficient", iconTrendMinus
        }

        recentHalf := points[:n/2]
        olderHalf := points[n/2:]

        recentAvg := avgScores(recentHalf)
        olderAvg := avgScores(olderHalf)

        delta := recentAvg - olderAvg
        if math.Abs(delta) < 3.0 {
                return "stable", iconTrendEquals
        }
        if delta > 0 {
                return "improving", iconTrendUp
        }
        return "declining", iconTrendDown
}

func avgScores(rows []dbq.ICuAEGetRecentTrendRow) float64 {
        if len(rows) == 0 {
                return 0
        }
        total := 0.0
        for _, r := range rows {
                total += float64(r.OverallScore)
        }
        return total / float64(len(rows))
}
