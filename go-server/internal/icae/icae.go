// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package icae

import (
        "time"
)

const (
        LayerCollection = "collection"
        LayerAnalysis   = "analysis"

        MaturityDevelopment = "development"
        MaturityVerified    = "verified"
        MaturityConsistent  = "consistent"
        MaturityGold        = "gold"
        MaturityGoldMaster  = "gold_master"

        ThresholdVerified   = 100
        ThresholdConsistent = 500
        ThresholdGold       = 1000
        ThresholdGoldMaster = 5000

        ConsistentDays = 30
        GoldDays       = 90
        GoldMasterDays = 180
)

var Protocols = []string{
        "spf", "dkim", "dmarc", "dane", "dnssec",
        "bimi", "mta_sts", "tlsrpt", "caa",
}

var ProtocolDisplayNames = map[string]string{
        "spf":     "SPF",
        "dkim":    "DKIM",
        "dmarc":   "DMARC",
        "dane":    "DANE/TLSA",
        "dnssec":  "DNSSEC",
        "bimi":    "BIMI",
        "mta_sts": "MTA-STS",
        "tlsrpt":  "TLS-RPT",
        "caa":     "CAA",
}

var MaturityDisplayNames = map[string]string{
        MaturityDevelopment: "Development",
        MaturityVerified:    "Verified",
        MaturityConsistent:  "Consistent",
        MaturityGold:        "Gold",
        MaturityGoldMaster:  "Gold Master",
}

var MaturityOrder = map[string]int{
        MaturityDevelopment: 0,
        MaturityVerified:    1,
        MaturityConsistent:  2,
        MaturityGold:        3,
        MaturityGoldMaster:  4,
}

type TestCase struct {
        CaseID     string
        CaseName   string
        Protocol   string
        Layer      string
        RFCSection string
        Expected   string
        RunFn      func() (actual string, passed bool)
}

type TestResult struct {
        CaseID     string
        CaseName   string
        Protocol   string
        Layer      string
        RFCSection string
        Expected   string
        Actual     string
        Passed     bool
        Notes      string
}

type RunSummary struct {
        AppVersion  string
        GitCommit   string
        RunType     string
        TotalCases  int
        TotalPassed int
        TotalFailed int
        DurationMs  int
        Results     []TestResult
        CreatedAt   time.Time
}

type ProtocolMaturity struct {
        Protocol          string
        Layer             string
        Maturity          string
        MaturityDisplay   string
        TotalRuns         int
        ConsecutivePasses int
        FirstPassAt       *time.Time
        LastRegressionAt  *time.Time
        LastEvaluatedAt   time.Time
}

type ReportMetrics struct {
        Protocols              []ProtocolReport
        ByKey                  map[string]ProtocolReport
        LastRunAt              *time.Time
        LastRunVersion         string
        TotalProtocols         int
        EvaluatedCount         int
        OverallMaturity        string
        OverallMaturityDisplay string
        TotalPasses            int
        TotalRuns              int
        CollectionPasses       int
        CollectionRuns         int
        PassRate               string
        FirstPassAt            string
        DaysRunning            int
        Regressions            []RegressionEvent
        TotalCollectionCases   int
        TotalAnalysisCases     int
        TotalAllCases          int
        HashAudit              *HashAuditResult
        Calibration            *CalibrationResult
}

type RegressionEvent struct {
        Protocol    string
        DisplayName string
        OccurredAt  string
        RunsSince   int
}

func NextTierPct(currentLevel string, consecutivePasses, daysSinceFirst int) int {
        _, _, nextPasses, nextDays, _, _, atMax := ComputeNextTier(currentLevel, consecutivePasses, daysSinceFirst)
        if atMax {
                return 100
        }
        passPct := 0
        if nextPasses > 0 {
                passPct = (consecutivePasses * 100) / nextPasses
                if passPct > 100 {
                        passPct = 100
                }
        }
        dayPct := 100
        if nextDays > 0 {
                dayPct = (daysSinceFirst * 100) / nextDays
                if dayPct > 100 {
                        dayPct = 100
                }
        }
        if passPct < dayPct {
                return passPct
        }
        return dayPct
}

type ProtocolReport struct {
        Protocol          string
        DisplayName       string
        EffectiveLevel    string
        EffectiveDisplay  string
        CollectionLevel   string
        CollectionDisplay string
        CollectionRuns    int
        CollectionPasses  int
        HasCollection     bool
        AnalysisLevel     string
        AnalysisDisplay   string
        AnalysisRuns      int
        AnalysisPasses    int
        HasAnalysis       bool
        HasRuns           bool
        LastRegressionAt  string
        LastEvaluatedAt   string
        FirstPassAt       string
        CollectionBarPct  int
        AnalysisBarPct    int
        NextTierName      string
        NextTierKey       string
        NextTierPasses    int
        NextTierDays      int
        PassesMet         bool
        DaysMet           bool
        DaysElapsed       int
        AtMaxTier         bool
        NextTierPct       int
        ColNextTierName   string
        ColNextTierKey    string
        ColNextTierPasses int
        ColNextTierDays   int
        ColPassesMet      bool
        ColDaysMet        bool
        ColDaysElapsed    int
        ColAtMaxTier      bool
        ColNextTierPct    int
        CollectionCases   int
        AnalysisCases     int
        TotalCases        int
}

type ProtocolCaseCounts struct {
        Collection int
        Analysis   int
        Total      int
}

func CountCasesByProtocol() map[string]ProtocolCaseCounts {
        counts := make(map[string]ProtocolCaseCounts)
        for _, tc := range AnalysisTestCases() {
                c := counts[tc.Protocol]
                c.Analysis++
                c.Total++
                counts[tc.Protocol] = c
        }
        for _, tc := range CollectionTestCases() {
                c := counts[tc.Protocol]
                c.Collection++
                c.Total++
                counts[tc.Protocol] = c
        }
        return counts
}

func ComputeNextTier(currentLevel string, consecutivePasses, daysSinceFirst int) (nextName, nextKey string, nextPasses, nextDays int, passesMet, daysMet, atMax bool) {
        switch currentLevel {
        case MaturityDevelopment:
                return MaturityDisplayNames[MaturityVerified], "verified", ThresholdVerified, 0, consecutivePasses >= ThresholdVerified, true, false
        case MaturityVerified:
                return MaturityDisplayNames[MaturityConsistent], "consistent", ThresholdConsistent, ConsistentDays, consecutivePasses >= ThresholdConsistent, daysSinceFirst >= ConsistentDays, false
        case MaturityConsistent:
                return MaturityDisplayNames[MaturityGold], "gold", ThresholdGold, GoldDays, consecutivePasses >= ThresholdGold, daysSinceFirst >= GoldDays, false
        case MaturityGold:
                return MaturityDisplayNames[MaturityGoldMaster], "gold-master", ThresholdGoldMaster, GoldMasterDays, consecutivePasses >= ThresholdGoldMaster, daysSinceFirst >= GoldMasterDays, false
        default:
                return "", "", 0, 0, true, true, true
        }
}

func runsToBarPct(runs int) int {
        switch {
        case runs <= 0:
                return 0
        case runs < ThresholdVerified:
                return 1 + (runs*19)/ThresholdVerified
        case runs < ThresholdConsistent:
                return 20 + ((runs-ThresholdVerified)*20)/(ThresholdConsistent-ThresholdVerified)
        case runs < ThresholdGold:
                return 40 + ((runs-ThresholdConsistent)*20)/(ThresholdGold-ThresholdConsistent)
        case runs < ThresholdGoldMaster:
                return 60 + ((runs-ThresholdGold)*20)/(ThresholdGoldMaster-ThresholdGold)
        default:
                pct := 80 + ((runs-ThresholdGoldMaster)*20)/ThresholdGoldMaster
                if pct > 100 {
                        pct = 100
                }
                return pct
        }
}

func ComputeMaturity(consecutivePasses int, firstPassAt *time.Time, lastRegressionAt *time.Time) string {
        if consecutivePasses < ThresholdVerified {
                return MaturityDevelopment
        }

        if firstPassAt == nil {
                return MaturityVerified
        }

        daysSinceFirst := int(time.Since(*firstPassAt).Hours() / 24)

        regressedRecently := false
        if lastRegressionAt != nil {
                daysSinceRegression := int(time.Since(*lastRegressionAt).Hours() / 24)
                if daysSinceRegression < ConsistentDays {
                        regressedRecently = true
                }
        }

        if regressedRecently {
                if consecutivePasses >= ThresholdVerified {
                        return MaturityVerified
                }
                return MaturityDevelopment
        }

        if consecutivePasses >= ThresholdGoldMaster && daysSinceFirst >= GoldMasterDays {
                return MaturityGoldMaster
        }
        if consecutivePasses >= ThresholdGold && daysSinceFirst >= GoldDays {
                return MaturityGold
        }
        if consecutivePasses >= ThresholdConsistent && daysSinceFirst >= ConsistentDays {
                return MaturityConsistent
        }
        if consecutivePasses >= ThresholdVerified {
                return MaturityVerified
        }

        return MaturityDevelopment
}

func CombinedMaturity(analysisLevel, collectionLevel string) string {
        aOrder := MaturityOrder[analysisLevel]
        cOrder := MaturityOrder[collectionLevel]
        if cOrder < aOrder {
                return collectionLevel
        }
        return analysisLevel
}

func OverallMaturity(protocols []ProtocolReport) string {
        lowest := MaturityGoldMaster
        lowestOrder := MaturityOrder[lowest]
        hasAny := false

        for _, p := range protocols {
                if p.HasRuns {
                        hasAny = true
                        order, ok := MaturityOrder[p.EffectiveLevel]
                        if !ok {
                                return MaturityDevelopment
                        }
                        if order < lowestOrder {
                                lowestOrder = order
                                lowest = p.EffectiveLevel
                        }
                }
        }

        if !hasAny {
                return MaturityDevelopment
        }

        return lowest
}

func IsDegraded(previousMaturity, newMaturity string) bool {
        return MaturityOrder[newMaturity] < MaturityOrder[previousMaturity]
}
