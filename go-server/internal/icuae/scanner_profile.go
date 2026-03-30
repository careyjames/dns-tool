// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
//
// Phase 2: Suggested Config — Scanner Profile Recommendations
//
// Generates recommended scanner profiles from rolling statistics:
//   - Resolver set optimization
//   - Retry threshold adjustments
//   - Record type priorities
//   - Timeout tuning
//
// All suggestions require explicit user approval before applying.
// Grounded in NIST SP 800-53 SI-7 (information integrity) and RFC 8767 (TTL behavior).
// dns-tool:scrutiny science
package icuae

import (
        "fmt"
        "math"
        "sort"
)

const severityHigh = "high"

const (
        mapKeyMedium     = "medium"
        mapKeyTimeout    = "timeout"
        severityLow      = "low"
        paramTimeoutSecs = "timeout_seconds"
        paramRetryCount  = "retry_count"
)

type ScannerProfile struct {
        ResolverSet        []string `json:"resolver_set"`
        TimeoutSeconds     int      `json:"timeout_seconds"`
        RetryCount         int      `json:"retry_count"`
        RecordTypePriority []string `json:"record_type_priority"`
        ConcurrencyLimit   int      `json:"concurrency_limit"`
}

// S1313 suppressed: well-known public DNS resolver IPs — intentional for multi-resolver scanning.
var DefaultProfile = ScannerProfile{
        ResolverSet:        []string{"8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222", "185.228.168.168"},
        TimeoutSeconds:     5,
        RetryCount:         2,
        RecordTypePriority: []string{"A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "CAA", "TLSA"},
        ConcurrencyLimit:   10,
}

type ProfileSuggestion struct {
        Parameter string `json:"parameter"`
        Current   string `json:"current"`
        Suggested string `json:"suggested"`
        Rationale string `json:"rationale"`
        Standard  string `json:"standard"`
        Severity  string `json:"severity"`
        Category  string `json:"category"`
}

func (s ProfileSuggestion) SeverityClass() string {
        switch s.Severity {
        case severityHigh:
                return "danger"
        case mapKeyMedium:
                return "warning"
        default:
                return "info"
        }
}

func (s ProfileSuggestion) CategoryIcon() string {
        switch s.Category {
        case "resolver":
                return "server"
        case "retry":
                return "arrows-rotate"
        case mapKeyTimeout:
                return "clock"
        case "priority":
                return "cogs"
        default:
                return "cogs"
        }
}

type RollingStats struct {
        ScanCount            int                  `json:"scan_count"`
        AvgResolverAgreement float64              `json:"avg_resolver_agreement"`
        TTLDeviations        map[string]float64   `json:"ttl_deviations"`
        DimensionTrends      map[string][]float64 `json:"dimension_trends"`
        RecordTypeErrors     map[string]int       `json:"record_type_errors"`
        AvgScanDuration      float64              `json:"avg_scan_duration_ms"`
}

type SuggestedConfig struct {
        Profile     ScannerProfile      `json:"profile"`
        Suggestions []ProfileSuggestion `json:"suggestions"`
        BasedOn     int                 `json:"based_on_scans"`
        Confidence  string              `json:"confidence"`
}

func (sc SuggestedConfig) HasSuggestions() bool {
        return len(sc.Suggestions) > 0
}

func (sc SuggestedConfig) ConfidenceClass() string {
        switch sc.Confidence {
        case severityHigh:
                return "success"
        case mapKeyMedium:
                return "info"
        default:
                return "secondary"
        }
}

func GenerateSuggestedConfig(stats RollingStats, current ScannerProfile) SuggestedConfig {
        suggested := current
        var suggestions []ProfileSuggestion

        if stats.ScanCount < 3 {
                return SuggestedConfig{
                        Profile:     current,
                        Suggestions: nil,
                        BasedOn:     stats.ScanCount,
                        Confidence:  severityLow,
                }
        }

        resolverSugs := suggestResolverChanges(stats, current)
        suggestions = append(suggestions, resolverSugs...)

        retrySugs := suggestRetryChanges(stats, current)
        suggestions = append(suggestions, retrySugs...)

        timeoutSugs := suggestTimeoutChanges(stats, current)
        suggestions = append(suggestions, timeoutSugs...)

        prioritySugs := suggestRecordPriority(stats, current)
        suggestions = append(suggestions, prioritySugs...)

        applySuggestedProfile(&suggested, current, stats, resolverSugs, retrySugs, timeoutSugs, prioritySugs)

        confidence := mapKeyMedium
        if stats.ScanCount >= 10 {
                confidence = severityHigh
        }

        return SuggestedConfig{
                Profile:     suggested,
                Suggestions: suggestions,
                BasedOn:     stats.ScanCount,
                Confidence:  confidence,
        }
}

func applySuggestedProfile(suggested *ScannerProfile, current ScannerProfile, stats RollingStats, resolverSugs, retrySugs, timeoutSugs, prioritySugs []ProfileSuggestion) {
        if len(resolverSugs) > 0 {
                suggested.ResolverSet = current.ResolverSet
        }
        applyRetryCount(suggested, retrySugs, stats.AvgResolverAgreement)
        if len(timeoutSugs) > 0 && stats.AvgScanDuration > 30000 {
                suggested.TimeoutSeconds = 8
        }
        if len(prioritySugs) > 0 {
                suggested.RecordTypePriority = buildPriorityOrder(stats)
        }
}

func applyRetryCount(suggested *ScannerProfile, retrySugs []ProfileSuggestion, agreement float64) {
        for _, s := range retrySugs {
                if s.Parameter != paramRetryCount {
                        continue
                }
                switch {
                case agreement < 60:
                        suggested.RetryCount = 4
                case agreement < 80:
                        suggested.RetryCount = 3
                }
        }
}

func accumulateDimensionStats(stats *RollingStats, dim DimensionScore) (float64, bool) {
        stats.DimensionTrends[dim.Dimension] = append(stats.DimensionTrends[dim.Dimension], dim.Score)
        for _, f := range dim.Findings {
                deviation := math.Abs(f.Ratio - 1.0)
                if existing, ok := stats.TTLDeviations[f.RecordType]; !ok || deviation > existing {
                        stats.TTLDeviations[f.RecordType] = deviation
                }
        }
        return dim.Score, dim.Dimension == DimensionSourceCredibility
}

func suggestResolverChanges(stats RollingStats, current ScannerProfile) []ProfileSuggestion {
        var suggestions []ProfileSuggestion

        if stats.AvgResolverAgreement < 70 {
                suggestions = append(suggestions, ProfileSuggestion{
                        Parameter: "resolver_set",
                        Current:   fmt.Sprintf("%d resolvers, %.0f%% agreement", len(current.ResolverSet), stats.AvgResolverAgreement),
                        Suggested: "Add additional resolvers or replace low-agreement ones",
                        Rationale: fmt.Sprintf("Resolver agreement rate is %.1f%%, below the 70%% threshold. "+
                                "Low agreement indicates potential DNS propagation issues or resolver-specific caching behavior. "+
                                "Adding diverse resolvers improves measurement confidence.",
                                stats.AvgResolverAgreement),
                        Standard: StandardNIST80053SI7,
                        Severity: resolverSeverity(stats.AvgResolverAgreement),
                        Category: "resolver",
                })
        }

        return suggestions
}

func suggestRetryChanges(stats RollingStats, current ScannerProfile) []ProfileSuggestion {
        var suggestions []ProfileSuggestion

        errorRate := totalErrorRate(stats)
        if errorRate > 10 {
                suggestedRetries := current.RetryCount
                if errorRate > 30 {
                        suggestedRetries = 4
                } else if errorRate > 10 {
                        suggestedRetries = 3
                }

                if suggestedRetries > current.RetryCount {
                        suggestions = append(suggestions, ProfileSuggestion{
                                Parameter: paramRetryCount,
                                Current:   fmt.Sprintf("%d retries", current.RetryCount),
                                Suggested: fmt.Sprintf("%d retries", suggestedRetries),
                                Rationale: fmt.Sprintf("Record lookup error rate is %.1f%% across %d scans. "+
                                        "Increasing retries from %d to %d reduces transient failures and improves data completeness.",
                                        errorRate, stats.ScanCount, current.RetryCount, suggestedRetries),
                                Standard: StandardNIST80053SI7,
                                Severity: mapKeyMedium,
                                Category: "retry",
                        })
                }
        }

        return suggestions
}

func suggestTimeoutChanges(stats RollingStats, current ScannerProfile) []ProfileSuggestion {
        var suggestions []ProfileSuggestion

        if stats.AvgScanDuration > 30000 && current.TimeoutSeconds < 8 {
                suggestions = append(suggestions, ProfileSuggestion{
                        Parameter: paramTimeoutSecs,
                        Current:   fmt.Sprintf("%ds", current.TimeoutSeconds),
                        Suggested: "8s",
                        Rationale: fmt.Sprintf("Average scan duration is %.1fs, suggesting DNS responses are slow for this domain. "+
                                "Increasing timeout from %ds to 8s prevents premature resolution failures.",
                                stats.AvgScanDuration/1000, current.TimeoutSeconds),
                        Standard: "RFC 8767",
                        Severity: severityLow,
                        Category: mapKeyTimeout,
                })
        } else if stats.AvgScanDuration < 5000 && current.TimeoutSeconds > 5 {
                suggestions = append(suggestions, ProfileSuggestion{
                        Parameter: paramTimeoutSecs,
                        Current:   fmt.Sprintf("%ds", current.TimeoutSeconds),
                        Suggested: "5s",
                        Rationale: fmt.Sprintf("Average scan duration is %.1fs, well within normal range. "+
                                "Timeout can be reduced from %ds to 5s without risk of failures.",
                                stats.AvgScanDuration/1000, current.TimeoutSeconds),
                        Standard: "RFC 8767",
                        Severity: severityLow,
                        Category: mapKeyTimeout,
                })
        }

        return suggestions
}

func suggestRecordPriority(stats RollingStats, current ScannerProfile) []ProfileSuggestion {
        var suggestions []ProfileSuggestion

        errorRecords := make([]string, 0)
        for rt, errCount := range stats.RecordTypeErrors {
                if errCount > stats.ScanCount/3 {
                        errorRecords = append(errorRecords, rt)
                }
        }

        if len(errorRecords) > 0 {
                sort.Strings(errorRecords)
                suggestions = append(suggestions, ProfileSuggestion{
                        Parameter: "record_type_priority",
                        Current:   "Default priority order",
                        Suggested: fmt.Sprintf("Deprioritize error-prone types: %v", errorRecords),
                        Rationale: fmt.Sprintf("Record types %v have error rates exceeding 33%% across %d scans. "+
                                "Deprioritizing these types allows critical records (A, MX, SPF) to be resolved first, "+
                                "improving overall scan efficiency.",
                                errorRecords, stats.ScanCount),
                        Standard: StandardNIST80053SI7,
                        Severity: severityLow,
                        Category: "priority",
                })
        }

        return suggestions
}

func BuildRollingStats(reports []CurrencyReport, scanDurations []float64) RollingStats {
        stats := RollingStats{
                ScanCount:        len(reports),
                TTLDeviations:    make(map[string]float64),
                DimensionTrends:  make(map[string][]float64),
                RecordTypeErrors: make(map[string]int),
        }

        if len(reports) == 0 {
                return stats
        }

        totalAgreement := 0.0
        agreementCount := 0
        for _, report := range reports {
                for _, dim := range report.Dimensions {
                        agreement, isCredibility := accumulateDimensionStats(&stats, dim)
                        if isCredibility {
                                totalAgreement += agreement
                                agreementCount++
                        }
                }
        }

        if agreementCount > 0 {
                stats.AvgResolverAgreement = totalAgreement / float64(agreementCount)
        }

        if len(scanDurations) > 0 {
                total := 0.0
                for _, d := range scanDurations {
                        total += d
                }
                stats.AvgScanDuration = total / float64(len(scanDurations))
        }

        return stats
}

func resolverSeverity(agreement float64) string {
        if agreement < 50 {
                return severityHigh
        }
        return mapKeyMedium
}

func totalErrorRate(stats RollingStats) float64 {
        if stats.ScanCount == 0 {
                return 0
        }
        totalErrors := 0
        for _, count := range stats.RecordTypeErrors {
                totalErrors += count
        }
        return float64(totalErrors) / float64(stats.ScanCount) * 100 / float64(max(len(stats.RecordTypeErrors), 1))
}

func buildPriorityOrder(stats RollingStats) []string {
        type rtError struct {
                rt     string
                errors int
        }

        allTypes := []string{"A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "CAA", "TLSA"}
        errorRates := make([]rtError, 0, len(allTypes))
        for _, rt := range allTypes {
                errorRates = append(errorRates, rtError{rt: rt, errors: stats.RecordTypeErrors[rt]})
        }

        sort.Slice(errorRates, func(i, j int) bool {
                return errorRates[i].errors < errorRates[j].errors
        })

        result := make([]string, 0, len(errorRates))
        for _, rte := range errorRates {
                result = append(result, rte.rt)
        }
        return result
}
