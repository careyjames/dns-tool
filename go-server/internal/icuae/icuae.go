// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
//
// # ICuAE — Intelligence Currency Audit Engine
//
// Companion to ICAE (Intelligence Confidence Audit Engine).
// ICAE answers: "Did we interpret the DNS data correctly?"
// ICuAE answers: "Is the DNS data still valid/current?"
//
// Grounded in five authoritative standards:
//   - ICD 203 (CIA): Timeliness as core analytic standard
//   - NIST SP 800-53 SI-7: Software, Firmware, and Information Integrity
//   - ISO/IEC 25012: Currentness — data of the right age for its context
//   - RFC 8767: TTL-based cache expiration and serve-stale behavior
//   - SPJ Code of Ethics: Multiple independent sources for verification
// dns-tool:scrutiny science
package icuae

import (
        "encoding/json"
        "fmt"
)

const (
        StandardNIST80053SI7 = "NIST SP 800-53 SI-7"

        DimensionCurrentness       = "currentness"
        DimensionTTLCompliance     = "ttl_compliance"
        DimensionCompleteness      = "completeness"
        DimensionSourceCredibility = "source_credibility"
        DimensionTTLRelevance      = "ttl_relevance"

        GradeExcellent = "excellent"
        GradeGood      = "good"
        GradeAdequate  = "adequate"
        GradeDegraded  = "degraded"
        GradeStale     = "stale"
)

var DimensionDisplayNames = map[string]string{
        DimensionCurrentness:       "Currentness",
        DimensionTTLCompliance:     "TTL Compliance",
        DimensionCompleteness:      "Completeness",
        DimensionSourceCredibility: "Source Credibility",
        DimensionTTLRelevance:      "TTL Relevance",
}

var DimensionStandards = map[string]string{
        DimensionCurrentness:       "ISO/IEC 25012",
        DimensionTTLCompliance:     "RFC 8767",
        DimensionCompleteness:      StandardNIST80053SI7,
        DimensionSourceCredibility: "ISO/IEC 25012 + SPJ",
        DimensionTTLRelevance:      StandardNIST80053SI7,
}

var GradeOrder = map[string]int{
        GradeExcellent: 4,
        GradeGood:      3,
        GradeAdequate:  2,
        GradeDegraded:  1,
        GradeStale:     0,
}

var GradeDisplayNames = map[string]string{
        GradeExcellent: "Excellent",
        GradeGood:      "Good",
        GradeAdequate:  "Adequate",
        GradeDegraded:  "Degraded",
        GradeStale:     "Stale",
}

var GradeBootstrapClass = map[string]string{
        GradeExcellent: "success",
        GradeGood:      "success",
        GradeAdequate:  "info",
        GradeDegraded:  "warning",
        GradeStale:     "danger",
}

type DimensionScore struct {
        Dimension   string       `json:"dimension"`
        Standard    string       `json:"standard"`
        Grade       string       `json:"grade"`
        Score       float64      `json:"score"`
        Details     string       `json:"details"`
        RecordTypes int          `json:"record_types_evaluated"`
        Findings    []TTLFinding `json:"findings,omitempty"`
}

func (d DimensionScore) RecordTypesList() []string {
        out := make([]string, 0, d.RecordTypes)
        for _, f := range d.Findings {
                if f.RecordType != "" {
                        out = append(out, f.RecordType)
                }
        }
        return out
}

type TTLFinding struct {
        RecordType     string  `json:"record_type"`
        ObservedTTL    uint32  `json:"observed_ttl"`
        TypicalTTL     uint32  `json:"typical_ttl"`
        Ratio          float64 `json:"ratio"`
        Severity       string  `json:"severity"`
        Standard       string  `json:"standard"`
        Recommendation string  `json:"recommendation"`
        ProviderNote   string  `json:"provider_note,omitempty"`
}

func (f TTLFinding) HasProviderNote() bool { return f.ProviderNote != "" }

func (f TTLFinding) SeverityClass() string {
        switch f.Severity {
        case "high":
                return "danger"
        case "medium":
                return "warning"
        default:
                return "info"
        }
}

func (f TTLFinding) ObservedDisplay() string {
        return formatTTLDuration(f.ObservedTTL)
}

func (f TTLFinding) TypicalDisplay() string {
        return formatTTLDuration(f.TypicalTTL)
}

func formatTTLDuration(ttl uint32) string {
        if ttl >= 86400 && ttl%86400 == 0 {
                d := ttl / 86400
                if d == 1 {
                        return "1 day (86400s)"
                }
                return fmt.Sprintf("%d days (%ds)", d, ttl)
        }
        if ttl >= 3600 && ttl%3600 == 0 {
                h := ttl / 3600
                if h == 1 {
                        return "1 hour (3600s)"
                }
                return fmt.Sprintf("%d hours (%ds)", h, ttl)
        }
        if ttl >= 60 && ttl%60 == 0 {
                m := ttl / 60
                if m == 1 {
                        return "1 minute (60s)"
                }
                return fmt.Sprintf("%d minutes (%ds)", m, ttl)
        }
        return fmt.Sprintf("%ds", ttl)
}

type TrafficEngineeringContext struct {
        Detected    bool   `json:"detected"`
        Explanation string `json:"explanation"`
        Pattern     string `json:"pattern"`
        ShortCount  int    `json:"short_count"`
}

type CurrencyReport struct {
        OverallGrade       string                     `json:"overall_grade"`
        OverallScore       float64                    `json:"overall_score"`
        Dimensions         []DimensionScore           `json:"dimensions"`
        ResolverCount      int                        `json:"resolver_count"`
        RecordCount        int                        `json:"record_count"`
        Guidance           string                     `json:"guidance"`
        ProviderName       string                     `json:"provider_name,omitempty"`
        SOACompliance      *SOAComplianceReport       `json:"soa_compliance,omitempty"`
        TrafficEngineering *TrafficEngineeringContext `json:"traffic_engineering,omitempty"`
}

func (r CurrencyReport) HasProviderIntel() bool {
        return r.ProviderName != "" || (r.SOACompliance != nil && r.SOACompliance.HasFindings())
}

func (r CurrencyReport) ProviderComplianceNotes() []ProviderComplianceNote {
        if r.ProviderName == "" {
                return nil
        }
        p, ok := GetProviderProfile(r.ProviderName)
        if !ok {
                return nil
        }
        return p.Notes
}

func (r CurrencyReport) HasProviderComplianceNotes() bool {
        return len(r.ProviderComplianceNotes()) > 0
}

func (r CurrencyReport) BootstrapClass() string {
        if c, ok := GradeBootstrapClass[r.OverallGrade]; ok {
                return c
        }
        return "secondary"
}

func (r CurrencyReport) HasFindings() bool {
        for _, d := range r.Dimensions {
                if len(d.Findings) > 0 {
                        return true
                }
        }
        return false
}

func (r CurrencyReport) AllFindings() []TTLFinding {
        var all []TTLFinding
        for _, d := range r.Dimensions {
                all = append(all, d.Findings...)
        }
        return all
}

func (r CurrencyReport) OverallGradeDisplay() string {
        if d, ok := GradeDisplayNames[r.OverallGrade]; ok {
                return d
        }
        return "Unknown"
}

func (d DimensionScore) BootstrapClass() string {
        if c, ok := GradeBootstrapClass[d.Grade]; ok {
                return c
        }
        return "secondary"
}

func (d DimensionScore) GradeDisplay() string {
        if g, ok := GradeDisplayNames[d.Grade]; ok {
                return g
        }
        return "Unknown"
}

func (d DimensionScore) DisplayName() string {
        if n, ok := DimensionDisplayNames[d.Dimension]; ok {
                return n
        }
        return d.Dimension
}

func HydrateCurrencyReport(v interface{}) (CurrencyReport, bool) {
        if v == nil {
                return CurrencyReport{}, false
        }
        if cr, ok := v.(CurrencyReport); ok {
                return cr, true
        }
        b, err := json.Marshal(v)
        if err != nil {
                return CurrencyReport{}, false
        }
        var cr CurrencyReport
        if json.Unmarshal(b, &cr) != nil {
                return CurrencyReport{}, false
        }
        return cr, true
}

type RecordCurrency struct {
        RecordType  string  `json:"record_type"`
        ObservedTTL uint32  `json:"observed_ttl"`
        TypicalTTL  uint32  `json:"typical_ttl"`
        DataAgeS    float64 `json:"data_age_seconds"`
        TTLRatio    float64 `json:"ttl_ratio"`
}

type ResolverAgreement struct {
        RecordType     string `json:"record_type"`
        AgreeCount     int    `json:"agree_count"`
        TotalResolvers int    `json:"total_resolvers"`
        Unanimous      bool   `json:"unanimous"`
}

// typicalTTLs are the baseline TTLs for ICuAE TTL Relevance scoring.
// These represent what a well-configured production domain SHOULD use
// (aligned with the TTL Tuner Stability profile and RFC 1912 guidance).
// NOTE: analyzer/currency.go has a SEPARATE typicalTTLs map at A/AAAA=300
// for rescan/data-freshness timing — that reflects what is commonly OBSERVED
// in the wild (dominated by CDN defaults). The two maps serve different purposes.
var typicalTTLs = map[string]uint32{
        "A":       3600,
        "AAAA":    3600,
        "MX":      3600,
        "TXT":     3600,
        "NS":      86400,
        "CNAME":   300,
        "CAA":     3600,
        "SOA":     3600,
        "SPF":     3600,
        "DMARC":   3600,
        "DKIM":    3600,
        "MTA-STS": 86400,
        "TLS-RPT": 3600,
        "BIMI":    3600,
        "TLSA":    3600,
        "DNSSEC":  86400,
        "DANE":    3600,
}

var expectedRecordTypes = []string{
        "A", "AAAA", "MX", "TXT", "NS", "SOA",
        "SPF", "DMARC", "DKIM", "MTA-STS", "TLS-RPT",
        "BIMI", "TLSA", "DNSSEC", "CAA",
}

func TypicalTTLFor(recordType string) uint32 {
        if ttl, ok := typicalTTLs[recordType]; ok {
                return ttl
        }
        return 300
}

func scoreToGrade(score float64) string {
        switch {
        case score >= 90:
                return GradeExcellent
        case score >= 75:
                return GradeGood
        case score >= 50:
                return GradeAdequate
        case score >= 25:
                return GradeDegraded
        default:
                return GradeStale
        }
}

func EvaluateCurrentness(records []RecordCurrency) DimensionScore {
        if len(records) == 0 {
                return DimensionScore{
                        Dimension:   DimensionCurrentness,
                        Standard:    DimensionStandards[DimensionCurrentness],
                        Grade:       GradeStale,
                        Score:       0,
                        Details:     "No record currency data available",
                        RecordTypes: 0,
                }
        }

        totalScore := 0.0
        for _, r := range records {
                validWindow := float64(r.ObservedTTL)
                if validWindow == 0 {
                        validWindow = float64(r.TypicalTTL)
                }
                if validWindow == 0 {
                        validWindow = 300
                }

                if r.DataAgeS <= validWindow {
                        totalScore += 100.0
                } else if r.DataAgeS <= validWindow*2 {
                        totalScore += 50.0
                } else {
                        totalScore += 0.0
                }
        }

        avg := totalScore / float64(len(records))
        return DimensionScore{
                Dimension:   DimensionCurrentness,
                Standard:    DimensionStandards[DimensionCurrentness],
                Grade:       scoreToGrade(avg),
                Score:       avg,
                Details:     currentnessDetails(avg, len(records)),
                RecordTypes: len(records),
        }
}

func currentnessDetails(score float64, count int) string {
        grade := scoreToGrade(score)
        switch grade {
        case GradeExcellent:
                return "All record data is within its TTL validity window"
        case GradeGood:
                return "Most record data is within its TTL validity window"
        case GradeAdequate:
                return "Some records may have aged beyond their TTL windows"
        case GradeDegraded:
                return "Multiple records have aged beyond TTL validity — consider re-scanning"
        default:
                return "Record data has significantly aged beyond TTL windows — re-scan recommended"
        }
}

func EvaluateTTLCompliance(resolverTTLs, authTTLs map[string]uint32) DimensionScore {
        if len(authTTLs) == 0 {
                return DimensionScore{
                        Dimension:   DimensionTTLCompliance,
                        Standard:    DimensionStandards[DimensionTTLCompliance],
                        Grade:       GradeAdequate,
                        Score:       50,
                        Details:     "No authoritative TTL data for comparison",
                        RecordTypes: 0,
                }
        }

        compliant := 0
        total := 0
        for rt, authTTL := range authTTLs {
                resTTL, ok := resolverTTLs[rt]
                if !ok {
                        continue
                }
                total++
                if resTTL <= authTTL {
                        compliant++
                }
        }

        if total == 0 {
                return DimensionScore{
                        Dimension:   DimensionTTLCompliance,
                        Standard:    DimensionStandards[DimensionTTLCompliance],
                        Grade:       GradeAdequate,
                        Score:       50,
                        Details:     "No overlapping resolver/authoritative records for TTL comparison",
                        RecordTypes: 0,
                }
        }

        score := (float64(compliant) / float64(total)) * 100
        return DimensionScore{
                Dimension:   DimensionTTLCompliance,
                Standard:    DimensionStandards[DimensionTTLCompliance],
                Grade:       scoreToGrade(score),
                Score:       score,
                Details:     ttlComplianceDetails(compliant, total),
                RecordTypes: total,
        }
}

func ttlComplianceDetails(compliant, total int) string {
        if compliant == total {
                return "All resolver TTLs are within authoritative limits (RFC 8767 compliant)"
        }
        violated := total - compliant
        if violated == 1 {
                return "1 resolver TTL exceeds its authoritative value — possible serve-stale (RFC 8767), timing skew, or cache misconfiguration"
        }
        return fmt.Sprintf("%d of %d resolver TTLs exceed authoritative values — possible serve-stale (RFC 8767), timing skew, or cache misconfiguration", violated, total)
}

func EvaluateCompleteness(observedTypes map[string]bool) DimensionScore {
        found := 0
        for _, rt := range expectedRecordTypes {
                if observedTypes[rt] {
                        found++
                }
        }

        score := (float64(found) / float64(len(expectedRecordTypes))) * 100
        return DimensionScore{
                Dimension:   DimensionCompleteness,
                Standard:    DimensionStandards[DimensionCompleteness],
                Grade:       scoreToGrade(score),
                Score:       score,
                Details:     completenessDetails(found, len(expectedRecordTypes)),
                RecordTypes: found,
        }
}

func completenessDetails(found, total int) string {
        if found == total {
                return "All expected record types have authoritative TTL data"
        }
        missing := total - found
        if missing == 1 {
                return "1 expected record type is missing TTL data"
        }
        return fmt.Sprintf("%d of %d expected record types are missing TTL data", missing, total)
}

func EvaluateSourceCredibility(agreements []ResolverAgreement) DimensionScore {
        if len(agreements) == 0 {
                return DimensionScore{
                        Dimension:   DimensionSourceCredibility,
                        Standard:    DimensionStandards[DimensionSourceCredibility],
                        Grade:       GradeStale,
                        Score:       0,
                        Details:     "No multi-resolver data available for credibility assessment",
                        RecordTypes: 0,
                }
        }

        totalScore := 0.0
        for _, a := range agreements {
                if a.TotalResolvers == 0 {
                        continue
                }
                ratio := float64(a.AgreeCount) / float64(a.TotalResolvers)
                totalScore += ratio * 100
        }

        avg := totalScore / float64(len(agreements))
        return DimensionScore{
                Dimension:   DimensionSourceCredibility,
                Standard:    DimensionStandards[DimensionSourceCredibility],
                Grade:       scoreToGrade(avg),
                Score:       avg,
                Details:     credibilityDetails(avg),
                RecordTypes: len(agreements),
        }
}

func credibilityDetails(score float64) string {
        grade := scoreToGrade(score)
        switch grade {
        case GradeExcellent:
                return "All resolvers return consistent data — high source credibility"
        case GradeGood:
                return "Most resolvers agree — good source credibility"
        case GradeAdequate:
                return "Some resolver disagreements detected — moderate credibility"
        case GradeDegraded:
                return "Significant resolver disagreements — credibility concerns"
        default:
                return "Resolvers return conflicting data — investigate DNS propagation"
        }
}

func EvaluateTTLRelevance(resolverTTLs map[string]uint32) DimensionScore {
        if len(resolverTTLs) == 0 {
                return DimensionScore{
                        Dimension:   DimensionTTLRelevance,
                        Standard:    DimensionStandards[DimensionTTLRelevance],
                        Grade:       GradeAdequate,
                        Score:       50,
                        Details:     "No TTL data available for relevance analysis",
                        RecordTypes: 0,
                }
        }

        totalScore := 0.0
        evaluated := 0
        var findings []TTLFinding
        for rt, observedTTL := range resolverTTLs {
                typical, ok := typicalTTLs[rt]
                if !ok {
                        continue
                }
                evaluated++
                ratio := float64(observedTTL) / float64(typical)
                switch {
                case ratio >= 0.5 && ratio <= 2.0:
                        totalScore += 100
                case ratio >= 0.1 && ratio <= 5.0:
                        totalScore += 50
                        findings = append(findings, buildTTLFinding(rt, observedTTL, typical, ratio, "medium"))
                default:
                        totalScore += 0
                        findings = append(findings, buildTTLFinding(rt, observedTTL, typical, ratio, "high"))
                }
        }

        if evaluated == 0 {
                return DimensionScore{
                        Dimension:   DimensionTTLRelevance,
                        Standard:    DimensionStandards[DimensionTTLRelevance],
                        Grade:       GradeAdequate,
                        Score:       50,
                        Details:     "No matching record types for TTL relevance comparison",
                        RecordTypes: 0,
                }
        }

        avg := totalScore / float64(evaluated)
        return DimensionScore{
                Dimension:   DimensionTTLRelevance,
                Standard:    DimensionStandards[DimensionTTLRelevance],
                Grade:       scoreToGrade(avg),
                Score:       avg,
                Details:     ttlRelevanceDetails(avg),
                RecordTypes: evaluated,
                Findings:    findings,
        }
}

func buildTTLFinding(recordType string, observed, typical uint32, ratio float64, severity string) TTLFinding {
        recommendation := ttlRecommendation(recordType, observed, typical)

        return TTLFinding{
                RecordType:     recordType,
                ObservedTTL:    observed,
                TypicalTTL:     typical,
                Ratio:          ratio,
                Severity:       severity,
                Standard:       StandardNIST80053SI7,
                Recommendation: recommendation,
        }
}

func ttlRecommendation(recordType string, observed, typical uint32) string {
        if observed < typical {
                return fmt.Sprintf(
                        "%s TTL is below typical — observed %s, typical value is %s. "+
                                "Short TTLs increase DNS query volume but enable faster propagation. "+
                                "If you are preparing for a migration or need rapid failover, this may be intentional (RFC 1035 §3.2.1). "+
                                "For steady-state production, consider %d seconds per "+StandardNIST80053SI7+" relevance guidance. "+
                                "Use the TTL Tuner for profile-specific recommendations.",
                        recordType,
                        formatTTLDuration(observed), formatTTLDuration(typical),
                        typical,
                )
        }
        return fmt.Sprintf(
                "%s TTL is above typical — observed %s, typical value is %s. "+
                        "Long TTLs reduce DNS query volume but slow propagation when records change. "+
                        "Consider %d seconds for a balance of performance and flexibility per "+StandardNIST80053SI7+" relevance guidance.",
                recordType,
                formatTTLDuration(observed), formatTTLDuration(typical),
                typical,
        )
}

func ttlRelevanceDetails(score float64) string {
        grade := scoreToGrade(score)
        switch grade {
        case GradeExcellent:
                return "All observed TTLs are within typical ranges for their record types"
        case GradeGood:
                return "Most TTLs are within expected ranges"
        case GradeAdequate:
                return "Some TTLs deviate from typical ranges — may indicate custom configuration"
        case GradeDegraded:
                return "Multiple TTLs significantly deviate from standards — review DNS configuration"
        default:
                return "TTL values are far outside expected ranges — possible misconfiguration"
        }
}

type CurrencyReportInput struct {
        Records       []RecordCurrency
        ResolverTTLs  map[string]uint32
        AuthTTLs      map[string]uint32
        ObservedTypes map[string]bool
        Agreements    []ResolverAgreement
        ResolverCount int
        DNSProviders  []string
        NSRecords     []string
        SOARaw        string
}

func BuildCurrencyReport(
        records []RecordCurrency,
        resolverTTLs, authTTLs map[string]uint32,
        observedTypes map[string]bool,
        agreements []ResolverAgreement,
        resolverCount int,
) CurrencyReport {
        return BuildCurrencyReportWithProvider(CurrencyReportInput{
                Records:       records,
                ResolverTTLs:  resolverTTLs,
                AuthTTLs:      authTTLs,
                ObservedTypes: observedTypes,
                Agreements:    agreements,
                ResolverCount: resolverCount,
        })
}

func BuildCurrencyReportWithProvider(input CurrencyReportInput) CurrencyReport {
        dims := []DimensionScore{
                EvaluateCurrentness(input.Records),
                EvaluateTTLCompliance(input.ResolverTTLs, input.AuthTTLs),
                EvaluateCompleteness(input.ObservedTypes),
                EvaluateSourceCredibility(input.Agreements),
                EvaluateTTLRelevance(input.ResolverTTLs),
        }

        providerName := DetectDNSProvider(input.DNSProviders, input.NSRecords)

        if providerName != "" {
                for i := range dims {
                        for j := range dims[i].Findings {
                                AnnotateFindingForProvider(&dims[i].Findings[j], providerName)
                        }
                }
        }

        totalScore := 0.0
        for _, d := range dims {
                totalScore += d.Score
        }
        overallScore := totalScore / float64(len(dims))

        report := CurrencyReport{
                OverallGrade:  scoreToGrade(overallScore),
                OverallScore:  overallScore,
                Dimensions:    dims,
                ResolverCount: input.ResolverCount,
                RecordCount:   len(input.Records),
                Guidance:      overallGuidance(overallScore),
                ProviderName:  providerName,
        }

        if input.SOARaw != "" {
                soa := AnalyzeSOACompliance(input.SOARaw, providerName)
                report.SOACompliance = &soa
        }

        report.TrafficEngineering = detectTrafficEngineering(input.ResolverTTLs)

        return report
}

const (
        teThresholdA    uint32 = 120
        teThresholdCore uint32 = 300
        teMinShortTypes int    = 3
)

var teTrafficTypes = []string{"A", "AAAA", "MX", "TXT", "SOA"}

func detectTrafficEngineering(resolverTTLs map[string]uint32) *TrafficEngineeringContext {
        aTTL, hasA := resolverTTLs["A"]
        if !hasA || aTTL > teThresholdA {
                return nil
        }

        shortCount := 0
        for _, rt := range teTrafficTypes {
                if ttl, ok := resolverTTLs[rt]; ok && ttl < teThresholdCore {
                        shortCount++
                }
        }

        if shortCount < teMinShortTypes {
                return nil
        }

        return &TrafficEngineeringContext{
                Detected:   true,
                ShortCount: shortCount,
                Pattern:    "DNS-based Global Server Load Balancing (GSLB)",
                Explanation: fmt.Sprintf(
                        "This domain uses short TTLs across %d record types (A record at %ds), consistent with "+
                                "DNS-based traffic management (GSLB). Enterprises operating large anycast networks "+
                                "intentionally use short TTLs to enable rapid failover, geographic steering, and "+
                                "load distribution. This is a deliberate infrastructure choice, not a misconfiguration. "+
                                "RFC 1035 §3.2.1 permits any TTL value the zone administrator selects. "+
                                "The findings below reflect deviation from typical values for reference, "+
                                "not necessarily actionable recommendations for this class of infrastructure.",
                        shortCount, aTTL,
                ),
        }
}

func overallGuidance(score float64) string {
        grade := scoreToGrade(score)
        switch grade {
        case GradeExcellent:
                return "DNS data is fresh, consistent, and comprehensive — high intelligence currency"
        case GradeGood:
                return "DNS data is mostly current with minor gaps — good intelligence currency"
        case GradeAdequate:
                return "DNS data shows some aging or gaps — consider re-scanning for critical decisions"
        case GradeDegraded:
                return "DNS data currency is degraded — re-scan recommended before making security decisions"
        default:
                return "DNS data may be stale — immediate re-scan strongly recommended"
        }
}
