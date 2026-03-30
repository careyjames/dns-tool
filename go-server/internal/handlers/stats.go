// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "encoding/hex"
        "encoding/json"
        "log/slog"
        "net/http"
        "os"
        "strings"
        "sync"
        "time"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/dbq"

        "github.com/gin-gonic/gin"
        "golang.org/x/crypto/sha3"
)

type EDEAmendment struct {
        Ground        string `json:"ground"`
        Date          string `json:"date"`
        FieldChanged  string `json:"field_changed"`
        OriginalValue string `json:"original_value"`
        CorrectedTo   string `json:"corrected_to"`
        Evidence      string `json:"evidence"`
        Rationale     string `json:"rationale"`
        Justification string `json:"justification"`
}

type IntegrityEvent struct {
        ID                  string         `json:"id"`
        Date                string         `json:"date"`
        Commit              string         `json:"commit"`
        Category            string         `json:"category"`
        Severity            string         `json:"severity"`
        Title               string         `json:"title"`
        Status              string         `json:"status"`
        Attribution         string         `json:"attribution"`
        ProtocolsAffected   []string       `json:"protocols_affected"`
        ConfidenceImpact    string         `json:"confidence_impact"`
        Resolution          string         `json:"resolution"`
        BayesianNote        string         `json:"bayesian_note"`
        CorrectionAction    string         `json:"correction_action"`
        PreventionRule      string         `json:"prevention_rule"`
        AuthoritativeSource string         `json:"authoritative_source"`
        Amendments          []EDEAmendment `json:"amendments,omitempty"`
        EventHash           string         `json:"-"`
}

type IntegritySummary struct {
        TotalEvents              int      `json:"total_events"`
        Open                     int      `json:"open"`
        Closed                   int      `json:"closed"`
        LastEventDate            string   `json:"last_event_date"`
        ConfidenceRecalibrations int      `json:"confidence_recalibrations"`
        ProtocolsAffected        []string `json:"protocols_affected"`
}

type TamperResistancePolicy struct {
        Enabled       bool   `json:"enabled"`
        Effective     string `json:"effective"`
        Standard      string `json:"standard"`
        AmendmentRule string `json:"amendment_rule"`
}

type IntegrityData struct {
        Summary               IntegritySummary       `json:"summary"`
        Events                []IntegrityEvent       `json:"events"`
        Taxonomy              map[string]string      `json:"taxonomy"`
        TamperResistancePolicy TamperResistancePolicy `json:"tamper_resistance_policy"`
        SHA3Hash              string                 `json:"-"`
}

var (
        integrityCache     IntegrityData
        integrityCacheMu   sync.RWMutex
        integrityCacheTime time.Time
)

func loadIntegrityData() IntegrityData {
        integrityCacheMu.RLock()
        if !integrityCacheTime.IsZero() && time.Since(integrityCacheTime) < 5*time.Minute {
                cached := integrityCache
                integrityCacheMu.RUnlock()
                return cached
        }
        integrityCacheMu.RUnlock()

        integrityCacheMu.Lock()
        defer integrityCacheMu.Unlock()

        if !integrityCacheTime.IsZero() && time.Since(integrityCacheTime) < 5*time.Minute {
                return integrityCache
        }

        data, err := os.ReadFile("static/data/integrity_stats.json")
        if err != nil {
                slog.Warn("Stats: failed to read integrity_stats.json", mapKeyError, err)
                return IntegrityData{}
        }
        hash := sha3.Sum512(data)
        hashHex := hex.EncodeToString(hash[:])

        var f IntegrityData
        if err := json.Unmarshal(data, &f); err != nil {
                slog.Warn("Stats: failed to parse integrity_stats.json", mapKeyError, err)
                return IntegrityData{}
        }
        f.SHA3Hash = hashHex
        for i := range f.Events {
                redactDignityAmendments(&f.Events[i])
                hashEvent(&f.Events[i])
        }
        for i, j := 0, len(f.Events)-1; i < j; i, j = i+1, j-1 {
                f.Events[i], f.Events[j] = f.Events[j], f.Events[i]
        }
        integrityCache = f
        integrityCacheTime = time.Now()
        return f
}

func redactDignityAmendments(event *IntegrityEvent) {
        for j := range event.Amendments {
                if event.Amendments[j].Ground == "DIGNITY_OF_EXPRESSION" &&
                        event.Amendments[j].OriginalValue != "[REDACTED — DIGNITY_OF_EXPRESSION]" {
                        event.Amendments[j].OriginalValue = "[REDACTED — DIGNITY_OF_EXPRESSION]"
                }
        }
}

func hashEvent(event *IntegrityEvent) {
        eventJSON, err := json.Marshal(event)
        if err == nil {
                eh := sha3.Sum512(eventJSON)
                event.EventHash = hex.EncodeToString(eh[:])
        }
}

type StatsHandler struct {
        DB     *db.Database
        Config *config.Config
}

func NewStatsHandler(database *db.Database, cfg *config.Config) *StatsHandler {
        return &StatsHandler{DB: database, Config: cfg}
}

func (h *StatsHandler) Stats(c *gin.Context) {
        nonce, _ := c.Get("csp_nonce")
        csrfToken, _ := c.Get("csrf_token")
        ctx := c.Request.Context()

        recentStats, err := h.DB.Queries.ListRecentStats(ctx, 30)
        if err != nil {
                errData := gin.H{
                        keyAppVersion:      h.Config.AppVersion,
                        keyMaintenanceNote: h.Config.MaintenanceNote,
                        keyBetaPages:       h.Config.BetaPages,
                        keyCspNonce:        nonce,
                        "CsrfToken":       csrfToken,
                        keyActivePage:      "stats",
                        "FlashMessages":   []FlashMessage{{Category: "danger", Message: "Failed to fetch stats"}},
                }
                mergeAuthData(c, h.Config, errData)
                c.HTML(http.StatusInternalServerError, "stats.html", errData)
                return
        }

        statsSummary, err := h.DB.Queries.SumAnalysisStats(ctx)
        if err != nil {
                slog.Warn("Stats: failed to sum analysis stats", mapKeyError, err)
        }
        totalAnalyses := statsSummary.Total
        successfulAnalyses := statsSummary.Successful
        failedAnalyses := statsSummary.Failed
        uniqueDomains, err := h.DB.Queries.CountUniqueDomainsTotal(ctx)
        if err != nil {
                slog.Warn("Stats: failed to count unique domains", mapKeyError, err)
        }

        popularDomains, err := h.DB.Queries.ListPopularDomains(ctx, 10)
        if err != nil {
                slog.Warn("Stats: failed to list popular domains", mapKeyError, err)
        }
        countryStats, err := h.DB.Queries.ListCountryDistribution(ctx, 20)
        if err != nil {
                slog.Warn("Stats: failed to list country distribution", mapKeyError, err)
        }

        maxRecentStats := 7
        if len(recentStats) < maxRecentStats {
                maxRecentStats = len(recentStats)
        }
        slicedStats := recentStats[:maxRecentStats]

        statItems := make([]DailyStat, 0, len(slicedStats))
        for _, s := range slicedStats {
                statItems = append(statItems, buildDailyStat(s))
        }

        popItems := make([]PopularDomain, 0, len(popularDomains))
        for _, d := range popularDomains {
                popItems = append(popItems, PopularDomain{Domain: d.Domain, Count: d.Count})
        }

        countryItems := make([]CountryStat, 0, len(countryStats))
        for _, cs := range countryStats {
                countryItems = append(countryItems, buildCountryStat(cs))
        }

        remediatedDomains, err := h.DB.Queries.CountRemediatedDomains(ctx)
        if err != nil {
                slog.Warn("Stats: failed to count remediated domains", mapKeyError, err)
        }

        var uniqueVisitors int64
        err = h.DB.Pool.QueryRow(ctx,
                `SELECT COALESCE(SUM(unique_visitors), 0) FROM site_analytics`).Scan(&uniqueVisitors)
        if err != nil {
                slog.Warn("Stats: failed to sum unique visitors", mapKeyError, err)
        }

        integrityData := loadIntegrityData()

        data := gin.H{
                keyAppVersion:         h.Config.AppVersion,
                keyMaintenanceNote:    h.Config.MaintenanceNote,
                keyBetaPages:          h.Config.BetaPages,
                keyCspNonce:           nonce,
                "CsrfToken":          csrfToken,
                keyActivePage:         "stats",
                "TotalAnalyses":      totalAnalyses,
                "SuccessfulAnalyses": successfulAnalyses,
                "FailedAnalyses":     failedAnalyses,
                "UniqueDomains":      uniqueDomains,
                "UniqueVisitors":     uniqueVisitors,
                "CountryStats":       countryItems,
                "PopularDomains":     popItems,
                "RecentStats":        statItems,
                "RemediatedDomains":  remediatedDomains,
                "IntegrityData":      integrityData,
        }
        mergeAuthData(c, h.Config, data)
        c.HTML(http.StatusOK, "stats.html", data)
}

func buildDailyStat(s dbq.AnalysisStat) DailyStat {
        dateStr := ""
        if s.Date.Valid {
                dateStr = s.Date.Time.Format("01/02")
        }
        var total, successful, failed, unique int32
        if s.TotalAnalyses != nil {
                total = *s.TotalAnalyses
        }
        if s.SuccessfulAnalyses != nil {
                successful = *s.SuccessfulAnalyses
        }
        if s.FailedAnalyses != nil {
                failed = *s.FailedAnalyses
        }
        if s.UniqueDomains != nil {
                unique = *s.UniqueDomains
        }
        var avg float64
        hasAvg := false
        if s.AvgAnalysisTime != nil {
                avg = *s.AvgAnalysisTime
                hasAvg = true
        }
        return DailyStat{
                Date:               dateStr,
                TotalAnalyses:      total,
                SuccessfulAnalyses: successful,
                FailedAnalyses:     failed,
                UniqueDomains:      unique,
                AvgAnalysisTime:    avg,
                HasAvgTime:         hasAvg,
        }
}

func buildCountryStat(cs dbq.ListCountryDistributionRow) CountryStat {
        code, name := "", ""
        if cs.CountryCode != nil {
                code = *cs.CountryCode
        }
        if cs.CountryName != nil {
                name = *cs.CountryName
        }
        flag := ""
        if len(code) == 2 {
                upper := strings.ToUpper(code)
                r1 := rune(0x1F1E6 + int(upper[0]) - int('A'))
                r2 := rune(0x1F1E6 + int(upper[1]) - int('A'))
                flag = string([]rune{r1, r2})
        }
        return CountryStat{Code: code, Name: name, Count: cs.Count, Flag: flag}
}

func (h *StatsHandler) StatisticsRedirect(c *gin.Context) {
        c.Redirect(http.StatusFound, "/stats")
}
