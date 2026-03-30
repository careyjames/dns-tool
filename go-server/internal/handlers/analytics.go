// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"dnstool/go-server/internal/config"
	"dnstool/go-server/internal/db"

	"github.com/gin-gonic/gin"
)

type AnalyticsHandler struct {
	DB     *db.Database
	Config *config.Config
}

func NewAnalyticsHandler(database *db.Database, cfg *config.Config) *AnalyticsHandler {
	return &AnalyticsHandler{DB: database, Config: cfg}
}

type AnalyticsDay struct {
	Date                  string
	Pageviews             int
	UniqueVisitors        int
	AnalysesRun           int
	UniqueDomainsAnalyzed int
	ReferrerSources       map[string]int
	TopPages              map[string]int
}

type AnalyticsSummary struct {
	TotalPageviews      int64
	TotalUniqueVisitors int64
	TotalAnalyses       int64
	TotalUniqueDomains  int64
	DaysTracked         int
	AvgDailyPageviews   int
	AvgDailyVisitors    int
	TopReferrers        []ReferrerEntry
	TopPages            []PageEntry
}

type ReferrerEntry struct {
	Source string
	Count  int
}

type PageEntry struct {
	Path  string
	Count int
}

func (h *AnalyticsHandler) Dashboard(c *gin.Context) {
	nonce, _ := c.Get("csp_nonce")
	csrfToken, _ := c.Get("csrf_token")
	ctx := c.Request.Context()

	days := h.fetchDailyAnalytics(ctx, 30)
	summary := h.computeSummary(ctx, days)

	data := gin.H{
		keyAppVersion:      h.Config.AppVersion,
		keyMaintenanceNote: h.Config.MaintenanceNote,
		keyBetaPages:       h.Config.BetaPages,
		keyCspNonce:        nonce,
		"CsrfToken":       csrfToken,
		keyActivePage:      "admin",
		"Days":            days,
		"Summary":         summary,
	}
	mergeAuthData(c, h.Config, data)
	c.HTML(http.StatusOK, "admin_analytics.html", data)
}

func (h *AnalyticsHandler) fetchDailyAnalytics(ctx context.Context, limit int) []AnalyticsDay {
	rows, err := h.DB.Pool.Query(ctx,
		`SELECT date, pageviews, unique_visitors, analyses_run, unique_domains_analyzed,
                        COALESCE(referrer_sources, '{}'), COALESCE(top_pages, '{}')
                 FROM site_analytics
                 ORDER BY date DESC LIMIT $1`, limit)
	if err != nil {
		slog.Error("Analytics: failed to fetch daily data", mapKeyError, err)
		return nil
	}
	defer func() { rows.Close() }()

	var days []AnalyticsDay
	for rows.Next() {
		var d AnalyticsDay
		var dateVal time.Time
		var refsJSON, pagesJSON []byte
		if err := rows.Scan(&dateVal, &d.Pageviews, &d.UniqueVisitors, &d.AnalysesRun,
			&d.UniqueDomainsAnalyzed, &refsJSON, &pagesJSON); err != nil {
			slog.Error("Analytics: row scan error", mapKeyError, err)
			continue
		}
		d.Date = dateVal.Format("2006-01-02")
		d.ReferrerSources = make(map[string]int)
		d.TopPages = make(map[string]int)
		if err := json.Unmarshal(refsJSON, &d.ReferrerSources); err != nil {
			slog.Warn("Analytics: unmarshal referrer_sources", mapKeyError, err)
		}
		if err := json.Unmarshal(pagesJSON, &d.TopPages); err != nil {
			slog.Warn("Analytics: unmarshal top_pages", mapKeyError, err)
		}
		days = append(days, d)
	}
	if err := rows.Err(); err != nil {
		slog.Error("Analytics: rows iteration error", mapKeyError, err)
	}
	return days
}

func (h *AnalyticsHandler) computeSummary(ctx context.Context, days []AnalyticsDay) AnalyticsSummary {
	var s AnalyticsSummary
	s.DaysTracked = len(days)

	refTotals := make(map[string]int)
	pageTotals := make(map[string]int)

	for _, d := range days {
		s.TotalPageviews += int64(d.Pageviews)
		s.TotalUniqueVisitors += int64(d.UniqueVisitors)
		s.TotalAnalyses += int64(d.AnalysesRun)
		s.TotalUniqueDomains += int64(d.UniqueDomainsAnalyzed)
		for k, v := range d.ReferrerSources {
			refTotals[k] += v
		}
		for k, v := range d.TopPages {
			pageTotals[k] += v
		}
	}

	if s.DaysTracked > 0 {
		s.AvgDailyPageviews = int(s.TotalPageviews) / s.DaysTracked
		s.AvgDailyVisitors = int(s.TotalUniqueVisitors) / s.DaysTracked
	}

	s.TopReferrers = topN(refTotals, 10)
	s.TopPages = topNPages(pageTotals, 10)

	return s
}

func topN(m map[string]int, n int) []ReferrerEntry {
	var entries []ReferrerEntry
	for k, v := range m {
		entries = append(entries, ReferrerEntry{Source: k, Count: v})
	}
	for i := 0; i < len(entries); i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[j].Count > entries[i].Count {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}
	if len(entries) > n {
		entries = entries[:n]
	}
	return entries
}

func topNPages(m map[string]int, n int) []PageEntry {
	var entries []PageEntry
	for k, v := range m {
		entries = append(entries, PageEntry{Path: k, Count: v})
	}
	for i := 0; i < len(entries); i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[j].Count > entries[i].Count {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}
	if len(entries) > n {
		entries = entries[:n]
	}
	return entries
}
