// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"dnstool/go-server/internal/config"
	"dnstool/go-server/internal/db"
	"dnstool/go-server/internal/dbq"

	"github.com/gin-gonic/gin"
)

type FailuresHandler struct {
	DB     *db.Database
	Config *config.Config
}

func NewFailuresHandler(database *db.Database, cfg *config.Config) *FailuresHandler {
	return &FailuresHandler{DB: database, Config: cfg}
}

type FailureEntry struct {
	Domain    string
	Category  string
	Icon      string
	Timestamp string
	TimeAgo   string
}

func timeAgo(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		m := int(d.Minutes())
		if m == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", m)
	case d < 24*time.Hour:
		h := int(d.Hours())
		if h == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", h)
	default:
		days := int(d.Hours() / 24)
		if days == 1 {
			return "1 day ago"
		}
		return fmt.Sprintf("%d days ago", days)
	}
}

var ipPattern = regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?`)
var pathPattern = regexp.MustCompile(`/[a-zA-Z0-9_/.]+`)

type errorCategory struct {
	keywords []string
	label    string
	icon     string
}

var errorCategories = []errorCategory{
	{[]string{"timeout", "timed out", "deadline"}, "DNS Resolution Timeout", "clock"},
	{[]string{"no such host", "nxdomain", "not found"}, "Domain Not Found (NXDOMAIN)", "unlink"},
	{[]string{"connection refused", "connection reset"}, "Connection Refused", "ban"},
	{[]string{"servfail", "server failure"}, "DNS Server Failure (SERVFAIL)", "server"},
	{[]string{"network", "unreachable"}, "Network Unreachable", "wifi"},
	{[]string{"tls", "certificate", "x509"}, "TLS/Certificate Error", "lock"},
	{[]string{"refused"}, "Query Refused", "hand-paper"},
	{[]string{"rate limit", "throttl"}, "Rate Limited", "tachometer-alt"},
	{[]string{"invalid", "malformed"}, "Invalid Input", "exclamation-triangle"},
}

func matchErrorCategory(msg string) (string, string, bool) {
	for _, cat := range errorCategories {
		for _, kw := range cat.keywords {
			if strings.Contains(msg, kw) {
				return cat.label, cat.icon, true
			}
		}
	}
	return "", "", false
}

func sanitizeErrorMessage(raw *string) (string, string) {
	if raw == nil || *raw == "" {
		return "Unknown Error", "question-circle"
	}
	msg := strings.ToLower(*raw)

	if label, icon, ok := matchErrorCategory(msg); ok {
		return label, icon
	}

	cleaned := ipPattern.ReplaceAllString(*raw, "[redacted]")
	cleaned = pathPattern.ReplaceAllString(cleaned, "[path]")
	if len(cleaned) > 80 {
		cleaned = cleaned[:77] + "..."
	}
	return "Analysis Error: " + cleaned, "exclamation-circle"
}

func (h *FailuresHandler) Failures(c *gin.Context) {
	nonce, _ := c.Get("csp_nonce")
	csrfToken, _ := c.Get("csrf_token")
	ctx := c.Request.Context()

	aggregateStats, _ := h.DB.Queries.SumAnalysisStats(ctx)
	statsFailedCount := aggregateStats.Failed

	storedCount, _ := h.DB.Queries.CountAllAnalyses(ctx)
	totalAll := storedCount + statsFailedCount

	failures, err := h.DB.Queries.ListFailedAnalyses(ctx, dbq.ListFailedAnalysesParams{
		Limit:  50,
		Offset: 0,
	})
	if err != nil {
		errData := gin.H{
			keyAppVersion:      h.Config.AppVersion,
			keyMaintenanceNote: h.Config.MaintenanceNote,
			keyBetaPages:       h.Config.BetaPages,
			keyCspNonce:        nonce,
			"CsrfToken":       csrfToken,
			keyActivePage:      "failures",
			"FlashMessages":   []FlashMessage{{Category: "danger", Message: "Failed to fetch failure log"}},
		}
		mergeAuthData(c, h.Config, errData)
		c.HTML(http.StatusInternalServerError, "failures.html", errData)
		return
	}

	entries := make([]FailureEntry, 0, len(failures))
	for _, f := range failures {
		category, icon := sanitizeErrorMessage(f.ErrorMessage)
		ts := ""
		ago := ""
		if f.CreatedAt.Valid {
			ts = f.CreatedAt.Time.Format("2006-01-02 15:04 UTC")
			ago = timeAgo(f.CreatedAt.Time)
		}
		entries = append(entries, FailureEntry{
			Domain:    f.Domain,
			Category:  category,
			Icon:      icon,
			Timestamp: ts,
			TimeAgo:   ago,
		})
	}

	var failureRate float64
	if totalAll > 0 {
		failureRate = float64(statsFailedCount) / float64(totalAll) * 100
	}

	data := gin.H{
		keyAppVersion:      h.Config.AppVersion,
		keyMaintenanceNote: h.Config.MaintenanceNote,
		keyBetaPages:       h.Config.BetaPages,
		keyCspNonce:        nonce,
		"CsrfToken":       csrfToken,
		keyActivePage:      "failures",
		"Failures":        entries,
		"TotalFailed":     statsFailedCount,
		"TotalAnalyses":   totalAll,
		"FailureRate":     failureRate,
	}
	mergeAuthData(c, h.Config, data)
	c.HTML(http.StatusOK, "failures.html", data)
}
