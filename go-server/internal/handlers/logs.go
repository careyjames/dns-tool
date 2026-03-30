// dns-tool:scrutiny design
package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"dnstool/go-server/internal/config"
	"dnstool/go-server/internal/db"
	"dnstool/go-server/internal/dbq"
	"dnstool/go-server/internal/middleware"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgtype"
)

type LogsHandler struct {
	DB     *db.Database
	Config *config.Config
}

func NewLogsHandler(database *db.Database, cfg *config.Config) *LogsHandler {
	return &LogsHandler{DB: database, Config: cfg}
}

func parseTimeFilter(val string) pgtype.Timestamp {
	if val == "" {
		return pgtype.Timestamp{}
	}
	for _, layout := range []string{
		"2006-01-02T15:04",
		"2006-01-02T15:04:05",
		"2006-01-02",
	} {
		if t, err := time.Parse(layout, val); err == nil {
			return pgtype.Timestamp{Time: t, Valid: true}
		}
	}
	return pgtype.Timestamp{}
}

func buildLogParams(c *gin.Context, maxRows int32) dbq.ListSystemLogsParams {
	levelFilter := c.Query("level")
	categoryFilter := c.Query("category")
	domainFilter := c.Query("domain")
	traceFilter := c.Query("trace_id")
	afterStr := c.Query("after")
	beforeStr := c.Query("before")

	params := dbq.ListSystemLogsParams{
		MaxRows:  maxRows,
		AfterTs:  parseTimeFilter(afterStr),
		BeforeTs: parseTimeFilter(beforeStr),
	}
	if levelFilter != "" {
		params.Level = &levelFilter
	}
	if categoryFilter != "" {
		params.Category = &categoryFilter
	}
	if domainFilter != "" {
		params.DomainFilter = &domainFilter
	}
	if traceFilter != "" {
		params.TraceIDFilter = &traceFilter
	}
	return params
}

func (h *LogsHandler) Dashboard(c *gin.Context) {
	ctx := c.Request.Context()

	params := buildLogParams(c, 200)

	logs, err := h.DB.Queries.ListSystemLogs(ctx, params)
	if err != nil {
		logs = nil
	}

	totalCount, _ := h.DB.Queries.CountSystemLogs(ctx)
	levelCounts, _ := h.DB.Queries.GetLogLevelCounts(ctx)
	recentEvents, _ := h.DB.Queries.GetRecentLogEvents(ctx)

	type logEntry struct {
		ID        int32  `json:"id"`
		Timestamp string `json:"timestamp"`
		Level     string `json:"level"`
		Message   string `json:"message"`
		Event     string `json:"event"`
		Category  string `json:"category"`
		Domain    string `json:"domain"`
		TraceID   string `json:"trace_id"`
		AttrsJSON string `json:"attrs"`
	}

	entries := make([]logEntry, 0, len(logs))
	for _, l := range logs {
		ts := ""
		if l.Timestamp.Valid {
			ts = l.Timestamp.Time.Format("2006-01-02 15:04:05")
		}
		attrsStr := "{}"
		if len(l.Attrs) > 0 {
			var pretty map[string]any
			if json.Unmarshal(l.Attrs, &pretty) == nil {
				if b, err := json.MarshalIndent(pretty, "", "  "); err == nil {
					attrsStr = string(b)
				}
			}
		}
		entries = append(entries, logEntry{
			ID:        l.ID,
			Timestamp: ts,
			Level:     l.Level,
			Message:   l.Message,
			Event:     l.Event,
			Category:  l.Category,
			Domain:    l.Domain,
			TraceID:   l.TraceID,
			AttrsJSON: attrsStr,
		})
	}

	nonce, _ := c.Get("csp_nonce")
	csrfToken, _ := c.Get("csrf_token")
	data := gin.H{
		keyAppVersion:      h.Config.AppVersion,
		keyMaintenanceNote: h.Config.MaintenanceNote,
		keyBetaPages:       h.Config.BetaPages,
		keyCspNonce:        nonce,
		"CsrfToken":       csrfToken,
		keyActivePage:      "ops",
		"Logs":            entries,
		"TotalCount":      totalCount,
		"LevelCounts":     levelCounts,
		"RecentEvents":    recentEvents,
		"FilterLevel":     c.Query("level"),
		"FilterCategory":  c.Query("category"),
		"FilterDomain":    c.Query("domain"),
		"FilterTraceID":   c.Query("trace_id"),
		"FilterAfter":     c.Query("after"),
		"FilterBefore":    c.Query("before"),
	}
	for k, v := range middleware.GetAuthTemplateData(c) {
		data[k] = v
	}
	c.HTML(http.StatusOK, "admin_logs.html", data)
}

func (h *LogsHandler) ExportJSONL(c *gin.Context) {
	ctx := c.Request.Context()

	params := buildLogParams(c, 5000)

	logs, err := h.DB.Queries.ListSystemLogs(ctx, params)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query logs"})
		return
	}

	c.Header("Content-Type", "application/x-ndjson")
	c.Header("Content-Disposition", "attachment; filename=dns-tool-logs.jsonl")

	writer := c.Writer
	for _, l := range logs {
		ts := ""
		if l.Timestamp.Valid {
			ts = l.Timestamp.Time.Format("2006-01-02T15:04:05Z")
		}
		var attrs map[string]any
		if len(l.Attrs) > 0 {
			json.Unmarshal(l.Attrs, &attrs)
		}
		entry := map[string]any{
			"id":        l.ID,
			"timestamp": ts,
			"level":     l.Level,
			"message":   l.Message,
			"event":     l.Event,
			"category":  l.Category,
			"domain":    l.Domain,
			"trace_id":  l.TraceID,
			"attrs":     attrs,
		}
		line, err := json.Marshal(entry)
		if err != nil {
			continue
		}
		writer.Write(line)
		writer.Write([]byte("\n"))
	}
}
