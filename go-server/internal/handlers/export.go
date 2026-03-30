// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "encoding/json"
        "fmt"
        "log/slog"
        "net/http"
        "time"

        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/dbq"

        "github.com/gin-gonic/gin"
)

type ExportHandler struct {
        DB *db.Database
}

func NewExportHandler(database *db.Database) *ExportHandler {
        return &ExportHandler{DB: database}
}

func (h *ExportHandler) ExportJSON(c *gin.Context) {
        timestamp := time.Now().UTC().Format("20060102_150405")
        filename := fmt.Sprintf("dns_tool_export_%s.ndjson", timestamp)

        c.Header("Content-Type", "application/x-ndjson")
        c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
        c.Status(http.StatusOK)

        ctx := c.Request.Context()
        perPage := int32(100)
        offset := int32(0)

        for {
                analyses, err := h.DB.Queries.ListSuccessfulAnalyses(ctx, dbq.ListSuccessfulAnalysesParams{
                        Limit:  perPage,
                        Offset: offset,
                })
                if err != nil || len(analyses) == 0 {
                        break
                }

                for _, a := range analyses {
                        writeExportRecord(c.Writer, a)
                }

                c.Writer.Flush()

                if len(analyses) < int(perPage) {
                        break
                }
                offset += perPage
        }
}

func buildExportRecord(a dbq.DomainAnalysis) map[string]interface{} {
        var fullResults interface{}
        if len(a.FullResults) > 0 {
                if err := json.Unmarshal(a.FullResults, &fullResults); err != nil {
                        slog.Warn("Export: failed to unmarshal full results", "domain", a.Domain, mapKeyError, err)
                }
        }
        return map[string]interface{}{
                "id":                a.ID,
                "domain":            a.Domain,
                "ascii_domain":      a.AsciiDomain,
                "created_at":        formatTimestampISO(a.CreatedAt),
                "updated_at":        formatTimestampISO(a.UpdatedAt),
                "analysis_duration": a.AnalysisDuration,
                "country_code":      a.CountryCode,
                "country_name":      a.CountryName,
                "full_results":      fullResults,
        }
}

func writeExportRecord(w interface{ Write([]byte) (int, error) }, a dbq.DomainAnalysis) {
        record := buildExportRecord(a)
        line, err := json.Marshal(record)
        if err != nil {
                return
        }
        w.Write(line)
        w.Write([]byte("\n"))
}
