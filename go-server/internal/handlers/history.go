// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "context"
        "encoding/json"
        "net/http"
        "strconv"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/dbq"

        "github.com/gin-gonic/gin"
)

const (
        templateHistory = "history.html"

        mapKeyHistory = "history"
)

type HistoryHandler struct {
        DB     *db.Database
        Config *config.Config
}

func NewHistoryHandler(database *db.Database, cfg *config.Config) *HistoryHandler {
        return &HistoryHandler{DB: database, Config: cfg}
}

type historyAnalysisItem struct {
        ID               int32
        Domain           string
        AsciiDomain      string
        SpfStatus        string
        DmarcStatus      string
        DkimStatus       string
        AnalysisDuration float64
        CreatedDate      string
        CreatedTime      string
        ToolVersion      string
        RequestSource    string
}

func buildHistoryItem(a dbq.DomainAnalysis) historyAnalysisItem {
        spfStatus := ""
        if a.SpfStatus != nil {
                spfStatus = *a.SpfStatus
        }
        dmarcStatus := ""
        if a.DmarcStatus != nil {
                dmarcStatus = *a.DmarcStatus
        }
        dkimStatus := ""
        if a.DkimStatus != nil {
                dkimStatus = *a.DkimStatus
        }
        dur := 0.0
        if a.AnalysisDuration != nil {
                dur = *a.AnalysisDuration
        }
        createdDate, createdTime := "", ""
        if a.CreatedAt.Valid {
                createdDate = a.CreatedAt.Time.UTC().Format("2 Jan 2006")
                createdTime = a.CreatedAt.Time.UTC().Format("15:04 UTC")
        }
        toolVersion := ""
        requestSource := ""
        if len(a.FullResults) > 0 {
                var fr map[string]interface{}
                if json.Unmarshal(a.FullResults, &fr) == nil {
                        if tv, ok := fr["_tool_version"].(string); ok {
                                toolVersion = tv
                        }
                        if rs, ok := fr["_request_source"].(string); ok {
                                requestSource = rs
                        }
                }
        }
        return historyAnalysisItem{
                ID:               a.ID,
                Domain:           a.Domain,
                AsciiDomain:      a.AsciiDomain,
                SpfStatus:        spfStatus,
                DmarcStatus:      dmarcStatus,
                DkimStatus:       dkimStatus,
                AnalysisDuration: dur,
                CreatedDate:      createdDate,
                CreatedTime:      createdTime,
                ToolVersion:      toolVersion,
                RequestSource:    requestSource,
        }
}

func (h *HistoryHandler) History(c *gin.Context) {
        nonce, _ := c.Get("csp_nonce")      //nolint:errcheck // zero-value fallback for template rendering
        csrfToken, _ := c.Get("csrf_token") //nolint:errcheck // zero-value fallback for template rendering
        page, err := strconv.Atoi(c.DefaultQuery("page", "1"))
        if err != nil {
                page = 1
        }
        if page < 1 {
                page = 1
        }
        searchDomain := c.Query("domain")
        perPage := 20

        ctx := c.Request.Context()

        total, err := h.countAnalyses(ctx, searchDomain)
        if err != nil {
                errData := gin.H{
                        strAppversion:      h.Config.AppVersion,
                        strMaintenancenote: h.Config.MaintenanceNote,
                        strBetapages:       h.Config.BetaPages,
                        strCspnonce:        nonce,
                        strCsrftoken:       csrfToken,
                        strActivepage:      mapKeyHistory,
                        "FlashMessages":    []FlashMessage{{Category: "danger", Message: "Failed to count analyses"}},
                }
                mergeAuthData(c, h.Config, errData)
                c.HTML(http.StatusInternalServerError, templateHistory, errData)
                return
        }

        pagination := NewPagination(page, perPage, total)

        items, err := h.fetchAnalyses(ctx, searchDomain, &pagination)
        if err != nil {
                errData := gin.H{
                        strAppversion:      h.Config.AppVersion,
                        strMaintenancenote: h.Config.MaintenanceNote,
                        strBetapages:       h.Config.BetaPages,
                        strCspnonce:        nonce,
                        strCsrftoken:       csrfToken,
                        strActivepage:      mapKeyHistory,
                        "FlashMessages":    []FlashMessage{{Category: "danger", Message: "Failed to fetch analyses"}},
                }
                mergeAuthData(c, h.Config, errData)
                c.HTML(http.StatusInternalServerError, templateHistory, errData)
                return
        }

        pd := BuildPagination(page, pagination.TotalPages, total)

        data := gin.H{
                strAppversion:      h.Config.AppVersion,
                strMaintenancenote: h.Config.MaintenanceNote,
                strBetapages:       h.Config.BetaPages,
                strCspnonce:        nonce,
                strCsrftoken:       csrfToken,
                strActivepage:      mapKeyHistory,
                "Analyses":         items,
                "Pagination":       pd,
                "SearchDomain":     searchDomain,
        }
        mergeAuthData(c, h.Config, data)
        c.HTML(http.StatusOK, templateHistory, data)
}

func (h *HistoryHandler) countAnalyses(ctx context.Context, searchDomain string) (int64, error) {
        if searchDomain != "" {
                searchPattern := "%" + searchDomain + "%"
                return h.DB.Queries.CountSearchSuccessfulAnalyses(ctx, searchPattern)
        }
        return h.DB.Queries.CountSuccessfulAnalyses(ctx)
}

func (h *HistoryHandler) fetchAnalyses(ctx context.Context, searchDomain string, pagination *PaginationInfo) ([]historyAnalysisItem, error) {
        var analyses []dbq.DomainAnalysis
        var err error

        if searchDomain != "" {
                searchPattern := "%" + searchDomain + "%"
                analyses, err = h.DB.Queries.SearchSuccessfulAnalyses(ctx, dbq.SearchSuccessfulAnalysesParams{
                        Domain: searchPattern,
                        Limit:  pagination.Limit(),
                        Offset: pagination.Offset(),
                })
        } else {
                analyses, err = h.DB.Queries.ListSuccessfulAnalyses(ctx, dbq.ListSuccessfulAnalysesParams{
                        Limit:  pagination.Limit(),
                        Offset: pagination.Offset(),
                })
        }
        if err != nil {
                return nil, err
        }

        items := make([]historyAnalysisItem, 0, len(analyses))
        for _, a := range analyses {
                items = append(items, buildHistoryItem(a))
        }
        return items, nil
}
