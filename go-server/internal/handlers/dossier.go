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
	mapKeyDossier = "dossier"
)

const templateDossier = "dossier.html"

type DossierHandler struct {
	DB     *db.Database
	Config *config.Config
}

func NewDossierHandler(database *db.Database, cfg *config.Config) *DossierHandler {
	return &DossierHandler{DB: database, Config: cfg}
}

type dossierItem struct {
	ID               int32
	Domain           string
	AsciiDomain      string
	SpfStatus        string
	DmarcStatus      string
	DkimStatus       string
	AnalysisSuccess  bool
	AnalysisDuration float64
	CreatedDate      string
	CreatedTime      string
	ToolVersion      string
	PostureHash      string
}

func buildDossierItem(a dbq.ListUserAnalysesRow) dossierItem {
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
	if len(a.FullResults) > 0 {
		var fr map[string]interface{}
		if json.Unmarshal(a.FullResults, &fr) == nil {
			if tv, ok := fr["_tool_version"].(string); ok {
				toolVersion = tv
			}
		}
	}
	postureHash := ""
	if a.PostureHash != nil {
		postureHash = *a.PostureHash
	}
	return dossierItem{
		ID:               a.ID,
		Domain:           a.Domain,
		AsciiDomain:      a.AsciiDomain,
		SpfStatus:        spfStatus,
		DmarcStatus:      dmarcStatus,
		DkimStatus:       dkimStatus,
		AnalysisSuccess:  true,
		AnalysisDuration: dur,
		CreatedDate:      createdDate,
		CreatedTime:      createdTime,
		ToolVersion:      toolVersion,
		PostureHash:      postureHash,
	}
}

func buildDossierItemFromSearch(a dbq.SearchUserAnalysesRow) dossierItem {
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
	if len(a.FullResults) > 0 {
		var fr map[string]interface{}
		if json.Unmarshal(a.FullResults, &fr) == nil {
			if tv, ok := fr["_tool_version"].(string); ok {
				toolVersion = tv
			}
		}
	}
	postureHash := ""
	if a.PostureHash != nil {
		postureHash = *a.PostureHash
	}
	return dossierItem{
		ID:               a.ID,
		Domain:           a.Domain,
		AsciiDomain:      a.AsciiDomain,
		SpfStatus:        spfStatus,
		DmarcStatus:      dmarcStatus,
		DkimStatus:       dkimStatus,
		AnalysisSuccess:  true,
		AnalysisDuration: dur,
		CreatedDate:      createdDate,
		CreatedTime:      createdTime,
		ToolVersion:      toolVersion,
		PostureHash:      postureHash,
	}
}

func (h *DossierHandler) Dossier(c *gin.Context) {
	nonce, _ := c.Get("csp_nonce")
	csrfToken, _ := c.Get("csrf_token")

	auth, exists := c.Get("authenticated")
	if !exists || auth != true {
		data := gin.H{
			strAppversion:      h.Config.AppVersion,
			strMaintenancenote: h.Config.MaintenanceNote,
			strBetapages:       h.Config.BetaPages,
			strCspnonce:        nonce,
			strCsrftoken:       csrfToken,
			strActivepage:      mapKeyDossier,
			"RequiresAuth":     true,
			"TotalReports":     int64(0),
			"Analyses":         []dossierItem{},
			"Pagination":       BuildPagination(1, 1, 0),
			"SearchDomain":     "",
		}
		mergeAuthData(c, h.Config, data)
		c.HTML(http.StatusOK, templateDossier, data)
		return
	}

	uid, _ := c.Get("user_id")
	userID, _ := uid.(int32)

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	searchDomain := c.Query("domain")
	perPage := 20

	ctx := c.Request.Context()

	total, err := h.countUserAnalyses(ctx, userID, searchDomain)
	if err != nil {
		errData := gin.H{
			strAppversion:      h.Config.AppVersion,
			strMaintenancenote: h.Config.MaintenanceNote,
			strBetapages:       h.Config.BetaPages,
			strCspnonce:        nonce,
			strCsrftoken:       csrfToken,
			strActivepage:      mapKeyDossier,
			"FlashMessages":    []FlashMessage{{Category: "danger", Message: "Failed to load intelligence reports"}},
		}
		mergeAuthData(c, h.Config, errData)
		c.HTML(http.StatusInternalServerError, templateDossier, errData)
		return
	}

	pagination := NewPagination(page, perPage, total)

	items, err := h.fetchUserAnalyses(ctx, userID, searchDomain, &pagination)
	if err != nil {
		errData := gin.H{
			strAppversion:      h.Config.AppVersion,
			strMaintenancenote: h.Config.MaintenanceNote,
			strBetapages:       h.Config.BetaPages,
			strCspnonce:        nonce,
			strCsrftoken:       csrfToken,
			strActivepage:      mapKeyDossier,
			"FlashMessages":    []FlashMessage{{Category: "danger", Message: "Failed to load tasked collections"}},
		}
		mergeAuthData(c, h.Config, errData)
		c.HTML(http.StatusInternalServerError, templateDossier, errData)
		return
	}

	pd := BuildPagination(page, pagination.TotalPages, total)

	data := gin.H{
		strAppversion:      h.Config.AppVersion,
		strMaintenancenote: h.Config.MaintenanceNote,
		strBetapages:       h.Config.BetaPages,
		strCspnonce:        nonce,
		strCsrftoken:       csrfToken,
		strActivepage:      mapKeyDossier,
		"Analyses":         items,
		"Pagination":       pd,
		"SearchDomain":     searchDomain,
		"TotalReports":     total,
	}
	mergeAuthData(c, h.Config, data)
	c.HTML(http.StatusOK, templateDossier, data)
}

func (h *DossierHandler) countUserAnalyses(ctx context.Context, userID int32, searchDomain string) (int64, error) {
	if searchDomain != "" {
		searchPattern := "%" + searchDomain + "%"
		return h.DB.Queries.CountSearchUserAnalyses(ctx, dbq.CountSearchUserAnalysesParams{
			UserID: userID,
			Domain: searchPattern,
		})
	}
	return h.DB.Queries.CountUserAnalyses(ctx, userID)
}

func (h *DossierHandler) fetchUserAnalyses(ctx context.Context, userID int32, searchDomain string, pagination *PaginationInfo) ([]dossierItem, error) {
	if searchDomain != "" {
		searchPattern := "%" + searchDomain + "%"
		analyses, err := h.DB.Queries.SearchUserAnalyses(ctx, dbq.SearchUserAnalysesParams{
			UserID: userID,
			Domain: searchPattern,
			Limit:  pagination.Limit(),
			Offset: pagination.Offset(),
		})
		if err != nil {
			return nil, err
		}
		items := make([]dossierItem, 0, len(analyses))
		for _, a := range analyses {
			items = append(items, buildDossierItemFromSearch(a))
		}
		return items, nil
	}

	analyses, err := h.DB.Queries.ListUserAnalyses(ctx, dbq.ListUserAnalysesParams{
		UserID: userID,
		Limit:  pagination.Limit(),
		Offset: pagination.Offset(),
	})
	if err != nil {
		return nil, err
	}
	items := make([]dossierItem, 0, len(analyses))
	for _, a := range analyses {
		items = append(items, buildDossierItem(a))
	}
	return items, nil
}
