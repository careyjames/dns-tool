// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"dnstool/go-server/internal/config"
	"dnstool/go-server/internal/db"
	"dnstool/go-server/internal/dbq"

	"github.com/gin-gonic/gin"
)

const (
	templateCompare       = "compare.html"
	templateCompareSelect = "compare_select.html"

	mapKeyCompare    = "compare"
	strDomain        = "Domain"
	strFlashmessages = "FlashMessages"
)

type CompareHandler struct {
	DB     *db.Database
	Config *config.Config
}

func NewCompareHandler(database *db.Database, cfg *config.Config) *CompareHandler {
	return &CompareHandler{DB: database, Config: cfg}
}

func formatDiffValue(v interface{}) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

func buildCompareAnalysis(a dbq.DomainAnalysis) CompareAnalysis {
	ca := CompareAnalysis{}
	if a.CreatedAt.Valid {
		ca.CreatedAt = a.CreatedAt.Time.UTC().Format("2006-01-02 15:04:05 UTC")
	}
	if len(a.FullResults) > 0 {
		var fr map[string]interface{}
		if json.Unmarshal(a.FullResults, &fr) == nil {
			if tv, ok := fr["_tool_version"].(string); ok {
				ca.ToolVersion = tv
				ca.HasToolVersion = true
			}
		}
	}
	if a.AnalysisDuration != nil {
		ca.AnalysisDuration = fmt.Sprintf("%.1fs", *a.AnalysisDuration)
		ca.HasDuration = true
	}
	return ca
}

type compareErrorParams struct {
	handler    *CompareHandler
	nonce      interface{}
	csrfToken  interface{}
	tmpl       string
	statusCode int
	message    string
	domain     string
}

func renderCompareError(c *gin.Context, p compareErrorParams) {
	data := gin.H{
		strAppversion:      p.handler.Config.AppVersion,
		strMaintenancenote: p.handler.Config.MaintenanceNote,
		strBetapages:       p.handler.Config.BetaPages,
		strCspnonce:        p.nonce,
		strCsrftoken:       p.csrfToken,
		strActivepage:      mapKeyCompare,
		strFlashmessages:   []FlashMessage{{Category: "danger", Message: p.message}},
	}
	if p.domain != "" {
		data[strDomain] = p.domain
	}
	mergeAuthData(c, p.handler.Config, data)
	c.HTML(p.statusCode, p.tmpl, data)
}

func buildDiffItems(diffs []SectionDiff) ([]DiffItem, int) {
	items := make([]DiffItem, 0, len(diffs))
	changes := 0
	for _, d := range diffs {
		item := DiffItem{
			Label:   d.Label,
			Icon:    d.Icon,
			Changed: d.Changed,
			StatusA: d.StatusA,
			StatusB: d.StatusB,
		}
		if d.Changed {
			changes++
		}
		for _, dc := range d.DetailChanges {
			_, isMapOld := dc.Old.(map[string]interface{})
			item.DetailChanges = append(item.DetailChanges, DiffChange{
				Field:  dc.Field,
				Old:    dc.Old,
				New:    dc.New,
				OldStr: formatDiffValue(dc.Old),
				NewStr: formatDiffValue(dc.New),
				IsMap:  isMapOld,
			})
		}
		items = append(items, item)
	}
	return items, changes
}

func (h *CompareHandler) Compare(c *gin.Context) {
	domain := c.Query("domain")
	idAStr := c.Query("a")
	idBStr := c.Query("b")

	idA, errA := strconv.ParseInt(idAStr, 10, 32)
	idB, errB := strconv.ParseInt(idBStr, 10, 32)

	if errA != nil || errB != nil {
		h.selectDomain(c, domain)
		return
	}

	nonce, _ := c.Get("csp_nonce")
	csrfToken, _ := c.Get("csrf_token")
	ctx := c.Request.Context()

	analysisA, err := h.DB.Queries.GetAnalysisByID(ctx, int32(idA))
	if err != nil {
		renderCompareError(c, compareErrorParams{handler: h, nonce: nonce, csrfToken: csrfToken, tmpl: templateCompare, statusCode: http.StatusNotFound, message: "Analysis A not found"})
		return
	}

	analysisB, err := h.DB.Queries.GetAnalysisByID(ctx, int32(idB))
	if err != nil {
		renderCompareError(c, compareErrorParams{handler: h, nonce: nonce, csrfToken: csrfToken, tmpl: templateCompare, statusCode: http.StatusNotFound, message: "Analysis B not found"})
		return
	}

	if analysisA.Domain != analysisB.Domain {
		renderCompareError(c, compareErrorParams{handler: h, nonce: nonce, csrfToken: csrfToken, tmpl: templateCompareSelect, statusCode: http.StatusBadRequest, message: "Cannot compare analyses of different domains", domain: analysisA.Domain})
		return
	}

	if analysisA.CreatedAt.Valid && analysisB.CreatedAt.Valid {
		if analysisA.CreatedAt.Time.After(analysisB.CreatedAt.Time) {
			analysisA, analysisB = analysisB, analysisA
		}
	}

	resultsA := NormalizeResults(analysisA.FullResults)
	resultsB := NormalizeResults(analysisB.FullResults)

	if resultsA == nil || resultsB == nil {
		renderCompareError(c, compareErrorParams{handler: h, nonce: nonce, csrfToken: csrfToken, tmpl: templateCompareSelect, statusCode: http.StatusBadRequest, message: "One or both analyses have no stored data", domain: analysisA.Domain})
		return
	}

	diffs := ComputeAllDiffs(resultsA, resultsB)
	diffItems, changesFound := buildDiffItems(diffs)

	data := gin.H{
		strAppversion:      h.Config.AppVersion,
		strMaintenancenote: h.Config.MaintenanceNote,
		strBetapages:       h.Config.BetaPages,
		strCspnonce:        nonce,
		strCsrftoken:       csrfToken,
		strActivepage:      mapKeyCompare,
		strDomain:          analysisA.Domain,
		"AnalysisA":        buildCompareAnalysis(analysisA),
		"AnalysisB":        buildCompareAnalysis(analysisB),
		"Diffs":            diffItems,
		"ChangesFound":     changesFound,
	}
	mergeAuthData(c, h.Config, data)
	c.HTML(http.StatusOK, templateCompare, data)
}

func (h *CompareHandler) selectDomain(c *gin.Context, domain string) {
	nonce, _ := c.Get("csp_nonce")
	csrfToken, _ := c.Get("csrf_token")

	if domain == "" {
		emptyData := gin.H{
			strAppversion:      h.Config.AppVersion,
			strMaintenancenote: h.Config.MaintenanceNote,
			strBetapages:       h.Config.BetaPages,
			strCspnonce:        nonce,
			strCsrftoken:       csrfToken,
			strActivepage:      mapKeyCompare,
			strDomain:          "",
			strFlashmessages:   []FlashMessage{{Category: "warning", Message: "Please provide a domain to compare analyses."}},
		}
		mergeAuthData(c, h.Config, emptyData)
		c.HTML(http.StatusOK, templateCompareSelect, emptyData)
		return
	}

	ctx := c.Request.Context()
	analyses, err := h.DB.Queries.ListAnalysesByDomain(ctx, dbq.ListAnalysesByDomainParams{
		Domain: domain,
		Limit:  20,
	})
	if err != nil {
		fetchErrData := gin.H{
			strAppversion:      h.Config.AppVersion,
			strMaintenancenote: h.Config.MaintenanceNote,
			strBetapages:       h.Config.BetaPages,
			strCspnonce:        nonce,
			strCsrftoken:       csrfToken,
			strActivepage:      mapKeyCompare,
			strDomain:          domain,
			strFlashmessages:   []FlashMessage{{Category: "danger", Message: "Failed to fetch analyses"}},
		}
		mergeAuthData(c, h.Config, fetchErrData)
		c.HTML(http.StatusInternalServerError, templateCompareSelect, fetchErrData)
		return
	}

	if len(analyses) == 0 {
		noData := gin.H{
			strAppversion:      h.Config.AppVersion,
			strMaintenancenote: h.Config.MaintenanceNote,
			strBetapages:       h.Config.BetaPages,
			strCspnonce:        nonce,
			strCsrftoken:       csrfToken,
			strActivepage:      mapKeyCompare,
			strDomain:          domain,
			"AnalysisCount":    0,
		}
		mergeAuthData(c, h.Config, noData)
		c.HTML(http.StatusOK, templateCompareSelect, noData)
		return
	}
	if len(analyses) < 2 {
		items := make([]AnalysisItem, 0, len(analyses))
		for _, a := range analyses {
			items = append(items, buildSelectAnalysisItem(a))
		}
		fewData := gin.H{
			strAppversion:      h.Config.AppVersion,
			strMaintenancenote: h.Config.MaintenanceNote,
			strBetapages:       h.Config.BetaPages,
			strCspnonce:        nonce,
			strCsrftoken:       csrfToken,
			strActivepage:      mapKeyCompare,
			strDomain:          domain,
			"Analyses":         items,
			"AnalysisCount":    len(analyses),
		}
		mergeAuthData(c, h.Config, fewData)
		c.HTML(http.StatusOK, templateCompareSelect, fewData)
		return
	}

	items := make([]AnalysisItem, 0, len(analyses))
	for _, a := range analyses {
		items = append(items, buildSelectAnalysisItem(a))
	}

	selectData := gin.H{
		strAppversion:      h.Config.AppVersion,
		strMaintenancenote: h.Config.MaintenanceNote,
		strBetapages:       h.Config.BetaPages,
		strCspnonce:        nonce,
		strCsrftoken:       csrfToken,
		strActivepage:      "",
		strDomain:          domain,
		"Analyses":         items,
	}
	mergeAuthData(c, h.Config, selectData)
	c.HTML(http.StatusOK, templateCompareSelect, selectData)
}

func buildSelectAnalysisItem(a dbq.DomainAnalysis) AnalysisItem {
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
	createdAt := ""
	if a.CreatedAt.Valid {
		createdAt = a.CreatedAt.Time.UTC().Format("2006-01-02 15:04:05 UTC")
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
	return AnalysisItem{
		ID:               a.ID,
		Domain:           a.Domain,
		AsciiDomain:      a.AsciiDomain,
		SpfStatus:        spfStatus,
		DmarcStatus:      dmarcStatus,
		DkimStatus:       dkimStatus,
		AnalysisDuration: dur,
		CreatedAt:        createdAt,
		ToolVersion:      toolVersion,
	}
}
