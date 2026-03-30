// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"mime/multipart"
	"net/http"
	"strings"

	"dnstool/go-server/internal/config"
	"dnstool/go-server/internal/db"
	"dnstool/go-server/internal/dbq"
	"dnstool/go-server/internal/zoneparse"

	"github.com/gin-gonic/gin"
)

const tplZone = "zone.html"

const maxZoneFileSizeAuth = 2 << 20   // 2 MB — authenticated users
const maxZoneFileSizeUnauth = 1 << 20 // 1 MB — non-authenticated users

type ZoneHandler struct {
	DB     *db.Database
	Config *config.Config
}

func NewZoneHandler(database *db.Database, cfg *config.Config) *ZoneHandler {
	return &ZoneHandler{DB: database, Config: cfg}
}

func (h *ZoneHandler) UploadForm(c *gin.Context) {
	nonce, _ := c.Get("csp_nonce")
	csrfToken, _ := c.Get("csrf_token")

	data := gin.H{
		strAppversion:      h.Config.AppVersion,
		strCspnonce:        nonce,
		strCsrftoken:       csrfToken,
		strActivepage:      "zone",
		strShowform:        true,
		strMaintenancenote: h.Config.MaintenanceNote,
		strBetapages:       h.Config.BetaPages,
	}
	mergeAuthData(c, h.Config, data)
	c.HTML(http.StatusOK, tplZone, data)
}

func (h *ZoneHandler) ProcessUpload(c *gin.Context) {
	nonce, _ := c.Get("csp_nonce")
	csrfToken, _ := c.Get("csrf_token")

	uid, _ := c.Get("user_id")
	userID, ok := uid.(int32)
	if !ok {
		userID = 0
	}

	maxSize := int64(maxZoneFileSizeUnauth)
	sizeLabel := "1 MB"
	if userID > 0 {
		maxSize = maxZoneFileSizeAuth
		sizeLabel = "2 MB"
	}

	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxSize+1024)

	file, header, err := c.Request.FormFile("zone_file")
	if err != nil {
		h.renderZoneFlash(c, nonce, csrfToken, mapKeyDanger, "Please select a zone file to upload.")
		return
	}
	defer safeClose(file, "zone file")

	if header.Size > maxSize {
		h.renderZoneFlash(c, nonce, csrfToken, mapKeyDanger, fmt.Sprintf("Zone file exceeds the %s size limit.", sizeLabel))
		return
	}

	domainOverride := strings.TrimSpace(c.PostForm("domain_override"))
	retain := c.PostForm("retain") == "1"

	parseResult, rawData, err := zoneparse.ParseZoneFile(file, domainOverride)
	if err != nil {
		slog.Error("Zone file parse error", mapKeyError, err)
		h.renderZoneFlash(c, nonce, csrfToken, mapKeyDanger, "Failed to parse zone file: "+err.Error())
		return
	}

	if parseResult.RecordCount == 0 {
		h.renderZoneFlash(c, nonce, csrfToken, "warning", "No DNS records found in the uploaded zone file. Verify the file format.")
		return
	}

	domain := parseResult.Domain
	if domain == "" {
		h.renderZoneFlash(c, nonce, csrfToken, mapKeyDanger, "Could not determine the domain from the zone file. Please provide a domain override.")
		return
	}

	ctx := c.Request.Context()
	driftReport, liveAnalysisID := h.compareZoneDrift(ctx, domain, parseResult)
	zoneHealth := zoneparse.AnalyzeHealth(parseResult.Records)

	if retain && userID > 0 {
		h.persistZoneImport(ctx, userID, domain, parseResult, header, rawData, driftReport)
	}

	data := gin.H{
		strAppversion:      h.Config.AppVersion,
		strCspnonce:        nonce,
		strCsrftoken:       csrfToken,
		strActivepage:      "zone",
		strShowform:        false,
		"ShowResults":      true,
		"ParseResult":      parseResult,
		"ZoneHealth":       zoneHealth,
		"DriftReport":      driftReport,
		"LiveAnalysisID":   liveAnalysisID,
		"Filename":         header.Filename,
		"FileSize":         header.Size,
		"Retained":         retain,
		strMaintenancenote: h.Config.MaintenanceNote,
		strBetapages:       h.Config.BetaPages,
	}
	mergeAuthData(c, h.Config, data)
	c.HTML(http.StatusOK, tplZone, data)
}

func (h *ZoneHandler) persistZoneImport(ctx context.Context, userID int32, domain string, parseResult *zoneparse.ParseResult, header *multipart.FileHeader, rawData []byte, driftReport *zoneparse.DriftReport) {
	var driftJSON []byte
	if driftReport != nil {
		var err error
		driftJSON, err = json.Marshal(driftReport)
		if err != nil {
			slog.Warn("Zone: marshal drift report", mapKeyError, err)
		}
	}
	zoneStr := string(rawData)
	_, dbErr := h.DB.Queries.InsertZoneImport(ctx, dbq.InsertZoneImportParams{
		UserID:           userID,
		Domain:           domain,
		Sha256Hash:       parseResult.IntegrityHash,
		OriginalFilename: header.Filename,
		FileSize:         int32(header.Size),
		RecordCount:      int32(parseResult.RecordCount),
		Retained:         true,
		ZoneData:         &zoneStr,
		DriftSummary:     driftJSON,
	})
	if dbErr != nil {
		slog.Error("Failed to store zone import", mapKeyError, dbErr, "domain", domain, "user_id", userID)
	}
}

func (h *ZoneHandler) compareZoneDrift(ctx context.Context, domain string, parseResult *zoneparse.ParseResult) (*zoneparse.DriftReport, int32) {
	analysis, err := h.DB.Queries.GetRecentAnalysisByDomain(ctx, domain)
	if err != nil || len(analysis.FullResults) == 0 {
		return nil, 0
	}
	var liveResults map[string]any
	if json.Unmarshal(analysis.FullResults, &liveResults) != nil {
		return nil, 0
	}
	driftReport := zoneparse.CompareDrift(parseResult.Records, liveResults)
	driftReport.Domain = domain
	return driftReport, analysis.ID
}

func (h *ZoneHandler) renderZoneFlash(c *gin.Context, nonce, csrfToken any, category, message string) {
	data := gin.H{
		strAppversion:      h.Config.AppVersion,
		strCspnonce:        nonce,
		strCsrftoken:       csrfToken,
		strActivepage:      "zone",
		strShowform:        true,
		"FlashMessages":    []FlashMessage{{Category: category, Message: message}},
		strMaintenancenote: h.Config.MaintenanceNote,
		strBetapages:       h.Config.BetaPages,
	}
	mergeAuthData(c, h.Config, data)
	c.HTML(http.StatusOK, tplZone, data)
}
