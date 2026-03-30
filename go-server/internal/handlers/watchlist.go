// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.

// dns-tool:scrutiny design
package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"dnstool/go-server/internal/config"
	"dnstool/go-server/internal/db"
	"dnstool/go-server/internal/dbq"
	"dnstool/go-server/internal/notifier"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgtype"
)

const (
	templateWatchlist   = "watchlist.html"
	maxWatchlistEntries = 25
	timeFormatDisplay   = "2 Jan 2006 15:04 UTC"
	pathWatchlist       = "/watchlist"

	mapKeyDaily = "daily"
)

type WatchlistHandler struct {
	DB       *db.Database
	Config   *config.Config
	Notifier *notifier.Notifier
}

func NewWatchlistHandler(database *db.Database, cfg *config.Config) *WatchlistHandler {
	return &WatchlistHandler{
		DB:       database,
		Config:   cfg,
		Notifier: notifier.New(database.Queries),
	}
}

type watchlistItem struct {
	ID        int32
	Domain    string
	Cadence   string
	Enabled   bool
	LastRunAt string
	NextRunAt string
	CreatedAt string
}

type endpointItem struct {
	ID           int32
	EndpointType string
	URL          string
	MaskedURL    string
	Enabled      bool
	CreatedAt    string
}

func maskURL(u string) string {
	if len(u) <= 30 {
		return u
	}
	return u[:20] + "..." + u[len(u)-10:]
}

func cadenceToNextRun(cadence string) pgtype.Timestamp {
	var d time.Duration
	switch cadence {
	case "hourly":
		d = time.Hour
	case mapKeyDaily:
		d = 24 * time.Hour
	case "weekly":
		d = 7 * 24 * time.Hour
	default:
		d = 24 * time.Hour
	}
	return pgtype.Timestamp{Time: time.Now().UTC().Add(d), Valid: true}
}

func (h *WatchlistHandler) baseTmplData(c *gin.Context) gin.H {
	nonce := c.MustGet("csp_nonce")
	csrfToken := c.MustGet("csrf_token")
	data := gin.H{
		keyAppVersion:      h.Config.AppVersion,
		keyMaintenanceNote: h.Config.MaintenanceNote,
		keyBetaPages:       h.Config.BetaPages,
		keyCspNonce:        nonce,
		"CsrfToken":       csrfToken,
		keyActivePage:      "watchlist",
	}
	mergeAuthData(c, h.Config, data)
	return data
}

func (h *WatchlistHandler) Watchlist(c *gin.Context) {
	uid, _ := c.Get(mapKeyUserId)
	userID, ok := uid.(int32)
	if !ok || userID == 0 {
		h.renderUnauthenticatedWatchlist(c)
		return
	}

	ctx := c.Request.Context()

	entries, err := h.DB.Queries.ListWatchlistByUser(ctx, userID)
	if err != nil {
		slog.Error("Failed to load watchlist", mapKeyUserId, userID, mapKeyError, err)
		data := h.baseTmplData(c)
		data["FlashMessages"] = []FlashMessage{{Category: "danger", Message: "Failed to load watchlist."}}
		c.HTML(http.StatusInternalServerError, templateWatchlist, data)
		return
	}

	items := convertWatchlistEntries(entries)
	eps := h.loadEndpoints(ctx, userID)

	data := h.baseTmplData(c)
	data["WatchlistItems"] = items
	data["Endpoints"] = eps
	data["WatchlistCount"] = len(items)
	data["MaxWatchlist"] = maxWatchlistEntries
	c.HTML(http.StatusOK, templateWatchlist, data)
}

func (h *WatchlistHandler) renderUnauthenticatedWatchlist(c *gin.Context) {
	data := h.baseTmplData(c)
	data["FlashMessages"] = []FlashMessage{{Category: "warning", Message: "Sign in to manage your watchlist."}}
	data["WatchlistItems"] = []watchlistItem{}
	data["Endpoints"] = []endpointItem{}
	data["WatchlistCount"] = 0
	data["MaxWatchlist"] = maxWatchlistEntries
	c.HTML(http.StatusOK, templateWatchlist, data)
	if !c.Writer.Written() {
		slog.Error("Watchlist template produced no output — possible execution error")
	} else {
		slog.Debug("Watchlist rendered", "size", c.Writer.Size())
	}
}

func convertWatchlistEntries(entries []dbq.DomainWatchlist) []watchlistItem {
	items := make([]watchlistItem, 0, len(entries))
	for _, e := range entries {
		wi := watchlistItem{
			ID:      e.ID,
			Domain:  e.Domain,
			Cadence: e.Cadence,
			Enabled: e.Enabled,
		}
		if e.LastRunAt.Valid {
			wi.LastRunAt = e.LastRunAt.Time.Format(timeFormatDisplay)
		}
		if e.NextRunAt.Valid {
			wi.NextRunAt = e.NextRunAt.Time.Format(timeFormatDisplay)
		}
		if e.CreatedAt.Valid {
			wi.CreatedAt = e.CreatedAt.Time.Format(timeFormatDisplay)
		}
		items = append(items, wi)
	}
	return items
}

func (h *WatchlistHandler) loadEndpoints(ctx context.Context, userID int32) []endpointItem {
	endpoints, err := h.DB.Queries.ListNotificationEndpointsByUser(ctx, userID)
	if err != nil {
		slog.Error("Failed to load endpoints", mapKeyUserId, userID, mapKeyError, err)
	}
	eps := make([]endpointItem, 0, len(endpoints))
	for _, ep := range endpoints {
		ei := endpointItem{
			ID:           ep.ID,
			EndpointType: ep.EndpointType,
			URL:          ep.Url,
			MaskedURL:    maskURL(ep.Url),
			Enabled:      ep.Enabled,
		}
		if ep.CreatedAt.Valid {
			ei.CreatedAt = ep.CreatedAt.Time.Format(timeFormatDisplay)
		}
		eps = append(eps, ei)
	}
	return eps
}

func (h *WatchlistHandler) AddDomain(c *gin.Context) {
	uid, _ := c.Get(mapKeyUserId)
	userID, ok := uid.(int32)
	if !ok || userID == 0 {
		c.Redirect(http.StatusSeeOther, pathWatchlist)
		return
	}

	domain := strings.TrimSpace(strings.ToLower(c.PostForm("domain")))
	cadence := c.PostForm("cadence")
	if domain == "" {
		c.Redirect(http.StatusSeeOther, pathWatchlist)
		return
	}
	if cadence != "hourly" && cadence != mapKeyDaily && cadence != "weekly" {
		cadence = mapKeyDaily
	}

	ctx := c.Request.Context()

	count, err := h.DB.Queries.CountWatchlistByUser(ctx, userID)
	if err != nil {
		slog.Error("Failed to count watchlist", mapKeyError, err)
		c.Redirect(http.StatusSeeOther, pathWatchlist)
		return
	}
	if count >= int64(maxWatchlistEntries) {
		c.Redirect(http.StatusSeeOther, pathWatchlist)
		return
	}

	_, err = h.DB.Queries.InsertWatchlistEntry(ctx, dbq.InsertWatchlistEntryParams{
		UserID:    userID,
		Domain:    domain,
		Cadence:   cadence,
		NextRunAt: cadenceToNextRun(cadence),
	})
	if err != nil {
		slog.Error("Failed to add watchlist entry", mapKeyUserId, userID, "domain", domain, mapKeyError, err)
	}

	c.Redirect(http.StatusSeeOther, pathWatchlist)
}

func (h *WatchlistHandler) RemoveDomain(c *gin.Context) {
	uid, _ := c.Get(mapKeyUserId)
	userID, ok := uid.(int32)
	if !ok || userID == 0 {
		c.Redirect(http.StatusSeeOther, pathWatchlist)
		return
	}

	idStr := c.Param("id")
	entryID, err := strconv.Atoi(idStr)
	if err != nil {
		c.Redirect(http.StatusSeeOther, pathWatchlist)
		return
	}

	ctx := c.Request.Context()
	if err := h.DB.Queries.DeleteWatchlistEntry(ctx, dbq.DeleteWatchlistEntryParams{
		ID:     int32(entryID),
		UserID: userID,
	}); err != nil {
		slog.Error("Failed to delete watchlist entry", "id", entryID, mapKeyError, err)
	}

	c.Redirect(http.StatusSeeOther, pathWatchlist)
}

func (h *WatchlistHandler) ToggleDomain(c *gin.Context) {
	uid, _ := c.Get(mapKeyUserId)
	userID, ok := uid.(int32)
	if !ok || userID == 0 {
		c.Redirect(http.StatusSeeOther, pathWatchlist)
		return
	}

	idStr := c.Param("id")
	entryID, err := strconv.Atoi(idStr)
	if err != nil {
		c.Redirect(http.StatusSeeOther, pathWatchlist)
		return
	}

	enabled := c.PostForm("enabled") == "true"

	ctx := c.Request.Context()
	if err := h.DB.Queries.ToggleWatchlistEntry(ctx, dbq.ToggleWatchlistEntryParams{
		ID:      int32(entryID),
		UserID:  userID,
		Enabled: enabled,
	}); err != nil {
		slog.Error("Failed to toggle watchlist entry", "id", entryID, mapKeyError, err)
	}

	c.Redirect(http.StatusSeeOther, pathWatchlist)
}

func (h *WatchlistHandler) AddEndpoint(c *gin.Context) {
	uid, _ := c.Get(mapKeyUserId)
	userID, ok := uid.(int32)
	if !ok || userID == 0 {
		c.Redirect(http.StatusSeeOther, pathWatchlist)
		return
	}

	url := strings.TrimSpace(c.PostForm("url"))
	secret := strings.TrimSpace(c.PostForm("secret"))
	if url == "" || (!strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://")) {
		c.Redirect(http.StatusSeeOther, pathWatchlist)
		return
	}

	var secretPtr *string
	if secret != "" {
		secretPtr = &secret
	}

	ctx := c.Request.Context()
	_, err := h.DB.Queries.InsertNotificationEndpoint(ctx, dbq.InsertNotificationEndpointParams{
		UserID:       userID,
		EndpointType: "webhook",
		Url:          url,
		Secret:       secretPtr,
	})
	if err != nil {
		slog.Error("Failed to add notification endpoint", mapKeyUserId, userID, "url", url, mapKeyError, err)
	}

	c.Redirect(http.StatusSeeOther, pathWatchlist)
}

func (h *WatchlistHandler) RemoveEndpoint(c *gin.Context) {
	uid, _ := c.Get(mapKeyUserId)
	userID, ok := uid.(int32)
	if !ok || userID == 0 {
		c.Redirect(http.StatusSeeOther, pathWatchlist)
		return
	}

	idStr := c.Param("id")
	endpointID, err := strconv.Atoi(idStr)
	if err != nil {
		c.Redirect(http.StatusSeeOther, pathWatchlist)
		return
	}

	ctx := c.Request.Context()
	if err := h.DB.Queries.DeleteNotificationEndpoint(ctx, dbq.DeleteNotificationEndpointParams{
		ID:     int32(endpointID),
		UserID: userID,
	}); err != nil {
		slog.Error("Failed to delete notification endpoint", "id", endpointID, mapKeyError, err)
	}

	c.Redirect(http.StatusSeeOther, pathWatchlist)
}

func (h *WatchlistHandler) ToggleEndpoint(c *gin.Context) {
	uid, _ := c.Get(mapKeyUserId)
	userID, ok := uid.(int32)
	if !ok || userID == 0 {
		c.Redirect(http.StatusSeeOther, pathWatchlist)
		return
	}

	idStr := c.Param("id")
	endpointID, err := strconv.Atoi(idStr)
	if err != nil {
		c.Redirect(http.StatusSeeOther, pathWatchlist)
		return
	}

	enabled := c.PostForm("enabled") == "true"

	ctx := c.Request.Context()
	if err := h.DB.Queries.ToggleNotificationEndpoint(ctx, dbq.ToggleNotificationEndpointParams{
		ID:      int32(endpointID),
		UserID:  userID,
		Enabled: enabled,
	}); err != nil {
		slog.Error("Failed to toggle notification endpoint", "id", endpointID, mapKeyError, err)
	}

	c.Redirect(http.StatusSeeOther, pathWatchlist)
}

func (h *WatchlistHandler) TestWebhook(c *gin.Context) {
	if h.Config.DiscordWebhookURL == "" {
		slog.Warn("Test webhook: DISCORD_WEBHOOK_URL not configured")
		c.Redirect(http.StatusSeeOther, pathWatchlist)
		return
	}
	ctx := c.Request.Context()
	if err := h.Notifier.SendTestDiscord(ctx, h.Config.DiscordWebhookURL); err != nil {
		slog.Error("Test webhook failed", mapKeyError, err)
	} else {
		slog.Info("Test webhook sent successfully")
	}
	c.Redirect(http.StatusSeeOther, pathWatchlist)
}
