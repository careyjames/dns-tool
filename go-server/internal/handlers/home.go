// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
	"net/http"

	"dnstool/go-server/internal/config"
	"dnstool/go-server/internal/db"
	"dnstool/go-server/internal/icae"
	"dnstool/go-server/internal/icuae"

	"github.com/gin-gonic/gin"
)

type HomeHandler struct {
	Config *config.Config
	DB     *db.Database
}

func NewHomeHandler(cfg *config.Config, database *db.Database) *HomeHandler {
	return &HomeHandler{Config: cfg, DB: database}
}

func applyWelcomeOrFlash(c *gin.Context, data gin.H) {
	if welcome := c.Query("welcome"); welcome != "" {
		name := welcome
		if len(name) > 100 {
			name = name[:100]
		}
		data["WelcomeName"] = name
		return
	}
	applyFlashFromQuery(c, data)
}

func applyFlashFromQuery(c *gin.Context, data gin.H) {
	flash := c.Query("flash")
	if flash == "" {
		return
	}
	cat := c.DefaultQuery("flash_cat", "warning")
	if cat != "success" && cat != "danger" {
		cat = "warning"
	}
	msg := flash
	if len(msg) > 200 {
		msg = msg[:200]
	}
	data["FlashMessages"] = []FlashMessage{{Category: cat, Message: msg}}
	if domain := c.Query("domain"); domain != "" {
		d := domain
		if len(d) > 253 {
			d = d[:253]
		}
		data["PrefillDomain"] = d
	}
}

func (h *HomeHandler) Index(c *gin.Context) {
	nonce, _ := c.Get("csp_nonce")
	csrfToken, _ := c.Get("csrf_token")
	data := gin.H{
		keyAppVersion:      h.Config.AppVersion,
		keyMaintenanceNote: h.Config.MaintenanceNote,
		keyBetaPages:       h.Config.BetaPages,
		"BaseURL":         h.Config.BaseURL,
		keyCspNonce:        nonce,
		keyActivePage:      "home",
		"CsrfToken":       csrfToken,
		"WaitDomain":      c.Query("wait_domain"),
		"WaitSeconds":     c.Query("wait_seconds"),
		"WaitReason":      c.DefaultQuery("wait_reason", "anti_repeat"),
		"Changelog":       GetRecentChangelog(6),
		"DKIMExpand":      c.Query("dkim") != "",
	}

	if h.DB != nil {
		if metrics := icae.LoadReportMetrics(c.Request.Context(), h.DB.Queries); metrics != nil {
			data["ICAEMetrics"] = metrics
		}
		if rm := icuae.LoadRuntimeMetrics(c.Request.Context(), h.DB.Queries); rm != nil && rm.HasData {
			data["ICuAEMetrics"] = rm
		}
	}

	applyWelcomeOrFlash(c, data)

	mergeAuthData(c, h.Config, data)
	c.HTML(http.StatusOK, "index.html", data)
}
