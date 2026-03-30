// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
	"net/http"

	"dnstool/go-server/internal/config"

	"github.com/gin-gonic/gin"
)

type ColorScienceHandler struct {
	Config *config.Config
}

func NewColorScienceHandler(cfg *config.Config) *ColorScienceHandler {
	return &ColorScienceHandler{Config: cfg}
}

func (h *ColorScienceHandler) ColorScience(c *gin.Context) {
	nonce, _ := c.Get("csp_nonce")
	data := gin.H{
		keyAppVersion:      h.Config.AppVersion,
		keyMaintenanceNote: h.Config.MaintenanceNote,
		keyBetaPages:       h.Config.BetaPages,
		keyCspNonce:        nonce,
		keyActivePage:      "color-science",
	}
	mergeAuthData(c, h.Config, data)
	c.HTML(http.StatusOK, "color_science.html", data)
}
