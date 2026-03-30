// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "net/http"

        "dnstool/go-server/internal/config"

        "github.com/gin-gonic/gin"
)

type ApproachHandler struct {
        Config *config.Config
}

func NewApproachHandler(cfg *config.Config) *ApproachHandler {
        return &ApproachHandler{Config: cfg}
}

func (h *ApproachHandler) Approach(c *gin.Context) {
        nonce, _ := c.Get("csp_nonce")
        ytID := h.Config.YouTubeVideoIDs["forgotten-domain"]
        data := gin.H{
                keyAppVersion:      h.Config.AppVersion,
                keyMaintenanceNote: h.Config.MaintenanceNote,
                keyBetaPages:       h.Config.BetaPages,
                keyCspNonce:        nonce,
                keyActivePage:      "approach",
                "YouTubeID":       ytID,
        }
        mergeAuthData(c, h.Config, data)
        c.HTML(http.StatusOK, "approach.html", data)
}
