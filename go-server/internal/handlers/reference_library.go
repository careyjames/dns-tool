// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "net/http"

        "dnstool/go-server/internal/config"

        "github.com/gin-gonic/gin"
)

type ReferenceLibraryHandler struct {
        Config *config.Config
}

func NewReferenceLibraryHandler(cfg *config.Config) *ReferenceLibraryHandler {
        return &ReferenceLibraryHandler{Config: cfg}
}

func (h *ReferenceLibraryHandler) ReferenceLibrary(c *gin.Context) {
        nonce, _ := c.Get("csp_nonce")
        data := gin.H{
                keyAppVersion:      h.Config.AppVersion,
                keyMaintenanceNote: h.Config.MaintenanceNote,
                keyBetaPages:       h.Config.BetaPages,
                keyCspNonce:        nonce,
                keyActivePage:      "reference-library",
        }
        mergeAuthData(c, h.Config, data)
        c.HTML(http.StatusOK, "reference_library.html", data)
}
