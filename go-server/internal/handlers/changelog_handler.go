// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "net/http"

        "dnstool/go-server/internal/config"

        "github.com/gin-gonic/gin"
)

type ChangelogHandler struct {
        Config *config.Config
}

func NewChangelogHandler(cfg *config.Config) *ChangelogHandler {
        return &ChangelogHandler{Config: cfg}
}

func (h *ChangelogHandler) Changelog(c *gin.Context) {
        nonce, _ := c.Get("csp_nonce")

        all := GetChangelog()
        recentCut := 20
        if recentCut > len(all) {
                recentCut = len(all)
        }

        data := gin.H{
                keyAppVersion:      h.Config.AppVersion,
                keyMaintenanceNote: h.Config.MaintenanceNote,
                keyBetaPages:       h.Config.BetaPages,
                keyCspNonce:        nonce,
                keyActivePage:      "changelog",
                "RecentChangelog":  all[:recentCut],
                "ArchiveChangelog": all[recentCut:],
                "ArchiveCount":     len(all) - recentCut,
                "TotalCount":       len(all),
                "LegacyChangelog":  GetLegacyChangelog(),
        }
        mergeAuthData(c, h.Config, data)
        c.HTML(http.StatusOK, "changelog.html", data)
}
