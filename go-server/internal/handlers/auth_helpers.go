// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.

// dns-tool:scrutiny design
package handlers

import (
	"dnstool/go-server/internal/config"
	"dnstool/go-server/internal/middleware"

	"github.com/gin-gonic/gin"
)

func mergeAuthData(c *gin.Context, cfg *config.Config, data gin.H) gin.H {
	for k, v := range middleware.GetAuthTemplateData(c) {
		data[k] = v
	}
	if cfg.GoogleClientID != "" {
		data["GoogleAuthEnabled"] = true
	}
	return data
}
