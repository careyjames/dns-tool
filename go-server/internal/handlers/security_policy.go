// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
	"net/http"

	"dnstool/go-server/internal/config"

	"github.com/gin-gonic/gin"
)

type SecurityPolicyHandler struct {
	Config *config.Config
}

func NewSecurityPolicyHandler(cfg *config.Config) *SecurityPolicyHandler {
	return &SecurityPolicyHandler{Config: cfg}
}

func (h *SecurityPolicyHandler) SecurityPolicy(c *gin.Context) {
	nonce, _ := c.Get("csp_nonce")
	data := gin.H{
		keyAppVersion:      h.Config.AppVersion,
		keyMaintenanceNote: h.Config.MaintenanceNote,
		keyBetaPages:       h.Config.BetaPages,
		keyCspNonce:        nonce,
		keyActivePage:      "security-policy",
	}
	mergeAuthData(c, h.Config, data)
	c.HTML(http.StatusOK, "security_policy.html", data)
}
