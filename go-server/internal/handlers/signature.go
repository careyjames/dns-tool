// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "fmt"
        "net/http"

        "dnstool/go-server/internal/config"

        "github.com/gin-gonic/gin"
)

type SignatureHandler struct {
        Config *config.Config
}

func NewSignatureHandler(cfg *config.Config) *SignatureHandler {
        return &SignatureHandler{Config: cfg}
}

func (h *SignatureHandler) SignaturePage(c *gin.Context) {
        nonce, _ := c.Get("csp_nonce")

        mode := c.DefaultQuery("mode", "page")

        data := gin.H{
                keyAppVersion:      h.Config.AppVersion,
                keyMaintenanceNote: h.Config.MaintenanceNote,
                keyBetaPages:       h.Config.BetaPages,
                keyCspNonce:        nonce,
                keyActivePage:      "signature",
                "RawMode":         mode == "raw",
                "BaseURL":         h.Config.BaseURL,
        }
        mergeAuthData(c, h.Config, data)

        if mode == "raw" {
                nonceStr, _ := nonce.(string)
                c.Header("Content-Security-Policy", fmt.Sprintf("default-src 'none'; style-src 'nonce-%s'; img-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'", nonceStr))
                c.HTML(http.StatusOK, "signature_raw.html", data)
                return
        }

        c.HTML(http.StatusOK, "signature.html", data)
}
