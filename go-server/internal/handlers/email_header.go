// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
	"io"
	"net/http"
	"strings"

	"dnstool/go-server/internal/analyzer"
	"dnstool/go-server/internal/config"

	"github.com/gin-gonic/gin"
)

const (
	strShowform = "ShowForm"
)

const emailHeaderTemplate = "email_header.html"
const activePageEmailHeader = "email-header"
const maxHeaderSize = 256 * 1024

type EmailHeaderHandler struct {
	Config *config.Config
}

func NewEmailHeaderHandler(cfg *config.Config) *EmailHeaderHandler {
	return &EmailHeaderHandler{Config: cfg}
}

func (h *EmailHeaderHandler) EmailHeaderPage(c *gin.Context) {
	nonce, _ := c.Get("csp_nonce")
	csrfToken, _ := c.Get("csrf_token")

	data := gin.H{
		strAppversion:      h.Config.AppVersion,
		strMaintenancenote: h.Config.MaintenanceNote,
		strBetapages:       h.Config.BetaPages,
		strCspnonce:        nonce,
		strCsrftoken:       csrfToken,
		strActivepage:      activePageEmailHeader,
		strShowform:        true,
	}
	mergeAuthData(c, h.Config, data)
	c.HTML(http.StatusOK, emailHeaderTemplate, data)
}

func (h *EmailHeaderHandler) AnalyzeEmailHeader(c *gin.Context) {
	nonce, _ := c.Get("csp_nonce")
	csrfToken, _ := c.Get("csrf_token")

	renderErr := func(msg string) {
		errData := gin.H{
			strAppversion:      h.Config.AppVersion,
			strMaintenancenote: h.Config.MaintenanceNote,
			strBetapages:       h.Config.BetaPages,
			strCspnonce:        nonce,
			strCsrftoken:       csrfToken,
			strActivepage:      activePageEmailHeader,
			strShowform:        true,
			"FlashMessages":    []FlashMessage{{Category: "danger", Message: msg}},
		}
		mergeAuthData(c, h.Config, errData)
		c.HTML(http.StatusOK, emailHeaderTemplate, errData)
	}

	var rawInput string
	var uploadFilename string

	file, fileHeader, err := c.Request.FormFile("header_file")
	if err == nil && fileHeader != nil && fileHeader.Size > 0 {
		defer safeClose(file, "email header file")
		if fileHeader.Size > maxHeaderSize {
			renderErr("File too large. Maximum size is 256 KB.")
			return
		}
		data, readErr := io.ReadAll(io.LimitReader(file, maxHeaderSize))
		if readErr != nil {
			renderErr("Could not read the uploaded file.")
			return
		}
		rawInput = string(data)
		uploadFilename = fileHeader.Filename
	}

	if rawInput == "" {
		rawInput = strings.TrimSpace(c.PostForm("raw_header"))
	}

	if rawInput == "" {
		renderErr("Please paste an email header or upload a file.")
		return
	}

	if len(rawInput) > maxHeaderSize {
		rawInput = rawInput[:maxHeaderSize]
	}

	detected := analyzer.DetectAndExtractHeaders(rawInput, uploadFilename)
	if detected.Error != "" {
		renderErr(detected.Error)
		return
	}

	analysis := analyzer.AnalyzeEmailHeaders(detected.Headers)
	analysis.SourceFormat = detected.Format

	resultData := gin.H{
		strAppversion:      h.Config.AppVersion,
		strMaintenancenote: h.Config.MaintenanceNote,
		strBetapages:       h.Config.BetaPages,
		strCspnonce:        nonce,
		strCsrftoken:       csrfToken,
		strActivepage:      activePageEmailHeader,
		strShowform:        false,
		"ShowResults":      true,
		"Analysis":         analysis,
	}
	mergeAuthData(c, h.Config, resultData)
	c.HTML(http.StatusOK, emailHeaderTemplate, resultData)
}
