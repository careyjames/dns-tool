// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
	"encoding/json"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"dnstool/go-server/internal/config"

	"github.com/gin-gonic/gin"
)

type TopologyHandler struct {
	Config        *config.Config
	solverOnce    sync.Once
	solverLayouts map[string]json.RawMessage
}

func NewTopologyHandler(cfg *config.Config) *TopologyHandler {
	return &TopologyHandler{Config: cfg}
}

func (h *TopologyHandler) loadSolverLayouts() {
	h.solverLayouts = make(map[string]json.RawMessage)
	profiles := []string{"desktop", "tablet", "mobile"}
	solverDir := filepath.Join("go-server", "tools", "topology-solver", "output")

	for _, profile := range profiles {
		path := filepath.Join(solverDir, profile+"-layout.json")
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if json.Valid(data) {
			h.solverLayouts[profile] = data
		}
	}
}

func (h *TopologyHandler) Topology(c *gin.Context) {
	nonce, _ := c.Get("csp_nonce")

	h.solverOnce.Do(h.loadSolverLayouts)

	solverJSON := "{}"
	if len(h.solverLayouts) > 0 {
		merged, err := json.Marshal(h.solverLayouts)
		if err == nil {
			solverJSON = string(merged)
		}
	}

	data := gin.H{
		keyAppVersion:      h.Config.AppVersion,
		keyMaintenanceNote: h.Config.MaintenanceNote,
		keyBetaPages:       h.Config.BetaPages,
		keyCspNonce:        nonce,
		keyActivePage:      "topology",
		"SolverLayouts":   template.JS(solverJSON),
	}
	mergeAuthData(c, h.Config, data)
	c.HTML(http.StatusOK, "topology.html", data)
}
