// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "encoding/json"
        "fmt"
        "io"
        "net/http"
        "net/url"
        "strconv"
        "strings"
        "time"

        "dnstool/go-server/internal/config"

        "github.com/gin-gonic/gin"
)

const (
        mapKeyToolkit = "toolkit"
)

const tplToolkit = "toolkit.html"

type ToolkitHandler struct {
        Config *config.Config
}

func NewToolkitHandler(cfg *config.Config) *ToolkitHandler {
        return &ToolkitHandler{Config: cfg}
}

func (h *ToolkitHandler) ToolkitPage(c *gin.Context) {
        nonce, _ := c.Get(mapKeyCspNonce)
        csrfToken, _ := c.Get(mapKeyCsrfToken)
        data := gin.H{
                strAppversion:      h.Config.AppVersion,
                strMaintenancenote: h.Config.MaintenanceNote,
                strBetapages:       h.Config.BetaPages,
                strCspnonce:        nonce,
                strCsrftoken:       csrfToken,
                strActivepage:      mapKeyToolkit,
                "ProbeLocations":   h.Config.Probes,
        }
        mergeAuthData(c, h.Config, data)
        c.HTML(http.StatusOK, tplToolkit, data)
}

func (h *ToolkitHandler) MyIP(c *gin.Context) {
        nonce, _ := c.Get(mapKeyCspNonce)
        csrfToken, _ := c.Get(mapKeyCsrfToken)

        clientIP := c.ClientIP()
        userAgent := c.GetHeader("User-Agent")
        platform := detectPlatform(userAgent)

        data := gin.H{
                strAppversion:      h.Config.AppVersion,
                strMaintenancenote: h.Config.MaintenanceNote,
                strBetapages:       h.Config.BetaPages,
                strCspnonce:        nonce,
                strCsrftoken:       csrfToken,
                strActivepage:      mapKeyToolkit,
                "ClientIP":         clientIP,
                "Platform":         platform,
                "ShowMyIP":         true,
        }
        mergeAuthData(c, h.Config, data)
        c.HTML(http.StatusOK, tplToolkit, data)
}

func (h *ToolkitHandler) PortCheck(c *gin.Context) {
        nonce, _ := c.Get(mapKeyCspNonce)
        csrfToken, _ := c.Get(mapKeyCsrfToken)

        targetHost := strings.TrimSpace(c.PostForm("target_host"))
        targetPort := strings.TrimSpace(c.PostForm("target_port"))

        selectedProbeID := strings.TrimSpace(c.PostForm("probe_location"))
        if selectedProbeID == "" && len(h.Config.Probes) > 0 {
                selectedProbeID = h.Config.Probes[0].ID
        }

        data := gin.H{
                strAppversion:      h.Config.AppVersion,
                strMaintenancenote: h.Config.MaintenanceNote,
                strBetapages:       h.Config.BetaPages,
                strCspnonce:        nonce,
                strCsrftoken:       csrfToken,
                strActivepage:      mapKeyToolkit,
                "TargetHost":       targetHost,
                "TargetPort":       targetPort,
                "ShowPortCheck":    true,
                "ProbeLocations":   h.Config.Probes,
                "SelectedProbe":    selectedProbeID,
        }

        if targetHost == "" {
                h.renderToolkitWithError(c, data, "Please enter a target host (IP address or hostname).")
                return
        }

        portNum, err := strconv.Atoi(targetPort)
        if err != nil || portNum < 1 || portNum > 65535 {
                h.renderToolkitWithError(c, data, "Please enter a valid port number between 1 and 65535.")
                return
        }

        probe, ok := h.resolveProbeConfig(selectedProbeID)
        if !ok {
                h.renderToolkitWithError(c, data, "Port check service is not configured.")
                return
        }

        data["ProbeLabel"] = probe.label

        probeResult, probeErr := h.executeProbeRequest(probe, targetHost, targetPort)
        if probeErr != "" {
                h.renderToolkitWithError(c, data, probeErr)
                return
        }

        data["ProbeResult"] = probeResult
        mergeAuthData(c, h.Config, data)
        c.HTML(http.StatusOK, tplToolkit, data)
}

func (h *ToolkitHandler) renderToolkitWithError(c *gin.Context, data gin.H, msg string) {
        data["ProbeError"] = msg
        mergeAuthData(c, h.Config, data)
        c.HTML(http.StatusOK, tplToolkit, data)
}

func (h *ToolkitHandler) executeProbeRequest(probe probeConfig, targetHost, targetPort string) (map[string]any, string) {
        probeURL := probe.url + "/api/v2/tcp-check?host=" + url.QueryEscape(targetHost) + "&port=" + targetPort

        client := &http.Client{Timeout: 15 * time.Second}
        req, err := http.NewRequest("GET", probeURL, nil)
        if err != nil {
                return nil, "Failed to create request to probe service."
        }

        req.Header.Set("X-Probe-Key", probe.key)

        resp, err := client.Do(req)
        if err != nil {
                return nil, "Could not connect to the probe service. It may be temporarily unavailable."
        }
        defer safeClose(resp.Body, "probe-response")

        body, err := io.ReadAll(resp.Body)
        if err != nil {
                return nil, "Failed to read response from probe service."
        }

        if resp.StatusCode != 200 {
                return nil, fmt.Sprintf("Probe service returned an error (status %d).", resp.StatusCode)
        }

        var probeResult map[string]any
        if err := json.Unmarshal(body, &probeResult); err != nil {
                return nil, "Failed to parse response from probe service."
        }

        return probeResult, ""
}

type probeConfig struct {
        url, key, label string
}

func (h *ToolkitHandler) resolveProbeConfig(selectedProbeID string) (probeConfig, bool) {
        if len(h.Config.Probes) > 0 {
                selected := h.Config.Probes[0]
                for _, p := range h.Config.Probes {
                        if p.ID == selectedProbeID {
                                selected = p
                                break
                        }
                }
                return probeConfig{url: selected.URL, key: selected.Key, label: selected.Label}, true
        }
        if h.Config.ProbeAPIURL != "" {
                return probeConfig{url: h.Config.ProbeAPIURL, key: h.Config.ProbeAPIKey, label: "Default"}, true
        }
        return probeConfig{}, false
}

func detectPlatform(userAgent string) string {
        ua := strings.ToLower(userAgent)

        if strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad") || strings.Contains(ua, "ipod") {
                return "ios"
        }

        if strings.Contains(ua, "android") {
                return "android"
        }

        if strings.Contains(ua, "mac") {
                return "macos"
        }

        if strings.Contains(ua, "windows") {
                return "windows"
        }

        if strings.Contains(ua, "linux") {
                return "linux"
        }

        return "unknown"
}
