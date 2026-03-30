// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import (
        "context"
        "net/http"
        "net/http/httptest"
        "os"
        "path/filepath"
        "testing"

        "dnstool/go-server/internal/config"

        "github.com/gin-gonic/gin"
)

func TestSnapshotICAEMetrics_NilDB_B5(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        results := map[string]any{
                "calibrated_confidence": map[string]float64{
                        "spf": 0.9, "dkim": 0.8, "dmarc": 0.85,
                },
        }
        h.snapshotICAEMetrics(context.Background(), results)
        snap, ok := results["_icae_snapshot"]
        if !ok {
                t.Fatal("_icae_snapshot should be set")
        }
        snapMap, ok := snap.(map[string]any)
        if !ok {
                t.Fatal("snapshot should be a map")
        }
        if _, hasUC := snapMap["unified_confidence"]; hasUC {
                t.Error("unified_confidence should NOT be set when maturity level is missing (nil DB)")
        }
}

func TestSnapshotICAEMetrics_NoCalibratedConfidence_B5(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        results := map[string]any{"spf": "pass"}
        h.snapshotICAEMetrics(context.Background(), results)
        snap, ok := results["_icae_snapshot"].(map[string]any)
        if !ok {
                t.Fatal("snapshot should be set as map")
        }
        if _, has := snap["unified_confidence"]; has {
                t.Error("should not have unified_confidence without calibrated data")
        }
}

func TestHandlePostAnalysisSideEffectsAsync_NilDB_NoAnalysisID_B5(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        h.handlePostAnalysisSideEffectsAsync(context.Background(), sideEffectsParams{
                analysisID:  0,
                ephemeral:   true,
                domainExists: true,
        })
}

func TestHandlePostAnalysisSideEffectsAsync_NilDB_WithAnalysisID_B5(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        h.handlePostAnalysisSideEffectsAsync(context.Background(), sideEffectsParams{
                analysisID:      42,
                isAuthenticated: false,
                ephemeral:       true,
                domainExists:    false,
                drift:           driftInfo{Detected: false},
                analysisSuccess: true,
        })
}

func TestHandlePostAnalysisSideEffects_NilDB_B5(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

        h := &AnalysisHandler{Config: &config.Config{}}
        h.handlePostAnalysisSideEffects(context.Background(), c, sideEffectsParams{
                analysisID:  0,
                ephemeral:   true,
                domainExists: false,
        })
}

func TestLoadSolverLayouts_MissingDir_B5(t *testing.T) {
        cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
        h := NewTopologyHandler(cfg)
        h.loadSolverLayouts()
        if len(h.solverLayouts) != 0 {
                t.Errorf("expected 0 layouts for missing dir, got %d", len(h.solverLayouts))
        }
}

func TestLoadSolverLayouts_WithValidFiles_B5(t *testing.T) {
        dir := t.TempDir()
        solverDir := filepath.Join(dir, "go-server", "tools", "topology-solver", "output")
        os.MkdirAll(solverDir, 0755)

        os.WriteFile(filepath.Join(solverDir, "desktop-layout.json"), []byte(`{"nodes":[]}`), 0644)
        os.WriteFile(filepath.Join(solverDir, "tablet-layout.json"), []byte(`not-json`), 0644)
        os.WriteFile(filepath.Join(solverDir, "mobile-layout.json"), []byte(`{"sections":[]}`), 0644)

        origWd, err := os.Getwd()
        if err != nil {
                t.Fatalf("failed to get working directory: %v", err)
        }
        if err := os.Chdir(dir); err != nil {
                t.Fatalf("failed to chdir: %v", err)
        }
        t.Cleanup(func() { os.Chdir(origWd) })

        cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
        h := NewTopologyHandler(cfg)
        h.loadSolverLayouts()

        if _, ok := h.solverLayouts["desktop"]; !ok {
                t.Error("desktop layout should be loaded")
        }
        if _, ok := h.solverLayouts["tablet"]; ok {
                t.Error("tablet layout with invalid JSON should NOT be loaded")
        }
        if _, ok := h.solverLayouts["mobile"]; !ok {
                t.Error("mobile layout should be loaded")
        }
}

func TestRemediationHandler_Store_NilDB_B5(t *testing.T) {
        h := &RemediationHandler{Config: &config.Config{}}
        s := h.store()
        if s != nil {
                t.Error("store should be nil when both lookupStore and DB are nil")
        }
}

func TestCheckSSRF_Loopback_B5(t *testing.T) {
        err := checkSSRF("localhost")
        if err == nil {
                t.Error("localhost should be blocked by SSRF check")
        }
}

func TestCheckSSRF_PublicDomain_B5(t *testing.T) {
        if testing.Short() {
                t.Skip("skipping network-dependent test in short mode")
        }
        err := checkSSRF("google.com")
        if err != nil {
                t.Errorf("public domain should pass SSRF: %v", err)
        }
}

func TestCheckSSRF_InvalidHost_B5(t *testing.T) {
        if testing.Short() {
                t.Skip("skipping network-dependent test in short mode")
        }
        err := checkSSRF("thisdomaindoesnotexist12345.invalid")
        if err == nil {
                t.Error("non-resolving domain should fail SSRF check")
        }
}

func TestValidateBIMIResponse_Non200_B5(t *testing.T) {
        resp := &http.Response{StatusCode: 404}
        _, _, err := validateBIMIResponse(resp)
        if err == nil {
                t.Error("should error on non-200 response")
        }
}

func TestValidateBIMIResponse_NotImage_B5(t *testing.T) {
        resp := &http.Response{
                StatusCode: 200,
                Header:     http.Header{"Content-Type": {"text/html"}},
                Body:       http.NoBody,
        }
        _, _, err := validateBIMIResponse(resp)
        if err == nil {
                t.Error("should error on non-image content type")
        }
}

func TestBuildSafeURL_B5(t *testing.T) {
        parsed, _ := (&http.Request{}).URL.Parse("http://example.com/path?q=1#frag")
        result := buildSafeURL(parsed)
        if result != "https://example.com/path?q=1#frag" {
                t.Errorf("got %q", result)
        }
}

func TestSonarBadgeURLs_B5(t *testing.T) {
        expected := []string{"qg-web", "ai-web", "qg-full", "ai-full", "qg-intel", "ai-intel", "qg-cli", "ai-cli", "qg-legacy", "ai-legacy"}
        for _, key := range expected {
                if _, ok := sonarBadgeURLs[key]; !ok {
                        t.Errorf("sonarBadgeURLs missing key %q", key)
                }
        }
}

func TestNewProxyHandler_B5(t *testing.T) {
        h := NewProxyHandler()
        if h == nil {
                t.Fatal("should not be nil")
        }
}

func TestBIMIAllowedContentTypes_B5(t *testing.T) {
        if !bimiAllowedContentTypes["image/svg+xml"] {
                t.Error("svg should be allowed")
        }
        if !bimiAllowedContentTypes["image/png"] {
                t.Error("png should be allowed")
        }
        if bimiAllowedContentTypes["text/html"] {
                t.Error("html should not be allowed")
        }
}
