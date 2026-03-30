// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import (
        "context"
        "image"
        "image/color"
        "net/http"
        "net/http/httptest"
        "testing"

        "dnstool/go-server/internal/config"

        "github.com/gin-gonic/gin"
)

func TestAnimContentType_B7(t *testing.T) {
        if animContentType("gif") != "image/gif" {
                t.Error("gif should return image/gif")
        }
        if animContentType("apng") != "image/png" {
                t.Error("apng should return image/png")
        }
        if animContentType("") != "image/png" {
                t.Error("empty should default to image/png")
        }
}

func TestGifPalette_B7(t *testing.T) {
        pal := gifPalette()
        if len(pal) == 0 {
                t.Fatal("palette should not be empty")
        }
        if len(pal) > 256 {
                t.Errorf("palette should be capped at 256, got %d", len(pal))
        }
}

func TestAssembleGIF_B7(t *testing.T) {
        frames := make([]*image.NRGBA, 3)
        for i := range frames {
                frames[i] = image.NewNRGBA(image.Rect(0, 0, 10, 10))
                for x := 0; x < 10; x++ {
                        for y := 0; y < 10; y++ {
                                frames[i].SetNRGBA(x, y, color.NRGBA{R: uint8(i * 80), G: 100, B: 200, A: 255})
                        }
                }
        }
        data, err := assembleGIF(frames)
        if err != nil {
                t.Fatalf("assembleGIF error: %v", err)
        }
        if len(data) == 0 {
                t.Error("GIF data should not be empty")
        }
        if string(data[:3]) != "GIF" {
                t.Error("should start with GIF magic bytes")
        }
}

func TestAssembleAPNG_B7(t *testing.T) {
        frames := make([]*image.NRGBA, 2)
        for i := range frames {
                frames[i] = image.NewNRGBA(image.Rect(0, 0, 8, 8))
                for x := 0; x < 8; x++ {
                        for y := 0; y < 8; y++ {
                                frames[i].SetNRGBA(x, y, color.NRGBA{R: 50, G: uint8(i * 100), B: 150, A: 255})
                        }
                }
        }
        data, err := assembleAPNG(frames)
        if err != nil {
                t.Fatalf("assembleAPNG error: %v", err)
        }
        if len(data) == 0 {
                t.Error("APNG data should not be empty")
        }
        if data[0] != 0x89 || data[1] != 'P' {
                t.Error("should start with PNG magic bytes")
        }
}

func TestRenderAnimatedFramesRGBA_NoRSVG_B7(t *testing.T) {
        origPath := rsvgBinPath
        rsvgBinPath = ""
        defer func() { rsvgBinPath = origPath }()

        _, err := renderAnimatedFramesRGBA([]byte("<svg></svg>"), 2, "detailed")
        if err == nil {
                t.Error("should fail when rsvg-convert not available")
        }
}

func TestRenderAnimatedFramesRGBA_Covert_NoRSVG_B7(t *testing.T) {
        origPath := rsvgBinPath
        rsvgBinPath = ""
        defer func() { rsvgBinPath = origPath }()

        _, err := renderAnimatedFramesRGBA([]byte("<svg></svg>"), 2, "covert")
        if err == nil {
                t.Error("should fail when rsvg-convert not available")
        }
}

func TestLogEphemeralReason_B7(t *testing.T) {
        logEphemeralReason("example.com", true, true)
        logEphemeralReason("example.com", false, false)
        logEphemeralReason("example.com", false, true)
}

func TestRecordAnalyticsCollector_NoCollector_B7(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

        recordAnalyticsCollector(c, "example.com")
}

type mockCollector struct {
        recorded string
}

func (m *mockCollector) RecordAnalysis(domain string) {
        m.recorded = domain
}

func TestRecordAnalyticsCollector_WithCollector_B7(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

        mc := &mockCollector{}
        c.Set("analytics_collector", mc)

        recordAnalyticsCollector(c, "example.com")

        if mc.recorded != "example.com" {
                t.Errorf("expected example.com, got %q", mc.recorded)
        }
}

func TestPersistOrLogEphemeral_Ephemeral_B7(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        id, ts := h.persistOrLogEphemeral(context.Background(), persistParams{
                asciiDomain:  "example.com",
                results:      map[string]any{},
                ephemeral:    true,
                domainExists: true,
        })
        if id != 0 {
                t.Errorf("ephemeral should return ID=0, got %d", id)
        }
        if ts == "" {
                t.Error("timestamp should not be empty")
        }
}

func TestPersistOrLogEphemeral_DevNull_B7(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        id, _ := h.persistOrLogEphemeral(context.Background(), persistParams{
                asciiDomain:  "example.com",
                results:      map[string]any{},
                devNull:      true,
                domainExists: true,
        })
        if id != 0 {
                t.Errorf("devNull should return ID=0, got %d", id)
        }
}

func TestPersistOrLogEphemeral_NonExistentDomain_B7(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        id, _ := h.persistOrLogEphemeral(context.Background(), persistParams{
                asciiDomain:  "nonexistent.invalid",
                results:      map[string]any{},
                domainExists: false,
        })
        if id != 0 {
                t.Errorf("non-existent domain should return ID=0, got %d", id)
        }
}

func TestRecordUserAnalysisAsync_NotAuthenticated_B7(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        h.recordUserAnalysisAsync(sideEffectsParams{
                isAuthenticated: false,
                userID:          0,
                analysisID:      1,
        })
}

func TestRecordUserAnalysisAsync_ZeroUserID_B7(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        h.recordUserAnalysisAsync(sideEffectsParams{
                isAuthenticated: true,
                userID:          0,
                analysisID:      1,
        })
}

func TestRecordDailyStats_NilDB_B7(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        h.recordDailyStats(true, 1.5)
        h.recordDailyStats(false, 2.0)
}

func TestExtractRootDomain_B7(t *testing.T) {
        isSub, root := extractRootDomain("sub.example.com")
        if !isSub {
                t.Error("sub.example.com should be a subdomain")
        }
        if root != "example.com" {
                t.Errorf("root should be example.com, got %s", root)
        }

        isSub2, _ := extractRootDomain("example.com")
        if isSub2 {
                t.Error("example.com should not be a subdomain")
        }
}

func TestIsPublicSuffixDomain_B7(t *testing.T) {
        if !isPublicSuffixDomain("com") {
                t.Error("com should be public suffix")
        }
}

func TestReportModeTemplate_B7(t *testing.T) {
        tests := []struct {
                mode string
                want string
        }{
                {"E", "results.html"},
                {"C", "results_covert.html"},
                {"Z", "results.html"},
                {"CZ", "results_covert.html"},
        }
        for _, tt := range tests {
                got := reportModeTemplate(tt.mode)
                if got != tt.want {
                        t.Errorf("reportModeTemplate(%q) = %q, want %q", tt.mode, got, tt.want)
                }
        }
}

func TestIsCovertMode_B7(t *testing.T) {
        if !isCovertMode("C") {
                t.Error("C should be covert")
        }
        if !isCovertMode("CZ") {
                t.Error("CZ should be covert")
        }
        if isCovertMode("E") {
                t.Error("E should not be covert")
        }
        if isCovertMode("Z") {
                t.Error("Z should not be covert")
        }
}

func TestPluralS_B7(t *testing.T) {
        if pluralS(1) != "" {
                t.Error("1 should return empty")
        }
        if pluralS(0) != "s" {
                t.Error("0 should return s")
        }
        if pluralS(5) != "s" {
                t.Error("5 should return s")
        }
}

func TestServeAnimFromCache_Miss_B7(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

        served := serveAnimFromCache(c, "nonexistent-key", "apng")
        if served {
                t.Error("should return false on cache miss")
        }
}

func TestStoreAndServeAnimFromCache_Hit_B7(t *testing.T) {
        gin.SetMode(gin.TestMode)
        testKey := "test-anim-cache-hit-b7"
        data := []byte("fake-animation-data")
        etag := storeAnimInCache(testKey, data)
        t.Cleanup(func() {
                animCacheMu.Lock()
                delete(animCache, testKey)
                animCacheMu.Unlock()
        })
        if etag == "" {
                t.Fatal("etag should not be empty")
        }

        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

        served := serveAnimFromCache(c, testKey, "apng")
        if !served {
                t.Error("should serve from cache after store")
        }
        if w.Code != http.StatusOK {
                t.Errorf("expected 200, got %d", w.Code)
        }
}

func TestServeAnimFromCache_ETagMatch_B7(t *testing.T) {
        gin.SetMode(gin.TestMode)
        testKey := "test-etag-match-b7"
        data := []byte("fake-animation-etag-test")
        etag := storeAnimInCache(testKey, data)
        t.Cleanup(func() {
                animCacheMu.Lock()
                delete(animCache, testKey)
                animCacheMu.Unlock()
        })

        router := gin.New()
        router.GET("/test", func(c *gin.Context) {
                served := serveAnimFromCache(c, testKey, "gif")
                if !served {
                        c.String(http.StatusInternalServerError, "cache miss")
                }
        })

        req := httptest.NewRequest(http.MethodGet, "/test", nil)
        req.Header.Set("If-None-Match", etag)
        w := httptest.NewRecorder()
        router.ServeHTTP(w, req)

        if w.Code != http.StatusNotModified {
                t.Errorf("expected 304, got %d", w.Code)
        }
}

func TestEvictLRUAnimEntry_B7(t *testing.T) {
        storeAnimInCache("a-evict-b7", []byte("a"))
        storeAnimInCache("b-evict-b7", []byte("b"))
        defer func() {
                animCacheMu.Lock()
                delete(animCache, "a-evict-b7")
                delete(animCache, "b-evict-b7")
                animCacheMu.Unlock()
        }()

        animCacheMu.Lock()
        before := len(animCache)
        evictLRUAnimEntry()
        after := len(animCache)
        animCacheMu.Unlock()

        if after >= before {
                t.Errorf("evict should reduce count: before=%d after=%d", before, after)
        }
}

func TestBuildAnalyzeViewData_NilDB_B7(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

        h := &AnalysisHandler{Config: &config.Config{AppVersion: "v1.0", BetaPages: map[string]bool{}}}
        data := h.buildAnalyzeViewData(c, "nonce", "csrf", viewDataInput{
                domain:      "example.com",
                asciiDomain: "example.com",
                results:     map[string]any{},
                analysisID:  0,
                timestamp:   "2025-01-01 00:00:00 UTC",
                postureHash: "abc123",
        })
        if data["Domain"] != "example.com" {
                t.Error("domain not set")
        }
        if data["AppVersion"] != "v1.0" {
                t.Error("app version not set")
        }
        if data["IntegrityHash"] == "" {
                t.Error("integrity hash should be computed")
        }
}

func TestDetectDrift_DevNull_B7(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        d := h.detectDrift(context.Background(), true, true, "example.com", "hash123", map[string]any{})
        if d.Detected {
                t.Error("devNull should skip drift detection")
        }
}

func TestDetectDrift_DomainNotExist_B7(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        d := h.detectDrift(context.Background(), false, false, "example.com", "hash123", map[string]any{})
        if d.Detected {
                t.Error("non-existent domain should skip drift detection")
        }
}
