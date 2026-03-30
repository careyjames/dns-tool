package handlers_test

import (
        "net/http"
        "net/http/httptest"
        "strings"
        "testing"

        "dnstool/go-server/internal/citation"
        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/handlers"

        "github.com/gin-gonic/gin"
)

func aboutRouter_CB10(t *testing.T) *gin.Engine {
        t.Helper()
        r := allTemplates()
        cfg := testConfig()
        h := handlers.NewAboutHandler(cfg)
        r.GET("/about", h.About)
        return r
}

func TestAboutPage_CB10(t *testing.T) {
        r := aboutRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/about", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
        }
}

func sourcesRouter_CB10(t *testing.T) *gin.Engine {
        t.Helper()
        r := allTemplates()
        cfg := testConfig()
        h := handlers.NewSourcesHandler(cfg)
        r.GET("/sources", h.Sources)
        return r
}

func TestSourcesPage_CB10(t *testing.T) {
        r := sourcesRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/sources", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
        }
}

func roadmapRouter_CB10(t *testing.T) *gin.Engine {
        t.Helper()
        r := allTemplates()
        cfg := testConfig()
        h := handlers.NewRoadmapHandler(cfg)
        r.GET("/roadmap", h.Roadmap)
        return r
}

func TestRoadmapPage_CB10(t *testing.T) {
        r := roadmapRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/roadmap", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
        }
}

func brandColorsRouter_CB10(t *testing.T) *gin.Engine {
        t.Helper()
        r := allTemplates()
        cfg := testConfig()
        h := handlers.NewBrandColorsHandler(cfg)
        r.GET("/brand-colors", h.BrandColors)
        return r
}

func TestBrandColorsPage_CB10(t *testing.T) {
        r := brandColorsRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/brand-colors", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
        }
}

func signatureRouter_CB10(t *testing.T) *gin.Engine {
        t.Helper()
        r := allTemplates()
        cfg := testConfig()
        h := handlers.NewSignatureHandler(cfg)
        r.GET("/signature", h.SignaturePage)
        return r
}

func TestSignaturePage_CB10(t *testing.T) {
        r := signatureRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/signature", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
        }
}

func edeRouter_CB10(t *testing.T) *gin.Engine {
        t.Helper()
        r := allTemplates()
        cfg := testConfig()
        h := handlers.NewEDEHandler(&db.Database{}, cfg)
        r.GET("/ede", h.EDE)
        return r
}

func TestEDEPage_CB10(t *testing.T) {
        r := edeRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/ede", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
        }
}

func toolkitRouter_CB10(t *testing.T) *gin.Engine {
        t.Helper()
        r := allTemplates()
        cfg := testConfig()
        h := handlers.NewToolkitHandler(cfg)
        r.GET("/toolkit", h.ToolkitPage)
        r.GET("/toolkit/myip", h.MyIP)
        return r
}

func TestToolkitPage_CB10(t *testing.T) {
        r := toolkitRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/toolkit", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
        }
}

func TestToolkitMyIP_CB10(t *testing.T) {
        r := toolkitRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/toolkit/myip", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }
}

func statsRouter_CB10(t *testing.T) *gin.Engine {
        t.Helper()
        r := allTemplates()
        database := setupTestDB(t)
        t.Cleanup(func() { cleanupTestDB(t, database) })
        cfg := testConfig()
        h := handlers.NewStatsHandler(database, cfg)
        r.GET("/stats", h.Stats)
        r.GET("/statistics", h.StatisticsRedirect)
        return r
}

func TestStatsPage_CB10(t *testing.T) {
        r := statsRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/stats", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
        }
}

func TestStatisticsRedirect_CB10(t *testing.T) {
        r := statsRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/statistics", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusFound && w.Code != http.StatusMovedPermanently && w.Code != http.StatusPermanentRedirect {
                t.Fatalf("expected redirect, got %d", w.Code)
        }
        loc := w.Header().Get("Location")
        if !strings.Contains(loc, "/stats") {
                t.Errorf("expected redirect to /stats, got Location: %q", loc)
        }
}

func remediationRouter_CB10(t *testing.T) *gin.Engine {
        t.Helper()
        r := allTemplates()
        database := setupTestDB(t)
        t.Cleanup(func() { cleanupTestDB(t, database) })
        cfg := testConfig()
        h := handlers.NewRemediationHandler(database, cfg)
        r.GET("/remediation/:id", h.RemediationPage)
        return r
}

func TestRemediationNotFound_CB10(t *testing.T) {
        r := remediationRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/remediation/999999", nil)
        r.ServeHTTP(w, req)
        if w.Code == http.StatusInternalServerError {
                t.Fatalf("expected non-500, got %d", w.Code)
        }
}

func TestRemediationInvalidID_CB10(t *testing.T) {
        r := remediationRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/remediation/abc", nil)
        r.ServeHTTP(w, req)
        if w.Code >= 500 {
                t.Fatalf("expected non-500, got %d", w.Code)
        }
}

func badgeEmbedRouter_CB10(t *testing.T) *gin.Engine {
        t.Helper()
        r := allTemplates()
        database := setupTestDB(t)
        t.Cleanup(func() { cleanupTestDB(t, database) })
        cfg := testConfig()
        h := handlers.NewBadgeHandler(database, cfg)
        r.GET("/badge/embed/:domain", h.BadgeEmbed)
        r.GET("/badge/:domain", h.Badge)
        r.GET("/badge/shields/:domain", h.BadgeShieldsIO)
        return r
}

func TestBadgeEmbedNotFound_CB10(t *testing.T) {
        r := badgeEmbedRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/badge/embed/nonexistent.test.invalid", nil)
        r.ServeHTTP(w, req)
        if w.Code == http.StatusInternalServerError {
                t.Fatalf("expected non-500, got %d", w.Code)
        }
}

func TestBadgeSVGNotFound_CB10(t *testing.T) {
        r := badgeEmbedRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/badge/nonexistent.test.invalid", nil)
        r.ServeHTTP(w, req)
        if w.Code == http.StatusInternalServerError {
                t.Fatalf("expected non-500, got %d", w.Code)
        }
}

func citationRouter_CB10(t *testing.T) *gin.Engine {
        t.Helper()
        r := allTemplates()
        database := setupTestDB(t)
        t.Cleanup(func() { cleanupTestDB(t, database) })
        cfg := testConfig()
        reg := citation.Global()
        h := handlers.NewCitationHandler(cfg, reg, database)
        r.GET("/authorities", h.Authorities)
        r.GET("/cite/software", h.SoftwareCitation)
        r.GET("/cite/analysis/:id", h.AnalysisCitation)
        return r
}

func TestAuthoritiesPage_CB10(t *testing.T) {
        r := citationRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/authorities", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }
        ct := w.Header().Get("Content-Type")
        if !strings.Contains(ct, "application/json") {
                t.Errorf("expected JSON content-type, got %q", ct)
        }
        body := w.Body.String()
        if !strings.Contains(body, "count") || !strings.Contains(body, "entries") {
                t.Errorf("expected JSON with count and entries fields, got: %s", body[:min(len(body), 200)])
        }
}

func TestSoftwareCitationJSON_CB10(t *testing.T) {
        r := citationRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/cite/software", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }
        ct := w.Header().Get("Content-Type")
        if !strings.Contains(ct, "application/json") {
                t.Errorf("expected JSON content-type, got %q", ct)
        }
}

func TestAnalysisCitationNotFound_CB10(t *testing.T) {
        r := citationRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/cite/analysis/999999", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusNotFound {
                t.Fatalf("expected 404, got %d", w.Code)
        }
}

func TestRemediationInvalidID_Specific_CB10(t *testing.T) {
        r := remediationRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/remediation/abc", nil)
        r.ServeHTTP(w, req)
        if w.Code >= 500 {
                t.Errorf("expected non-500 for invalid ID, got %d", w.Code)
        }
}

func compareSelectRouter_CB10(t *testing.T) *gin.Engine {
        t.Helper()
        r := allTemplates()
        database := setupTestDB(t)
        t.Cleanup(func() { cleanupTestDB(t, database) })
        cfg := testConfig()
        h := handlers.NewCompareHandler(database, cfg)
        r.GET("/compare", h.Compare)
        return r
}

func TestCompareSelectNoDomain_CB10(t *testing.T) {
        r := compareSelectRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/compare", nil)
        r.ServeHTTP(w, req)
        if w.Code >= 500 {
                t.Fatalf("expected non-500, got %d", w.Code)
        }
}

func TestCompareSelectWithDomain_CB10(t *testing.T) {
        r := compareSelectRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/compare?domain=example.com", nil)
        r.ServeHTTP(w, req)
        if w.Code >= 500 {
                t.Fatalf("expected non-500, got %d", w.Code)
        }
}

func TestCompareWithInvalidIDs_CB10(t *testing.T) {
        r := compareSelectRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/compare?domain=example.com&a=abc&b=def", nil)
        r.ServeHTTP(w, req)
        if w.Code >= 500 {
                t.Fatalf("expected non-500, got %d", w.Code)
        }
}

func TestCompareNotFoundIDs_CB10(t *testing.T) {
        r := compareSelectRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/compare?domain=example.com&a=999998&b=999999", nil)
        r.ServeHTTP(w, req)
        if w.Code == http.StatusInternalServerError {
                t.Fatalf("expected non-500, got %d", w.Code)
        }
}

func TestSignatureRawCSPNonce_CB10(t *testing.T) {
        r := allTemplates()
        cfg := testConfig()
        h := handlers.NewSignatureHandler(cfg)
        r.GET("/signature", h.SignaturePage)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/signature?mode=raw", nil)
        r.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
        }

        csp := w.Header().Get("Content-Security-Policy")
        if csp == "" {
                t.Fatal("expected CSP header on signature raw endpoint")
        }
        if strings.Contains(csp, "unsafe-inline") {
                t.Error("signature raw CSP must not contain unsafe-inline")
        }
        if !strings.Contains(csp, "style-src 'nonce-") {
                t.Error("signature raw CSP must use nonce-based style-src")
        }
        if !strings.Contains(csp, "default-src 'none'") {
                t.Error("signature raw CSP must have default-src 'none'")
        }
        if strings.Contains(csp, "img-src 'self' https:") {
                t.Error("signature raw CSP img-src must not allow blanket https:")
        }
}
