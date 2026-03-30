package handlers_test

import (
        "html/template"
        "net/http"
        "net/http/httptest"
        "net/url"
        "strings"
        "testing"

        "dnstool/go-server/internal/handlers"

        "github.com/gin-gonic/gin"
)

func init() {
        gin.SetMode(gin.TestMode)
}

func injectCSPAndCSRF() gin.HandlerFunc {
        return func(c *gin.Context) {
                c.Set("csp_nonce", "test-nonce")
                c.Set("csrf_token", "test-csrf")
                c.Next()
        }
}

func allTemplates() *gin.Engine {
        r := gin.New()
        r.Use(injectCSPAndCSRF())
        tmpl := template.New("root")
        names := []string{
                "about.html", "admin.html", "admin_analytics.html", "admin_ops.html",
                "admin_probes.html", "approach.html", "architecture.html", "audit_log.html",
                "badge_embed.html", "brand_colors.html", "changelog.html", "color_science.html",
                "communication_standards.html",
                "compare.html", "compare_select.html", "confidence.html", "dossier.html",
                "drift.html", "ede.html", "email_header.html", "failures.html", "faq_subdomains.html",
                "manifesto.html",
                "history.html", "index.html", "investigate.html", "remediation.html", "roadmap.html",
                "results.html", "results_covert.html", "results_executive.html",
                "roe.html", "security_policy.html", "signature.html", "signature_raw.html",
                "snapshot.html", "sources.html",
                "stats.html", "toolkit.html", "ttl_tuner.html", "watchlist.html",
                "zone.html",
        }
        for _, name := range names {
                template.Must(tmpl.New(name).Parse(`OK`))
        }
        r.SetHTMLTemplate(tmpl)
        return r
}

func TestAdminDashboardIntegration_CB7(t *testing.T) {
        database := setupTestDB(t)
        defer cleanupTestDB(t, database)

        cfg := testConfig()
        router := allTemplates()
        handler := handlers.NewAdminHandler(database, cfg, func() int64 { return 0 })
        router.GET("/admin", handler.Dashboard)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/admin", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("Admin Dashboard: got %d, want 200; body: %s", w.Code, w.Body.String())
        }
}

func TestAdminOpsPageIntegration_CB7(t *testing.T) {
        database := setupTestDB(t)
        defer cleanupTestDB(t, database)

        cfg := testConfig()
        router := allTemplates()
        handler := handlers.NewAdminHandler(database, cfg, func() int64 { return 0 })
        router.GET("/admin/ops", handler.OperationsPage)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/admin/ops", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("Admin Ops: got %d, want 200; body: %s", w.Code, w.Body.String())
        }
}

func TestAnalyticsPageIntegration_CB7(t *testing.T) {
        database := setupTestDB(t)
        defer cleanupTestDB(t, database)

        cfg := testConfig()
        router := allTemplates()
        handler := handlers.NewAnalyticsHandler(database, cfg)
        router.GET("/admin/analytics", handler.Dashboard)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/admin/analytics", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("Analytics: got %d, want 200; body: %s", w.Code, w.Body.String())
        }
}

func TestCompareSelectIntegration_CB7(t *testing.T) {
        database := setupTestDB(t)
        defer cleanupTestDB(t, database)

        cfg := testConfig()
        router := allTemplates()
        handler := handlers.NewCompareHandler(database, cfg)
        router.GET("/compare", handler.Compare)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/compare?domain=example.com", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("CompareSelect: got %d, want 200; body: %s", w.Code, w.Body.String())
        }
}

func TestCompareSelectNoDomainIntegration_CB7(t *testing.T) {
        database := setupTestDB(t)
        defer cleanupTestDB(t, database)

        cfg := testConfig()
        router := allTemplates()
        handler := handlers.NewCompareHandler(database, cfg)
        router.GET("/compare", handler.Compare)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/compare", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("CompareSelect no domain: got %d, want 200; body: %s", w.Code, w.Body.String())
        }
}

func TestDossierPageIntegration_CB7(t *testing.T) {
        database := setupTestDB(t)
        defer cleanupTestDB(t, database)

        cfg := testConfig()
        router := allTemplates()
        handler := handlers.NewDossierHandler(database, cfg)
        router.GET("/dossier", handler.Dossier)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/dossier", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("Dossier: got %d, want 200; body: %s", w.Code, w.Body.String())
        }
}

func TestDriftPageIntegration_CB7(t *testing.T) {
        database := setupTestDB(t)
        defer cleanupTestDB(t, database)

        cfg := testConfig()
        router := allTemplates()
        handler := handlers.NewDriftHandler(database, cfg)
        router.GET("/drift/:domain", handler.Timeline)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/drift/example.com", nil)
        router.ServeHTTP(w, req)
        if w.Code == http.StatusInternalServerError {
                t.Fatalf("Drift page internal error; body: %s", w.Body.String())
        }
}

func TestExportJSONIntegration_CB7(t *testing.T) {
        database := setupTestDB(t)
        defer cleanupTestDB(t, database)

        router := gin.New()
        handler := handlers.NewExportHandler(database)
        router.GET("/export", handler.ExportJSON)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/export", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("ExportJSON: got %d, want 200", w.Code)
        }
        ct := w.Header().Get("Content-Type")
        if ct != "application/x-ndjson" {
                t.Fatalf("ExportJSON Content-Type: got %q, want application/x-ndjson", ct)
        }
}

func TestBadgeHandlerIntegration_CB7(t *testing.T) {
        database := setupTestDB(t)
        defer cleanupTestDB(t, database)

        cfg := testConfig()
        router := allTemplates()
        handler := handlers.NewBadgeHandler(database, cfg)
        router.GET("/badge/:domain", handler.Badge)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/badge/example.com", nil)
        router.ServeHTTP(w, req)
        if w.Code == http.StatusInternalServerError {
                t.Fatalf("Badge internal error; body: %s", w.Body.String())
        }
}

func TestBadgeEmbedIntegration_CB7(t *testing.T) {
        database := setupTestDB(t)
        defer cleanupTestDB(t, database)

        cfg := testConfig()
        router := allTemplates()
        handler := handlers.NewBadgeHandler(database, cfg)
        router.GET("/badge/:domain/embed", handler.BadgeEmbed)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/badge/example.com/embed", nil)
        router.ServeHTTP(w, req)
        if w.Code == http.StatusInternalServerError {
                t.Fatalf("BadgeEmbed internal error; body: %s", w.Body.String())
        }
}

func TestSnapshotHandlerMissing_CB7(t *testing.T) {
        database := setupTestDB(t)
        defer cleanupTestDB(t, database)

        cfg := testConfig()
        router := gin.New()
        handler := handlers.NewSnapshotHandler(database, cfg)
        router.GET("/snapshot/:domain", handler.Snapshot)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/snapshot/nonexistent.example.com", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusNotFound {
                t.Fatalf("Snapshot missing: got %d, want 404", w.Code)
        }
}

func TestSnapshotHandlerEmptyDomain_CB7(t *testing.T) {
        database := setupTestDB(t)
        defer cleanupTestDB(t, database)

        cfg := testConfig()
        router := gin.New()
        handler := handlers.NewSnapshotHandler(database, cfg)
        router.GET("/snapshot/:domain", handler.Snapshot)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/snapshot/", nil)
        router.ServeHTTP(w, req)
}

func TestWatchlistPageIntegration_CB7(t *testing.T) {
        database := setupTestDB(t)
        defer cleanupTestDB(t, database)

        cfg := testConfig()
        router := allTemplates()
        handler := handlers.NewWatchlistHandler(database, cfg)
        router.GET("/watchlist", handler.Watchlist)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/watchlist", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("Watchlist: got %d, want 200; body: %s", w.Code, w.Body.String())
        }
}

func TestHealthCheckFullIntegration_CB7(t *testing.T) {
        database := setupTestDB(t)
        defer cleanupTestDB(t, database)

        router := gin.New()
        handler := handlers.NewHealthHandler(database, nil)
        router.GET("/health", handler.HealthCheck)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/health", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("HealthCheck: got %d; body: %s", w.Code, w.Body.String())
        }
}

func TestToolkitPortCheckInvalidPort_CB7(t *testing.T) {
        cfg := testConfig()
        router := allTemplates()
        handler := handlers.NewToolkitHandler(cfg)
        router.POST("/toolkit/portcheck", handler.PortCheck)

        form := url.Values{}
        form.Set("target_host", "example.com")
        form.Set("target_port", "999999")
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/toolkit/portcheck", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        router.ServeHTTP(w, req)
}

func TestToolkitPortCheckMissingHost_CB7(t *testing.T) {
        cfg := testConfig()
        router := allTemplates()
        handler := handlers.NewToolkitHandler(cfg)
        router.POST("/toolkit/portcheck", handler.PortCheck)

        form := url.Values{}
        form.Set("target_host", "")
        form.Set("target_port", "443")
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/toolkit/portcheck", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        router.ServeHTTP(w, req)
}

func TestViewAnalysisBadID_CB7(t *testing.T) {
        database := setupTestDB(t)
        defer cleanupTestDB(t, database)

        cfg := testConfig()
        router := allTemplates()
        handler := handlers.NewAnalysisHandler(database, cfg, nil, nil)
        t.Cleanup(handler.Close)
        router.GET("/analysis/:id", handler.ViewAnalysis)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/analysis/abc", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusBadRequest {
                t.Fatalf("ViewAnalysis bad ID: got %d, want 400", w.Code)
        }
}

func TestViewAnalysisMissing_CB7(t *testing.T) {
        database := setupTestDB(t)
        defer cleanupTestDB(t, database)

        cfg := testConfig()
        router := allTemplates()
        handler := handlers.NewAnalysisHandler(database, cfg, nil, nil)
        t.Cleanup(handler.Close)
        router.GET("/analysis/:id", handler.ViewAnalysis)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/analysis/999999", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusNotFound {
                t.Fatalf("ViewAnalysis missing: got %d, want 404", w.Code)
        }
}

func TestViewAnalysisExecutiveBadID_CB7(t *testing.T) {
        database := setupTestDB(t)
        defer cleanupTestDB(t, database)

        cfg := testConfig()
        router := allTemplates()
        handler := handlers.NewAnalysisHandler(database, cfg, nil, nil)
        t.Cleanup(handler.Close)
        router.GET("/analysis/:id/executive", handler.ViewAnalysisExecutive)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/analysis/xyz/executive", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusBadRequest {
                t.Fatalf("ViewAnalysisExecutive bad ID: got %d, want 400", w.Code)
        }
}

func TestAnalyzeEmptyDomain_CB7(t *testing.T) {
        database := setupTestDB(t)
        defer cleanupTestDB(t, database)

        cfg := testConfig()
        router := allTemplates()
        handler := handlers.NewAnalysisHandler(database, cfg, nil, nil)
        t.Cleanup(handler.Close)
        router.POST("/analyze", handler.Analyze)

        form := url.Values{}
        form.Set("domain", "")
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/analyze", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        router.ServeHTTP(w, req)
}

func TestAPIDNSHistoryMissing_CB7(t *testing.T) {
        database := setupTestDB(t)
        defer cleanupTestDB(t, database)

        cfg := testConfig()
        router := gin.New()
        handler := handlers.NewAnalysisHandler(database, cfg, nil, nil)
        t.Cleanup(handler.Close)
        router.GET("/api/dns-history/:domain", handler.APIDNSHistory)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/api/dns-history/nonexistent.example.com", nil)
        router.ServeHTTP(w, req)
}

func TestAPIAnalysisMissing_CB7(t *testing.T) {
        database := setupTestDB(t)
        defer cleanupTestDB(t, database)

        cfg := testConfig()
        router := gin.New()
        handler := handlers.NewAnalysisHandler(database, cfg, nil, nil)
        t.Cleanup(handler.Close)
        router.GET("/api/analysis/:id", handler.APIAnalysis)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/api/analysis/999999", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusNotFound {
                t.Fatalf("API Analysis missing: got %d, want 404", w.Code)
        }
}

func TestAPIAnalysisBadID_CB7(t *testing.T) {
        database := setupTestDB(t)
        defer cleanupTestDB(t, database)

        cfg := testConfig()
        router := gin.New()
        handler := handlers.NewAnalysisHandler(database, cfg, nil, nil)
        t.Cleanup(handler.Close)
        router.GET("/api/analysis/:id", handler.APIAnalysis)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/api/analysis/abc", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusBadRequest {
                t.Fatalf("API Analysis bad ID: got %d, want 400", w.Code)
        }
}

func TestAPIAnalysisChecksumMissing_CB7(t *testing.T) {
        database := setupTestDB(t)
        defer cleanupTestDB(t, database)

        cfg := testConfig()
        router := gin.New()
        handler := handlers.NewAnalysisHandler(database, cfg, nil, nil)
        t.Cleanup(handler.Close)
        router.GET("/api/analysis/:id/checksum", handler.APIAnalysisChecksum)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/api/analysis/999999/checksum", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusNotFound {
                t.Fatalf("API Checksum missing: got %d, want 404", w.Code)
        }
}

func TestAPISubdomainsMissing_CB7(t *testing.T) {
        database := setupTestDB(t)
        defer cleanupTestDB(t, database)

        cfg := testConfig()
        router := gin.New()
        handler := handlers.NewAnalysisHandler(database, cfg, nil, nil)
        t.Cleanup(handler.Close)
        router.GET("/api/subdomains/:id", handler.APISubdomains)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/api/subdomains/999999", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusBadRequest && w.Code != http.StatusNotFound {
                t.Fatalf("API Subdomains missing: got %d, want 400 or 404", w.Code)
        }
}

func TestHomeIndexIntegration_CB7(t *testing.T) {
        database := setupTestDB(t)
        defer cleanupTestDB(t, database)

        cfg := testConfig()
        router := allTemplates()
        handler := handlers.NewHomeHandler(cfg, database)
        router.GET("/", handler.Index)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("Home Index: got %d; body: %s", w.Code, w.Body.String())
        }
}

func TestConfidenceIntegration_CB7(t *testing.T) {
        database := setupTestDB(t)
        defer cleanupTestDB(t, database)

        cfg := testConfig()
        router := allTemplates()
        handler := handlers.NewConfidenceHandler(cfg, database)
        router.GET("/confidence", handler.Confidence)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/confidence", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("Confidence: got %d; body: %s", w.Code, w.Body.String())
        }
}

func TestEmailHeaderPageIntegration_CB7(t *testing.T) {
        cfg := testConfig()
        router := allTemplates()
        handler := handlers.NewEmailHeaderHandler(cfg)
        router.GET("/email-header", handler.EmailHeaderPage)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/email-header", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("EmailHeader: got %d; body: %s", w.Code, w.Body.String())
        }
}

func TestEmailHeaderAnalyzeEmpty_CB7(t *testing.T) {
        cfg := testConfig()
        router := allTemplates()
        handler := handlers.NewEmailHeaderHandler(cfg)
        router.POST("/email-header", handler.AnalyzeEmailHeader)

        form := url.Values{}
        form.Set("raw_headers", "")
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/email-header", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        router.ServeHTTP(w, req)
}

func TestEmailHeaderAnalyzeWithHeaders_CB7(t *testing.T) {
        cfg := testConfig()
        router := allTemplates()
        handler := handlers.NewEmailHeaderHandler(cfg)
        router.POST("/email-header", handler.AnalyzeEmailHeader)

        headers := `From: test@example.com
To: recipient@example.com
Subject: Test Email
Received: from mail.example.com by mx.example.com
Date: Mon, 1 Jan 2024 00:00:00 +0000`

        form := url.Values{}
        form.Set("raw_headers", headers)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/email-header", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        router.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("EmailHeader analyze: got %d; body: %s", w.Code, w.Body.String())
        }
}

func TestProbeAdminDashboard_CB7(t *testing.T) {
        database := setupTestDB(t)
        defer cleanupTestDB(t, database)

        t.Setenv("PROBE_API_URL", "")
        t.Setenv("PROBE_API_URL_2", "")

        cfg := testConfig()
        router := allTemplates()
        handler := handlers.NewProbeAdminHandler(database, cfg)
        router.GET("/admin/probes", handler.ProbeDashboard)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/admin/probes", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("Probe Dashboard: got %d; body: %s", w.Code, w.Body.String())
        }
}
