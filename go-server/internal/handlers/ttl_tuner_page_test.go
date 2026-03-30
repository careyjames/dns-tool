package handlers_test

import (
        "net/http"
        "net/http/httptest"
        "net/url"
        "strings"
        "testing"

        "dnstool/go-server/internal/analyzer"
        "dnstool/go-server/internal/handlers"

        "github.com/gin-gonic/gin"
)

func ttlTunerRouter_CB10(t *testing.T) *gin.Engine {
        r := allTemplates()
        database := setupTestDB(t)
        t.Cleanup(func() { cleanupTestDB(t, database) })
        cfg := testConfig()
        a := analyzer.New(analyzer.WithInitialIANAFetch(false))
        h := handlers.NewTTLTunerHandler(cfg, a)
        r.GET("/ttl-tuner", h.TTLTunerPage)
        r.POST("/ttl-tuner/analyze", h.AnalyzeTTL)
        return r
}

func TestTTLTunerPage_CB10(t *testing.T) {
        r := ttlTunerRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/ttl-tuner", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
        }
}

func TestTTLTunerAnalyzeEmptyDomain_CB10(t *testing.T) {
        r := ttlTunerRouter_CB10(t)
        w := httptest.NewRecorder()
        form := url.Values{"domain": {""}}
        req := httptest.NewRequest(http.MethodPost, "/ttl-tuner/analyze", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        r.ServeHTTP(w, req)
        if w.Code >= 500 {
                t.Fatalf("expected non-500, got %d", w.Code)
        }
}

func TestTTLTunerAnalyzeValidDomain_CB10(t *testing.T) {
        r := ttlTunerRouter_CB10(t)
        w := httptest.NewRecorder()
        form := url.Values{"domain": {"example.com"}, "profile": {"default"}}
        req := httptest.NewRequest(http.MethodPost, "/ttl-tuner/analyze", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
        }
}

func snapshotRouter_CB10(t *testing.T) *gin.Engine {
        r := allTemplates()
        database := setupTestDB(t)
        t.Cleanup(func() { cleanupTestDB(t, database) })
        cfg := testConfig()
        h := handlers.NewSnapshotHandler(database, cfg)
        r.GET("/snapshot/:domain", h.Snapshot)
        return r
}

func TestSnapshotMissing_CB10(t *testing.T) {
        r := snapshotRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/snapshot/nonexistent.example.test", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusNotFound {
                t.Fatalf("expected 404, got %d", w.Code)
        }
}

func watchlistRouter_CB10(t *testing.T) *gin.Engine {
        r := allTemplates()
        database := setupTestDB(t)
        t.Cleanup(func() { cleanupTestDB(t, database) })
        cfg := testConfig()
        h := handlers.NewWatchlistHandler(database, cfg)
        r.GET("/watchlist", h.Watchlist)
        r.POST("/watchlist/add", h.AddDomain)
        r.POST("/watchlist/remove", h.RemoveDomain)
        r.POST("/watchlist/toggle", h.ToggleDomain)
        r.POST("/watchlist/endpoint/add", h.AddEndpoint)
        r.POST("/watchlist/endpoint/remove", h.RemoveEndpoint)
        r.POST("/watchlist/endpoint/toggle", h.ToggleEndpoint)
        r.POST("/watchlist/test-webhook", h.TestWebhook)
        return r
}

func TestWatchlistUnauthenticated_CB10(t *testing.T) {
        r := watchlistRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/watchlist", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
        }
}

func TestWatchlistAddDomainNoAuth_CB10(t *testing.T) {
        r := watchlistRouter_CB10(t)
        w := httptest.NewRecorder()
        form := url.Values{"domain": {"example.com"}}
        req := httptest.NewRequest(http.MethodPost, "/watchlist/add", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        r.ServeHTTP(w, req)
        if w.Code != http.StatusSeeOther {
                t.Fatalf("expected 303 redirect, got %d", w.Code)
        }
}

func TestWatchlistRemoveDomainNoAuth_CB10(t *testing.T) {
        r := watchlistRouter_CB10(t)
        w := httptest.NewRecorder()
        form := url.Values{"id": {"1"}}
        req := httptest.NewRequest(http.MethodPost, "/watchlist/remove", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        r.ServeHTTP(w, req)
        if w.Code != http.StatusSeeOther {
                t.Fatalf("expected 303 redirect, got %d", w.Code)
        }
}

func TestWatchlistToggleDomainNoAuth_CB10(t *testing.T) {
        r := watchlistRouter_CB10(t)
        w := httptest.NewRecorder()
        form := url.Values{"id": {"1"}}
        req := httptest.NewRequest(http.MethodPost, "/watchlist/toggle", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        r.ServeHTTP(w, req)
        if w.Code != http.StatusSeeOther {
                t.Fatalf("expected 303 redirect, got %d", w.Code)
        }
}

func TestWatchlistAddEndpointNoAuth_CB10(t *testing.T) {
        r := watchlistRouter_CB10(t)
        w := httptest.NewRecorder()
        form := url.Values{"type": {"webhook"}, "url": {"https://example.com/hook"}}
        req := httptest.NewRequest(http.MethodPost, "/watchlist/endpoint/add", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        r.ServeHTTP(w, req)
        if w.Code != http.StatusSeeOther {
                t.Fatalf("expected 303 redirect, got %d", w.Code)
        }
}

func TestWatchlistRemoveEndpointNoAuth_CB10(t *testing.T) {
        r := watchlistRouter_CB10(t)
        w := httptest.NewRecorder()
        form := url.Values{"id": {"1"}}
        req := httptest.NewRequest(http.MethodPost, "/watchlist/endpoint/remove", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        r.ServeHTTP(w, req)
        if w.Code != http.StatusSeeOther {
                t.Fatalf("expected 303 redirect, got %d", w.Code)
        }
}

func TestWatchlistToggleEndpointNoAuth_CB10(t *testing.T) {
        r := watchlistRouter_CB10(t)
        w := httptest.NewRecorder()
        form := url.Values{"id": {"1"}}
        req := httptest.NewRequest(http.MethodPost, "/watchlist/endpoint/toggle", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        r.ServeHTTP(w, req)
        if w.Code != http.StatusSeeOther {
                t.Fatalf("expected 303 redirect, got %d", w.Code)
        }
}

func TestWatchlistTestWebhookNoAuth_CB10(t *testing.T) {
        r := watchlistRouter_CB10(t)
        w := httptest.NewRecorder()
        form := url.Values{"id": {"1"}}
        req := httptest.NewRequest(http.MethodPost, "/watchlist/test-webhook", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        r.ServeHTTP(w, req)
        if w.Code != http.StatusSeeOther {
                t.Fatalf("expected 303 redirect, got %d", w.Code)
        }
}

func badgeRouter_CB10(t *testing.T) *gin.Engine {
        r := allTemplates()
        database := setupTestDB(t)
        t.Cleanup(func() { cleanupTestDB(t, database) })
        cfg := testConfig()
        h := handlers.NewBadgeHandler(database, cfg)
        r.GET("/badge/shields/:domain", h.BadgeShieldsIO)
        return r
}

func TestBadgeShieldsIONotFound_CB10(t *testing.T) {
        r := badgeRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/badge/shields/nonexistent.example.test", nil)
        r.ServeHTTP(w, req)
        if w.Code >= 500 {
                t.Fatalf("expected non-500, got %d", w.Code)
        }
}

func adminRouter_CB10(t *testing.T) *gin.Engine {
        t.Setenv("PROBE_API_URL", "")
        t.Setenv("PROBE_API_URL_2", "")

        r := allTemplates()
        database := setupTestDB(t)
        t.Cleanup(func() { cleanupTestDB(t, database) })
        cfg := testConfig()
        h := handlers.NewAdminHandler(database, cfg, nil)
        r.GET("/admin/delete-user", h.DeleteUser)
        r.GET("/admin/reset-sessions", h.ResetUserSessions)
        r.GET("/admin/purge-sessions", h.PurgeExpiredSessions)
        r.GET("/admin/ops", h.OperationsPage)
        r.POST("/admin/ops/run", h.RunOperation)

        ph := handlers.NewProbeAdminHandler(database, cfg)
        r.GET("/admin/probes", ph.ProbeDashboard)
        r.POST("/admin/probes/run", ph.RunProbeAction)

        return r
}

func TestAdminDeleteUserNoAuth_CB10(t *testing.T) {
        r := adminRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/admin/delete-user?id=999", nil)
        r.ServeHTTP(w, req)
        if w.Code >= 500 {
                t.Fatalf("expected non-500, got %d", w.Code)
        }
}

func TestAdminResetSessionsNoAuth_CB10(t *testing.T) {
        r := adminRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/admin/reset-sessions?id=999", nil)
        r.ServeHTTP(w, req)
        if w.Code >= 500 {
                t.Fatalf("expected non-500, got %d", w.Code)
        }
}

func TestAdminPurgeExpiredSessions_CB10(t *testing.T) {
        r := adminRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/admin/purge-sessions", nil)
        r.ServeHTTP(w, req)
        if w.Code >= 500 {
                t.Fatalf("expected non-500, got %d", w.Code)
        }
}

func TestAdminOpsPage_CB10(t *testing.T) {
        r := adminRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/admin/ops", nil)
        r.ServeHTTP(w, req)
        if w.Code >= 500 {
                t.Fatalf("expected non-500, got %d; body: %s", w.Code, w.Body.String())
        }
}

func TestAdminRunOperationNoAuth_CB10(t *testing.T) {
        r := adminRouter_CB10(t)
        w := httptest.NewRecorder()
        form := url.Values{"operation": {"test"}}
        req := httptest.NewRequest(http.MethodPost, "/admin/ops/run", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        r.ServeHTTP(w, req)
        if w.Code >= 500 {
                t.Fatalf("expected non-500, got %d", w.Code)
        }
}

func TestAdminProbesDashboard_CB10(t *testing.T) {
        r := adminRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/admin/probes", nil)
        r.ServeHTTP(w, req)
        if w.Code >= 500 {
                t.Fatalf("expected non-500, got %d; body: %s", w.Code, w.Body.String())
        }
}

func TestAdminRunProbeActionNoAuth_CB10(t *testing.T) {
        r := adminRouter_CB10(t)
        w := httptest.NewRecorder()
        form := url.Values{"target": {"example.com"}}
        req := httptest.NewRequest(http.MethodPost, "/admin/probes/run", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        r.ServeHTTP(w, req)
        if w.Code >= 500 {
                t.Fatalf("expected non-500, got %d", w.Code)
        }
}

func auditLogRouter_CB10(t *testing.T) *gin.Engine {
        r := allTemplates()
        database := setupTestDB(t)
        t.Cleanup(func() { cleanupTestDB(t, database) })
        cfg := testConfig()
        h := handlers.NewAuditLogHandler(cfg, database)
        r.GET("/audit-log", h.Confidence)
        return r
}

func TestAuditLogPage_CB10(t *testing.T) {
        r := auditLogRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/audit-log", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
        }
}

func TestAuditLogPageWithPagination_CB10(t *testing.T) {
        r := auditLogRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/audit-log?page=2", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }
}

func proxyRouter_CB10(t *testing.T) *gin.Engine {
        r := allTemplates()
        h := handlers.NewProxyHandler()
        r.GET("/proxy/bimi/:domain", h.BIMILogo)
        return r
}

func TestProxyBIMIMissingDomain_CB10(t *testing.T) {
        r := proxyRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/proxy/bimi/nonexistent.invalid.test", nil)
        r.ServeHTTP(w, req)
        if w.Code >= 500 {
                t.Fatalf("expected non-500, got %d", w.Code)
        }
}

func analysisAPIRouter_CB10(t *testing.T) *gin.Engine {
        r := allTemplates()
        database := setupTestDB(t)
        t.Cleanup(func() { cleanupTestDB(t, database) })
        cfg := testConfig()
        a := analyzer.New(analyzer.WithInitialIANAFetch(false))
        h := handlers.NewAnalysisHandler(database, cfg, a, nil)
        t.Cleanup(h.Close)
        r.GET("/analysis/static/:id", h.ViewAnalysisStatic)
        r.GET("/api/subdomains/*domain", h.APISubdomains)
        r.GET("/api/analysis/checksum/:id", h.APIAnalysisChecksum)
        return r
}

func TestViewAnalysisStaticNotFound_CB10(t *testing.T) {
        r := analysisAPIRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/analysis/static/999999", nil)
        r.ServeHTTP(w, req)
        if w.Code == http.StatusInternalServerError {
                t.Fatalf("expected non-500, got %d", w.Code)
        }
}

func TestAPISubdomainsEmpty_CB10(t *testing.T) {
        r := analysisAPIRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/api/subdomains/", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusBadRequest {
                t.Fatalf("expected 400, got %d", w.Code)
        }
}

func TestAPISubdomainsInvalidDomain_CB10(t *testing.T) {
        r := analysisAPIRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/api/subdomains/not-a-domain!!invalid", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusBadRequest {
                t.Fatalf("expected 400, got %d", w.Code)
        }
}

func TestAPIAnalysisChecksumNotFound_CB10(t *testing.T) {
        r := analysisAPIRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/api/analysis/checksum/999999", nil)
        r.ServeHTTP(w, req)
        if w.Code == http.StatusInternalServerError {
                t.Fatalf("expected non-500, got %d", w.Code)
        }
}

func investigateRouter_CB10(t *testing.T) *gin.Engine {
        r := allTemplates()
        cfg := testConfig()
        a := analyzer.New(analyzer.WithInitialIANAFetch(false))
        h := handlers.NewInvestigateHandler(cfg, a)
        r.GET("/investigate", h.Investigate)
        return r
}

func TestInvestigateNoDomain_CB10(t *testing.T) {
        r := investigateRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/investigate", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
        }
}

func TestInvestigateInvalidIP_CB10(t *testing.T) {
        r := investigateRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/investigate?ip=not-an-ip", nil)
        r.ServeHTTP(w, req)
        if w.Code >= 500 {
                t.Fatalf("expected non-500, got %d", w.Code)
        }
}

func compareRouter_CB10(t *testing.T) *gin.Engine {
        r := allTemplates()
        database := setupTestDB(t)
        t.Cleanup(func() { cleanupTestDB(t, database) })
        cfg := testConfig()
        h := handlers.NewCompareHandler(database, cfg)
        r.POST("/compare", h.Compare)
        return r
}

func TestComparePostNoDomains_CB10(t *testing.T) {
        r := compareRouter_CB10(t)
        w := httptest.NewRecorder()
        form := url.Values{}
        req := httptest.NewRequest(http.MethodPost, "/compare", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        r.ServeHTTP(w, req)
        if w.Code >= 500 {
                t.Fatalf("expected non-500, got %d", w.Code)
        }
}

func dossierRouter_CB10(t *testing.T) *gin.Engine {
        r := allTemplates()
        database := setupTestDB(t)
        t.Cleanup(func() { cleanupTestDB(t, database) })
        cfg := testConfig()
        h := handlers.NewDossierHandler(database, cfg)
        r.GET("/dossier", h.Dossier)
        return r
}

func TestDossierPageNoAuth_CB10(t *testing.T) {
        r := dossierRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/dossier", nil)
        r.ServeHTTP(w, req)
        if w.Code >= 500 {
                t.Fatalf("expected non-500, got %d; body: %s", w.Code, w.Body.String())
        }
}

func analysisFullRouter_CB10(t *testing.T) *gin.Engine {
        r := allTemplates()
        database := setupTestDB(t)
        t.Cleanup(func() { cleanupTestDB(t, database) })
        cfg := testConfig()
        a := analyzer.New(analyzer.WithInitialIANAFetch(false))
        h := handlers.NewAnalysisHandler(database, cfg, a, nil)
        t.Cleanup(h.Close)
        r.POST("/analyze", h.Analyze)
        r.GET("/analysis/:id/view", h.ViewAnalysis)
        r.GET("/analysis/:id/executive", h.ViewAnalysisExecutive)
        r.GET("/api/analysis/:id", h.APIAnalysis)
        r.GET("/api/dns-history/:domain", h.APIDNSHistory)
        r.GET("/export/subdomains", h.ExportSubdomainsCSV)
        return r
}

func TestAnalyzeEmptyDomainPost_CB10(t *testing.T) {
        r := analysisFullRouter_CB10(t)
        w := httptest.NewRecorder()
        form := url.Values{"domain": {""}}
        req := httptest.NewRequest(http.MethodPost, "/analyze", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("expected 200 with flash, got %d", w.Code)
        }
}

func TestAnalyzeInvalidDomainPost_CB10(t *testing.T) {
        r := analysisFullRouter_CB10(t)
        w := httptest.NewRecorder()
        form := url.Values{"domain": {"!!invalid!!"}}
        req := httptest.NewRequest(http.MethodPost, "/analyze", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("expected 200 with flash, got %d", w.Code)
        }
}

func TestViewAnalysisNotFound_CB10(t *testing.T) {
        r := analysisFullRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/analysis/999999/view", nil)
        r.ServeHTTP(w, req)
        if w.Code == http.StatusInternalServerError {
                t.Fatalf("expected non-500, got %d", w.Code)
        }
}

func TestViewAnalysisInvalidID_CB10(t *testing.T) {
        r := analysisFullRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/analysis/abc/view", nil)
        r.ServeHTTP(w, req)
        if w.Code == http.StatusInternalServerError {
                t.Fatalf("expected non-500, got %d", w.Code)
        }
}

func TestViewAnalysisExecutiveNotFound_CB10(t *testing.T) {
        r := analysisFullRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/analysis/999999/executive", nil)
        r.ServeHTTP(w, req)
        if w.Code == http.StatusInternalServerError {
                t.Fatalf("expected non-500, got %d", w.Code)
        }
}

func TestAPIAnalysisNotFound_CB10(t *testing.T) {
        r := analysisFullRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/api/analysis/999999", nil)
        r.ServeHTTP(w, req)
        if w.Code == http.StatusInternalServerError {
                t.Fatalf("expected non-500, got %d", w.Code)
        }
}

func TestAPIDNSHistoryNotFound_CB10(t *testing.T) {
        r := analysisFullRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/api/dns-history/nonexistent.example.test", nil)
        r.ServeHTTP(w, req)
        if w.Code >= 500 {
                t.Fatalf("expected non-500, got %d", w.Code)
        }
}

func TestExportSubdomainsCSVEmptyDomain_CB10(t *testing.T) {
        r := analysisFullRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/export/subdomains", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusFound {
                t.Fatalf("expected 302 redirect, got %d", w.Code)
        }
}

func TestExportSubdomainsCSVInvalidDomain_CB10(t *testing.T) {
        r := analysisFullRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/export/subdomains?domain=!!invalid!!", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusFound {
                t.Fatalf("expected 302 redirect, got %d", w.Code)
        }
}

func TestExportSubdomainsCSVNoCached_CB10(t *testing.T) {
        r := analysisFullRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/export/subdomains?domain=example.com", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusFound {
                t.Fatalf("expected 302 redirect, got %d", w.Code)
        }
}

func emailHeaderRouter_CB10(t *testing.T) *gin.Engine {
        r := allTemplates()
        cfg := testConfig()
        h := handlers.NewEmailHeaderHandler(cfg)
        r.GET("/email-header", h.EmailHeaderPage)
        r.POST("/email-header", h.AnalyzeEmailHeader)
        return r
}

func TestEmailHeaderPage_CB10(t *testing.T) {
        r := emailHeaderRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/email-header", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }
}

func TestAnalyzeEmailHeaderEmpty_CB10(t *testing.T) {
        r := emailHeaderRouter_CB10(t)
        w := httptest.NewRecorder()
        form := url.Values{"raw_headers": {""}}
        req := httptest.NewRequest(http.MethodPost, "/email-header", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }
}

func TestAnalyzeEmailHeaderValid_CB10(t *testing.T) {
        r := emailHeaderRouter_CB10(t)
        w := httptest.NewRecorder()
        rawHeaders := `From: sender@example.com
To: recipient@example.com
Subject: Test Email
Date: Mon, 1 Jan 2024 00:00:00 +0000
Message-ID: <test123@example.com>
Return-Path: <sender@example.com>
Received: from mail.example.com (mail.example.com [93.184.216.34]) by mx.example.com with ESMTP id abc123; Mon, 1 Jan 2024 00:00:00 +0000
Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com`
        form := url.Values{"raw_headers": {rawHeaders}}
        req := httptest.NewRequest(http.MethodPost, "/email-header", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }
}

func TestAnalyzeValidDomainPost_CB10(t *testing.T) {
        if testing.Short() {
                t.Skip("skipping live DNS analysis in short mode")
        }
        r := analysisFullRouter_CB10(t)
        w := httptest.NewRecorder()
        form := url.Values{"domain": {"example.com"}, "devnull": {"1"}}
        req := httptest.NewRequest(http.MethodPost, "/analyze", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        r.ServeHTTP(w, req)
        if w.Code >= 500 {
                t.Fatalf("expected non-500, got %d", w.Code)
        }
}

func authRouter_CB10(t *testing.T) *gin.Engine {
        r := allTemplates()
        database := setupTestDB(t)
        t.Cleanup(func() { cleanupTestDB(t, database) })
        cfg := testConfig()
        h := handlers.NewAuthHandler(cfg, database.Pool)
        r.GET("/auth/login", h.Login)
        r.GET("/auth/callback", h.Callback)
        r.GET("/auth/logout", h.Logout)
        return r
}

func TestAuthLogin_CB10(t *testing.T) {
        r := authRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusFound {
                t.Fatalf("expected 302 redirect to Google, got %d", w.Code)
        }
}

func TestAuthCallbackNoParams_CB10(t *testing.T) {
        r := authRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusFound {
                t.Fatalf("expected 302 redirect, got %d", w.Code)
        }
}

func TestAuthLogout_CB10(t *testing.T) {
        r := authRouter_CB10(t)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/auth/logout", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusFound {
                t.Fatalf("expected 302 redirect, got %d", w.Code)
        }
}
