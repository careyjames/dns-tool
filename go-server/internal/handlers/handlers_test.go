// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers_test

import (
        "context"
        "encoding/json"
        "net/http"
        "net/http/httptest"
        "os"
        "path/filepath"
        "testing"
        "time"

        "dnstool/go-server/internal/analyzer"
        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/handlers"

        "github.com/gin-gonic/gin"
)

const (
        testHealthEndpoint = "/api/health"
        headerContentType  = "Content-Type"
)

func init() {
        gin.SetMode(gin.TestMode)
}

func assertStatusOK(t *testing.T, w *httptest.ResponseRecorder) {
        t.Helper()
        if w.Code != http.StatusOK {
                t.Fatalf("expected status 200, got %d", w.Code)
        }
}

func parseJSONResponse(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
        t.Helper()
        var response map[string]interface{}
        if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
                t.Fatalf("failed to parse JSON response: %v", err)
        }
        return response
}

func assertStatusOKField(t *testing.T, response map[string]interface{}) {
        t.Helper()
        if status, ok := response["status"].(string); !ok || status != "ok" {
                t.Errorf("expected status 'ok', got %v", response["status"])
        }
}

func getTestDB(t *testing.T) *db.Database {
        t.Helper()
        dbURL := os.Getenv("DATABASE_URL")
        if dbURL == "" {
                t.Skip("DATABASE_URL not set, skipping database integration test")
        }
        database, err := db.ConnectForTests(dbURL)
        if err != nil {
                t.Fatalf("Failed to connect to database: %v", err)
        }
        t.Cleanup(func() { database.Close() })
        return database
}

func TestHealthCheckEndpoint(t *testing.T) {
        database := getTestDB(t)

        router := gin.New()
        handler := handlers.NewHealthHandler(database, nil)
        router.GET(testHealthEndpoint, handler.HealthCheck)

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", testHealthEndpoint, nil)
        router.ServeHTTP(w, req)

        assertStatusOK(t, w)

        response := parseJSONResponse(t, w)
        assertStatusOKField(t, response)

        if runtime, ok := response["runtime"].(string); !ok || runtime != "go" {
                t.Errorf("expected runtime 'go', got %v", response["runtime"])
        }

        if _, ok := response["uptime"].(string); !ok {
                t.Errorf("expected uptime field as string")
        }

        if _, ok := response["database"].(map[string]interface{}); !ok {
                t.Errorf("expected database field as object")
        }

        if _, ok := response["memory"].(map[string]interface{}); !ok {
                t.Errorf("expected memory field as object")
        }
}

func TestHealthCheckWithAnalyzer(t *testing.T) {
        database := getTestDB(t)

        router := gin.New()
        analyzerInstance := analyzer.New(analyzer.WithInitialIANAFetch(false))
        handler := handlers.NewHealthHandler(database, analyzerInstance)
        router.GET(testHealthEndpoint, handler.HealthCheck)

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", testHealthEndpoint, nil)
        router.ServeHTTP(w, req)

        assertStatusOK(t, w)

        response := parseJSONResponse(t, w)
        assertStatusOKField(t, response)

        if _, ok := response["providers"]; !ok {
                t.Errorf("expected providers field when analyzer is present")
        }

        if _, ok := response["caches"]; !ok {
                t.Errorf("expected caches field when analyzer is present")
        }

        if _, ok := response["overall_provider_health"]; !ok {
                t.Errorf("expected overall_provider_health field when analyzer is present")
        }
}

func TestSitemapXML(t *testing.T) {
        router := gin.New()
        handler := handlers.NewStaticHandler("", "test", "https://dnstool.it-help.tech")
        router.GET("/sitemap.xml", handler.SitemapXML)

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/sitemap.xml", nil)
        router.ServeHTTP(w, req)

        assertStatusOK(t, w)

        contentType := w.Header().Get(headerContentType)
        if contentType != "application/xml" {
                t.Errorf("expected content-type 'application/xml', got %s", contentType)
        }

        body := w.Body.String()
        if !contains(body, "<?xml") {
                t.Error("expected XML declaration in response")
        }

        if !contains(body, "<urlset") {
                t.Error("expected <urlset element in sitemap XML")
        }

        if !contains(body, "</urlset>") {
                t.Error("expected </urlset> closing tag in sitemap XML")
        }

        if !contains(body, "https://dnstool.it-help.tech/") {
                t.Error("expected home URL in sitemap")
        }

        if !contains(body, "https://dnstool.it-help.tech/history") {
                t.Error("expected history URL in sitemap")
        }

        if !contains(body, "https://dnstool.it-help.tech/stats") {
                t.Error("expected stats URL in sitemap")
        }
}

func TestRobotsTxt(t *testing.T) {
        tempDir := t.TempDir()
        robotsContent := "User-agent: *\nDisallow: /api/\nAllow: /\n"
        robotsPath := filepath.Join(tempDir, "robots.txt")
        if err := os.WriteFile(robotsPath, []byte(robotsContent), 0644); err != nil {
                t.Fatalf("failed to create test robots.txt: %v", err)
        }

        router := gin.New()
        handler := handlers.NewStaticHandler(tempDir, "test", "https://dnstool.it-help.tech")
        router.GET("/robots.txt", handler.RobotsTxt)

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/robots.txt", nil)
        router.ServeHTTP(w, req)

        assertStatusOK(t, w)

        body := w.Body.String()
        if !contains(body, "User-agent: *") {
                t.Error("expected 'User-agent: *' in robots.txt response")
        }

        if !contains(body, "Disallow: /api/") {
                t.Error("expected 'Disallow: /api/' in robots.txt response")
        }
}

func TestLLMsTxt(t *testing.T) {
        tempDir := t.TempDir()
        llmsContent := "Model 1\nModel 2\nModel 3\n"
        llmsPath := filepath.Join(tempDir, "llms.txt")
        if err := os.WriteFile(llmsPath, []byte(llmsContent), 0644); err != nil {
                t.Fatalf("failed to create test llms.txt: %v", err)
        }

        router := gin.New()
        handler := handlers.NewStaticHandler(tempDir, "test", "https://dnstool.it-help.tech")
        router.GET("/llms.txt", handler.LLMsTxt)

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/llms.txt", nil)
        router.ServeHTTP(w, req)

        assertStatusOK(t, w)

        body := w.Body.String()
        if !contains(body, "Model 1") {
                t.Error("expected 'Model 1' in llms.txt response")
        }

        if !contains(body, "Model 2") {
                t.Error("expected 'Model 2' in llms.txt response")
        }
}

func TestManifestJSON(t *testing.T) {
        tempDir := t.TempDir()
        manifestContent := `{"name":"Test App","version":"1.0"}`
        manifestPath := filepath.Join(tempDir, "manifest.json")
        if err := os.WriteFile(manifestPath, []byte(manifestContent), 0644); err != nil {
                t.Fatalf("failed to create test manifest.json: %v", err)
        }

        router := gin.New()
        handler := handlers.NewStaticHandler(tempDir, "test", "https://dnstool.it-help.tech")
        router.GET("/manifest.json", handler.ManifestJSON)

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/manifest.json", nil)
        router.ServeHTTP(w, req)

        assertStatusOK(t, w)

        contentType := w.Header().Get(headerContentType)
        if contentType != "application/manifest+json" {
                t.Errorf("expected content-type 'application/manifest+json', got %s", contentType)
        }

        var manifest map[string]interface{}
        if err := json.Unmarshal(w.Body.Bytes(), &manifest); err != nil {
                t.Fatalf("failed to parse manifest JSON: %v", err)
        }

        if name, ok := manifest["name"].(string); !ok || name != "Test App" {
                t.Errorf("expected manifest name 'Test App', got %v", manifest["name"])
        }
}

func TestServiceWorker(t *testing.T) {
        tempDir := t.TempDir()
        swContent := "var CACHE_VERSION = 'SW_VERSION_PLACEHOLDER';\nvar CACHE_NAME = 'dnstool-' + CACHE_VERSION;"
        swPath := filepath.Join(tempDir, "sw.js")
        if err := os.WriteFile(swPath, []byte(swContent), 0644); err != nil {
                t.Fatalf("failed to create test sw.js: %v", err)
        }

        router := gin.New()
        handler := handlers.NewStaticHandler(tempDir, "26.14.6", "https://dnstool.it-help.tech")
        router.GET("/sw.js", handler.ServiceWorker)

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/sw.js", nil)
        router.ServeHTTP(w, req)

        assertStatusOK(t, w)

        contentType := w.Header().Get(headerContentType)
        if contentType != "application/javascript" {
                t.Errorf("expected content-type 'application/javascript', got %s", contentType)
        }

        body := w.Body.String()
        if !contains(body, "'26.14.6'") {
                t.Error("expected version-injected CACHE_VERSION in service worker response")
        }
        if contains(body, "SW_VERSION_PLACEHOLDER") {
                t.Error("placeholder should be replaced with actual version")
        }

        cacheControl := w.Header().Get("Cache-Control")
        if cacheControl != "no-cache, no-store, must-revalidate" {
                t.Errorf("expected no-cache Cache-Control for sw.js, got %s", cacheControl)
        }
}

func TestSecurityTxt(t *testing.T) {
        tempDir := t.TempDir()
        wellKnownDir := filepath.Join(tempDir, ".well-known")
        if err := os.MkdirAll(wellKnownDir, 0755); err != nil {
                t.Fatalf("failed to create .well-known dir: %v", err)
        }
        secContent := "Contact: security@example.com\nExpires: 2027-01-01T00:00:00.000Z\n"
        secPath := filepath.Join(wellKnownDir, "security.txt")
        if err := os.WriteFile(secPath, []byte(secContent), 0644); err != nil {
                t.Fatalf("failed to create test security.txt: %v", err)
        }

        router := gin.New()
        handler := handlers.NewStaticHandler(tempDir, "test", "https://dnstool.it-help.tech")
        router.GET("/.well-known/security.txt", handler.SecurityTxt)

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/.well-known/security.txt", nil)
        router.ServeHTTP(w, req)

        assertStatusOK(t, w)

        contentType := w.Header().Get(headerContentType)
        if contentType != "text/plain; charset=utf-8" {
                t.Errorf("expected content-type 'text/plain; charset=utf-8', got %s", contentType)
        }

        body := w.Body.String()
        if !contains(body, "Contact: security@example.com") {
                t.Error("expected 'Contact: security@example.com' in security.txt response")
        }

        if !contains(body, "Expires:") {
                t.Error("expected 'Expires:' in security.txt response")
        }
}

func TestLLMsFullTxt(t *testing.T) {
        tempDir := t.TempDir()
        content := "Full model details\nModel A v2\nModel B v3\n"
        fpath := filepath.Join(tempDir, "llms-full.txt")
        if err := os.WriteFile(fpath, []byte(content), 0644); err != nil {
                t.Fatalf("failed to create test llms-full.txt: %v", err)
        }

        router := gin.New()
        handler := handlers.NewStaticHandler(tempDir, "test", "https://dnstool.it-help.tech")
        router.GET("/llms-full.txt", handler.LLMsFullTxt)

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/llms-full.txt", nil)
        router.ServeHTTP(w, req)

        assertStatusOK(t, w)

        body := w.Body.String()
        if !contains(body, "Full model details") {
                t.Error("expected 'Full model details' in llms-full.txt response")
        }
}

func TestServiceWorkerNotFound(t *testing.T) {
        tempDir := t.TempDir()

        router := gin.New()
        handler := handlers.NewStaticHandler(tempDir, "test", "https://dnstool.it-help.tech")
        router.GET("/sw.js", handler.ServiceWorker)

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/sw.js", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusNotFound {
                t.Errorf("expected status 404 for missing sw.js, got %d", w.Code)
        }
}

func TestHealthCheckContextTimeout(t *testing.T) {
        database := getTestDB(t)

        router := gin.New()
        handler := handlers.NewHealthHandler(database, nil)
        router.GET(testHealthEndpoint, handler.HealthCheck)

        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()

        w := httptest.NewRecorder()
        req := httptest.NewRequestWithContext(ctx, "GET", testHealthEndpoint, nil)
        router.ServeHTTP(w, req)

        assertStatusOK(t, w)

        response := parseJSONResponse(t, w)
        assertStatusOKField(t, response)
}

func contains(s, substr string) bool {
        return len(s) >= len(substr) && (substr == s || len(s) > 0 && s[0:len(substr)] == substr || len(s) > len(substr) && index(s, substr) >= 0)
}

func index(s, sep string) int {
        for i := 0; i <= len(s)-len(sep); i++ {
                if s[i:i+len(sep)] == sep {
                        return i
                }
        }
        return -1
}
