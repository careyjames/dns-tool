package handlers

import (
        "net/http"
        "net/http/httptest"
        "os"
        "strings"
        "testing"

        "github.com/gin-gonic/gin"
)

func TestNewStaticHandler(t *testing.T) {
        h := NewStaticHandler("/static", "1.0.0", "https://example.com")
        if h == nil {
                t.Fatal("expected non-nil handler")
        }
        if h.StaticDir != "/static" {
                t.Errorf("StaticDir = %q, want /static", h.StaticDir)
        }
        if h.AppVersion != "1.0.0" {
                t.Errorf("AppVersion = %q, want 1.0.0", h.AppVersion)
        }
        if h.BaseURL != "https://example.com" {
                t.Errorf("BaseURL = %q, want https://example.com", h.BaseURL)
        }
}

func TestStaticHandlerConstants(t *testing.T) {
        if headerContentType != "Content-Type" {
                t.Errorf("headerContentType = %q", headerContentType)
        }
        if headerCacheControl != "Cache-Control" {
                t.Errorf("headerCacheControl = %q", headerCacheControl)
        }
        if cachePublicDay != "public, max-age=86400" {
                t.Errorf("cachePublicDay = %q", cachePublicDay)
        }
}

func TestSitemapPriorityConstants(t *testing.T) {
        if sitemapPriorityHigh != "0.7" {
                t.Errorf("sitemapPriorityHigh = %q", sitemapPriorityHigh)
        }
        if sitemapPriorityMedium != "0.6" {
                t.Errorf("sitemapPriorityMedium = %q", sitemapPriorityMedium)
        }
        if sitemapPriorityLow != "0.5" {
                t.Errorf("sitemapPriorityLow = %q", sitemapPriorityLow)
        }
}

func TestSitemapXMLContent(t *testing.T) {
        gin.SetMode(gin.TestMode)
        h := NewStaticHandler("/static", "1.0.0", "https://dns.example.com")

        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/sitemap.xml", nil)

        h.SitemapXML(c)

        if w.Code != http.StatusOK {
                t.Errorf("status = %d, want 200", w.Code)
        }

        body := w.Body.String()

        if !strings.Contains(body, `<?xml version="1.0"`) {
                t.Error("expected XML declaration")
        }
        if !strings.Contains(body, "<urlset") {
                t.Error("expected urlset element")
        }
        if !strings.Contains(body, "https://dns.example.com/") {
                t.Error("expected base URL in sitemap")
        }
        if !strings.Contains(body, "<priority>1.0</priority>") {
                t.Error("expected home page priority 1.0")
        }
        if !strings.Contains(body, "https://dns.example.com/investigate") {
                t.Error("expected investigate page")
        }
        if !strings.Contains(body, "https://dns.example.com/toolkit") {
                t.Error("expected toolkit page")
        }
        if !strings.Contains(body, "https://dns.example.com/roadmap") {
                t.Error("expected roadmap page")
        }

        cacheControl := w.Header().Get("Cache-Control")
        if cacheControl != "public, max-age=3600" {
                t.Errorf("Cache-Control = %q", cacheControl)
        }

        urlCount := strings.Count(body, "<url>")
        if urlCount < 10 {
                t.Errorf("expected at least 10 URLs in sitemap, got %d", urlCount)
        }
}

func TestBIMILogoSVG(t *testing.T) {
        gin.SetMode(gin.TestMode)
        tmpDir := t.TempDir()

        svgContent := `<svg version="1.2" baseProfile="tiny-ps" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256"><title>Test</title></svg>`
        if err := os.WriteFile(tmpDir+"/bimi-logo.svg", []byte(svgContent), 0644); err != nil {
                t.Fatal(err)
        }

        h := NewStaticHandler(tmpDir, "1.0.0", "https://example.com")
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/bimi-logo.svg", nil)

        h.BIMILogoSVG(c)

        if w.Code != http.StatusOK {
                t.Errorf("status = %d, want 200", w.Code)
        }
        if ct := w.Header().Get("Content-Type"); ct != "image/svg+xml" {
                t.Errorf("Content-Type = %q, want image/svg+xml", ct)
        }
        if cc := w.Header().Get("Cache-Control"); cc != cachePublicDay {
                t.Errorf("Cache-Control = %q, want %q", cc, cachePublicDay)
        }
}

func TestBIMILogoSVGNotFound(t *testing.T) {
        gin.SetMode(gin.TestMode)
        tmpDir := t.TempDir()
        h := NewStaticHandler(tmpDir, "1.0.0", "https://example.com")

        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/bimi-logo.svg", nil)

        h.BIMILogoSVG(c)

        if w.Code != http.StatusNotFound {
                t.Errorf("status = %d, want 404 when file missing", w.Code)
        }
}

func TestMethodologyPDF(t *testing.T) {
        gin.SetMode(gin.TestMode)
        tmpDir := t.TempDir()
        docsDir := tmpDir + "/docs"
        if err := os.MkdirAll(docsDir, 0o755); err != nil {
                t.Fatal(err)
        }
        if err := os.WriteFile(docsDir+"/dns-tool-methodology.pdf", []byte("%PDF-1.4 test"), 0o644); err != nil {
                t.Fatal(err)
        }
        h := NewStaticHandler(tmpDir, "2.0.0", "https://example.com")

        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/methodology", nil)

        h.MethodologyPDF(c)

        if w.Code != http.StatusOK {
                t.Errorf("status = %d, want 200", w.Code)
        }
        ct := w.Header().Get("Content-Type")
        if ct != "application/pdf" {
                t.Errorf("Content-Type = %q, want application/pdf", ct)
        }
        cc := w.Header().Get("Cache-Control")
        if cc != "public, max-age=86400" {
                t.Errorf("Cache-Control = %q, want public, max-age=86400", cc)
        }
        cd := w.Header().Get("Content-Disposition")
        if !strings.Contains(cd, "dns-tool-methodology.pdf") {
                t.Errorf("Content-Disposition = %q, should contain filename", cd)
        }
}

func TestFoundationsPDF(t *testing.T) {
        gin.SetMode(gin.TestMode)
        tmpDir := t.TempDir()
        docsDir := tmpDir + "/docs"
        if err := os.MkdirAll(docsDir, 0o755); err != nil {
                t.Fatal(err)
        }
        if err := os.WriteFile(docsDir+"/philosophical-foundations.pdf", []byte("%PDF-1.4 test"), 0o644); err != nil {
                t.Fatal(err)
        }
        h := NewStaticHandler(tmpDir, "2.0.0", "https://example.com")

        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/foundations", nil)

        h.FoundationsPDF(c)

        if w.Code != http.StatusOK {
                t.Errorf("status = %d, want 200", w.Code)
        }
        ct := w.Header().Get("Content-Type")
        if ct != "application/pdf" {
                t.Errorf("Content-Type = %q, want application/pdf", ct)
        }
        cc := w.Header().Get("Cache-Control")
        if cc != "public, max-age=86400" {
                t.Errorf("Cache-Control = %q, want public, max-age=86400", cc)
        }
        cd := w.Header().Get("Content-Disposition")
        if !strings.Contains(cd, "philosophical-foundations.pdf") {
                t.Errorf("Content-Disposition = %q, should contain filename", cd)
        }
}

func TestServiceWorkerNotFoundStatic(t *testing.T) {
        gin.SetMode(gin.TestMode)
        tmpDir := t.TempDir()
        h := NewStaticHandler(tmpDir, "2.0.0", "https://example.com")

        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/sw.js", nil)

        h.ServiceWorker(c)

        if c.Writer.Status() != http.StatusNotFound {
                t.Errorf("status = %d, want 404", c.Writer.Status())
        }
}
