package handlers

import (
        "encoding/json"
        htmltemplate "html/template"
        "net/http"
        "net/http/httptest"
        "net/url"
        "strings"
        "testing"

        "dnstool/go-server/internal/config"

        "github.com/gin-gonic/gin"
)

func miniTemplates() *htmltemplate.Template {
        tmpl := htmltemplate.New("root")
        names := []string{
                "about.html", "admin.html", "admin_analytics.html", "admin_ops.html",
                "admin_probes.html", "approach.html", "architecture.html", "audit_log.html",
                "communication_standards.html",
                "badge_embed.html", "brand_colors.html", "changelog.html", "color_science.html",
                "compare.html", "compare_select.html", "confidence.html", "dossier.html",
                "drift.html", "email_header.html", "failures.html", "faq_subdomains.html", "manifesto.html",
                "history.html", "index.html", "investigate.html", "roadmap.html",
                "results.html", "results_covert.html", "results_executive.html",
                "roe.html", "security_policy.html", "snapshot.html", "sources.html",
                "stats.html", "toolkit.html", "ttl_tuner.html", "watchlist.html",
                "zone.html",
        }
        for _, name := range names {
                htmltemplate.Must(tmpl.New(name).Parse(`OK`))
        }
        return tmpl
}

func miniRouter() *gin.Engine {
        gin.SetMode(gin.TestMode)
        r := gin.New()
        r.Use(func(c *gin.Context) {
                c.Set("csp_nonce", "test-nonce")
                c.Set("csrf_token", "test-csrf")
                c.Next()
        })
        r.SetHTMLTemplate(miniTemplates())
        return r
}

func TestStaticSecurityTxt_CB9(t *testing.T) {
        h := NewStaticHandler(".", "v1.0.0", "https://dnstool.it-help.tech")
        router := miniRouter()
        router.GET("/.well-known/security.txt", h.SecurityTxt)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/.well-known/security.txt", nil)
        router.ServeHTTP(w, req)
}

func TestStaticRobotsTxt_CB9(t *testing.T) {
        h := NewStaticHandler(".", "v1.0.0", "https://dnstool.it-help.tech")
        router := miniRouter()
        router.GET("/robots.txt", h.RobotsTxt)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
        router.ServeHTTP(w, req)
}

func TestStaticLLMsTxt_CB9(t *testing.T) {
        h := NewStaticHandler(".", "v1.0.0", "https://dnstool.it-help.tech")
        router := miniRouter()
        router.GET("/llms.txt", h.LLMsTxt)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/llms.txt", nil)
        router.ServeHTTP(w, req)
}

func TestStaticLLMsFullTxt_CB9(t *testing.T) {
        h := NewStaticHandler(".", "v1.0.0", "https://dnstool.it-help.tech")
        router := miniRouter()
        router.GET("/llms-full.txt", h.LLMsFullTxt)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/llms-full.txt", nil)
        router.ServeHTTP(w, req)
}

func TestStaticServiceWorker_CB9(t *testing.T) {
        h := NewStaticHandler(".", "v1.0.0", "https://dnstool.it-help.tech")
        router := miniRouter()
        router.GET("/sw.js", h.ServiceWorker)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/sw.js", nil)
        router.ServeHTTP(w, req)
}

func TestStaticSitemapXML_CB9(t *testing.T) {
        h := NewStaticHandler("", "v1.0.0", "https://dnstool.it-help.tech")
        router := miniRouter()
        router.GET("/sitemap.xml", h.SitemapXML)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/sitemap.xml", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("SitemapXML: got %d", w.Code)
        }
}

func TestStaticManifestJSON_CB9(t *testing.T) {
        h := NewStaticHandler(".", "v1.0.0", "https://dnstool.it-help.tech")
        router := miniRouter()
        router.GET("/manifest.json", h.ManifestJSON)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/manifest.json", nil)
        router.ServeHTTP(w, req)
}

func TestGetChangelog_CB9(t *testing.T) {
        log := GetChangelog()
        if len(log) == 0 {
                t.Fatal("expected non-empty changelog")
        }
}

func TestGetRecentChangelog_CB9(t *testing.T) {
        log := GetRecentChangelog(3)
        if len(log) == 0 {
                t.Fatal("expected non-empty recent changelog")
        }
        if len(log) > 3 {
                t.Fatalf("expected at most 3, got %d", len(log))
        }
}

func TestGetLegacyChangelog_CB9(t *testing.T) {
        log := GetLegacyChangelog()
        if len(log) == 0 {
                t.Fatal("expected non-empty legacy changelog")
        }
}

func TestSourcesHandler_CB9(t *testing.T) {
        cfg := &config.Config{}
        h := NewSourcesHandler(cfg)
        router := miniRouter()
        router.GET("/sources", h.Sources)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/sources", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("Sources: got %d", w.Code)
        }
}

func TestBrandColorsHandler_CB9(t *testing.T) {
        cfg := &config.Config{}
        h := NewBrandColorsHandler(cfg)
        router := miniRouter()
        router.GET("/brand-colors", h.BrandColors)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/brand-colors", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("BrandColors: got %d", w.Code)
        }
}

func TestToolkitPage_CB9(t *testing.T) {
        cfg := &config.Config{}
        h := NewToolkitHandler(cfg)
        router := miniRouter()
        router.GET("/toolkit", h.ToolkitPage)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/toolkit", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("Toolkit: got %d", w.Code)
        }
}

func TestToolkitPortCheckValid_CB9(t *testing.T) {
        cfg := &config.Config{}
        h := NewToolkitHandler(cfg)
        router := miniRouter()
        router.POST("/toolkit/portcheck", h.PortCheck)

        form := url.Values{}
        form.Set("target_host", "example.com")
        form.Set("target_port", "443")
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/toolkit/portcheck", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        router.ServeHTTP(w, req)
}

func TestInvestigatePageHandler_CB9(t *testing.T) {
        cfg := &config.Config{}
        h := NewInvestigateHandler(cfg, nil)
        router := miniRouter()
        router.GET("/investigate", h.InvestigatePage)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/investigate", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("InvestigatePage: got %d", w.Code)
        }
}

func TestHealthzHandler_CB9(t *testing.T) {
        h := NewHealthHandler(nil, nil)
        router := gin.New()
        router.GET("/healthz", h.Healthz)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("Healthz: got %d", w.Code)
        }
}

func TestCapacityHandler_CB9(t *testing.T) {
        h := NewHealthHandler(nil, nil)
        router := gin.New()
        router.GET("/capacity", h.Capacity)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/capacity", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("Capacity: got %d", w.Code)
        }
        var data map[string]any
        if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
                t.Fatalf("Capacity response not valid JSON: %v", err)
        }
}

func TestMyIPHandler_CB9(t *testing.T) {
        cfg := &config.Config{}
        h := NewToolkitHandler(cfg)
        router := miniRouter()
        router.GET("/myip", h.MyIP)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/myip", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("MyIP: got %d", w.Code)
        }
}

func TestRecordAnalyticsCollector_CB9(t *testing.T) {
        c, _ := gin.CreateTestContext(httptest.NewRecorder())
        c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
        recordAnalyticsCollector(c, "example.com")

        c.Set("analytics_collector", "not-a-collector")
        recordAnalyticsCollector(c, "example.com")
}

func TestApplyDevNullHeaders_CB9(t *testing.T) {
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

        applyDevNullHeaders(c, true)
        if w.Header().Get("X-Persistence") != "/dev/null" {
                t.Fatal("expected X-Persistence header")
        }
        if w.Header().Get("X-Hacker") == "" {
                t.Fatal("expected X-Hacker header")
        }

        w2 := httptest.NewRecorder()
        c2, _ := gin.CreateTestContext(w2)
        c2.Request = httptest.NewRequest(http.MethodGet, "/", nil)
        applyDevNullHeaders(c2, false)
        if w2.Header().Get("X-Persistence") != "" {
                t.Fatal("expected no X-Persistence header when devNull is false")
        }
}

func TestExtractAuthInfo_CB9(t *testing.T) {
        c, _ := gin.CreateTestContext(httptest.NewRecorder())
        c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

        authenticated, userID := extractAuthInfo(c)
        if authenticated {
                t.Fatal("expected unauthenticated")
        }
        if userID != 0 {
                t.Fatalf("expected userID=0, got %d", userID)
        }

        c.Set("authenticated", true)
        c.Set("user_id", int32(42))
        c.Set("user_role", "admin")
        auth2, uid2 := extractAuthInfo(c)
        if !auth2 {
                t.Fatal("expected authenticated")
        }
        if uid2 != 42 {
                t.Fatalf("expected userID=42, got %d", uid2)
        }
}

func TestGetSection_CB9(t *testing.T) {
        results := map[string]any{
                "basic_records": map[string]any{
                        "A": []string{"1.2.3.4"},
                },
        }
        s := getSection(results, "basic_records")
        if s == nil {
                t.Fatal("expected non-nil section")
        }
        if _, ok := s["A"]; !ok {
                t.Fatal("expected A key in section")
        }
        s2 := getSection(results, "nonexistent")
        if len(s2) != 0 {
                t.Fatal("expected empty map for nonexistent section")
        }
}

func TestIsActiveStatus_CB9(t *testing.T) {
        if !isActiveStatus("success") {
                t.Fatal("expected 'success' to be active")
        }
        if !isActiveStatus("warning") {
                t.Fatal("expected 'warning' to be active")
        }
        if isActiveStatus("unknown") {
                t.Fatal("expected 'unknown' to not be active")
        }
        if isActiveStatus("") {
                t.Fatal("expected empty to not be active")
        }
}

func TestGetStatus_CB9(t *testing.T) {
        section := map[string]any{"status": "healthy"}
        if getStatus(section) != "healthy" {
                t.Fatalf("expected 'healthy', got %q", getStatus(section))
        }
        stateSection := map[string]any{"state": "secure"}
        if getStatus(stateSection) != "secure" {
                t.Fatalf("expected 'secure', got %q", getStatus(stateSection))
        }
        empty := map[string]any{}
        if getStatus(empty) != "unknown" {
                t.Fatalf("expected 'unknown' for missing status, got %q", getStatus(empty))
        }
}

func TestNewPaginationNegative_CB9(t *testing.T) {
        p := NewPagination(-1, 25, 100)
        if p.Page != 1 {
                t.Fatalf("expected page 1, got %d", p.Page)
        }
        if p.TotalPages < 1 {
                t.Fatal("expected at least 1 total page")
        }
}

func TestNewPaginationLargeTotal_CB9(t *testing.T) {
        p := NewPagination(1, 25, 250)
        if p.TotalPages == 0 {
                t.Fatal("expected non-zero total pages")
        }
}

func TestPaginationOffset_CB9(t *testing.T) {
        p := NewPagination(3, 25, 100)
        offset := p.Offset()
        if offset != 50 {
                t.Fatalf("expected offset 50, got %d", offset)
        }
}
