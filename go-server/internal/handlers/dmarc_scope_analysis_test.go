package handlers

import (
        "encoding/json"
        "html/template"
        "net/http"
        "net/http/httptest"
        "testing"
        "time"

        "dnstool/go-server/internal/analyzer"
        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/telemetry"

        "github.com/gin-gonic/gin"
)

func init() {
        gin.SetMode(gin.TestMode)
}

func stubEngine(templateNames ...string) *gin.Engine {
        r := gin.New()
        tmpl := template.New("root")
        for _, name := range templateNames {
                template.Must(tmpl.New(name).Parse(`OK`))
        }
        r.SetHTMLTemplate(tmpl)
        return r
}

func testCfg() *config.Config {
        return &config.Config{
                AppVersion:      "test-v1",
                MaintenanceNote: "",
                BetaPages:       map[string]bool{},
                SectionTuning:   map[string]string{},
                BaseURL:         "https://dnstool.it-help.tech",
        }
}

func TestAboutHandler_CB6(t *testing.T) {
        r := stubEngine("about.html")
        h := NewAboutHandler(testCfg())
        r.GET("/about", h.About)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/about", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Errorf("About: got %d, want 200", w.Code)
        }
}

func TestApproachHandler_CB6(t *testing.T) {
        r := stubEngine("approach.html")
        h := NewApproachHandler(testCfg())
        r.GET("/approach", h.Approach)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/approach", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Errorf("Approach: got %d, want 200", w.Code)
        }
}

func TestArchitectureHandler_CB6(t *testing.T) {
        r := stubEngine("architecture.html")
        h := NewArchitectureHandler(testCfg())
        r.GET("/architecture", h.Architecture)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/architecture", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Errorf("Architecture: got %d, want 200", w.Code)
        }
}

func TestChangelogHandlerPage_CB6(t *testing.T) {
        r := stubEngine("changelog.html")
        h := NewChangelogHandler(testCfg())
        r.GET("/changelog", h.Changelog)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/changelog", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Errorf("Changelog: got %d, want 200", w.Code)
        }
}

func TestColorScienceHandler_CB6(t *testing.T) {
        r := stubEngine("color_science.html")
        h := NewColorScienceHandler(testCfg())
        r.GET("/color-science", h.ColorScience)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/color-science", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Errorf("ColorScience: got %d, want 200", w.Code)
        }
}

func TestConfidenceHandler_CB6(t *testing.T) {
        r := stubEngine("confidence.html")
        h := NewConfidenceHandler(testCfg(), nil)
        r.GET("/confidence", h.Confidence)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/confidence", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Errorf("Confidence: got %d, want 200", w.Code)
        }
}

func TestFAQSubdomainDiscovery_CB6(t *testing.T) {
        r := stubEngine("faq_subdomains.html")
        h := NewFAQHandler(testCfg())
        r.GET("/faq", h.SubdomainDiscovery)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/faq", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Errorf("FAQ: got %d, want 200", w.Code)
        }
}

func TestRoadmapHandler_CB6(t *testing.T) {
        r := stubEngine("roadmap.html")
        h := NewRoadmapHandler(testCfg())
        r.GET("/roadmap", h.Roadmap)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/roadmap", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Errorf("Roadmap: got %d, want 200", w.Code)
        }
}

func TestROEHandler_CB6(t *testing.T) {
        r := stubEngine("roe.html")
        h := NewROEHandler(testCfg())
        r.GET("/roe", h.ROE)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/roe", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Errorf("ROE: got %d, want 200", w.Code)
        }
}

func TestSecurityPolicyHandler_CB6(t *testing.T) {
        r := stubEngine("security_policy.html")
        h := NewSecurityPolicyHandler(testCfg())
        r.GET("/security-policy", h.SecurityPolicy)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/security-policy", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Errorf("SecurityPolicy: got %d, want 200", w.Code)
        }
}

func TestSourcesHandler_CB6(t *testing.T) {
        r := stubEngine("sources.html")
        h := NewSourcesHandler(testCfg())
        r.GET("/sources", h.Sources)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/sources", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Errorf("Sources: got %d, want 200", w.Code)
        }
}

func TestBrandColorsHandler_CB6(t *testing.T) {
        r := stubEngine("brand_colors.html")
        h := NewBrandColorsHandler(testCfg())
        r.GET("/brand-colors", h.BrandColors)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/brand-colors", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Errorf("BrandColors: got %d, want 200", w.Code)
        }
}

func TestToolkitPage_CB6(t *testing.T) {
        r := stubEngine("toolkit.html")
        h := NewToolkitHandler(testCfg())
        r.GET("/toolkit", h.ToolkitPage)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/toolkit", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Errorf("Toolkit: got %d, want 200", w.Code)
        }
}

func TestToolkitMyIP_CB6(t *testing.T) {
        r := stubEngine("toolkit.html")
        h := NewToolkitHandler(testCfg())
        r.GET("/toolkit/myip", h.MyIP)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/toolkit/myip", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Errorf("MyIP: got %d, want 200", w.Code)
        }
}

func TestInvestigatePage_CB6(t *testing.T) {
        r := stubEngine("investigate.html")
        h := NewInvestigateHandler(testCfg(), nil)
        r.GET("/investigate", h.InvestigatePage)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/investigate", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Errorf("Investigate: got %d, want 200", w.Code)
        }
}

func TestHomePage_CB6(t *testing.T) {
        r := stubEngine("index.html")
        h := NewHomeHandler(testCfg(), nil)
        r.GET("/", h.Index)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Errorf("Home: got %d, want 200", w.Code)
        }
}

func TestHomeWithFlash_CB6(t *testing.T) {
        r := stubEngine("index.html")
        h := NewHomeHandler(testCfg(), nil)
        r.GET("/", h.Index)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/?flash=info&flash_msg=hello", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Errorf("Home with flash: got %d, want 200", w.Code)
        }
}

func TestHomeWithWelcome_CB6(t *testing.T) {
        r := stubEngine("index.html")
        h := NewHomeHandler(testCfg(), nil)
        r.GET("/", h.Index)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/?welcome=1", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Errorf("Home welcome: got %d, want 200", w.Code)
        }
}

func TestHealthz_CB6(t *testing.T) {
        r := gin.New()
        h := NewHealthHandler(nil, nil)
        r.GET("/healthz", h.Healthz)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Errorf("Healthz: got %d, want 200", w.Code)
        }
        var resp map[string]any
        json.Unmarshal(w.Body.Bytes(), &resp)
        if resp["status"] != "ok" {
                t.Errorf("Healthz status: got %v, want ok", resp["status"])
        }
}

func TestCapacity_NilAnalyzer_CB6(t *testing.T) {
        r := gin.New()
        h := NewHealthHandler(nil, nil)
        r.GET("/capacity", h.Capacity)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/capacity", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Errorf("Capacity: got %d, want 200", w.Code)
        }
        var resp map[string]any
        json.Unmarshal(w.Body.Bytes(), &resp)
        if resp["available"] != true {
                t.Errorf("Capacity available: got %v, want true", resp["available"])
        }
}

func TestSitemapXML_CB6(t *testing.T) {
        r := gin.New()
        h := NewStaticHandler("/tmp", "v1", "https://dnstool.it-help.tech")
        r.GET("/sitemap.xml", h.SitemapXML)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/sitemap.xml", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Errorf("Sitemap: got %d, want 200", w.Code)
        }
        body := w.Body.String()
        if len(body) < 100 {
                t.Error("Sitemap body too short")
        }
        ct := w.Header().Get("Content-Type")
        if ct != "application/xml" {
                t.Errorf("Sitemap content-type: got %q", ct)
        }
}

func TestServiceWorker_Missing_CB6(t *testing.T) {
        r := gin.New()
        h := NewStaticHandler("/tmp/nonexistent", "v1", "https://example.com")
        r.GET("/sw.js", h.ServiceWorker)
        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/sw.js", nil)
        r.ServeHTTP(w, req)
        if w.Code != http.StatusNotFound {
                t.Errorf("ServiceWorker missing: got %d, want 404", w.Code)
        }
}

func TestBuildProviderEntries_CB6(t *testing.T) {
        now := time.Now()
        stats := []telemetry.ProviderStats{
                {
                        Name:            "test-provider",
                        State:           telemetry.Healthy,
                        TotalRequests:   100,
                        SuccessCount:    95,
                        FailureCount:    5,
                        ConsecFailures:  0,
                        AvgLatencyMs:    50.0,
                        P95LatencyMs:    120.0,
                        InCooldown:      false,
                        LastError:       "timeout",
                        LastErrorTime:   &now,
                        LastSuccessTime: &now,
                },
        }
        entries := buildProviderEntries(stats)
        if len(entries) != 1 {
                t.Fatalf("expected 1 entry, got %d", len(entries))
        }
        if entries[0]["name"] != "test-provider" {
                t.Errorf("expected test-provider, got %v", entries[0]["name"])
        }
        if entries[0]["last_error"] != "timeout" {
                t.Errorf("expected timeout error, got %v", entries[0]["last_error"])
        }
        if _, ok := entries[0]["last_error_time"]; !ok {
                t.Error("expected last_error_time")
        }
        if _, ok := entries[0]["last_success_time"]; !ok {
                t.Error("expected last_success_time")
        }
}

func TestBuildProviderEntries_NoOptionals_CB6(t *testing.T) {
        stats := []telemetry.ProviderStats{
                {Name: "clean", State: telemetry.Healthy},
        }
        entries := buildProviderEntries(stats)
        if _, ok := entries[0]["last_error"]; ok {
                t.Error("should not have last_error when empty")
        }
}

func TestComputeOverallHealth_CB6(t *testing.T) {
        tests := []struct {
                name   string
                stats  []telemetry.ProviderStats
                expect string
        }{
                {"empty", nil, string(telemetry.Healthy)},
                {"all healthy", []telemetry.ProviderStats{{State: telemetry.Healthy}}, string(telemetry.Healthy)},
                {"one degraded", []telemetry.ProviderStats{{State: telemetry.Healthy}, {State: telemetry.Degraded}}, string(telemetry.Degraded)},
                {"one unhealthy", []telemetry.ProviderStats{{State: telemetry.Healthy}, {State: telemetry.Unhealthy}}, string(telemetry.Unhealthy)},
                {"unhealthy wins", []telemetry.ProviderStats{{State: telemetry.Degraded}, {State: telemetry.Unhealthy}}, string(telemetry.Unhealthy)},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := computeOverallHealth(tt.stats)
                        if got != tt.expect {
                                t.Errorf("computeOverallHealth = %q, want %q", got, tt.expect)
                        }
                })
        }
}

func TestExtractAnalysisError_CB6(t *testing.T) {
        t.Run("no error", func(t *testing.T) {
                ok, errStr := extractAnalysisError(map[string]any{"status": "ok"})
                if !ok {
                        t.Error("expected ok=true for no error")
                }
                if errStr != nil {
                        t.Error("expected nil error string")
                }
        })
        t.Run("with error", func(t *testing.T) {
                ok, errStr := extractAnalysisError(map[string]any{"error": "DNS timeout"})
                if ok {
                        t.Error("expected ok=false for error")
                }
                if errStr == nil || *errStr != "DNS timeout" {
                        t.Errorf("expected 'DNS timeout', got %v", errStr)
                }
        })
        t.Run("empty error string", func(t *testing.T) {
                ok, errStr := extractAnalysisError(map[string]any{"error": ""})
                if !ok {
                        t.Error("expected ok=true for empty error string")
                }
                if errStr != nil {
                        t.Error("expected nil for empty error")
                }
        })
}

func TestOptionalStrings_CB6(t *testing.T) {
        t.Run("both empty", func(t *testing.T) {
                a, b := optionalStrings("", "")
                if a != nil || b != nil {
                        t.Error("expected both nil")
                }
        })
        t.Run("both present", func(t *testing.T) {
                a, b := optionalStrings("x", "y")
                if a == nil || *a != "x" {
                        t.Error("expected a=x")
                }
                if b == nil || *b != "y" {
                        t.Error("expected b=y")
                }
        })
        t.Run("mixed", func(t *testing.T) {
                a, b := optionalStrings("x", "")
                if a == nil || *a != "x" {
                        t.Error("expected a=x")
                }
                if b != nil {
                        t.Error("expected b=nil")
                }
        })
}

func TestGetStringFromResults_CB6(t *testing.T) {
        results := map[string]any{
                "top_level": "hello",
                "section": map[string]any{
                        "key1": "value1",
                        "key2": 42,
                },
        }
        t.Run("top level", func(t *testing.T) {
                got := getStringFromResults(results, "top_level", "")
                if got == nil || *got != "hello" {
                        t.Errorf("expected hello, got %v", got)
                }
        })
        t.Run("nested", func(t *testing.T) {
                got := getStringFromResults(results, "section", "key1")
                if got == nil || *got != "value1" {
                        t.Errorf("expected value1, got %v", got)
                }
        })
        t.Run("missing section", func(t *testing.T) {
                got := getStringFromResults(results, "missing", "key")
                if got != nil {
                        t.Error("expected nil for missing section")
                }
        })
        t.Run("non-string value", func(t *testing.T) {
                got := getStringFromResults(results, "section", "key2")
                if got != nil {
                        t.Error("expected nil for non-string value")
                }
        })
        t.Run("missing key", func(t *testing.T) {
                got := getStringFromResults(results, "section", "missing")
                if got != nil {
                        t.Error("expected nil for missing key")
                }
        })
        t.Run("top level missing", func(t *testing.T) {
                got := getStringFromResults(results, "nope", "")
                if got != nil {
                        t.Error("expected nil for missing top level")
                }
        })
        t.Run("top level non-string", func(t *testing.T) {
                got := getStringFromResults(map[string]any{"num": 42}, "num", "")
                if got != nil {
                        t.Error("expected nil for non-string top level")
                }
        })
}

func TestGetJSONFromResults_CB6(t *testing.T) {
        results := map[string]any{
                "top": "hello",
                "section": map[string]any{
                        "key": "value",
                },
        }
        t.Run("top level", func(t *testing.T) {
                got := getJSONFromResults(results, "top", "")
                if got == nil {
                        t.Fatal("expected non-nil")
                }
                if string(got) != `"hello"` {
                        t.Errorf("expected '\"hello\"', got %s", string(got))
                }
        })
        t.Run("nested", func(t *testing.T) {
                got := getJSONFromResults(results, "section", "key")
                if got == nil {
                        t.Fatal("expected non-nil")
                }
        })
        t.Run("missing top", func(t *testing.T) {
                got := getJSONFromResults(results, "missing", "")
                if got != nil {
                        t.Error("expected nil")
                }
        })
        t.Run("missing section", func(t *testing.T) {
                got := getJSONFromResults(results, "nope", "key")
                if got != nil {
                        t.Error("expected nil for missing section")
                }
        })
        t.Run("missing key", func(t *testing.T) {
                got := getJSONFromResults(results, "section", "nope")
                if got != nil {
                        t.Error("expected nil for missing key")
                }
        })
}

func TestProtocolRawConfidence_CB6(t *testing.T) {
        tests := []struct {
                status string
                want   float64
        }{
                {"secure", 1.0},
                {"pass", 1.0},
                {"valid", 1.0},
                {"good", 1.0},
                {"warning", 0.7},
                {"info", 0.7},
                {"partial", 0.7},
                {"fail", 0.3},
                {"danger", 0.3},
                {"critical", 0.3},
                {"error", 0.0},
                {"n/a", 0.0},
                {"", 0.0},
                {"unknown", 0.5},
        }
        for _, tt := range tests {
                t.Run(tt.status, func(t *testing.T) {
                        results := map[string]any{
                                "spf_analysis": map[string]any{"status": tt.status},
                        }
                        got := protocolRawConfidence(results, "spf_analysis")
                        if got != tt.want {
                                t.Errorf("protocolRawConfidence(%q) = %v, want %v", tt.status, got, tt.want)
                        }
                })
        }
        t.Run("missing section", func(t *testing.T) {
                got := protocolRawConfidence(map[string]any{}, "spf_analysis")
                if got != 0.0 {
                        t.Errorf("expected 0.0 for missing section, got %v", got)
                }
        })
}

func TestAggregateResolverAgreement_CB6(t *testing.T) {
        t.Run("no consensus data", func(t *testing.T) {
                agree, total := aggregateResolverAgreement(map[string]any{})
                if agree != 0 || total != 0 {
                        t.Errorf("expected 0,0 got %d,%d", agree, total)
                }
        })
        t.Run("no per_record", func(t *testing.T) {
                results := map[string]any{
                        "resolver_consensus": map[string]any{},
                }
                agree, total := aggregateResolverAgreement(results)
                if agree != 0 || total != 0 {
                        t.Errorf("expected 0,0 got %d,%d", agree, total)
                }
        })
        t.Run("with consensus", func(t *testing.T) {
                results := map[string]any{
                        "resolver_consensus": map[string]any{
                                "per_record_consensus": map[string]any{
                                        "A": map[string]any{
                                                "resolver_count": 4,
                                                "consensus":      true,
                                        },
                                        "MX": map[string]any{
                                                "resolver_count": 4,
                                                "consensus":      false,
                                        },
                                },
                        },
                }
                agree, total := aggregateResolverAgreement(results)
                if total != 8 {
                        t.Errorf("expected total=8, got %d", total)
                }
                if agree != 7 {
                        t.Errorf("expected agree=7, got %d", agree)
                }
        })
}

func TestLookupCountry_CB6(t *testing.T) {
        t.Run("empty ip", func(t *testing.T) {
                code, name := lookupCountry("")
                if code != "" || name != "" {
                        t.Errorf("expected empty for empty ip, got %q %q", code, name)
                }
        })
        t.Run("localhost", func(t *testing.T) {
                code, name := lookupCountry("127.0.0.1")
                if code != "" || name != "" {
                        t.Errorf("expected empty for localhost, got %q %q", code, name)
                }
        })
        t.Run("ipv6 localhost", func(t *testing.T) {
                code, name := lookupCountry("::1")
                if code != "" || name != "" {
                        t.Errorf("expected empty for ::1, got %q %q", code, name)
                }
        })
}

func TestMergeAuthData_CB6(t *testing.T) {
        t.Run("unauthenticated", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
                data := gin.H{}
                mergeAuthData(c, testCfg(), data)
                if _, ok := data["Authenticated"]; ok {
                        t.Error("should not have Authenticated")
                }
        })
        t.Run("authenticated", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
                c.Set("authenticated", true)
                c.Set("user_email", "test@example.com")
                c.Set("user_name", "Test User")
                c.Set("user_role", "admin")
                data := gin.H{}
                mergeAuthData(c, testCfg(), data)
                if data["Authenticated"] != true {
                        t.Error("expected Authenticated=true")
                }
                if data["UserEmail"] != "test@example.com" {
                        t.Errorf("expected test@example.com, got %v", data["UserEmail"])
                }
        })
        t.Run("google auth enabled", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
                cfg := testCfg()
                cfg.GoogleClientID = "test-client-id"
                data := gin.H{}
                mergeAuthData(c, cfg, data)
                if data["GoogleAuthEnabled"] != true {
                        t.Error("expected GoogleAuthEnabled=true with GoogleClientID set")
                }
        })
}

func TestBuildCacheEntries_NilRDAPCache_CB6(t *testing.T) {
        a := &analyzer.Analyzer{}
        entries := buildCacheEntries(a)
        if len(entries) == 0 {
                t.Fatal("expected at least dns_query cache entry")
        }
        found := false
        for _, e := range entries {
                if e["name"] == "dns_query" {
                        found = true
                }
        }
        if !found {
                t.Error("expected dns_query cache entry")
        }
}

func TestComputeDriftFromPrev_CB6(t *testing.T) {
        t.Run("nil prev hash", func(t *testing.T) {
                di := computeDriftFromPrev("abc", prevAnalysisSnapshot{}, map[string]any{})
                if di.Detected {
                        t.Error("should not detect drift with nil prev hash")
                }
        })
        t.Run("same hash", func(t *testing.T) {
                h := "abc123"
                di := computeDriftFromPrev("abc123", prevAnalysisSnapshot{Hash: &h}, map[string]any{})
                if di.Detected {
                        t.Error("should not detect drift with same hash")
                }
        })
        t.Run("empty prev hash", func(t *testing.T) {
                h := ""
                di := computeDriftFromPrev("abc123", prevAnalysisSnapshot{Hash: &h}, map[string]any{})
                if di.Detected {
                        t.Error("should not detect drift with empty prev hash")
                }
        })
        t.Run("different hash with time", func(t *testing.T) {
                h := "old-hash"
                ts := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
                di := computeDriftFromPrev("new-hash", prevAnalysisSnapshot{
                        Hash:           &h,
                        ID:             42,
                        CreatedAtValid: true,
                        CreatedAt:      ts,
                }, map[string]any{})
                if !di.Detected {
                        t.Error("expected drift detected")
                }
                if di.PrevHash != "old-hash" {
                        t.Errorf("expected old-hash, got %q", di.PrevHash)
                }
                if di.PrevID != 42 {
                        t.Errorf("expected PrevID=42, got %d", di.PrevID)
                }
                if di.PrevTime == "" {
                        t.Error("expected non-empty PrevTime")
                }
        })
        t.Run("different hash with full results", func(t *testing.T) {
                h := "old"
                prev := map[string]any{"posture": map[string]any{"risk": "low"}}
                prevJSON, _ := json.Marshal(prev)
                di := computeDriftFromPrev("new", prevAnalysisSnapshot{
                        Hash:        &h,
                        FullResults: prevJSON,
                }, map[string]any{"posture": map[string]any{"risk": "high"}})
                if !di.Detected {
                        t.Error("expected drift detected")
                }
        })
}

func TestCsvEscape_CB6(t *testing.T) {
        tests := []struct {
                input, want string
        }{
                {"hello", "hello"},
                {`has "quotes"`, `"has ""quotes"""`},
                {"has,comma", `"has,comma"`},
                {"has\nnewline", `"has` + "\n" + `newline"`},
        }
        for _, tt := range tests {
                got := csvEscape(tt.input)
                if got != tt.want {
                        t.Errorf("csvEscape(%q) = %q, want %q", tt.input, got, tt.want)
                }
        }
}

func TestNormalizeForCompare_CB6(t *testing.T) {
        t.Run("non-slice returns unchanged", func(t *testing.T) {
                got := normalizeForCompare(float64(42))
                if got != float64(42) {
                        t.Errorf("expected float64(42), got %v (%T)", got, got)
                }
        })
        t.Run("string returns unchanged", func(t *testing.T) {
                got := normalizeForCompare("hello")
                if got != "hello" {
                        t.Errorf("expected hello, got %v", got)
                }
        })
        t.Run("nil returns nil", func(t *testing.T) {
                got := normalizeForCompare(nil)
                if got != nil {
                        t.Errorf("expected nil, got %v", got)
                }
        })
        t.Run("short slice returns unchanged", func(t *testing.T) {
                input := []interface{}{"single"}
                got := normalizeForCompare(input)
                arr, ok := got.([]interface{})
                if !ok {
                        t.Fatalf("expected []interface{}, got %T", got)
                }
                if len(arr) != 1 {
                        t.Errorf("expected len 1, got %d", len(arr))
                }
        })
        t.Run("sorts string slice", func(t *testing.T) {
                input := []interface{}{"banana", "apple"}
                got := normalizeForCompare(input)
                arr, ok := got.([]interface{})
                if !ok {
                        t.Fatalf("expected []interface{}, got %T", got)
                }
                if arr[0] != "apple" || arr[1] != "banana" {
                        t.Errorf("expected [apple, banana], got %v", arr)
                }
        })
}

func TestParseSortedElement_CB6(t *testing.T) {
        t.Run("string first", func(t *testing.T) {
                got := parseSortedElement("hello", true)
                if got != "hello" {
                        t.Errorf("expected hello, got %v", got)
                }
        })
        t.Run("number with firstIsString=false", func(t *testing.T) {
                got := parseSortedElement("42", false)
                if got != float64(42) {
                        t.Errorf("expected float64(42), got %v (%T)", got, got)
                }
        })
        t.Run("number with firstIsString=true", func(t *testing.T) {
                got := parseSortedElement("42", true)
                if got != "42" {
                        t.Errorf("expected '42', got %v", got)
                }
        })
        t.Run("invalid json with firstIsString=false", func(t *testing.T) {
                got := parseSortedElement("{bad", false)
                if got != "{bad" {
                        t.Errorf("expected '{bad', got %v", got)
                }
        })
}

func TestCheckPrivateAccess_CB6(t *testing.T) {
        t.Run("not private", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
                h := &AnalysisHandler{Config: testCfg()}
                if !h.checkPrivateAccess(c, 1, false) {
                        t.Error("expected true for non-private analysis")
                }
        })
        t.Run("private no auth", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
                h := &AnalysisHandler{Config: testCfg()}
                if h.checkPrivateAccess(c, 1, true) {
                        t.Error("expected false for private analysis without auth")
                }
        })
}

func TestEnrichResultsNoHistory_CB6(t *testing.T) {
        h := &AnalysisHandler{Config: testCfg()}
        results := map[string]any{
                "spf_analysis": map[string]any{"status": "pass"},
        }
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
        h.enrichResultsNoHistory(c, "example.com", results)
}

func TestExtractAuthInfo_CB6(t *testing.T) {
        t.Run("no auth", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
                isAuth, uid := extractAuthInfo(c)
                if isAuth {
                        t.Error("expected not authenticated")
                }
                if uid != 0 {
                        t.Errorf("expected uid=0, got %d", uid)
                }
        })
        t.Run("with auth", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
                c.Set("authenticated", true)
                c.Set("user_id", int32(42))
                isAuth, uid := extractAuthInfo(c)
                if !isAuth {
                        t.Error("expected authenticated")
                }
                if uid != 42 {
                        t.Errorf("expected uid=42, got %d", uid)
                }
        })
}

func TestApplyDevNullHeaders_CB6(t *testing.T) {
        t.Run("devnull true", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
                applyDevNullHeaders(c, true)
                if w.Header().Get("X-Persistence") != "/dev/null" {
                        t.Error("expected X-Persistence header for devNull")
                }
                if w.Header().Get("X-Hacker") == "" {
                        t.Error("expected X-Hacker header for devNull")
                }
        })
        t.Run("devnull false", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
                applyDevNullHeaders(c, false)
                if w.Header().Get("X-Persistence") != "" {
                        t.Error("should not set X-Persistence when devNull is false")
                }
        })
}

func TestLogEphemeralReason_CB6(t *testing.T) {
        logEphemeralReason("example.com", true, false)
        logEphemeralReason("example.com", false, false)
        logEphemeralReason("localhost", false, true)
}

func TestResolveCovertMode_CB6(t *testing.T) {
        t.Run("covert query param", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest(http.MethodGet, "/?covert=1", nil)
                got := resolveCovertMode(c, "example.com")
                if got != "C" {
                        t.Errorf("expected C, got %q", got)
                }
        })
        t.Run("no covert param", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
                got := resolveCovertMode(c, "example.com")
                if got != "E" {
                        t.Errorf("expected E, got %q", got)
                }
        })
        t.Run("TLD without covert", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
                got := resolveCovertMode(c, "com")
                if got != "Z" {
                        t.Errorf("expected Z, got %q", got)
                }
        })
        t.Run("TLD with covert", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest(http.MethodGet, "/?covert=1", nil)
                got := resolveCovertMode(c, "com")
                if got != "CZ" {
                        t.Errorf("expected CZ, got %q", got)
                }
        })
}

func TestResolveReportMode_CB6(t *testing.T) {
        t.Run("no mode param defaults to E", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
                got := resolveReportMode(c)
                if got != "E" {
                        t.Errorf("expected E, got %q", got)
                }
        })
        t.Run("covert query param", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest(http.MethodGet, "/?covert=1", nil)
                got := resolveReportMode(c)
                if got != "C" {
                        t.Errorf("expected C, got %q", got)
                }
        })
        t.Run("mode param via gin params", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
                c.Params = gin.Params{{Key: "mode", Value: "B"}}
                got := resolveReportMode(c)
                if got != "B" {
                        t.Errorf("expected B, got %q", got)
                }
        })
}

func TestResultsDomainExists_CB6(t *testing.T) {
        t.Run("exists", func(t *testing.T) {
                results := map[string]any{"domain_exists": true}
                if !resultsDomainExists(results) {
                        t.Error("expected true")
                }
        })
        t.Run("not exists", func(t *testing.T) {
                results := map[string]any{"domain_exists": false}
                if resultsDomainExists(results) {
                        t.Error("expected false")
                }
        })
        t.Run("missing key", func(t *testing.T) {
                results := map[string]any{}
                if !resultsDomainExists(results) {
                        t.Error("expected true for missing key")
                }
        })
}

func TestExtractToolVersion_CB6(t *testing.T) {
        t.Run("present", func(t *testing.T) {
                results := map[string]any{"_tool_version": "1.0.0"}
                got := extractToolVersion(results)
                if got != "1.0.0" {
                        t.Errorf("expected 1.0.0, got %q", got)
                }
        })
        t.Run("missing", func(t *testing.T) {
                results := map[string]any{}
                got := extractToolVersion(results)
                if got != "" {
                        t.Errorf("expected empty, got %q", got)
                }
        })
}

func TestNewHomeHandler_CB6(t *testing.T) {
        cfg := testCfg()
        h := NewHomeHandler(cfg, nil)
        if h == nil {
                t.Fatal("expected non-nil HomeHandler")
        }
        if h.Config != cfg {
                t.Error("expected Config to match")
        }
}

func TestNewStaticHandler_CB6(t *testing.T) {
        h := NewStaticHandler("/static", "v1", "https://example.com")
        if h == nil {
                t.Fatal("expected non-nil StaticHandler")
        }
        if h.AppVersion != "v1" {
                t.Errorf("expected v1, got %s", h.AppVersion)
        }
}

func TestNewToolkitHandler_CB6(t *testing.T) {
        h := NewToolkitHandler(testCfg())
        if h == nil {
                t.Fatal("expected non-nil ToolkitHandler")
        }
}

func TestNewInvestigateHandler_CB6(t *testing.T) {
        h := NewInvestigateHandler(testCfg(), nil)
        if h == nil {
                t.Fatal("expected non-nil InvestigateHandler")
        }
}

func TestNewBrandColorsHandler_CB6(t *testing.T) {
        h := NewBrandColorsHandler(testCfg())
        if h == nil {
                t.Fatal("expected non-nil BrandColorsHandler")
        }
}

func TestGetBrandPalette_CB6(t *testing.T) {
        colors := getBrandPalette()
        if len(colors) == 0 {
                t.Error("expected non-empty brand palette")
        }
        for _, c := range colors {
                if c.Name == "" || c.Value == "" {
                        t.Errorf("brand color missing name or value: %+v", c)
                }
        }
}

func TestGetStatusColors_CB6(t *testing.T) {
        colors := getStatusColors()
        if len(colors) == 0 {
                t.Error("expected non-empty status colors")
        }
}

func TestGetSurfaceColors_CB6(t *testing.T) {
        colors := getSurfaceColors()
        if len(colors) == 0 {
                t.Error("expected non-empty surface colors")
        }
}

func TestGetTLPColors_CB6(t *testing.T) {
        colors := getTLPColors()
        if len(colors) == 0 {
                t.Error("expected non-empty TLP colors")
        }
}

func TestGetCVSSColors_CB6(t *testing.T) {
        colors := getCVSSColors()
        if len(colors) == 0 {
                t.Error("expected non-empty CVSS colors")
        }
        for _, c := range colors {
                if c.SourceURL == "" {
                        t.Errorf("CVSS color missing source URL: %+v", c)
                }
        }
}

func TestHasLocalMXRecords_CB6(t *testing.T) {
        t.Run("no mx", func(t *testing.T) {
                if hasLocalMXRecords(map[string]any{}) {
                        t.Error("expected false for no MX")
                }
        })
        t.Run("with mx", func(t *testing.T) {
                results := map[string]any{
                        "basic_records": map[string]any{
                                "MX": []any{
                                        map[string]any{"Host": "mail.example.com."},
                                },
                        },
                }
                if !hasLocalMXRecords(results) {
                        t.Error("expected true for MX present")
                }
        })
        t.Run("empty mx list", func(t *testing.T) {
                results := map[string]any{
                        "basic_records": map[string]any{
                                "MX": []any{},
                        },
                }
                if hasLocalMXRecords(results) {
                        t.Error("expected false for empty MX list")
                }
        })
        t.Run("string slice mx", func(t *testing.T) {
                results := map[string]any{
                        "basic_records": map[string]any{
                                "MX": []string{"mail.example.com"},
                        },
                }
                if !hasLocalMXRecords(results) {
                        t.Error("expected true for string MX")
                }
        })
}

func TestDetermineSPFScope_CB6(t *testing.T) {
        t.Run("has spf", func(t *testing.T) {
                scope, verdict := determineSPFScope(true)
                if scope == "" || verdict == "" {
                        t.Error("expected non-empty scope and verdict")
                }
        })
        t.Run("no spf", func(t *testing.T) {
                scope, verdict := determineSPFScope(false)
                if scope == "" || verdict == "" {
                        t.Error("expected non-empty scope and verdict for no SPF")
                }
        })
}

func TestDetermineDMARCScope_CB6(t *testing.T) {
        t.Run("sub has dmarc", func(t *testing.T) {
                scope, verdict := determineDMARCScope(true, false, "", "example.com")
                if scope == "" {
                        t.Error("expected non-empty scope")
                }
                if verdict == "" {
                        t.Error("expected non-empty verdict")
                }
        })
        t.Run("org has dmarc reject", func(t *testing.T) {
                scope, _ := determineDMARCScope(false, true, "reject", "example.com")
                if scope == "" {
                        t.Error("expected non-empty scope")
                }
        })
        t.Run("no dmarc anywhere", func(t *testing.T) {
                scope, _ := determineDMARCScope(false, false, "", "example.com")
                if scope == "" {
                        t.Error("expected non-empty scope")
                }
        })
}

func TestParseOrgDMARC_CB6(t *testing.T) {
        t.Run("reject policy", func(t *testing.T) {
                ok, policy := parseOrgDMARC([]string{"v=DMARC1; p=reject"})
                if !ok {
                        t.Error("expected ok=true")
                }
                if policy != "reject" {
                        t.Errorf("expected reject, got %q", policy)
                }
        })
        t.Run("no records", func(t *testing.T) {
                ok, _ := parseOrgDMARC(nil)
                if ok {
                        t.Error("expected ok=false for no records")
                }
        })
        t.Run("no p tag returns ok with empty policy", func(t *testing.T) {
                ok, policy := parseOrgDMARC([]string{"v=DMARC1"})
                if !ok {
                        t.Error("expected ok=true for valid DMARC record without p tag")
                }
                if policy != "" {
                        t.Errorf("expected empty policy, got %q", policy)
                }
        })
}

func TestIsPublicSuffixDomain_CB6(t *testing.T) {
        tests := []struct {
                domain string
                want   bool
        }{
                {"com", true},
                {"co.uk", true},
                {"example.com", false},
                {"test.co.uk", false},
        }
        for _, tt := range tests {
                t.Run(tt.domain, func(t *testing.T) {
                        got := isPublicSuffixDomain(tt.domain)
                        if got != tt.want {
                                t.Errorf("isPublicSuffixDomain(%q) = %v, want %v", tt.domain, got, tt.want)
                        }
                })
        }
}

func TestIsTwoPartSuffix_CB6(t *testing.T) {
        tests := []struct {
                domain string
                want   bool
        }{
                {"co.uk", true},
                {"com.au", true},
                {"com", false},
                {"example.com", false},
        }
        for _, tt := range tests {
                t.Run(tt.domain, func(t *testing.T) {
                        got := isTwoPartSuffix(tt.domain)
                        if got != tt.want {
                                t.Errorf("isTwoPartSuffix(%q) = %v, want %v", tt.domain, got, tt.want)
                        }
                })
        }
}

func TestExtractRootDomain_CB6(t *testing.T) {
        tests := []struct {
                domain string
                isSub  bool
                root   string
        }{
                {"example.com", false, ""},
                {"sub.example.com", true, "example.com"},
                {"deep.sub.example.com", true, "example.com"},
                {"com", false, ""},
        }
        for _, tt := range tests {
                t.Run(tt.domain, func(t *testing.T) {
                        isSub, root := extractRootDomain(tt.domain)
                        if isSub != tt.isSub {
                                t.Errorf("isSub = %v, want %v", isSub, tt.isSub)
                        }
                        if root != tt.root {
                                t.Errorf("root = %q, want %q", root, tt.root)
                        }
                })
        }
}
