package middleware

import (
        "html/template"
        "net/http"
        "net/http/httptest"
        "os"
        "strings"
        "testing"
        "time"

        "github.com/gin-gonic/gin"
)

func TestSecurityHeadersStaticPath(t *testing.T) {
        router := gin.New()
        router.Use(RequestContext())
        router.Use(SecurityHeaders())
        router.GET("/static/css/style.css", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/static/css/style.css", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }
        if w.Header().Get("X-Content-Type-Options") != "nosniff" {
                t.Error("expected X-Content-Type-Options nosniff for static path")
        }
        csp := w.Header().Get("Content-Security-Policy")
        if csp == "" {
                t.Error("static paths should have a restrictive CSP header")
        }
        if !strings.Contains(csp, "default-src 'none'") {
                t.Error("static CSP should contain default-src 'none'")
        }
        if !strings.Contains(csp, "script-src 'none'") {
                t.Error("static CSP should contain script-src 'none'")
        }
        if !strings.Contains(csp, "style-src 'unsafe-inline'") {
                t.Error("static CSP should allow unsafe-inline styles for SVG compatibility")
        }
        if w.Header().Get("X-Frame-Options") != "" {
                t.Error("static paths should not have X-Frame-Options")
        }
}

func TestSecurityHeadersDevMode(t *testing.T) {
        router := gin.New()
        router.Use(RequestContext())
        router.Use(SecurityHeaders(true))
        router.GET("/test", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/test", nil)
        router.ServeHTTP(w, req)

        if w.Header().Get("Cross-Origin-Opener-Policy") != "same-origin-allow-popups" {
                t.Errorf("expected same-origin-allow-popups in dev mode, got %q", w.Header().Get("Cross-Origin-Opener-Policy"))
        }
        if w.Header().Get("Cross-Origin-Resource-Policy") != "cross-origin" {
                t.Errorf("expected cross-origin in dev mode, got %q", w.Header().Get("Cross-Origin-Resource-Policy"))
        }
        if w.Header().Get("X-Frame-Options") != "" {
                t.Error("X-Frame-Options should not be set in dev mode")
        }
        csp := w.Header().Get("Content-Security-Policy")
        if !strings.Contains(csp, "replit.com") {
                t.Error("dev mode CSP should contain replit.com")
        }
}

func TestSecurityHeadersSignaturePath(t *testing.T) {
        router := gin.New()
        router.Use(RequestContext())
        router.Use(SecurityHeaders())
        router.GET("/signature", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/signature", nil)
        router.ServeHTTP(w, req)

        if w.Header().Get("X-Frame-Options") != "SAMEORIGIN" {
                t.Errorf("expected SAMEORIGIN for /signature, got %q", w.Header().Get("X-Frame-Options"))
        }
        csp := w.Header().Get("Content-Security-Policy")
        if !strings.Contains(csp, "frame-src 'self'") {
                t.Error("CSP for /signature should contain frame-src 'self'")
        }
}

func TestExtractNonceStrNonString(t *testing.T) {
        router := gin.New()
        var result string
        router.GET("/test", func(c *gin.Context) {
                c.Set(ginKeyCSPNonce, 12345)
                result = extractNonceStr(c)
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/test", nil)
        router.ServeHTTP(w, req)

        if result != "" {
                t.Errorf("expected empty string for non-string nonce, got %q", result)
        }
}

func TestExtractNonceStrMissing(t *testing.T) {
        router := gin.New()
        var result string
        router.GET("/test", func(c *gin.Context) {
                result = extractNonceStr(c)
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/test", nil)
        router.ServeHTTP(w, req)

        if result != "" {
                t.Errorf("expected empty string for missing nonce, got %q", result)
        }
}

func TestRateLimitMessageDefault(t *testing.T) {
        msg := rateLimitMessage(RateLimitResult{
                Allowed:     false,
                Reason:      "unknown_reason",
                WaitSeconds: 5,
        })
        if !strings.Contains(msg, "5 seconds") {
                t.Errorf("expected default message with wait seconds, got %q", msg)
        }
        if strings.Contains(msg, "Rate limit reached") || strings.Contains(msg, "recently analyzed") {
                t.Error("default case should not use specific messages")
        }
}

func TestRateLimitMessageRateLimit(t *testing.T) {
        msg := rateLimitMessage(RateLimitResult{
                Reason:      "rate_limit",
                WaitSeconds: 10,
        })
        if !strings.Contains(msg, "Rate limit reached") {
                t.Errorf("expected rate_limit message, got %q", msg)
        }
}

func TestRateLimitMessageAntiRepeat(t *testing.T) {
        msg := rateLimitMessage(RateLimitResult{
                Reason:      "anti_repeat",
                WaitSeconds: 7,
        })
        if !strings.Contains(msg, "recently analyzed") {
                t.Errorf("expected anti_repeat message, got %q", msg)
        }
}

func TestRecoveryWithExtraData(t *testing.T) {
        router := gin.New()
        router.Use(RequestContext())
        tmpl := template.Must(template.New("index.html").Parse(`{{.ActivePage}}|{{.ExtraKey}}`))
        router.SetHTMLTemplate(tmpl)
        router.Use(Recovery("v2", map[string]any{"ExtraKey": "extraVal"}))
        router.GET("/panic", func(c *gin.Context) {
                panic("boom")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/panic", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusInternalServerError {
                t.Fatalf("expected 500, got %d", w.Code)
        }
        body := w.Body.String()
        if !strings.Contains(body, "extraVal") {
                t.Errorf("expected extraVal in body, got %q", body)
        }
}

func TestRecoveryNoExtraData(t *testing.T) {
        router := gin.New()
        router.Use(RequestContext())
        tmpl := template.Must(template.New("index.html").Parse(`{{.ActivePage}}`))
        router.SetHTMLTemplate(tmpl)
        router.Use(Recovery("v3"))
        router.GET("/panic", func(c *gin.Context) {
                panic("crash")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/panic", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusInternalServerError {
                t.Fatalf("expected 500, got %d", w.Code)
        }
}


func TestParseExcludeIPsWithWhitespace(t *testing.T) {
        os.Setenv("ANALYTICS_EXCLUDE_IPS", " 1.2.3.4 , 5.6.7.8 , ")
        defer os.Unsetenv("ANALYTICS_EXCLUDE_IPS")

        result := parseExcludeIPs()
        if result == nil {
                t.Fatal("expected non-nil map")
        }
        if !result["1.2.3.4"] {
                t.Error("expected 1.2.3.4 in excluded IPs")
        }
        if !result["5.6.7.8"] {
                t.Error("expected 5.6.7.8 in excluded IPs")
        }
        if result[""] {
                t.Error("empty string should not be in excluded IPs")
        }
}

func TestParseExcludeIPsEmpty(t *testing.T) {
        os.Unsetenv("ANALYTICS_EXCLUDE_IPS")
        result := parseExcludeIPs()
        if result != nil {
                t.Errorf("expected nil for empty env, got %v", result)
        }
}

func TestSafeRefererPathVariants(t *testing.T) {
        tests := []struct {
                name    string
                referer string
                want    string
        }{
                {"empty referer", "", "/"},
                {"invalid URL", "://bad\x00url", "/"},
                {"valid path", "https://example.com/about", "/about"},
                {"double slash in path", "https://example.com//evil", "/"},
                {"no path", "https://example.com", "/"},
                {"root path", "https://example.com/", "/"},
                {"relative path (no leading slash)", "relative/path", "/"},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        router := gin.New()
                        var result string
                        router.GET("/test", func(c *gin.Context) {
                                c.Request.Header.Set("Referer", tt.referer)
                                result = safeRefererPath(c)
                                c.String(http.StatusOK, "ok")
                        })
                        w := httptest.NewRecorder()
                        req := httptest.NewRequest("GET", "/test", nil)
                        router.ServeHTTP(w, req)

                        if result != tt.want {
                                t.Errorf("safeRefererPath(%q) = %q, want %q", tt.referer, result, tt.want)
                        }
                })
        }
}

func TestSetFlashCookies(t *testing.T) {
        router := gin.New()
        router.GET("/test", func(c *gin.Context) {
                setFlashCookies(c, "test message")
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/test", nil)
        router.ServeHTTP(w, req)

        cookies := w.Result().Cookies()
        var foundMessage, foundCategory bool
        for _, c := range cookies {
                if c.Name == "flash_message" && c.Value == "test message" {
                        foundMessage = true
                }
                if c.Name == "flash_category" && c.Value == "warning" {
                        foundCategory = true
                }
        }
        if !foundMessage {
                t.Error("expected flash_message cookie")
        }
        if !foundCategory {
                t.Error("expected flash_category cookie")
        }
}

func TestAnalyticsMiddlewareExcludedIP(t *testing.T) {
        ac := &AnalyticsCollector{
                visitors:        make(map[string]bool),
                pageCounts:      make(map[string]int),
                refCounts:       make(map[string]int),
                analysisDomains: make(map[string]bool),
                excludeIPs:      map[string]bool{"192.0.2.1": true},
                dailySalt:       "test-salt",
                saltDate:        time.Now().UTC().Format("2006-01-02"),
        }

        router := gin.New()
        router.Use(ac.Middleware())
        router.GET("/page", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/page", nil)
        router.ServeHTTP(w, req)

        if ac.pageviews != 0 {
                t.Errorf("expected 0 pageviews for excluded IP, got %d", ac.pageviews)
        }
}

func TestAnalyticsMiddlewareAdminSkip(t *testing.T) {
        ac := &AnalyticsCollector{
                visitors:        make(map[string]bool),
                pageCounts:      make(map[string]int),
                refCounts:       make(map[string]int),
                analysisDomains: make(map[string]bool),
                dailySalt:       "test-salt",
                saltDate:        time.Now().UTC().Format("2006-01-02"),
        }

        router := gin.New()
        router.Use(func(c *gin.Context) {
                c.Set(mapKeyUserRole, "admin")
                c.Next()
        })
        router.Use(ac.Middleware())
        router.GET("/page", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/page", nil)
        router.ServeHTTP(w, req)

        if ac.pageviews != 0 {
                t.Errorf("expected 0 pageviews for admin, got %d", ac.pageviews)
        }
}

func TestCanonicalHostRedirectInvalidURL(t *testing.T) {
        router := gin.New()
        router.Use(CanonicalHostRedirect(""))
        router.GET("/", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200 for disabled middleware, got %d", w.Code)
        }
}

func TestCanonicalHostRedirectNonReplitHost(t *testing.T) {
        router := gin.New()
        router.Use(CanonicalHostRedirect("https://mysite.com"))
        router.GET("/", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "http://other.com/", nil)
        req.Host = "other.com"
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200 for non-replit host, got %d", w.Code)
        }
}

func TestCanonicalHostRedirectWithPort(t *testing.T) {
        router := gin.New()
        router.Use(CanonicalHostRedirect("https://mysite.com"))
        router.GET("/", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "http://mysite.com:8080/", nil)
        req.Host = "mysite.com:8080"
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200 for canonical host with port, got %d", w.Code)
        }
}

func TestCanonicalHostRedirectReplitDev(t *testing.T) {
        router := gin.New()
        router.Use(CanonicalHostRedirect("https://mysite.com"))
        router.GET("/test", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "https://myapp.replit.dev/test", nil)
        req.Host = "myapp.replit.dev"
        router.ServeHTTP(w, req)

        if w.Code != http.StatusFound {
                t.Fatalf("expected 302, got %d", w.Code)
        }
        loc := w.Header().Get("Location")
        if loc != "https://mysite.com/test" {
                t.Errorf("expected redirect to https://mysite.com/test, got %s", loc)
        }
}

func TestCanonicalHostRedirectNoScheme(t *testing.T) {
        router := gin.New()
        router.Use(CanonicalHostRedirect("//mysite.com"))
        router.GET("/", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "http://test.replit.app/", nil)
        req.Host = "test.replit.app"
        router.ServeHTTP(w, req)

        if w.Code != http.StatusFound {
                t.Fatalf("expected 302, got %d", w.Code)
        }
        loc := w.Header().Get("Location")
        if !strings.HasPrefix(loc, "https://") {
                t.Errorf("expected https scheme as default, got %s", loc)
        }
}

func TestGenerateNonceLength(t *testing.T) {
        nonce := generateNonce()
        if nonce == "" {
                t.Error("expected non-empty nonce")
        }
        if len(nonce) < 10 {
                t.Errorf("expected nonce length >= 10, got %d", len(nonce))
        }
}

func TestBuildCSPDevMode(t *testing.T) {
        router := gin.New()
        var csp string
        router.GET("/test", func(c *gin.Context) {
                csp = buildCSP(c, "testnonce", true)
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/test", nil)
        router.ServeHTTP(w, req)

        if !strings.Contains(csp, "replit.com") {
                t.Error("dev mode CSP should contain replit.com")
        }
        if !strings.Contains(csp, "frame-ancestors") {
                t.Error("dev mode CSP should contain frame-ancestors")
        }
}

func TestBuildCSPSignaturePath(t *testing.T) {
        router := gin.New()
        var csp string
        router.GET("/signature", func(c *gin.Context) {
                csp = buildCSP(c, "testnonce", false)
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/signature", nil)
        router.ServeHTTP(w, req)

        if !strings.Contains(csp, "frame-src 'self'") {
                t.Error("CSP for /signature should have frame-src 'self'")
        }
}

func TestDocsPDFFrameAncestorsSelf(t *testing.T) {
        router := gin.New()
        router.Use(RequestContext())
        router.Use(SecurityHeaders(false))
        router.GET("/docs/dns-tool-methodology.pdf", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/docs/dns-tool-methodology.pdf", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }
        csp := w.Header().Get("Content-Security-Policy")
        if !strings.Contains(csp, "frame-ancestors 'self'") {
                t.Errorf("CSP for /docs/ should have frame-ancestors 'self', got: %s", csp)
        }
        if strings.Contains(csp, "frame-ancestors 'none'") {
                t.Error("CSP for /docs/ should NOT have frame-ancestors 'none'")
        }
        xfo := w.Header().Get("X-Frame-Options")
        if xfo != "SAMEORIGIN" {
                t.Errorf("X-Frame-Options for /docs/ should be SAMEORIGIN, got: %s", xfo)
        }
}

func TestRequireAuthNonBoolValue(t *testing.T) {
        router := gin.New()
        router.Use(func(c *gin.Context) {
                c.Set("authenticated", "string-not-bool")
                c.Next()
        })
        router.Use(RequireAuth())
        router.GET("/test", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/test", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusUnauthorized {
                t.Fatalf("expected 401 for non-bool auth, got %d", w.Code)
        }
}

func TestRequireAdminNonBoolAuth(t *testing.T) {
        router := gin.New()
        router.Use(func(c *gin.Context) {
                c.Set("authenticated", 42)
                c.Next()
        })
        router.Use(RequireAdmin())
        router.GET("/admin", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/admin", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusUnauthorized {
                t.Fatalf("expected 401 for non-bool auth, got %d", w.Code)
        }
}

func TestRequireAdminNoRoleKey(t *testing.T) {
        router := gin.New()
        router.Use(func(c *gin.Context) {
                c.Set("authenticated", true)
                c.Next()
        })
        router.Use(RequireAdmin())
        router.GET("/admin", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/admin", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusForbidden {
                t.Fatalf("expected 403 for auth without role, got %d", w.Code)
        }
}

func TestCSRFRejectWithDomainInQuery(t *testing.T) {
        m := NewCSRFMiddleware("test-secret")
        router := gin.New()
        router.Use(m.Handler())
        router.POST("/submit", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("POST", "/submit?domain=query.com", nil)
        req.AddCookie(&http.Cookie{Name: "_csrf", Value: "valid.badsig"})
        router.ServeHTTP(w, req)

        if w.Code != http.StatusSeeOther {
                t.Fatalf("expected 303, got %d", w.Code)
        }
        loc := w.Header().Get("Location")
        if !strings.Contains(loc, "domain=query.com") {
                t.Errorf("expected domain in redirect URL, got %q", loc)
        }
}

func TestCSRFRejectNoDomain(t *testing.T) {
        m := NewCSRFMiddleware("test-secret")
        router := gin.New()
        router.Use(m.Handler())
        router.POST("/submit", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("POST", "/submit", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusSeeOther {
                t.Fatalf("expected 303, got %d", w.Code)
        }
        loc := w.Header().Get("Location")
        if !strings.Contains(loc, "flash=") {
                t.Errorf("expected flash in redirect URL, got %q", loc)
        }
        if strings.Contains(loc, "domain=") {
                t.Errorf("expected no domain in redirect URL, got %q", loc)
        }
}

func TestAnalyticsMiddlewareInternalRefNotCounted(t *testing.T) {
        ac := &AnalyticsCollector{
                visitors:        make(map[string]bool),
                pageCounts:      make(map[string]int),
                refCounts:       make(map[string]int),
                analysisDomains: make(map[string]bool),
                dailySalt:       "test-salt",
                saltDate:        time.Now().UTC().Format("2006-01-02"),
                baseHost:        "mysite.com",
        }

        router := gin.New()
        router.Use(ac.Middleware())
        router.GET("/page", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/page", nil)
        req.Header.Set("Referer", "https://mysite.com/other")
        router.ServeHTTP(w, req)

        if len(ac.refCounts) != 0 {
                t.Errorf("expected no refCounts for internal referer, got %d", len(ac.refCounts))
        }
}

func TestNewAnalyticsCollectorWithExcludedIPs(t *testing.T) {
        os.Setenv("ANALYTICS_EXCLUDE_IPS", "10.0.0.1,10.0.0.2")
        defer os.Unsetenv("ANALYTICS_EXCLUDE_IPS")

        ac := NewAnalyticsCollector(nil, "https://test.com")
        if len(ac.excludeIPs) != 2 {
                t.Errorf("expected 2 excluded IPs, got %d", len(ac.excludeIPs))
        }
        if !ac.excludeIPs["10.0.0.1"] {
                t.Error("expected 10.0.0.1 in excluded IPs")
        }
}

func TestFlushPreparesDataBeforeDBCall(t *testing.T) {
        ac := &AnalyticsCollector{
                visitors:        map[string]bool{"v1": true, "v2": true},
                pageCounts:      map[string]int{"/about": 3, "/contact": 1},
                refCounts:       map[string]int{"google.com": 2},
                analysisDomains: map[string]bool{"example.com": true},
                pageviews:       5,
                analysesRun:     2,
                dailySalt:       "test",
                saltDate:        time.Now().UTC().Format("2006-01-02"),
        }

        func() {
                defer func() {
                        recover()
                }()
                ac.Flush()
        }()

        if ac.pageviews != 0 {
                t.Errorf("expected pageviews reset to 0, got %d", ac.pageviews)
        }
        if ac.analysesRun != 0 {
                t.Errorf("expected analysesRun reset to 0, got %d", ac.analysesRun)
        }
}

func TestLogRateLimitTriggered(t *testing.T) {
        router := gin.New()
        router.Use(func(c *gin.Context) {
                c.Set(ginKeyTraceID, "test-trace-123")
                c.Next()
        })
        router.GET("/test", func(c *gin.Context) {
                logRateLimitTriggered(c, "1.2.3.4", "example.com", RateLimitResult{
                        Allowed:     false,
                        Reason:      "rate_limit",
                        WaitSeconds: 10,
                })
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/test", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }
}
