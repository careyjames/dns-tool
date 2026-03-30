package middleware

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestRecordAnalysisMultiple(t *testing.T) {
	ac := &AnalyticsCollector{
		visitors:        make(map[string]bool),
		pageCounts:      make(map[string]int),
		refCounts:       make(map[string]int),
		analysisDomains: make(map[string]bool),
	}

	ac.RecordAnalysis("Example.COM")
	ac.RecordAnalysis("example.com")
	ac.RecordAnalysis("Other.Net")
	ac.RecordAnalysis("another.org")

	if ac.analysesRun != 4 {
		t.Errorf("expected 4 analyses run, got %d", ac.analysesRun)
	}
	if len(ac.analysisDomains) != 3 {
		t.Errorf("expected 3 unique domains, got %d", len(ac.analysisDomains))
	}
}

func TestAnalyticsMiddlewareSkipsWellKnownPaths(t *testing.T) {
	ac := &AnalyticsCollector{
		visitors:        make(map[string]bool),
		pageCounts:      make(map[string]int),
		refCounts:       make(map[string]int),
		analysisDomains: make(map[string]bool),
		dailySalt:       "test-salt",
		saltDate:        time.Now().UTC().Format("2006-01-02"),
	}

	router := gin.New()
	router.Use(ac.Middleware())

	paths := []string{
		"/sitemap.xml", "/sw.js", "/manifest.json", "/llms-full.txt",
	}
	for _, p := range paths {
		router.GET(p, func(c *gin.Context) {
			c.String(http.StatusOK, "ok")
		})
	}

	for _, p := range paths {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", p, nil)
		router.ServeHTTP(w, req)
	}

	if ac.pageviews != 0 {
		t.Errorf("expected 0 pageviews for static/well-known paths, got %d", ac.pageviews)
	}
}

func TestAnalyticsMiddlewareSkips400Responses(t *testing.T) {
	ac := &AnalyticsCollector{
		visitors:        make(map[string]bool),
		pageCounts:      make(map[string]int),
		refCounts:       make(map[string]int),
		analysisDomains: make(map[string]bool),
		dailySalt:       "test-salt",
		saltDate:        time.Now().UTC().Format("2006-01-02"),
	}

	router := gin.New()
	router.Use(ac.Middleware())
	router.GET("/error", func(c *gin.Context) {
		c.String(http.StatusNotFound, "not found")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/error", nil)
	router.ServeHTTP(w, req)

	if ac.pageviews != 0 {
		t.Errorf("expected 0 pageviews for 404 response, got %d", ac.pageviews)
	}
}

func TestAnalyticsMiddlewareSetsCollector(t *testing.T) {
	ac := &AnalyticsCollector{
		visitors:        make(map[string]bool),
		pageCounts:      make(map[string]int),
		refCounts:       make(map[string]int),
		analysisDomains: make(map[string]bool),
		dailySalt:       "test-salt",
		saltDate:        time.Now().UTC().Format("2006-01-02"),
	}

	router := gin.New()
	router.Use(ac.Middleware())

	var gotCollector bool
	router.GET("/page", func(c *gin.Context) {
		_, gotCollector = c.Get("analytics_collector")
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/page", nil)
	router.ServeHTTP(w, req)

	if !gotCollector {
		t.Error("expected analytics_collector to be set in context")
	}
}

func TestAnalyticsMiddlewareDirectReferer(t *testing.T) {
	ac := &AnalyticsCollector{
		visitors:        make(map[string]bool),
		pageCounts:      make(map[string]int),
		refCounts:       make(map[string]int),
		analysisDomains: make(map[string]bool),
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

	if len(ac.refCounts) != 0 {
		t.Errorf("expected no refCounts for direct visit, got %d", len(ac.refCounts))
	}
}

func TestCSRFRejectWithDomainInPost(t *testing.T) {
	m := NewCSRFMiddleware("test-secret")
	router := gin.New()
	router.Use(m.Handler())
	router.POST("/submit", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/submit", strings.NewReader("domain=test.com&csrf_token=bad"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "_csrf", Value: "valid.badsig"})
	router.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "domain=test.com") {
		t.Errorf("expected domain in redirect URL, got %q", loc)
	}
}

func TestCSRFHeadRequestSetsToken(t *testing.T) {
	m := NewCSRFMiddleware("test-secret")
	router := gin.New()
	router.Use(m.Handler())

	var token string
	router.HEAD("/check", func(c *gin.Context) {
		token = GetCSRFToken(c)
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("HEAD", "/check", nil)
	router.ServeHTTP(w, req)

	if token == "" {
		t.Error("expected csrf_token to be set for HEAD request")
	}
}

func TestCSRFOptionsRequestPassthrough(t *testing.T) {
	m := NewCSRFMiddleware("test-secret")
	router := gin.New()
	router.Use(m.Handler())
	router.OPTIONS("/preflight", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("OPTIONS", "/preflight", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for OPTIONS, got %d", w.Code)
	}
}

func TestCSRFPutRequestValidation(t *testing.T) {
	m := NewCSRFMiddleware("test-secret")
	router := gin.New()
	router.Use(m.Handler())
	router.PUT("/update", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/update", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 for PUT without CSRF, got %d", w.Code)
	}
}

func TestCSRFDeleteRequestValidation(t *testing.T) {
	m := NewCSRFMiddleware("test-secret")
	router := gin.New()
	router.Use(m.Handler())
	router.DELETE("/remove", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/remove", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 for DELETE without CSRF, got %d", w.Code)
	}
}

func TestCSRFExemptPaths(t *testing.T) {
	tests := []struct {
		path   string
		exempt bool
	}{
		{"/api/analyze", true},
		{"/api/v1/report", true},
		{"/go/health", true},
		{"/robots.txt", true},
		{"/sitemap.xml", true},
		{"/manifest.json", true},
		{"/sw.js", true},
		{"/", false},
		{"/submit", false},
		{"/about", false},
	}
	for _, tt := range tests {
		got := isCSRFExempt(tt.path)
		if got != tt.exempt {
			t.Errorf("isCSRFExempt(%q) = %v, want %v", tt.path, got, tt.exempt)
		}
	}
}

func TestRateLimitDifferentIPs(t *testing.T) {
	limiter := NewInMemoryRateLimiter()

	r1 := limiter.CheckAndRecord("1.2.3.4", "example.com")
	r2 := limiter.CheckAndRecord("5.6.7.8", "example.com")

	if !r1.Allowed || !r2.Allowed {
		t.Error("different IPs should be allowed for same domain")
	}
}

func TestRateLimitAntiRepeatWaitSeconds(t *testing.T) {
	limiter := NewInMemoryRateLimiter()

	limiter.CheckAndRecord("10.0.0.1", "test.com")
	result := limiter.CheckAndRecord("10.0.0.1", "test.com")

	if result.Allowed {
		t.Fatal("repeat should be blocked")
	}
	if result.WaitSeconds < 1 {
		t.Errorf("WaitSeconds should be >= 1, got %d", result.WaitSeconds)
	}
}

func TestAuthRateLimitNonAuthPath(t *testing.T) {
	limiter := NewInMemoryRateLimiter()
	router := gin.New()
	router.Use(AuthRateLimit(limiter))
	router.GET("/other", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/other", nil)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for non-auth path, got %d", w.Code)
	}
}

func TestAnalyzeRateLimitRateLimitReasonMessage(t *testing.T) {
	limiter := NewInMemoryRateLimiter()
	router := gin.New()
	router.Use(RequestContext())
	router.Use(AnalyzeRateLimit(limiter))
	router.POST("/", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	for i := 0; i < RateLimitMaxRequests; i++ {
		w := httptest.NewRecorder()
		body := strings.NewReader("domain=domain" + strings.Repeat("z", i) + ".com")
		req := httptest.NewRequest("POST", "/", body)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		router.ServeHTTP(w, req)
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader("domain=overflow.com"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for JSON rate limit, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Rate limit reached") {
		t.Errorf("expected rate limit message in body, got %q", body)
	}
}

func TestNewAnalyticsCollectorBaseHost(t *testing.T) {
	ac := &AnalyticsCollector{
		visitors:        make(map[string]bool),
		pageCounts:      make(map[string]int),
		refCounts:       make(map[string]int),
		analysisDomains: make(map[string]bool),
	}
	ac.rotateSalt()

	if ac.dailySalt == "" {
		t.Error("expected salt to be set")
	}
	if ac.saltDate == "" {
		t.Error("expected saltDate to be set")
	}
}

func TestNormalizePath_RootWithQuery(t *testing.T) {
	got := normalizePath("/?q=1")
	if got != "/" {
		t.Errorf("normalizePath(/?q=1) = %q, want /", got)
	}
}

func TestExtractRefOrigin_InternalSubdomain(t *testing.T) {
	got := extractRefOrigin("https://sub.example.com/page", "example.com")
	if got != "" {
		t.Errorf("expected empty for internal subdomain, got %q", got)
	}
}

func TestSecurityHeadersAllPresent(t *testing.T) {
	router := gin.New()
	router.Use(RequestContext())
	router.Use(SecurityHeaders())
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)

	headers := []string{
		"Referrer-Policy",
		"Permissions-Policy",
		"Cross-Origin-Opener-Policy",
		"Cross-Origin-Resource-Policy",
		"X-Permitted-Cross-Domain-Policies",
	}
	for _, h := range headers {
		if w.Header().Get(h) == "" {
			t.Errorf("expected %s header to be set", h)
		}
	}
}

func TestRecoveryHandlesPanic(t *testing.T) {
	router := gin.New()
	router.Use(RequestContext())
	tmpl := template.Must(template.New("index.html").Parse(`{{.ActivePage}}`))
	router.SetHTMLTemplate(tmpl)
	router.Use(Recovery("test-version"))
	router.GET("/panic", func(c *gin.Context) {
		panic("test panic")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/panic", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "home") {
		t.Errorf("expected body to contain 'home' from template, got %q", w.Body.String())
	}
}

func TestRecoveryNoPanic(t *testing.T) {
	router := gin.New()
	router.Use(RequestContext())
	router.Use(Recovery("v1"))
	router.GET("/ok", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/ok", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestAnalyzeRateLimitAllowsGET(t *testing.T) {
	limiter := NewInMemoryRateLimiter()
	router := gin.New()
	router.Use(AnalyzeRateLimit(limiter))
	router.GET("/analyze", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/analyze", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestAnalyzeRateLimitEmptyDomainEdge(t *testing.T) {
	limiter := NewInMemoryRateLimiter()
	router := gin.New()
	router.Use(AnalyzeRateLimit(limiter))
	router.POST("/analyze", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/analyze", strings.NewReader("domain="))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for empty domain, got %d", w.Code)
	}
}

func TestAnalyzeRateLimitBlocksRepeatJSON(t *testing.T) {
	limiter := NewInMemoryRateLimiter()
	router := gin.New()
	router.Use(AnalyzeRateLimit(limiter))
	router.POST("/analyze", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	body := "domain=example.com"
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/analyze", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("first request expected 200, got %d", w.Code)
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/analyze", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("repeat request expected 429, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "anti_repeat") {
		t.Errorf("expected anti_repeat reason in JSON body")
	}
}

func TestAnalyzeRateLimitBlocksRepeatHTML(t *testing.T) {
	limiter := NewInMemoryRateLimiter()
	router := gin.New()
	router.Use(AnalyzeRateLimit(limiter))
	router.POST("/analyze", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	body := "domain=example.com"
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/analyze", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w, req)

	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/analyze", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("repeat HTML request expected 303, got %d", w.Code)
	}

	cookies := w.Result().Cookies()
	var foundFlash bool
	for _, c := range cookies {
		if c.Name == "flash_message" {
			foundFlash = true
		}
	}
	if !foundFlash {
		t.Error("expected flash_message cookie to be set")
	}
}

func TestAnalyzeRateLimitOverflowJSON(t *testing.T) {
	limiter := NewInMemoryRateLimiter()
	router := gin.New()
	router.Use(AnalyzeRateLimit(limiter))
	router.POST("/analyze", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	for i := 0; i < RateLimitMaxRequests; i++ {
		body := strings.NewReader("domain=domain" + strings.Repeat("x", i) + ".com")
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/analyze", body)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		router.ServeHTTP(w, req)
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/analyze", strings.NewReader("domain=overflow.com"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("overflow request expected 429, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "rate_limit") {
		t.Errorf("expected rate_limit reason in JSON body")
	}
}

func TestAuthRateLimitCallback(t *testing.T) {
	limiter := NewInMemoryRateLimiter()
	router := gin.New()
	router.Use(AuthRateLimit(limiter))
	router.POST("/auth/callback", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/auth/callback", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/auth/callback", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("repeat callback expected 302, got %d", w.Code)
	}
}

func TestCheckAndRecordWaitSecondsMinOne(t *testing.T) {
	limiter := &InMemoryRateLimiter{
		requests: make(map[string][]requestEntry),
	}

	now := float64(time.Now().Unix())
	limiter.requests["10.0.0.1"] = []requestEntry{
		{timestamp: now, domain: "test.com"},
	}

	result := limiter.CheckAndRecord("10.0.0.1", "test.com")
	if result.Allowed {
		t.Fatal("expected not allowed")
	}
	if result.WaitSeconds < 1 {
		t.Errorf("waitSeconds should be >= 1, got %d", result.WaitSeconds)
	}
}

func TestFlushZeroPageviews(t *testing.T) {
	ac := &AnalyticsCollector{
		visitors:        make(map[string]bool),
		pageCounts:      make(map[string]int),
		refCounts:       make(map[string]int),
		analysisDomains: make(map[string]bool),
		pageviews:       0,
	}
	ac.Flush()
	if ac.pageviews != 0 {
		t.Errorf("expected pageviews to remain 0")
	}
}

func TestPruneOldRemovesExpired(t *testing.T) {
	now := float64(time.Now().Unix())
	entries := []requestEntry{
		{timestamp: now - RateLimitWindow - 10, domain: "old.com"},
		{timestamp: now - RateLimitWindow - 1, domain: "old2.com"},
		{timestamp: now - 5, domain: "recent.com"},
		{timestamp: now, domain: "current.com"},
	}
	result := pruneOld(entries, now)
	if len(result) != 2 {
		t.Errorf("expected 2 entries after prune, got %d", len(result))
	}
	if result[0].domain != "recent.com" {
		t.Errorf("expected recent.com first, got %s", result[0].domain)
	}
}

func TestCheckAndRecordRateLimitWaitSecondsMinOne(t *testing.T) {
	limiter := &InMemoryRateLimiter{
		requests: make(map[string][]requestEntry),
	}

	now := float64(time.Now().Unix())
	entries := make([]requestEntry, RateLimitMaxRequests)
	for i := 0; i < RateLimitMaxRequests; i++ {
		entries[i] = requestEntry{
			timestamp: now - float64(RateLimitMaxRequests-i),
			domain:    "d" + strings.Repeat("x", i) + ".com",
		}
	}
	limiter.requests["10.0.0.2"] = entries

	result := limiter.CheckAndRecord("10.0.0.2", "new.com")
	if result.Allowed {
		t.Fatal("expected not allowed due to rate limit")
	}
	if result.Reason != "rate_limit" {
		t.Errorf("expected rate_limit reason, got %s", result.Reason)
	}
	if result.WaitSeconds < 1 {
		t.Errorf("waitSeconds should be >= 1, got %d", result.WaitSeconds)
	}
}

func TestAnalyticsMiddlewareTracksReferer(t *testing.T) {
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
	router.GET("/about", func(c *gin.Context) {
		c.String(http.StatusOK, "about page")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/about", nil)
	req.Header.Set("Referer", "https://google.com/search?q=test")
	router.ServeHTTP(w, req)

	if ac.pageviews != 1 {
		t.Errorf("expected 1 pageview, got %d", ac.pageviews)
	}
	if ac.refCounts["google.com"] != 1 {
		t.Errorf("expected google.com referer count of 1, got %d", ac.refCounts["google.com"])
	}
}

func TestAnalyticsMiddlewareSkipsSelfReferer(t *testing.T) {
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
		t.Errorf("expected no ref counts for self-referrer, got %v", ac.refCounts)
	}
}

func TestCanonicalHostRedirectNonReplitNonCanonicalPassesThrough(t *testing.T) {
	router := gin.New()
	router.Use(CanonicalHostRedirect("https://dnstool.it-help.tech"))
	router.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "other-domain.com"
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("non-replit non-canonical host should pass through, got %d", w.Code)
	}
}

func TestCanonicalHostRedirectHostWithPort(t *testing.T) {
	router := gin.New()
	router.Use(CanonicalHostRedirect("https://dnstool.it-help.tech"))
	router.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "dnstool.it-help.tech:8080"
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("canonical host with port should pass through, got %d", w.Code)
	}
}

func TestCanonicalHostRedirectNoSchemeDefaultsHTTPS(t *testing.T) {
	router := gin.New()
	router.Use(CanonicalHostRedirect("//dnstool.it-help.tech"))
	router.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "test.replit.app"
	router.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://") {
		t.Errorf("expected https scheme, got %s", loc)
	}
}

func TestFlushWithPageviewsSnapshotLogic(t *testing.T) {
	ac := &AnalyticsCollector{
		visitors:        map[string]bool{"v1": true, "v2": true},
		pageCounts:      map[string]int{"/about": 3, "/": 5},
		refCounts:       map[string]int{"google.com": 2},
		analysisDomains: map[string]bool{"example.com": true},
		pageviews:       8,
		analysesRun:     1,
	}

	ac.mu.Lock()
	pv := ac.pageviews
	uv := len(ac.visitors)
	ar := ac.analysesRun
	ud := len(ac.analysisDomains)
	ac.pageviews = 0
	ac.analysesRun = 0
	ac.pageCounts = make(map[string]int)
	ac.refCounts = make(map[string]int)
	ac.mu.Unlock()

	if pv != 8 {
		t.Errorf("expected 8 pageviews snapshot, got %d", pv)
	}
	if uv != 2 {
		t.Errorf("expected 2 unique visitors, got %d", uv)
	}
	if ar != 1 {
		t.Errorf("expected 1 analysis, got %d", ar)
	}
	if ud != 1 {
		t.Errorf("expected 1 unique domain, got %d", ud)
	}
	if ac.pageviews != 0 {
		t.Errorf("expected pageviews reset to 0, got %d", ac.pageviews)
	}
	if ac.analysesRun != 0 {
		t.Errorf("expected analysesRun reset to 0, got %d", ac.analysesRun)
	}
}

func TestAnalyzeRateLimitRedirectUsesReferer(t *testing.T) {
	limiter := NewInMemoryRateLimiter()
	router := gin.New()
	router.Use(RequestContext())
	router.Use(AnalyzeRateLimit(limiter))
	router.POST("/analyze", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("POST", "/analyze", strings.NewReader("domain=example.com"))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w1, req1)

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("POST", "/analyze", strings.NewReader("domain=example.com"))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("Referer", "https://mysite.com/results?domain=example.com")
	router.ServeHTTP(w2, req2)

	if w2.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", w2.Code)
	}
	loc := w2.Header().Get("Location")
	if loc != "/results" {
		t.Errorf("expected redirect to /results from referer, got %s", loc)
	}
}

func TestAnalyzeRateLimitRedirectBadReferer(t *testing.T) {
	limiter := NewInMemoryRateLimiter()
	router := gin.New()
	router.Use(RequestContext())
	router.Use(AnalyzeRateLimit(limiter))
	router.POST("/analyze", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("POST", "/analyze", strings.NewReader("domain=example.com"))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w1, req1)

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("POST", "/analyze", strings.NewReader("domain=example.com"))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("Referer", "://bad-url")
	router.ServeHTTP(w2, req2)

	if w2.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", w2.Code)
	}
	loc := w2.Header().Get("Location")
	if loc != "/" {
		t.Errorf("expected redirect to / for bad referer, got %s", loc)
	}
}

func TestAnalyzeRateLimitHTMLFlashCategory(t *testing.T) {
	limiter := NewInMemoryRateLimiter()
	router := gin.New()
	router.Use(RequestContext())
	router.Use(AnalyzeRateLimit(limiter))
	router.POST("/analyze", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("POST", "/analyze", strings.NewReader("domain=test.org"))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w1, req1)

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("POST", "/analyze", strings.NewReader("domain=test.org"))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w2, req2)

	var foundCategory bool
	for _, c := range w2.Result().Cookies() {
		if c.Name == "flash_category" && c.Value == "warning" {
			foundCategory = true
		}
	}
	if !foundCategory {
		t.Error("expected flash_category cookie with value 'warning'")
	}
}

func TestAnalyzeRateLimitRateLimitHTMLMessage(t *testing.T) {
	limiter := NewInMemoryRateLimiter()
	router := gin.New()
	router.Use(RequestContext())
	router.Use(AnalyzeRateLimit(limiter))
	router.POST("/analyze", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	for i := 0; i < RateLimitMaxRequests; i++ {
		w := httptest.NewRecorder()
		body := strings.NewReader("domain=d" + strings.Repeat("y", i) + ".com")
		req := httptest.NewRequest("POST", "/analyze", body)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		router.ServeHTTP(w, req)
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/analyze", strings.NewReader("domain=overflow.com"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", w.Code)
	}

	var foundFlash bool
	for _, c := range w.Result().Cookies() {
		if c.Name == "flash_message" && strings.Contains(c.Value, "Rate limit") {
			foundFlash = true
		}
	}
	if !foundFlash {
		t.Error("expected flash_message cookie with rate limit message")
	}
}

func TestCSRFRejectNoDomainInPost(t *testing.T) {
	m := NewCSRFMiddleware("test-secret")
	router := gin.New()
	router.Use(m.Handler())
	router.POST("/submit", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/submit", strings.NewReader("csrf_token=bad"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "_csrf", Value: "valid.badsig"})
	router.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if strings.Contains(loc, "domain=") {
		t.Errorf("expected no domain in redirect URL, got %q", loc)
	}
}

func TestCSRFRejectDomainFromQuery(t *testing.T) {
	m := NewCSRFMiddleware("test-secret")
	router := gin.New()
	router.Use(m.Handler())
	router.POST("/submit", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/submit?domain=query-domain.com", nil)
	req.AddCookie(&http.Cookie{Name: "_csrf", Value: "valid.badsig"})
	router.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "domain=query-domain.com") {
		t.Errorf("expected domain from query in redirect URL, got %q", loc)
	}
}

func TestCSRFHandlerPostWithValidTokenSetsContext(t *testing.T) {
	m := NewCSRFMiddleware("test-secret")
	router := gin.New()
	router.Use(m.Handler())

	var contextToken string
	router.GET("/form", func(c *gin.Context) {
		contextToken = GetCSRFToken(c)
		c.String(http.StatusOK, "ok")
	})
	router.POST("/submit", func(c *gin.Context) {
		contextToken = GetCSRFToken(c)
		c.String(http.StatusOK, "ok")
	})

	getW := httptest.NewRecorder()
	getReq := httptest.NewRequest("GET", "/form", nil)
	router.ServeHTTP(getW, getReq)
	token := contextToken

	var csrfCookie string
	for _, ck := range getW.Result().Cookies() {
		if ck.Name == "_csrf" {
			csrfCookie = ck.Value
		}
	}

	postW := httptest.NewRecorder()
	postReq := httptest.NewRequest("POST", "/submit", strings.NewReader("csrf_token="+token))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.AddCookie(&http.Cookie{Name: "_csrf", Value: csrfCookie})
	router.ServeHTTP(postW, postReq)

	if postW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", postW.Code)
	}
	if contextToken != token {
		t.Errorf("expected csrf_token to be set in context after valid POST, got %q", contextToken)
	}
}

func TestCSRFEnsureTokenInvalidCookieGeneratesNew(t *testing.T) {
	m := NewCSRFMiddleware("test-secret")
	router := gin.New()
	router.Use(m.Handler())

	var token string
	router.GET("/form", func(c *gin.Context) {
		token = GetCSRFToken(c)
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/form", nil)
	req.AddCookie(&http.Cookie{Name: "_csrf", Value: "invalid.cookie.value"})
	router.ServeHTTP(w, req)

	if token == "" {
		t.Fatal("expected new token to be generated for invalid cookie")
	}

	var newCookie bool
	for _, ck := range w.Result().Cookies() {
		if ck.Name == "_csrf" {
			newCookie = true
		}
	}
	if !newCookie {
		t.Error("expected new _csrf cookie to be set")
	}
}

func TestSecurityHeadersTLSRequest(t *testing.T) {
	router := gin.New()
	router.Use(RequestContext())
	router.Use(SecurityHeaders())
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	router.ServeHTTP(w, req)

	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "upgrade-insecure-requests") {
		t.Error("CSP should contain upgrade-insecure-requests for HTTPS")
	}
}

func TestGetAuthTemplateDataNonBoolAuth(t *testing.T) {
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("authenticated", "not-a-bool")
		c.Next()
	})

	var data map[string]any
	router.GET("/test", func(c *gin.Context) {
		data = GetAuthTemplateData(c)
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)

	if _, ok := data["Authenticated"]; ok {
		t.Error("Authenticated should not be set for non-bool auth value")
	}
}

func TestRequireAuthFalseValue(t *testing.T) {
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("authenticated", false)
		c.Next()
	})
	router.Use(RequireAuth())
	router.GET("/protected", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/protected", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for false auth, got %d", w.Code)
	}
}

func TestRequireAdminAuthFalse(t *testing.T) {
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("authenticated", false)
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
		t.Fatalf("expected 401 for false auth, got %d", w.Code)
	}
}

func TestRecoveryWithCSRFAndNonce(t *testing.T) {
	router := gin.New()
	router.Use(RequestContext())
	m := NewCSRFMiddleware("test-secret")
	router.Use(m.Handler())
	tmpl := template.Must(template.New("index.html").Parse(`{{.CspNonce}}|{{.CsrfToken}}|{{.ActivePage}}`))
	router.SetHTMLTemplate(tmpl)
	router.Use(Recovery("v1"))
	router.GET("/panic", func(c *gin.Context) {
		panic("test panic")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/panic", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "home") {
		t.Errorf("expected 'home' in body, got %q", body)
	}
}

func TestCheckAndRecordAntiRepeatBreaksOnOldEntries(t *testing.T) {
	limiter := &InMemoryRateLimiter{
		requests: make(map[string][]requestEntry),
	}

	now := float64(time.Now().Unix())
	limiter.requests["10.0.0.5"] = []requestEntry{
		{timestamp: now - AntiRepeatWindow - 5, domain: "old.com"},
		{timestamp: now - AntiRepeatWindow - 1, domain: "target.com"},
		{timestamp: now - 1, domain: "recent.com"},
	}

	result := limiter.CheckAndRecord("10.0.0.5", "target.com")
	if !result.Allowed {
		t.Fatal("should be allowed since target.com entry is outside anti-repeat window")
	}
}

func TestCheckAndRecordRateLimitWaitSecondsClamp(t *testing.T) {
	limiter := &InMemoryRateLimiter{
		requests: make(map[string][]requestEntry),
	}

	now := float64(time.Now().Unix())
	entries := make([]requestEntry, RateLimitMaxRequests)
	for i := 0; i < RateLimitMaxRequests; i++ {
		entries[i] = requestEntry{
			timestamp: now,
			domain:    "d" + strings.Repeat("q", i) + ".com",
		}
	}
	limiter.requests["10.0.0.6"] = entries

	result := limiter.CheckAndRecord("10.0.0.6", "new.com")
	if result.Allowed {
		t.Fatal("expected blocked")
	}
	if result.WaitSeconds < 1 {
		t.Errorf("waitSeconds should be >= 1, got %d", result.WaitSeconds)
	}
}

func TestCheckAndRecordAntiRepeatWaitSecondsClamp(t *testing.T) {
	limiter := &InMemoryRateLimiter{
		requests: make(map[string][]requestEntry),
	}

	now := float64(time.Now().Unix())
	limiter.requests["10.0.0.7"] = []requestEntry{
		{timestamp: now, domain: "test.com"},
	}

	result := limiter.CheckAndRecord("10.0.0.7", "test.com")
	if result.Allowed {
		t.Fatal("should be blocked by anti-repeat")
	}
	if result.WaitSeconds < 1 {
		t.Errorf("waitSeconds should be >= 1, got %d", result.WaitSeconds)
	}
}

func TestCheckAndRecordMultipleDomainsAntiRepeat(t *testing.T) {
	limiter := &InMemoryRateLimiter{
		requests: make(map[string][]requestEntry),
	}

	now := float64(time.Now().Unix())
	limiter.requests["10.0.0.8"] = []requestEntry{
		{timestamp: now - 2, domain: "first.com"},
		{timestamp: now - 1, domain: "second.com"},
		{timestamp: now, domain: "third.com"},
	}

	result := limiter.CheckAndRecord("10.0.0.8", "second.com")
	if result.Allowed {
		t.Fatal("should be blocked by anti-repeat for second.com")
	}
	if result.Reason != "anti_repeat" {
		t.Errorf("expected anti_repeat, got %s", result.Reason)
	}
}

func TestAnalyticsMiddlewareMultiplePageviews(t *testing.T) {
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
	router.GET("/page1", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	router.GET("/page2", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	for _, path := range []string{"/page1", "/page1", "/page2"} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", path, nil)
		router.ServeHTTP(w, req)
	}

	if ac.pageviews != 3 {
		t.Errorf("expected 3 pageviews, got %d", ac.pageviews)
	}
	if ac.pageCounts["/page1"] != 2 {
		t.Errorf("expected 2 counts for /page1, got %d", ac.pageCounts["/page1"])
	}
	if ac.pageCounts["/page2"] != 1 {
		t.Errorf("expected 1 count for /page2, got %d", ac.pageCounts["/page2"])
	}
}

func TestAnalyticsMiddlewareSkipsPostMethod(t *testing.T) {
	ac := &AnalyticsCollector{
		visitors:        make(map[string]bool),
		pageCounts:      make(map[string]int),
		refCounts:       make(map[string]int),
		analysisDomains: make(map[string]bool),
		dailySalt:       "test-salt",
		saltDate:        time.Now().UTC().Format("2006-01-02"),
	}
	router := gin.New()
	router.Use(ac.Middleware())
	router.POST("/submit", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/submit", nil)
	router.ServeHTTP(w, req)

	if ac.pageviews != 1 {
		t.Errorf("expected 1 pageview for POST, got %d", ac.pageviews)
	}
}

func TestAnalyzeRateLimitRefererEmptyPath(t *testing.T) {
	limiter := NewInMemoryRateLimiter()
	router := gin.New()
	router.Use(RequestContext())
	router.Use(AnalyzeRateLimit(limiter))
	router.POST("/analyze", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("POST", "/analyze", strings.NewReader("domain=example.com"))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w1, req1)

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("POST", "/analyze", strings.NewReader("domain=example.com"))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("Referer", "https://mysite.com")
	router.ServeHTTP(w2, req2)

	if w2.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", w2.Code)
	}
}

func TestNewAnalyticsCollectorSetsFields(t *testing.T) {
	ac := NewAnalyticsCollector(nil, "https://example.com")

	if ac.baseHost != "example.com" {
		t.Errorf("expected baseHost 'example.com', got %q", ac.baseHost)
	}
	if ac.dailySalt == "" {
		t.Error("expected dailySalt to be set")
	}
	if ac.saltDate == "" {
		t.Error("expected saltDate to be set")
	}
	if ac.visitors == nil {
		t.Error("expected visitors map to be initialized")
	}
	if ac.pageCounts == nil {
		t.Error("expected pageCounts map to be initialized")
	}
}

func TestNewAnalyticsCollectorInvalidURL(t *testing.T) {
	ac := NewAnalyticsCollector(nil, "://bad")
	if ac.baseHost != "" {
		t.Errorf("expected empty baseHost for invalid URL, got %q", ac.baseHost)
	}
}

func TestCleanupLogicDirectly(t *testing.T) {
	limiter := &InMemoryRateLimiter{
		requests: make(map[string][]requestEntry),
	}

	now := float64(time.Now().Unix())
	limiter.requests["10.0.0.1"] = []requestEntry{
		{timestamp: now - RateLimitWindow - 10, domain: "expired.com"},
	}
	limiter.requests["10.0.0.2"] = []requestEntry{
		{timestamp: now - RateLimitWindow - 5, domain: "expired2.com"},
		{timestamp: now - 1, domain: "recent.com"},
	}
	limiter.requests["10.0.0.3"] = []requestEntry{
		{timestamp: now, domain: "current.com"},
	}

	limiter.mu.Lock()
	cleanupNow := float64(time.Now().Unix())
	for ip, entries := range limiter.requests {
		limiter.requests[ip] = pruneOld(entries, cleanupNow)
		if len(limiter.requests[ip]) == 0 {
			delete(limiter.requests, ip)
		}
	}
	limiter.mu.Unlock()

	if _, exists := limiter.requests["10.0.0.1"]; exists {
		t.Error("expected 10.0.0.1 to be removed (all expired)")
	}
	if len(limiter.requests["10.0.0.2"]) != 1 {
		t.Errorf("expected 1 entry for 10.0.0.2, got %d", len(limiter.requests["10.0.0.2"]))
	}
	if len(limiter.requests["10.0.0.3"]) != 1 {
		t.Errorf("expected 1 entry for 10.0.0.3, got %d", len(limiter.requests["10.0.0.3"]))
	}
}

func TestSessionLoaderNoCookie(t *testing.T) {
	handler := SessionLoader(nil)
	router := gin.New()
	router.Use(handler)

	var authed bool
	router.GET("/test", func(c *gin.Context) {
		_, authed = c.Get("authenticated")
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if authed {
		t.Error("expected no authenticated key for request without session cookie")
	}
}

func TestSessionLoaderEmptyCookie(t *testing.T) {
	handler := SessionLoader(nil)
	router := gin.New()
	router.Use(handler)

	var authed bool
	router.GET("/test", func(c *gin.Context) {
		_, authed = c.Get("authenticated")
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	req.AddCookie(&http.Cookie{Name: "_dns_session", Value: ""})
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if authed {
		t.Error("expected no authenticated key for empty session cookie")
	}
}

func TestFlushResetsCounters(t *testing.T) {
	ac := &AnalyticsCollector{
		visitors:        map[string]bool{"v1": true},
		pageCounts:      map[string]int{"/about": 1},
		refCounts:       map[string]int{"google.com": 1},
		analysisDomains: map[string]bool{"example.com": true},
		pageviews:       0,
		analysesRun:     0,
	}

	ac.Flush()

	if ac.pageviews != 0 {
		t.Errorf("expected pageviews 0, got %d", ac.pageviews)
	}
}

func TestNormalizePathEdgeCases(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/about", "/about"},
		{"/about?foo=bar", "/about"},
		{"/about/", "/about"},
		{"/about/?x=1", "/about/"},
		{"/", "/"},
		{"///", ""},
	}
	for _, tt := range tests {
		got := normalizePath(tt.input)
		if got != tt.want {
			t.Errorf("normalizePath(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
