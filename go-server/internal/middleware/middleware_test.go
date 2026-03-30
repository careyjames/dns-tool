// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package middleware_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"dnstool/go-server/internal/middleware"

	"github.com/gin-gonic/gin"
)

const testSecret = "test-secret-key-for-csrf"

const (
	msgExpect200       = "expected 200, got %d"
	pathSubmit         = "/submit"
	headerContentType  = "Content-Type"
	contentTypeForm    = "application/x-www-form-urlencoded"
	msgExpect403       = "expected 403, got %d"
	testDomainExample  = "example.com"
	msgFirstReqAllowed = "first request should be allowed"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func setupCSRFRouter() (*gin.Engine, *middleware.CSRFMiddleware) {
	csrf := middleware.NewCSRFMiddleware(testSecret)
	router := gin.New()
	router.Use(csrf.Handler())
	return router, csrf
}

func TestCSRFGetRequestSetsToken(t *testing.T) {
	router, _ := setupCSRFRouter()

	var ctxToken string
	router.GET("/form", func(c *gin.Context) {
		ctxToken = middleware.GetCSRFToken(c)
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/form", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf(msgExpect200, w.Code)
	}

	if ctxToken == "" {
		t.Fatal("csrf_token was not set in context")
	}

	cookies := w.Result().Cookies()
	var csrfCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "_csrf" {
			csrfCookie = c
			break
		}
	}
	if csrfCookie == nil {
		t.Fatal("_csrf cookie was not set")
	}
	if csrfCookie.Value == "" {
		t.Fatal("_csrf cookie value is empty")
	}
}

func TestCSRFPostWithoutCookie(t *testing.T) {
	router, _ := setupCSRFRouter()

	router.POST(pathSubmit, func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", pathSubmit, strings.NewReader("csrf_token=sometoken"))
	req.Header.Set(headerContentType, contentTypeForm)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d", w.Code)
	}
}

func TestCSRFPostWithInvalidSignature(t *testing.T) {
	router, _ := setupCSRFRouter()

	router.POST(pathSubmit, func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", pathSubmit, strings.NewReader("csrf_token=faketoken"))
	req.Header.Set(headerContentType, contentTypeForm)
	req.AddCookie(&http.Cookie{
		Name:  "_csrf",
		Value: "faketoken.invalidsignature",
	})
	router.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d", w.Code)
	}
}

func TestCSRFPostWithValidToken(t *testing.T) {
	router, _ := setupCSRFRouter()

	var capturedToken string
	router.GET("/form", func(c *gin.Context) {
		capturedToken = middleware.GetCSRFToken(c)
		c.String(http.StatusOK, "ok")
	})
	router.POST(pathSubmit, func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	getW := httptest.NewRecorder()
	getReq := httptest.NewRequest("GET", "/form", nil)
	router.ServeHTTP(getW, getReq)

	var csrfCookieValue string
	for _, c := range getW.Result().Cookies() {
		if c.Name == "_csrf" {
			csrfCookieValue = c.Value
			break
		}
	}

	form := url.Values{}
	form.Set("csrf_token", capturedToken)
	postW := httptest.NewRecorder()
	postReq := httptest.NewRequest("POST", pathSubmit, strings.NewReader(form.Encode()))
	postReq.Header.Set(headerContentType, contentTypeForm)
	postReq.AddCookie(&http.Cookie{
		Name:  "_csrf",
		Value: csrfCookieValue,
	})
	router.ServeHTTP(postW, postReq)

	if postW.Code != http.StatusOK {
		t.Fatalf(msgExpect200, postW.Code)
	}
}

func TestCSRFPostWithHeaderToken(t *testing.T) {
	router, _ := setupCSRFRouter()

	var capturedToken string
	router.GET("/form", func(c *gin.Context) {
		capturedToken = middleware.GetCSRFToken(c)
		c.String(http.StatusOK, "ok")
	})
	router.POST(pathSubmit, func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	getW := httptest.NewRecorder()
	getReq := httptest.NewRequest("GET", "/form", nil)
	router.ServeHTTP(getW, getReq)

	var csrfCookieValue string
	for _, c := range getW.Result().Cookies() {
		if c.Name == "_csrf" {
			csrfCookieValue = c.Value
			break
		}
	}

	postW := httptest.NewRecorder()
	postReq := httptest.NewRequest("POST", pathSubmit, nil)
	postReq.Header.Set("X-CSRF-Token", capturedToken)
	postReq.AddCookie(&http.Cookie{
		Name:  "_csrf",
		Value: csrfCookieValue,
	})
	router.ServeHTTP(postW, postReq)

	if postW.Code != http.StatusOK {
		t.Fatalf(msgExpect200, postW.Code)
	}
}

func TestCSRFPostTokenMismatch(t *testing.T) {
	router, _ := setupCSRFRouter()

	router.GET("/form", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	router.POST(pathSubmit, func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	getW := httptest.NewRecorder()
	getReq := httptest.NewRequest("GET", "/form", nil)
	router.ServeHTTP(getW, getReq)

	var csrfCookieValue string
	for _, c := range getW.Result().Cookies() {
		if c.Name == "_csrf" {
			csrfCookieValue = c.Value
			break
		}
	}

	form := url.Values{}
	form.Set("csrf_token", "wrong-token-value")
	postW := httptest.NewRecorder()
	postReq := httptest.NewRequest("POST", pathSubmit, strings.NewReader(form.Encode()))
	postReq.Header.Set(headerContentType, contentTypeForm)
	postReq.AddCookie(&http.Cookie{
		Name:  "_csrf",
		Value: csrfCookieValue,
	})
	router.ServeHTTP(postW, postReq)

	if postW.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d", postW.Code)
	}
}

func TestCSRFAPIRouteExempt(t *testing.T) {
	router, _ := setupCSRFRouter()

	router.POST("/api/something", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/something", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for exempt API route, got %d", w.Code)
	}
}

func TestRateLimitAllowsInitial(t *testing.T) {
	limiter := middleware.NewInMemoryRateLimiter()
	result := limiter.CheckAndRecord("192.168.1.1", testDomainExample)

	if !result.Allowed {
		t.Fatalf("expected initial request to be allowed, got blocked with reason: %s", result.Reason)
	}
}

func TestRateLimitBlocksAfterMax(t *testing.T) {
	limiter := middleware.NewInMemoryRateLimiter()

	for i := 0; i < 8; i++ {
		domain := fmt.Sprintf("domain%d.com", i)
		result := limiter.CheckAndRecord("10.0.0.1", domain)
		if !result.Allowed {
			t.Fatalf("request %d should be allowed, got blocked with reason: %s", i+1, result.Reason)
		}
	}

	result := limiter.CheckAndRecord("10.0.0.1", "domain8.com")
	if result.Allowed {
		t.Fatal("9th request should be blocked")
	}
	if result.Reason != "rate_limit" {
		t.Fatalf("expected reason 'rate_limit', got '%s'", result.Reason)
	}
}

func TestAntiRepeatBlocksSameDomain(t *testing.T) {
	limiter := middleware.NewInMemoryRateLimiter()

	result := limiter.CheckAndRecord("10.0.0.2", testDomainExample)
	if !result.Allowed {
		t.Fatal(msgFirstReqAllowed)
	}

	result = limiter.CheckAndRecord("10.0.0.2", testDomainExample)
	if result.Allowed {
		t.Fatal("repeat request for same domain should be blocked")
	}
	if result.Reason != "anti_repeat" {
		t.Fatalf("expected reason 'anti_repeat', got '%s'", result.Reason)
	}
}

func TestAntiRepeatAllowsDifferentDomain(t *testing.T) {
	limiter := middleware.NewInMemoryRateLimiter()

	result := limiter.CheckAndRecord("10.0.0.3", testDomainExample)
	if !result.Allowed {
		t.Fatal(msgFirstReqAllowed)
	}

	result = limiter.CheckAndRecord("10.0.0.3", "different.com")
	if !result.Allowed {
		t.Fatalf("different domain should be allowed, got blocked with reason: %s", result.Reason)
	}
}

func TestAntiRepeatCaseInsensitive(t *testing.T) {
	limiter := middleware.NewInMemoryRateLimiter()

	result := limiter.CheckAndRecord("10.0.0.4", "Example.COM")
	if !result.Allowed {
		t.Fatal(msgFirstReqAllowed)
	}

	result = limiter.CheckAndRecord("10.0.0.4", testDomainExample)
	if result.Allowed {
		t.Fatal("case-insensitive duplicate should be blocked")
	}
	if result.Reason != "anti_repeat" {
		t.Fatalf("expected reason 'anti_repeat', got '%s'", result.Reason)
	}
}

func TestSecurityHeadersPresent(t *testing.T) {
	router := gin.New()
	router.Use(middleware.RequestContext())
	router.Use(middleware.SecurityHeaders())
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf(msgExpect200, w.Code)
	}

	checks := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
	}

	for header, expected := range checks {
		got := w.Header().Get(header)
		if got != expected {
			t.Errorf("expected %s: %s, got: %s", header, expected, got)
		}
	}

	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("Content-Security-Policy header is missing")
	}
	if !strings.Contains(csp, "nonce-") {
		t.Error("CSP header does not contain a nonce")
	}
	if strings.Contains(csp, "upgrade-insecure-requests") {
		t.Error("CSP should NOT contain upgrade-insecure-requests for plain HTTP requests")
	}
}

func TestSecurityHeadersUpgradeInsecureHTTPS(t *testing.T) {
	router := gin.New()
	router.Use(middleware.RequestContext())
	router.Use(middleware.SecurityHeaders())
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	router.ServeHTTP(w, req)

	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "upgrade-insecure-requests") {
		t.Error("CSP should contain upgrade-insecure-requests for HTTPS requests")
	}
}

func TestRequestContextSetsNonceAndTraceID(t *testing.T) {
	router := gin.New()
	router.Use(middleware.RequestContext())

	var nonce, traceID string
	router.GET("/test", func(c *gin.Context) {
		n, _ := c.Get("csp_nonce")
		nonce, _ = n.(string)
		t, _ := c.Get("trace_id")
		traceID, _ = t.(string)
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)

	if nonce == "" {
		t.Error("csp_nonce should be set by RequestContext")
	}
	if traceID == "" {
		t.Error("trace_id should be set by RequestContext")
	}
}

func TestCSRFEnsureTokenReusesCookie(t *testing.T) {
	router, _ := setupCSRFRouter()

	var token1, token2 string
	router.GET("/form", func(c *gin.Context) {
		token1 = middleware.GetCSRFToken(c)
		c.String(http.StatusOK, "ok")
	})

	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("GET", "/form", nil)
	router.ServeHTTP(w1, req1)

	var csrfCookie string
	for _, ck := range w1.Result().Cookies() {
		if ck.Name == "_csrf" {
			csrfCookie = ck.Value
			break
		}
	}

	router2, _ := setupCSRFRouter()
	router2.GET("/form2", func(c *gin.Context) {
		token2 = middleware.GetCSRFToken(c)
		c.String(http.StatusOK, "ok")
	})
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/form2", nil)
	req2.AddCookie(&http.Cookie{Name: "_csrf", Value: csrfCookie})
	router2.ServeHTTP(w2, req2)

	if token1 == "" || token2 == "" {
		t.Fatal("tokens should not be empty")
	}
	if token1 != token2 {
		t.Errorf("token should be reused from valid cookie; got %q vs %q", token1, token2)
	}
}

func TestAnalyzeRateLimitPostBlocked(t *testing.T) {
	limiter := middleware.NewInMemoryRateLimiter()
	router := gin.New()
	router.Use(middleware.AnalyzeRateLimit(limiter))
	router.POST("/analyze", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("POST", "/analyze", strings.NewReader("domain=example.com"))
	req1.Header.Set(headerContentType, contentTypeForm)
	router.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", w1.Code)
	}

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("POST", "/analyze", strings.NewReader("domain=example.com"))
	req2.Header.Set(headerContentType, contentTypeForm)
	router.ServeHTTP(w2, req2)
	if w2.Code != http.StatusSeeOther {
		t.Fatalf("repeat request: expected 303 redirect, got %d", w2.Code)
	}
}

func TestAnalyzeRateLimitGetPassthroughExt(t *testing.T) {
	limiter := middleware.NewInMemoryRateLimiter()
	router := gin.New()
	router.Use(middleware.AnalyzeRateLimit(limiter))
	router.GET("/analyze", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/analyze", nil)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET should pass through, got %d", w.Code)
	}
}

func TestAnalyzeRateLimitEmptyDomainExt(t *testing.T) {
	limiter := middleware.NewInMemoryRateLimiter()
	router := gin.New()
	router.Use(middleware.AnalyzeRateLimit(limiter))
	router.POST("/analyze", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/analyze", strings.NewReader("domain="))
	req.Header.Set(headerContentType, contentTypeForm)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("empty domain POST should pass through, got %d", w.Code)
	}
}

func TestAnalyzeRateLimitJSONResponse(t *testing.T) {
	limiter := middleware.NewInMemoryRateLimiter()
	router := gin.New()
	router.Use(middleware.AnalyzeRateLimit(limiter))
	router.POST("/analyze", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("POST", "/analyze", strings.NewReader("domain=test.com"))
	req1.Header.Set(headerContentType, contentTypeForm)
	router.ServeHTTP(w1, req1)

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("POST", "/analyze", strings.NewReader("domain=test.com"))
	req2.Header.Set(headerContentType, contentTypeForm)
	req2.Header.Set("Accept", "application/json")
	router.ServeHTTP(w2, req2)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("JSON rate limit: expected 429, got %d", w2.Code)
	}
}

func TestAnalyzeRateLimitMaxRequests(t *testing.T) {
	limiter := middleware.NewInMemoryRateLimiter()
	router := gin.New()
	router.Use(middleware.AnalyzeRateLimit(limiter))
	router.POST("/analyze", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	for i := 0; i < 8; i++ {
		w := httptest.NewRecorder()
		body := fmt.Sprintf("domain=domain%d.com", i)
		req := httptest.NewRequest("POST", "/analyze", strings.NewReader(body))
		req.Header.Set(headerContentType, contentTypeForm)
		router.ServeHTTP(w, req)
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/analyze", strings.NewReader("domain=domain99.com"))
	req.Header.Set(headerContentType, contentTypeForm)
	router.ServeHTTP(w, req)
	if w.Code == http.StatusOK {
		t.Fatal("9th request should be rate limited")
	}
}

func TestAuthRateLimitBlocks(t *testing.T) {
	limiter := middleware.NewInMemoryRateLimiter()
	router := gin.New()
	router.Use(middleware.AuthRateLimit(limiter))
	router.GET("/auth/login", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("GET", "/auth/login", nil)
	router.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first auth request: expected 200, got %d", w1.Code)
	}

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/auth/login", nil)
	router.ServeHTTP(w2, req2)
	if w2.Code != http.StatusFound {
		t.Fatalf("repeat auth request: expected 302 redirect, got %d", w2.Code)
	}
}

func TestAuthRateLimitCallbackPathExt(t *testing.T) {
	limiter := middleware.NewInMemoryRateLimiter()
	router := gin.New()
	router.Use(middleware.AuthRateLimit(limiter))
	router.GET("/auth/callback", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("GET", "/auth/callback", nil)
	router.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first callback: expected 200, got %d", w1.Code)
	}

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/auth/callback", nil)
	router.ServeHTTP(w2, req2)
	if w2.Code != http.StatusFound {
		t.Fatalf("repeat callback: expected 302, got %d", w2.Code)
	}
}

func TestRateLimitWaitSecondsMinimum(t *testing.T) {
	limiter := middleware.NewInMemoryRateLimiter()

	for i := 0; i < 8; i++ {
		limiter.CheckAndRecord("10.10.10.10", fmt.Sprintf("d%d.com", i))
	}

	result := limiter.CheckAndRecord("10.10.10.10", "extra.com")
	if result.Allowed {
		t.Fatal("should be blocked")
	}
	if result.WaitSeconds < 1 {
		t.Errorf("WaitSeconds should be >= 1, got %d", result.WaitSeconds)
	}
}

func TestCanonicalHostRedirect_ReplitAppRedirects(t *testing.T) {
	router := gin.New()
	router.Use(middleware.CanonicalHostRedirect("https://dnstool.it-help.tech"))
	router.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://dns-tool.replit.app/", nil)
	req.Host = "dns-tool.replit.app"
	router.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc != "https://dnstool.it-help.tech/" {
		t.Errorf("expected redirect to canonical host, got %s", loc)
	}
	cc := w.Header().Get("Cache-Control")
	if cc != "no-cache, no-store, must-revalidate" {
		t.Errorf("expected no-cache header on redirect, got %s", cc)
	}
}

func TestCanonicalHostRedirect_CanonicalHostPasses(t *testing.T) {
	router := gin.New()
	router.Use(middleware.CanonicalHostRedirect("https://dnstool.it-help.tech"))
	router.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://dnstool.it-help.tech/", nil)
	req.Host = "dnstool.it-help.tech"
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf(msgExpect200, w.Code)
	}
}

func TestCanonicalHostRedirect_PreservesPath(t *testing.T) {
	router := gin.New()
	router.Use(middleware.CanonicalHostRedirect("https://dnstool.it-help.tech"))
	router.GET("/analyze", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://dns-tool.replit.app/analyze?domain=example.com", nil)
	req.Host = "dns-tool.replit.app"
	router.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc != "https://dnstool.it-help.tech/analyze?domain=example.com" {
		t.Errorf("expected path+query preserved, got %s", loc)
	}
}

func TestCanonicalHostRedirect_ReplitDevRedirects(t *testing.T) {
	router := gin.New()
	router.Use(middleware.CanonicalHostRedirect("https://dnstool.it-help.tech"))
	router.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "something.replit.dev"
	router.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302 for .replit.dev, got %d", w.Code)
	}
}

func TestCanonicalHostRedirect_InvalidURLDisablesMiddleware(t *testing.T) {
	router := gin.New()
	router.Use(middleware.CanonicalHostRedirect(""))
	router.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "dns-tool.replit.app"
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("middleware should be disabled for invalid URL, got %d", w.Code)
	}
}

func TestRecovery_NoPanic(t *testing.T) {
	router := gin.New()
	router.Use(middleware.RequestContext())
	router.Use(middleware.Recovery("1.0.0"))
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

func TestRecovery_WithExtraData(t *testing.T) {
	router := gin.New()
	router.Use(middleware.RequestContext())
	extra := map[string]any{"MaintenanceNote": "test note", "BetaPages": map[string]bool{}}
	router.Use(middleware.Recovery("1.0.0", extra))
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

func TestSecurityHeaders_DevMode_ConnectSrc(t *testing.T) {
	router := gin.New()
	router.Use(middleware.RequestContext())
	router.Use(middleware.SecurityHeaders(true))
	router.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	router.ServeHTTP(w, req)

	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "connect-src 'self' https://replit.com") {
		t.Errorf("dev mode CSP should include Replit connect-src, got: %s", csp)
	}
	if !strings.Contains(csp, "frame-ancestors https://replit.com") {
		t.Errorf("dev mode CSP should include Replit frame-ancestors, got: %s", csp)
	}
}

func TestSecurityHeaders_ProdMode_ConnectSrc(t *testing.T) {
	router := gin.New()
	router.Use(middleware.RequestContext())
	router.Use(middleware.SecurityHeaders(false))
	router.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	router.ServeHTTP(w, req)

	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "connect-src 'self'") {
		t.Errorf("prod mode CSP should have connect-src 'self', got: %s", csp)
	}
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("prod mode CSP should have frame-ancestors 'none', got: %s", csp)
	}
}

func TestCSRFPostWithEmptyBody(t *testing.T) {
	router, _ := setupCSRFRouter()
	router.POST(pathSubmit, func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", pathSubmit, nil)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("POST with no body: expected 303, got %d", w.Code)
	}
}
