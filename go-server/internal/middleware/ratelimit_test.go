package middleware

import (
        "net/http"
        "net/http/httptest"
        "net/url"
        "strings"
        "testing"

        "github.com/gin-gonic/gin"
)

func TestInMemoryRateLimiter_AllowsInitialRequests(t *testing.T) {
        limiter := &InMemoryRateLimiter{
                requests: make(map[string][]requestEntry),
        }

        result := limiter.CheckAndRecord("10.0.0.1", "example.com")
        if !result.Allowed {
                t.Error("first request should be allowed")
        }
        if result.Reason != "ok" {
                t.Errorf("reason = %q, want 'ok'", result.Reason)
        }
}

func TestInMemoryRateLimiter_BlocksAfterMax(t *testing.T) {
        limiter := &InMemoryRateLimiter{
                requests: make(map[string][]requestEntry),
        }

        for i := 0; i < RateLimitMaxRequests; i++ {
                result := limiter.CheckAndRecord("10.0.0.1", "domain"+string(rune('a'+i))+".com")
                if !result.Allowed {
                        t.Fatalf("request %d should be allowed", i)
                }
        }

        result := limiter.CheckAndRecord("10.0.0.1", "excess.com")
        if result.Allowed {
                t.Error("request beyond max should be blocked")
        }
        if result.Reason != "rate_limit" {
                t.Errorf("reason = %q, want 'rate_limit'", result.Reason)
        }
        if result.WaitSeconds < 1 {
                t.Errorf("WaitSeconds = %d, should be >= 1", result.WaitSeconds)
        }
}

func TestInMemoryRateLimiter_AntiRepeat_BlocksDuplicateDomain(t *testing.T) {
        limiter := &InMemoryRateLimiter{
                requests: make(map[string][]requestEntry),
        }

        result1 := limiter.CheckAndRecord("10.0.0.2", "example.com")
        if !result1.Allowed {
                t.Fatal("first request should be allowed")
        }

        result2 := limiter.CheckAndRecord("10.0.0.2", "example.com")
        if result2.Allowed {
                t.Error("duplicate domain should be blocked by anti-repeat")
        }
        if result2.Reason != "anti_repeat" {
                t.Errorf("reason = %q, want 'anti_repeat'", result2.Reason)
        }
}

func TestInMemoryRateLimiter_CaseInsensitive(t *testing.T) {
        limiter := &InMemoryRateLimiter{
                requests: make(map[string][]requestEntry),
        }

        limiter.CheckAndRecord("10.0.0.3", "EXAMPLE.COM")
        result := limiter.CheckAndRecord("10.0.0.3", "example.com")
        if result.Allowed {
                t.Error("domain should be case-insensitive for anti-repeat")
        }
}

func TestInMemoryRateLimiter_DifferentIPsIndependent(t *testing.T) {
        limiter := &InMemoryRateLimiter{
                requests: make(map[string][]requestEntry),
        }

        for i := 0; i < RateLimitMaxRequests; i++ {
                limiter.CheckAndRecord("10.0.0.4", "domain"+string(rune('a'+i))+".com")
        }

        result := limiter.CheckAndRecord("10.0.0.5", "example.com")
        if !result.Allowed {
                t.Error("different IP should not be rate limited")
        }
}

func TestPruneOld_RemovesExpired(t *testing.T) {
        now := float64(1000)
        entries := []requestEntry{
                {timestamp: 900, domain: "old.com"},
                {timestamp: 930, domain: "also_old.com"},
                {timestamp: 950, domain: "newer.com"},
                {timestamp: 990, domain: "recent.com"},
        }

        result := pruneOld(entries, now)
        if len(result) != 2 {
                t.Errorf("expected 2 entries after pruning (cutoff=%d), got %d", int(now)-RateLimitWindow, len(result))
        }
        if result[0].domain != "newer.com" {
                t.Errorf("expected newer.com first, got %s", result[0].domain)
        }
        if result[1].domain != "recent.com" {
                t.Errorf("expected recent.com second, got %s", result[1].domain)
        }
}

func TestPruneOld_EmptyInput(t *testing.T) {
        result := pruneOld(nil, 1000)
        if len(result) != 0 {
                t.Errorf("expected 0 entries, got %d", len(result))
        }
}

func TestRateLimitMessage_RateLimit(t *testing.T) {
        msg := rateLimitMessage(RateLimitResult{Reason: "rate_limit", WaitSeconds: 30})
        if !strings.Contains(msg, "30 seconds") {
                t.Errorf("msg = %q, should contain '30 seconds'", msg)
        }
        if !strings.Contains(msg, "Rate limit") {
                t.Errorf("msg = %q, should contain 'Rate limit'", msg)
        }
}

func TestRateLimitMessage_AntiRepeat(t *testing.T) {
        msg := rateLimitMessage(RateLimitResult{Reason: "anti_repeat", WaitSeconds: 15})
        if !strings.Contains(msg, "recently analyzed") {
                t.Errorf("msg = %q, should contain 'recently analyzed'", msg)
        }
}

func TestRateLimitMessage_UnknownReason(t *testing.T) {
        msg := rateLimitMessage(RateLimitResult{Reason: "unknown", WaitSeconds: 5})
        if !strings.Contains(msg, "5 seconds") {
                t.Errorf("msg = %q, should contain '5 seconds'", msg)
        }
}

func TestSafeRefererPath_Empty(t *testing.T) {
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodPost, "/test", nil)

        result := safeRefererPath(c)
        if result != "/" {
                t.Errorf("safeRefererPath = %q, want '/'", result)
        }
}

func TestSafeRefererPath_Valid(t *testing.T) {
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodPost, "/test", nil)
        c.Request.Header.Set("Referer", "https://example.com/about")

        result := safeRefererPath(c)
        if result != "/about" {
                t.Errorf("safeRefererPath = %q, want '/about'", result)
        }
}

func TestSafeRefererPath_DoubleSlash(t *testing.T) {
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodPost, "/test", nil)
        c.Request.Header.Set("Referer", "https://example.com//evil")

        result := safeRefererPath(c)
        if result != "/" {
                t.Errorf("safeRefererPath = %q, want '/' for double-slash", result)
        }
}

func TestSafeRefererPath_InvalidURL(t *testing.T) {
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodPost, "/test", nil)
        c.Request.Header.Set("Referer", "://invalid")

        result := safeRefererPath(c)
        if result != "/" {
                t.Errorf("safeRefererPath = %q, want '/' for invalid URL", result)
        }
}

func TestAnalyzeRateLimit_SkipsGET(t *testing.T) {
        gin.SetMode(gin.TestMode)
        limiter := &InMemoryRateLimiter{
                requests: make(map[string][]requestEntry),
        }
        router := gin.New()
        router.Use(AnalyzeRateLimit(limiter))
        router.GET("/test", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/test", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Errorf("GET should pass through, got %d", w.Code)
        }
}

func TestAnalyzeRateLimit_SkipsEmptyDomain(t *testing.T) {
        gin.SetMode(gin.TestMode)
        limiter := &InMemoryRateLimiter{
                requests: make(map[string][]requestEntry),
        }
        router := gin.New()
        router.Use(AnalyzeRateLimit(limiter))
        router.POST("/test", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/test", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Errorf("POST without domain should pass, got %d", w.Code)
        }
}

func TestAnalyzeRateLimit_BlocksRateLimited(t *testing.T) {
        gin.SetMode(gin.TestMode)
        limiter := &InMemoryRateLimiter{
                requests: make(map[string][]requestEntry),
        }
        router := gin.New()
        router.Use(AnalyzeRateLimit(limiter))
        router.POST("/test", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        var lastCode int
        for i := 0; i < RateLimitMaxRequests+1; i++ {
                form := url.Values{}
                form.Set("domain", "unique"+string(rune('a'+i))+".com")
                w := httptest.NewRecorder()
                req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(form.Encode()))
                req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
                req.RemoteAddr = "10.0.0.99:12345"
                router.ServeHTTP(w, req)
                lastCode = w.Code
        }

        if lastCode == http.StatusOK {
                t.Error("request beyond rate limit should not return 200")
        }
}

func TestAnalyzeRateLimit_AntiRepeatBlocks(t *testing.T) {
        gin.SetMode(gin.TestMode)
        limiter := &InMemoryRateLimiter{
                requests: make(map[string][]requestEntry),
        }
        router := gin.New()
        router.Use(AnalyzeRateLimit(limiter))
        router.POST("/test", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        form := url.Values{}
        form.Set("domain", "repeat.com")
        w1 := httptest.NewRecorder()
        req1 := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(form.Encode()))
        req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        req1.RemoteAddr = "10.0.0.100:12345"
        router.ServeHTTP(w1, req1)
        if w1.Code != http.StatusOK {
                t.Fatalf("first request should pass, got %d", w1.Code)
        }

        w2 := httptest.NewRecorder()
        req2 := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(form.Encode()))
        req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        req2.RemoteAddr = "10.0.0.100:12345"
        router.ServeHTTP(w2, req2)
        if w2.Code == http.StatusOK {
                t.Error("anti-repeat should block duplicate domain within window")
        }
}

func TestAuthRateLimit_BlocksRepeatPath(t *testing.T) {
        gin.SetMode(gin.TestMode)
        limiter := &InMemoryRateLimiter{
                requests: make(map[string][]requestEntry),
        }
        router := gin.New()
        router.Use(AuthRateLimit(limiter))
        router.POST("/auth/login", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w1 := httptest.NewRecorder()
        req1 := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
        req1.RemoteAddr = "10.0.0.200:12345"
        router.ServeHTTP(w1, req1)
        if w1.Code != http.StatusOK {
                t.Fatalf("first auth request should pass, got %d", w1.Code)
        }

        w2 := httptest.NewRecorder()
        req2 := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
        req2.RemoteAddr = "10.0.0.200:12345"
        router.ServeHTTP(w2, req2)
        if w2.Code == http.StatusOK {
                t.Error("auth rate limiter should block repeat path")
        }
}

func TestAuthRateLimit_AllowsFirstRequest(t *testing.T) {
        gin.SetMode(gin.TestMode)
        limiter := &InMemoryRateLimiter{
                requests: make(map[string][]requestEntry),
        }
        router := gin.New()
        router.Use(AuthRateLimit(limiter))
        router.POST("/login", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/login", nil)
        req.RemoteAddr = "10.0.0.10:12345"
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Errorf("first auth request should pass, got %d", w.Code)
        }
}

func TestRateLimitConstants(t *testing.T) {
        if RateLimitMaxRequests != 8 {
                t.Errorf("RateLimitMaxRequests = %d, want 8", RateLimitMaxRequests)
        }
        if RateLimitWindow != 60 {
                t.Errorf("RateLimitWindow = %d, want 60", RateLimitWindow)
        }
        if AntiRepeatWindow != 15 {
                t.Errorf("AntiRepeatWindow = %d, want 15", AntiRepeatWindow)
        }
}
