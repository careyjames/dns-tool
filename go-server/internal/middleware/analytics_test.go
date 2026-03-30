package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestExtractRefOrigin(t *testing.T) {
	baseHost := "dnstool.it-help.tech"
	tests := []struct {
		name string
		ref  string
		want string
	}{
		{"empty string returns direct", "", "direct"},
		{"invalid URL returns direct", "://bad", "direct"},
		{"no host returns direct", "/just/a/path", "direct"},
		{"internal dnstool domain returns empty", "https://dnstool.it-help.tech/report", ""},
		{"subdomain of base returns empty", "https://app.dnstool.it-help.tech/page", ""},
		{"external google returns host", "https://www.google.com/search?q=dns", "www.google.com"},
		{"external twitter returns host", "https://twitter.com/share", "twitter.com"},
		{"external with port returns host only", "https://example.com:8080/page", "example.com"},
		{"external with path returns host", "https://reddit.com/r/sysadmin", "reddit.com"},
		{"scheme only no host returns direct", "http://", "direct"},
		{"bare external host", "https://github.com", "github.com"},
		{"external with fragment", "https://stackoverflow.com/questions#answer", "stackoverflow.com"},
		{"external with query params", "https://bing.com/search?q=test&lang=en", "bing.com"},
		{"ftp scheme external", "ftp://files.example.com/data", "files.example.com"},
		{"unrelated domain not filtered", "https://dnstool.example.com/x", "dnstool.example.com"},
		{"relative path no scheme", "about", "direct"},
		{"mailto scheme no host", "mailto:user@example.com", "direct"},
		{"external with userinfo", "https://user:pass@secure.example.org/path", "secure.example.org"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRefOrigin(tt.ref, baseHost)
			if got != tt.want {
				t.Errorf("extractRefOrigin(%q, %q) = %q, want %q", tt.ref, baseHost, got, tt.want)
			}
		})
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{"root stays root", "/", "/"},
		{"trailing slash removed", "/about/", "/about"},
		{"multiple trailing slashes removed", "/page///", "/page"},
		{"query params stripped", "/report?domain=example.com", "/report"},
		{"path with trailing slash and query", "/report/?foo=bar", "/report/"},
		{"no trailing slash unchanged", "/contact", "/contact"},
		{"nested path", "/admin/settings", "/admin/settings"},
		{"nested path with trailing slash", "/admin/settings/", "/admin/settings"},
		{"empty string", "", ""},
		{"path with multiple query params", "/lookup?domain=test.com&type=A", "/lookup"},
		{"deeply nested path", "/a/b/c/d/e", "/a/b/c/d/e"},
		{"deeply nested with trailing slash", "/a/b/c/d/e/", "/a/b/c/d/e"},
		{"query only no path change", "/?q=1", "/"},
		{"path with hash in query", "/page?ref=x#top", "/page"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizePath(tt.path)
			if got != tt.want {
				t.Errorf("normalizePath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestIsCSRFExempt(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"api route exempt", "/api/analyze", true},
		{"api nested route exempt", "/api/v1/report", true},
		{"health endpoint exempt", "/go/health", true},
		{"robots.txt exempt", "/robots.txt", true},
		{"sitemap.xml exempt", "/sitemap.xml", true},
		{"manifest.json exempt", "/manifest.json", true},
		{"sw.js exempt", "/sw.js", true},
		{"root not exempt", "/", false},
		{"form path not exempt", "/submit", false},
		{"about not exempt", "/about", false},
		{"admin not exempt", "/admin", false},
		{"api-like but not prefix", "/not-api/something", false},
		{"partial health match", "/go/healthz", false},
		{"robots without .txt", "/robots", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isCSRFExempt(tt.path)
			if got != tt.want {
				t.Errorf("isCSRFExempt(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestPruneOld(t *testing.T) {
	now := float64(1000)

	tests := []struct {
		name    string
		entries []requestEntry
		wantLen int
	}{
		{"empty entries", nil, 0},
		{"all entries within window", []requestEntry{
			{timestamp: 950, domain: "a.com"},
			{timestamp: 960, domain: "b.com"},
			{timestamp: 999, domain: "c.com"},
		}, 3},
		{"all entries expired", []requestEntry{
			{timestamp: 900, domain: "a.com"},
			{timestamp: 910, domain: "b.com"},
			{timestamp: 930, domain: "c.com"},
		}, 0},
		{"mixed old and new", []requestEntry{
			{timestamp: 920, domain: "old.com"},
			{timestamp: 950, domain: "new1.com"},
			{timestamp: 990, domain: "new2.com"},
		}, 2},
		{"boundary exactly at cutoff kept", []requestEntry{
			{timestamp: 940, domain: "exact.com"},
			{timestamp: 941, domain: "after.com"},
		}, 2},
		{"boundary one before cutoff pruned", []requestEntry{
			{timestamp: 939, domain: "before.com"},
			{timestamp: 941, domain: "after.com"},
		}, 1},
		{"single entry within window", []requestEntry{
			{timestamp: 999, domain: "recent.com"},
		}, 1},
		{"single entry expired", []requestEntry{
			{timestamp: 900, domain: "old.com"},
		}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pruneOld(tt.entries, now)
			if len(got) != tt.wantLen {
				t.Errorf("pruneOld() returned %d entries, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestCSRFValidateSignedToken(t *testing.T) {
	m := NewCSRFMiddleware("test-secret")

	t.Run("valid signed token", func(t *testing.T) {
		token := m.generateToken()
		signed := m.makeSignedToken(token)
		got, valid := m.validateSignedToken(signed)
		if !valid {
			t.Fatal("expected valid token")
		}
		if got != token {
			t.Errorf("got token %q, want %q", got, token)
		}
	})

	t.Run("tampered signature", func(t *testing.T) {
		token := m.generateToken()
		signed := m.makeSignedToken(token)
		tampered := signed[:len(signed)-2] + "XX"
		_, valid := m.validateSignedToken(tampered)
		if valid {
			t.Fatal("expected invalid for tampered signature")
		}
	})

	t.Run("no dot separator", func(t *testing.T) {
		_, valid := m.validateSignedToken("notokenherejustnodot")
		if valid {
			t.Fatal("expected invalid for token without dot")
		}
	})

	t.Run("empty string", func(t *testing.T) {
		_, valid := m.validateSignedToken("")
		if valid {
			t.Fatal("expected invalid for empty string")
		}
	})

	t.Run("just a dot", func(t *testing.T) {
		_, valid := m.validateSignedToken(".")
		if valid {
			t.Fatal("expected invalid for just a dot")
		}
	})

	t.Run("multiple dots uses last", func(t *testing.T) {
		token := m.generateToken()
		signed := m.makeSignedToken(token)
		got, valid := m.validateSignedToken(signed)
		if !valid {
			t.Fatal("expected valid")
		}
		if got != token {
			t.Errorf("got %q, want %q", got, token)
		}
	})

	t.Run("different secret rejects", func(t *testing.T) {
		m2 := NewCSRFMiddleware("different-secret")
		token := m.generateToken()
		signed := m.makeSignedToken(token)
		_, valid := m2.validateSignedToken(signed)
		if valid {
			t.Fatal("expected invalid for token signed with different secret")
		}
	})
}

func TestRecordAnalysis(t *testing.T) {
	ac := &AnalyticsCollector{
		visitors:        make(map[string]bool),
		pageCounts:      make(map[string]int),
		refCounts:       make(map[string]int),
		analysisDomains: make(map[string]bool),
	}

	ac.RecordAnalysis("Example.COM")
	ac.RecordAnalysis("example.com")
	ac.RecordAnalysis("Other.Net")

	if ac.analysesRun != 3 {
		t.Errorf("expected 3 analyses run, got %d", ac.analysesRun)
	}
	if len(ac.analysisDomains) != 2 {
		t.Errorf("expected 2 unique domains, got %d", len(ac.analysisDomains))
	}
	if !ac.analysisDomains["example.com"] {
		t.Error("expected example.com in analysisDomains")
	}
	if !ac.analysisDomains["other.net"] {
		t.Error("expected other.net in analysisDomains")
	}
}

func TestPseudoID(t *testing.T) {
	ac := &AnalyticsCollector{
		dailySalt: "fixed-salt-for-test",
	}

	id1 := ac.pseudoID("1.2.3.4", "Mozilla/5.0")
	id2 := ac.pseudoID("1.2.3.4", "Mozilla/5.0")
	id3 := ac.pseudoID("5.6.7.8", "Mozilla/5.0")
	id4 := ac.pseudoID("1.2.3.4", "Chrome/99")

	if id1 != id2 {
		t.Error("same inputs should produce same pseudoID")
	}
	if id1 == id3 {
		t.Error("different IPs should produce different pseudoID")
	}
	if id1 == id4 {
		t.Error("different UAs should produce different pseudoID")
	}
	if len(id1) != 16 {
		t.Errorf("pseudoID should be 16 hex chars (8 bytes), got %d chars", len(id1))
	}
}

func TestRotateSalt(t *testing.T) {
	ac := &AnalyticsCollector{
		visitors:        make(map[string]bool),
		pageCounts:      make(map[string]int),
		refCounts:       make(map[string]int),
		analysisDomains: make(map[string]bool),
	}

	ac.rotateSalt()
	today := time.Now().UTC().Format("2006-01-02")

	if ac.saltDate != today {
		t.Errorf("expected saltDate %q, got %q", today, ac.saltDate)
	}
	if ac.dailySalt == "" {
		t.Error("dailySalt should not be empty after rotation")
	}

	firstSalt := ac.dailySalt
	ac.rotateSalt()
	if ac.dailySalt != firstSalt {
		t.Error("rotateSalt should not change salt if same day")
	}
}

func TestFlushNoPageviews(t *testing.T) {
	ac := &AnalyticsCollector{
		visitors:        make(map[string]bool),
		pageCounts:      make(map[string]int),
		refCounts:       make(map[string]int),
		analysisDomains: make(map[string]bool),
		pageviews:       0,
	}

	ac.Flush()

	if ac.pageviews != 0 {
		t.Errorf("expected pageviews to remain 0, got %d", ac.pageviews)
	}
}

func TestAnalyzeRateLimitGetPassthrough(t *testing.T) {
	gin.SetMode(gin.TestMode)
	limiter := NewInMemoryRateLimiter()
	router := gin.New()
	router.Use(AnalyzeRateLimit(limiter))
	router.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for GET, got %d", w.Code)
	}
}

func TestAnalyzeRateLimitPostEmptyDomain(t *testing.T) {
	gin.SetMode(gin.TestMode)
	limiter := NewInMemoryRateLimiter()
	router := gin.New()
	router.Use(AnalyzeRateLimit(limiter))
	router.POST("/", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader("domain="))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for empty domain POST, got %d", w.Code)
	}
}

func TestAnalyzeRateLimitPostAllowed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	limiter := NewInMemoryRateLimiter()
	router := gin.New()
	router.Use(AnalyzeRateLimit(limiter))
	router.POST("/", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader("domain=example.com"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for first POST, got %d", w.Code)
	}
}

func TestAnalyzeRateLimitPostBlockedAntiRepeatHTML(t *testing.T) {
	gin.SetMode(gin.TestMode)
	limiter := NewInMemoryRateLimiter()
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("trace_id", "test-trace")
		c.Next()
	})
	router.Use(AnalyzeRateLimit(limiter))
	router.POST("/", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("POST", "/", strings.NewReader("domain=example.com"))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w1, req1)

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("POST", "/", strings.NewReader("domain=example.com"))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w2, req2)

	if w2.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect for repeat domain, got %d", w2.Code)
	}
}

func TestAnalyzeRateLimitPostBlockedJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	limiter := NewInMemoryRateLimiter()
	router := gin.New()
	router.Use(AnalyzeRateLimit(limiter))
	router.POST("/", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("POST", "/", strings.NewReader("domain=test.org"))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w1, req1)

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("POST", "/", strings.NewReader("domain=test.org"))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("Accept", "application/json")
	router.ServeHTTP(w2, req2)

	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for JSON repeat, got %d", w2.Code)
	}
}

func TestAnalyzeRateLimitBlockedRateLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	limiter := NewInMemoryRateLimiter()
	router := gin.New()
	router.Use(AnalyzeRateLimit(limiter))
	router.POST("/", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	for i := 0; i < RateLimitMaxRequests; i++ {
		w := httptest.NewRecorder()
		body := strings.NewReader("domain=domain" + strings.Repeat("x", i) + ".com")
		req := httptest.NewRequest("POST", "/", body)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		router.ServeHTTP(w, req)
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader("domain=overflow.com"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 for rate limit, got %d", w.Code)
	}
}

func TestAuthRateLimitAllowed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	limiter := NewInMemoryRateLimiter()
	router := gin.New()
	router.Use(AuthRateLimit(limiter))
	router.POST("/auth/login", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/auth/login", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for first auth request, got %d", w.Code)
	}
}

func TestAuthRateLimitBlocked(t *testing.T) {
	gin.SetMode(gin.TestMode)
	limiter := NewInMemoryRateLimiter()
	router := gin.New()
	router.Use(AuthRateLimit(limiter))
	router.POST("/auth/login", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("POST", "/auth/login", nil)
	router.ServeHTTP(w1, req1)

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("POST", "/auth/login", nil)
	router.ServeHTTP(w2, req2)

	if w2.Code != http.StatusFound {
		t.Fatalf("expected 302 for repeated auth, got %d", w2.Code)
	}
}

func TestAuthRateLimitCallbackPath(t *testing.T) {
	gin.SetMode(gin.TestMode)
	limiter := NewInMemoryRateLimiter()
	router := gin.New()
	router.Use(AuthRateLimit(limiter))
	router.GET("/auth/callback", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/auth/callback", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for first callback, got %d", w.Code)
	}
}

func TestAnalyticsMiddlewareSkipsStaticPaths(t *testing.T) {
	gin.SetMode(gin.TestMode)
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
	router.GET("/static/css/style.css", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	router.GET("/favicon.ico", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	router.GET("/robots.txt", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	router.GET("/health", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	router.GET("/.well-known/security.txt", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	router.GET("/llms.txt", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	paths := []string{"/static/css/style.css", "/favicon.ico", "/robots.txt", "/health", "/.well-known/security.txt", "/llms.txt"}
	for _, p := range paths {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", p, nil)
		router.ServeHTTP(w, req)
	}

	if ac.pageviews != 0 {
		t.Errorf("expected 0 pageviews for static paths, got %d", ac.pageviews)
	}
}

func TestAnalyticsMiddlewareRecordsPageview(t *testing.T) {
	gin.SetMode(gin.TestMode)
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
	router.GET("/about", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/about", nil)
	req.Header.Set("Referer", "https://google.com/search")
	router.ServeHTTP(w, req)

	if ac.pageviews != 1 {
		t.Errorf("expected 1 pageview, got %d", ac.pageviews)
	}
	if ac.pageCounts["/about"] != 1 {
		t.Errorf("expected 1 count for /about, got %d", ac.pageCounts["/about"])
	}
	if ac.refCounts["google.com"] != 1 {
		t.Errorf("expected 1 ref for google.com, got %d", ac.refCounts["google.com"])
	}
	if len(ac.visitors) != 1 {
		t.Errorf("expected 1 visitor, got %d", len(ac.visitors))
	}
}

func TestAnalyticsMiddlewareSkips4xx(t *testing.T) {
	gin.SetMode(gin.TestMode)
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
		t.Errorf("expected 0 pageviews for 404, got %d", ac.pageviews)
	}
}

func TestCSRFRejectWithDomain(t *testing.T) {
	gin.SetMode(gin.TestMode)
	csrf := NewCSRFMiddleware("test-secret-key")
	router := gin.New()
	router.Use(csrf.Handler())
	router.POST("/submit", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/submit", strings.NewReader("domain=test.com&csrf_token=bad"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "domain=test.com") {
		t.Errorf("redirect should contain domain param, got %q", loc)
	}
}
