package middleware

import (
        "net/http"
        "net/http/httptest"
        "net/url"
        "strings"
        "testing"

        "github.com/gin-gonic/gin"
)

func TestCSRFMiddleware_ExemptPaths(t *testing.T) {
        gin.SetMode(gin.TestMode)

        tests := []struct {
                path string
        }{
                {"/api/v1/resource"},
                {"/go/health"},
                {"/robots.txt"},
                {"/sitemap.xml"},
                {"/manifest.json"},
                {"/sw.js"},
        }

        for _, tt := range tests {
                t.Run(tt.path, func(t *testing.T) {
                        m := NewCSRFMiddleware("test-secret")
                        router := gin.New()
                        router.Use(m.Handler())
                        router.POST(tt.path, func(c *gin.Context) {
                                c.String(http.StatusOK, "ok")
                        })

                        w := httptest.NewRecorder()
                        req := httptest.NewRequest(http.MethodPost, tt.path, nil)
                        router.ServeHTTP(w, req)

                        if w.Code == http.StatusForbidden {
                                t.Errorf("POST %s should be CSRF-exempt, got 403", tt.path)
                        }
                })
        }
}

func TestCSRFMiddleware_GET_SetsToken(t *testing.T) {
        gin.SetMode(gin.TestMode)
        m := NewCSRFMiddleware("test-secret")
        router := gin.New()
        router.Use(m.Handler())
        router.GET("/test", func(c *gin.Context) {
                token, exists := c.Get("csrf_token")
                if !exists {
                        t.Error("expected csrf_token in context")
                }
                if token == "" {
                        t.Error("expected non-empty csrf_token")
                }
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/test", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Errorf("GET should succeed, got %d", w.Code)
        }

        cookies := w.Result().Cookies()
        found := false
        for _, c := range cookies {
                if c.Name == "_csrf" {
                        found = true
                        if !c.HttpOnly {
                                t.Error("expected HttpOnly cookie")
                        }
                        if !c.Secure {
                                t.Error("expected Secure cookie")
                        }
                        break
                }
        }
        if !found {
                t.Error("expected _csrf cookie to be set")
        }
}

func TestCSRFMiddleware_POST_NoCookie_Redirects(t *testing.T) {
        gin.SetMode(gin.TestMode)
        m := NewCSRFMiddleware("test-secret")
        router := gin.New()
        router.Use(m.Handler())
        router.POST("/test", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/test", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusSeeOther {
                t.Errorf("POST without cookie should redirect, got %d", w.Code)
        }
}

func TestCSRFMiddleware_POST_ValidToken_Succeeds(t *testing.T) {
        gin.SetMode(gin.TestMode)
        secret := "test-secret-key-for-csrf"
        m := NewCSRFMiddleware(secret)

        router := gin.New()
        router.Use(m.Handler())

        var csrfToken string
        router.GET("/form", func(c *gin.Context) {
                token, _ := c.Get("csrf_token")
                csrfToken = token.(string)
                c.String(http.StatusOK, "ok")
        })
        router.POST("/test", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w1 := httptest.NewRecorder()
        req1 := httptest.NewRequest(http.MethodGet, "/form", nil)
        router.ServeHTTP(w1, req1)

        var csrfCookie *http.Cookie
        for _, c := range w1.Result().Cookies() {
                if c.Name == "_csrf" {
                        csrfCookie = c
                        break
                }
        }

        if csrfCookie == nil {
                t.Fatal("expected _csrf cookie")
        }

        form := url.Values{}
        form.Set("csrf_token", csrfToken)

        w2 := httptest.NewRecorder()
        req2 := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(form.Encode()))
        req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        req2.AddCookie(csrfCookie)
        router.ServeHTTP(w2, req2)

        if w2.Code != http.StatusOK {
                t.Errorf("POST with valid CSRF token should succeed, got %d", w2.Code)
        }
}

func TestCSRFMiddleware_POST_InvalidCookieSig_Redirects(t *testing.T) {
        gin.SetMode(gin.TestMode)
        m := NewCSRFMiddleware("test-secret")
        router := gin.New()
        router.Use(m.Handler())
        router.POST("/test", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        form := url.Values{}
        form.Set("csrf_token", "mytoken")

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        req.AddCookie(&http.Cookie{Name: "_csrf", Value: "invalid-cookie-value"})
        router.ServeHTTP(w, req)

        if w.Code != http.StatusSeeOther {
                t.Errorf("POST with invalid cookie sig should redirect, got %d", w.Code)
        }
}

func TestCSRFMiddleware_POST_MismatchedToken_Redirects(t *testing.T) {
        gin.SetMode(gin.TestMode)
        secret := "test-secret"
        m := NewCSRFMiddleware(secret)

        router := gin.New()
        router.Use(m.Handler())

        var csrfCookie *http.Cookie
        router.GET("/form", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })
        router.POST("/test", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w1 := httptest.NewRecorder()
        req1 := httptest.NewRequest(http.MethodGet, "/form", nil)
        router.ServeHTTP(w1, req1)

        for _, c := range w1.Result().Cookies() {
                if c.Name == "_csrf" {
                        csrfCookie = c
                        break
                }
        }
        if csrfCookie == nil {
                t.Fatal("expected _csrf cookie")
        }

        form := url.Values{}
        form.Set("csrf_token", "wrong-token-value")

        w2 := httptest.NewRecorder()
        req2 := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(form.Encode()))
        req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        req2.AddCookie(csrfCookie)
        router.ServeHTTP(w2, req2)

        if w2.Code != http.StatusSeeOther {
                t.Errorf("POST with mismatched token should redirect, got %d", w2.Code)
        }
}

func TestCSRFMiddleware_HEAD_ShouldBeSafe(t *testing.T) {
        gin.SetMode(gin.TestMode)
        m := NewCSRFMiddleware("test-secret")
        router := gin.New()
        router.Use(m.Handler())
        router.HEAD("/test", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodHead, "/test", nil)
        router.ServeHTTP(w, req)

        if w.Code == http.StatusSeeOther || w.Code == http.StatusForbidden {
                t.Error("HEAD should be treated as safe method")
        }
}

func TestCSRFMiddleware_OPTIONS_ShouldBeSafe(t *testing.T) {
        gin.SetMode(gin.TestMode)
        m := NewCSRFMiddleware("test-secret")
        router := gin.New()
        router.Use(m.Handler())
        router.OPTIONS("/test", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodOptions, "/test", nil)
        router.ServeHTTP(w, req)

        if w.Code == http.StatusSeeOther || w.Code == http.StatusForbidden {
                t.Error("OPTIONS should be treated as safe method")
        }
}

func TestCSRFMiddleware_RejectCSRF_WithDomain_RedirectsWithDomain(t *testing.T) {
        gin.SetMode(gin.TestMode)
        m := NewCSRFMiddleware("test-secret")
        router := gin.New()
        router.Use(m.Handler())
        router.POST("/test", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        form := url.Values{}
        form.Set("domain", "example.com")

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        router.ServeHTTP(w, req)

        loc := w.Header().Get("Location")
        if !strings.Contains(loc, "domain=example.com") {
                t.Errorf("redirect should include domain, got Location=%q", loc)
        }
}

func TestGetCSRFToken_NoContext(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        token := GetCSRFToken(c)
        if token != "" {
                t.Errorf("expected empty token, got %q", token)
        }
}

func TestGetCSRFToken_WithContext(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Set("csrf_token", "my-token")
        token := GetCSRFToken(c)
        if token != "my-token" {
                t.Errorf("expected 'my-token', got %q", token)
        }
}

func TestCSRFHiddenInput(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Set("csrf_token", "my-token")
        html := CSRFHiddenInput(c)
        if !strings.Contains(html, `name="csrf_token"`) {
                t.Error("expected csrf_token field name")
        }
        if !strings.Contains(html, `value="my-token"`) {
                t.Error("expected token value")
        }
        if !strings.Contains(html, `type="hidden"`) {
                t.Error("expected hidden input type")
        }
}

func TestIsCSRFExempt_EdgeCases(t *testing.T) {
        tests := []struct {
                path string
                want bool
        }{
                {"/api/", true},
                {"/api/v2/deep/path", true},
                {"/apifake", false},
                {"/go/healthcheck", false},
                {"", false},
        }
        for _, tt := range tests {
                t.Run(tt.path, func(t *testing.T) {
                        got := isCSRFExempt(tt.path)
                        if got != tt.want {
                                t.Errorf("isCSRFExempt(%q) = %v, want %v", tt.path, got, tt.want)
                        }
                })
        }
}

func TestCSRFMiddleware_MakeSignedToken_ValidateRoundTrip(t *testing.T) {
        m := NewCSRFMiddleware("test-secret")
        token := m.generateToken()
        signed := m.makeSignedToken(token)

        extracted, valid := m.validateSignedToken(signed)
        if !valid {
                t.Error("expected valid signed token")
        }
        if extracted != token {
                t.Errorf("extracted = %q, want %q", extracted, token)
        }
}

func TestCSRFMiddleware_ValidateSignedToken_InvalidFormat(t *testing.T) {
        m := NewCSRFMiddleware("test-secret")

        _, valid := m.validateSignedToken("no-dot-here")
        if valid {
                t.Error("expected invalid for token without dot")
        }
}

func TestCSRFMiddleware_ValidateSignedToken_WrongSecret(t *testing.T) {
        m1 := NewCSRFMiddleware("secret-1")
        m2 := NewCSRFMiddleware("secret-2")

        token := m1.generateToken()
        signed := m1.makeSignedToken(token)

        _, valid := m2.validateSignedToken(signed)
        if valid {
                t.Error("expected invalid when verified with wrong secret")
        }
}

func TestCSRFMiddleware_POST_TamperedCookie_Redirects(t *testing.T) {
        gin.SetMode(gin.TestMode)
        secret := "test-secret-tamper"
        m := NewCSRFMiddleware(secret)

        router := gin.New()
        router.Use(m.Handler())

        var csrfToken string
        router.GET("/form", func(c *gin.Context) {
                token, _ := c.Get("csrf_token")
                csrfToken = token.(string)
                c.String(http.StatusOK, "ok")
        })
        router.POST("/submit", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w1 := httptest.NewRecorder()
        req1 := httptest.NewRequest(http.MethodGet, "/form", nil)
        router.ServeHTTP(w1, req1)

        var csrfCookie *http.Cookie
        for _, c := range w1.Result().Cookies() {
                if c.Name == "_csrf" {
                        csrfCookie = c
                        break
                }
        }
        if csrfCookie == nil {
                t.Fatal("expected _csrf cookie")
        }

        tamperedCookie := *csrfCookie
        tamperedCookie.Value = csrfCookie.Value[:len(csrfCookie.Value)-2] + "XX"

        form := url.Values{}
        form.Set("csrf_token", csrfToken)
        w2 := httptest.NewRecorder()
        req2 := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(form.Encode()))
        req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        req2.AddCookie(&tamperedCookie)
        router.ServeHTTP(w2, req2)

        if w2.Code == http.StatusOK {
                t.Error("POST with tampered cookie should NOT succeed")
        }
}

func TestCSRFMiddleware_POST_ReplayWithDifferentSecretInstance(t *testing.T) {
        gin.SetMode(gin.TestMode)

        m1 := NewCSRFMiddleware("secret-instance-1")
        m2 := NewCSRFMiddleware("secret-instance-2")

        router1 := gin.New()
        router1.Use(m1.Handler())
        var csrfToken1 string
        router1.GET("/form", func(c *gin.Context) {
                token, _ := c.Get("csrf_token")
                csrfToken1 = token.(string)
                c.String(http.StatusOK, "ok")
        })

        w1 := httptest.NewRecorder()
        req1 := httptest.NewRequest(http.MethodGet, "/form", nil)
        router1.ServeHTTP(w1, req1)

        var csrfCookie1 *http.Cookie
        for _, c := range w1.Result().Cookies() {
                if c.Name == "_csrf" {
                        csrfCookie1 = c
                        break
                }
        }
        if csrfCookie1 == nil {
                t.Fatal("expected _csrf cookie from instance 1")
        }

        router2 := gin.New()
        router2.Use(m2.Handler())
        router2.POST("/submit", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        form := url.Values{}
        form.Set("csrf_token", csrfToken1)
        w2 := httptest.NewRecorder()
        req2 := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(form.Encode()))
        req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        req2.AddCookie(csrfCookie1)
        router2.ServeHTTP(w2, req2)

        if w2.Code == http.StatusOK {
                t.Error("CSRF token from instance-1 should not be valid on instance-2")
        }
}

func TestCSRFMiddleware_POST_EmptyFormToken_Redirects(t *testing.T) {
        gin.SetMode(gin.TestMode)
        m := NewCSRFMiddleware("test-secret-empty")
        router := gin.New()
        router.Use(m.Handler())

        router.GET("/form", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })
        router.POST("/submit", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w1 := httptest.NewRecorder()
        req1 := httptest.NewRequest(http.MethodGet, "/form", nil)
        router.ServeHTTP(w1, req1)

        var csrfCookie *http.Cookie
        for _, c := range w1.Result().Cookies() {
                if c.Name == "_csrf" {
                        csrfCookie = c
                        break
                }
        }

        form := url.Values{}
        form.Set("csrf_token", "")
        w2 := httptest.NewRecorder()
        req2 := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(form.Encode()))
        req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        req2.AddCookie(csrfCookie)
        router.ServeHTTP(w2, req2)

        if w2.Code == http.StatusOK {
                t.Error("POST with empty CSRF token should not succeed")
        }
}

func TestCSRFMiddleware_POST_XHeaderToken_Succeeds(t *testing.T) {
        gin.SetMode(gin.TestMode)
        secret := "test-secret-header"
        m := NewCSRFMiddleware(secret)

        router := gin.New()
        router.Use(m.Handler())

        var csrfToken string
        router.GET("/form", func(c *gin.Context) {
                token, _ := c.Get("csrf_token")
                csrfToken = token.(string)
                c.String(http.StatusOK, "ok")
        })
        router.POST("/submit", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w1 := httptest.NewRecorder()
        req1 := httptest.NewRequest(http.MethodGet, "/form", nil)
        router.ServeHTTP(w1, req1)

        var csrfCookie *http.Cookie
        for _, c := range w1.Result().Cookies() {
                if c.Name == "_csrf" {
                        csrfCookie = c
                        break
                }
        }
        if csrfCookie == nil {
                t.Fatal("expected _csrf cookie")
        }

        w2 := httptest.NewRecorder()
        req2 := httptest.NewRequest(http.MethodPost, "/submit", nil)
        req2.Header.Set("X-CSRF-Token", csrfToken)
        req2.AddCookie(csrfCookie)
        router.ServeHTTP(w2, req2)

        if w2.Code != http.StatusOK {
                t.Errorf("POST with X-CSRF-Token header should succeed, got %d", w2.Code)
        }
}

func TestCSRFMiddleware_DELETE_RequiresToken(t *testing.T) {
        gin.SetMode(gin.TestMode)
        m := NewCSRFMiddleware("test-secret")
        router := gin.New()
        router.Use(m.Handler())
        router.DELETE("/resource", func(c *gin.Context) {
                c.String(http.StatusOK, "deleted")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodDelete, "/resource", nil)
        router.ServeHTTP(w, req)

        if w.Code == http.StatusOK {
                t.Error("DELETE without CSRF token should not succeed")
        }
}

func TestCSRFMiddleware_PUT_RequiresToken(t *testing.T) {
        gin.SetMode(gin.TestMode)
        m := NewCSRFMiddleware("test-secret")
        router := gin.New()
        router.Use(m.Handler())
        router.PUT("/resource", func(c *gin.Context) {
                c.String(http.StatusOK, "updated")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodPut, "/resource", nil)
        router.ServeHTTP(w, req)

        if w.Code == http.StatusOK {
                t.Error("PUT without CSRF token should not succeed")
        }
}
