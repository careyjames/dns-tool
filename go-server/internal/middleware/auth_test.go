package middleware_test

import (
        "net/http"
        "net/http/httptest"
        "testing"

        "dnstool/go-server/internal/middleware"

        "github.com/gin-gonic/gin"
)

func TestGetAuthTemplateDataUnauthenticated(t *testing.T) {
        router := gin.New()

        var data map[string]any
        router.GET("/test", func(c *gin.Context) {
                data = middleware.GetAuthTemplateData(c)
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/test", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }

        if _, ok := data["Authenticated"]; ok {
                t.Error("Authenticated should not be set for unauthenticated request")
        }
        if data["UserPlan"] != "anonymous" {
                t.Errorf("expected UserPlan=anonymous for unauthenticated request, got %v", data["UserPlan"])
        }
        if data["HasFeaturePersonalHistory"] != false {
                t.Error("anonymous user should not have personal history feature")
        }
        if data["HasFeatureWatchlist"] != false {
                t.Error("anonymous user should not have watchlist feature")
        }
}

func TestGetAuthTemplateDataAuthenticated(t *testing.T) {
        router := gin.New()

        router.Use(func(c *gin.Context) {
                c.Set("authenticated", true)
                c.Set("user_email", "test@example.com")
                c.Set("user_name", "Test User")
                c.Set("user_role", "admin")
                c.Next()
        })

        var data map[string]any
        router.GET("/test", func(c *gin.Context) {
                data = middleware.GetAuthTemplateData(c)
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/test", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }

        if data["Authenticated"] != true {
                t.Error("expected Authenticated to be true")
        }
        if data["UserEmail"] != "test@example.com" {
                t.Errorf("expected UserEmail 'test@example.com', got %v", data["UserEmail"])
        }
        if data["UserName"] != "Test User" {
                t.Errorf("expected UserName 'Test User', got %v", data["UserName"])
        }
        if data["UserRole"] != "admin" {
                t.Errorf("expected UserRole 'admin', got %v", data["UserRole"])
        }
}

func TestGetAuthTemplateDataAuthenticatedFalse(t *testing.T) {
        router := gin.New()

        router.Use(func(c *gin.Context) {
                c.Set("authenticated", false)
                c.Next()
        })

        var data map[string]any
        router.GET("/test", func(c *gin.Context) {
                data = middleware.GetAuthTemplateData(c)
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/test", nil)
        router.ServeHTTP(w, req)

        if _, ok := data["Authenticated"]; ok {
                t.Error("Authenticated should not be set when auth value is false")
        }
}

func TestCSRFHiddenInput(t *testing.T) {
        csrf := middleware.NewCSRFMiddleware(testSecret)
        router := gin.New()
        router.Use(csrf.Handler())

        var hiddenInput string
        router.GET("/form", func(c *gin.Context) {
                hiddenInput = middleware.CSRFHiddenInput(c)
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/form", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }

        if hiddenInput == "" {
                t.Fatal("CSRFHiddenInput returned empty string")
        }

        expectedPrefix := `<input type="hidden" name="csrf_token" value="`
        if len(hiddenInput) < len(expectedPrefix) {
                t.Fatalf("CSRFHiddenInput too short: %s", hiddenInput)
        }
        if hiddenInput[:len(expectedPrefix)] != expectedPrefix {
                t.Errorf("CSRFHiddenInput does not start with expected prefix.\nGot: %s", hiddenInput)
        }
        if hiddenInput[len(hiddenInput)-2:] != `">` {
                t.Errorf("CSRFHiddenInput does not end with expected suffix.\nGot: %s", hiddenInput)
        }
}

func TestCSRFHiddenInputNoToken(t *testing.T) {
        router := gin.New()

        var hiddenInput string
        router.GET("/form", func(c *gin.Context) {
                hiddenInput = middleware.CSRFHiddenInput(c)
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/form", nil)
        router.ServeHTTP(w, req)

        expected := `<input type="hidden" name="csrf_token" value="">`
        if hiddenInput != expected {
                t.Errorf("expected %q, got %q", expected, hiddenInput)
        }
}

func TestRequireAuthBlocks(t *testing.T) {
        router := gin.New()
        router.Use(middleware.RequireAuth())
        router.GET("/protected", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/protected", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusUnauthorized {
                t.Fatalf("expected 401, got %d", w.Code)
        }
}

func TestRequireAuthAllows(t *testing.T) {
        router := gin.New()
        router.Use(func(c *gin.Context) {
                c.Set("authenticated", true)
                c.Next()
        })
        router.Use(middleware.RequireAuth())
        router.GET("/protected", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/protected", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }
}

func TestRequireAdminBlocks(t *testing.T) {
        router := gin.New()
        router.Use(func(c *gin.Context) {
                c.Set("authenticated", true)
                c.Set("user_role", "user")
                c.Next()
        })
        router.Use(middleware.RequireAdmin())
        router.GET("/admin", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/admin", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusForbidden {
                t.Fatalf("expected 403, got %d", w.Code)
        }
}

func TestRequireAdminAllows(t *testing.T) {
        router := gin.New()
        router.Use(func(c *gin.Context) {
                c.Set("authenticated", true)
                c.Set("user_role", "admin")
                c.Next()
        })
        router.Use(middleware.RequireAdmin())
        router.GET("/admin", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/admin", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }
}

func TestRequireAdminNoAuth(t *testing.T) {
        router := gin.New()
        router.Use(middleware.RequireAdmin())
        router.GET("/admin", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/admin", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusUnauthorized {
                t.Fatalf("expected 401, got %d", w.Code)
        }
}

func TestRequireAdminBrowserRedirectUnauthenticated(t *testing.T) {
        router := gin.New()
        router.Use(middleware.RequireAdmin())
        router.GET("/ops/pipeline", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/ops/pipeline", nil)
        req.Header.Set("Accept", "text/html,application/xhtml+xml")
        router.ServeHTTP(w, req)

        if w.Code != http.StatusFound {
                t.Fatalf("expected 302 redirect, got %d", w.Code)
        }
        loc := w.Header().Get("Location")
        if loc != "/auth/login?next=%2Fops%2Fpipeline" {
                t.Fatalf("expected redirect to /auth/login?next=%%2Fops%%2Fpipeline, got %s", loc)
        }
}

func TestRequireAdminBrowserRedirectNonAdmin(t *testing.T) {
        router := gin.New()
        router.Use(func(c *gin.Context) {
                c.Set("authenticated", true)
                c.Set("user_role", "user")
                c.Next()
        })
        router.Use(middleware.RequireAdmin())
        router.GET("/ops/pipeline", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/ops/pipeline", nil)
        req.Header.Set("Accept", "text/html,application/xhtml+xml")
        router.ServeHTTP(w, req)

        if w.Code != http.StatusFound {
                t.Fatalf("expected 302 redirect, got %d", w.Code)
        }
        loc := w.Header().Get("Location")
        if loc != "/" {
                t.Fatalf("expected redirect to /, got %s", loc)
        }
}
