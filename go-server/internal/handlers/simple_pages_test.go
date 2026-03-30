package handlers

import (
        "dnstool/go-server/internal/config"
        "html/template"
        "net/http"
        "net/http/httptest"
        "strings"
        "testing"

        "github.com/gin-gonic/gin"
)

func mustParseDataTemplate(name string) *template.Template {
        tmplStr := `{{define "` + name + `"}}nonce={{.CspNonce}}|ver={{.AppVersion}}|page={{.ActivePage}}|auth={{if .GoogleAuthEnabled}}yes{{else}}no{{end}}{{end}}`
        return template.Must(template.New(name).Parse(tmplStr))
}

func TestNewContactHandler(t *testing.T) {
        cfg := &config.Config{AppVersion: "1.0", MaintenanceNote: "Beta"}
        h := NewContactHandler(cfg)
        if h == nil {
                t.Fatal("expected non-nil")
        }
        if h.Config != cfg {
                t.Error("Config mismatch")
        }
        if h.Config.AppVersion != "1.0" {
                t.Errorf("AppVersion = %q", h.Config.AppVersion)
        }
        if h.Config.MaintenanceNote != "Beta" {
                t.Errorf("MaintenanceNote = %q", h.Config.MaintenanceNote)
        }
}

func TestNewCorpusHandler(t *testing.T) {
        cfg := &config.Config{AppVersion: "2.0"}
        h := NewCorpusHandler(cfg)
        if h == nil {
                t.Fatal("expected non-nil")
        }
        if h.Config != cfg {
                t.Error("Config mismatch")
        }
}

func TestNewPrivacyHandler(t *testing.T) {
        cfg := &config.Config{AppVersion: "3.0"}
        h := NewPrivacyHandler(cfg)
        if h == nil {
                t.Fatal("expected non-nil")
        }
        if h.Config != cfg {
                t.Error("Config mismatch")
        }
}

func TestNewReferenceLibraryHandler(t *testing.T) {
        cfg := &config.Config{AppVersion: "4.0"}
        h := NewReferenceLibraryHandler(cfg)
        if h == nil {
                t.Fatal("expected non-nil")
        }
        if h.Config != cfg {
                t.Error("Config mismatch")
        }
}

func TestNewContactHandler_NilConfig(t *testing.T) {
        h := NewContactHandler(nil)
        if h == nil {
                t.Fatal("expected non-nil")
        }
}

func TestNewCorpusHandler_NilConfig(t *testing.T) {
        h := NewCorpusHandler(nil)
        if h == nil {
                t.Fatal("expected non-nil")
        }
}

func TestNewPrivacyHandler_NilConfig(t *testing.T) {
        h := NewPrivacyHandler(nil)
        if h == nil {
                t.Fatal("expected non-nil")
        }
}

func TestNewReferenceLibraryHandler_NilConfig(t *testing.T) {
        h := NewReferenceLibraryHandler(nil)
        if h == nil {
                t.Fatal("expected non-nil")
        }
}

func TestContactHandler_Contact_HTTP(t *testing.T) {
        cfg := &config.Config{
                AppVersion:      "26.0.0",
                MaintenanceNote: "test",
                BetaPages:       map[string]bool{},
        }
        h := NewContactHandler(cfg)

        w := httptest.NewRecorder()
        tmpl := mustParseMinimalTemplate("contact.html")
        router := gin.New()
        router.SetHTMLTemplate(tmpl)
        router.GET("/contact", h.Contact)
        req := httptest.NewRequest(http.MethodGet, "/contact", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
        }
        body := w.Body.String()
        if !strings.Contains(body, "ok") {
                t.Errorf("expected rendered template, got %q", body)
        }
        ct := w.Header().Get("Content-Type")
        if !strings.Contains(ct, "text/html") {
                t.Errorf("Content-Type = %q, want text/html", ct)
        }
}

func TestContactHandler_Contact_WrongMethod(t *testing.T) {
        cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
        h := NewContactHandler(cfg)

        w := httptest.NewRecorder()
        tmpl := mustParseMinimalTemplate("contact.html")
        router := gin.New()
        router.SetHTMLTemplate(tmpl)
        router.GET("/contact", h.Contact)
        req := httptest.NewRequest(http.MethodPost, "/contact", nil)
        router.ServeHTTP(w, req)

        if w.Code == http.StatusOK {
                t.Error("POST should not return 200")
        }
}

func TestContactHandler_Contact_CSPNonceAndActivePage(t *testing.T) {
        cfg := &config.Config{
                AppVersion: "1.0",
                BetaPages:  map[string]bool{},
        }
        h := NewContactHandler(cfg)

        w := httptest.NewRecorder()
        tmpl := mustParseDataTemplate("contact.html")
        router := gin.New()
        router.SetHTMLTemplate(tmpl)
        router.Use(func(c *gin.Context) {
                c.Set("csp_nonce", "test-nonce-123")
                c.Next()
        })
        router.GET("/contact", h.Contact)
        req := httptest.NewRequest(http.MethodGet, "/contact", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("status = %d", w.Code)
        }
        body := w.Body.String()
        if !strings.Contains(body, "nonce=test-nonce-123") {
                t.Errorf("expected nonce in output, got %q", body)
        }
        if !strings.Contains(body, "page=contact") {
                t.Errorf("expected ActivePage=contact, got %q", body)
        }
        if !strings.Contains(body, "ver=1.0") {
                t.Errorf("expected AppVersion=1.0, got %q", body)
        }
}

func TestContactHandler_Contact_MergeAuthData(t *testing.T) {
        cfg := &config.Config{
                AppVersion:     "1.0",
                BetaPages:      map[string]bool{},
                GoogleClientID: "test-google-id",
        }
        h := NewContactHandler(cfg)

        w := httptest.NewRecorder()
        tmpl := mustParseDataTemplate("contact.html")
        router := gin.New()
        router.SetHTMLTemplate(tmpl)
        router.GET("/contact", h.Contact)
        req := httptest.NewRequest(http.MethodGet, "/contact", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("status = %d", w.Code)
        }
        body := w.Body.String()
        if !strings.Contains(body, "auth=yes") {
                t.Errorf("expected GoogleAuthEnabled=true in template data, got %q", body)
        }
}

func TestContactHandler_Contact_NoAuthWhenNoGoogleID(t *testing.T) {
        cfg := &config.Config{
                AppVersion: "1.0",
                BetaPages:  map[string]bool{},
        }
        h := NewContactHandler(cfg)

        w := httptest.NewRecorder()
        tmpl := mustParseDataTemplate("contact.html")
        router := gin.New()
        router.SetHTMLTemplate(tmpl)
        router.GET("/contact", h.Contact)
        req := httptest.NewRequest(http.MethodGet, "/contact", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("status = %d", w.Code)
        }
        body := w.Body.String()
        if !strings.Contains(body, "auth=no") {
                t.Errorf("expected GoogleAuthEnabled=false, got %q", body)
        }
}

func TestCorpusHandler_Corpus_HTTP(t *testing.T) {
        cfg := &config.Config{
                AppVersion:      "26.0.0",
                MaintenanceNote: "",
                BetaPages:       map[string]bool{},
        }
        h := NewCorpusHandler(cfg)

        w := httptest.NewRecorder()
        tmpl := mustParseMinimalTemplate("corpus.html")
        router := gin.New()
        router.SetHTMLTemplate(tmpl)
        router.GET("/corpus", h.Corpus)
        req := httptest.NewRequest(http.MethodGet, "/corpus", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
        }
        body := w.Body.String()
        if !strings.Contains(body, "ok") {
                t.Errorf("expected rendered template, got %q", body)
        }
}

func TestCorpusHandler_Corpus_WrongMethod(t *testing.T) {
        cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
        h := NewCorpusHandler(cfg)

        w := httptest.NewRecorder()
        tmpl := mustParseMinimalTemplate("corpus.html")
        router := gin.New()
        router.SetHTMLTemplate(tmpl)
        router.GET("/corpus", h.Corpus)
        req := httptest.NewRequest(http.MethodDelete, "/corpus", nil)
        router.ServeHTTP(w, req)

        if w.Code == http.StatusOK {
                t.Error("DELETE should not return 200")
        }
}

func TestCorpusHandler_Corpus_CSPNonceAndActivePage(t *testing.T) {
        cfg := &config.Config{
                AppVersion: "2.0",
                BetaPages:  map[string]bool{},
        }
        h := NewCorpusHandler(cfg)

        w := httptest.NewRecorder()
        tmpl := mustParseDataTemplate("corpus.html")
        router := gin.New()
        router.SetHTMLTemplate(tmpl)
        router.Use(func(c *gin.Context) {
                c.Set("csp_nonce", "corpus-nonce-456")
                c.Next()
        })
        router.GET("/corpus", h.Corpus)
        req := httptest.NewRequest(http.MethodGet, "/corpus", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("status = %d", w.Code)
        }
        body := w.Body.String()
        if !strings.Contains(body, "nonce=corpus-nonce-456") {
                t.Errorf("expected nonce in output, got %q", body)
        }
        if !strings.Contains(body, "page=corpus") {
                t.Errorf("expected ActivePage=corpus, got %q", body)
        }
}

func TestCorpusHandler_Corpus_MergeAuthData(t *testing.T) {
        cfg := &config.Config{
                AppVersion:     "2.0",
                BetaPages:      map[string]bool{},
                GoogleClientID: "google-id",
        }
        h := NewCorpusHandler(cfg)

        w := httptest.NewRecorder()
        tmpl := mustParseDataTemplate("corpus.html")
        router := gin.New()
        router.SetHTMLTemplate(tmpl)
        router.GET("/corpus", h.Corpus)
        req := httptest.NewRequest(http.MethodGet, "/corpus", nil)
        router.ServeHTTP(w, req)

        body := w.Body.String()
        if !strings.Contains(body, "auth=yes") {
                t.Errorf("expected GoogleAuthEnabled in template data, got %q", body)
        }
}

func TestPrivacyHandler_Privacy_HTTP(t *testing.T) {
        cfg := &config.Config{
                AppVersion:      "26.0.0",
                MaintenanceNote: "",
                BetaPages:       map[string]bool{},
        }
        h := NewPrivacyHandler(cfg)

        w := httptest.NewRecorder()
        tmpl := mustParseMinimalTemplate("privacy.html")
        router := gin.New()
        router.SetHTMLTemplate(tmpl)
        router.GET("/privacy", h.Privacy)
        req := httptest.NewRequest(http.MethodGet, "/privacy", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
        }
        body := w.Body.String()
        if !strings.Contains(body, "ok") {
                t.Errorf("expected rendered template, got %q", body)
        }
}

func TestPrivacyHandler_Privacy_WrongMethod(t *testing.T) {
        cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
        h := NewPrivacyHandler(cfg)

        w := httptest.NewRecorder()
        tmpl := mustParseMinimalTemplate("privacy.html")
        router := gin.New()
        router.SetHTMLTemplate(tmpl)
        router.GET("/privacy", h.Privacy)
        req := httptest.NewRequest(http.MethodPut, "/privacy", nil)
        router.ServeHTTP(w, req)

        if w.Code == http.StatusOK {
                t.Error("PUT should not return 200")
        }
}

func TestPrivacyHandler_Privacy_CSPNonceAndActivePage(t *testing.T) {
        cfg := &config.Config{
                AppVersion: "3.0",
                BetaPages:  map[string]bool{},
        }
        h := NewPrivacyHandler(cfg)

        w := httptest.NewRecorder()
        tmpl := mustParseDataTemplate("privacy.html")
        router := gin.New()
        router.SetHTMLTemplate(tmpl)
        router.Use(func(c *gin.Context) {
                c.Set("csp_nonce", "priv-nonce-789")
                c.Next()
        })
        router.GET("/privacy", h.Privacy)
        req := httptest.NewRequest(http.MethodGet, "/privacy", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("status = %d", w.Code)
        }
        body := w.Body.String()
        if !strings.Contains(body, "nonce=priv-nonce-789") {
                t.Errorf("expected nonce in output, got %q", body)
        }
        if !strings.Contains(body, "page=privacy") {
                t.Errorf("expected ActivePage=privacy, got %q", body)
        }
}

func TestPrivacyHandler_Privacy_MergeAuthData(t *testing.T) {
        cfg := &config.Config{
                AppVersion:     "3.0",
                BetaPages:      map[string]bool{},
                GoogleClientID: "google-id",
        }
        h := NewPrivacyHandler(cfg)

        w := httptest.NewRecorder()
        tmpl := mustParseDataTemplate("privacy.html")
        router := gin.New()
        router.SetHTMLTemplate(tmpl)
        router.GET("/privacy", h.Privacy)
        req := httptest.NewRequest(http.MethodGet, "/privacy", nil)
        router.ServeHTTP(w, req)

        body := w.Body.String()
        if !strings.Contains(body, "auth=yes") {
                t.Errorf("expected GoogleAuthEnabled in template data, got %q", body)
        }
}

func TestReferenceLibraryHandler_ReferenceLibrary_HTTP(t *testing.T) {
        cfg := &config.Config{
                AppVersion:      "26.0.0",
                MaintenanceNote: "",
                BetaPages:       map[string]bool{},
        }
        h := NewReferenceLibraryHandler(cfg)

        w := httptest.NewRecorder()
        tmpl := mustParseMinimalTemplate("reference_library.html")
        router := gin.New()
        router.SetHTMLTemplate(tmpl)
        router.GET("/reference-library", h.ReferenceLibrary)
        req := httptest.NewRequest(http.MethodGet, "/reference-library", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
        }
        body := w.Body.String()
        if !strings.Contains(body, "ok") {
                t.Errorf("expected rendered template, got %q", body)
        }
}

func TestReferenceLibraryHandler_ReferenceLibrary_WrongMethod(t *testing.T) {
        cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
        h := NewReferenceLibraryHandler(cfg)

        w := httptest.NewRecorder()
        tmpl := mustParseMinimalTemplate("reference_library.html")
        router := gin.New()
        router.SetHTMLTemplate(tmpl)
        router.GET("/reference-library", h.ReferenceLibrary)
        req := httptest.NewRequest(http.MethodPatch, "/reference-library", nil)
        router.ServeHTTP(w, req)

        if w.Code == http.StatusOK {
                t.Error("PATCH should not return 200")
        }
}

func TestReferenceLibraryHandler_CSPNonceAndActivePage(t *testing.T) {
        cfg := &config.Config{
                AppVersion: "4.0",
                BetaPages:  map[string]bool{},
        }
        h := NewReferenceLibraryHandler(cfg)

        w := httptest.NewRecorder()
        tmpl := mustParseDataTemplate("reference_library.html")
        router := gin.New()
        router.SetHTMLTemplate(tmpl)
        router.Use(func(c *gin.Context) {
                c.Set("csp_nonce", "ref-nonce-abc")
                c.Next()
        })
        router.GET("/reference-library", h.ReferenceLibrary)
        req := httptest.NewRequest(http.MethodGet, "/reference-library", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("status = %d", w.Code)
        }
        body := w.Body.String()
        if !strings.Contains(body, "nonce=ref-nonce-abc") {
                t.Errorf("expected nonce in output, got %q", body)
        }
        if !strings.Contains(body, "page=reference") {
                t.Errorf("expected ActivePage containing 'reference', got %q", body)
        }
}

func TestReferenceLibraryHandler_MergeAuthData(t *testing.T) {
        cfg := &config.Config{
                AppVersion:     "4.0",
                BetaPages:      map[string]bool{},
                GoogleClientID: "google-id",
        }
        h := NewReferenceLibraryHandler(cfg)

        w := httptest.NewRecorder()
        tmpl := mustParseDataTemplate("reference_library.html")
        router := gin.New()
        router.SetHTMLTemplate(tmpl)
        router.GET("/reference-library", h.ReferenceLibrary)
        req := httptest.NewRequest(http.MethodGet, "/reference-library", nil)
        router.ServeHTTP(w, req)

        body := w.Body.String()
        if !strings.Contains(body, "auth=yes") {
                t.Errorf("expected GoogleAuthEnabled in template data, got %q", body)
        }
}

func TestContactHandler_NoNonceWithoutMiddleware(t *testing.T) {
        cfg := &config.Config{
                AppVersion: "1.0",
                BetaPages:  map[string]bool{},
        }
        h := NewContactHandler(cfg)

        w := httptest.NewRecorder()
        tmpl := mustParseDataTemplate("contact.html")
        router := gin.New()
        router.SetHTMLTemplate(tmpl)
        router.GET("/contact", h.Contact)
        req := httptest.NewRequest(http.MethodGet, "/contact", nil)
        router.ServeHTTP(w, req)

        body := w.Body.String()
        if !strings.Contains(body, "nonce=<nil>") && !strings.Contains(body, "nonce=") {
                t.Errorf("expected empty/nil nonce without middleware, got %q", body)
        }
}
