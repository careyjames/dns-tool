package handlers

import (
	"dnstool/go-server/internal/config"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestNewOwlSemaphoreHandler(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0"}
	h := NewOwlSemaphoreHandler(cfg)
	if h == nil {
		t.Fatal("expected non-nil")
	}
	if h.Config != cfg {
		t.Error("Config mismatch")
	}
	if h.Config.AppVersion != "1.0" {
		t.Errorf("AppVersion = %q", h.Config.AppVersion)
	}
}

func TestNewOwlSemaphoreHandler_NilConfig(t *testing.T) {
	h := NewOwlSemaphoreHandler(nil)
	if h == nil {
		t.Fatal("expected non-nil handler even with nil config")
	}
	if h.Config != nil {
		t.Error("expected nil Config")
	}
}

func TestOwlSemaphoreHandler_OwlSemaphore_HTTP(t *testing.T) {
	cfg := &config.Config{
		AppVersion:      "26.0.0",
		MaintenanceNote: "",
		BetaPages:       map[string]bool{},
	}
	h := NewOwlSemaphoreHandler(cfg)

	w := httptest.NewRecorder()
	tmpl := mustParseMinimalTemplate("owl_semaphore.html")
	router := gin.New()
	router.SetHTMLTemplate(tmpl)
	router.GET("/owl-semaphore", h.OwlSemaphore)
	req := httptest.NewRequest(http.MethodGet, "/owl-semaphore", nil)
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

func TestOwlSemaphoreHandler_OwlSemaphore_WrongMethod(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
	h := NewOwlSemaphoreHandler(cfg)

	w := httptest.NewRecorder()
	tmpl := mustParseMinimalTemplate("owl_semaphore.html")
	router := gin.New()
	router.SetHTMLTemplate(tmpl)
	router.GET("/owl-semaphore", h.OwlSemaphore)
	req := httptest.NewRequest(http.MethodPost, "/owl-semaphore", nil)
	router.ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Error("POST should not return 200")
	}
}

func TestOwlSemaphoreHandler_OwlSemaphore_CSPNonce(t *testing.T) {
	cfg := &config.Config{
		AppVersion: "1.0",
		BetaPages:  map[string]bool{},
	}
	h := NewOwlSemaphoreHandler(cfg)

	w := httptest.NewRecorder()
	tmpl := mustParseDataTemplate("owl_semaphore.html")
	router := gin.New()
	router.SetHTMLTemplate(tmpl)
	router.Use(func(c *gin.Context) {
		c.Set("csp_nonce", "nonce-abc")
		c.Next()
	})
	router.GET("/owl-semaphore", h.OwlSemaphore)
	req := httptest.NewRequest(http.MethodGet, "/owl-semaphore", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "nonce=nonce-abc") {
		t.Errorf("expected nonce in output, got %q", body)
	}
	if !strings.Contains(body, "page=owl-semaphore") {
		t.Errorf("expected ActivePage=owl-semaphore, got %q", body)
	}
}

func TestOwlSemaphoreHandler_OwlSemaphore_MergeAuth(t *testing.T) {
	cfg := &config.Config{
		AppVersion:     "1.0",
		BetaPages:      map[string]bool{},
		GoogleClientID: "gid",
	}
	h := NewOwlSemaphoreHandler(cfg)

	w := httptest.NewRecorder()
	tmpl := mustParseDataTemplate("owl_semaphore.html")
	router := gin.New()
	router.SetHTMLTemplate(tmpl)
	router.GET("/owl-semaphore", h.OwlSemaphore)
	req := httptest.NewRequest(http.MethodGet, "/owl-semaphore", nil)
	router.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "auth=yes") {
		t.Errorf("expected GoogleAuthEnabled in template data, got %q", body)
	}
}

func TestOwlSemaphoreHandler_OwlLayers_HTTP(t *testing.T) {
	cfg := &config.Config{
		AppVersion:      "26.0.0",
		MaintenanceNote: "",
		BetaPages:       map[string]bool{},
	}
	h := NewOwlSemaphoreHandler(cfg)

	w := httptest.NewRecorder()
	tmpl := mustParseMinimalTemplate("owl_layers.html")
	router := gin.New()
	router.SetHTMLTemplate(tmpl)
	router.GET("/owl-layers", h.OwlLayers)
	req := httptest.NewRequest(http.MethodGet, "/owl-layers", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "ok") {
		t.Errorf("expected rendered template, got %q", body)
	}
}

func TestOwlSemaphoreHandler_OwlLayers_WrongMethod(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
	h := NewOwlSemaphoreHandler(cfg)

	w := httptest.NewRecorder()
	tmpl := mustParseMinimalTemplate("owl_layers.html")
	router := gin.New()
	router.SetHTMLTemplate(tmpl)
	router.GET("/owl-layers", h.OwlLayers)
	req := httptest.NewRequest(http.MethodDelete, "/owl-layers", nil)
	router.ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Error("DELETE should not return 200")
	}
}

func TestOwlSemaphoreHandler_OwlLayers_CSPNonce(t *testing.T) {
	cfg := &config.Config{
		AppVersion: "1.0",
		BetaPages:  map[string]bool{},
	}
	h := NewOwlSemaphoreHandler(cfg)

	w := httptest.NewRecorder()
	tmpl := mustParseDataTemplate("owl_layers.html")
	router := gin.New()
	router.SetHTMLTemplate(tmpl)
	router.Use(func(c *gin.Context) {
		c.Set("csp_nonce", "layers-nonce-xyz")
		c.Next()
	})
	router.GET("/owl-layers", h.OwlLayers)
	req := httptest.NewRequest(http.MethodGet, "/owl-layers", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "nonce=layers-nonce-xyz") {
		t.Errorf("expected nonce in output, got %q", body)
	}
	if !strings.Contains(body, "page=owl-layers") {
		t.Errorf("expected ActivePage=owl-layers, got %q", body)
	}
}

func TestOwlSemaphoreHandler_OwlLayers_MergeAuth(t *testing.T) {
	cfg := &config.Config{
		AppVersion:     "1.0",
		BetaPages:      map[string]bool{},
		GoogleClientID: "gid",
	}
	h := NewOwlSemaphoreHandler(cfg)

	w := httptest.NewRecorder()
	tmpl := mustParseDataTemplate("owl_layers.html")
	router := gin.New()
	router.SetHTMLTemplate(tmpl)
	router.GET("/owl-layers", h.OwlLayers)
	req := httptest.NewRequest(http.MethodGet, "/owl-layers", nil)
	router.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "auth=yes") {
		t.Errorf("expected GoogleAuthEnabled in template data, got %q", body)
	}
}
