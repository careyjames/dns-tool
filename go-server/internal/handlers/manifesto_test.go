package handlers

import (
	"dnstool/go-server/internal/config"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestNewManifestoHandler(t *testing.T) {
	cfg := &config.Config{}
	h := NewManifestoHandler(cfg)
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
	if h.Config != cfg {
		t.Error("handler should store provided config")
	}
}

func TestManifestoHandler_Manifesto(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
	h := NewManifestoHandler(cfg)

	w := httptest.NewRecorder()
	tmpl := mustParseMinimalTemplate("manifesto.html")
	router := gin.New()
	router.SetHTMLTemplate(tmpl)
	router.GET("/manifesto", h.Manifesto)
	req := httptest.NewRequest(http.MethodGet, "/manifesto", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !strings.Contains(w.Body.String(), "ok") {
		t.Error("expected rendered template body")
	}
	if !strings.Contains(w.Header().Get("Content-Type"), "text/html") {
		t.Errorf("Content-Type = %q, want text/html", w.Header().Get("Content-Type"))
	}
}

func TestManifestoHandler_PostNotAllowed(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
	h := NewManifestoHandler(cfg)

	w := httptest.NewRecorder()
	tmpl := mustParseMinimalTemplate("manifesto.html")
	router := gin.New()
	router.SetHTMLTemplate(tmpl)
	router.GET("/manifesto", h.Manifesto)
	req := httptest.NewRequest(http.MethodPost, "/manifesto", nil)
	router.ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Error("POST should not return 200")
	}
}
