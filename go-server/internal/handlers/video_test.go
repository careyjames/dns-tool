package handlers

import (
	"dnstool/go-server/internal/config"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestNewVideoHandler(t *testing.T) {
	cfg := &config.Config{}
	h := NewVideoHandler(cfg)
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
	if h.Config != cfg {
		t.Error("handler should store provided config")
	}
}

func TestVideoHandler_ForgottenDomain(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
	h := NewVideoHandler(cfg)

	w := httptest.NewRecorder()
	tmpl := mustParseMinimalTemplate("video_forgotten_domain.html")
	router := gin.New()
	router.SetHTMLTemplate(tmpl)
	router.GET("/video", h.ForgottenDomain)
	req := httptest.NewRequest(http.MethodGet, "/video", nil)
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

func TestVideoHandler_PostNotAllowed(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
	h := NewVideoHandler(cfg)

	w := httptest.NewRecorder()
	tmpl := mustParseMinimalTemplate("video_forgotten_domain.html")
	router := gin.New()
	router.SetHTMLTemplate(tmpl)
	router.GET("/video", h.ForgottenDomain)
	req := httptest.NewRequest(http.MethodPost, "/video", nil)
	router.ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Error("POST should not return 200")
	}
}
