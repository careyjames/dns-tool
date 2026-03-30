package handlers

import (
	"dnstool/go-server/internal/config"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestChangelogHandler_RendersOK(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
	h := NewChangelogHandler(cfg)

	w := httptest.NewRecorder()
	tmpl := mustParseMinimalTemplate("changelog.html")
	router := gin.New()
	router.SetHTMLTemplate(tmpl)
	router.GET("/changelog", h.Changelog)
	req := httptest.NewRequest(http.MethodGet, "/changelog", nil)
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

func TestChangelogHandler_PostNotAllowed(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
	h := NewChangelogHandler(cfg)

	w := httptest.NewRecorder()
	tmpl := mustParseMinimalTemplate("changelog.html")
	router := gin.New()
	router.SetHTMLTemplate(tmpl)
	router.GET("/changelog", h.Changelog)
	req := httptest.NewRequest(http.MethodPost, "/changelog", nil)
	router.ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Error("POST should not return 200")
	}
}
