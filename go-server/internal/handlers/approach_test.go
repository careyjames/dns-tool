package handlers

import (
	"dnstool/go-server/internal/config"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestApproachHandler_Approach(t *testing.T) {
	cfg := &config.Config{
		AppVersion: "1.0.0",
		BetaPages:  map[string]bool{},
	}
	h := NewApproachHandler(cfg)

	w := httptest.NewRecorder()
	tmpl := mustParseMinimalTemplate("approach.html")
	router := gin.New()
	router.SetHTMLTemplate(tmpl)
	router.GET("/approach", h.Approach)
	req := httptest.NewRequest(http.MethodGet, "/approach", nil)
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

func TestApproachHandler_PostNotAllowed(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0.0", BetaPages: map[string]bool{}}
	h := NewApproachHandler(cfg)

	w := httptest.NewRecorder()
	tmpl := mustParseMinimalTemplate("approach.html")
	router := gin.New()
	router.SetHTMLTemplate(tmpl)
	router.GET("/approach", h.Approach)
	req := httptest.NewRequest(http.MethodPost, "/approach", nil)
	router.ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Error("POST should not return 200")
	}
}
