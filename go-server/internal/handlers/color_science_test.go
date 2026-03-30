package handlers

import (
	"dnstool/go-server/internal/config"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestColorScienceHandler_ColorScience(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
	h := NewColorScienceHandler(cfg)

	w := httptest.NewRecorder()
	tmpl := mustParseMinimalTemplate("color_science.html")
	router := gin.New()
	router.SetHTMLTemplate(tmpl)
	router.GET("/color-science", h.ColorScience)
	req := httptest.NewRequest(http.MethodGet, "/color-science", nil)
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

func TestColorScienceHandler_DeleteNotAllowed(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
	h := NewColorScienceHandler(cfg)

	w := httptest.NewRecorder()
	tmpl := mustParseMinimalTemplate("color_science.html")
	router := gin.New()
	router.SetHTMLTemplate(tmpl)
	router.GET("/color-science", h.ColorScience)
	req := httptest.NewRequest(http.MethodDelete, "/color-science", nil)
	router.ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Error("DELETE should not return 200")
	}
}
