package handlers

import (
	"dnstool/go-server/internal/config"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestROEHandler_ROE(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
	h := NewROEHandler(cfg)

	w := httptest.NewRecorder()
	tmpl := mustParseMinimalTemplate("roe.html")
	router := gin.New()
	router.SetHTMLTemplate(tmpl)
	router.GET("/roe", h.ROE)
	req := httptest.NewRequest(http.MethodGet, "/roe", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "ok") {
		t.Errorf("expected rendered template in body, got %q", body)
	}
}

func TestROEHandler_WrongMethod(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
	h := NewROEHandler(cfg)

	w := httptest.NewRecorder()
	tmpl := mustParseMinimalTemplate("roe.html")
	router := gin.New()
	router.SetHTMLTemplate(tmpl)
	router.GET("/roe", h.ROE)
	req := httptest.NewRequest(http.MethodDelete, "/roe", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("DELETE should return 404, got %d", w.Code)
	}
}
