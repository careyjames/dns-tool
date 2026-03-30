package handlers

import (
	"dnstool/go-server/internal/config"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestFAQHandler_SubdomainDiscovery(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
	h := NewFAQHandler(cfg)

	w := httptest.NewRecorder()
	tmpl := mustParseMinimalTemplate("faq_subdomains.html")
	router := gin.New()
	router.SetHTMLTemplate(tmpl)
	router.GET("/faq", h.SubdomainDiscovery)
	req := httptest.NewRequest(http.MethodGet, "/faq", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "ok") {
		t.Errorf("expected template render output in body, got %q", body)
	}
}

func TestFAQHandler_WrongMethod(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
	h := NewFAQHandler(cfg)

	w := httptest.NewRecorder()
	tmpl := mustParseMinimalTemplate("faq_subdomains.html")
	router := gin.New()
	router.SetHTMLTemplate(tmpl)
	router.GET("/faq", h.SubdomainDiscovery)
	req := httptest.NewRequest(http.MethodPost, "/faq", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("POST should return 404, got %d", w.Code)
	}
}
