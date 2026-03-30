package handlers

import (
	"dnstool/go-server/internal/config"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestNewCommunicationStandardsHandler(t *testing.T) {
	cfg := &config.Config{}
	h := NewCommunicationStandardsHandler(cfg)
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
	if h.Config != cfg {
		t.Error("handler should store provided config")
	}
}

func TestCommunicationStandardsHandler_Render(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
	h := NewCommunicationStandardsHandler(cfg)

	w := httptest.NewRecorder()
	tmpl := mustParseMinimalTemplate("communication_standards.html")
	router := gin.New()
	router.SetHTMLTemplate(tmpl)
	router.GET("/communication-standards", h.CommunicationStandards)
	req := httptest.NewRequest(http.MethodGet, "/communication-standards", nil)
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

func TestCommunicationStandardsHandler_DeleteNotAllowed(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
	h := NewCommunicationStandardsHandler(cfg)

	w := httptest.NewRecorder()
	tmpl := mustParseMinimalTemplate("communication_standards.html")
	router := gin.New()
	router.SetHTMLTemplate(tmpl)
	router.GET("/communication-standards", h.CommunicationStandards)
	req := httptest.NewRequest(http.MethodDelete, "/communication-standards", nil)
	router.ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Error("DELETE should not return 200")
	}
}
