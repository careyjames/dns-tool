package handlers

import (
	"dnstool/go-server/internal/config"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSecurityPolicyHandler_SecurityPolicy(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
	h := NewSecurityPolicyHandler(cfg)

	w := httptest.NewRecorder()
	tmpl := mustParseMinimalTemplate("security_policy.html")
	router := gin.New()
	router.SetHTMLTemplate(tmpl)
	router.GET("/security-policy", h.SecurityPolicy)
	req := httptest.NewRequest(http.MethodGet, "/security-policy", nil)
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

func TestSecurityPolicyHandler_PostNotAllowed(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
	h := NewSecurityPolicyHandler(cfg)

	w := httptest.NewRecorder()
	tmpl := mustParseMinimalTemplate("security_policy.html")
	router := gin.New()
	router.SetHTMLTemplate(tmpl)
	router.GET("/security-policy", h.SecurityPolicy)
	req := httptest.NewRequest(http.MethodPost, "/security-policy", nil)
	router.ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Error("POST should not return 200")
	}
}
