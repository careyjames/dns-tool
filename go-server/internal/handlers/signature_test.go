package handlers

import (
	"dnstool/go-server/internal/config"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestNewSignatureHandler(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0"}
	h := NewSignatureHandler(cfg)
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
}

func TestSignatureHandler_PageMode(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}, BaseURL: "https://test.com"}
	h := NewSignatureHandler(cfg)

	w := httptest.NewRecorder()
	tmpl := mustParseMinimalTemplate("signature.html")
	router := gin.New()
	router.SetHTMLTemplate(tmpl)
	router.GET("/signature", h.SignaturePage)
	req := httptest.NewRequest(http.MethodGet, "/signature", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestSignatureHandler_RawMode(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}, BaseURL: "https://test.com"}
	h := NewSignatureHandler(cfg)

	w := httptest.NewRecorder()
	tmpl := mustParseMinimalTemplate("signature_raw.html")
	router := gin.New()
	router.SetHTMLTemplate(tmpl)
	router.GET("/signature", h.SignaturePage)
	req := httptest.NewRequest(http.MethodGet, "/signature?mode=raw", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("expected CSP header for raw mode")
	}
}
