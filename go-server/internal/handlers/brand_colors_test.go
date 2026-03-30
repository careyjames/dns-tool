package handlers

import (
	"dnstool/go-server/internal/config"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestBrandColorsHandler_BrandColors(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
	h := NewBrandColorsHandler(cfg)

	w := httptest.NewRecorder()
	tmpl := mustParseMinimalTemplate("brand_colors.html")
	router := gin.New()
	router.SetHTMLTemplate(tmpl)
	router.GET("/brand-colors", h.BrandColors)
	req := httptest.NewRequest(http.MethodGet, "/brand-colors", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestGetStatusColors_NotEmpty(t *testing.T) {
	colors := getStatusColors()
	if len(colors) == 0 {
		t.Fatal("expected non-empty status colors")
	}
}

func TestGetSurfaceColors_NotEmpty(t *testing.T) {
	colors := getSurfaceColors()
	if len(colors) == 0 {
		t.Fatal("expected non-empty surface colors")
	}
}

func TestGetTLPColors_NotEmpty(t *testing.T) {
	colors := getTLPColors()
	if len(colors) == 0 {
		t.Fatal("expected non-empty TLP colors")
	}
}

func TestGetCVSSColors_NotEmpty(t *testing.T) {
	colors := getCVSSColors()
	if len(colors) == 0 {
		t.Fatal("expected non-empty CVSS colors")
	}
}
