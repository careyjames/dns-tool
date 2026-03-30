package handlers

import (
	"dnstool/go-server/internal/config"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestAboutHandler_About_SetsCorrectData(t *testing.T) {
	cfg := &config.Config{
		AppVersion:      "26.0.0",
		MaintenanceNote: "test note",
		BetaPages:       map[string]bool{"beta": true},
	}
	h := NewAboutHandler(cfg)
	if h == nil {
		t.Fatal("expected non-nil handler")
	}

	w := httptest.NewRecorder()
	tmpl := mustParseMinimalTemplate("about.html")
	router := gin.New()
	router.SetHTMLTemplate(tmpl)
	router.GET("/about", h.About)
	req := httptest.NewRequest(http.MethodGet, "/about", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "ok") {
		t.Errorf("expected rendered template in body, got %q", body)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
}

func TestAboutHandler_NilConfig(t *testing.T) {
	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		h := NewAboutHandler(nil)
		if h == nil {
			t.Fatal("expected non-nil handler")
		}
	}()
	if panicked {
		t.Error("NewAboutHandler should not panic with nil config")
	}
}

func TestAboutHandler_WrongMethod(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
	h := NewAboutHandler(cfg)

	w := httptest.NewRecorder()
	tmpl := mustParseMinimalTemplate("about.html")
	router := gin.New()
	router.SetHTMLTemplate(tmpl)
	router.GET("/about", h.About)
	req := httptest.NewRequest(http.MethodPut, "/about", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("PUT should return 404, got %d", w.Code)
	}
}
