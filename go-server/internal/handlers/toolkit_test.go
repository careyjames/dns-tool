package handlers

import (
	"dnstool/go-server/internal/config"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestToolkitHandler_ToolkitPage(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
	h := NewToolkitHandler(cfg)

	w := httptest.NewRecorder()
	tmpl := mustParseMinimalTemplate("toolkit.html")
	router := gin.New()
	router.SetHTMLTemplate(tmpl)
	router.GET("/toolkit", h.ToolkitPage)
	req := httptest.NewRequest(http.MethodGet, "/toolkit", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestToolkitHandler_ResolveProbeConfig_NoProbes(t *testing.T) {
	h := &ToolkitHandler{Config: &config.Config{}}
	_, ok := h.resolveProbeConfig("test")
	if ok {
		t.Error("expected ok = false with no probes configured")
	}
}

func TestToolkitHandler_ResolveProbeConfig_WithFallback(t *testing.T) {
	h := &ToolkitHandler{Config: &config.Config{
		ProbeAPIURL: "https://probe.example.com",
		ProbeAPIKey: "test-key",
	}}
	pc, ok := h.resolveProbeConfig("test")
	if !ok {
		t.Fatal("expected ok = true with fallback config")
	}
	if pc.label != "Default" {
		t.Errorf("label = %q, want 'Default'", pc.label)
	}
}

func TestToolkitHandler_ResolveProbeConfig_WithProbes(t *testing.T) {
	h := &ToolkitHandler{Config: &config.Config{
		Probes: []config.ProbeEndpoint{
			{ID: "us-west", URL: "https://us-west.probe.com", Key: "k1", Label: "US West"},
			{ID: "eu-central", URL: "https://eu.probe.com", Key: "k2", Label: "EU Central"},
		},
	}}
	pc, ok := h.resolveProbeConfig("eu-central")
	if !ok {
		t.Fatal("expected ok = true")
	}
	if pc.label != "EU Central" {
		t.Errorf("label = %q, want 'EU Central'", pc.label)
	}
}

func TestToolkitHandler_ResolveProbeConfig_DefaultsToFirst(t *testing.T) {
	h := &ToolkitHandler{Config: &config.Config{
		Probes: []config.ProbeEndpoint{
			{ID: "us-west", URL: "https://us-west.probe.com", Key: "k1", Label: "US West"},
		},
	}}
	pc, ok := h.resolveProbeConfig("nonexistent")
	if !ok {
		t.Fatal("expected ok = true")
	}
	if pc.label != "US West" {
		t.Errorf("label = %q, want 'US West'", pc.label)
	}
}

func TestToolkitConstants(t *testing.T) {
	if mapKeyToolkit != "toolkit" {
		t.Errorf("mapKeyToolkit = %q", mapKeyToolkit)
	}
	if tplToolkit != "toolkit.html" {
		t.Errorf("tplToolkit = %q", tplToolkit)
	}
}
