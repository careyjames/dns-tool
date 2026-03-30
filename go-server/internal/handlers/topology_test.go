package handlers

import (
	"dnstool/go-server/internal/config"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestNewTopologyHandler(t *testing.T) {
	cfg := &config.Config{}
	h := NewTopologyHandler(cfg)
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
}

func TestTopologyHandler_Topology(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
	h := NewTopologyHandler(cfg)

	w := httptest.NewRecorder()
	tmpl := mustParseMinimalTemplate("topology.html")
	router := gin.New()
	router.SetHTMLTemplate(tmpl)
	router.GET("/topology", h.Topology)
	req := httptest.NewRequest(http.MethodGet, "/topology", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestTopologyHandler_LoadSolverLayouts_NoFiles(t *testing.T) {
	h := &TopologyHandler{Config: &config.Config{}}
	h.loadSolverLayouts()
	if h.solverLayouts == nil {
		t.Error("expected non-nil solverLayouts map")
	}
}
