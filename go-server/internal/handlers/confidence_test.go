package handlers

import (
        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/icae"
        "net/http"
        "net/http/httptest"
        "strings"
        "testing"
        "time"

        "github.com/gin-gonic/gin"
)

func TestConfidenceHandler_NilDB(t *testing.T) {
        cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
        h := NewConfidenceHandler(cfg, nil)

        w := httptest.NewRecorder()
        tmpl := mustParseMinimalTemplate("confidence.html")
        router := gin.New()
        router.SetHTMLTemplate(tmpl)
        router.GET("/confidence", h.Confidence)
        req := httptest.NewRequest(http.MethodGet, "/confidence", nil)
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

func TestConfidenceHandler_AuditQ_NilDBAndStore(t *testing.T) {
        h := &ConfidenceHandler{Config: &config.Config{}}
        if h.auditQ() != nil {
                t.Error("auditQ should return nil when both DB and auditStore are nil")
        }
}

func TestConfidenceStateHash_Deterministic(t *testing.T) {
        ts := time.Date(2026, 3, 28, 12, 0, 0, 0, time.UTC)
        data := gin.H{
                keyAppVersion: "26.40.12",
                "ICAEMetrics": &icae.ReportMetrics{
                        TotalPasses:      500,
                        CollectionPasses: 300,
                        TotalRuns:        800,
                        EvaluatedCount:   9,
                        TotalProtocols:   9,
                        OverallMaturity:  "verified",
                        PassRate:         "95",
                        DaysRunning:      45,
                        Regressions:      nil,
                },
        }

        h1 := confidenceStateHash(data, ts)
        h2 := confidenceStateHash(data, ts)
        if h1 != h2 {
                t.Errorf("same inputs produced different hashes: %s vs %s", h1, h2)
        }
        if len(h1) != 64 {
                t.Errorf("hash length = %d, want 64 hex chars", len(h1))
        }

        h3 := confidenceStateHash(data, ts.Add(time.Second))
        if h1 == h3 {
                t.Error("different timestamps should produce different hashes")
        }

        data["ICAEMetrics"].(*icae.ReportMetrics).TotalPasses = 501
        h4 := confidenceStateHash(data, ts)
        if h1 == h4 {
                t.Error("different metrics should produce different hashes")
        }
}

func TestConfidenceStateHash_NilMetrics(t *testing.T) {
        ts := time.Date(2026, 3, 28, 12, 0, 0, 0, time.UTC)
        data := gin.H{keyAppVersion: "1.0"}
        h := confidenceStateHash(data, ts)
        if len(h) != 64 {
                t.Errorf("hash length = %d, want 64", len(h))
        }
}

func TestConfidenceHandler_PostNotAllowed(t *testing.T) {
        cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
        h := NewConfidenceHandler(cfg, nil)

        w := httptest.NewRecorder()
        tmpl := mustParseMinimalTemplate("confidence.html")
        router := gin.New()
        router.SetHTMLTemplate(tmpl)
        router.GET("/confidence", h.Confidence)
        req := httptest.NewRequest(http.MethodPost, "/confidence", nil)
        router.ServeHTTP(w, req)

        if w.Code == http.StatusOK {
                t.Error("POST should not return 200")
        }
}
