package handlers

import (
        "context"
        "errors"
        "net/http"
        "net/http/httptest"
        "testing"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/dbq"

        "github.com/gin-gonic/gin"
)

type mockPipelineStore struct {
        getPipelineStageStatsFn          func(ctx context.Context) ([]dbq.GetPipelineStageStatsRow, error)
        getPipelineEndToEndStatsFn       func(ctx context.Context) (dbq.GetPipelineEndToEndStatsRow, error)
        getPipelineDurationDistributionFn func(ctx context.Context) ([]dbq.GetPipelineDurationDistributionRow, error)
        getDriftSeverityDistributionFn   func(ctx context.Context) ([]dbq.GetDriftSeverityDistributionRow, error)
        getSlowestPhasesFn               func(ctx context.Context, limit int32) ([]dbq.GetSlowestPhasesRow, error)
        getTelemetryTrendsFn             func(ctx context.Context) ([]dbq.GetTelemetryTrendsRow, error)
}

func (m *mockPipelineStore) GetPipelineStageStats(ctx context.Context) ([]dbq.GetPipelineStageStatsRow, error) {
        if m.getPipelineStageStatsFn != nil {
                return m.getPipelineStageStatsFn(ctx)
        }
        return nil, nil
}

func (m *mockPipelineStore) GetPipelineEndToEndStats(ctx context.Context) (dbq.GetPipelineEndToEndStatsRow, error) {
        if m.getPipelineEndToEndStatsFn != nil {
                return m.getPipelineEndToEndStatsFn(ctx)
        }
        return dbq.GetPipelineEndToEndStatsRow{}, nil
}

func (m *mockPipelineStore) GetPipelineDurationDistribution(ctx context.Context) ([]dbq.GetPipelineDurationDistributionRow, error) {
        if m.getPipelineDurationDistributionFn != nil {
                return m.getPipelineDurationDistributionFn(ctx)
        }
        return nil, nil
}

func (m *mockPipelineStore) GetDriftSeverityDistribution(ctx context.Context) ([]dbq.GetDriftSeverityDistributionRow, error) {
        if m.getDriftSeverityDistributionFn != nil {
                return m.getDriftSeverityDistributionFn(ctx)
        }
        return nil, nil
}

func (m *mockPipelineStore) GetSlowestPhases(ctx context.Context, limit int32) ([]dbq.GetSlowestPhasesRow, error) {
        if m.getSlowestPhasesFn != nil {
                return m.getSlowestPhasesFn(ctx, limit)
        }
        return nil, nil
}

func (m *mockPipelineStore) GetTelemetryTrends(ctx context.Context) ([]dbq.GetTelemetryTrendsRow, error) {
        if m.getTelemetryTrendsFn != nil {
                return m.getTelemetryTrendsFn(ctx)
        }
        return nil, nil
}

func TestObservatory_AllDBErrors(t *testing.T) {
        dbErr := errors.New("db unavailable")
        mock := &mockPipelineStore{
                getPipelineStageStatsFn:          func(ctx context.Context) ([]dbq.GetPipelineStageStatsRow, error) { return nil, dbErr },
                getPipelineEndToEndStatsFn:       func(ctx context.Context) (dbq.GetPipelineEndToEndStatsRow, error) { return dbq.GetPipelineEndToEndStatsRow{}, dbErr },
                getPipelineDurationDistributionFn: func(ctx context.Context) ([]dbq.GetPipelineDurationDistributionRow, error) { return nil, dbErr },
                getDriftSeverityDistributionFn:   func(ctx context.Context) ([]dbq.GetDriftSeverityDistributionRow, error) { return nil, dbErr },
                getSlowestPhasesFn:               func(ctx context.Context, limit int32) ([]dbq.GetSlowestPhasesRow, error) { return nil, dbErr },
                getTelemetryTrendsFn:             func(ctx context.Context) ([]dbq.GetTelemetryTrendsRow, error) { return nil, dbErr },
        }

        h := &PipelineHandler{
                Config:        &config.Config{},
                pipelineStore: mock,
        }

        w := httptest.NewRecorder()
        c, engine := gin.CreateTestContext(w)
        engine.SetHTMLTemplate(mustParseMinimalTemplate("admin_pipeline.html"))
        c.Request = httptest.NewRequest(http.MethodGet, "/admin/pipeline", nil)

        func() {
                defer func() {
                        if r := recover(); r != nil {
                                t.Fatalf("Observatory panicked: %v", r)
                        }
                }()
                h.Observatory(c)
        }()

        if w.Code != http.StatusOK {
                t.Errorf("expected 200 OK with graceful fallback, got %d", w.Code)
        }
}

func TestObservatory_WithData(t *testing.T) {
        mock := &mockPipelineStore{
                getPipelineStageStatsFn: func(ctx context.Context) ([]dbq.GetPipelineStageStatsRow, error) {
                        return []dbq.GetPipelineStageStatsRow{
                                {PhaseGroup: "dns_basic", ScanCount: 100, AvgMs: 50, P50Ms: 45, P95Ms: 90, P99Ms: 120, MinMs: int64(10), MaxMs: int64(200), TotalRecords: 500, ErrorCount: 3},
                                {PhaseGroup: "email_auth", ScanCount: 100, AvgMs: 80, P50Ms: 70, P95Ms: 150, P99Ms: 200, MinMs: int64(20), MaxMs: int64(300), TotalRecords: 400, ErrorCount: 8},
                                {PhaseGroup: "tls_dane", ScanCount: 50, AvgMs: 120, P50Ms: 100, P95Ms: 250, P99Ms: 350, MinMs: int64(30), MaxMs: int64(500), TotalRecords: 200, ErrorCount: 15},
                        }, nil
                },
                getPipelineEndToEndStatsFn: func(ctx context.Context) (dbq.GetPipelineEndToEndStatsRow, error) {
                        return dbq.GetPipelineEndToEndStatsRow{TotalScans: 100, AvgTotalMs: 500}, nil
                },
        }

        h := &PipelineHandler{
                Config:        &config.Config{},
                pipelineStore: mock,
        }

        w := httptest.NewRecorder()
        c, engine := gin.CreateTestContext(w)
        engine.SetHTMLTemplate(mustParseMinimalTemplate("admin_pipeline.html"))
        c.Request = httptest.NewRequest(http.MethodGet, "/admin/pipeline", nil)

        h.Observatory(c)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }
}

func TestObservatory_NavDataPresent(t *testing.T) {
        mock := &mockPipelineStore{}
        betaPages := map[string]bool{"ttl-tuner": true}
        h := &PipelineHandler{
                Config:        &config.Config{AppVersion: "1.0.0", MaintenanceNote: "Test", BetaPages: betaPages},
                pipelineStore: mock,
        }

        w := httptest.NewRecorder()
        c, engine := gin.CreateTestContext(w)
        engine.SetHTMLTemplate(mustParseMinimalTemplate("admin_pipeline.html"))
        c.Request = httptest.NewRequest(http.MethodGet, "/admin/pipeline", nil)

        func() {
                defer func() {
                        if r := recover(); r != nil {
                                t.Fatalf("Observatory panicked with nav data — BetaPages/AppVersion/MaintenanceNote not wired: %v", r)
                        }
                }()
                h.Observatory(c)
        }()

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }

        body := w.Body.String()
        if body == "" {
                t.Fatal("response body is empty — template rendering failed (likely missing nav data)")
        }
}

func TestPipelineStageView_HealthClassification(t *testing.T) {
        tests := []struct {
                name       string
                scanCount  int64
                errorCount int32
                wantHealth string
        }{
                {"success - low errors", 100, 3, "success"},
                {"warning - 6% errors", 100, 6, "warning"},
                {"danger - 11% errors", 100, 11, "danger"},
                {"success - zero scans", 0, 0, "success"},
                {"danger - boundary 10.1%", 1000, 101, "danger"},
                {"warning - boundary 5.1%", 1000, 51, "warning"},
                {"success - boundary 5.0%", 100, 5, "success"},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        var errorRate float64
                        if tt.scanCount > 0 {
                                errorRate = float64(tt.errorCount) / float64(tt.scanCount) * 100
                        }
                        health := "success"
                        if errorRate > 10 {
                                health = "danger"
                        } else if errorRate > 5 {
                                health = "warning"
                        }
                        if health != tt.wantHealth {
                                t.Errorf("health = %q, want %q (errorRate=%.2f%%)", health, tt.wantHealth, errorRate)
                        }
                })
        }
}

func TestToInt64_TypeMatrix(t *testing.T) {
        tests := []struct {
                name string
                val  interface{}
                want int64
        }{
                {"int32", int32(42), 42},
                {"int64", int64(999), 999},
                {"int", int(123), 123},
                {"float64", float64(3.14), 3},
                {"string returns 0", "hello", 0},
                {"nil returns 0", nil, 0},
                {"bool returns 0", true, 0},
                {"negative int32", int32(-10), -10},
                {"zero float64", float64(0), 0},
                {"large int64", int64(9223372036854775807), 9223372036854775807},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := toInt64(tt.val)
                        if got != tt.want {
                                t.Errorf("toInt64(%v) = %d, want %d", tt.val, got, tt.want)
                        }
                })
        }
}
