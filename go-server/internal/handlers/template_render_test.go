// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import (
        "context"
        "errors"
        "net/http"
        "net/http/httptest"
        "strings"
        "testing"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/dbq"

        "github.com/gin-gonic/gin"
)

func TestPipelineRealTemplate_EmptyData(t *testing.T) {
        tmpl := mustLoadRealTemplates(t)

        mock := &mockPipelineStore{
                getPipelineStageStatsFn:          func(_ context.Context) ([]dbq.GetPipelineStageStatsRow, error) { return nil, errors.New("table missing") },
                getPipelineEndToEndStatsFn:       func(_ context.Context) (dbq.GetPipelineEndToEndStatsRow, error) { return dbq.GetPipelineEndToEndStatsRow{}, errors.New("table missing") },
                getPipelineDurationDistributionFn: func(_ context.Context) ([]dbq.GetPipelineDurationDistributionRow, error) { return nil, errors.New("table missing") },
                getDriftSeverityDistributionFn:   func(_ context.Context) ([]dbq.GetDriftSeverityDistributionRow, error) { return nil, errors.New("table missing") },
                getSlowestPhasesFn:               func(_ context.Context, _ int32) ([]dbq.GetSlowestPhasesRow, error) { return nil, errors.New("table missing") },
                getTelemetryTrendsFn:             func(_ context.Context) ([]dbq.GetTelemetryTrendsRow, error) { return nil, errors.New("table missing") },
        }

        h := &PipelineHandler{
                Config:        &config.Config{AppVersion: "test", BetaPages: map[string]bool{}},
                pipelineStore: mock,
        }

        w := httptest.NewRecorder()
        c, engine := gin.CreateTestContext(w)
        engine.SetHTMLTemplate(tmpl)
        c.Request = httptest.NewRequest(http.MethodGet, "/ops/pipeline", nil)
        c.Set("csp_nonce", "test-nonce")
        c.Set("csrf_token", "test-csrf")
        c.Set("authenticated", true)
        c.Set("user_role", "admin")

        func() {
                defer func() {
                        if r := recover(); r != nil {
                                t.Fatalf("Pipeline template PANICKED with empty data: %v", r)
                        }
                }()
                h.Observatory(c)
        }()

        if errs := c.Errors; len(errs) > 0 {
                for _, e := range errs {
                        t.Errorf("Gin error: %v", e)
                }
        }

        var buf strings.Builder
        err := tmpl.ExecuteTemplate(&buf, "admin_pipeline.html", gin.H{
                "Title":             "Pipeline Observatory",
                "ActivePage":        "pipeline",
                "AppVersion":        "test",
                "MaintenanceNote":   "",
                "BetaPages":         map[string]bool{},
                "CspNonce":          "test",
                "CsrfToken":         "test",
                "Stages":            []pipelineStageView{},
                "EndToEnd":          dbq.GetPipelineEndToEndStatsRow{},
                "Distribution":      []dbq.GetPipelineDurationDistributionRow(nil),
                "DriftDistribution": []dbq.GetDriftSeverityDistributionRow(nil),
                "Slowest":           []dbq.GetSlowestPhasesRow(nil),
                "Trends":            []dbq.GetTelemetryTrendsRow(nil),
                "PhaseGroupLabels":  map[string]string{},
                "PhaseGroupOrder":   []string{},
                "IsAuthenticated":   true,
                "IsAdmin":           true,
        })
        if err != nil {
                t.Fatalf("Direct template execution FAILED: %v", err)
        }
        t.Logf("Direct template render: %d bytes", buf.Len())

        if w.Code != http.StatusOK {
                t.Errorf("expected 200, got %d", w.Code)
        }

        body := w.Body.String()
        t.Logf("Response body length: %d bytes", len(body))

        if len(body) < 500 {
                t.Errorf("Response too short (%d bytes), likely rendering failure. Body: %s", len(body), body)
        }
        if !strings.Contains(body, "Pipeline Observatory") {
                t.Error("Response missing 'Pipeline Observatory' heading")
        }
        if !strings.Contains(body, "</html>") {
                t.Error("Response truncated — missing closing </html>")
        }
        if strings.Contains(body, "Not Found") {
                t.Error("Response contains 'Not Found' text — template rendering is broken")
        }
        if strings.Contains(body, "No pipeline stage data yet") {
                t.Log("OK: shows empty-state message for stages")
        }
}

func TestPipelineRealTemplate_WithData(t *testing.T) {
        tmpl := mustLoadRealTemplates(t)

        mock := &mockPipelineStore{
                getPipelineStageStatsFn: func(_ context.Context) ([]dbq.GetPipelineStageStatsRow, error) {
                        return []dbq.GetPipelineStageStatsRow{
                                {PhaseGroup: "dns_basic", ScanCount: 100, AvgMs: 50, P50Ms: 45, P95Ms: 90, P99Ms: 120, MinMs: int64(10), MaxMs: int64(200), TotalRecords: 500, ErrorCount: 3},
                                {PhaseGroup: "email_auth", ScanCount: 100, AvgMs: 80, P50Ms: 70, P95Ms: 150, P99Ms: 200, MinMs: int64(20), MaxMs: int64(300), TotalRecords: 400, ErrorCount: 8},
                        }, nil
                },
                getPipelineEndToEndStatsFn: func(_ context.Context) (dbq.GetPipelineEndToEndStatsRow, error) {
                        return dbq.GetPipelineEndToEndStatsRow{TotalScans: 100, AvgTotalMs: 5200, P50TotalMs: 4800, P95TotalMs: 9000, P99TotalMs: 12000}, nil
                },
                getPipelineDurationDistributionFn: func(_ context.Context) ([]dbq.GetPipelineDurationDistributionRow, error) {
                        return []dbq.GetPipelineDurationDistributionRow{
                                {Bucket: "0-5s", Count: 20},
                                {Bucket: "5-10s", Count: 50},
                        }, nil
                },
                getSlowestPhasesFn: func(_ context.Context, _ int32) ([]dbq.GetSlowestPhasesRow, error) {
                        return []dbq.GetSlowestPhasesRow{
                                {PhaseGroup: "dns_basic", PhaseTask: "resolve_A", AvgMs: 100, P50Ms: 90, P95Ms: 200, P99Ms: 300, SampleCount: 50},
                        }, nil
                },
        }

        h := &PipelineHandler{
                Config:        &config.Config{AppVersion: "test", BetaPages: map[string]bool{}},
                pipelineStore: mock,
        }

        w := httptest.NewRecorder()
        c, engine := gin.CreateTestContext(w)
        engine.SetHTMLTemplate(tmpl)
        c.Request = httptest.NewRequest(http.MethodGet, "/ops/pipeline", nil)
        c.Set("csp_nonce", "test-nonce")
        c.Set("csrf_token", "test-csrf")
        c.Set("authenticated", true)
        c.Set("user_role", "admin")

        func() {
                defer func() {
                        if r := recover(); r != nil {
                                t.Fatalf("Pipeline template PANICKED with real data: %v", r)
                        }
                }()
                h.Observatory(c)
        }()

        if w.Code != http.StatusOK {
                t.Errorf("expected 200, got %d", w.Code)
        }

        body := w.Body.String()
        if !strings.Contains(body, "Pipeline Observatory") {
                t.Error("Response missing 'Pipeline Observatory'")
        }
        if !strings.Contains(body, "</html>") {
                t.Error("Response truncated")
        }
        if !strings.Contains(body, "100") {
                t.Error("Total scans count not rendered")
        }
        if !strings.Contains(body, "dns_basic") {
                t.Error("Stage key 'dns_basic' not rendered")
        }
}
