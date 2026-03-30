package handlers

import (
        "net/http"
        "net/http/httptest"
        "testing"
        "time"

        "dnstool/go-server/internal/analyzer"
        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/telemetry"

        "github.com/gin-gonic/gin"
)

func TestComputeOverallHealth_AllHealthy_B12(t *testing.T) {
        stats := []telemetry.ProviderStats{
                {Name: "p1", State: telemetry.Healthy},
                {Name: "p2", State: telemetry.Healthy},
        }
        got := computeOverallHealth(stats)
        if got != "healthy" {
                t.Fatalf("expected healthy, got %s", got)
        }
}

func TestComputeOverallHealth_OneDegraded_B12(t *testing.T) {
        stats := []telemetry.ProviderStats{
                {Name: "p1", State: telemetry.Healthy},
                {Name: "p2", State: telemetry.Degraded},
        }
        got := computeOverallHealth(stats)
        if got != "degraded" {
                t.Fatalf("expected degraded, got %s", got)
        }
}

func TestComputeOverallHealth_OneUnhealthy_B12(t *testing.T) {
        stats := []telemetry.ProviderStats{
                {Name: "p1", State: telemetry.Healthy},
                {Name: "p2", State: telemetry.Unhealthy},
        }
        got := computeOverallHealth(stats)
        if got != "unhealthy" {
                t.Fatalf("expected unhealthy, got %s", got)
        }
}

func TestComputeOverallHealth_Empty_B12(t *testing.T) {
        got := computeOverallHealth(nil)
        if got != "healthy" {
                t.Fatalf("expected healthy for empty, got %s", got)
        }
}

func TestBuildProviderEntries_Basic_B12(t *testing.T) {
        now := time.Now()
        stats := []telemetry.ProviderStats{
                {
                        Name:            "TestProvider",
                        State:           telemetry.Healthy,
                        TotalRequests:   100,
                        SuccessCount:    95,
                        FailureCount:    5,
                        ConsecFailures:  0,
                        AvgLatencyMs:    50.0,
                        P95LatencyMs:    120.0,
                        InCooldown:      false,
                        LastError:       "timeout",
                        LastErrorTime:   &now,
                        LastSuccessTime: &now,
                },
        }
        entries := buildProviderEntries(stats)
        if len(entries) != 1 {
                t.Fatalf("expected 1 entry, got %d", len(entries))
        }
        e := entries[0]
        if e["name"] != "TestProvider" {
                t.Fatalf("expected TestProvider, got %v", e["name"])
        }
        if e["total_requests"] != int64(100) {
                t.Fatalf("expected 100, got %v", e["total_requests"])
        }
        if e["last_error"] != "timeout" {
                t.Fatalf("expected timeout, got %v", e["last_error"])
        }
}

func TestBuildProviderEntries_NoErrors_B12(t *testing.T) {
        stats := []telemetry.ProviderStats{
                {Name: "Clean", State: telemetry.Healthy},
        }
        entries := buildProviderEntries(stats)
        if _, ok := entries[0]["last_error"]; ok {
                t.Fatal("expected no last_error field")
        }
}

func TestBuildProviderEntries_Empty_B12(t *testing.T) {
        entries := buildProviderEntries(nil)
        if len(entries) != 0 {
                t.Fatalf("expected 0 entries, got %d", len(entries))
        }
}

func TestBuildCacheEntries_B12(t *testing.T) {
        a := analyzer.New(analyzer.WithInitialIANAFetch(false))
        entries := buildCacheEntries(a)
        if len(entries) == 0 {
                t.Fatal("expected at least 1 cache entry")
        }
        found := false
        for _, e := range entries {
                if e["name"] == "dns_query" {
                        found = true
                }
        }
        if !found {
                t.Fatal("expected dns_query cache entry")
        }
}

func TestHealthz_B12(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/healthz", nil)

        h := &HealthHandler{StartTime: time.Now()}
        h.Healthz(c)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }
}

func TestCapacity_NilAnalyzer_B12(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/capacity", nil)

        h := &HealthHandler{StartTime: time.Now(), Analyzer: nil}
        h.Capacity(c)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }
}

func TestCapacity_WithAnalyzer_B12(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/capacity", nil)

        a := analyzer.New(analyzer.WithInitialIANAFetch(false))
        h := &HealthHandler{StartTime: time.Now(), Analyzer: a}
        h.Capacity(c)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }
}

func TestGetStr_Present_B12(t *testing.T) {
        m := map[string]any{"key": "value"}
        if got := getStr(m, "key"); got != "value" {
                t.Fatalf("expected value, got %s", got)
        }
}

func TestGetStr_Missing_B12(t *testing.T) {
        m := map[string]any{}
        if got := getStr(m, "key"); got != "" {
                t.Fatalf("expected empty, got %s", got)
        }
}

func TestGetStr_NonString_B12(t *testing.T) {
        m := map[string]any{"key": 42}
        got := getStr(m, "key")
        if got != "42" {
                t.Fatalf("expected 42, got %s", got)
        }
}

func TestBuildCopyableRecord_Basic_B12(t *testing.T) {
        got := buildCopyableRecord("TXT", "example.com", "v=spf1 ~all")
        if got != "example.com  TXT  v=spf1 ~all" {
                t.Fatalf("unexpected: %s", got)
        }
}

func TestBuildCopyableRecord_EmptyValue_B12(t *testing.T) {
        got := buildCopyableRecord("TXT", "example.com", "")
        if got != "" {
                t.Fatalf("expected empty for empty value, got %s", got)
        }
}

func TestNewHealthHandler_B12(t *testing.T) {
        h := NewHealthHandler(nil, nil)
        if h == nil {
                t.Fatal("expected non-nil handler")
        }
        if h.StartTime.IsZero() {
                t.Fatal("expected non-zero start time")
        }
}

func TestNewApproachHandler_B12(t *testing.T) {
        h := NewApproachHandler(&config.Config{AppVersion: "test"})
        if h == nil || h.Config.AppVersion != "test" {
                t.Fatal("expected valid handler")
        }
}

func TestNewArchitectureHandler_B12(t *testing.T) {
        h := NewArchitectureHandler(&config.Config{AppVersion: "test"})
        if h == nil {
                t.Fatal("expected non-nil handler")
        }
}

func TestNewChangelogHandler_B12(t *testing.T) {
        h := NewChangelogHandler(&config.Config{AppVersion: "test"})
        if h == nil {
                t.Fatal("expected non-nil handler")
        }
}

func TestNewColorScienceHandler_B12(t *testing.T) {
        h := NewColorScienceHandler(&config.Config{AppVersion: "test"})
        if h == nil {
                t.Fatal("expected non-nil handler")
        }
}

func TestNewFAQHandler_B12(t *testing.T) {
        h := NewFAQHandler(&config.Config{AppVersion: "test"})
        if h == nil {
                t.Fatal("expected non-nil handler")
        }
}

func TestNewROEHandler_B12(t *testing.T) {
        h := NewROEHandler(&config.Config{AppVersion: "test"})
        if h == nil {
                t.Fatal("expected non-nil handler")
        }
}

func TestNewSecurityPolicyHandler_B12(t *testing.T) {
        h := NewSecurityPolicyHandler(&config.Config{AppVersion: "test"})
        if h == nil {
                t.Fatal("expected non-nil handler")
        }
}

func TestNewSignatureHandler_B12(t *testing.T) {
        h := NewSignatureHandler(&config.Config{AppVersion: "test"})
        if h == nil {
                t.Fatal("expected non-nil handler")
        }
}

func TestNewVideoHandler_B12(t *testing.T) {
        h := NewVideoHandler(&config.Config{AppVersion: "test"})
        if h == nil {
                t.Fatal("expected non-nil handler")
        }
}

func TestNewHomeHandler_B12(t *testing.T) {
        h := NewHomeHandler(&config.Config{AppVersion: "test"}, nil)
        if h == nil {
                t.Fatal("expected non-nil handler")
        }
}

func TestNewConfidenceHandler_B12(t *testing.T) {
        h := NewConfidenceHandler(&config.Config{AppVersion: "test"}, nil)
        if h == nil {
                t.Fatal("expected non-nil handler")
        }
}

func TestConfidenceHandler_AuditQ_Nil_B12(t *testing.T) {
        h := &ConfidenceHandler{Config: &config.Config{}}
        if h.auditQ() != nil {
                t.Fatal("expected nil for no DB and no auditStore")
        }
}

func TestNewRemediationHandler_B12(t *testing.T) {
        h := NewRemediationHandler(nil, &config.Config{AppVersion: "test"})
        if h == nil {
                t.Fatal("expected non-nil handler")
        }
}

func TestNewCitationHandler_B12(t *testing.T) {
        h := NewCitationHandler(&config.Config{AppVersion: "test"}, nil, nil)
        if h == nil {
                t.Fatal("expected non-nil handler")
        }
}

func TestNewTelemetryHandler_B12(t *testing.T) {
        h := NewTelemetryHandler(nil, &config.Config{AppVersion: "test"})
        if h == nil {
                t.Fatal("expected non-nil handler")
        }
}

func TestCitationHandler_Store_Nil_B12(t *testing.T) {
        h := &CitationHandler{Config: &config.Config{}}
        if h.store() != nil {
                t.Fatal("expected nil store for nil DB")
        }
}

func TestExtractAnalysisError_Success_B12(t *testing.T) {
        results := map[string]any{"analysis_success": true}
        success, errMsg := extractAnalysisError(results)
        if !success || errMsg != nil {
                t.Fatalf("expected success=true, errMsg nil, got %v %v", success, errMsg)
        }
}

func TestExtractAnalysisError_Failure_B12(t *testing.T) {
        results := map[string]any{"error": "something broke"}
        success, errMsg := extractAnalysisError(results)
        if success {
                t.Fatal("expected success=false")
        }
        if errMsg == nil || *errMsg != "something broke" {
                t.Fatalf("expected errMsg=something broke, got %v", errMsg)
        }
}

func TestExtractAnalysisError_EmptyError_B12(t *testing.T) {
        results := map[string]any{"error": ""}
        success, errMsg := extractAnalysisError(results)
        if !success {
                t.Fatal("expected success=true for empty error")
        }
        if errMsg != nil {
                t.Fatal("expected nil errMsg for empty error")
        }
}

func TestNormalizeVerdicts_CallsAll_B12(t *testing.T) {
        results := map[string]interface{}{
                "ai_surface": map[string]interface{}{
                        "llms_txt": map[string]interface{}{"found": true},
                },
        }
        posture := map[string]interface{}{
                "verdicts": map[string]interface{}{
                        "dns_tampering": map[string]interface{}{
                                "label": "Exposed",
                        },
                },
        }
        normalizeVerdicts(results, posture)
        v := posture["verdicts"].(map[string]interface{})
        if v["dns_tampering"] == nil {
                t.Fatal("expected dns_tampering normalized")
        }
}

func TestNormalizeVerdicts_NoVerdicts_B12(t *testing.T) {
        results := map[string]interface{}{}
        posture := map[string]interface{}{}
        normalizeVerdicts(results, posture)
}
