// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import (
        "encoding/json"
        "net/http"
        "net/http/httptest"
        "net/url"
        "strings"
        "testing"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/dbq"
        "dnstool/go-server/internal/unified"

        "github.com/gin-gonic/gin"
        "github.com/jackc/pgx/v5/pgtype"
)

func TestRemediationSubmit_AnalysisID_B6(t *testing.T) {
        gin.SetMode(gin.TestMode)
        router := gin.New()
        cfg := &config.Config{}
        h := &RemediationHandler{Config: cfg}
        router.POST("/remediation/submit", h.RemediationSubmit)

        body := strings.NewReader("analysis_id=123")
        req := httptest.NewRequest(http.MethodPost, "/remediation/submit", body)
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        w := httptest.NewRecorder()
        router.ServeHTTP(w, req)

        if w.Code != http.StatusSeeOther {
                t.Errorf("expected 303, got %d", w.Code)
        }
        loc := w.Header().Get("Location")
        if !strings.Contains(loc, "analysis_id=123") {
                t.Errorf("redirect should contain analysis_id=123, got %q", loc)
        }
}

func TestRemediationSubmit_Domain_B6(t *testing.T) {
        gin.SetMode(gin.TestMode)
        router := gin.New()
        cfg := &config.Config{}
        h := &RemediationHandler{Config: cfg}
        router.POST("/remediation/submit", h.RemediationSubmit)

        body := strings.NewReader("domain=Example.Com")
        req := httptest.NewRequest(http.MethodPost, "/remediation/submit", body)
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        w := httptest.NewRecorder()
        router.ServeHTTP(w, req)

        if w.Code != http.StatusSeeOther {
                t.Errorf("expected 303, got %d", w.Code)
        }
        loc := w.Header().Get("Location")
        if !strings.Contains(loc, "domain=example.com") {
                t.Errorf("should lowercase domain, got %q", loc)
        }
}

func TestRemediationSubmit_Empty_B6(t *testing.T) {
        gin.SetMode(gin.TestMode)
        router := gin.New()
        cfg := &config.Config{}
        h := &RemediationHandler{Config: cfg}
        router.POST("/remediation/submit", h.RemediationSubmit)

        body := strings.NewReader("")
        req := httptest.NewRequest(http.MethodPost, "/remediation/submit", body)
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        w := httptest.NewRecorder()
        router.ServeHTTP(w, req)

        if w.Code != http.StatusSeeOther {
                t.Errorf("expected 303, got %d", w.Code)
        }
        loc := w.Header().Get("Location")
        if loc != "/remediation" {
                t.Errorf("expected /remediation, got %q", loc)
        }
}

func TestBuildRemediationItems_DNSFix_B6(t *testing.T) {
        fixes := []any{
                map[string]any{
                        "title":       "Add SPF",
                        "fix":         "Create SPF record",
                        "section":     "email",
                        "dns_host":    "_spf.example.com",
                        "dns_type":    "TXT",
                        "dns_value":   "v=spf1 include:_spf.google.com ~all",
                        "dns_purpose": "Allow Google to send email",
                },
        }
        items := buildRemediationItems(fixes)
        if len(items) != 1 {
                t.Fatalf("expected 1 item, got %d", len(items))
        }
        if !items[0].HasDNS {
                t.Error("should have DNS flag")
        }
        if items[0].DNSHost != "_spf.example.com" {
                t.Errorf("wrong host: %s", items[0].DNSHost)
        }
        if items[0].CopyableRecord == "" {
                t.Error("copyable record should not be empty")
        }
}

func TestBuildRemediationItems_ManualFix_B6(t *testing.T) {
        fixes := []any{
                map[string]any{
                        "title":   "Enable 2FA",
                        "fix":     "Enable two-factor auth",
                        "section": "security",
                },
        }
        items := buildRemediationItems(fixes)
        if len(items) != 1 {
                t.Fatalf("expected 1 item, got %d", len(items))
        }
        if items[0].HasDNS {
                t.Error("should NOT have DNS flag for manual fix")
        }
}

func TestBuildRemediationItems_DNSRecordFallback_B6(t *testing.T) {
        fixes := []any{
                map[string]any{
                        "title":      "Add DKIM",
                        "dns_record": "selector._domainkey IN TXT v=DKIM1;k=rsa;p=...",
                },
        }
        items := buildRemediationItems(fixes)
        if len(items) != 1 {
                t.Fatalf("expected 1, got %d", len(items))
        }
        if !items[0].HasDNS {
                t.Error("dns_record fallback should set HasDNS")
        }
        if items[0].CopyableRecord == "" {
                t.Error("should have copyable record from dns_record")
        }
}

func TestBuildRemediationItems_InvalidEntry_B6(t *testing.T) {
        fixes := []any{42}
        items := buildRemediationItems(fixes)
        if len(items) != 0 {
                t.Errorf("int entry should be skipped, got %d items", len(items))
        }
}

func TestBuildCopyableRecord_B6(t *testing.T) {
        r := buildCopyableRecord("TXT", "example.com", "v=spf1 ~all")
        if r != "example.com  TXT  v=spf1 ~all" {
                t.Errorf("got %q", r)
        }
        if buildCopyableRecord("TXT", "example.com", "") != "" {
                t.Error("empty value should return empty")
        }
}

func TestGetStr_B6(t *testing.T) {
        m := map[string]any{"name": "test", "count": 42, "missing": nil}
        if getStr(m, "name") != "test" {
                t.Error("string value wrong")
        }
        if getStr(m, "count") != "42" {
                t.Error("non-string should use Sprintf")
        }
        if getStr(m, "nope") != "" {
                t.Error("missing key should return empty")
        }
}

func TestFormatDiffValue_B6(t *testing.T) {
        if formatDiffValue(nil) != "" {
                t.Error("nil should return empty")
        }
        if formatDiffValue("hello") != "hello" {
                t.Error("string passthrough failed")
        }
        result := formatDiffValue([]int{1, 2, 3})
        if result != "[1,2,3]" {
                t.Errorf("json marshal failed: got %q", result)
        }
}

func TestBuildDiffItems_B6(t *testing.T) {
        diffs := []SectionDiff{
                {Label: "SPF", Icon: "check", Changed: true, StatusA: "pass", StatusB: "fail",
                        DetailChanges: []DetailChange{{Field: "record", Old: "v=spf1", New: "v=spf1 ~all"}}},
                {Label: "DKIM", Icon: "check", Changed: false},
        }
        items, changes := buildDiffItems(diffs)
        if len(items) != 2 {
                t.Fatalf("expected 2 items, got %d", len(items))
        }
        if changes != 1 {
                t.Errorf("expected 1 change, got %d", changes)
        }
        if len(items[0].DetailChanges) != 1 {
                t.Error("first item should have 1 detail change")
        }
        if items[0].DetailChanges[0].OldStr != "v=spf1" {
                t.Errorf("old string wrong: %s", items[0].DetailChanges[0].OldStr)
        }
}

func TestBuildCompareAnalysis_WithDuration_B6(t *testing.T) {
        dur := 2.5
        a := dbq.DomainAnalysis{
                CreatedAt:        pgtype.Timestamp{Valid: true, Time: mustParseTime("2025-01-01T12:00:00Z")},
                FullResults:      json.RawMessage(`{"_tool_version":"v1.0"}`),
                AnalysisDuration: &dur,
        }
        ca := buildCompareAnalysis(a)
        if ca.CreatedAt == "" {
                t.Error("created_at should be formatted")
        }
        if !ca.HasToolVersion || ca.ToolVersion != "v1.0" {
                t.Errorf("tool version: has=%v ver=%s", ca.HasToolVersion, ca.ToolVersion)
        }
        if !ca.HasDuration || ca.AnalysisDuration != "2.5s" {
                t.Errorf("duration: has=%v dur=%s", ca.HasDuration, ca.AnalysisDuration)
        }
}

func TestBuildCompareAnalysis_NoDuration_B6(t *testing.T) {
        a := dbq.DomainAnalysis{}
        ca := buildCompareAnalysis(a)
        if ca.HasDuration {
                t.Error("should not have duration")
        }
        if ca.HasToolVersion {
                t.Error("should not have tool version without results")
        }
}

func TestValidateParsedURL_B6(t *testing.T) {
        https, _ := url.Parse("https://example.com/logo.svg")
        if err := validateParsedURL(https); err != nil {
                t.Errorf("https should pass: %v", err)
        }

        httpURL, _ := url.Parse("http://example.com/logo.svg")
        if err := validateParsedURL(httpURL); err == nil {
                t.Error("http should fail")
        }

        noHost, _ := url.Parse("https:///path")
        if err := validateParsedURL(noHost); err == nil {
                t.Error("empty host should fail")
        }
}

func TestFollowRedirects_NoRedirect_B6(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

        h := &ProxyHandler{}
        resp := &http.Response{StatusCode: 200, Body: http.NoBody}
        result, err := h.followRedirects(c, &http.Client{}, resp)
        if err != nil {
                t.Fatalf("unexpected error: %v", err)
        }
        if result.StatusCode != 200 {
                t.Errorf("should return same response, got %d", result.StatusCode)
        }
}

func TestFollowRedirects_NoLocation_B6(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

        h := &ProxyHandler{}
        resp := &http.Response{StatusCode: 301, Header: http.Header{}, Body: http.NoBody}
        _, err := h.followRedirects(c, &http.Client{}, resp)
        if err == nil {
                t.Error("should error on redirect without Location")
        }
}

func TestFollowRedirects_HTTPRedirect_B6(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

        h := &ProxyHandler{}
        resp := &http.Response{
                StatusCode: 302,
                Header:     http.Header{"Location": {"http://example.com/logo.svg"}},
                Body:       http.NoBody,
        }
        _, err := h.followRedirects(c, &http.Client{}, resp)
        if err == nil {
                t.Error("http redirect should be rejected by validateParsedURL")
        }
}

func TestRestoreUnifiedConfidence_B6(t *testing.T) {
        m := map[string]any{
                "level":            "high",
                "score":            0.85,
                "accuracy_factor":  0.9,
                "currency_factor":  0.8,
                "maturity_ceiling": 0.95,
                "maturity_level":   "advanced",
                "weakest_link":     "dkim",
                "weakest_detail":   "missing rotation",
                "explanation":      "test explanation",
                "protocol_count":   float64(5),
        }
        uc := restoreUnifiedConfidence(m)
        if uc.Level != "high" {
                t.Errorf("level=%s", uc.Level)
        }
        if uc.Score != 0.85 {
                t.Errorf("score=%f", uc.Score)
        }
        if uc.ProtocolCount != 5 {
                t.Errorf("protocol_count=%d", uc.ProtocolCount)
        }
        if uc.WeakestLink != "dkim" {
                t.Errorf("weakest_link=%s", uc.WeakestLink)
        }
}

func TestRestoreUnifiedConfidence_Empty_B6(t *testing.T) {
        uc := restoreUnifiedConfidence(map[string]any{})
        if uc != (unified.UnifiedConfidence{}) {
                t.Error("empty map should yield zero-value struct")
        }
}

func TestAnalysisTimestamp_B6(t *testing.T) {
        ts := analysisTimestamp(dbq.DomainAnalysis{
                CreatedAt: pgtype.Timestamp{Valid: true, Time: mustParseTime("2025-06-15T10:30:00Z")},
        })
        if ts == "" {
                t.Error("should format created_at")
        }

        updated := mustParseTime("2025-06-16T11:00:00Z")
        ts2 := analysisTimestamp(dbq.DomainAnalysis{
                CreatedAt: pgtype.Timestamp{Valid: true, Time: mustParseTime("2025-06-15T10:30:00Z")},
                UpdatedAt: pgtype.Timestamp{Valid: true, Time: updated},
        })
        if ts2 == ts {
                t.Error("should prefer updated_at when valid")
        }
}

func TestAnalysisDuration_B6(t *testing.T) {
        d := 3.14
        if analysisDuration(dbq.DomainAnalysis{AnalysisDuration: &d}) != 3.14 {
                t.Error("should return pointer value")
        }
        if analysisDuration(dbq.DomainAnalysis{}) != 0.0 {
                t.Error("nil should return 0.0")
        }
}

func TestComputeIntegrityHash_B6(t *testing.T) {
        a := dbq.DomainAnalysis{AsciiDomain: "example.com", ID: 1}
        h1 := computeIntegrityHash(a, "2025-01-01", "v1", "v2", map[string]any{})
        h2 := computeIntegrityHash(a, "2025-01-01", "", "v2", map[string]any{})
        if h1 == "" || h2 == "" {
                t.Error("hash should not be empty")
        }
        if h1 == h2 {
                t.Error("different tool version should yield different hash")
        }
}

func TestDerefString_B6(t *testing.T) {
        s := "hello"
        if derefString(&s) != "hello" {
                t.Error("should deref")
        }
        if derefString(nil) != "" {
                t.Error("nil should return empty")
        }
}

func TestConfiguredProbes_NoEnv_B6(t *testing.T) {
        h := &ProbeAdminHandler{Config: &config.Config{}}
        probes := h.configuredProbes()
        if len(probes) > 2 {
                t.Errorf("unexpected probes count: %d", len(probes))
        }
}

func TestEnrichViewDataMetrics_NilDB_B6(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        data := gin.H{}
        results := map[string]any{}
        h.enrichViewDataMetrics(nil, data, results, "example.com", 0)
}

func TestEnrichViewDataMetrics_WithSnapshot_B6(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        data := gin.H{}
        results := map[string]any{
                "_icae_snapshot": map[string]any{
                        "overall_maturity": "advanced",
                },
        }
        h.enrichViewDataMetrics(nil, data, results, "example.com", 0)
}

func TestEnrichFromSnapshot_NilDB_B6(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        data := gin.H{}
        snap := map[string]any{
                "overall_maturity": "developing",
                "unified_confidence": map[string]any{
                        "level": "medium",
                        "score": 0.6,
                },
        }
        results := map[string]any{}
        h.enrichFromSnapshot(nil, data, results, snap, "example.com", 0)

        if _, ok := data["UnifiedConfidence"]; !ok {
                t.Error("should restore UnifiedConfidence from snapshot")
        }
}

func TestDetectHistoricalDrift_EmptyHash_B6(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        drift := h.detectHistoricalDrift(nil, "", "example.com", 1, nil)
        if drift.Detected {
                t.Error("empty hash should return no drift")
        }
}

func TestBimiFetchError_Error_B6(t *testing.T) {
        e := &bimiFetchError{status: 502, msg: "test error"}
        if e.Error() != "test error" {
                t.Errorf("got %q", e.Error())
        }
}

func TestValidationError_Error_B6(t *testing.T) {
        e := &validationError{msg: "bad input"}
        if e.Error() != "bad input" {
                t.Errorf("got %q", e.Error())
        }
}

func TestNewCompareHandler_B6(t *testing.T) {
        cfg := &config.Config{AppVersion: "1.0"}
        h := NewCompareHandler(nil, cfg)
        if h == nil {
                t.Fatal("should not be nil")
        }
        if h.Config.AppVersion != "1.0" {
                t.Error("config not set")
        }
}

func TestNewEmailHeaderHandler_B6(t *testing.T) {
        cfg := &config.Config{AppVersion: "1.0"}
        h := NewEmailHeaderHandler(cfg)
        if h == nil {
                t.Fatal("should not be nil")
        }
}

func TestNewZoneHandler_B6(t *testing.T) {
        cfg := &config.Config{AppVersion: "1.0"}
        h := NewZoneHandler(nil, cfg)
        if h == nil {
                t.Fatal("should not be nil")
        }
}

func TestNewTelemetryHandler_B6(t *testing.T) {
        cfg := &config.Config{AppVersion: "1.0"}
        h := NewTelemetryHandler(nil, cfg)
        if h == nil {
                t.Fatal("should not be nil")
        }
}

func TestNewRemediationHandler_B6(t *testing.T) {
        cfg := &config.Config{AppVersion: "1.0"}
        h := NewRemediationHandler(nil, cfg)
        if h == nil {
                t.Fatal("should not be nil")
        }
}

func TestNewProbeAdminHandler_B6(t *testing.T) {
        cfg := &config.Config{AppVersion: "1.0"}
        h := NewProbeAdminHandler(nil, cfg)
        if h == nil {
                t.Fatal("should not be nil")
        }
}
