package handlers

import (
        "context"
        "encoding/json"
        "html/template"
        "net/http"
        "net/http/httptest"
        "testing"
        "time"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/dbq"
        "dnstool/go-server/internal/icae"
        "dnstool/go-server/internal/icuae"

        "github.com/gin-gonic/gin"
        "github.com/jackc/pgx/v5/pgtype"
)

func b8tmpl(name, body string) *template.Template {
        return template.Must(template.New(name).Parse("{{define \"" + name + "\"}}" + body + "{{end}}"))
}

func TestRenderIndexFlash_B8(t *testing.T) {
        gin.SetMode(gin.TestMode)
        h := &AnalysisHandler{Config: &config.Config{AppVersion: "v1", BetaPages: map[string]bool{}}}
        w := httptest.NewRecorder()
        c, engine := gin.CreateTestContext(w)
        engine.SetHTMLTemplate(b8tmpl("index.html", `{{range .FlashMessages}}{{.Category}}:{{.Message}}{{end}}`))
        c.Request = httptest.NewRequest("GET", "/", nil)
        h.renderIndexFlash(c, "nonce-x", "csrf-x", "danger", "Invalid domain")
        if w.Code != http.StatusOK {
                t.Errorf("renderIndexFlash status = %d, want 200", w.Code)
        }
        body := w.Body.String()
        if body == "" {
                t.Error("expected non-empty response body")
        }
}

func TestDriftBaseData_B8(t *testing.T) {
        gin.SetMode(gin.TestMode)
        cfg := &config.Config{AppVersion: "v-test", BetaPages: map[string]bool{}}
        h := &DriftHandler{Config: cfg}

        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/drift?domain=example.com", nil)
        c.Set("csp_nonce", "nonce-val")
        c.Set("csrf_token", "csrf-val")

        data := h.driftBaseData(c, "example.com")
        if data["AppVersion"] != "v-test" {
                t.Error("expected AppVersion")
        }
        if data["CspNonce"] != "nonce-val" {
                t.Error("expected nonce")
        }
        if data["Domain"] != "example.com" {
                t.Error("expected domain in data")
        }
}

func TestDriftBaseData_NoDomain_B8(t *testing.T) {
        gin.SetMode(gin.TestMode)
        cfg := &config.Config{AppVersion: "v1", BetaPages: map[string]bool{}}
        h := &DriftHandler{Config: cfg}

        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/drift", nil)
        c.Set("csp_nonce", "n")
        c.Set("csrf_token", "t")

        data := h.driftBaseData(c, "")
        if _, ok := data["Domain"]; ok {
                t.Error("empty domain should not be in data")
        }
}

func TestParsePageParam_B8(t *testing.T) {
        tests := []struct {
                query string
                want  int
        }{
                {"", 1},
                {"page=1", 1},
                {"page=5", 5},
                {"page=0", 1},
                {"page=-1", 1},
                {"page=abc", 1},
                {"page=100", 100},
        }
        for _, tt := range tests {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest("GET", "/?"+tt.query, nil)
                got := parsePageParam(c)
                if got != tt.want {
                        t.Errorf("parsePageParam(%q) = %d, want %d", tt.query, got, tt.want)
                }
        }
}

func TestEDEHandler_B8(t *testing.T) {
        gin.SetMode(gin.TestMode)
        cfg := &config.Config{AppVersion: "v-ede", BetaPages: map[string]bool{}}
        h := NewEDEHandler(&db.Database{}, cfg)
        if h == nil {
                t.Fatal("expected non-nil handler")
        }

        w := httptest.NewRecorder()
        c, engine := gin.CreateTestContext(w)
        engine.SetHTMLTemplate(b8tmpl("ede.html", `<html>{{.AppVersion}}</html>`))
        c.Request = httptest.NewRequest("GET", "/ede", nil)
        c.Set("csp_nonce", "n")
        h.EDE(c)
        if w.Code != http.StatusOK {
                t.Errorf("EDE status = %d, want 200", w.Code)
        }
        if w.Body.String() == "" {
                t.Error("expected non-empty body")
        }
}

func TestEmailHeaderPage_B8(t *testing.T) {
        gin.SetMode(gin.TestMode)
        cfg := &config.Config{AppVersion: "v-email", BetaPages: map[string]bool{}}
        h := NewEmailHeaderHandler(cfg)

        w := httptest.NewRecorder()
        c, engine := gin.CreateTestContext(w)
        engine.SetHTMLTemplate(b8tmpl("email_header.html", `<html>{{.AppVersion}}</html>`))
        c.Request = httptest.NewRequest("GET", "/email-header", nil)
        c.Set("csp_nonce", "n")
        c.Set("csrf_token", "t")
        h.EmailHeaderPage(c)
        if w.Code != http.StatusOK {
                t.Errorf("EmailHeaderPage status = %d, want 200", w.Code)
        }
}

func TestBuildSelectAnalysisItem_B8(t *testing.T) {
        spf := "pass"
        dmarc := "fail"
        dkim := "warning"
        dur := 1.5
        a := dbq.DomainAnalysis{
                ID:               42,
                Domain:           "example.com",
                AsciiDomain:      "example.com",
                SpfStatus:        &spf,
                DmarcStatus:      &dmarc,
                DkimStatus:       &dkim,
                AnalysisDuration: &dur,
                CreatedAt:        pgtype.Timestamp{Time: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC), Valid: true},
                FullResults:      json.RawMessage(`{"_tool_version": "v26.1"}`),
        }
        item := buildSelectAnalysisItem(a)
        if item.ID != 42 {
                t.Errorf("ID = %d, want 42", item.ID)
        }
        if item.SpfStatus != "pass" {
                t.Errorf("SpfStatus = %q", item.SpfStatus)
        }
        if item.DmarcStatus != "fail" {
                t.Errorf("DmarcStatus = %q", item.DmarcStatus)
        }
        if item.DkimStatus != "warning" {
                t.Errorf("DkimStatus = %q", item.DkimStatus)
        }
        if item.AnalysisDuration != 1.5 {
                t.Errorf("AnalysisDuration = %f", item.AnalysisDuration)
        }
        if item.ToolVersion != "v26.1" {
                t.Errorf("ToolVersion = %q", item.ToolVersion)
        }
        if item.CreatedAt == "" {
                t.Error("expected non-empty CreatedAt")
        }
}

func TestBuildSelectAnalysisItem_NilFields_B8(t *testing.T) {
        a := dbq.DomainAnalysis{ID: 1, Domain: "test.org"}
        item := buildSelectAnalysisItem(a)
        if item.SpfStatus != "" || item.DmarcStatus != "" || item.DkimStatus != "" {
                t.Error("nil status pointers should yield empty strings")
        }
        if item.AnalysisDuration != 0 {
                t.Error("nil duration should yield 0")
        }
        if item.ToolVersion != "" {
                t.Error("empty results should yield empty tool version")
        }
}

func TestRenderCompareError_B8(t *testing.T) {
        gin.SetMode(gin.TestMode)
        cfg := &config.Config{AppVersion: "v1", BetaPages: map[string]bool{}}
        h := &CompareHandler{Config: cfg}

        w := httptest.NewRecorder()
        c, engine := gin.CreateTestContext(w)
        engine.SetHTMLTemplate(b8tmpl("compare.html", `{{range .FlashMessages}}{{.Message}}{{end}}`))
        c.Request = httptest.NewRequest("GET", "/compare", nil)

        renderCompareError(c, compareErrorParams{
                handler:    h,
                nonce:      "n",
                csrfToken:  "t",
                tmpl:       "compare.html",
                statusCode: http.StatusBadRequest,
                message:    "Bad request",
                domain:     "example.com",
        })
        if w.Code != http.StatusBadRequest {
                t.Errorf("status = %d, want 400", w.Code)
        }
}

func TestRenderCompareError_NoDomain_B8(t *testing.T) {
        gin.SetMode(gin.TestMode)
        cfg := &config.Config{AppVersion: "v1", BetaPages: map[string]bool{}}
        h := &CompareHandler{Config: cfg}

        w := httptest.NewRecorder()
        c, engine := gin.CreateTestContext(w)
        engine.SetHTMLTemplate(b8tmpl("compare.html", `ok`))
        c.Request = httptest.NewRequest("GET", "/compare", nil)

        renderCompareError(c, compareErrorParams{
                handler:    h,
                nonce:      "n",
                csrfToken:  "t",
                tmpl:       "compare.html",
                statusCode: http.StatusBadRequest,
                message:    "Missing domain",
        })
        if w.Code != http.StatusBadRequest {
                t.Errorf("status = %d, want 400", w.Code)
        }
}

func TestApplyConfidenceEngines_WithReport_B8(t *testing.T) {
        h := &AnalysisHandler{
                Config:      &config.Config{},
                DimCharts:   icuae.NewDimensionCharts(),
                Calibration: icae.NewCalibrationEngine(),
        }
        results := map[string]any{
                "currency_report": icuae.CurrencyReport{
                        OverallScore: 0.75,
                        Dimensions: []icuae.DimensionScore{
                                {Dimension: "completeness", Score: 0.8},
                                {Dimension: "consistency", Score: 0.7},
                        },
                },
                "spf_analysis":    map[string]any{"status": "pass"},
                "dkim_analysis":   map[string]any{"status": "warning"},
                "dmarc_analysis":  map[string]any{"status": "pass"},
                "dnssec_analysis": map[string]any{"status": "secure"},
        }
        h.applyConfidenceEngines(results)
        if _, ok := results["calibrated_confidence"]; !ok {
                t.Error("expected calibrated_confidence to be set")
        }
        if _, ok := results["ewma_drift"]; !ok {
                t.Error("expected ewma_drift to be set")
        }
}

func TestComputeCalibratedConfidence_B8(t *testing.T) {
        h := &AnalysisHandler{
                Calibration: icae.NewCalibrationEngine(),
        }
        results := map[string]any{
                "spf_analysis":   map[string]any{"status": "pass"},
                "dkim_analysis":  map[string]any{"status": "fail"},
                "dmarc_analysis": map[string]any{"status": "warning"},
        }
        cr := icuae.CurrencyReport{OverallScore: 0.7}
        calibrated := h.computeCalibratedConfidence(results, cr)
        if len(calibrated) == 0 {
                t.Error("expected non-empty calibrated map")
        }
}

func TestSnapshotICAEMetrics_WithCalibratedConfidence_B8(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        results := map[string]any{
                "calibrated_confidence": map[string]float64{
                        "spf": 0.95, "dkim": 0.85, "dmarc": 0.9,
                },
                "currency_report": icuae.CurrencyReport{OverallScore: 0.8},
        }
        h.snapshotICAEMetrics(context.Background(), results)
        if _, ok := results["_icae_snapshot"]; !ok {
                t.Error("expected _icae_snapshot to be set")
        }
}

func TestEnrichResultsNoHistory_B8(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        results := map[string]any{
                "remediation": map[string]any{
                        "spf": map[string]any{"recommendation": "Add SPF record"},
                },
        }
        h.enrichResultsNoHistory(nil, "example.com", results)
        if _, ok := results["rfc_metadata"]; !ok {
                t.Error("expected rfc_metadata to be set")
        }
}

func TestEnrichResultsNoHistory_NoRemediation_B8(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        results := map[string]any{}
        h.enrichResultsNoHistory(nil, "example.com", results)
        if _, ok := results["rfc_metadata"]; !ok {
                t.Error("expected rfc_metadata even without remediation")
        }
}

func TestNewDriftHandler_B8(t *testing.T) {
        h := NewDriftHandler(nil, &config.Config{AppVersion: "1.0"})
        if h == nil {
                t.Fatal("expected non-nil handler")
        }
        if h.Config.AppVersion != "1.0" {
                t.Error("config not set")
        }
}

func TestNewAboutHandler_B8(t *testing.T) {
        h := NewAboutHandler(&config.Config{AppVersion: "2.0"})
        if h == nil || h.Config.AppVersion != "2.0" {
                t.Error("constructor failed")
        }
}

func TestAboutHandler_B8(t *testing.T) {
        gin.SetMode(gin.TestMode)
        h := NewAboutHandler(&config.Config{AppVersion: "v-about", BetaPages: map[string]bool{}})
        w := httptest.NewRecorder()
        c, engine := gin.CreateTestContext(w)
        engine.SetHTMLTemplate(b8tmpl("about.html", `<html>{{.AppVersion}}</html>`))
        c.Request = httptest.NewRequest("GET", "/about", nil)
        c.Set("csp_nonce", "n")
        h.About(c)
        if w.Code != http.StatusOK {
                t.Errorf("About status = %d, want 200", w.Code)
        }
}

func TestShortHash_B8(t *testing.T) {
        long := "abcdef1234567890abcdef"
        if got := shortHash(long); len(got) != 16 {
                t.Errorf("shortHash long = %q, want 16 chars", got)
        }
        short := "abc"
        if got := shortHash(short); got != "abc" {
                t.Errorf("shortHash short = %q, want abc", got)
        }
}

func TestBuildExportRecord_WithDuration_B8(t *testing.T) {
        dur := 3.5
        a := dbq.DomainAnalysis{
                ID:               10,
                Domain:           "export-test.com",
                AsciiDomain:      "export-test.com",
                FullResults:      json.RawMessage(`{"status":"ok"}`),
                AnalysisDuration: &dur,
                CreatedAt:        pgtype.Timestamp{Time: time.Now(), Valid: true},
        }
        rec := buildExportRecord(a)
        if rec["id"].(int32) != 10 {
                t.Error("expected id=10")
        }
        if rec["analysis_duration"] == nil {
                t.Error("expected duration")
        }
}

func TestBuildExportRecord_NoDuration_B8(t *testing.T) {
        a := dbq.DomainAnalysis{
                ID:          20,
                Domain:      "nodur.com",
                AsciiDomain: "nodur.com",
                FullResults: json.RawMessage(`{}`),
        }
        rec := buildExportRecord(a)
        if rec["id"].(int32) != 20 {
                t.Error("expected id=20")
        }
}

func TestNewExportHandler_B8(t *testing.T) {
        h := NewExportHandler(nil)
        if h == nil {
                t.Error("expected non-nil handler")
        }
}
