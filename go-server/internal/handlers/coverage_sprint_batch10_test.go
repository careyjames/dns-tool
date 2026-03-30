package handlers

import (
        "encoding/json"
        "net/http"
        "net/http/httptest"
        "net/url"
        "strings"
        "testing"
        "time"

        "dnstool/go-server/internal/analyzer"
        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/dbq"

        "github.com/gin-gonic/gin"
        "github.com/jackc/pgx/v5/pgtype"
)

func makeTestAnalysis() dbq.DomainAnalysis {
        return dbq.DomainAnalysis{
                ID:          1,
                Domain:      "example.com",
                AsciiDomain: "example.com",
                CreatedAt:   pgtype.Timestamp{Time: time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC), Valid: true},
        }
}

func TestResolveCovertMode_StandardMode_B10(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/analyze", nil)
        mode := resolveCovertMode(c, "example.com")
        if mode != "E" {
                t.Fatalf("expected E, got %s", mode)
        }
}

func TestResolveCovertMode_CovertMode_B10(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/analyze?covert=1", nil)
        mode := resolveCovertMode(c, "example.com")
        if mode != "C" {
                t.Fatalf("expected C, got %s", mode)
        }
}

func TestResolveCovertMode_TLDMode_B10(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/analyze", nil)
        mode := resolveCovertMode(c, "com")
        if mode != "Z" {
                t.Fatalf("expected Z, got %s", mode)
        }
}

func TestResolveCovertMode_CovertTLD_B10(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/analyze?covert=1", nil)
        mode := resolveCovertMode(c, "com")
        if mode != "CZ" {
                t.Fatalf("expected CZ, got %s", mode)
        }
}

func TestResolveCovertMode_PostForm_B10(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        form := url.Values{"covert": {"1"}}
        c.Request = httptest.NewRequest(http.MethodPost, "/analyze", strings.NewReader(form.Encode()))
        c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        mode := resolveCovertMode(c, "example.com")
        if mode != "C" {
                t.Fatalf("expected C, got %s", mode)
        }
}

func TestApplyDevNullHeaders_True_B10(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
        applyDevNullHeaders(c, true)
        if w.Header().Get("X-Hacker") == "" {
                t.Fatal("expected X-Hacker header when devNull=true")
        }
        if w.Header().Get("X-Persistence") != "/dev/null" {
                t.Fatal("expected X-Persistence=/dev/null")
        }
}

func TestApplyDevNullHeaders_False_B10(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
        applyDevNullHeaders(c, false)
        if w.Header().Get("X-Hacker") != "" {
                t.Fatal("expected no X-Hacker header when devNull=false")
        }
}

func TestExtractToolVersion_Present_B10(t *testing.T) {
        results := map[string]any{"_tool_version": "26.37.20"}
        v := extractToolVersion(results)
        if v != "26.37.20" {
                t.Fatalf("expected 26.37.20, got %s", v)
        }
}

func TestExtractToolVersion_Missing_B10(t *testing.T) {
        results := map[string]any{}
        v := extractToolVersion(results)
        if v != "" {
                t.Fatalf("expected empty, got %s", v)
        }
}

func TestExtractToolVersion_WrongType_B10(t *testing.T) {
        results := map[string]any{"_tool_version": 42}
        v := extractToolVersion(results)
        if v != "" {
                t.Fatalf("expected empty for wrong type, got %s", v)
        }
}

func TestDerefString_NonNil_B10(t *testing.T) {
        s := "hello"
        if got := derefString(&s); got != "hello" {
                t.Fatalf("expected hello, got %s", got)
        }
}

func TestDerefString_Nil_B10(t *testing.T) {
        if got := derefString(nil); got != "" {
                t.Fatalf("expected empty, got %s", got)
        }
}

func TestAnalysisTimestamp_WithUpdatedAt_B10(t *testing.T) {
        a := makeTestAnalysis()
        a.UpdatedAt = pgtype.Timestamp{Time: time.Date(2026, 3, 15, 13, 0, 0, 0, time.UTC), Valid: true}
        result := analysisTimestamp(a)
        if result == "" {
                t.Fatal("expected non-empty timestamp")
        }
}

func TestAnalysisTimestamp_WithoutUpdatedAt_B10(t *testing.T) {
        a := makeTestAnalysis()
        a.UpdatedAt = pgtype.Timestamp{Valid: false}
        result := analysisTimestamp(a)
        if result == "" {
                t.Fatal("expected non-empty timestamp")
        }
}

func TestAnalysisDuration_WithValue_B10(t *testing.T) {
        dur := 12.5
        a := makeTestAnalysis()
        a.AnalysisDuration = &dur
        if got := analysisDuration(a); got != 12.5 {
                t.Fatalf("expected 12.5, got %f", got)
        }
}

func TestAnalysisDuration_NilValue_B10(t *testing.T) {
        a := makeTestAnalysis()
        a.AnalysisDuration = nil
        if got := analysisDuration(a); got != 0.0 {
                t.Fatalf("expected 0.0, got %f", got)
        }
}

func TestExtractCustomSelectors_Both_B10(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        form := url.Values{
                "dkim_selector1": {"sel1"},
                "dkim_selector2": {"  sel2  "},
        }
        c.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
        c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        selectors := extractCustomSelectors(c)
        if len(selectors) != 2 {
                t.Fatalf("expected 2 selectors, got %d", len(selectors))
        }
        if selectors[0] != "sel1" || selectors[1] != "sel2" {
                t.Fatalf("unexpected selectors: %v", selectors)
        }
}

func TestExtractCustomSelectors_OneEmpty_B10(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        form := url.Values{
                "dkim_selector1": {"sel1"},
                "dkim_selector2": {"  "},
        }
        c.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
        c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        selectors := extractCustomSelectors(c)
        if len(selectors) != 1 {
                t.Fatalf("expected 1 selector, got %d", len(selectors))
        }
}

func TestExtractCustomSelectors_None_B10(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
        selectors := extractCustomSelectors(c)
        if len(selectors) != 0 {
                t.Fatalf("expected 0 selectors, got %d", len(selectors))
        }
}

func TestCsvEscape_Normal_B10(t *testing.T) {
        if got := csvEscape("hello"); got != "hello" {
                t.Fatalf("expected hello, got %s", got)
        }
}

func TestCsvEscape_WithComma_B10(t *testing.T) {
        got := csvEscape("hello,world")
        if got != "\"hello,world\"" {
                t.Fatalf("expected quoted, got %s", got)
        }
}

func TestCsvEscape_WithQuotes_B10(t *testing.T) {
        got := csvEscape("say \"hi\"")
        if got != "\"say \"\"hi\"\"\"" {
                t.Fatalf("expected escaped quotes, got %s", got)
        }
}

func TestCsvEscape_FormulaInjection_B10(t *testing.T) {
        tests := []struct {
                input    string
                expected string
        }{
                {"=cmd", "'=cmd"},
                {"+cmd", "'+cmd"},
                {"-cmd", "'-cmd"},
                {"@cmd", "'@cmd"},
        }
        for _, tt := range tests {
                t.Run(tt.input, func(t *testing.T) {
                        got := csvEscape(tt.input)
                        if got != tt.expected {
                                t.Fatalf("expected %s, got %s", tt.expected, got)
                        }
                })
        }
}

func TestCsvEscape_Empty_B10(t *testing.T) {
        if got := csvEscape(""); got != "" {
                t.Fatalf("expected empty, got %s", got)
        }
}

func TestCsvEscape_NewlineQuoting_B10(t *testing.T) {
        got := csvEscape("line1\nline2")
        if !strings.HasPrefix(got, "\"") {
                t.Fatalf("expected quoted for newline, got %s", got)
        }
}

func TestCsvEscape_TabPrefix_B10(t *testing.T) {
        got := csvEscape("\tcmd")
        if !strings.HasPrefix(got, "'") {
                t.Fatalf("expected ' prefix for tab, got %s", got)
        }
}

func TestMarshalOrderedJSON_Basic_B10(t *testing.T) {
        entries := []orderedKV{
                {Key: "a", Value: 1},
                {Key: "b", Value: "two"},
        }
        buf := marshalOrderedJSON(entries)
        var m map[string]any
        if err := json.Unmarshal(buf, &m); err != nil {
                t.Fatalf("invalid JSON: %v", err)
        }
        if m["a"] != float64(1) {
                t.Fatalf("expected a=1, got %v", m["a"])
        }
        if m["b"] != "two" {
                t.Fatalf("expected b=two, got %v", m["b"])
        }
}

func TestMarshalOrderedJSON_Nil_B10(t *testing.T) {
        buf := marshalOrderedJSON(nil)
        if string(buf) != "{}" {
                t.Fatalf("expected {}, got %s", string(buf))
        }
}

func TestMarshalOrderedJSON_PreservesOrder_B10(t *testing.T) {
        entries := []orderedKV{
                {Key: "z", Value: 3},
                {Key: "a", Value: 1},
                {Key: "m", Value: 2},
        }
        buf := marshalOrderedJSON(entries)
        s := string(buf)
        zIdx := strings.Index(s, "\"z\"")
        aIdx := strings.Index(s, "\"a\"")
        mIdx := strings.Index(s, "\"m\"")
        if zIdx > aIdx || aIdx > mIdx {
                t.Fatalf("expected z before a before m in output: %s", s)
        }
}

func TestMarshalOrderedJSON_NestedValues_B10(t *testing.T) {
        entries := []orderedKV{
                {Key: "nested", Value: map[string]any{"inner": true}},
        }
        buf := marshalOrderedJSON(entries)
        var m map[string]any
        if err := json.Unmarshal(buf, &m); err != nil {
                t.Fatalf("invalid JSON: %v", err)
        }
}

func TestReportModeTemplate_AllModes_B10(t *testing.T) {
        tests := []struct {
                mode     string
                expected string
        }{
                {"E", "results.html"},
                {"B", "results_executive.html"},
                {"C", "results_covert.html"},
                {"CZ", "results_covert.html"},
                {"Z", "results.html"},
        }
        for _, tt := range tests {
                t.Run(tt.mode, func(t *testing.T) {
                        got := reportModeTemplate(tt.mode)
                        if got != tt.expected {
                                t.Fatalf("reportModeTemplate(%s) = %s, want %s", tt.mode, got, tt.expected)
                        }
                })
        }
}

func TestResolveReportMode_Defaults_B10(t *testing.T) {
        tests := []struct {
                name     string
                mode     string
                covert   string
                expected string
        }{
                {"empty_no_covert", "", "", "E"},
                {"C_mode", "C", "", "C"},
                {"CZ_mode", "CZ", "", "CZ"},
                {"Z_mode", "Z", "", "Z"},
                {"B_mode", "B", "", "B"},
                {"EC_mode", "EC", "", "EC"},
                {"invalid", "INVALID", "", "E"},
                {"covert_query", "", "1", "C"},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        gin.SetMode(gin.TestMode)
                        w := httptest.NewRecorder()
                        c, _ := gin.CreateTestContext(w)
                        qp := ""
                        if tt.covert != "" {
                                qp = "?covert=" + tt.covert
                        }
                        c.Request = httptest.NewRequest(http.MethodGet, "/view/1"+qp, nil)
                        c.Params = gin.Params{{Key: "mode", Value: tt.mode}}
                        got := resolveReportMode(c)
                        if got != tt.expected {
                                t.Fatalf("resolveReportMode(mode=%s, covert=%s) = %s, want %s", tt.mode, tt.covert, got, tt.expected)
                        }
                })
        }
}

func TestIsCovertMode_True_B10(t *testing.T) {
        if !isCovertMode("C") {
                t.Fatal("expected true for C")
        }
        if !isCovertMode("CZ") {
                t.Fatal("expected true for CZ")
        }
        if !isCovertMode("EC") {
                t.Fatal("expected true for EC")
        }
}

func TestIsCovertMode_False_B10(t *testing.T) {
        if isCovertMode("E") {
                t.Fatal("expected false for E")
        }
        if isCovertMode("B") {
                t.Fatal("expected false for B")
        }
        if isCovertMode("Z") {
                t.Fatal("expected false for Z")
        }
}

func TestComputeIntegrityHash_Deterministic_B10(t *testing.T) {
        a := makeTestAnalysis()
        a.AsciiDomain = "example.com"
        a.ID = 1
        results := map[string]any{"test": "data"}
        h1 := computeIntegrityHash(a, "2026-03-15", "v1.0", "v1.0", results)
        h2 := computeIntegrityHash(a, "2026-03-15", "v1.0", "v1.0", results)
        if h1 != h2 {
                t.Fatal("expected deterministic hash")
        }
        if h1 == "" {
                t.Fatal("expected non-empty hash")
        }
}

func TestComputeIntegrityHash_ToolVersionFallback_B10(t *testing.T) {
        a := makeTestAnalysis()
        a.AsciiDomain = "example.com"
        a.ID = 1
        results := map[string]any{"test": "data"}
        h1 := computeIntegrityHash(a, "2026-03-15", "", "v2.0", results)
        h2 := computeIntegrityHash(a, "2026-03-15", "v2.0", "v2.0", results)
        if h1 != h2 {
                t.Fatal("empty toolVersion should fallback to appVersion")
        }
}

func TestIndexFlashData_Structure_B10(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

        h := &AnalysisHandler{
                Config: &config.Config{
                        AppVersion:      "test-v1",
                        BaseURL:         "https://test.example.com",
                        MaintenanceNote: "Beta",
                },
        }
        data := h.indexFlashData(c, "test-nonce", "test-csrf", "danger", "Something went wrong")

        if data["AppVersion"] != "test-v1" {
                t.Fatal("expected AppVersion=test-v1")
        }
        if data["BaseURL"] != "https://test.example.com" {
                t.Fatal("expected BaseURL set")
        }
        if data["CspNonce"] != "test-nonce" {
                t.Fatal("expected CspNonce set")
        }
        if data["CsrfToken"] != "test-csrf" {
                t.Fatal("expected CsrfToken set")
        }
        if data["ActivePage"] != "home" {
                t.Fatal("expected ActivePage=home")
        }
        if data["MaintenanceNote"] != "Beta" {
                t.Fatal("expected MaintenanceNote=Beta")
        }

        flashes, ok := data["FlashMessages"].([]FlashMessage)
        if !ok || len(flashes) != 1 {
                t.Fatal("expected 1 flash message")
        }
        if flashes[0].Category != "danger" || flashes[0].Message != "Something went wrong" {
                t.Fatalf("unexpected flash: %+v", flashes[0])
        }
}

func TestRecordAnalyticsCollector_NoExec_B10(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
        recordAnalyticsCollector(c, "example.com")
}

func TestBuildAnalyzeViewData_BasicStructure_B10(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

        h := &AnalysisHandler{
                Config: &config.Config{
                        AppVersion:      "test-v1",
                        MaintenanceNote: "",
                },
                Analyzer: analyzer.New(analyzer.WithInitialIANAFetch(false)),
        }

        results := map[string]any{
                "domain_exists":    true,
                "analysis_success": true,
                "spf_analysis":     map[string]any{"status": "pass"},
        }

        data := h.buildAnalyzeViewData(c, "nonce", "csrf", viewDataInput{
                domain:      "Example.com",
                asciiDomain: "example.com",
                results:     results,
                analysisID:  42,
                timestamp:   "2026-03-15 12:00 UTC",
                postureHash: "abc123",
                drift:       driftInfo{Detected: false},
        })

        if data["Domain"] != "Example.com" {
                t.Fatal("expected Domain=Example.com")
        }
        if data["AsciiDomain"] != "example.com" {
                t.Fatal("expected AsciiDomain=example.com")
        }
        if data["AnalysisID"] != int32(42) {
                t.Fatalf("expected AnalysisID=42, got %v", data["AnalysisID"])
        }
        if data["DomainExists"] != true {
                t.Fatal("expected DomainExists=true")
        }
        if data["PostureHash"] != "abc123" {
                t.Fatal("expected PostureHash set")
        }
        if data["IntegrityHash"] == "" {
                t.Fatal("expected non-empty IntegrityHash")
        }
        if data["Ephemeral"] != false {
                t.Fatal("expected Ephemeral=false")
        }
        if data["IsSubdomain"] != false {
                t.Fatal("expected IsSubdomain=false for example.com")
        }
}

func TestBuildAnalyzeViewData_Subdomain_B10(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

        h := &AnalysisHandler{
                Config: &config.Config{
                        AppVersion: "test-v1",
                },
                Analyzer: analyzer.New(analyzer.WithInitialIANAFetch(false)),
        }

        results := map[string]any{
                "domain_exists":    true,
                "analysis_success": true,
        }

        data := h.buildAnalyzeViewData(c, "nonce", "csrf", viewDataInput{
                domain:      "sub.example.com",
                asciiDomain: "sub.example.com",
                results:     results,
                analysisID:  1,
                drift:       driftInfo{},
        })

        if data["IsSubdomain"] != true {
                t.Fatal("expected IsSubdomain=true for sub.example.com")
        }
        if data["RootDomain"] != "example.com" {
                t.Fatalf("expected RootDomain=example.com, got %v", data["RootDomain"])
        }
}

func TestBuildAnalyzeViewData_WithDrift_B10(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

        h := &AnalysisHandler{
                Config:   &config.Config{AppVersion: "test-v1"},
                Analyzer: analyzer.New(analyzer.WithInitialIANAFetch(false)),
        }

        data := h.buildAnalyzeViewData(c, "nonce", "csrf", viewDataInput{
                domain:      "example.com",
                asciiDomain: "example.com",
                results:     map[string]any{"domain_exists": true},
                drift: driftInfo{
                        Detected: true,
                        PrevHash: "oldhash",
                        PrevTime: "2026-03-10",
                        PrevID:   5,
                },
        })

        if data["DriftDetected"] != true {
                t.Fatal("expected DriftDetected=true")
        }
        if data["DriftPrevHash"] != "oldhash" {
                t.Fatal("expected DriftPrevHash=oldhash")
        }
        if data["DriftPrevID"] != int32(5) {
                t.Fatalf("expected DriftPrevID=5, got %v", data["DriftPrevID"])
        }
}

func TestBuildAnalyzeViewData_Ephemeral_B10(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

        h := &AnalysisHandler{
                Config:   &config.Config{AppVersion: "test-v1"},
                Analyzer: analyzer.New(analyzer.WithInitialIANAFetch(false)),
        }

        data := h.buildAnalyzeViewData(c, "nonce", "csrf", viewDataInput{
                domain:      "example.com",
                asciiDomain: "example.com",
                results:     map[string]any{"domain_exists": true},
                ephemeral:   true,
                devNull:     true,
                drift:       driftInfo{},
        })

        if data["Ephemeral"] != true {
                t.Fatal("expected Ephemeral=true")
        }
        if data["DevNull"] != true {
                t.Fatal("expected DevNull=true")
        }
}

func TestAPIDNSHistory_EmptyDomain_B10(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/api/dns-history", nil)

        h := &AnalysisHandler{Config: &config.Config{AppVersion: "test"}}
        h.APIDNSHistory(c)

        if w.Code != http.StatusBadRequest {
                t.Fatalf("expected 400, got %d", w.Code)
        }
}

func TestAPIDNSHistory_InvalidDomain_B10(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/api/dns-history?domain=!!!invalid!!!", nil)

        h := &AnalysisHandler{Config: &config.Config{AppVersion: "test"}}
        h.APIDNSHistory(c)

        if w.Code != http.StatusBadRequest {
                t.Fatalf("expected 400, got %d", w.Code)
        }
}

func TestAPIDNSHistory_NoAPIKey_B10(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/api/dns-history?domain=example.com", nil)

        h := &AnalysisHandler{Config: &config.Config{AppVersion: "test"}}
        h.APIDNSHistory(c)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }
        var resp map[string]any
        json.Unmarshal(w.Body.Bytes(), &resp)
        if resp["status"] != "no_key" {
                t.Fatalf("expected status=no_key, got %v", resp["status"])
        }
}

func TestRecordDailyStats_NilExecer_B10(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        h.recordDailyStats(true, 1.5)
        h.recordDailyStats(false, 2.0)
}

func TestStoreTelemetry_Ephemeral_B10(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        h.storeTelemetry(nil, 42, map[string]any{}, true)
}

func TestStoreTelemetry_ZeroID_B10(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        h.storeTelemetry(nil, 0, map[string]any{}, false)
}

func TestRecordCurrencyIfEligible_Ephemeral_B10(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        h.recordCurrencyIfEligible(true, true, "example.com", map[string]any{})
}

func TestRecordCurrencyIfEligible_DomainNotExists_B10(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        h.recordCurrencyIfEligible(false, false, "example.com", map[string]any{})
}

func TestRecordCurrencyIfEligible_NoCurrencyReport_B10(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        h.recordCurrencyIfEligible(false, true, "example.com", map[string]any{})
}

func TestHandlePostAnalysisSideEffectsAsync_NoID_B10(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        h.handlePostAnalysisSideEffectsAsync(nil, sideEffectsParams{
                analysisID: 0,
        })
}

func TestHandlePostAnalysisSideEffectsAsync_WithID_NoDrift_B10(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        h.handlePostAnalysisSideEffectsAsync(nil, sideEffectsParams{
                analysisID:      42,
                ephemeral:       true,
                analysisSuccess: true,
        })
}

func TestRecordUserAnalysisAsync_NotAuth_B10(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        h.recordUserAnalysisAsync(sideEffectsParams{
                isAuthenticated: false,
                userID:          42,
                analysisID:      1,
        })
}

func TestRecordUserAnalysisAsync_ZeroUserID_B10(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        h.recordUserAnalysisAsync(sideEffectsParams{
                isAuthenticated: true,
                userID:          0,
                analysisID:      1,
        })
}

func TestEnrichViewDataMetrics_NoSnapshot_B10(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        data := gin.H{}
        results := map[string]any{}
        h.enrichViewDataMetrics(nil, data, results, "example.com", 0)
}

func TestEnrichViewDataMetrics_WithCurrencyReport_B10(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        data := gin.H{}
        results := map[string]any{
                "currency_report": map[string]any{
                        "overall_score":         85.0,
                        "overall_grade":         "Excellent",
                        "overall_grade_display": "Excellent",
                        "guidance":              "Fresh data.",
                },
        }
        h.enrichViewDataMetrics(nil, data, results, "example.com", 0)
        if _, ok := data["CurrencyReport"]; !ok {
                t.Fatal("expected CurrencyReport to be set")
        }
}

func TestEnrichViewDataMetrics_WithSnapshot_B10(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        data := gin.H{}
        results := map[string]any{
                "_icae_snapshot": map[string]any{
                        "overall_maturity": "Excellent",
                        "unified_confidence": map[string]any{
                                "overall": 0.95,
                        },
                },
        }
        h.enrichViewDataMetrics(nil, data, results, "example.com", 0)
}

func TestDetectDrift_DevNull_B10(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        drift := h.detectDrift(nil, true, true, "example.com", "hash", nil)
        if drift.Detected {
                t.Fatal("expected no drift for devNull")
        }
}

func TestDetectDrift_DomainNotExists_B10(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        drift := h.detectDrift(nil, false, false, "example.com", "hash", nil)
        if drift.Detected {
                t.Fatal("expected no drift for non-existent domain")
        }
}

func TestDetectHistoricalDrift_EmptyHash_B10(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        drift := h.detectHistoricalDrift(nil, "", "example.com", 1, nil)
        if drift.Detected {
                t.Fatal("expected no drift for empty hash")
        }
}

func TestClose_NilProgressStore_B10(t *testing.T) {
        h := &AnalysisHandler{Config: &config.Config{}}
        h.Close()
}

func TestExportSubdomainsCSV_EmptyDomain_B10(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/export/subdomains?domain=", nil)

        h := &AnalysisHandler{
                Config:   &config.Config{AppVersion: "test"},
                Analyzer: analyzer.New(analyzer.WithInitialIANAFetch(false)),
        }
        h.ExportSubdomainsCSV(c)

        if w.Code != http.StatusFound {
                t.Fatalf("expected redirect 302, got %d", w.Code)
        }
}

func TestExportSubdomainsCSV_InvalidDomain_B10(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/export/subdomains?domain=!!!invalid", nil)

        h := &AnalysisHandler{
                Config:   &config.Config{AppVersion: "test"},
                Analyzer: analyzer.New(analyzer.WithInitialIANAFetch(false)),
        }
        h.ExportSubdomainsCSV(c)

        if w.Code != http.StatusFound {
                t.Fatalf("expected redirect 302, got %d", w.Code)
        }
}

func TestExportSubdomainsCSV_NoCachedData_B10(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/export/subdomains?domain=example.com", nil)

        h := &AnalysisHandler{
                Config:   &config.Config{AppVersion: "test"},
                Analyzer: analyzer.New(analyzer.WithInitialIANAFetch(false)),
        }
        h.ExportSubdomainsCSV(c)

        if w.Code != http.StatusFound {
                t.Fatalf("expected redirect 302 (no cache), got %d", w.Code)
        }
}

func TestAPISubdomains_EmptyDomain_B10(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/api/subdomains/", nil)
        c.Params = gin.Params{{Key: "domain", Value: ""}}

        h := &AnalysisHandler{
                Config:   &config.Config{AppVersion: "test"},
                Analyzer: analyzer.New(analyzer.WithInitialIANAFetch(false)),
        }
        h.APISubdomains(c)

        if w.Code != http.StatusBadRequest {
                t.Fatalf("expected 400, got %d", w.Code)
        }
}

func TestAPISubdomains_InvalidDomain_B10(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/api/subdomains/!!!invalid", nil)
        c.Params = gin.Params{{Key: "domain", Value: "/!!!invalid"}}

        h := &AnalysisHandler{
                Config:   &config.Config{AppVersion: "test"},
                Analyzer: analyzer.New(analyzer.WithInitialIANAFetch(false)),
        }
        h.APISubdomains(c)

        if w.Code != http.StatusBadRequest {
                t.Fatalf("expected 400, got %d", w.Code)
        }
}

func TestExtractCurrencyFromResults_Present_B10(t *testing.T) {
        results := map[string]any{
                "currency_report": map[string]any{
                        "overall_score": 85.0,
                },
        }
        cr := extractCurrencyFromResults(results)
        if cr == nil {
                t.Fatal("expected currency report")
        }
}

func TestExtractCurrencyFromResults_Missing_B10(t *testing.T) {
        results := map[string]any{}
        cr := extractCurrencyFromResults(results)
        if cr != nil {
                t.Fatal("expected nil for missing currency report")
        }
}

func TestComputeDriftFromPrev_NilHash_B10(t *testing.T) {
        di := computeDriftFromPrev("currenthash", prevAnalysisSnapshot{Hash: nil}, nil)
        if di.Detected {
                t.Fatal("expected no drift for nil prev hash")
        }
}

func TestComputeDriftFromPrev_EmptyHash_B10(t *testing.T) {
        empty := ""
        di := computeDriftFromPrev("currenthash", prevAnalysisSnapshot{Hash: &empty}, nil)
        if di.Detected {
                t.Fatal("expected no drift for empty prev hash")
        }
}

func TestComputeDriftFromPrev_SameHash_B10(t *testing.T) {
        h := "samehash"
        di := computeDriftFromPrev("samehash", prevAnalysisSnapshot{Hash: &h, ID: 5}, nil)
        if di.Detected {
                t.Fatal("expected no drift when hashes match")
        }
}

func TestComputeDriftFromPrev_DifferentHash_B10(t *testing.T) {
        prev := "oldhash"
        di := computeDriftFromPrev("newhash", prevAnalysisSnapshot{
                Hash:           &prev,
                ID:             5,
                CreatedAtValid: true,
        }, map[string]any{})
        if !di.Detected {
                t.Fatal("expected drift when hashes differ")
        }
        if di.PrevHash != "oldhash" {
                t.Fatalf("expected PrevHash=oldhash, got %s", di.PrevHash)
        }
        if di.PrevID != 5 {
                t.Fatalf("expected PrevID=5, got %d", di.PrevID)
        }
}

func TestResolveEmailScope_NotSubdomain_B10(t *testing.T) {
        h := &AnalysisHandler{
                Config:   &config.Config{},
                Analyzer: analyzer.New(analyzer.WithInitialIANAFetch(false)),
        }
        es := h.resolveEmailScope(nil, false, "", "example.com", map[string]any{})
        if es != nil {
                t.Fatal("expected nil for non-subdomain")
        }
}

func TestResolveEmailScope_EmptyRoot_B10(t *testing.T) {
        h := &AnalysisHandler{
                Config:   &config.Config{},
                Analyzer: analyzer.New(analyzer.WithInitialIANAFetch(false)),
        }
        es := h.resolveEmailScope(nil, true, "", "sub.example.com", map[string]any{})
        if es != nil {
                t.Fatal("expected nil for empty root domain")
        }
}
