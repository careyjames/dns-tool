package handlers

import (
        "bytes"
        "encoding/json"
        "net/http"
        "net/http/httptest"
        "testing"
        "time"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/dbq"

        "github.com/gin-gonic/gin"
        "github.com/jackc/pgx/v5/pgtype"
)

func TestCoverageBoost18_BuildExportRecord(t *testing.T) {
        dur := 1.234
        cc := "US"
        cn := "United States"

        t.Run("with valid full_results", func(t *testing.T) {
                a := dbq.DomainAnalysis{
                        ID:               42,
                        Domain:           "example.com",
                        AsciiDomain:      "example.com",
                        AnalysisDuration: &dur,
                        CountryCode:      &cc,
                        CountryName:      &cn,
                        FullResults:      json.RawMessage(`{"spf":"pass"}`),
                        CreatedAt:        pgtype.Timestamp{Time: time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC), Valid: true},
                        UpdatedAt:        pgtype.Timestamp{Time: time.Date(2025, 1, 15, 11, 0, 0, 0, time.UTC), Valid: true},
                }
                rec := buildExportRecord(a)
                if rec["id"] != int32(42) {
                        t.Errorf("id = %v, want 42", rec["id"])
                }
                if rec["domain"] != "example.com" {
                        t.Errorf("domain = %v", rec["domain"])
                }
                if rec["ascii_domain"] != "example.com" {
                        t.Errorf("ascii_domain = %v", rec["ascii_domain"])
                }
                if rec["full_results"] == nil {
                        t.Error("full_results should not be nil")
                }
                if rec["country_code"] != &cc {
                        t.Errorf("country_code = %v", rec["country_code"])
                }
        })

        t.Run("with empty full_results", func(t *testing.T) {
                a := dbq.DomainAnalysis{
                        ID:          1,
                        Domain:      "empty.com",
                        AsciiDomain: "empty.com",
                        FullResults: json.RawMessage(``),
                }
                rec := buildExportRecord(a)
                if rec["full_results"] != nil {
                        t.Errorf("expected nil full_results for empty data, got %v", rec["full_results"])
                }
        })

        t.Run("with invalid JSON full_results", func(t *testing.T) {
                a := dbq.DomainAnalysis{
                        ID:          2,
                        Domain:      "bad.com",
                        AsciiDomain: "bad.com",
                        FullResults: json.RawMessage(`{invalid json`),
                }
                rec := buildExportRecord(a)
                if rec["full_results"] != nil {
                        t.Errorf("expected nil full_results for invalid JSON, got %v", rec["full_results"])
                }
        })

        t.Run("with nil optional fields", func(t *testing.T) {
                a := dbq.DomainAnalysis{
                        ID:          3,
                        Domain:      "nil.com",
                        AsciiDomain: "nil.com",
                }
                rec := buildExportRecord(a)
                if rec["analysis_duration"] != (*float64)(nil) {
                        t.Errorf("analysis_duration = %v", rec["analysis_duration"])
                }
                if rec["country_code"] != (*string)(nil) {
                        t.Errorf("country_code = %v", rec["country_code"])
                }
        })
}

func TestCoverageBoost18_WriteExportRecord(t *testing.T) {
        t.Run("writes valid NDJSON line", func(t *testing.T) {
                var buf bytes.Buffer
                a := dbq.DomainAnalysis{
                        ID:          10,
                        Domain:      "test.com",
                        AsciiDomain: "test.com",
                        FullResults: json.RawMessage(`{"key":"value"}`),
                }
                writeExportRecord(&buf, a)
                output := buf.String()
                if len(output) == 0 {
                        t.Fatal("expected non-empty output")
                }
                if output[len(output)-1] != '\n' {
                        t.Error("expected trailing newline")
                }
                var m map[string]interface{}
                if err := json.Unmarshal([]byte(output), &m); err != nil {
                        t.Errorf("expected valid JSON line, got error: %v", err)
                }
                if m["domain"] != "test.com" {
                        t.Errorf("domain = %v", m["domain"])
                }
        })

        t.Run("writes line even with empty results", func(t *testing.T) {
                var buf bytes.Buffer
                a := dbq.DomainAnalysis{
                        ID:          11,
                        Domain:      "empty.com",
                        AsciiDomain: "empty.com",
                }
                writeExportRecord(&buf, a)
                if buf.Len() == 0 {
                        t.Error("expected output even with empty results")
                }
        })
}

func TestCoverageBoost18_NewEDEHandler(t *testing.T) {
        cfg := &config.Config{
                AppVersion:      "1.0.0",
                MaintenanceNote: "",
        }
        h := NewEDEHandler(&db.Database{}, cfg)
        if h == nil {
                t.Fatal("expected non-nil handler")
        }
        if h.Config != cfg {
                t.Error("config not set correctly")
        }
}

func TestCoverageBoost18_RenderCompareError(t *testing.T) {
        gin.SetMode(gin.TestMode)

        t.Run("renders error with domain", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest(http.MethodGet, "/compare", nil)

                cfg := &config.Config{AppVersion: "1.0.0"}
                handler := &CompareHandler{
                        DB:     &db.Database{},
                        Config: cfg,
                }

                panicked1 := false
                func() {
                        defer func() {
                                if r := recover(); r != nil {
                                        panicked1 = true
                                }
                        }()
                        renderCompareError(c, compareErrorParams{
                                handler:    handler,
                                nonce:      "test-nonce",
                                csrfToken:  "test-csrf",
                                tmpl:       templateCompareSelect,
                                statusCode: http.StatusBadRequest,
                                message:    "Test error message",
                                domain:     "example.com",
                        })
                }()
                if !panicked1 {
                        t.Error("expected panic with no template engine")
                }
        })

        t.Run("renders error without domain", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest(http.MethodGet, "/compare", nil)

                cfg := &config.Config{AppVersion: "2.0.0"}
                handler := &CompareHandler{
                        DB:     &db.Database{},
                        Config: cfg,
                }

                panicked2 := false
                func() {
                        defer func() {
                                if r := recover(); r != nil {
                                        panicked2 = true
                                }
                        }()
                        renderCompareError(c, compareErrorParams{
                                handler:    handler,
                                nonce:      nil,
                                csrfToken:  nil,
                                tmpl:       templateCompare,
                                statusCode: http.StatusNotFound,
                                message:    "Not found",
                                domain:     "",
                        })
                }()
                if !panicked2 {
                        t.Error("expected panic with no template engine")
                }
        })
}

func TestCoverageBoost18_GetJSONFromResults(t *testing.T) {
        t.Run("top-level string value", func(t *testing.T) {
                results := map[string]any{"domain": "example.com"}
                raw := getJSONFromResults(results, "domain", "")
                if raw == nil {
                        t.Fatal("expected non-nil")
                }
        })

        t.Run("nested key from map section", func(t *testing.T) {
                results := map[string]any{
                        "spf_analysis": map[string]any{
                                "record": "v=spf1 -all",
                        },
                }
                raw := getJSONFromResults(results, "spf_analysis", "record")
                if raw == nil {
                        t.Fatal("expected non-nil")
                }
                var val string
                json.Unmarshal(raw, &val)
                if val != "v=spf1 -all" {
                        t.Errorf("got %q", val)
                }
        })

        t.Run("nil results", func(t *testing.T) {
                raw := getJSONFromResults(nil, "x", "y")
                if raw != nil {
                        t.Error("expected nil")
                }
        })

        t.Run("section not a map with non-empty key", func(t *testing.T) {
                results := map[string]any{"section": "string_value"}
                raw := getJSONFromResults(results, "section", "key")
                if raw != nil {
                        t.Error("expected nil when section is not a map")
                }
        })

        t.Run("missing key in section", func(t *testing.T) {
                results := map[string]any{
                        "section": map[string]any{"a": 1},
                }
                raw := getJSONFromResults(results, "section", "missing")
                if raw != nil {
                        t.Error("expected nil for missing key")
                }
        })

        t.Run("missing section", func(t *testing.T) {
                results := map[string]any{}
                raw := getJSONFromResults(results, "missing", "")
                if raw != nil {
                        t.Error("expected nil for missing section")
                }
        })
}

func TestCoverageBoost18_FormatDiffValue(t *testing.T) {
        t.Run("nil value", func(t *testing.T) {
                if got := formatDiffValue(nil); got != "" {
                        t.Errorf("got %q, want empty", got)
                }
        })

        t.Run("string value", func(t *testing.T) {
                if got := formatDiffValue("hello"); got != "hello" {
                        t.Errorf("got %q, want hello", got)
                }
        })

        t.Run("number value", func(t *testing.T) {
                got := formatDiffValue(42)
                if got != "42" {
                        t.Errorf("got %q, want 42", got)
                }
        })

        t.Run("map value", func(t *testing.T) {
                got := formatDiffValue(map[string]string{"k": "v"})
                if got == "" {
                        t.Error("expected non-empty for map")
                }
        })

        t.Run("bool value", func(t *testing.T) {
                got := formatDiffValue(true)
                if got != "true" {
                        t.Errorf("got %q, want true", got)
                }
        })
}

func TestCoverageBoost18_BuildCompareAnalysis(t *testing.T) {
        t.Run("with all fields", func(t *testing.T) {
                dur := 2.5
                a := dbq.DomainAnalysis{
                        CreatedAt:        pgtype.Timestamp{Time: time.Date(2025, 3, 15, 10, 0, 0, 0, time.UTC), Valid: true},
                        AnalysisDuration: &dur,
                        FullResults:      json.RawMessage(`{"_tool_version":"3.0.0"}`),
                }
                ca := buildCompareAnalysis(a)
                if ca.CreatedAt == "" {
                        t.Error("expected non-empty CreatedAt")
                }
                if !ca.HasDuration {
                        t.Error("expected HasDuration true")
                }
                if ca.AnalysisDuration != "2.5s" {
                        t.Errorf("duration = %q", ca.AnalysisDuration)
                }
                if ca.ToolVersion != "3.0.0" {
                        t.Errorf("tool version = %q", ca.ToolVersion)
                }
                if !ca.HasToolVersion {
                        t.Error("expected HasToolVersion true")
                }
        })

        t.Run("with no optional fields", func(t *testing.T) {
                a := dbq.DomainAnalysis{}
                ca := buildCompareAnalysis(a)
                if ca.CreatedAt != "" {
                        t.Errorf("expected empty CreatedAt, got %q", ca.CreatedAt)
                }
                if ca.HasDuration {
                        t.Error("expected HasDuration false")
                }
                if ca.HasToolVersion {
                        t.Error("expected HasToolVersion false")
                }
        })

        t.Run("with full_results but no tool_version", func(t *testing.T) {
                a := dbq.DomainAnalysis{
                        FullResults: json.RawMessage(`{"spf":"pass"}`),
                }
                ca := buildCompareAnalysis(a)
                if ca.HasToolVersion {
                        t.Error("expected HasToolVersion false when no _tool_version key")
                }
        })

        t.Run("with invalid JSON full_results", func(t *testing.T) {
                a := dbq.DomainAnalysis{
                        FullResults: json.RawMessage(`{bad json`),
                }
                ca := buildCompareAnalysis(a)
                if ca.HasToolVersion {
                        t.Error("expected HasToolVersion false for invalid JSON")
                }
        })
}

func TestCoverageBoost18_BuildDiffItems(t *testing.T) {
        t.Run("empty diffs", func(t *testing.T) {
                items, changes := buildDiffItems(nil)
                if len(items) != 0 {
                        t.Errorf("expected 0 items, got %d", len(items))
                }
                if changes != 0 {
                        t.Errorf("expected 0 changes, got %d", changes)
                }
        })

        t.Run("mixed changed and unchanged", func(t *testing.T) {
                diffs := []SectionDiff{
                        {Label: "SPF", Icon: "shield", Changed: true, StatusA: "pass", StatusB: "fail"},
                        {Label: "DKIM", Icon: "key", Changed: false, StatusA: "pass", StatusB: "pass"},
                        {Label: "DMARC", Icon: "lock", Changed: true, StatusA: "none", StatusB: "reject",
                                DetailChanges: []DetailChange{
                                        {Field: "policy", Old: "none", New: "reject"},
                                        {Field: "config", Old: map[string]interface{}{"a": 1}, New: "simple"},
                                },
                        },
                }
                items, changes := buildDiffItems(diffs)
                if len(items) != 3 {
                        t.Errorf("expected 3 items, got %d", len(items))
                }
                if changes != 2 {
                        t.Errorf("expected 2 changes, got %d", changes)
                }
                if len(items[2].DetailChanges) != 2 {
                        t.Errorf("expected 2 detail changes on DMARC, got %d", len(items[2].DetailChanges))
                }
                if !items[2].DetailChanges[1].IsMap {
                        t.Error("expected IsMap true for map old value")
                }
                if items[2].DetailChanges[0].IsMap {
                        t.Error("expected IsMap false for string old value")
                }
        })
}

func TestCoverageBoost18_BuildSelectAnalysisItem(t *testing.T) {
        t.Run("with all optional fields", func(t *testing.T) {
                spf := "pass"
                dmarc := "reject"
                dkim := "valid"
                dur := 3.14
                a := dbq.DomainAnalysis{
                        ID:               100,
                        Domain:           "test.org",
                        AsciiDomain:      "test.org",
                        SpfStatus:        &spf,
                        DmarcStatus:      &dmarc,
                        DkimStatus:       &dkim,
                        AnalysisDuration: &dur,
                        CreatedAt:        pgtype.Timestamp{Time: time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC), Valid: true},
                        FullResults:      json.RawMessage(`{"_tool_version":"4.2.0"}`),
                }
                item := buildSelectAnalysisItem(a)
                if item.ID != 100 {
                        t.Errorf("ID = %d", item.ID)
                }
                if item.SpfStatus != "pass" {
                        t.Errorf("SpfStatus = %q", item.SpfStatus)
                }
                if item.DmarcStatus != "reject" {
                        t.Errorf("DmarcStatus = %q", item.DmarcStatus)
                }
                if item.DkimStatus != "valid" {
                        t.Errorf("DkimStatus = %q", item.DkimStatus)
                }
                if item.AnalysisDuration != 3.14 {
                        t.Errorf("AnalysisDuration = %f", item.AnalysisDuration)
                }
                if item.ToolVersion != "4.2.0" {
                        t.Errorf("ToolVersion = %q", item.ToolVersion)
                }
                if item.CreatedAt == "" {
                        t.Error("expected non-empty CreatedAt")
                }
        })

        t.Run("with nil optional fields", func(t *testing.T) {
                a := dbq.DomainAnalysis{
                        ID:          200,
                        Domain:      "nil.org",
                        AsciiDomain: "nil.org",
                }
                item := buildSelectAnalysisItem(a)
                if item.SpfStatus != "" {
                        t.Errorf("SpfStatus = %q, want empty", item.SpfStatus)
                }
                if item.DmarcStatus != "" {
                        t.Errorf("DmarcStatus = %q, want empty", item.DmarcStatus)
                }
                if item.DkimStatus != "" {
                        t.Errorf("DkimStatus = %q, want empty", item.DkimStatus)
                }
                if item.AnalysisDuration != 0 {
                        t.Errorf("AnalysisDuration = %f, want 0", item.AnalysisDuration)
                }
                if item.CreatedAt != "" {
                        t.Errorf("CreatedAt = %q, want empty", item.CreatedAt)
                }
                if item.ToolVersion != "" {
                        t.Errorf("ToolVersion = %q, want empty", item.ToolVersion)
                }
        })
}

func TestCoverageBoost18_ProtocolRawConfidence(t *testing.T) {
        tests := []struct {
                name     string
                results  map[string]any
                key      string
                expected float64
        }{
                {"secure status", map[string]any{"spf": map[string]any{"status": "secure"}}, "spf", 1.0},
                {"pass status", map[string]any{"spf": map[string]any{"status": "pass"}}, "spf", 1.0},
                {"valid status", map[string]any{"spf": map[string]any{"status": "valid"}}, "spf", 1.0},
                {"good status", map[string]any{"spf": map[string]any{"status": "good"}}, "spf", 1.0},
                {"warning status", map[string]any{"spf": map[string]any{"status": "warning"}}, "spf", 0.7},
                {"info status", map[string]any{"spf": map[string]any{"status": "info"}}, "spf", 0.7},
                {"partial status", map[string]any{"spf": map[string]any{"status": "partial"}}, "spf", 0.7},
                {"fail status", map[string]any{"spf": map[string]any{"status": "fail"}}, "spf", 0.3},
                {"danger status", map[string]any{"spf": map[string]any{"status": "danger"}}, "spf", 0.3},
                {"critical status", map[string]any{"spf": map[string]any{"status": "critical"}}, "spf", 0.3},
                {"error status", map[string]any{"spf": map[string]any{"status": "error"}}, "spf", 0.0},
                {"n/a status", map[string]any{"spf": map[string]any{"status": "n/a"}}, "spf", 0.0},
                {"empty status", map[string]any{"spf": map[string]any{"status": ""}}, "spf", 0.0},
                {"unknown status", map[string]any{"spf": map[string]any{"status": "something_else"}}, "spf", 0.5},
                {"missing section", map[string]any{}, "spf", 0.0},
                {"section not a map", map[string]any{"spf": "string"}, "spf", 0.0},
                {"no status key", map[string]any{"spf": map[string]any{"record": "v=spf1"}}, "spf", 0.0},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := protocolRawConfidence(tt.results, tt.key)
                        if got != tt.expected {
                                t.Errorf("protocolRawConfidence() = %f, want %f", got, tt.expected)
                        }
                })
        }
}

func TestCoverageBoost18_AggregateResolverAgreement(t *testing.T) {
        t.Run("no consensus key", func(t *testing.T) {
                agree, total := aggregateResolverAgreement(map[string]any{})
                if agree != 0 || total != 0 {
                        t.Errorf("got (%d, %d), want (0, 0)", agree, total)
                }
        })

        t.Run("consensus not a map", func(t *testing.T) {
                agree, total := aggregateResolverAgreement(map[string]any{
                        "resolver_consensus": "not_a_map",
                })
                if agree != 0 || total != 0 {
                        t.Errorf("got (%d, %d), want (0, 0)", agree, total)
                }
        })

        t.Run("no per_record_consensus", func(t *testing.T) {
                agree, total := aggregateResolverAgreement(map[string]any{
                        "resolver_consensus": map[string]any{},
                })
                if agree != 0 || total != 0 {
                        t.Errorf("got (%d, %d), want (0, 0)", agree, total)
                }
        })

        t.Run("with consensus records", func(t *testing.T) {
                results := map[string]any{
                        "resolver_consensus": map[string]any{
                                "per_record_consensus": map[string]any{
                                        "A": map[string]any{
                                                "resolver_count": 4,
                                                "consensus":      true,
                                        },
                                        "MX": map[string]any{
                                                "resolver_count": 4,
                                                "consensus":      false,
                                        },
                                },
                        },
                }
                agree, total := aggregateResolverAgreement(results)
                if total != 8 {
                        t.Errorf("total = %d, want 8", total)
                }
                if agree != 7 {
                        t.Errorf("agree = %d, want 7", agree)
                }
        })

        t.Run("record data not a map is skipped", func(t *testing.T) {
                results := map[string]any{
                        "resolver_consensus": map[string]any{
                                "per_record_consensus": map[string]any{
                                        "A":  "not_a_map",
                                        "MX": map[string]any{"resolver_count": 3, "consensus": true},
                                },
                        },
                }
                agree, total := aggregateResolverAgreement(results)
                if total != 3 {
                        t.Errorf("total = %d, want 3", total)
                }
                if agree != 3 {
                        t.Errorf("agree = %d, want 3", agree)
                }
        })

        t.Run("no consensus with zero resolver_count", func(t *testing.T) {
                results := map[string]any{
                        "resolver_consensus": map[string]any{
                                "per_record_consensus": map[string]any{
                                        "A": map[string]any{
                                                "resolver_count": 0,
                                                "consensus":      false,
                                        },
                                },
                        },
                }
                agree, total := aggregateResolverAgreement(results)
                if total != 0 {
                        t.Errorf("total = %d, want 0", total)
                }
                if agree != 0 {
                        t.Errorf("agree = %d, want 0", agree)
                }
        })
}

func TestCoverageBoost18_NewExportHandler(t *testing.T) {
        database := &db.Database{}
        h := NewExportHandler(database)
        if h == nil {
                t.Fatal("expected non-nil handler")
        }
        if h.DB != database {
                t.Error("DB not set correctly")
        }
}

func TestCoverageBoost18_NewCompareHandler(t *testing.T) {
        database := &db.Database{}
        cfg := &config.Config{AppVersion: "1.0.0"}
        h := NewCompareHandler(database, cfg)
        if h == nil {
                t.Fatal("expected non-nil handler")
        }
        if h.DB != database {
                t.Error("DB not set correctly")
        }
        if h.Config != cfg {
                t.Error("Config not set correctly")
        }
}

func TestCoverageBoost18_IsAnalysisFailure(t *testing.T) {
        t.Run("success true", func(t *testing.T) {
                failed, msg := isAnalysisFailure(map[string]any{"analysis_success": true})
                if failed {
                        t.Error("expected not failed")
                }
                if msg != "" {
                        t.Errorf("expected empty msg, got %q", msg)
                }
        })

        t.Run("no analysis_success key", func(t *testing.T) {
                failed, _ := isAnalysisFailure(map[string]any{})
                if failed {
                        t.Error("expected not failed when key missing")
                }
        })

        t.Run("success false with error", func(t *testing.T) {
                failed, msg := isAnalysisFailure(map[string]any{
                        "analysis_success": false,
                        "error":            "DNS timeout",
                })
                if !failed {
                        t.Error("expected failed")
                }
                if msg != "DNS timeout" {
                        t.Errorf("msg = %q", msg)
                }
        })

        t.Run("success false without error string", func(t *testing.T) {
                failed, _ := isAnalysisFailure(map[string]any{
                        "analysis_success": false,
                })
                if failed {
                        t.Error("expected not failed when no error key")
                }
        })

        t.Run("success false with non-string error", func(t *testing.T) {
                failed, _ := isAnalysisFailure(map[string]any{
                        "analysis_success": false,
                        "error":            123,
                })
                if failed {
                        t.Error("expected not failed when error is non-string")
                }
        })
}
