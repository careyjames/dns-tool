package handlers

import (
        "context"
        "encoding/json"
        "net/http"
        "net/http/httptest"
        "testing"

        "dnstool/go-server/internal/db"

        "github.com/gin-gonic/gin"
)

func TestEnrichViewDataMetricsSnapshotPath_CB15(t *testing.T) {
        gin.SetMode(gin.TestMode)
        h := &AnalysisHandler{DB: &db.Database{}}

        results := map[string]any{
                "_icae_snapshot": map[string]any{
                        "overall_maturity": "Operational",
                        "unified_confidence": map[string]any{
                                "level":            "High",
                                "score":            0.85,
                                "accuracy_factor":  0.9,
                                "currency_factor":  0.8,
                                "maturity_ceiling": 0.95,
                                "maturity_level":   "Operational",
                                "weakest_link":     "DKIM",
                                "weakest_detail":   "No DKIM found",
                                "explanation":      "Test",
                                "protocol_count":   float64(7),
                        },
                },
        }

        data := gin.H{}
        panicked := false
        func() {
                defer func() {
                        if r := recover(); r != nil {
                                panicked = true
                        }
                }()
                h.enrichViewDataMetrics(context.Background(), data, results, "example.com", 0)
        }()
        if panicked {
                t.Error("enrichViewDataMetrics should not panic with nil queries in snapshot path")
        }
}

func TestEnrichViewDataMetricsNonSnapshotPath_CB15(t *testing.T) {
        gin.SetMode(gin.TestMode)
        h := &AnalysisHandler{DB: &db.Database{}}

        results := map[string]any{
                "some_key": "some_value",
        }

        data := gin.H{}
        panicked := false
        func() {
                defer func() {
                        if r := recover(); r != nil {
                                panicked = true
                        }
                }()
                h.enrichViewDataMetrics(context.Background(), data, results, "example.com", 1)
        }()
        if panicked {
                t.Error("enrichViewDataMetrics should not panic with nil queries in non-snapshot path")
        }
}

func TestEnrichViewDataMetricsSnapshotNoAnalysisID_CB15(t *testing.T) {
        gin.SetMode(gin.TestMode)
        h := &AnalysisHandler{DB: &db.Database{}}

        results := map[string]any{
                "_icae_snapshot": map[string]any{
                        "overall_maturity": "Baseline",
                },
        }
        data := gin.H{}
        panicked := false
        func() {
                defer func() {
                        if r := recover(); r != nil {
                                panicked = true
                        }
                }()
                h.enrichViewDataMetrics(context.Background(), data, results, "test.com", 0)
        }()
        if panicked {
                t.Error("enrichViewDataMetrics should not panic with snapshot and id=0")
        }
}

func TestExportSubdomainsCSVNoPanic_CB15(t *testing.T) {
        gin.SetMode(gin.TestMode)

        t.Run("empty domain redirects", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest(http.MethodGet, "/export/subdomains", nil)

                h := &AnalysisHandler{DB: &db.Database{}}
                func() {
                        defer func() {
                                if r := recover(); r != nil {
                                        t.Fatalf("unexpected panic on empty domain: %v", r)
                                }
                        }()
                        h.ExportSubdomainsCSV(c)
                }()
                if w.Code != http.StatusFound {
                        t.Errorf("expected 302, got %d", w.Code)
                }
        })

        t.Run("invalid domain redirects", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest(http.MethodGet, "/export/subdomains?domain=!!bad!!", nil)

                h := &AnalysisHandler{DB: &db.Database{}}
                func() {
                        defer func() {
                                if r := recover(); r != nil {
                                        t.Fatalf("unexpected panic on invalid domain: %v", r)
                                }
                        }()
                        h.ExportSubdomainsCSV(c)
                }()
                if w.Code != http.StatusFound {
                        t.Errorf("expected 302, got %d", w.Code)
                }
        })
}

func TestNormalizeEmailAnswer_CB15(t *testing.T) {
        t.Run("Yes with emdash", func(t *testing.T) {
                verdicts := map[string]interface{}{
                        "email_answer": "Yes — Spoofing is possible",
                }
                normalizeEmailAnswer(verdicts)
                if verdicts["email_answer_short"] != "Yes" {
                        t.Errorf("short = %v, want Yes", verdicts["email_answer_short"])
                }
                if verdicts["email_answer_color"] != "danger" {
                        t.Errorf("color = %v, want danger", verdicts["email_answer_color"])
                }
                if verdicts["email_answer_reason"] != "Spoofing is possible" {
                        t.Errorf("reason = %v", verdicts["email_answer_reason"])
                }
        })

        t.Run("No with emdash", func(t *testing.T) {
                verdicts := map[string]interface{}{
                        "email_answer": "No — Well protected",
                }
                normalizeEmailAnswer(verdicts)
                if verdicts["email_answer_short"] != "No" {
                        t.Errorf("short = %v, want No", verdicts["email_answer_short"])
                }
                if verdicts["email_answer_color"] != "success" {
                        t.Errorf("color = %v, want success", verdicts["email_answer_color"])
                }
        })

        t.Run("Uncertain with emdash", func(t *testing.T) {
                verdicts := map[string]interface{}{
                        "email_answer": "Uncertain — Needs review",
                }
                normalizeEmailAnswer(verdicts)
                if verdicts["email_answer_short"] != "Uncertain" {
                        t.Errorf("short = %v, want Uncertain", verdicts["email_answer_short"])
                }
                if verdicts["email_answer_color"] != "warning" {
                        t.Errorf("color = %v, want warning", verdicts["email_answer_color"])
                }
        })

        t.Run("existing short answer preserved", func(t *testing.T) {
                verdicts := map[string]interface{}{
                        "email_answer":       "Yes — Something",
                        "email_answer_short": "Already Set",
                }
                normalizeEmailAnswer(verdicts)
                if verdicts["email_answer_short"] != "Already Set" {
                        t.Errorf("short answer should be preserved, got %v", verdicts["email_answer_short"])
                }
        })

        t.Run("empty answer", func(t *testing.T) {
                verdicts := map[string]interface{}{
                        "email_answer": "",
                }
                normalizeEmailAnswer(verdicts)
                if _, ok := verdicts["email_answer_short"]; ok {
                        t.Error("empty answer should not set short")
                }
        })

        t.Run("no email_answer key", func(t *testing.T) {
                verdicts := map[string]interface{}{}
                normalizeEmailAnswer(verdicts)
                if _, ok := verdicts["email_answer_short"]; ok {
                        t.Error("missing key should not set short")
                }
        })

        t.Run("non-string email_answer", func(t *testing.T) {
                verdicts := map[string]interface{}{
                        "email_answer": 12345,
                }
                normalizeEmailAnswer(verdicts)
                if _, ok := verdicts["email_answer_short"]; ok {
                        t.Error("non-string should not set short")
                }
        })

        t.Run("Likely with emdash", func(t *testing.T) {
                verdicts := map[string]interface{}{
                        "email_answer": "Likely — Weak DMARC",
                }
                normalizeEmailAnswer(verdicts)
                if verdicts["email_answer_color"] != "danger" {
                        t.Errorf("color = %v, want danger", verdicts["email_answer_color"])
                }
        })

        t.Run("Unlikely with emdash", func(t *testing.T) {
                verdicts := map[string]interface{}{
                        "email_answer": "Unlikely — DMARC reject",
                }
                normalizeEmailAnswer(verdicts)
                if verdicts["email_answer_color"] != "success" {
                        t.Errorf("color = %v, want success", verdicts["email_answer_color"])
                }
        })

        t.Run("unknown prefix defaults to warning", func(t *testing.T) {
                verdicts := map[string]interface{}{
                        "email_answer": "Maybe — Something else",
                }
                normalizeEmailAnswer(verdicts)
                if verdicts["email_answer_color"] != "warning" {
                        t.Errorf("color = %v, want warning", verdicts["email_answer_color"])
                }
        })
}

func TestMissionCriticalDomainsFromBaseURL_CB15(t *testing.T) {
        t.Run("empty string", func(t *testing.T) {
                domains := missionCriticalDomainsFromBaseURL("")
                if len(domains) != 1 || domains[0] != "" {
                        t.Errorf("expected [''], got %v", domains)
                }
        })

        t.Run("just scheme", func(t *testing.T) {
                domains := missionCriticalDomainsFromBaseURL("https://")
                if len(domains) != 1 {
                        t.Errorf("expected 1, got %d: %v", len(domains), domains)
                }
        })

        t.Run("IP address", func(t *testing.T) {
                domains := missionCriticalDomainsFromBaseURL("https://192.168.1.1:8080")
                if len(domains) != 2 {
                        t.Errorf("expected 2 entries for IP (splits on first dot), got %d: %v", len(domains), domains)
                }
                if domains[1] != "192.168.1.1" {
                        t.Errorf("host = %q, want 192.168.1.1", domains[1])
                }
        })

        t.Run("deep subdomain", func(t *testing.T) {
                domains := missionCriticalDomainsFromBaseURL("https://a.b.c.d.example.com")
                if len(domains) != 2 {
                        t.Errorf("expected 2 domains, got %d: %v", len(domains), domains)
                }
                if domains[0] != "b.c.d.example.com" {
                        t.Errorf("root = %q", domains[0])
                }
                if domains[1] != "a.b.c.d.example.com" {
                        t.Errorf("host = %q", domains[1])
                }
        })

        t.Run("two-part domain", func(t *testing.T) {
                domains := missionCriticalDomainsFromBaseURL("https://example.com")
                if len(domains) != 1 {
                        t.Errorf("expected 1, got %d: %v", len(domains), domains)
                }
                if domains[0] != "example.com" {
                        t.Errorf("domain = %q", domains[0])
                }
        })

        t.Run("path included in host", func(t *testing.T) {
                domains := missionCriticalDomainsFromBaseURL("https://app.example.com/some/path")
                if len(domains) < 1 {
                        t.Fatal("expected at least 1 domain")
                }
                hostFound := false
                for _, d := range domains {
                        if d == "app.example.com/some/path" {
                                hostFound = true
                        }
                }
                if !hostFound {
                        found := false
                        for _, d := range domains {
                                if d == "app.example.com" {
                                        found = true
                                }
                        }
                        if !found {
                                t.Errorf("expected host or full URL in domains, got %v", domains)
                        }
                }
        })

        t.Run("http scheme", func(t *testing.T) {
                domains := missionCriticalDomainsFromBaseURL("http://dns.example.org")
                if len(domains) != 2 {
                        t.Errorf("expected 2, got %d: %v", len(domains), domains)
                }
        })
}

func TestBuildSuggestedConfigNilQueries_CB15(t *testing.T) {
        panicked := false
        func() {
                defer func() {
                        if r := recover(); r != nil {
                                panicked = true
                        }
                }()
                result := buildSuggestedConfig(context.Background(), nil, "example.com", 1)
                if result != nil {
                        t.Error("expected nil result with nil queries")
                }
        }()
        if !panicked {
                t.Error("buildSuggestedConfig should panic with nil queries")
        }
}

func TestGetJSONFromResults_CB15(t *testing.T) {
        t.Run("top-level section only", func(t *testing.T) {
                results := map[string]any{
                        "domain": "example.com",
                }
                raw := getJSONFromResults(results, "domain", "")
                if raw == nil {
                        t.Fatal("expected non-nil for top-level key")
                }
                var s string
                if json.Unmarshal(raw, &s) != nil {
                        t.Error("expected valid JSON string")
                }
                if s != "example.com" {
                        t.Errorf("got %q", s)
                }
        })

        t.Run("nested map with key", func(t *testing.T) {
                results := map[string]any{
                        "spf_analysis": map[string]any{
                                "record":  "v=spf1 -all",
                                "status":  "pass",
                                "lookups": float64(3),
                        },
                }
                raw := getJSONFromResults(results, "spf_analysis", "record")
                if raw == nil {
                        t.Fatal("expected non-nil")
                }
                var val string
                if json.Unmarshal(raw, &val) != nil {
                        t.Error("expected valid JSON")
                }
                if val != "v=spf1 -all" {
                        t.Errorf("got %q", val)
                }
        })

        t.Run("numeric value", func(t *testing.T) {
                results := map[string]any{
                        "section": map[string]any{
                                "count": float64(42),
                        },
                }
                raw := getJSONFromResults(results, "section", "count")
                if raw == nil {
                        t.Fatal("expected non-nil")
                }
                var n float64
                if json.Unmarshal(raw, &n) != nil {
                        t.Error("expected valid JSON number")
                }
                if n != 42 {
                        t.Errorf("got %f", n)
                }
        })

        t.Run("boolean value", func(t *testing.T) {
                results := map[string]any{
                        "section": map[string]any{
                                "valid": true,
                        },
                }
                raw := getJSONFromResults(results, "section", "valid")
                if raw == nil {
                        t.Fatal("expected non-nil")
                }
        })

        t.Run("nil results map", func(t *testing.T) {
                raw := getJSONFromResults(nil, "section", "key")
                if raw != nil {
                        t.Error("expected nil for nil results")
                }
        })

        t.Run("empty results map", func(t *testing.T) {
                raw := getJSONFromResults(map[string]any{}, "section", "key")
                if raw != nil {
                        t.Error("expected nil for empty results")
                }
        })

        t.Run("section is not a map", func(t *testing.T) {
                results := map[string]any{
                        "section": "just_a_string",
                }
                raw := getJSONFromResults(results, "section", "key")
                if raw != nil {
                        t.Error("expected nil when section is not a map")
                }
        })

        t.Run("section with empty key returns whole section", func(t *testing.T) {
                results := map[string]any{
                        "section": map[string]any{"a": 1, "b": 2},
                }
                raw := getJSONFromResults(results, "section", "")
                if raw == nil {
                        t.Fatal("expected non-nil")
                }
                var m map[string]any
                if json.Unmarshal(raw, &m) != nil {
                        t.Error("expected valid JSON object")
                }
        })

        t.Run("array value", func(t *testing.T) {
                results := map[string]any{
                        "records": map[string]any{
                                "ns": []string{"ns1.example.com", "ns2.example.com"},
                        },
                }
                raw := getJSONFromResults(results, "records", "ns")
                if raw == nil {
                        t.Fatal("expected non-nil for array value")
                }
                var arr []string
                if json.Unmarshal(raw, &arr) != nil {
                        t.Error("expected valid JSON array")
                }
                if len(arr) != 2 {
                        t.Errorf("expected 2 elements, got %d", len(arr))
                }
        })
}

func TestCsvEscape_CB15(t *testing.T) {
        tests := []struct {
                input string
                want  string
        }{
                {"simple", "simple"},
                {"has,comma", "\"has,comma\""},
                {"has\"quote", "\"has\"\"quote\""},
                {"has\nnewline", "\"has\nnewline\""},
                {"", ""},
                {"has\rreturn", "\"has\rreturn\""},
        }
        for _, tt := range tests {
                got := csvEscape(tt.input)
                if got != tt.want {
                        t.Errorf("csvEscape(%q) = %q, want %q", tt.input, got, tt.want)
                }
        }
}

func TestRestoreUnifiedConfidenceWrongTypes_CB15(t *testing.T) {
        m := map[string]any{
                "level":          42,
                "score":          "not a number",
                "protocol_count": "nope",
        }
        uc := restoreUnifiedConfidence(m)
        if uc.Level != "" {
                t.Errorf("wrong type for level should yield empty, got %q", uc.Level)
        }
        if uc.Score != 0 {
                t.Errorf("wrong type for score should yield 0, got %f", uc.Score)
        }
        if uc.ProtocolCount != 0 {
                t.Errorf("wrong type for protocol_count should yield 0, got %d", uc.ProtocolCount)
        }
}

func TestResolveReportMode_CB15(t *testing.T) {
        gin.SetMode(gin.TestMode)

        t.Run("default mode", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
                mode := resolveReportMode(c)
                if mode != "E" {
                        t.Errorf("default mode = %q, want E", mode)
                }
        })

        t.Run("covert query param", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest(http.MethodGet, "/?covert=1", nil)
                mode := resolveReportMode(c)
                if mode != "C" {
                        t.Errorf("covert mode = %q, want C", mode)
                }
        })
}

func TestReportModeTemplate_CB15(t *testing.T) {
        tests := []struct {
                mode string
                want string
        }{
                {"C", "results_covert.html"},
                {"CZ", "results_covert.html"},
                {"B", "results_executive.html"},
                {"E", "results.html"},
                {"Z", "results.html"},
        }
        for _, tt := range tests {
                got := reportModeTemplate(tt.mode)
                if got != tt.want {
                        t.Errorf("reportModeTemplate(%q) = %q, want %q", tt.mode, got, tt.want)
                }
        }
}

func TestIsCovertMode_CB15(t *testing.T) {
        tests := []struct {
                mode string
                want bool
        }{
                {"C", true},
                {"CZ", true},
                {"EC", true},
                {"E", false},
                {"Z", false},
                {"B", false},
        }
        for _, tt := range tests {
                got := isCovertMode(tt.mode)
                if got != tt.want {
                        t.Errorf("isCovertMode(%q) = %v, want %v", tt.mode, got, tt.want)
                }
        }
}
