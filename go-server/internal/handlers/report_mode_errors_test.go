package handlers

import (
        "encoding/json"
        "fmt"
        "net/http"
        "net/http/httptest"
        "net/url"
        "strings"
        "testing"
        "time"

        "dnstool/go-server/internal/dbq"
        "dnstool/go-server/internal/icuae"

        "github.com/gin-gonic/gin"
)

func init() {
        gin.SetMode(gin.TestMode)
}

func TestResolveReportMode(t *testing.T) {
        tests := []struct {
                name     string
                param    string
                query    string
                expected string
        }{
                {"default no param", "", "", "E"},
                {"param C", "C", "", "C"},
                {"param c lowercase", "c", "", "C"},
                {"param CZ", "CZ", "", "CZ"},
                {"param cz lowercase", "cz", "", "CZ"},
                {"param Z", "Z", "", "Z"},
                {"param EC", "EC", "", "EC"},
                {"param B", "B", "", "B"},
                {"param unknown", "X", "", "E"},
                {"covert query", "", "1", "C"},
                {"covert query 0", "", "0", "E"},
                {"param overrides query", "B", "1", "B"},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        w := httptest.NewRecorder()
                        c, engine := gin.CreateTestContext(w)

                        path := "/test"
                        if tt.param != "" {
                                path = "/test/" + tt.param
                        }

                        queryStr := ""
                        if tt.query != "" {
                                queryStr = "?covert=" + tt.query
                        }

                        if tt.param != "" {
                                engine.GET("/test/:mode", func(ctx *gin.Context) {
                                        result := resolveReportMode(ctx)
                                        ctx.String(http.StatusOK, result)
                                })
                        } else {
                                engine.GET("/test", func(ctx *gin.Context) {
                                        result := resolveReportMode(ctx)
                                        ctx.String(http.StatusOK, result)
                                })
                        }

                        c.Request = httptest.NewRequest(http.MethodGet, path+queryStr, nil)
                        engine.ServeHTTP(w, c.Request)

                        got := w.Body.String()
                        if got != tt.expected {
                                t.Errorf("resolveReportMode() = %q, want %q", got, tt.expected)
                        }
                })
        }
}

func TestApplyDevNullHeaders_CB3(t *testing.T) {
        t.Run("devNull true sets headers", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

                applyDevNullHeaders(c, true)

                if w.Header().Get("X-Hacker") == "" {
                        t.Error("expected X-Hacker header when devNull=true")
                }
                if w.Header().Get("X-Persistence") != "/dev/null" {
                        t.Errorf("expected X-Persistence=/dev/null, got %q", w.Header().Get("X-Persistence"))
                }
        })

        t.Run("devNull false no headers", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

                applyDevNullHeaders(c, false)

                if w.Header().Get("X-Hacker") != "" {
                        t.Error("expected no X-Hacker header when devNull=false")
                }
                if w.Header().Get("X-Persistence") != "" {
                        t.Error("expected no X-Persistence header when devNull=false")
                }
        })
}

func TestExtractCustomSelectors(t *testing.T) {
        t.Run("both selectors provided", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)

                form := url.Values{}
                form.Set("dkim_selector1", "selector1")
                form.Set("dkim_selector2", "selector2")
                c.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
                c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

                selectors := extractCustomSelectors(c)
                if len(selectors) != 2 {
                        t.Fatalf("expected 2 selectors, got %d", len(selectors))
                }
                if selectors[0] != "selector1" || selectors[1] != "selector2" {
                        t.Errorf("selectors = %v", selectors)
                }
        })

        t.Run("only first selector", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)

                form := url.Values{}
                form.Set("dkim_selector1", "myselector")
                c.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
                c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

                selectors := extractCustomSelectors(c)
                if len(selectors) != 1 {
                        t.Fatalf("expected 1 selector, got %d", len(selectors))
                }
        })

        t.Run("empty selectors", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)

                c.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(""))
                c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

                selectors := extractCustomSelectors(c)
                if len(selectors) != 0 {
                        t.Errorf("expected 0 selectors, got %d", len(selectors))
                }
        })

        t.Run("whitespace-only selectors trimmed", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)

                form := url.Values{}
                form.Set("dkim_selector1", "  ")
                form.Set("dkim_selector2", "  valid  ")
                c.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
                c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

                selectors := extractCustomSelectors(c)
                if len(selectors) != 1 {
                        t.Fatalf("expected 1 selector (whitespace trimmed), got %d", len(selectors))
                }
                if selectors[0] != "valid" {
                        t.Errorf("expected 'valid', got %q", selectors[0])
                }
        })
}

func TestResolveCovertMode(t *testing.T) {
        tests := []struct {
                name     string
                domain   string
                covertQ  string
                covertP  string
                expected string
        }{
                {"standard domain no covert", "example.com", "", "", "E"},
                {"standard domain covert query", "example.com", "1", "", "C"},
                {"standard domain covert post", "example.com", "", "1", "C"},
                {"tld no covert", "com", "", "", "Z"},
                {"tld with covert", "com", "1", "", "CZ"},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        w := httptest.NewRecorder()
                        c, engine := gin.CreateTestContext(w)

                        engine.POST("/test", func(ctx *gin.Context) {
                                result := resolveCovertMode(ctx, tt.domain)
                                ctx.String(http.StatusOK, result)
                        })

                        form := url.Values{}
                        if tt.covertP != "" {
                                form.Set("covert", tt.covertP)
                        }

                        queryStr := ""
                        if tt.covertQ != "" {
                                queryStr = "?covert=" + tt.covertQ
                        }

                        c.Request = httptest.NewRequest(http.MethodPost, "/test"+queryStr, strings.NewReader(form.Encode()))
                        c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
                        engine.ServeHTTP(w, c.Request)

                        got := w.Body.String()
                        if got != tt.expected {
                                t.Errorf("resolveCovertMode(%q) = %q, want %q", tt.domain, got, tt.expected)
                        }
                })
        }
}

func TestExtractReportsAndDurations(t *testing.T) {
        t.Run("empty analyses", func(t *testing.T) {
                reports, durations := extractReportsAndDurations(nil)
                if len(reports) != 0 {
                        t.Errorf("expected 0 reports, got %d", len(reports))
                }
                if len(durations) != 0 {
                        t.Errorf("expected 0 durations, got %d", len(durations))
                }
        })

        t.Run("analysis with no full_results", func(t *testing.T) {
                analyses := []dbq.DomainAnalysis{
                        {ID: 1, FullResults: nil},
                }
                reports, durations := extractReportsAndDurations(analyses)
                if len(reports) != 0 {
                        t.Errorf("expected 0 reports, got %d", len(reports))
                }
                if len(durations) != 0 {
                        t.Errorf("expected 0 durations, got %d", len(durations))
                }
        })

        t.Run("analysis with duration but no currency report", func(t *testing.T) {
                dur := 2.5
                fr := map[string]any{"spf_analysis": map[string]any{"status": "pass"}}
                frJSON, _ := json.Marshal(fr)
                analyses := []dbq.DomainAnalysis{
                        {ID: 1, FullResults: frJSON, AnalysisDuration: &dur},
                }
                reports, durations := extractReportsAndDurations(analyses)
                if len(reports) != 0 {
                        t.Errorf("expected 0 reports (no currency_report), got %d", len(reports))
                }
                if len(durations) != 1 {
                        t.Fatalf("expected 1 duration, got %d", len(durations))
                }
                if durations[0] != 2500 {
                        t.Errorf("expected 2500ms, got %f", durations[0])
                }
        })

        t.Run("analysis with currency report", func(t *testing.T) {
                cr := icuae.CurrencyReport{
                        OverallGrade: "A",
                        OverallScore: 0.95,
                }
                dur := 1.0
                fr := map[string]any{
                        "currency_report": cr,
                }
                frJSON, _ := json.Marshal(fr)
                analyses := []dbq.DomainAnalysis{
                        {ID: 1, FullResults: frJSON, AnalysisDuration: &dur},
                }
                reports, durations := extractReportsAndDurations(analyses)
                if len(durations) != 1 {
                        t.Fatalf("expected 1 duration, got %d", len(durations))
                }
                if len(reports) != 1 {
                        t.Fatalf("expected 1 report, got %d", len(reports))
                }
        })

        t.Run("invalid JSON skipped", func(t *testing.T) {
                analyses := []dbq.DomainAnalysis{
                        {ID: 1, FullResults: []byte("not valid json")},
                }
                reports, durations := extractReportsAndDurations(analyses)
                if len(reports) != 0 {
                        t.Errorf("expected 0 reports for invalid JSON, got %d", len(reports))
                }
                if len(durations) != 0 {
                        t.Errorf("expected 0 durations for invalid JSON, got %d", len(durations))
                }
        })

        t.Run("nil duration skipped", func(t *testing.T) {
                fr := map[string]any{"test": true}
                frJSON, _ := json.Marshal(fr)
                analyses := []dbq.DomainAnalysis{
                        {ID: 1, FullResults: frJSON, AnalysisDuration: nil},
                }
                _, durations := extractReportsAndDurations(analyses)
                if len(durations) != 0 {
                        t.Errorf("expected 0 durations for nil duration, got %d", len(durations))
                }
        })
}

func TestComputeSummary(t *testing.T) {
        h := &AnalyticsHandler{}

        t.Run("empty days", func(t *testing.T) {
                s := h.computeSummary(nil, nil)
                if s.DaysTracked != 0 {
                        t.Errorf("DaysTracked = %d, want 0", s.DaysTracked)
                }
                if s.TotalPageviews != 0 {
                        t.Errorf("TotalPageviews = %d", s.TotalPageviews)
                }
        })

        t.Run("with data", func(t *testing.T) {
                days := []AnalyticsDay{
                        {
                                Pageviews:             100,
                                UniqueVisitors:        50,
                                AnalysesRun:           10,
                                UniqueDomainsAnalyzed: 5,
                                ReferrerSources:       map[string]int{"google": 30, "direct": 70},
                                TopPages:              map[string]int{"/": 80, "/about": 20},
                        },
                        {
                                Pageviews:             200,
                                UniqueVisitors:        100,
                                AnalysesRun:           20,
                                UniqueDomainsAnalyzed: 10,
                                ReferrerSources:       map[string]int{"google": 50, "bing": 30},
                                TopPages:              map[string]int{"/": 150, "/stats": 50},
                        },
                }

                s := h.computeSummary(nil, days)
                if s.DaysTracked != 2 {
                        t.Errorf("DaysTracked = %d, want 2", s.DaysTracked)
                }
                if s.TotalPageviews != 300 {
                        t.Errorf("TotalPageviews = %d, want 300", s.TotalPageviews)
                }
                if s.TotalUniqueVisitors != 150 {
                        t.Errorf("TotalUniqueVisitors = %d, want 150", s.TotalUniqueVisitors)
                }
                if s.TotalAnalyses != 30 {
                        t.Errorf("TotalAnalyses = %d, want 30", s.TotalAnalyses)
                }
                if s.TotalUniqueDomains != 15 {
                        t.Errorf("TotalUniqueDomains = %d, want 15", s.TotalUniqueDomains)
                }
                if s.AvgDailyPageviews != 150 {
                        t.Errorf("AvgDailyPageviews = %d, want 150", s.AvgDailyPageviews)
                }
                if s.AvgDailyVisitors != 75 {
                        t.Errorf("AvgDailyVisitors = %d, want 75", s.AvgDailyVisitors)
                }
                if len(s.TopReferrers) == 0 {
                        t.Error("expected non-empty TopReferrers")
                }
                if len(s.TopPages) == 0 {
                        t.Error("expected non-empty TopPages")
                }
        })

        t.Run("single day", func(t *testing.T) {
                days := []AnalyticsDay{
                        {Pageviews: 50, UniqueVisitors: 25},
                }
                s := h.computeSummary(nil, days)
                if s.AvgDailyPageviews != 50 {
                        t.Errorf("AvgDailyPageviews = %d, want 50", s.AvgDailyPageviews)
                }
        })
}

func TestMergeTTLValues_CB3(t *testing.T) {
        t.Run("basic merge", func(t *testing.T) {
                ttls := make(map[string]uint32)
                m := map[string]any{"A": float64(300), "MX": float64(3600)}
                mergeTTLValues(ttls, m, false)
                if ttls["A"] != 300 {
                        t.Errorf("A TTL = %d, want 300", ttls["A"])
                }
                if ttls["MX"] != 3600 {
                        t.Errorf("MX TTL = %d, want 3600", ttls["MX"])
                }
        })

        t.Run("overwrite when skipExisting is false", func(t *testing.T) {
                ttls := map[string]uint32{"A": 100}
                m := map[string]any{"A": float64(300)}
                mergeTTLValues(ttls, m, false)
                if ttls["A"] != 300 {
                        t.Errorf("A TTL = %d, want 300 (overwritten)", ttls["A"])
                }
        })

        t.Run("skip existing when skipExisting is true", func(t *testing.T) {
                ttls := map[string]uint32{"A": 100}
                m := map[string]any{"A": float64(300)}
                mergeTTLValues(ttls, m, true)
                if ttls["A"] != 100 {
                        t.Errorf("A TTL = %d, want 100 (skipped)", ttls["A"])
                }
        })

        t.Run("json.Number handling", func(t *testing.T) {
                ttls := make(map[string]uint32)
                m := map[string]any{"NS": json.Number("86400")}
                mergeTTLValues(ttls, m, false)
                if ttls["NS"] != 86400 {
                        t.Errorf("NS TTL = %d, want 86400", ttls["NS"])
                }
        })

        t.Run("non-numeric value ignored", func(t *testing.T) {
                ttls := make(map[string]uint32)
                m := map[string]any{"A": "not a number"}
                mergeTTLValues(ttls, m, false)
                if _, ok := ttls["A"]; ok {
                        t.Error("expected no A TTL for string value")
                }
        })
}

func TestExtractTTLMap_CB3(t *testing.T) {
        t.Run("from resolver_ttl", func(t *testing.T) {
                results := map[string]any{
                        "resolver_ttl": map[string]any{
                                "A":  float64(300),
                                "MX": float64(3600),
                        },
                }
                ttls := extractTTLMap(results)
                if ttls["A"] != 300 {
                        t.Errorf("A = %d, want 300", ttls["A"])
                }
        })

        t.Run("basic_records _ttl fallback", func(t *testing.T) {
                results := map[string]any{
                        "basic_records": map[string]any{
                                "_ttl": map[string]any{
                                        "NS": float64(86400),
                                },
                        },
                }
                ttls := extractTTLMap(results)
                if ttls["NS"] != 86400 {
                        t.Errorf("NS = %d, want 86400", ttls["NS"])
                }
        })

        t.Run("resolver_ttl takes priority", func(t *testing.T) {
                results := map[string]any{
                        "resolver_ttl": map[string]any{
                                "A": float64(300),
                        },
                        "basic_records": map[string]any{
                                "_ttl": map[string]any{
                                        "A": float64(600),
                                },
                        },
                }
                ttls := extractTTLMap(results)
                if ttls["A"] != 300 {
                        t.Errorf("A = %d, want 300 (resolver_ttl priority)", ttls["A"])
                }
        })

        t.Run("empty results", func(t *testing.T) {
                ttls := extractTTLMap(map[string]any{})
                if len(ttls) != 0 {
                        t.Errorf("expected empty TTL map, got %d entries", len(ttls))
                }
        })
}

func TestExtractEmailSubdomainRecords_CB3(t *testing.T) {
        t.Run("from auth key", func(t *testing.T) {
                auth := map[string]any{
                        "DMARC": []any{"v=DMARC1; p=reject"},
                }
                results := map[string]any{}
                recs := extractEmailSubdomainRecords(auth, results, "DMARC", "_dmarc", "example.com")
                if len(recs) != 1 {
                        t.Fatalf("expected 1 record, got %d", len(recs))
                }
                if recs[0] != "v=DMARC1; p=reject" {
                        t.Errorf("record = %q", recs[0])
                }
        })

        t.Run("fallback to analysis record", func(t *testing.T) {
                auth := map[string]any{}
                results := map[string]any{
                        "dmarc_analysis": map[string]any{
                                "record": "v=DMARC1; p=none",
                        },
                }
                recs := extractEmailSubdomainRecords(auth, results, "DMARC", "_dmarc", "example.com")
                if len(recs) != 1 || recs[0] != "v=DMARC1; p=none" {
                        t.Errorf("recs = %v", recs)
                }
        })

        t.Run("fallback to valid_records", func(t *testing.T) {
                auth := map[string]any{}
                results := map[string]any{
                        "mta_sts_analysis": map[string]any{
                                "valid_records": []any{"v=STSv1; id=abc"},
                        },
                }
                recs := extractEmailSubdomainRecords(auth, results, "MTA-STS", "_mta-sts", "example.com")
                if len(recs) != 1 {
                        t.Fatalf("expected 1 record, got %d", len(recs))
                }
        })

        t.Run("TLS-RPT maps correctly", func(t *testing.T) {
                auth := map[string]any{}
                results := map[string]any{
                        "tlsrpt_analysis": map[string]any{
                                "record": "v=TLSRPTv1; rua=mailto:tls@example.com",
                        },
                }
                recs := extractEmailSubdomainRecords(auth, results, "TLS-RPT", "_smtp._tls", "example.com")
                if len(recs) != 1 {
                        t.Fatalf("expected 1 record, got %d", len(recs))
                }
        })

        t.Run("unknown auth key returns nil", func(t *testing.T) {
                recs := extractEmailSubdomainRecords(map[string]any{}, map[string]any{}, "UNKNOWN", "_unknown", "example.com")
                if recs != nil {
                        t.Errorf("expected nil for unknown key, got %v", recs)
                }
        })

        t.Run("no records found", func(t *testing.T) {
                recs := extractEmailSubdomainRecords(map[string]any{}, map[string]any{}, "DMARC", "_dmarc", "example.com")
                if recs != nil {
                        t.Errorf("expected nil, got %v", recs)
                }
        })
}

func TestWriteRecordSection_CB3(t *testing.T) {
        t.Run("with records", func(t *testing.T) {
                var sb strings.Builder
                ttls := map[string]uint32{"A": 300}
                writeRecordSection(&sb, "A Records", "example.com.", []string{"1.2.3.4", "5.6.7.8"}, ttls, "A")
                out := sb.String()
                if !strings.Contains(out, "A Records") {
                        t.Error("expected section label")
                }
                if !strings.Contains(out, "1.2.3.4") {
                        t.Error("expected first record")
                }
                if !strings.Contains(out, "300") {
                        t.Error("expected TTL value")
                }
        })

        t.Run("empty records", func(t *testing.T) {
                var sb strings.Builder
                writeRecordSection(&sb, "AAAA Records", "example.com.", nil, nil, "AAAA")
                out := sb.String()
                if !strings.Contains(out, snapshotNoneDiscovered) {
                        t.Error("expected none discovered message")
                }
        })
}

func TestWriteSRVSection_CB3(t *testing.T) {
        t.Run("with SRV records", func(t *testing.T) {
                var sb strings.Builder
                writeSRVSection(&sb, "example.com.", []string{"_sip._tcp: 10 5 5060 sip.example.com."})
                out := sb.String()
                if !strings.Contains(out, "_sip._tcp") {
                        t.Error("expected SRV name")
                }
        })

        t.Run("SRV without colon", func(t *testing.T) {
                var sb strings.Builder
                writeSRVSection(&sb, "example.com.", []string{"10 5 5060 sip.example.com."})
                out := sb.String()
                if !strings.Contains(out, "SRV") {
                        t.Error("expected SRV record")
                }
        })

        t.Run("empty SRV records", func(t *testing.T) {
                var sb strings.Builder
                writeSRVSection(&sb, "example.com.", nil)
                out := sb.String()
                if !strings.Contains(out, snapshotNoneDiscovered) {
                        t.Error("expected none discovered message")
                }
        })
}

func TestWriteTXTSection_CB3(t *testing.T) {
        t.Run("with TXT records", func(t *testing.T) {
                var sb strings.Builder
                basic := map[string]any{
                        "TXT": []any{"v=spf1 include:example.com ~all"},
                }
                auth := map[string]any{}
                results := map[string]any{}
                ttls := map[string]uint32{"TXT": 300}
                writeTXTSection(&sb, "example.com.", basic, auth, results, "example.com", ttls)
                out := sb.String()
                if !strings.Contains(out, "TXT") {
                        t.Error("expected TXT section")
                }
                if !strings.Contains(out, "v=spf1") {
                        t.Error("expected SPF record")
                }
        })

        t.Run("no TXT records produces no output", func(t *testing.T) {
                var sb strings.Builder
                writeTXTSection(&sb, "example.com.", map[string]any{}, map[string]any{}, map[string]any{}, "example.com", nil)
                if sb.Len() != 0 {
                        t.Error("expected empty output for no TXT records")
                }
        })

        t.Run("with DMARC subrecords", func(t *testing.T) {
                var sb strings.Builder
                basic := map[string]any{}
                auth := map[string]any{
                        "DMARC": []any{"v=DMARC1; p=reject"},
                }
                results := map[string]any{}
                writeTXTSection(&sb, "example.com.", basic, auth, results, "example.com", nil)
                out := sb.String()
                if !strings.Contains(out, "_dmarc") {
                        t.Error("expected _dmarc subdomain")
                }
        })
}

func TestGetTTL_CB3(t *testing.T) {
        ttls := map[string]uint32{"A": 300, "MX": 3600}

        if got := getTTL(ttls, "A"); got != "300" {
                t.Errorf("getTTL(A) = %q, want 300", got)
        }
        if got := getTTL(ttls, "AAAA"); got != "; TTL unknown" {
                t.Errorf("getTTL(AAAA) = %q, want '; TTL unknown'", got)
        }
}

func TestEscapeTXT_CB3(t *testing.T) {
        if got := escapeTXT(`hello "world"`); got != `hello \"world\"` {
                t.Errorf("escapeTXT = %q", got)
        }
        if got := escapeTXT("no quotes"); got != "no quotes" {
                t.Errorf("escapeTXT = %q", got)
        }
}

func TestSanitizeErrorMessage_CB3(t *testing.T) {
        t.Run("nil input", func(t *testing.T) {
                label, icon := sanitizeErrorMessage(nil)
                if label != "Unknown Error" {
                        t.Errorf("label = %q", label)
                }
                if icon == "" {
                        t.Error("expected non-empty icon")
                }
        })

        t.Run("empty input", func(t *testing.T) {
                empty := ""
                label, _ := sanitizeErrorMessage(&empty)
                if label != "Unknown Error" {
                        t.Errorf("label = %q", label)
                }
        })

        t.Run("known category", func(t *testing.T) {
                msg := "dns resolution timeout occurred"
                label, icon := sanitizeErrorMessage(&msg)
                if label != "DNS Resolution Timeout" {
                        t.Errorf("label = %q", label)
                }
                if icon == "" {
                        t.Error("expected non-empty icon")
                }
        })

        t.Run("unknown error with IP redacted", func(t *testing.T) {
                msg := "failed to connect to 192.168.1.1:53"
                label, _ := sanitizeErrorMessage(&msg)
                if strings.Contains(label, "192.168") {
                        t.Error("expected IP to be redacted")
                }
        })

        t.Run("long error truncated", func(t *testing.T) {
                msg := strings.Repeat("x", 200)
                label, _ := sanitizeErrorMessage(&msg)
                if len(label) > 100 {
                        t.Errorf("label length = %d, expected truncated", len(label))
                }
        })
}

func TestTimeAgoFunction(t *testing.T) {
        if got := timeAgo(time.Now()); got != "just now" {
                t.Errorf("expected 'just now', got %q", got)
        }
        if got := timeAgo(time.Now().Add(-2 * time.Minute)); got == "just now" {
                t.Errorf("expected something other than 'just now' for 2min ago, got %q", got)
        }
}

func TestSecurityTrailsErrorMessages(t *testing.T) {
        tests := []struct {
                errMsg   string
                contains string
        }{
                {"rate_limited", "rate limit"},
                {"auth_failed", "rejected"},
                {"connection_error", "Could not connect"},
                {"unknown_error", "unexpected error"},
        }
        for _, tt := range tests {
                t.Run(tt.errMsg, func(t *testing.T) {
                        result := securityTrailsErrorMessage(fmt.Errorf("%s", tt.errMsg))
                        if result == "" {
                                t.Error("expected non-empty error message")
                        }
                })
        }
}

func TestIpInfoErrorMessage(t *testing.T) {
        tests := []struct {
                errMsg   string
                contains string
        }{
                {"rate limit exceeded", "rate limit"},
                {"invalid token", "rejected"},
                {"something else", "Could not retrieve"},
        }
        for _, tt := range tests {
                t.Run(tt.errMsg, func(t *testing.T) {
                        result := ipInfoErrorMessage(fmt.Errorf("%s", tt.errMsg))
                        if result == "" {
                                t.Error("expected non-empty error message")
                        }
                })
        }
}

func TestApplySecurityTrailsNeighborhood_CB3(t *testing.T) {
        t.Run("filters out query domain", func(t *testing.T) {
                results := map[string]any{}
                applySecurityTrailsNeighborhood(
                        []string{"example.com", "other.com", "EXAMPLE.COM"},
                        "example.com", "example.com", results,
                )
                neighborhood, ok := results["neighborhood"].([]map[string]any)
                if !ok {
                        t.Fatal("expected neighborhood to be []map[string]any")
                }
                if len(neighborhood) != 1 {
                        t.Errorf("expected 1 neighbor (excluding example.com), got %d", len(neighborhood))
                }
                if neighborhood[0]["domain"] != "other.com" {
                        t.Errorf("expected other.com, got %v", neighborhood[0]["domain"])
                }
        })

        t.Run("caps at 10", func(t *testing.T) {
                domains := make([]string, 20)
                for i := range domains {
                        domains[i] = strings.Repeat("a", i+1) + ".com"
                }
                results := map[string]any{}
                applySecurityTrailsNeighborhood(domains, "query.com", "query.com", results)
                neighborhood := results["neighborhood"].([]map[string]any)
                if len(neighborhood) > 10 {
                        t.Errorf("expected max 10 neighbors, got %d", len(neighborhood))
                }
        })

        t.Run("sets metadata", func(t *testing.T) {
                results := map[string]any{}
                applySecurityTrailsNeighborhood([]string{"a.com"}, "b.com", "b.com", results)
                if results["neighborhood_source"] != "SecurityTrails" {
                        t.Error("expected SecurityTrails source")
                }
                if results["st_enabled"] != true {
                        t.Error("expected st_enabled = true")
                }
        })
}

func TestCheckProviderLockCB3(t *testing.T) {
        t.Run("no provider", func(t *testing.T) {
                locked, reason := checkProviderLock("A", 300, "", icuae.ProviderProfile{}, false)
                if locked {
                        t.Error("expected not locked")
                }
                if reason != "" {
                        t.Errorf("reason = %q", reason)
                }
        })

        t.Run("NS always locked", func(t *testing.T) {
                locked, reason := checkProviderLock("NS", 86400, "Cloudflare", icuae.ProviderProfile{}, true)
                if !locked {
                        t.Error("expected locked for NS")
                }
                if !strings.Contains(reason, "Cloudflare") {
                        t.Error("expected provider name in reason")
                }
        })

        t.Run("cloudflare proxied lock", func(t *testing.T) {
                profile := icuae.ProviderProfile{ProxiedTTL: 300}
                locked, reason := checkProviderLock("A", 300, "Cloudflare", profile, true)
                if !locked {
                        t.Error("expected locked for Cloudflare proxied A record")
                }
                if !strings.Contains(reason, "proxied") {
                        t.Error("expected proxied mention in reason")
                }
        })

        t.Run("route53 alias lock", func(t *testing.T) {
                profile := icuae.ProviderProfile{AliasTTL: 60}
                locked, reason := checkProviderLock("A", 60, "AWS Route 53", profile, true)
                if !locked {
                        t.Error("expected locked for Route 53 alias")
                }
                if !strings.Contains(reason, "alias") {
                        t.Error("expected alias mention in reason")
                }
        })

        t.Run("provider with min TTL", func(t *testing.T) {
                profile := icuae.ProviderProfile{MinAllowedTTL: 120}
                locked, reason := checkProviderLock("A", 300, "CustomDNS", profile, true)
                if locked {
                        t.Error("expected not locked (min TTL is informational)")
                }
                if !strings.Contains(reason, "minimum TTL") {
                        t.Error("expected minimum TTL note")
                }
        })
}

func TestHasMigrationRecordCB3(t *testing.T) {
        if !hasMigrationRecord([]TTLRecordResult{{RecordType: "A"}}) {
                t.Error("expected true for A record")
        }
        if !hasMigrationRecord([]TTLRecordResult{{RecordType: "AAAA"}}) {
                t.Error("expected true for AAAA record")
        }
        if hasMigrationRecord([]TTLRecordResult{{RecordType: "MX"}}) {
                t.Error("expected false for MX only")
        }
        if hasMigrationRecord(nil) {
                t.Error("expected false for nil")
        }
}

func TestFormatTotalReductionCB3(t *testing.T) {
        tests := []struct {
                name     string
                oldQ     float64
                newQ     float64
                contains string
                empty    bool
        }{
                {"reduction", 1000, 500, "fewer", false},
                {"increase", 500, 1000, "more", false},
                {"equal", 500, 500, "", true},
                {"zero old", 0, 100, "", true},
                {"zero new", 100, 0, "", true},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := formatTotalReduction(tt.oldQ, tt.newQ)
                        if tt.empty && got != "" {
                                t.Errorf("expected empty, got %q", got)
                        }
                        if !tt.empty && !strings.Contains(got, tt.contains) {
                                t.Errorf("expected %q in result, got %q", tt.contains, got)
                        }
                })
        }
}

func TestBuildPropagationNoteCB3(t *testing.T) {
        if got := buildPropagationNote("A", 7200); !strings.Contains(got, "propagate") {
                t.Errorf("expected propagation note for high TTL A record, got %q", got)
        }
        if got := buildPropagationNote("A", 60); !strings.Contains(got, "fast") {
                t.Errorf("expected fast propagation note, got %q", got)
        }
        if got := buildPropagationNote("MX", 7200); got != "" {
                t.Errorf("expected empty for MX, got %q", got)
        }
        if got := buildPropagationNote("A", 1800); got != "" {
                t.Errorf("expected empty for mid-range TTL, got %q", got)
        }
}

func TestDetermineTunerStatusCB3(t *testing.T) {
        t.Run("locked", func(t *testing.T) {
                status, class, rec := determineTunerStatus(300, 300, true, "Provider locked", "stability")
                if status != "Provider-Locked" {
                        t.Errorf("status = %q", status)
                }
                if class != "secondary" {
                        t.Errorf("class = %q", class)
                }
                if rec != "Provider locked" {
                        t.Errorf("rec = %q", rec)
                }
        })

        t.Run("optimal", func(t *testing.T) {
                status, class, _ := determineTunerStatus(3600, 3600, false, "", "stability")
                if status != "Optimal" || class != "success" {
                        t.Errorf("status=%q, class=%q", status, class)
                }
        })

        t.Run("not set", func(t *testing.T) {
                status, class, _ := determineTunerStatus(0, 3600, false, "", "stability")
                if status != "Not Set" || class != "warning" {
                        t.Errorf("status=%q, class=%q", status, class)
                }
        })

        t.Run("acceptable range", func(t *testing.T) {
                status, class, _ := determineTunerStatus(5000, 3600, false, "", "stability")
                if status != "Acceptable" || class != "info" {
                        t.Errorf("status=%q, class=%q", status, class)
                }
        })

        t.Run("too high", func(t *testing.T) {
                status, _, rec := determineTunerStatus(86400, 3600, false, "", "stability")
                if status != "Adjust" {
                        t.Errorf("status = %q", status)
                }
                if !strings.Contains(rec, "Reduce") {
                        t.Errorf("rec = %q, expected Reduce", rec)
                }
        })

        t.Run("too low", func(t *testing.T) {
                status, _, rec := determineTunerStatus(10, 3600, false, "", "stability")
                if status != "Adjust" {
                        t.Errorf("status = %q", status)
                }
                if !strings.Contains(rec, "Increase") {
                        t.Errorf("rec = %q, expected Increase", rec)
                }
        })
}

func TestCalculateQueryReductionCB3(t *testing.T) {
        t.Run("reduction", func(t *testing.T) {
                got := calculateQueryReduction(300, 3600)
                if !strings.Contains(got, "fewer") {
                        t.Errorf("expected 'fewer', got %q", got)
                }
        })

        t.Run("increase", func(t *testing.T) {
                got := calculateQueryReduction(3600, 300)
                if !strings.Contains(got, "more") {
                        t.Errorf("expected 'more', got %q", got)
                }
        })

        t.Run("zero observed", func(t *testing.T) {
                if got := calculateQueryReduction(0, 3600); got != "" {
                        t.Errorf("expected empty, got %q", got)
                }
        })

        t.Run("zero typical", func(t *testing.T) {
                if got := calculateQueryReduction(300, 0); got != "" {
                        t.Errorf("expected empty, got %q", got)
                }
        })

        t.Run("similar values", func(t *testing.T) {
                got := calculateQueryReduction(3600, 3600)
                if got != "" {
                        t.Errorf("expected empty for same values, got %q", got)
                }
        })
}

func TestFormatHumanTTLCB3(t *testing.T) {
        tests := []struct {
                ttl      uint32
                expected string
        }{
                {86400, "1 day"},
                {172800, "2 days"},
                {3600, "1 hour"},
                {7200, "2 hours"},
                {60, "1 minute"},
                {120, "2 minutes"},
                {30, "30 seconds"},
                {0, "0 seconds"},
                {90, "90 seconds"},
        }
        for _, tt := range tests {
                t.Run(tt.expected, func(t *testing.T) {
                        if got := formatHumanTTL(tt.ttl); got != tt.expected {
                                t.Errorf("formatHumanTTL(%d) = %q, want %q", tt.ttl, got, tt.expected)
                        }
                })
        }
}

func TestBuildRoute53JSONCB3(t *testing.T) {
        got := buildRoute53JSON("A", 300)
        if !strings.Contains(got, `"Type": "A"`) {
                t.Error("expected record type A in output")
        }
        if !strings.Contains(got, `"TTL": 300`) {
                t.Error("expected TTL 300 in output")
        }
        if !strings.Contains(got, "UPSERT") {
                t.Error("expected UPSERT action")
        }
}

func TestTtlForProfileCB3(t *testing.T) {
        if got := ttlForProfile("A", "stability"); got != 3600 {
                t.Errorf("A stability = %d, want 3600", got)
        }
        if got := ttlForProfile("A", "agility"); got != 300 {
                t.Errorf("A agility = %d, want 300", got)
        }
        if got := ttlForProfile("NS", "stability"); got != 86400 {
                t.Errorf("NS stability = %d, want 86400", got)
        }
        if got := ttlForProfile("NS", "agility"); got != 3600 {
                t.Errorf("NS agility = %d, want 3600", got)
        }
}

func TestResultsDomainExistsCB3(t *testing.T) {
        if !resultsDomainExists(map[string]any{"domain_exists": true}) {
                t.Error("expected true")
        }
        if resultsDomainExists(map[string]any{"domain_exists": false}) {
                t.Error("expected false")
        }
        if !resultsDomainExists(map[string]any{}) {
                t.Error("expected true for missing key")
        }
        if !resultsDomainExists(map[string]any{"domain_exists": "not a bool"}) {
                t.Error("expected true for non-bool value")
        }
}

func TestCsvEscapeCB3(t *testing.T) {
        if got := csvEscape("simple"); got != "simple" {
                t.Errorf("got %q", got)
        }
        if got := csvEscape("has,comma"); got != `"has,comma"` {
                t.Errorf("got %q", got)
        }
        if got := csvEscape(`has "quote"`); got != `"has ""quote"""` {
                t.Errorf("got %q", got)
        }
        if got := csvEscape("has\nnewline"); !strings.HasPrefix(got, `"`) {
                t.Errorf("expected quoted, got %q", got)
        }
}

func TestCleanDomainInputCB3(t *testing.T) {
        tests := []struct {
                input    string
                expected string
        }{
                {"example.com", "example.com"},
                {"http://example.com", "example.com"},
                {"https://example.com", "example.com"},
                {"https://example.com/", "example.com"},
                {"https://example.com/path/to/page", "example.com"},
        }
        for _, tt := range tests {
                if got := cleanDomainInput(tt.input); got != tt.expected {
                        t.Errorf("cleanDomainInput(%q) = %q, want %q", tt.input, got, tt.expected)
                }
        }
}

func TestUnmarshalResultsCB3(t *testing.T) {
        t.Run("valid JSON", func(t *testing.T) {
                data := []byte(`{"status": "pass"}`)
                got := unmarshalResults(data, "Test")
                if got == nil {
                        t.Fatal("expected non-nil")
                }
                if got["status"] != "pass" {
                        t.Errorf("status = %v", got["status"])
                }
        })

        t.Run("empty", func(t *testing.T) {
                got := unmarshalResults(nil, "Test")
                if got != nil {
                        t.Error("expected nil for empty input")
                }
        })

        t.Run("invalid JSON", func(t *testing.T) {
                got := unmarshalResults([]byte("not json"), "Test")
                if got != nil {
                        t.Error("expected nil for invalid JSON")
                }
        })
}

func TestExtractPostureRiskCB3(t *testing.T) {
        t.Run("with label", func(t *testing.T) {
                results := map[string]any{
                        "posture": map[string]any{
                                "label": "Low Risk",
                                "color": "success",
                        },
                }
                label, color := extractPostureRisk(results)
                if label != "Low Risk" {
                        t.Errorf("label = %q", label)
                }
                if color != "success" {
                        t.Errorf("color = %q", color)
                }
        })

        t.Run("with grade fallback", func(t *testing.T) {
                results := map[string]any{
                        "posture": map[string]any{
                                "grade": "A+",
                        },
                }
                label, _ := extractPostureRisk(results)
                if label != "A+" {
                        t.Errorf("label = %q", label)
                }
        })

        t.Run("nil results", func(t *testing.T) {
                label, _ := extractPostureRisk(nil)
                if label != "Unknown" {
                        t.Errorf("label = %q", label)
                }
        })

        t.Run("no posture", func(t *testing.T) {
                label, _ := extractPostureRisk(map[string]any{})
                if label != "Unknown" {
                        t.Errorf("label = %q", label)
                }
        })
}

func TestRiskColorToHexCB3(t *testing.T) {
        if got := riskColorToHex("success"); got != "#3fb950" {
                t.Errorf("success = %q", got)
        }
        if got := riskColorToHex("warning"); got != "#d29922" {
                t.Errorf("warning = %q", got)
        }
        if got := riskColorToHex("danger"); got != colorDanger {
                t.Errorf("danger = %q", got)
        }
        if got := riskColorToHex("unknown"); got != colorGrey {
                t.Errorf("unknown = %q", got)
        }
}

func TestRiskColorToShieldsCB3(t *testing.T) {
        if got := riskColorToShields("success"); got != "brightgreen" {
                t.Errorf("success = %q", got)
        }
        if got := riskColorToShields("warning"); got != "yellow" {
                t.Errorf("warning = %q", got)
        }
        if got := riskColorToShields("danger"); got != "red" {
                t.Errorf("danger = %q", got)
        }
        if got := riskColorToShields("other"); got != "lightgrey" {
                t.Errorf("other = %q", got)
        }
}

func TestBadgeSVGCB3(t *testing.T) {
        svg := badgeSVG("example.com", "Low Risk (90/100)", "#3fb950")
        if len(svg) == 0 {
                t.Error("expected non-empty SVG")
        }
        svgStr := string(svg)
        if !strings.Contains(svgStr, "example.com") {
                t.Error("expected domain label in SVG")
        }
        if !strings.Contains(svgStr, "Low Risk (90/100)") {
                t.Error("expected value with score in SVG")
        }
        if !strings.Contains(svgStr, "#3fb950") {
                t.Error("expected color in SVG")
        }
}

func TestBadgeSVGCovertCB3(t *testing.T) {
        results := map[string]any{
                "posture": map[string]any{
                        "label": "Medium Risk",
                        "color": "warning",
                        "score": float64(50),
                },
                "spf_analysis":  map[string]any{"status": "success"},
                "dkim_analysis": map[string]any{"status": "success"},
        }
        svg := badgeSVGCovert("example.com", results, time.Now(), 1, "testhashtesttest", "https://dnstool.it-help.tech")
        if len(svg) == 0 {
                t.Error("expected non-empty SVG")
        }
        svgStr := string(svg)
        if !strings.Contains(svgStr, "example.com") {
                t.Error("expected domain in SVG")
        }
        if !strings.Contains(svgStr, "Partial") {
                t.Error("expected covert label 'Partial' for medium risk")
        }
}

func TestShortHashCB3(t *testing.T) {
        if got := shortHash("abcdef1234567890extra"); got != "abcdef1234567890" {
                t.Errorf("expected truncated to 16, got %q", got)
        }
        if got := shortHash("short"); got != "short" {
                t.Errorf("expected full string, got %q", got)
        }
        if got := shortHash(""); got != "" {
                t.Errorf("expected empty, got %q", got)
        }
}

func TestExtractMapSafeCB3(t *testing.T) {
        results := map[string]any{
                "basic_records": map[string]any{"A": []any{"1.2.3.4"}},
                "not_a_map":     "string value",
        }

        m := extractMapSafe(results, "basic_records")
        if m == nil {
                t.Fatal("expected non-nil map")
        }
        if _, ok := m["A"]; !ok {
                t.Error("expected A key")
        }

        m2 := extractMapSafe(results, "missing")
        if m2 == nil || len(m2) != 0 {
                t.Error("expected empty map for missing key")
        }

        m3 := extractMapSafe(results, "not_a_map")
        if m3 == nil || len(m3) != 0 {
                t.Error("expected empty map for non-map value")
        }
}

func TestExtractStringSliceCB3(t *testing.T) {
        t.Run("[]any with strings", func(t *testing.T) {
                m := map[string]any{"A": []any{"1.2.3.4", "5.6.7.8"}}
                got := extractStringSlice(m, "A")
                if len(got) != 2 {
                        t.Fatalf("expected 2, got %d", len(got))
                }
        })

        t.Run("[]string", func(t *testing.T) {
                m := map[string]any{"A": []string{"1.2.3.4"}}
                got := extractStringSlice(m, "A")
                if len(got) != 1 {
                        t.Fatalf("expected 1, got %d", len(got))
                }
        })

        t.Run("missing key", func(t *testing.T) {
                got := extractStringSlice(map[string]any{}, "A")
                if got != nil {
                        t.Error("expected nil")
                }
        })

        t.Run("non-slice value", func(t *testing.T) {
                m := map[string]any{"A": "not a slice"}
                got := extractStringSlice(m, "A")
                if got != nil {
                        t.Error("expected nil for non-slice")
                }
        })
}

func TestBuildTunerRecordCB3(t *testing.T) {
        rec := buildTunerRecord("A", 300, 3600, "Cloudflare", icuae.ProviderProfile{}, true, "stability")
        if rec.RecordType != "A" {
                t.Errorf("RecordType = %q", rec.RecordType)
        }
        if rec.ObservedTTL != 300 {
                t.Errorf("ObservedTTL = %d", rec.ObservedTTL)
        }
        if rec.TypicalTTL != 3600 {
                t.Errorf("TypicalTTL = %d", rec.TypicalTTL)
        }
        if rec.CloudflareUI == "" {
                t.Error("expected non-empty CloudflareUI")
        }
        if rec.Route53JSON == "" {
                t.Error("expected non-empty Route53JSON")
        }
        if rec.BINDSnippet == "" {
                t.Error("expected non-empty BINDSnippet")
        }
        if rec.GenericStep == "" {
                t.Error("expected non-empty GenericStep")
        }
        if rec.Status == "" {
                t.Error("expected non-empty Status")
        }
}
