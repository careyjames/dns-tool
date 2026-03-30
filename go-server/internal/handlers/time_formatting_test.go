package handlers

import (
        "strings"
        "testing"
        "time"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/dbq"

        "github.com/jackc/pgx/v5/pgtype"
)

func TestTimeAgo_CB4(t *testing.T) {
        tests := []struct {
                name     string
                offset   time.Duration
                expected string
        }{
                {"just now", 0, "just now"},
                {"30 seconds ago", 30 * time.Second, "just now"},
                {"1 minute ago", 1 * time.Minute, "1 minute ago"},
                {"5 minutes ago", 5 * time.Minute, "5 minutes ago"},
                {"1 hour ago", 1 * time.Hour, "1 hour ago"},
                {"3 hours ago", 3 * time.Hour, "3 hours ago"},
                {"1 day ago", 24 * time.Hour, "1 day ago"},
                {"7 days ago", 7 * 24 * time.Hour, "7 days ago"},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        result := timeAgo(time.Now().Add(-tt.offset))
                        if result != tt.expected {
                                t.Errorf("timeAgo(%v) = %q, want %q", tt.offset, result, tt.expected)
                        }
                })
        }
}

func TestMatchErrorCategory_CB4(t *testing.T) {
        tests := []struct {
                msg     string
                wantOK  bool
                wantLbl string
        }{
                {"connection timed out", true, "DNS Resolution Timeout"},
                {"deadline exceeded", true, "DNS Resolution Timeout"},
                {"no such host found", true, "Domain Not Found (NXDOMAIN)"},
                {"nxdomain response", true, "Domain Not Found (NXDOMAIN)"},
                {"connection refused by server", true, "Connection Refused"},
                {"connection reset by peer", true, "Connection Refused"},
                {"servfail from upstream", true, "DNS Server Failure (SERVFAIL)"},
                {"network unreachable", true, "Network Unreachable"},
                {"tls handshake failure", true, "TLS/Certificate Error"},
                {"x509 certificate expired", true, "TLS/Certificate Error"},
                {"query refused", true, "Query Refused"},
                {"rate limit exceeded", true, "Rate Limited"},
                {"throttled by server", true, "Rate Limited"},
                {"invalid domain format", true, "Invalid Input"},
                {"malformed query", true, "Invalid Input"},
                {"some random error", false, ""},
        }
        for _, tt := range tests {
                t.Run(tt.msg, func(t *testing.T) {
                        label, _, ok := matchErrorCategory(tt.msg)
                        if ok != tt.wantOK {
                                t.Errorf("matchErrorCategory(%q) ok=%v, want %v", tt.msg, ok, tt.wantOK)
                        }
                        if ok && label != tt.wantLbl {
                                t.Errorf("matchErrorCategory(%q) label=%q, want %q", tt.msg, label, tt.wantLbl)
                        }
                })
        }
}

func TestSanitizeErrorMessage_CB4(t *testing.T) {
        t.Run("nil input", func(t *testing.T) {
                label, icon := sanitizeErrorMessage(nil)
                if label != "Unknown Error" {
                        t.Errorf("expected 'Unknown Error', got %q", label)
                }
                if icon != "question-circle" {
                        t.Errorf("unexpected icon: %q", icon)
                }
        })
        t.Run("empty string", func(t *testing.T) {
                s := ""
                label, _ := sanitizeErrorMessage(&s)
                if label != "Unknown Error" {
                        t.Errorf("expected 'Unknown Error', got %q", label)
                }
        })
        t.Run("categorized error", func(t *testing.T) {
                s := "connection timed out"
                label, icon := sanitizeErrorMessage(&s)
                if label != "DNS Resolution Timeout" {
                        t.Errorf("expected 'DNS Resolution Timeout', got %q", label)
                }
                if icon != "clock" {
                        t.Errorf("unexpected icon: %q", icon)
                }
        })
        t.Run("uncategorized with IP", func(t *testing.T) {
                s := "failed to connect to 192.168.1.1:53"
                label, _ := sanitizeErrorMessage(&s)
                if strings.Contains(label, "192.168.1.1") {
                        t.Error("IP address should be redacted")
                }
                if !strings.Contains(label, "[redacted]") {
                        t.Error("should contain [redacted]")
                }
        })
        t.Run("uncategorized with path", func(t *testing.T) {
                s := "error reading /etc/resolv.conf"
                label, _ := sanitizeErrorMessage(&s)
                if strings.Contains(label, "/etc/resolv.conf") {
                        t.Error("path should be redacted")
                }
        })
        t.Run("long message truncated", func(t *testing.T) {
                s := strings.Repeat("x", 200)
                label, _ := sanitizeErrorMessage(&s)
                if len(label) > 100 {
                        t.Errorf("label should be truncated, got length %d", len(label))
                }
        })
}

func TestDetectPlatform_CB4(t *testing.T) {
        tests := []struct {
                ua       string
                expected string
        }{
                {"Mozilla/5.0 (iPhone; CPU iPhone OS 14_0)", "ios"},
                {"Mozilla/5.0 (iPad; CPU OS 14_0)", "ios"},
                {"Mozilla/5.0 (iPod touch; CPU iPhone OS 14_0)", "ios"},
                {"Mozilla/5.0 (Linux; Android 11)", "android"},
                {"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15)", "macos"},
                {"Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "windows"},
                {"Mozilla/5.0 (X11; Linux x86_64)", "linux"},
                {"curl/7.68.0", "unknown"},
                {"", "unknown"},
        }
        for _, tt := range tests {
                t.Run(tt.ua, func(t *testing.T) {
                        if result := detectPlatform(tt.ua); result != tt.expected {
                                t.Errorf("detectPlatform(%q) = %q, want %q", tt.ua, result, tt.expected)
                        }
                })
        }
}

func TestBuildPagination_CB4(t *testing.T) {
        t.Run("single page", func(t *testing.T) {
                pd := BuildPagination(1, 1, 10)
                if pd.HasPrev || pd.HasNext {
                        t.Error("single page should have no prev/next")
                }
                if pd.CurrentPage != 1 || pd.TotalPages != 1 {
                        t.Error("page values wrong")
                }
                if pd.Total != 10 {
                        t.Errorf("total should be 10, got %d", pd.Total)
                }
        })
        t.Run("middle page", func(t *testing.T) {
                pd := BuildPagination(5, 10, 100)
                if !pd.HasPrev || !pd.HasNext {
                        t.Error("middle page should have both prev and next")
                }
                if pd.PrevPage != 4 || pd.NextPage != 6 {
                        t.Errorf("prev/next wrong: %d/%d", pd.PrevPage, pd.NextPage)
                }
        })
        t.Run("first page", func(t *testing.T) {
                pd := BuildPagination(1, 10, 100)
                if pd.HasPrev {
                        t.Error("first page should have no prev")
                }
                if !pd.HasNext {
                        t.Error("first page should have next")
                }
        })
        t.Run("last page", func(t *testing.T) {
                pd := BuildPagination(10, 10, 100)
                if !pd.HasPrev {
                        t.Error("last page should have prev")
                }
                if pd.HasNext {
                        t.Error("last page should have no next")
                }
        })
}

func TestIterPages_CB4(t *testing.T) {
        t.Run("small page count", func(t *testing.T) {
                pages := iterPages(1, 5)
                if len(pages) != 5 {
                        t.Errorf("expected 5 pages, got %d", len(pages))
                }
                for i, p := range pages {
                        if p.Number != i+1 {
                                t.Errorf("page %d number = %d", i, p.Number)
                        }
                        if p.IsGap {
                                t.Error("no gaps expected in small page count")
                        }
                }
                if !pages[0].IsActive {
                        t.Error("page 1 should be active")
                }
        })
        t.Run("large page count with gaps", func(t *testing.T) {
                pages := iterPages(15, 50)
                hasGap := false
                for _, p := range pages {
                        if p.IsGap {
                                hasGap = true
                                break
                        }
                }
                if !hasGap {
                        t.Error("expected gaps in large page count")
                }
                for _, p := range pages {
                        if p.IsActive && p.Number != 15 {
                                t.Errorf("only page 15 should be active, got %d", p.Number)
                        }
                }
        })
}

func TestTopN_CB4(t *testing.T) {
        t.Run("empty map", func(t *testing.T) {
                result := topN(nil, 5)
                if len(result) != 0 {
                        t.Errorf("expected empty result, got %d", len(result))
                }
        })
        t.Run("fewer than n", func(t *testing.T) {
                m := map[string]int{"a": 3, "b": 1}
                result := topN(m, 5)
                if len(result) != 2 {
                        t.Errorf("expected 2 results, got %d", len(result))
                }
                if result[0].Count < result[1].Count {
                        t.Error("results should be sorted descending")
                }
        })
        t.Run("more than n", func(t *testing.T) {
                m := map[string]int{"a": 5, "b": 3, "c": 8, "d": 1, "e": 7}
                result := topN(m, 3)
                if len(result) != 3 {
                        t.Errorf("expected 3 results, got %d", len(result))
                }
                if result[0].Count != 8 {
                        t.Errorf("first entry should have count 8, got %d", result[0].Count)
                }
        })
}

func TestTopNPages_CB4(t *testing.T) {
        t.Run("empty map", func(t *testing.T) {
                result := topNPages(nil, 5)
                if len(result) != 0 {
                        t.Errorf("expected empty result, got %d", len(result))
                }
        })
        t.Run("sorted correctly", func(t *testing.T) {
                m := map[string]int{"/home": 10, "/about": 5, "/contact": 15}
                result := topNPages(m, 2)
                if len(result) != 2 {
                        t.Errorf("expected 2 results, got %d", len(result))
                }
                if result[0].Count != 15 {
                        t.Errorf("first entry should have count 15, got %d", result[0].Count)
                }
        })
}

func TestGetBrandPalette_CB4(t *testing.T) {
        palette := getBrandPalette()
        if len(palette) == 0 {
                t.Fatal("brand palette should not be empty")
        }
        for _, c := range palette {
                if c.Name == "" || c.Token == "" || c.Value == "" {
                        t.Errorf("brand color missing field: %+v", c)
                }
        }
}

func TestGetStatusColors_CB4(t *testing.T) {
        colors := getStatusColors()
        if len(colors) == 0 {
                t.Fatal("status colors should not be empty")
        }
        for _, c := range colors {
                if c.Name == "" || c.Value == "" {
                        t.Errorf("status color missing field: %+v", c)
                }
        }
}

func TestGetSurfaceColors_CB4(t *testing.T) {
        colors := getSurfaceColors()
        if len(colors) == 0 {
                t.Fatal("surface colors should not be empty")
        }
}

func TestGetTLPColors_CB4(t *testing.T) {
        colors := getTLPColors()
        if len(colors) == 0 {
                t.Fatal("TLP colors should not be empty")
        }
        for _, c := range colors {
                if c.Name == "" || c.Value == "" {
                        t.Errorf("TLP color missing field: %+v", c)
                }
        }
}

func TestGetCVSSColors_CB4(t *testing.T) {
        colors := getCVSSColors()
        if len(colors) == 0 {
                t.Fatal("CVSS colors should not be empty")
        }
}

func TestGetChangelog_CB4(t *testing.T) {
        entries := GetChangelog()
        if len(entries) == 0 {
                t.Fatal("changelog should not be empty")
        }
        for _, e := range entries {
                if e.Version == "" {
                        t.Error("changelog entry missing version")
                }
                if e.Title == "" {
                        t.Error("changelog entry missing title")
                }
                if e.Date == "" {
                        t.Error("changelog entry missing date")
                }
        }
}

func TestGetRecentChangelog_CB4(t *testing.T) {
        recent := GetRecentChangelog(3)
        if len(recent) > 3 {
                t.Errorf("expected at most 3 entries, got %d", len(recent))
        }
        all := GetChangelog()
        if len(all) >= 3 && len(recent) != 3 {
                t.Errorf("expected exactly 3 entries when enough exist, got %d", len(recent))
        }
}

func TestGetLegacyChangelog_CB4(t *testing.T) {
        legacy := GetLegacyChangelog()
        for _, e := range legacy {
                if !e.IsLegacy {
                        t.Errorf("legacy entry should have IsLegacy=true: %s", e.Version)
                }
        }
}

func TestBuildDailyStat_CB4(t *testing.T) {
        t.Run("all nil pointers", func(t *testing.T) {
                stat := buildDailyStat(dbq.AnalysisStat{})
                if stat.Date != "" {
                        t.Errorf("expected empty date, got %q", stat.Date)
                }
                if stat.TotalAnalyses != 0 || stat.SuccessfulAnalyses != 0 {
                        t.Error("nil pointers should yield zero values")
                }
                if stat.HasAvgTime {
                        t.Error("nil avg time should yield HasAvgTime=false")
                }
        })
        t.Run("all values set", func(t *testing.T) {
                total := int32(100)
                success := int32(90)
                failed := int32(10)
                unique := int32(50)
                avg := 2.5
                now := time.Now()
                stat := buildDailyStat(dbq.AnalysisStat{
                        Date:               pgtype.Date{Time: now, Valid: true},
                        TotalAnalyses:      &total,
                        SuccessfulAnalyses: &success,
                        FailedAnalyses:     &failed,
                        UniqueDomains:      &unique,
                        AvgAnalysisTime:    &avg,
                })
                if stat.Date == "" {
                        t.Error("expected non-empty date")
                }
                if stat.TotalAnalyses != 100 {
                        t.Errorf("expected 100 total, got %d", stat.TotalAnalyses)
                }
                if stat.SuccessfulAnalyses != 90 {
                        t.Errorf("expected 90 successful, got %d", stat.SuccessfulAnalyses)
                }
                if stat.FailedAnalyses != 10 {
                        t.Errorf("expected 10 failed, got %d", stat.FailedAnalyses)
                }
                if stat.UniqueDomains != 50 {
                        t.Errorf("expected 50 unique, got %d", stat.UniqueDomains)
                }
                if stat.AvgAnalysisTime != 2.5 {
                        t.Errorf("expected 2.5 avg, got %f", stat.AvgAnalysisTime)
                }
                if !stat.HasAvgTime {
                        t.Error("expected HasAvgTime=true")
                }
        })
}

func TestBuildCountryStat_CB4(t *testing.T) {
        t.Run("nil pointers", func(t *testing.T) {
                cs := buildCountryStat(dbq.ListCountryDistributionRow{Count: 42})
                if cs.Code != "" || cs.Name != "" {
                        t.Error("nil pointers should yield empty strings")
                }
                if cs.Flag != "" {
                        t.Error("empty code should yield empty flag")
                }
                if cs.Count != 42 {
                        t.Errorf("expected count 42, got %d", cs.Count)
                }
        })
        t.Run("valid country", func(t *testing.T) {
                code := "us"
                name := "United States"
                cs := buildCountryStat(dbq.ListCountryDistributionRow{
                        CountryCode: &code,
                        CountryName: &name,
                        Count:       100,
                })
                if cs.Code != "us" || cs.Name != "United States" {
                        t.Errorf("unexpected code/name: %q/%q", cs.Code, cs.Name)
                }
                if cs.Flag == "" {
                        t.Error("expected non-empty flag for 2-letter code")
                }
                if cs.Count != 100 {
                        t.Errorf("expected count 100, got %d", cs.Count)
                }
        })
        t.Run("single char code no flag", func(t *testing.T) {
                code := "X"
                cs := buildCountryStat(dbq.ListCountryDistributionRow{CountryCode: &code, Count: 1})
                if cs.Flag != "" {
                        t.Error("single char code should yield no flag")
                }
        })
}

func TestOpsTaskList_CB4(t *testing.T) {
        tasks := opsTaskList()
        if len(tasks) == 0 {
                t.Fatal("opsTaskList should return at least one task")
        }
        for _, task := range tasks {
                if task.ID == "" || task.Label == "" {
                        t.Errorf("task missing ID or Label: %+v", task)
                }
        }
}

func TestNewBrandColorsHandler_CB4(t *testing.T) {
        cfg := &config.Config{AppVersion: "test"}
        h := NewBrandColorsHandler(cfg)
        if h == nil {
                t.Fatal("expected non-nil handler")
        }
        if h.Config.AppVersion != "test" {
                t.Error("config not set correctly")
        }
}

func TestNewToolkitHandler_CB4(t *testing.T) {
        cfg := &config.Config{AppVersion: "test"}
        h := NewToolkitHandler(cfg)
        if h == nil {
                t.Fatal("expected non-nil handler")
        }
}

func TestResolveProbeConfig_CB4(t *testing.T) {
        t.Run("no probes no fallback", func(t *testing.T) {
                cfg := &config.Config{}
                h := NewToolkitHandler(cfg)
                _, ok := h.resolveProbeConfig("")
                if ok {
                        t.Error("expected no probe config when nothing configured")
                }
        })
        t.Run("fallback to ProbeAPIURL", func(t *testing.T) {
                cfg := &config.Config{ProbeAPIURL: "http://example.com", ProbeAPIKey: "key123"}
                h := NewToolkitHandler(cfg)
                pc, ok := h.resolveProbeConfig("")
                if !ok {
                        t.Fatal("expected probe config from fallback")
                }
                if pc.url != "http://example.com" || pc.key != "key123" {
                        t.Errorf("unexpected probe config: %+v", pc)
                }
        })
        t.Run("probes configured selects by ID", func(t *testing.T) {
                cfg := &config.Config{
                        Probes: []config.ProbeEndpoint{
                                {ID: "p1", Label: "Probe 1", URL: "http://p1.com", Key: "k1"},
                                {ID: "p2", Label: "Probe 2", URL: "http://p2.com", Key: "k2"},
                        },
                }
                h := NewToolkitHandler(cfg)
                pc, ok := h.resolveProbeConfig("p2")
                if !ok {
                        t.Fatal("expected probe config")
                }
                if pc.url != "http://p2.com" {
                        t.Errorf("expected p2 URL, got %q", pc.url)
                }
        })
        t.Run("probes configured defaults to first", func(t *testing.T) {
                cfg := &config.Config{
                        Probes: []config.ProbeEndpoint{
                                {ID: "p1", Label: "Probe 1", URL: "http://p1.com", Key: "k1"},
                                {ID: "p2", Label: "Probe 2", URL: "http://p2.com", Key: "k2"},
                        },
                }
                h := NewToolkitHandler(cfg)
                pc, ok := h.resolveProbeConfig("nonexistent")
                if !ok {
                        t.Fatal("expected probe config")
                }
                if pc.url != "http://p1.com" {
                        t.Errorf("expected default to first probe, got %q", pc.url)
                }
        })
}

func TestFlashMessageStruct_CB4(t *testing.T) {
        fm := FlashMessage{Category: "success", Message: "Done!"}
        if fm.Category != "success" || fm.Message != "Done!" {
                t.Error("FlashMessage fields not set")
        }
}

func TestAnalysisItemStruct_CB4(t *testing.T) {
        ai := AnalysisItem{
                ID:               1,
                Domain:           "example.com",
                AsciiDomain:      "example.com",
                SpfStatus:        "pass",
                DmarcStatus:      "pass",
                DkimStatus:       "pass",
                AnalysisSuccess:  true,
                AnalysisDuration: 1.5,
                CreatedAt:        "2026-01-01",
                CreatedDate:      "01/01",
                CreatedTime:      "12:00",
                ToolVersion:      "26.27.10",
        }
        if ai.ID != 1 || ai.Domain != "example.com" {
                t.Error("AnalysisItem fields not set")
        }
}

func TestDiffItemStruct_CB4(t *testing.T) {
        di := DiffItem{
                Label:   "SPF",
                Icon:    "envelope",
                Changed: true,
                StatusA: "pass",
                StatusB: "fail",
        }
        if !di.Changed || di.Label != "SPF" {
                t.Error("DiffItem fields not set")
        }
}

func TestCompareAnalysisStruct_CB4(t *testing.T) {
        ca := CompareAnalysis{
                CreatedAt:        "2026-01-01",
                ToolVersion:      "26.27.10",
                AnalysisDuration: "1.5s",
                HasToolVersion:   true,
                HasDuration:      true,
        }
        if !ca.HasToolVersion || !ca.HasDuration {
                t.Error("CompareAnalysis fields not set")
        }
}
