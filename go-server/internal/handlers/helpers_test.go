package handlers

import (
        "testing"
        "time"

        "github.com/jackc/pgx/v5/pgtype"
)

func TestReportModeTemplate(t *testing.T) {
        tests := []struct {
                mode     string
                expected string
        }{
                {"C", "results_covert.html"},
                {"CZ", "results_covert.html"},
                {"B", "results_executive.html"},
                {"E", "results.html"},
                {"Z", "results.html"},
                {"EC", "results.html"},
                {"", "results.html"},
        }
        for _, tt := range tests {
                t.Run("mode_"+tt.mode, func(t *testing.T) {
                        got := reportModeTemplate(tt.mode)
                        if got != tt.expected {
                                t.Errorf("reportModeTemplate(%q) = %q, want %q", tt.mode, got, tt.expected)
                        }
                })
        }
}

func TestIsCovertMode(t *testing.T) {
        tests := []struct {
                mode     string
                expected bool
        }{
                {"C", true},
                {"CZ", true},
                {"EC", true},
                {"E", false},
                {"B", false},
                {"Z", false},
                {"", false},
        }
        for _, tt := range tests {
                t.Run("mode_"+tt.mode, func(t *testing.T) {
                        got := isCovertMode(tt.mode)
                        if got != tt.expected {
                                t.Errorf("isCovertMode(%q) = %v, want %v", tt.mode, got, tt.expected)
                        }
                })
        }
}

func TestShortHash(t *testing.T) {
        tests := []struct {
                name     string
                input    string
                expected string
        }{
                {"short string", "abc", "abc"},
                {"exactly 16", "1234567890123456", "1234567890123456"},
                {"longer than 16", "12345678901234567890", "1234567890123456"},
                {"empty", "", ""},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := shortHash(tt.input)
                        if got != tt.expected {
                                t.Errorf("shortHash(%q) = %q, want %q", tt.input, got, tt.expected)
                        }
                })
        }
}

func TestDetectPlatform(t *testing.T) {
        tests := []struct {
                name     string
                ua       string
                expected string
        }{
                {"iPhone", "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)", "ios"},
                {"iPad", "Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X)", "ios"},
                {"iPod", "Mozilla/5.0 (iPod touch; CPU iPhone OS 16_0)", "ios"},
                {"Android", "Mozilla/5.0 (Linux; Android 13; Pixel 7)", "android"},
                {"macOS", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "macos"},
                {"Windows", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "windows"},
                {"Linux", "Mozilla/5.0 (X11; Linux x86_64)", "linux"},
                {"empty", "", "unknown"},
                {"bot", "Googlebot/2.1", "unknown"},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := detectPlatform(tt.ua)
                        if got != tt.expected {
                                t.Errorf("detectPlatform(%q) = %q, want %q", tt.ua, got, tt.expected)
                        }
                })
        }
}

func TestSanitizeErrorMessage(t *testing.T) {
        tests := []struct {
                name         string
                input        *string
                wantCategory string
                wantIcon     string
        }{
                {"nil input", nil, "Unknown Error", "question-circle"},
                {"empty string", strPtr(""), "Unknown Error", "question-circle"},
                {"timeout", strPtr("connection timed out"), "DNS Resolution Timeout", "clock"},
                {"deadline", strPtr("context deadline exceeded"), "DNS Resolution Timeout", "clock"},
                {"nxdomain", strPtr("no such host"), "Domain Not Found (NXDOMAIN)", "unlink"},
                {"nxdomain upper", strPtr("NXDOMAIN returned"), "Domain Not Found (NXDOMAIN)", "unlink"},
                {"connection refused", strPtr("connection refused by server"), "Connection Refused", "ban"},
                {"connection reset", strPtr("connection reset by peer"), "Connection Refused", "ban"},
                {"servfail", strPtr("SERVFAIL from resolver"), "DNS Server Failure (SERVFAIL)", "server"},
                {"network unreachable", strPtr("network is unreachable"), "Network Unreachable", "wifi"},
                {"tls error", strPtr("TLS handshake failed"), "TLS/Certificate Error", "lock"},
                {"x509 error", strPtr("x509 certificate has expired"), "TLS/Certificate Error", "lock"},
                {"refused", strPtr("query refused"), "Query Refused", "hand-paper"},
                {"rate limit", strPtr("rate limit exceeded"), "Rate Limited", "tachometer-alt"},
                {"throttled", strPtr("request throttled"), "Rate Limited", "tachometer-alt"},
                {"invalid", strPtr("invalid domain format"), "Invalid Input", "exclamation-triangle"},
                {"malformed", strPtr("malformed DNS response"), "Invalid Input", "exclamation-triangle"},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        cat, icon := sanitizeErrorMessage(tt.input)
                        if cat != tt.wantCategory {
                                t.Errorf("category = %q, want %q", cat, tt.wantCategory)
                        }
                        if icon != tt.wantIcon {
                                t.Errorf("icon = %q, want %q", icon, tt.wantIcon)
                        }
                })
        }

        t.Run("redacts IPs", func(t *testing.T) {
                msg := "failed to connect to 192.168.1.100:53"
                cat, _ := sanitizeErrorMessage(&msg)
                if cat == "" {
                        t.Error("expected non-empty category")
                }
        })

        t.Run("truncates long messages", func(t *testing.T) {
                long := ""
                for i := 0; i < 100; i++ {
                        long += "abcdefgh"
                }
                cat, _ := sanitizeErrorMessage(&long)
                if len(cat) > 200 {
                        t.Errorf("expected truncated message, got len %d", len(cat))
                }
        })
}

func TestFormatDiffValue(t *testing.T) {
        tests := []struct {
                name     string
                input    interface{}
                expected string
        }{
                {"nil", nil, ""},
                {"string", "hello", "hello"},
                {"number", float64(42), "42"},
                {"bool", true, "true"},
                {"map", map[string]interface{}{"a": "b"}, `{"a":"b"}`},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := formatDiffValue(tt.input)
                        if got != tt.expected {
                                t.Errorf("formatDiffValue(%v) = %q, want %q", tt.input, got, tt.expected)
                        }
                })
        }
}

func TestCsvEscape(t *testing.T) {
        tests := []struct {
                name     string
                input    string
                expected string
        }{
                {"plain", "hello", "hello"},
                {"with comma", "hello,world", `"hello,world"`},
                {"with quote", `say "hi"`, `"say ""hi"""`},
                {"with newline", "line1\nline2", "\"line1\nline2\""},
                {"empty", "", ""},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := csvEscape(tt.input)
                        if got != tt.expected {
                                t.Errorf("csvEscape(%q) = %q, want %q", tt.input, got, tt.expected)
                        }
                })
        }
}

func TestDerefString(t *testing.T) {
        s := "hello"
        if got := derefString(&s); got != "hello" {
                t.Errorf("derefString(&hello) = %q", got)
        }
        if got := derefString(nil); got != "" {
                t.Errorf("derefString(nil) = %q", got)
        }
}

func TestExtractToolVersion(t *testing.T) {
        tests := []struct {
                name     string
                results  map[string]any
                expected string
        }{
                {"present", map[string]any{"_tool_version": "1.2.3"}, "1.2.3"},
                {"missing", map[string]any{}, ""},
                {"wrong type", map[string]any{"_tool_version": 123}, ""},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := extractToolVersion(tt.results)
                        if got != tt.expected {
                                t.Errorf("got %q, want %q", got, tt.expected)
                        }
                })
        }
}

func TestResultsDomainExists(t *testing.T) {
        tests := []struct {
                name     string
                results  map[string]any
                expected bool
        }{
                {"true", map[string]any{"domain_exists": true}, true},
                {"false", map[string]any{"domain_exists": false}, false},
                {"missing", map[string]any{}, true},
                {"wrong type", map[string]any{"domain_exists": "yes"}, true},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := resultsDomainExists(tt.results)
                        if got != tt.expected {
                                t.Errorf("got %v, want %v", got, tt.expected)
                        }
                })
        }
}

func TestExtractAnalysisError(t *testing.T) {
        t.Run("no error", func(t *testing.T) {
                ok, errMsg := extractAnalysisError(map[string]any{})
                if !ok {
                        t.Error("expected ok=true")
                }
                if errMsg != nil {
                        t.Error("expected nil error message")
                }
        })

        t.Run("with error", func(t *testing.T) {
                ok, errMsg := extractAnalysisError(map[string]any{"error": "something failed"})
                if ok {
                        t.Error("expected ok=false")
                }
                if errMsg == nil || *errMsg != "something failed" {
                        t.Errorf("expected error message 'something failed', got %v", errMsg)
                }
        })

        t.Run("empty error string", func(t *testing.T) {
                ok, errMsg := extractAnalysisError(map[string]any{"error": ""})
                if !ok {
                        t.Error("expected ok=true for empty error")
                }
                if errMsg != nil {
                        t.Error("expected nil for empty error")
                }
        })
}

func TestOptionalStrings(t *testing.T) {
        a, b := optionalStrings("hello", "")
        if a == nil || *a != "hello" {
                t.Errorf("expected 'hello', got %v", a)
        }
        if b != nil {
                t.Errorf("expected nil, got %v", b)
        }

        a, b = optionalStrings("", "world")
        if a != nil {
                t.Errorf("expected nil, got %v", a)
        }
        if b == nil || *b != "world" {
                t.Errorf("expected 'world', got %v", b)
        }
}

func TestFormatTimestamp(t *testing.T) {
        t.Run("valid timestamp", func(t *testing.T) {
                ts := pgtype.Timestamp{
                        Time:  time.Date(2026, 2, 15, 14, 30, 0, 0, time.UTC),
                        Valid: true,
                }
                got := formatTimestamp(ts)
                if got != "15 Feb 2026, 14:30 UTC" {
                        t.Errorf("got %q", got)
                }
        })

        t.Run("invalid timestamp", func(t *testing.T) {
                ts := pgtype.Timestamp{Valid: false}
                got := formatTimestamp(ts)
                if got != "" {
                        t.Errorf("expected empty, got %q", got)
                }
        })
}

func TestFormatTimestampISO(t *testing.T) {
        t.Run("valid timestamp", func(t *testing.T) {
                ts := pgtype.Timestamp{
                        Time:  time.Date(2026, 2, 15, 14, 30, 0, 0, time.UTC),
                        Valid: true,
                }
                got := formatTimestampISO(ts)
                if got != "2026-02-15T14:30:00Z" {
                        t.Errorf("got %q", got)
                }
        })

        t.Run("invalid timestamp", func(t *testing.T) {
                ts := pgtype.Timestamp{Valid: false}
                got := formatTimestampISO(ts)
                if got != "" {
                        t.Errorf("expected empty, got %q", got)
                }
        })
}

func TestRoadmapDataIntegrity(t *testing.T) {
        h := NewRoadmapHandler(nil)
        if h == nil {
                t.Fatal("expected non-nil RoadmapHandler")
        }
}

func TestRoadmapItemsNonEmpty(t *testing.T) {
        done := []RoadmapItem{
                {Title: "Intelligence Confidence Audit Engine (ICAE)", Version: "129 Test Cases", Date: "Feb 2026", Type: "Feature"},
                {Title: "Intelligence Currency Assurance Engine (ICuAE)", Version: "29 Test Cases", Date: "Feb 2026", Type: "Feature"},
        }

        for i, item := range done {
                if item.Title == "" {
                        t.Errorf("done[%d] has empty Title", i)
                }
                if item.Version == "" {
                        t.Errorf("done[%d] (%s) has empty Version", i, item.Title)
                }
                if item.Date == "" {
                        t.Errorf("done[%d] (%s) has empty Date", i, item.Title)
                }
                if item.Type == "" {
                        t.Errorf("done[%d] (%s) has empty Type", i, item.Title)
                }
        }
}

func TestRoadmapConstants(t *testing.T) {
        if roadmapDateFeb2026 != "Feb 2026" {
                t.Errorf("unexpected roadmapDateFeb2026: %q", roadmapDateFeb2026)
        }
        if roadmapVersionV2620 != "v26.20.0+" {
                t.Errorf("unexpected roadmapVersionV2620: %q", roadmapVersionV2620)
        }
        if roadmapTypeFeature != "Feature" {
                t.Errorf("unexpected roadmapTypeFeature: %q", roadmapTypeFeature)
        }
}

func TestBuildDiffItems(t *testing.T) {
        diffs := []SectionDiff{
                {
                        Key: "spf", Label: "SPF", Icon: "fa-envelope",
                        StatusA: "success", StatusB: "warning", Changed: true,
                        DetailChanges: []DetailChange{
                                {Field: "Record", Old: "v=spf1 -all", New: "v=spf1 ~all"},
                        },
                },
                {
                        Key: "dmarc", Label: "DMARC", Icon: "fa-shield",
                        StatusA: "success", StatusB: "success", Changed: false,
                },
        }

        items, changes := buildDiffItems(diffs)
        if len(items) != 2 {
                t.Fatalf("expected 2 items, got %d", len(items))
        }
        if changes != 1 {
                t.Errorf("expected 1 change, got %d", changes)
        }
        if !items[0].Changed {
                t.Error("expected first item to be changed")
        }
        if items[1].Changed {
                t.Error("expected second item to be unchanged")
        }
        if len(items[0].DetailChanges) != 1 {
                t.Errorf("expected 1 detail change, got %d", len(items[0].DetailChanges))
        }
}

func TestTimeAgo(t *testing.T) {
        tests := []struct {
                name     string
                d        time.Duration
                expected string
        }{
                {"just now", 10 * time.Second, "just now"},
                {"1 minute", 90 * time.Second, "1 minute ago"},
                {"5 minutes", 5 * time.Minute, "5 minutes ago"},
                {"1 hour", 90 * time.Minute, "1 hour ago"},
                {"3 hours", 3 * time.Hour, "3 hours ago"},
                {"1 day", 36 * time.Hour, "1 day ago"},
                {"5 days", 5 * 24 * time.Hour, "5 days ago"},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := timeAgo(time.Now().Add(-tt.d))
                        if got != tt.expected {
                                t.Errorf("got %q, want %q", got, tt.expected)
                        }
                })
        }
}

func TestParseOrgDMARC(t *testing.T) {
        tests := []struct {
                name       string
                records    []string
                wantFound  bool
                wantPolicy string
        }{
                {"valid reject", []string{"v=DMARC1; p=reject; rua=mailto:a@b.com"}, true, "reject"},
                {"valid quarantine", []string{"v=DMARC1; p=quarantine"}, true, "quarantine"},
                {"valid none", []string{"v=dmarc1; p=none"}, true, "none"},
                {"no dmarc", []string{"some random text"}, false, ""},
                {"empty", []string{}, false, ""},
                {"dmarc only tag", []string{"v=DMARC1"}, true, ""},
                {"multiple records", []string{"ignore", "v=DMARC1; p=reject"}, true, "reject"},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        found, policy := parseOrgDMARC(tt.records)
                        if found != tt.wantFound {
                                t.Errorf("found = %v, want %v", found, tt.wantFound)
                        }
                        if policy != tt.wantPolicy {
                                t.Errorf("policy = %q, want %q", policy, tt.wantPolicy)
                        }
                })
        }
}

func TestDetermineDMARCScope(t *testing.T) {
        tests := []struct {
                name      string
                subDMARC  bool
                orgDMARC  bool
                orgPolicy string
                root      string
                wantScope string
        }{
                {"sub has DMARC", true, false, "", "example.com", "local"},
                {"inherited with policy", false, true, "reject", "example.com", "inherited"},
                {"inherited no policy", false, true, "", "example.com", "inherited"},
                {"none", false, false, "", "example.com", "none"},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        scope, _ := determineDMARCScope(tt.subDMARC, tt.orgDMARC, tt.orgPolicy, tt.root)
                        if scope != tt.wantScope {
                                t.Errorf("scope = %q, want %q", scope, tt.wantScope)
                        }
                })
        }
}

func TestDetermineSPFScope(t *testing.T) {
        scope, note := determineSPFScope(true)
        if scope != "local" {
                t.Errorf("scope = %q, want local", scope)
        }
        if note == "" {
                t.Error("expected non-empty note")
        }

        scope, note = determineSPFScope(false)
        if scope != "none" {
                t.Errorf("scope = %q, want none", scope)
        }
        if note == "" {
                t.Error("expected non-empty note")
        }
}

func TestIsActiveStatus(t *testing.T) {
        if !isActiveStatus("success") {
                t.Error("expected success to be active")
        }
        if !isActiveStatus("warning") {
                t.Error("expected warning to be active")
        }
        if isActiveStatus("danger") {
                t.Error("expected danger to not be active")
        }
        if isActiveStatus("unknown") {
                t.Error("expected unknown to not be active")
        }
}

func TestHasLocalMXRecords(t *testing.T) {
        tests := []struct {
                name    string
                results map[string]any
                want    bool
        }{
                {"with string MX", map[string]any{"basic_records": map[string]any{"MX": []string{"mx1.example.com"}}}, true},
                {"with any MX", map[string]any{"basic_records": map[string]any{"MX": []any{"mx1.example.com"}}}, true},
                {"empty MX", map[string]any{"basic_records": map[string]any{"MX": []string{}}}, false},
                {"no MX key", map[string]any{"basic_records": map[string]any{}}, false},
                {"no basic_records", map[string]any{}, false},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := hasLocalMXRecords(tt.results)
                        if got != tt.want {
                                t.Errorf("got %v, want %v", got, tt.want)
                        }
                })
        }
}

func TestNormalizeForCompareEdgeCases(t *testing.T) {
        t.Run("non-array", func(t *testing.T) {
                got := normalizeForCompare("hello")
                if got != "hello" {
                        t.Errorf("expected hello, got %v", got)
                }
        })

        t.Run("single element array returned as-is", func(t *testing.T) {
                arr := []interface{}{"a"}
                got := normalizeForCompare(arr)
                gotArr, ok := got.([]interface{})
                if !ok {
                        t.Fatal("expected array result")
                }
                if len(gotArr) != 1 || gotArr[0] != "a" {
                        t.Errorf("expected [a], got %v", gotArr)
                }
        })

        t.Run("sorts string array", func(t *testing.T) {
                arr := []interface{}{"c", "a", "b"}
                got := normalizeForCompare(arr)
                sorted, ok := got.([]interface{})
                if !ok {
                        t.Fatal("expected array result")
                }
                if sorted[0] != "a" || sorted[1] != "b" || sorted[2] != "c" {
                        t.Errorf("expected sorted [a,b,c], got %v", sorted)
                }
        })
}

func TestNormalizeVerdictEntry(t *testing.T) {
        t.Run("sets answer from label", func(t *testing.T) {
                verdicts := map[string]interface{}{
                        "dns_tampering": map[string]interface{}{
                                "label": "Protected",
                        },
                }
                labelMap := map[string]string{
                        "Protected": "No",
                        "Exposed":   "Yes",
                }
                normalizeVerdictEntry(verdicts, "dns_tampering", labelMap)
                v := verdicts["dns_tampering"].(map[string]interface{})
                if v["answer"] != "No" {
                        t.Errorf("answer = %v, want No", v["answer"])
                }
        })

        t.Run("skips if answer exists", func(t *testing.T) {
                verdicts := map[string]interface{}{
                        "dns_tampering": map[string]interface{}{
                                "answer": "existing",
                                "label":  "Protected",
                        },
                }
                labelMap := map[string]string{"Protected": "No"}
                normalizeVerdictEntry(verdicts, "dns_tampering", labelMap)
                v := verdicts["dns_tampering"].(map[string]interface{})
                if v["answer"] != "existing" {
                        t.Errorf("answer should remain 'existing', got %v", v["answer"])
                }
        })

        t.Run("trims reason prefix", func(t *testing.T) {
                verdicts := map[string]interface{}{
                        "test": map[string]interface{}{
                                "label":  "Protected",
                                "reason": "No — well protected",
                        },
                }
                labelMap := map[string]string{"Protected": "No"}
                normalizeVerdictEntry(verdicts, "test", labelMap)
                v := verdicts["test"].(map[string]interface{})
                if v["reason"] != "well protected" {
                        t.Errorf("reason = %q, want 'well protected'", v["reason"])
                }
        })
}

func TestBuildPagination(t *testing.T) {
        pd := BuildPagination(3, 10, 100)
        if pd.CurrentPage != 3 {
                t.Errorf("CurrentPage = %d, want 3", pd.CurrentPage)
        }
        if pd.TotalPages != 10 {
                t.Errorf("TotalPages = %d, want 10", pd.TotalPages)
        }
        if !pd.HasPrev {
                t.Error("expected HasPrev")
        }
        if !pd.HasNext {
                t.Error("expected HasNext")
        }
        if pd.PrevPage != 2 {
                t.Errorf("PrevPage = %d, want 2", pd.PrevPage)
        }
        if pd.NextPage != 4 {
                t.Errorf("NextPage = %d, want 4", pd.NextPage)
        }
        if len(pd.Pages) == 0 {
                t.Error("expected non-empty Pages")
        }
}

func TestIterPages(t *testing.T) {
        t.Run("small page count", func(t *testing.T) {
                pages := iterPages(1, 5)
                if len(pages) != 5 {
                        t.Errorf("expected 5 pages, got %d", len(pages))
                }
                for _, p := range pages {
                        if p.IsGap {
                                t.Error("no gaps expected for 5 pages")
                        }
                }
        })

        t.Run("large page count has gaps", func(t *testing.T) {
                pages := iterPages(1, 50)
                hasGap := false
                for _, p := range pages {
                        if p.IsGap {
                                hasGap = true
                                break
                        }
                }
                if !hasGap {
                        t.Error("expected gaps in pagination with 50 pages")
                }
        })

        t.Run("active page marked", func(t *testing.T) {
                pages := iterPages(3, 10)
                found := false
                for _, p := range pages {
                        if p.IsActive && p.Number == 3 {
                                found = true
                        }
                }
                if !found {
                        t.Error("expected page 3 to be active")
                }
        })
}

func TestNewPaginationHelper(t *testing.T) {
        tests := []struct {
                name      string
                page      int
                perPage   int
                total     int64
                wantPage  int
                wantPages int
                wantPrev  bool
                wantNext  bool
        }{
                {"first page", 1, 10, 50, 1, 5, false, true},
                {"middle page", 3, 10, 50, 3, 5, true, true},
                {"last page", 5, 10, 50, 5, 5, true, false},
                {"single page", 1, 10, 5, 1, 1, false, false},
                {"zero total", 1, 10, 0, 1, 1, false, false},
                {"negative page clamps to 1", -1, 10, 50, 1, 5, false, true},
                {"zero page clamps to 1", 0, 10, 50, 1, 5, false, true},
                {"exact fit", 1, 10, 10, 1, 1, false, false},
                {"partial last page", 1, 10, 11, 1, 2, false, true},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        p := NewPagination(tt.page, tt.perPage, tt.total)
                        if p.Page != tt.wantPage {
                                t.Errorf("Page = %d, want %d", p.Page, tt.wantPage)
                        }
                        if p.TotalPages != tt.wantPages {
                                t.Errorf("TotalPages = %d, want %d", p.TotalPages, tt.wantPages)
                        }
                        if p.HasPrev != tt.wantPrev {
                                t.Errorf("HasPrev = %v, want %v", p.HasPrev, tt.wantPrev)
                        }
                        if p.HasNext != tt.wantNext {
                                t.Errorf("HasNext = %v, want %v", p.HasNext, tt.wantNext)
                        }
                })
        }
}

func TestPaginationOffsetHelper(t *testing.T) {
        p := NewPagination(3, 10, 100)
        if p.Offset() != 20 {
                t.Errorf("Offset = %d, want 20", p.Offset())
        }
}

func TestPaginationLimitHelper(t *testing.T) {
        p := NewPagination(1, 25, 100)
        if p.Limit() != 25 {
                t.Errorf("Limit = %d, want 25", p.Limit())
        }
}

func TestPaginationPagesHelper(t *testing.T) {
        p := NewPagination(1, 10, 30)
        pages := p.Pages()
        if len(pages) != 3 {
                t.Fatalf("expected 3 pages, got %d", len(pages))
        }
        for i, pg := range pages {
                if pg != i+1 {
                        t.Errorf("pages[%d] = %d, want %d", i, pg, i+1)
                }
        }
}

func TestNormalizeResultsHelper(t *testing.T) {
        t.Run("nil input", func(t *testing.T) {
                got := NormalizeResults(nil)
                if got != nil {
                        t.Error("expected nil for nil input")
                }
        })

        t.Run("empty input", func(t *testing.T) {
                got := NormalizeResults([]byte{})
                if got != nil {
                        t.Error("expected nil for empty input")
                }
        })

        t.Run("invalid JSON", func(t *testing.T) {
                got := NormalizeResults([]byte("not json"))
                if got != nil {
                        t.Error("expected nil for invalid JSON")
                }
        })

        t.Run("fills defaults for missing keys", func(t *testing.T) {
                got := NormalizeResults([]byte(`{"some_key": "value"}`))
                if got == nil {
                        t.Fatal("expected non-nil result")
                }
                if _, ok := got["spf_analysis"]; !ok {
                        t.Error("expected spf_analysis default")
                }
                if _, ok := got["dmarc_analysis"]; !ok {
                        t.Error("expected dmarc_analysis default")
                }
                if _, ok := got["posture"]; !ok {
                        t.Error("expected posture default")
                }
        })

        t.Run("does not overwrite existing keys", func(t *testing.T) {
                got := NormalizeResults([]byte(`{"spf_analysis": {"status": "success"}}`))
                if got == nil {
                        t.Fatal("expected non-nil result")
                }
                spf, ok := got["spf_analysis"].(map[string]interface{})
                if !ok {
                        t.Fatal("expected spf_analysis to be map")
                }
                if spf["status"] != "success" {
                        t.Errorf("spf status = %v, want success", spf["status"])
                }
        })

        t.Run("normalizes legacy posture states", func(t *testing.T) {
                got := NormalizeResults([]byte(`{"posture": {"state": "STRONG"}}`))
                if got == nil {
                        t.Fatal("expected non-nil result")
                }
                posture := got["posture"].(map[string]interface{})
                if posture["state"] != "Secure" {
                        t.Errorf("state = %v, want Secure", posture["state"])
                }
                if posture["color"] != "success" {
                        t.Errorf("color = %v, want success", posture["color"])
                }
        })

        t.Run("normalizes WEAK to High Risk", func(t *testing.T) {
                got := NormalizeResults([]byte(`{"posture": {"state": "WEAK"}}`))
                posture := got["posture"].(map[string]interface{})
                if posture["state"] != "High Risk" {
                        t.Errorf("state = %v, want High Risk", posture["state"])
                }
        })
}

func TestNormalizeEmailAnswerHelper(t *testing.T) {
        t.Run("already has short answer", func(t *testing.T) {
                verdicts := map[string]interface{}{
                        "email_answer_short": "existing",
                }
                normalizeEmailAnswer(verdicts)
                if verdicts["email_answer_short"] != "existing" {
                        t.Error("should not overwrite existing short answer")
                }
        })

        t.Run("no email_answer", func(t *testing.T) {
                verdicts := map[string]interface{}{}
                normalizeEmailAnswer(verdicts)
                if _, ok := verdicts["email_answer_short"]; ok {
                        t.Error("should not set short answer without email_answer")
                }
        })

        t.Run("parses No answer", func(t *testing.T) {
                verdicts := map[string]interface{}{
                        "email_answer": "No — domain has strong protections",
                }
                normalizeEmailAnswer(verdicts)
                if verdicts["email_answer_short"] != "No" {
                        t.Errorf("short = %v, want No", verdicts["email_answer_short"])
                }
                if verdicts["email_answer_reason"] != "domain has strong protections" {
                        t.Errorf("reason = %v", verdicts["email_answer_reason"])
                }
                if verdicts["email_answer_color"] != "success" {
                        t.Errorf("color = %v, want success", verdicts["email_answer_color"])
                }
        })

        t.Run("parses Yes answer", func(t *testing.T) {
                verdicts := map[string]interface{}{
                        "email_answer": "Yes — domain is vulnerable",
                }
                normalizeEmailAnswer(verdicts)
                if verdicts["email_answer_color"] != "danger" {
                        t.Errorf("color = %v, want danger", verdicts["email_answer_color"])
                }
        })

        t.Run("parses Unlikely answer", func(t *testing.T) {
                verdicts := map[string]interface{}{
                        "email_answer": "Unlikely — well protected",
                }
                normalizeEmailAnswer(verdicts)
                if verdicts["email_answer_color"] != "success" {
                        t.Errorf("color = %v, want success", verdicts["email_answer_color"])
                }
        })

        t.Run("parses Likely answer", func(t *testing.T) {
                verdicts := map[string]interface{}{
                        "email_answer": "Likely — weak protections",
                }
                normalizeEmailAnswer(verdicts)
                if verdicts["email_answer_color"] != "danger" {
                        t.Errorf("color = %v, want danger", verdicts["email_answer_color"])
                }
        })

        t.Run("parses Partially answer", func(t *testing.T) {
                verdicts := map[string]interface{}{
                        "email_answer": "Partially — some protections",
                }
                normalizeEmailAnswer(verdicts)
                if verdicts["email_answer_color"] != "warning" {
                        t.Errorf("color = %v, want warning", verdicts["email_answer_color"])
                }
        })

        t.Run("parses Uncertain answer", func(t *testing.T) {
                verdicts := map[string]interface{}{
                        "email_answer": "Uncertain — unclear status",
                }
                normalizeEmailAnswer(verdicts)
                if verdicts["email_answer_color"] != "warning" {
                        t.Errorf("color = %v, want warning", verdicts["email_answer_color"])
                }
        })

        t.Run("no separator does nothing", func(t *testing.T) {
                verdicts := map[string]interface{}{
                        "email_answer": "No separator here",
                }
                normalizeEmailAnswer(verdicts)
                if _, ok := verdicts["email_answer_short"]; ok {
                        t.Error("should not set short answer without separator")
                }
        })
}

func TestNormalizeLLMsTxtVerdictHelper(t *testing.T) {
        tests := []struct {
                name       string
                input      map[string]interface{}
                wantAnswer string
        }{
                {"both found", map[string]interface{}{"found": true, "full_found": true}, "Yes"},
                {"only found", map[string]interface{}{"found": true, "full_found": false}, "Yes"},
                {"not found", map[string]interface{}{"found": false}, "No"},
                {"empty map", map[string]interface{}{}, "No"},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := normalizeLLMsTxtVerdict(tt.input)
                        if got["answer"] != tt.wantAnswer {
                                t.Errorf("answer = %v, want %v", got["answer"], tt.wantAnswer)
                        }
                })
        }
}

func TestNormalizeRobotsTxtVerdictHelper(t *testing.T) {
        tests := []struct {
                name       string
                input      map[string]interface{}
                wantAnswer string
                wantColor  string
        }{
                {"found and blocks AI", map[string]interface{}{"found": true, "blocks_ai_crawlers": true}, "Yes", "success"},
                {"found but no block", map[string]interface{}{"found": true, "blocks_ai_crawlers": false}, "No", "warning"},
                {"not found", map[string]interface{}{"found": false}, "No", "secondary"},
                {"empty", map[string]interface{}{}, "No", "secondary"},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := normalizeRobotsTxtVerdict(tt.input)
                        if got["answer"] != tt.wantAnswer {
                                t.Errorf("answer = %v, want %v", got["answer"], tt.wantAnswer)
                        }
                        if got["color"] != tt.wantColor {
                                t.Errorf("color = %v, want %v", got["color"], tt.wantColor)
                        }
                })
        }
}

func TestNormalizeCountVerdictHelper(t *testing.T) {
        t.Run("positive count", func(t *testing.T) {
                section := map[string]interface{}{"ioc_count": float64(3)}
                got := normalizeCountVerdict(section, "ioc_count", "indicator(s) found", "None found")
                if got["answer"] != "Yes" {
                        t.Errorf("answer = %v, want Yes", got["answer"])
                }
                if got["color"] != "danger" {
                        t.Errorf("color = %v, want danger", got["color"])
                }
        })

        t.Run("zero count", func(t *testing.T) {
                section := map[string]interface{}{"ioc_count": float64(0)}
                got := normalizeCountVerdict(section, "ioc_count", "indicator(s) found", "None found")
                if got["answer"] != "No" {
                        t.Errorf("answer = %v, want No", got["answer"])
                }
                if got["color"] != "success" {
                        t.Errorf("color = %v, want success", got["color"])
                }
        })

        t.Run("missing key", func(t *testing.T) {
                section := map[string]interface{}{}
                got := normalizeCountVerdict(section, "ioc_count", "found", "None found")
                if got["answer"] != "No" {
                        t.Errorf("answer = %v, want No", got["answer"])
                }
        })
}

func TestGetNumValueHelper(t *testing.T) {
        tests := []struct {
                name string
                m    map[string]interface{}
                key  string
                want float64
        }{
                {"float64", map[string]interface{}{"k": float64(42)}, "k", 42},
                {"int", map[string]interface{}{"k": int(7)}, "k", 7},
                {"int64", map[string]interface{}{"k": int64(99)}, "k", 99},
                {"missing key", map[string]interface{}{}, "k", 0},
                {"string value", map[string]interface{}{"k": "hello"}, "k", 0},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := getNumValue(tt.m, tt.key)
                        if got != tt.want {
                                t.Errorf("got %v, want %v", got, tt.want)
                        }
                })
        }
}

func TestGetStatusHelper(t *testing.T) {
        tests := []struct {
                name string
                m    map[string]interface{}
                want string
        }{
                {"has status", map[string]interface{}{"status": "success"}, "success"},
                {"has state", map[string]interface{}{"state": "Secure"}, "Secure"},
                {"prefers status over state", map[string]interface{}{"status": "warning", "state": "Secure"}, "warning"},
                {"empty map", map[string]interface{}{}, "unknown"},
                {"non-string status", map[string]interface{}{"status": 42}, "unknown"},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := getStatus(tt.m)
                        if got != tt.want {
                                t.Errorf("got %q, want %q", got, tt.want)
                        }
                })
        }
}

func TestComputeSectionDiffHelper(t *testing.T) {
        t.Run("identical sections", func(t *testing.T) {
                secA := map[string]interface{}{"status": "success", "records": []interface{}{"a"}}
                secB := map[string]interface{}{"status": "success", "records": []interface{}{"a"}}
                diff := ComputeSectionDiff(secA, secB, "spf", "SPF", "fa-envelope")
                if diff.Changed {
                        t.Error("expected no change for identical sections")
                }
                if diff.StatusA != "success" || diff.StatusB != "success" {
                        t.Errorf("statuses = %q, %q", diff.StatusA, diff.StatusB)
                }
        })

        t.Run("different status", func(t *testing.T) {
                secA := map[string]interface{}{"status": "success"}
                secB := map[string]interface{}{"status": "warning"}
                diff := ComputeSectionDiff(secA, secB, "spf", "SPF", "fa-envelope")
                if !diff.Changed {
                        t.Error("expected change for different status")
                }
        })

        t.Run("different field values", func(t *testing.T) {
                secA := map[string]interface{}{"status": "success", "policy": "reject"}
                secB := map[string]interface{}{"status": "success", "policy": "quarantine"}
                diff := ComputeSectionDiff(secA, secB, "dmarc", "DMARC", "fa-shield")
                if !diff.Changed {
                        t.Error("expected change")
                }
                if len(diff.DetailChanges) != 1 {
                        t.Fatalf("expected 1 detail change, got %d", len(diff.DetailChanges))
                }
                if diff.DetailChanges[0].Old != "reject" {
                        t.Errorf("old = %v, want reject", diff.DetailChanges[0].Old)
                }
        })

        t.Run("skips status and state keys", func(t *testing.T) {
                secA := map[string]interface{}{"status": "success", "state": "a", "_schema_version": "1"}
                secB := map[string]interface{}{"status": "success", "state": "a", "_schema_version": "2"}
                diff := ComputeSectionDiff(secA, secB, "test", "Test", "fa-test")
                if diff.Changed {
                        t.Error("expected no change since skip keys differ")
                }
        })

        t.Run("key and label preserved", func(t *testing.T) {
                diff := ComputeSectionDiff(map[string]interface{}{}, map[string]interface{}{}, "k", "L", "i")
                if diff.Key != "k" || diff.Label != "L" || diff.Icon != "i" {
                        t.Error("key/label/icon not preserved")
                }
        })
}

func TestComputeAllDiffsHelper(t *testing.T) {
        resultsA := map[string]interface{}{
                "spf_analysis": map[string]interface{}{"status": "success"},
        }
        resultsB := map[string]interface{}{
                "spf_analysis": map[string]interface{}{"status": "warning"},
        }
        diffs := ComputeAllDiffs(resultsA, resultsB)
        if len(diffs) != len(CompareSections) {
                t.Errorf("expected %d diffs, got %d", len(CompareSections), len(diffs))
        }
        if diffs[0].Key != "spf_analysis" {
                t.Errorf("first diff key = %q, want spf_analysis", diffs[0].Key)
        }
        if !diffs[0].Changed {
                t.Error("expected SPF section to be changed")
        }
}

func TestGetSectionHelper(t *testing.T) {
        t.Run("existing key", func(t *testing.T) {
                results := map[string]interface{}{
                        "spf": map[string]interface{}{"status": "success"},
                }
                s := getSection(results, "spf")
                if s["status"] != "success" {
                        t.Errorf("status = %v", s["status"])
                }
        })

        t.Run("missing key", func(t *testing.T) {
                s := getSection(map[string]interface{}{}, "spf")
                if len(s) != 0 {
                        t.Error("expected empty map for missing key")
                }
        })

        t.Run("wrong type", func(t *testing.T) {
                results := map[string]interface{}{"spf": "not a map"}
                s := getSection(results, "spf")
                if len(s) != 0 {
                        t.Error("expected empty map for wrong type")
                }
        })
}

func TestExtractRootDomainHelper(t *testing.T) {
        tests := []struct {
                name     string
                domain   string
                wantSub  bool
                wantRoot string
        }{
                {"subdomain", "www.example.com", true, "example.com"},
                {"root domain", "example.com", false, ""},
                {"deep subdomain", "a.b.example.com", true, "example.com"},
                {"trailing dot", "www.example.com.", true, "example.com"},
                {"root with trailing dot", "example.com.", false, ""},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        isSub, root := extractRootDomain(tt.domain)
                        if isSub != tt.wantSub {
                                t.Errorf("isSub = %v, want %v", isSub, tt.wantSub)
                        }
                        if root != tt.wantRoot {
                                t.Errorf("root = %q, want %q", root, tt.wantRoot)
                        }
                })
        }
}

func TestIsPublicSuffixDomainHelper(t *testing.T) {
        tests := []struct {
                name   string
                domain string
                want   bool
        }{
                {"regular domain", "example.com", false},
                {"TLD", "com", true},
                {"co.uk suffix", "co.uk", true},
                {"subdomain", "www.example.com", false},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := isPublicSuffixDomain(tt.domain)
                        if got != tt.want {
                                t.Errorf("isPublicSuffixDomain(%q) = %v, want %v", tt.domain, got, tt.want)
                        }
                })
        }
}

func TestNormalizeAIVerdictsHelper(t *testing.T) {
        t.Run("skips if ai_llms_txt already present", func(t *testing.T) {
                verdicts := map[string]interface{}{
                        "ai_llms_txt": map[string]interface{}{"answer": "existing"},
                }
                results := map[string]interface{}{}
                normalizeAIVerdicts(results, verdicts)
                v := verdicts["ai_llms_txt"].(map[string]interface{})
                if v["answer"] != "existing" {
                        t.Error("should not overwrite existing ai_llms_txt")
                }
        })

        t.Run("no ai_surface does nothing", func(t *testing.T) {
                verdicts := map[string]interface{}{}
                results := map[string]interface{}{}
                normalizeAIVerdicts(results, verdicts)
                if _, ok := verdicts["ai_llms_txt"]; ok {
                        t.Error("should not create ai_llms_txt without ai_surface")
                }
        })

        t.Run("populates all AI verdicts", func(t *testing.T) {
                verdicts := map[string]interface{}{}
                results := map[string]interface{}{
                        "ai_surface": map[string]interface{}{
                                "llms_txt":       map[string]interface{}{"found": true},
                                "robots_txt":     map[string]interface{}{"found": true, "blocks_ai_crawlers": true},
                                "poisoning":      map[string]interface{}{"ioc_count": float64(2)},
                                "hidden_prompts": map[string]interface{}{"artifact_count": float64(0)},
                        },
                }
                normalizeAIVerdicts(results, verdicts)
                if _, ok := verdicts["ai_llms_txt"]; !ok {
                        t.Error("expected ai_llms_txt")
                }
                if _, ok := verdicts["ai_crawler_governance"]; !ok {
                        t.Error("expected ai_crawler_governance")
                }
                if _, ok := verdicts["ai_poisoning"]; !ok {
                        t.Error("expected ai_poisoning")
                }
                if _, ok := verdicts["ai_hidden_prompts"]; !ok {
                        t.Error("expected ai_hidden_prompts")
                }
        })
}

func TestParseSortedElement(t *testing.T) {
        t.Run("string when firstIsString", func(t *testing.T) {
                got := parseSortedElement("hello", true)
                if got != "hello" {
                        t.Errorf("got %v, want hello", got)
                }
        })

        t.Run("parses JSON when not firstIsString", func(t *testing.T) {
                got := parseSortedElement(`{"a":"b"}`, false)
                m, ok := got.(map[string]interface{})
                if !ok {
                        t.Fatal("expected map result")
                }
                if m["a"] != "b" {
                        t.Errorf("got %v", m)
                }
        })

        t.Run("returns string for invalid JSON when not firstIsString", func(t *testing.T) {
                got := parseSortedElement("not json {", false)
                if got != "not json {" {
                        t.Errorf("got %v", got)
                }
        })
}

func TestIsTwoPartSuffix(t *testing.T) {
        tests := []struct {
                name   string
                domain string
                want   bool
        }{
                {"co.uk is suffix", "co.uk", true},
                {"com is not two-part", "com", false},
                {"example.com is not suffix", "example.com", false},
                {"www.example.com not suffix", "www.example.com", false},
                {"empty string", "", false},
                {"single part", "localhost", false},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := isTwoPartSuffix(tt.domain)
                        if got != tt.want {
                                t.Errorf("isTwoPartSuffix(%q) = %v, want %v", tt.domain, got, tt.want)
                        }
                })
        }
}

func TestNormalizeVerdictAnswersAllKeys(t *testing.T) {
        t.Run("sets dns_tampering answer from Protected label", func(t *testing.T) {
                verdicts := map[string]interface{}{
                        "dns_tampering": map[string]interface{}{
                                "label": "Protected",
                        },
                }
                normalizeVerdictAnswers(verdicts)
                v := verdicts["dns_tampering"].(map[string]interface{})
                if v["answer"] != "No" {
                        t.Errorf("answer = %v, want No", v["answer"])
                }
        })

        t.Run("sets dns_tampering answer from Exposed label", func(t *testing.T) {
                verdicts := map[string]interface{}{
                        "dns_tampering": map[string]interface{}{
                                "label": "Exposed",
                        },
                }
                normalizeVerdictAnswers(verdicts)
                v := verdicts["dns_tampering"].(map[string]interface{})
                if v["answer"] != "Yes" {
                        t.Errorf("answer = %v, want Yes", v["answer"])
                }
        })

        t.Run("sets brand_impersonation answer", func(t *testing.T) {
                verdicts := map[string]interface{}{
                        "brand_impersonation": map[string]interface{}{
                                "label": "Protected",
                        },
                }
                normalizeVerdictAnswers(verdicts)
                v := verdicts["brand_impersonation"].(map[string]interface{})
                if v["answer"] != "No" {
                        t.Errorf("answer = %v, want No", v["answer"])
                }
        })

        t.Run("sets certificate_control answer", func(t *testing.T) {
                verdicts := map[string]interface{}{
                        "certificate_control": map[string]interface{}{
                                "label": "Configured",
                        },
                }
                normalizeVerdictAnswers(verdicts)
                v := verdicts["certificate_control"].(map[string]interface{})
                if v["answer"] != "Yes" {
                        t.Errorf("answer = %v, want Yes", v["answer"])
                }
        })

        t.Run("sets transport answer from Fully Protected", func(t *testing.T) {
                verdicts := map[string]interface{}{
                        "transport": map[string]interface{}{
                                "label": "Fully Protected",
                        },
                }
                normalizeVerdictAnswers(verdicts)
                v := verdicts["transport"].(map[string]interface{})
                if v["answer"] != "Yes" {
                        t.Errorf("answer = %v, want Yes", v["answer"])
                }
        })

        t.Run("sets transport Monitoring to Partially", func(t *testing.T) {
                verdicts := map[string]interface{}{
                        "transport": map[string]interface{}{
                                "label": "Monitoring",
                        },
                }
                normalizeVerdictAnswers(verdicts)
                v := verdicts["transport"].(map[string]interface{})
                if v["answer"] != "Partially" {
                        t.Errorf("answer = %v, want Partially", v["answer"])
                }
        })

        t.Run("handles multiple verdicts at once", func(t *testing.T) {
                verdicts := map[string]interface{}{
                        "dns_tampering": map[string]interface{}{
                                "label": "Exposed",
                        },
                        "brand_impersonation": map[string]interface{}{
                                "label": "Exposed",
                        },
                        "transport": map[string]interface{}{
                                "label": "Not Enforced",
                        },
                }
                normalizeVerdictAnswers(verdicts)
                if verdicts["dns_tampering"].(map[string]interface{})["answer"] != "Yes" {
                        t.Error("dns_tampering answer should be Yes")
                }
                if verdicts["brand_impersonation"].(map[string]interface{})["answer"] != "Yes" {
                        t.Error("brand_impersonation answer should be Yes")
                }
                if verdicts["transport"].(map[string]interface{})["answer"] != "No" {
                        t.Error("transport answer should be No")
                }
        })

        t.Run("skips unknown labels", func(t *testing.T) {
                verdicts := map[string]interface{}{
                        "dns_tampering": map[string]interface{}{
                                "label": "UnknownLabel",
                        },
                }
                normalizeVerdictAnswers(verdicts)
                v := verdicts["dns_tampering"].(map[string]interface{})
                if _, ok := v["answer"]; ok {
                        t.Error("should not set answer for unknown label")
                }
        })

        t.Run("does not overwrite existing answer", func(t *testing.T) {
                verdicts := map[string]interface{}{
                        "dns_tampering": map[string]interface{}{
                                "answer": "existing",
                                "label":  "Protected",
                        },
                }
                normalizeVerdictAnswers(verdicts)
                v := verdicts["dns_tampering"].(map[string]interface{})
                if v["answer"] != "existing" {
                        t.Errorf("answer = %v, want existing", v["answer"])
                }
        })
}

func TestNormalizeVerdictsIntegration(t *testing.T) {
        t.Run("without verdicts key does nothing", func(t *testing.T) {
                results := map[string]interface{}{}
                posture := map[string]interface{}{}
                normalizeVerdicts(results, posture)
                if _, ok := posture["verdicts"]; ok {
                        t.Error("should not create verdicts key")
                }
        })

        t.Run("with empty verdicts", func(t *testing.T) {
                results := map[string]interface{}{}
                posture := map[string]interface{}{
                        "verdicts": map[string]interface{}{},
                }
                normalizeVerdicts(results, posture)
                verdicts := posture["verdicts"].(map[string]interface{})
                if len(verdicts) != 0 {
                        t.Error("empty verdicts should remain empty without ai_surface")
                }
        })

        t.Run("with verdict labels", func(t *testing.T) {
                results := map[string]interface{}{}
                posture := map[string]interface{}{
                        "verdicts": map[string]interface{}{
                                "dns_tampering": map[string]interface{}{
                                        "label": "Protected",
                                },
                        },
                }
                normalizeVerdicts(results, posture)
                verdicts := posture["verdicts"].(map[string]interface{})
                v := verdicts["dns_tampering"].(map[string]interface{})
                if v["answer"] != "No" {
                        t.Errorf("answer = %v, want No", v["answer"])
                }
        })
}

func TestSubdomainEmailScopeStruct(t *testing.T) {
        scope := subdomainEmailScope{
                IsSubdomain:   true,
                ParentDomain:  "example.com",
                SPFScope:      "local",
                DMARCScope:    "inherited",
                SPFNote:       "SPF record published at this subdomain",
                DMARCNote:     "inherited from org",
                HasLocalEmail: true,
        }
        if !scope.IsSubdomain {
                t.Error("expected IsSubdomain to be true")
        }
        if scope.ParentDomain != "example.com" {
                t.Errorf("ParentDomain = %q, want example.com", scope.ParentDomain)
        }
        if scope.SPFScope != "local" {
                t.Errorf("SPFScope = %q, want local", scope.SPFScope)
        }
        if scope.DMARCScope != "inherited" {
                t.Errorf("DMARCScope = %q, want inherited", scope.DMARCScope)
        }
        if !scope.HasLocalEmail {
                t.Error("expected HasLocalEmail to be true")
        }
}

func TestDetermineDMARCScopeNotes(t *testing.T) {
        t.Run("local note", func(t *testing.T) {
                _, note := determineDMARCScope(true, false, "", "example.com")
                if note != "DMARC record published at this subdomain" {
                        t.Errorf("note = %q", note)
                }
        })

        t.Run("inherited with policy note", func(t *testing.T) {
                _, note := determineDMARCScope(false, true, "reject", "example.com")
                if note == "" {
                        t.Error("expected non-empty note")
                }
                if !contains(note, "p=reject") {
                        t.Errorf("note should contain p=reject: %q", note)
                }
                if !contains(note, "example.com") {
                        t.Errorf("note should contain domain: %q", note)
                }
        })

        t.Run("inherited without policy note", func(t *testing.T) {
                _, note := determineDMARCScope(false, true, "", "example.com")
                if contains(note, "p=") {
                        t.Errorf("note should not contain p= when policy is empty: %q", note)
                }
        })

        t.Run("none note", func(t *testing.T) {
                _, note := determineDMARCScope(false, false, "", "example.com")
                if !contains(note, "example.com") {
                        t.Errorf("note should contain domain: %q", note)
                }
        })
}

func contains(s, substr string) bool {
        return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
        for i := 0; i <= len(s)-len(substr); i++ {
                if s[i:i+len(substr)] == substr {
                        return true
                }
        }
        return false
}

func strPtr(s string) *string {
        return &s
}
