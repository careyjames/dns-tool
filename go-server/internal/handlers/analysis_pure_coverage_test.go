package handlers

import (
        "encoding/json"
        "testing"

        "dnstool/go-server/internal/dbq"
)

func TestIsAnalysisFailure(t *testing.T) {
        tests := []struct {
                name    string
                results map[string]any
                isFail  bool
                errMsg  string
        }{
                {"success true", map[string]any{"analysis_success": true}, false, ""},
                {"success false with error", map[string]any{"analysis_success": false, "error": "timeout"}, true, "timeout"},
                {"success false no error", map[string]any{"analysis_success": false}, false, ""},
                {"missing success key", map[string]any{}, false, ""},
                {"non-bool success", map[string]any{"analysis_success": "yes"}, false, ""},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        isFail, errMsg := isAnalysisFailure(tt.results)
                        if isFail != tt.isFail {
                                t.Errorf("isAnalysisFailure() isFail = %v, want %v", isFail, tt.isFail)
                        }
                        if errMsg != tt.errMsg {
                                t.Errorf("isAnalysisFailure() errMsg = %q, want %q", errMsg, tt.errMsg)
                        }
                })
        }
}

func TestExtractReportsAndDurations_Empty(t *testing.T) {
        reports, durations := extractReportsAndDurations(nil)
        if len(reports) != 0 || len(durations) != 0 {
                t.Errorf("extractReportsAndDurations(nil) = (%d, %d), want (0, 0)", len(reports), len(durations))
        }

        analyses := []dbq.DomainAnalysis{
                {FullResults: nil},
                {FullResults: json.RawMessage(`invalid json`)},
        }
        reports, durations = extractReportsAndDurations(analyses)
        if len(reports) != 0 || len(durations) != 0 {
                t.Errorf("extractReportsAndDurations(bad) = (%d, %d), want (0, 0)", len(reports), len(durations))
        }
}

func TestExtractReportsAndDurations_WithDuration(t *testing.T) {
        dur := 2.5
        analyses := []dbq.DomainAnalysis{
                {
                        FullResults:      json.RawMessage(`{"basic_records": {}}`),
                        AnalysisDuration: &dur,
                },
        }
        reports, durations := extractReportsAndDurations(analyses)
        if len(reports) != 0 {
                t.Errorf("expected 0 reports, got %d", len(reports))
        }
        if len(durations) != 1 || durations[0] != 2500 {
                t.Errorf("expected [2500], got %v", durations)
        }
}

func TestGetStr(t *testing.T) {
        m := map[string]any{
                "title":  "Fix SPF",
                "count":  42,
                "nested": map[string]any{"a": "b"},
        }
        if got := getStr(m, "title"); got != "Fix SPF" {
                t.Errorf("getStr(title) = %q, want %q", got, "Fix SPF")
        }
        if got := getStr(m, "count"); got != "42" {
                t.Errorf("getStr(count) = %q, want %q", got, "42")
        }
        if got := getStr(m, "missing"); got != "" {
                t.Errorf("getStr(missing) = %q, want empty", got)
        }
}

func TestBuildCopyableRecord(t *testing.T) {
        got := buildCopyableRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject")
        want := "_dmarc.example.com  TXT  v=DMARC1; p=reject"
        if got != want {
                t.Errorf("buildCopyableRecord() = %q, want %q", got, want)
        }
        if got := buildCopyableRecord("TXT", "host", ""); got != "" {
                t.Errorf("buildCopyableRecord(empty value) = %q, want empty", got)
        }
}

func TestBuildRemediationItems_Empty(t *testing.T) {
        items := buildRemediationItems(nil)
        if len(items) != 0 {
                t.Errorf("expected 0 items for nil, got %d", len(items))
        }
        items = buildRemediationItems([]any{})
        if len(items) != 0 {
                t.Errorf("expected 0 items for empty, got %d", len(items))
        }
}

func TestBuildRemediationItems_WithFix(t *testing.T) {
        fixes := []any{
                map[string]any{
                        "title":          "Add SPF record",
                        "fix":            "Create a TXT record",
                        "section":        "SPF",
                        "severity_label": "High",
                        "severity_color": "red",
                        "rfc":            "RFC 7208",
                        "rfc_url":        "https://tools.ietf.org/html/rfc7208",
                        "dns_host":       "example.com",
                        "dns_type":       "TXT",
                        "dns_value":      "v=spf1 -all",
                },
        }
        items := buildRemediationItems(fixes)
        if len(items) != 1 {
                t.Fatalf("expected 1 item, got %d", len(items))
        }
        if items[0].Title != "Add SPF record" {
                t.Errorf("Title = %q, want %q", items[0].Title, "Add SPF record")
        }
        if !items[0].HasDNS {
                t.Error("expected HasDNS=true")
        }
        if items[0].CopyableRecord == "" {
                t.Error("expected non-empty CopyableRecord")
        }
}

func TestBuildRemediationItems_DNSRecordFallback(t *testing.T) {
        fixes := []any{
                map[string]any{
                        "title":      "Manual fix",
                        "dns_record": "example.com IN TXT \"v=spf1 -all\"",
                },
        }
        items := buildRemediationItems(fixes)
        if len(items) != 1 {
                t.Fatalf("expected 1 item, got %d", len(items))
        }
        if !items[0].HasDNS {
                t.Error("expected HasDNS=true via dns_record fallback")
        }
}

func TestBuildRemediationItems_NonMapEntry(t *testing.T) {
        fixes := []any{"not-a-map", 42}
        items := buildRemediationItems(fixes)
        if len(items) != 0 {
                t.Errorf("expected 0 items for non-map entries, got %d", len(items))
        }
}

func TestAnimContentType(t *testing.T) {
        if got := animContentType("gif"); got != "image/gif" {
                t.Errorf("animContentType(gif) = %q, want image/gif", got)
        }
        if got := animContentType("png"); got != "image/png" {
                t.Errorf("animContentType(png) = %q, want image/png", got)
        }
        if got := animContentType("webp"); got != "image/png" {
                t.Errorf("animContentType(webp) = %q, want image/png (default)", got)
        }
}

