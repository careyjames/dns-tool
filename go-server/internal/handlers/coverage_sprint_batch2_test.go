package handlers

import (
        "encoding/json"
        "testing"
        "time"

        "dnstool/go-server/internal/dbq"

        "github.com/jackc/pgx/v5/pgtype"
)

func TestBatch2_maskURL_short(t *testing.T) {
        short := "https://example.com/hook"
        if got := maskURL(short); got != short {
                t.Errorf("maskURL(%q) = %q, want %q", short, got, short)
        }
}

func TestBatch2_maskURL_exactly30(t *testing.T) {
        url := "https://example.com/123456789a"
        if len(url) != 30 {
                t.Fatalf("test setup: url length = %d, want 30", len(url))
        }
        if got := maskURL(url); got != url {
                t.Errorf("maskURL(%q) = %q, want unchanged", url, got)
        }
}

func TestBatch2_maskURL_long(t *testing.T) {
        url := "https://hooks.example.com/callbacks/abc123def456/notifications/XXXXXXXXXXXXXXXXXXXX"
        got := maskURL(url)
        want := url[:20] + "..." + url[len(url)-10:]
        if got != want {
                t.Errorf("maskURL long = %q, want %q", got, want)
        }
}

func TestBatch2_cadenceToNextRun_hourly(t *testing.T) {
        before := time.Now().UTC()
        ts := cadenceToNextRun("hourly")
        after := time.Now().UTC()
        if !ts.Valid {
                t.Fatal("expected Valid=true for hourly")
        }
        expectedMin := before.Add(time.Hour)
        expectedMax := after.Add(time.Hour)
        if ts.Time.Before(expectedMin) || ts.Time.After(expectedMax) {
                t.Errorf("hourly next run %v not in expected range", ts.Time)
        }
}

func TestBatch2_cadenceToNextRun_daily(t *testing.T) {
        before := time.Now().UTC()
        ts := cadenceToNextRun("daily")
        if !ts.Valid {
                t.Fatal("expected Valid=true for daily")
        }
        expected := before.Add(24 * time.Hour)
        if ts.Time.Before(expected.Add(-time.Second)) || ts.Time.After(expected.Add(time.Second)) {
                t.Errorf("daily next run %v not near expected %v", ts.Time, expected)
        }
}

func TestBatch2_cadenceToNextRun_weekly(t *testing.T) {
        before := time.Now().UTC()
        ts := cadenceToNextRun("weekly")
        if !ts.Valid {
                t.Fatal("expected Valid=true for weekly")
        }
        expected := before.Add(7 * 24 * time.Hour)
        if ts.Time.Before(expected.Add(-time.Second)) || ts.Time.After(expected.Add(time.Second)) {
                t.Errorf("weekly next run %v not near expected %v", ts.Time, expected)
        }
}

func TestBatch2_cadenceToNextRun_default(t *testing.T) {
        before := time.Now().UTC()
        ts := cadenceToNextRun("unknown-cadence")
        if !ts.Valid {
                t.Fatal("expected Valid=true for default")
        }
        expected := before.Add(24 * time.Hour)
        if ts.Time.Before(expected.Add(-time.Second)) || ts.Time.After(expected.Add(time.Second)) {
                t.Errorf("default next run %v not near expected %v", ts.Time, expected)
        }
}

func TestBatch2_convertWatchlistEntries_empty(t *testing.T) {
        items := convertWatchlistEntries([]dbq.DomainWatchlist{})
        if len(items) != 0 {
                t.Errorf("expected 0 items, got %d", len(items))
        }
}

func TestBatch2_convertWatchlistEntries_nil(t *testing.T) {
        items := convertWatchlistEntries(nil)
        if items == nil {
                t.Error("expected non-nil empty slice")
        }
        if len(items) != 0 {
                t.Errorf("expected 0 items, got %d", len(items))
        }
}

func TestBatch2_convertWatchlistEntries_populated(t *testing.T) {
        now := time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC)
        entries := []dbq.DomainWatchlist{
                {
                        ID:      1,
                        UserID:  42,
                        Domain:  "example.com",
                        Cadence: "daily",
                        Enabled: true,
                        LastRunAt: pgtype.Timestamp{Time: now.Add(-24 * time.Hour), Valid: true},
                        NextRunAt: pgtype.Timestamp{Time: now.Add(24 * time.Hour), Valid: true},
                        CreatedAt: pgtype.Timestamp{Time: now.Add(-7 * 24 * time.Hour), Valid: true},
                },
                {
                        ID:      2,
                        UserID:  42,
                        Domain:  "test.org",
                        Cadence: "weekly",
                        Enabled: false,
                },
        }
        items := convertWatchlistEntries(entries)
        if len(items) != 2 {
                t.Fatalf("expected 2 items, got %d", len(items))
        }
        if items[0].Domain != "example.com" {
                t.Errorf("item[0].Domain = %q", items[0].Domain)
        }
        if items[0].LastRunAt == "" {
                t.Error("item[0].LastRunAt should be populated")
        }
        if items[0].NextRunAt == "" {
                t.Error("item[0].NextRunAt should be populated")
        }
        if items[0].CreatedAt == "" {
                t.Error("item[0].CreatedAt should be populated")
        }
        if items[1].LastRunAt != "" {
                t.Error("item[1].LastRunAt should be empty for invalid timestamp")
        }
        if items[1].Enabled {
                t.Error("item[1].Enabled should be false")
        }
}

func TestBatch2_buildHistoryItem_nilFields(t *testing.T) {
        a := dbq.DomainAnalysis{
                ID:          100,
                Domain:      "nil.example.com",
                AsciiDomain: "nil.example.com",
        }
        item := buildHistoryItem(a)
        if item.ID != 100 {
                t.Errorf("ID = %d, want 100", item.ID)
        }
        if item.SpfStatus != "" {
                t.Errorf("SpfStatus = %q, want empty", item.SpfStatus)
        }
        if item.DmarcStatus != "" {
                t.Errorf("DmarcStatus = %q, want empty", item.DmarcStatus)
        }
        if item.DkimStatus != "" {
                t.Errorf("DkimStatus = %q, want empty", item.DkimStatus)
        }
        if item.AnalysisDuration != 0.0 {
                t.Errorf("AnalysisDuration = %f, want 0", item.AnalysisDuration)
        }
        if item.CreatedDate != "" {
                t.Errorf("CreatedDate = %q, want empty", item.CreatedDate)
        }
        if item.ToolVersion != "" {
                t.Errorf("ToolVersion = %q, want empty", item.ToolVersion)
        }
}

func TestBatch2_buildHistoryItem_populated(t *testing.T) {
        spf := "pass"
        dmarc := "fail"
        dkim := "none"
        dur := 2.345
        ts := time.Date(2025, 3, 15, 14, 30, 0, 0, time.UTC)
        fr, _ := json.Marshal(map[string]interface{}{"_tool_version": "v1.2.3", "other": "data"})

        a := dbq.DomainAnalysis{
                ID:               200,
                Domain:           "pop.example.com",
                AsciiDomain:      "pop.example.com",
                SpfStatus:        &spf,
                DmarcStatus:      &dmarc,
                DkimStatus:       &dkim,
                AnalysisDuration: &dur,
                CreatedAt:        pgtype.Timestamp{Time: ts, Valid: true},
                FullResults:      json.RawMessage(fr),
        }
        item := buildHistoryItem(a)
        if item.SpfStatus != "pass" {
                t.Errorf("SpfStatus = %q", item.SpfStatus)
        }
        if item.DmarcStatus != "fail" {
                t.Errorf("DmarcStatus = %q", item.DmarcStatus)
        }
        if item.DkimStatus != "none" {
                t.Errorf("DkimStatus = %q", item.DkimStatus)
        }
        if item.AnalysisDuration != 2.345 {
                t.Errorf("AnalysisDuration = %f", item.AnalysisDuration)
        }
        if item.CreatedDate != "15 Mar 2025" {
                t.Errorf("CreatedDate = %q", item.CreatedDate)
        }
        if item.CreatedTime != "14:30 UTC" {
                t.Errorf("CreatedTime = %q", item.CreatedTime)
        }
        if item.ToolVersion != "v1.2.3" {
                t.Errorf("ToolVersion = %q", item.ToolVersion)
        }
}

func TestBatch2_buildHistoryItem_fullResultsNoVersion(t *testing.T) {
        fr, _ := json.Marshal(map[string]interface{}{"some_key": 42})
        a := dbq.DomainAnalysis{
                ID:          300,
                Domain:      "no-ver.example.com",
                AsciiDomain: "no-ver.example.com",
                FullResults: json.RawMessage(fr),
        }
        item := buildHistoryItem(a)
        if item.ToolVersion != "" {
                t.Errorf("ToolVersion = %q, want empty", item.ToolVersion)
        }
}

func TestBatch2_buildDossierItem_nilFields(t *testing.T) {
        a := dbq.ListUserAnalysesRow{
                ID:          10,
                Domain:      "nil.test.com",
                AsciiDomain: "nil.test.com",
        }
        item := buildDossierItem(a)
        if item.ID != 10 {
                t.Errorf("ID = %d", item.ID)
        }
        if item.SpfStatus != "" {
                t.Errorf("SpfStatus = %q", item.SpfStatus)
        }
        if item.DmarcStatus != "" {
                t.Errorf("DmarcStatus = %q", item.DmarcStatus)
        }
        if item.DkimStatus != "" {
                t.Errorf("DkimStatus = %q", item.DkimStatus)
        }
        if item.AnalysisDuration != 0.0 {
                t.Errorf("AnalysisDuration = %f", item.AnalysisDuration)
        }
        if item.PostureHash != "" {
                t.Errorf("PostureHash = %q", item.PostureHash)
        }
        if item.CreatedDate != "" {
                t.Errorf("CreatedDate = %q", item.CreatedDate)
        }
        if !item.AnalysisSuccess {
                t.Error("AnalysisSuccess should be true")
        }
}

func TestBatch2_buildDossierItem_populated(t *testing.T) {
        spf := "pass"
        dmarc := "reject"
        dkim := "pass"
        dur := 1.5
        hash := "abc123"
        ts := time.Date(2025, 1, 20, 8, 15, 0, 0, time.UTC)
        fr, _ := json.Marshal(map[string]interface{}{"_tool_version": "v2.0.0"})

        a := dbq.ListUserAnalysesRow{
                ID:               20,
                Domain:           "full.test.com",
                AsciiDomain:      "full.test.com",
                SpfStatus:        &spf,
                DmarcStatus:      &dmarc,
                DkimStatus:       &dkim,
                AnalysisDuration: &dur,
                PostureHash:      &hash,
                CreatedAt:        pgtype.Timestamp{Time: ts, Valid: true},
                FullResults:      json.RawMessage(fr),
        }
        item := buildDossierItem(a)
        if item.SpfStatus != "pass" {
                t.Errorf("SpfStatus = %q", item.SpfStatus)
        }
        if item.DmarcStatus != "reject" {
                t.Errorf("DmarcStatus = %q", item.DmarcStatus)
        }
        if item.DkimStatus != "pass" {
                t.Errorf("DkimStatus = %q", item.DkimStatus)
        }
        if item.AnalysisDuration != 1.5 {
                t.Errorf("AnalysisDuration = %f", item.AnalysisDuration)
        }
        if item.PostureHash != "abc123" {
                t.Errorf("PostureHash = %q", item.PostureHash)
        }
        if item.ToolVersion != "v2.0.0" {
                t.Errorf("ToolVersion = %q", item.ToolVersion)
        }
        if item.CreatedDate != "20 Jan 2025" {
                t.Errorf("CreatedDate = %q", item.CreatedDate)
        }
        if item.CreatedTime != "08:15 UTC" {
                t.Errorf("CreatedTime = %q", item.CreatedTime)
        }
}

func TestBatch2_buildDossierItemFromSearch_nilFields(t *testing.T) {
        a := dbq.SearchUserAnalysesRow{
                ID:          50,
                Domain:      "search-nil.test.com",
                AsciiDomain: "search-nil.test.com",
        }
        item := buildDossierItemFromSearch(a)
        if item.ID != 50 {
                t.Errorf("ID = %d", item.ID)
        }
        if item.SpfStatus != "" {
                t.Errorf("SpfStatus = %q", item.SpfStatus)
        }
        if item.PostureHash != "" {
                t.Errorf("PostureHash = %q", item.PostureHash)
        }
        if item.ToolVersion != "" {
                t.Errorf("ToolVersion = %q", item.ToolVersion)
        }
        if !item.AnalysisSuccess {
                t.Error("AnalysisSuccess should be true")
        }
}

func TestBatch2_buildDossierItemFromSearch_populated(t *testing.T) {
        spf := "softfail"
        dmarc := "none"
        dkim := "fail"
        dur := 3.7
        hash := "xyz789"
        ts := time.Date(2025, 7, 4, 16, 0, 0, 0, time.UTC)
        fr, _ := json.Marshal(map[string]interface{}{"_tool_version": "v3.1.0"})

        a := dbq.SearchUserAnalysesRow{
                ID:               60,
                Domain:           "search-full.test.com",
                AsciiDomain:      "search-full.test.com",
                SpfStatus:        &spf,
                DmarcStatus:      &dmarc,
                DkimStatus:       &dkim,
                AnalysisDuration: &dur,
                PostureHash:      &hash,
                CreatedAt:        pgtype.Timestamp{Time: ts, Valid: true},
                FullResults:      json.RawMessage(fr),
        }
        item := buildDossierItemFromSearch(a)
        if item.SpfStatus != "softfail" {
                t.Errorf("SpfStatus = %q", item.SpfStatus)
        }
        if item.DmarcStatus != "none" {
                t.Errorf("DmarcStatus = %q", item.DmarcStatus)
        }
        if item.DkimStatus != "fail" {
                t.Errorf("DkimStatus = %q", item.DkimStatus)
        }
        if item.AnalysisDuration != 3.7 {
                t.Errorf("AnalysisDuration = %f", item.AnalysisDuration)
        }
        if item.PostureHash != "xyz789" {
                t.Errorf("PostureHash = %q", item.PostureHash)
        }
        if item.ToolVersion != "v3.1.0" {
                t.Errorf("ToolVersion = %q", item.ToolVersion)
        }
        if item.CreatedDate != "4 Jul 2025" {
                t.Errorf("CreatedDate = %q", item.CreatedDate)
        }
}

func TestBatch2_opsTaskList_coversWhitelist(t *testing.T) {
        tasks := opsTaskList()
        if len(tasks) != len(opsWhitelist) {
                t.Errorf("opsTaskList returned %d tasks, opsWhitelist has %d entries", len(tasks), len(opsWhitelist))
        }
        seen := make(map[string]bool)
        for _, task := range tasks {
                seen[task.ID] = true
                if task.Label == "" {
                        t.Errorf("task %q has empty Label", task.ID)
                }
                if task.Command == "" {
                        t.Errorf("task %q has empty Command", task.ID)
                }
                if len(task.Args) == 0 {
                        t.Errorf("task %q has no Args", task.ID)
                }
        }
        for id := range opsWhitelist {
                if !seen[id] {
                        t.Errorf("opsWhitelist key %q not in opsTaskList output", id)
                }
        }
}

func TestBatch2_opsWhitelist_allKeys(t *testing.T) {
        expectedKeys := []string{
                "css-cohesion", "feature-inventory", "scientific-colors",
                "render-diagrams", "figma-bundle", "figma-verify",
                "miro-sync", "full-pipeline",
        }
        for _, key := range expectedKeys {
                if _, ok := opsWhitelist[key]; !ok {
                        t.Errorf("opsWhitelist missing key %q", key)
                }
        }
}
