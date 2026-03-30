package handlers

import (
        "testing"
        "time"

        "dnstool/go-server/internal/dbq"

        "github.com/jackc/pgx/v5/pgtype"
)

func TestMaskURL(t *testing.T) {
        tests := []struct {
                name     string
                input    string
                expected string
        }{
                {"short url", "https://example.com", "https://example.com"},
                {"exactly 30", "https://example.com/path12345/", "https://example.com/path12345/"},
                {"long url", "https://example.com/very-long-webhook-path/callbacks/abc123def456/XXXXXXXXXXXXXXXXXXXXXXXX", "https://example.com/...XXXXXXXXXX"},
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        got := maskURL(tc.input)
                        if got != tc.expected {
                                t.Errorf("maskURL(%q) = %q, want %q", tc.input, got, tc.expected)
                        }
                })
        }
}

func TestCadenceToNextRun(t *testing.T) {
        tests := []struct {
                name     string
                cadence  string
                minHours float64
                maxHours float64
        }{
                {"hourly", "hourly", 0.9, 1.1},
                {"daily", "daily", 23.9, 24.1},
                {"weekly", "weekly", 167.9, 168.1},
                {"default", "unknown", 23.9, 24.1},
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        before := time.Now().UTC()
                        result := cadenceToNextRun(tc.cadence)
                        if !result.Valid {
                                t.Fatal("expected valid timestamp")
                        }
                        diff := result.Time.Sub(before).Hours()
                        if diff < tc.minHours || diff > tc.maxHours {
                                t.Errorf("cadenceToNextRun(%q) diff = %f hours, want between %f and %f", tc.cadence, diff, tc.minHours, tc.maxHours)
                        }
                })
        }
}

func TestConvertWatchlistEntries(t *testing.T) {
        now := time.Now().UTC()
        entries := []dbq.DomainWatchlist{
                {
                        ID:        1,
                        Domain:    "example.com",
                        Cadence:   "daily",
                        Enabled:   true,
                        LastRunAt: pgtype.Timestamp{Time: now.Add(-1 * time.Hour), Valid: true},
                        NextRunAt: pgtype.Timestamp{Time: now.Add(23 * time.Hour), Valid: true},
                        CreatedAt: pgtype.Timestamp{Time: now.Add(-24 * time.Hour), Valid: true},
                },
                {
                        ID:      2,
                        Domain:  "test.org",
                        Cadence: "weekly",
                        Enabled: false,
                },
        }

        items := convertWatchlistEntries(entries)
        if len(items) != 2 {
                t.Fatalf("expected 2 items, got %d", len(items))
        }

        if items[0].ID != 1 || items[0].Domain != "example.com" || items[0].Cadence != "daily" || !items[0].Enabled {
                t.Errorf("unexpected first item: %+v", items[0])
        }
        if items[0].LastRunAt == "" {
                t.Error("expected non-empty LastRunAt for valid timestamp")
        }
        if items[0].NextRunAt == "" {
                t.Error("expected non-empty NextRunAt for valid timestamp")
        }
        if items[0].CreatedAt == "" {
                t.Error("expected non-empty CreatedAt for valid timestamp")
        }

        if items[1].LastRunAt != "" {
                t.Error("expected empty LastRunAt for invalid timestamp")
        }
        if items[1].NextRunAt != "" {
                t.Error("expected empty NextRunAt for invalid timestamp")
        }
        if items[1].CreatedAt != "" {
                t.Error("expected empty CreatedAt for invalid timestamp")
        }
}

func TestConvertWatchlistEntriesEmpty(t *testing.T) {
        items := convertWatchlistEntries(nil)
        if len(items) != 0 {
                t.Errorf("expected 0 items, got %d", len(items))
        }
}

func TestMaxWatchlistEntries(t *testing.T) {
        if maxWatchlistEntries != 25 {
                t.Errorf("maxWatchlistEntries = %d, want 25", maxWatchlistEntries)
        }
}

func TestTimeFormatDisplay(t *testing.T) {
        ref := time.Date(2026, 2, 25, 15, 4, 0, 0, time.UTC)
        got := ref.Format(timeFormatDisplay)
        if got != "25 Feb 2026 15:04 UTC" {
                t.Errorf("timeFormatDisplay produced %q, want '25 Feb 2026 15:04 UTC'", got)
        }
}

func TestMaskURLEdgeCases(t *testing.T) {
        tests := []struct {
                name     string
                input    string
                expected string
        }{
                {"empty string", "", ""},
                {"single char", "x", "x"},
                {"exactly 31 chars", "1234567890123456789012345678901", "12345678901234567890...2345678901"},
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        got := maskURL(tc.input)
                        if got != tc.expected {
                                t.Errorf("maskURL(%q) = %q, want %q", tc.input, got, tc.expected)
                        }
                })
        }
}

func TestCadenceToNextRunValid(t *testing.T) {
        result := cadenceToNextRun("hourly")
        if !result.Valid {
                t.Fatal("expected valid timestamp")
        }
        if result.Time.Before(time.Now().UTC()) {
                t.Error("expected future timestamp")
        }
}

func TestConvertWatchlistEntriesAllFieldsPresent(t *testing.T) {
        now := time.Now().UTC()
        entries := []dbq.DomainWatchlist{
                {
                        ID:        42,
                        Domain:    "sub.example.com",
                        Cadence:   "hourly",
                        Enabled:   false,
                        LastRunAt: pgtype.Timestamp{Time: now, Valid: true},
                        NextRunAt: pgtype.Timestamp{Time: now.Add(time.Hour), Valid: true},
                        CreatedAt: pgtype.Timestamp{Time: now.Add(-48 * time.Hour), Valid: true},
                },
        }

        items := convertWatchlistEntries(entries)
        if len(items) != 1 {
                t.Fatalf("expected 1 item, got %d", len(items))
        }
        item := items[0]
        if item.ID != 42 {
                t.Errorf("ID = %d, want 42", item.ID)
        }
        if item.Domain != "sub.example.com" {
                t.Errorf("Domain = %q, want sub.example.com", item.Domain)
        }
        if item.Cadence != "hourly" {
                t.Errorf("Cadence = %q, want hourly", item.Cadence)
        }
        if item.Enabled {
                t.Error("expected Enabled=false")
        }
}

func TestConvertWatchlistEntriesNoValidTimestamps(t *testing.T) {
        entries := []dbq.DomainWatchlist{
                {
                        ID:      1,
                        Domain:  "notime.com",
                        Cadence: "weekly",
                        Enabled: true,
                },
        }
        items := convertWatchlistEntries(entries)
        if items[0].LastRunAt != "" || items[0].NextRunAt != "" || items[0].CreatedAt != "" {
                t.Error("expected empty time strings for invalid timestamps")
        }
}

func TestTemplateWatchlistConstant(t *testing.T) {
        if templateWatchlist != "watchlist.html" {
                t.Errorf("templateWatchlist = %q, want watchlist.html", templateWatchlist)
        }
}

func TestPathWatchlistConstant(t *testing.T) {
        if pathWatchlist != "/watchlist" {
                t.Errorf("pathWatchlist = %q, want /watchlist", pathWatchlist)
        }
}
