package handlers

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestNewExportHandler(t *testing.T) {
	h := NewExportHandler(nil)
	if h == nil {
		t.Fatal("expected non-nil ExportHandler")
	}
	if h.DB != nil {
		t.Error("expected nil DB")
	}
}

func TestNewExportHandlerType(t *testing.T) {
	h := NewExportHandler(nil)
	var _ *ExportHandler = h
	if h == nil {
		t.Fatal("expected non-nil ExportHandler")
	}
}

func TestExportFilenameFormat(t *testing.T) {
	ts := time.Date(2025, 6, 15, 14, 30, 45, 0, time.UTC)
	timestamp := ts.Format("20060102_150405")
	filename := fmt.Sprintf("dns_tool_export_%s.ndjson", timestamp)
	if filename != "dns_tool_export_20250615_143045.ndjson" {
		t.Errorf("unexpected filename: %s", filename)
	}
	if !strings.HasPrefix(filename, "dns_tool_export_") {
		t.Error("filename should start with dns_tool_export_")
	}
	if !strings.HasSuffix(filename, ".ndjson") {
		t.Error("filename should end with .ndjson")
	}
}

func TestFormatTimestampValid(t *testing.T) {
	ts := pgtype.Timestamp{
		Time:  time.Date(2025, 3, 15, 10, 30, 0, 0, time.UTC),
		Valid: true,
	}
	result := formatTimestamp(ts)
	if result != "15 Mar 2025, 10:30 UTC" {
		t.Errorf("formatTimestamp = %q, want %q", result, "15 Mar 2025, 10:30 UTC")
	}
}

func TestFormatTimestampInvalid(t *testing.T) {
	ts := pgtype.Timestamp{Valid: false}
	result := formatTimestamp(ts)
	if result != "" {
		t.Errorf("expected empty string for invalid timestamp, got %q", result)
	}
}

func TestFormatTimestampISOValid(t *testing.T) {
	ts := pgtype.Timestamp{
		Time:  time.Date(2025, 3, 15, 10, 30, 0, 0, time.UTC),
		Valid: true,
	}
	result := formatTimestampISO(ts)
	if result != "2025-03-15T10:30:00Z" {
		t.Errorf("formatTimestampISO = %q, want %q", result, "2025-03-15T10:30:00Z")
	}
}

func TestFormatTimestampISOInvalid(t *testing.T) {
	ts := pgtype.Timestamp{Valid: false}
	result := formatTimestampISO(ts)
	if result != "" {
		t.Errorf("expected empty string for invalid timestamp, got %q", result)
	}
}

func TestFormatTimestampISOContainsT(t *testing.T) {
	ts := pgtype.Timestamp{
		Time:  time.Date(2024, 12, 25, 0, 0, 0, 0, time.UTC),
		Valid: true,
	}
	result := formatTimestampISO(ts)
	if !strings.Contains(result, "T") {
		t.Error("ISO timestamp should contain T separator")
	}
	if !strings.HasSuffix(result, "Z") {
		t.Error("ISO timestamp should end with Z")
	}
}

func TestFormatTimestampUTCOutput(t *testing.T) {
	ts := pgtype.Timestamp{
		Time:  time.Date(2025, 1, 1, 23, 59, 59, 0, time.UTC),
		Valid: true,
	}
	result := formatTimestamp(ts)
	if !strings.HasSuffix(result, "UTC") {
		t.Error("human timestamp should end with UTC")
	}
}

func TestExportHandlerNilDB(t *testing.T) {
	h := NewExportHandler(nil)
	if h.DB != nil {
		t.Error("expected nil DB for nil input")
	}
}

func TestExportFilenameTimestampFormat(t *testing.T) {
	tests := []struct {
		name    string
		t       time.Time
		wantSub string
	}{
		{"midnight", time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), "20250101_000000"},
		{"end of day", time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC), "20251231_235959"},
		{"leap year", time.Date(2024, 2, 29, 12, 0, 0, 0, time.UTC), "20240229_120000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			timestamp := tt.t.Format("20060102_150405")
			filename := fmt.Sprintf("dns_tool_export_%s.ndjson", timestamp)
			if !strings.Contains(filename, tt.wantSub) {
				t.Errorf("filename %q missing %q", filename, tt.wantSub)
			}
			if !strings.HasSuffix(filename, ".ndjson") {
				t.Error("filename should end with .ndjson")
			}
		})
	}
}

func TestFormatTimestampEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		ts   pgtype.Timestamp
		want string
	}{
		{"epoch", pgtype.Timestamp{Time: time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC), Valid: true}, "1 Jan 1970, 00:00 UTC"},
		{"far future", pgtype.Timestamp{Time: time.Date(2099, 12, 31, 23, 59, 0, 0, time.UTC), Valid: true}, "31 Dec 2099, 23:59 UTC"},
		{"single digit day", pgtype.Timestamp{Time: time.Date(2025, 3, 5, 9, 5, 0, 0, time.UTC), Valid: true}, "5 Mar 2025, 09:05 UTC"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatTimestamp(tt.ts)
			if got != tt.want {
				t.Errorf("formatTimestamp = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatTimestampISOEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		ts   pgtype.Timestamp
		want string
	}{
		{"epoch", pgtype.Timestamp{Time: time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC), Valid: true}, "1970-01-01T00:00:00Z"},
		{"far future", pgtype.Timestamp{Time: time.Date(2099, 12, 31, 23, 59, 59, 0, time.UTC), Valid: true}, "2099-12-31T23:59:59Z"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatTimestampISO(tt.ts)
			if got != tt.want {
				t.Errorf("formatTimestampISO = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExportHandlerZeroValue(t *testing.T) {
	h := &ExportHandler{}
	if h.DB != nil {
		t.Error("zero-value ExportHandler.DB should be nil")
	}
}

func TestExportFilenamePrefix(t *testing.T) {
	now := time.Now().UTC()
	timestamp := now.Format("20060102_150405")
	filename := fmt.Sprintf("dns_tool_export_%s.ndjson", timestamp)
	if !strings.HasPrefix(filename, "dns_tool_export_") {
		t.Error("export filename should start with dns_tool_export_")
	}
	if len(filename) != len("dns_tool_export_20060102_150405.ndjson") {
		t.Errorf("unexpected filename length: %d", len(filename))
	}
}
