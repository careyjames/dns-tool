package handlers

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestFormatTimestamp_Valid(t *testing.T) {
	ts := pgtype.Timestamp{
		Time:  time.Date(2026, 3, 15, 14, 30, 0, 0, time.UTC),
		Valid: true,
	}
	result := formatTimestamp(ts)
	if result != "15 Mar 2026, 14:30 UTC" {
		t.Errorf("formatTimestamp = %q", result)
	}
}

func TestFormatTimestamp_Invalid(t *testing.T) {
	ts := pgtype.Timestamp{Valid: false}
	result := formatTimestamp(ts)
	if result != "" {
		t.Errorf("formatTimestamp(invalid) = %q, want empty", result)
	}
}

func TestFormatTimestampISO_Valid(t *testing.T) {
	ts := pgtype.Timestamp{
		Time:  time.Date(2026, 3, 15, 14, 30, 0, 0, time.UTC),
		Valid: true,
	}
	result := formatTimestampISO(ts)
	if result != "2026-03-15T14:30:00Z" {
		t.Errorf("formatTimestampISO = %q", result)
	}
}

func TestFormatTimestampISO_Invalid(t *testing.T) {
	ts := pgtype.Timestamp{Valid: false}
	result := formatTimestampISO(ts)
	if result != "" {
		t.Errorf("formatTimestampISO(invalid) = %q, want empty", result)
	}
}
