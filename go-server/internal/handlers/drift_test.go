package handlers

import (
	"encoding/json"
	"testing"
	"time"

	"dnstool/go-server/internal/analyzer"
	"dnstool/go-server/internal/dbq"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestConvertDriftEvents(t *testing.T) {
	t.Run("empty input", func(t *testing.T) {
		result := convertDriftEvents(nil)
		if len(result) != 0 {
			t.Errorf("expected 0 events, got %d", len(result))
		}
	})

	t.Run("single event with timestamp", func(t *testing.T) {
		ts := pgtype.Timestamp{
			Time:  time.Date(2026, 2, 15, 10, 30, 0, 0, time.UTC),
			Valid: true,
		}
		events := []dbq.DriftEvent{
			{
				ID:             1,
				Domain:         "example.com",
				AnalysisID:     10,
				PrevAnalysisID: 9,
				CurrentHash:    "abcdef1234567890abcdef1234567890",
				PreviousHash:   "1234567890abcdef1234567890abcdef",
				Severity:       "major",
				CreatedAt:      ts,
			},
		}

		result := convertDriftEvents(events)
		if len(result) != 1 {
			t.Fatalf("expected 1 event, got %d", len(result))
		}

		ev := result[0]
		if ev.ID != 1 {
			t.Errorf("expected ID=1, got %d", ev.ID)
		}
		if ev.Domain != "example.com" {
			t.Errorf("expected Domain=example.com, got %q", ev.Domain)
		}
		if ev.AnalysisID != 10 {
			t.Errorf("expected AnalysisID=10, got %d", ev.AnalysisID)
		}
		if ev.PrevAnalysisID != 9 {
			t.Errorf("expected PrevAnalysisID=9, got %d", ev.PrevAnalysisID)
		}
		if ev.CurrentHashShort != "abcdef1234567890" {
			t.Errorf("unexpected CurrentHashShort: %q", ev.CurrentHashShort)
		}
		if ev.PrevHashShort != "1234567890abcdef" {
			t.Errorf("unexpected PrevHashShort: %q", ev.PrevHashShort)
		}
		if ev.Severity != "major" {
			t.Errorf("expected Severity=major, got %q", ev.Severity)
		}
		if ev.CreatedAt != "15 Feb 2026 10:30 UTC" {
			t.Errorf("unexpected CreatedAt: %q", ev.CreatedAt)
		}
	})

	t.Run("event without timestamp", func(t *testing.T) {
		events := []dbq.DriftEvent{
			{
				ID:           2,
				Domain:       "test.com",
				CurrentHash:  "short",
				PreviousHash: "alsoshort",
				Severity:     "minor",
			},
		}

		result := convertDriftEvents(events)
		if result[0].CreatedAt != "" {
			t.Errorf("expected empty CreatedAt, got %q", result[0].CreatedAt)
		}
		if result[0].CurrentHashShort != "short" {
			t.Errorf("unexpected CurrentHashShort for short hash: %q", result[0].CurrentHashShort)
		}
	})

	t.Run("event with diff summary", func(t *testing.T) {
		fields := []analyzer.PostureDiffField{
			{Label: "spf_status", Previous: "success", Current: "warning"},
		}
		diffJSON, _ := json.Marshal(fields)
		events := []dbq.DriftEvent{
			{
				ID:          3,
				Domain:      "diff.com",
				DiffSummary: diffJSON,
				Severity:    "major",
			},
		}

		result := convertDriftEvents(events)
		if len(result[0].Fields) != 1 {
			t.Fatalf("expected 1 field, got %d", len(result[0].Fields))
		}
		if result[0].Fields[0].Label != "spf_status" {
			t.Errorf("unexpected field name: %q", result[0].Fields[0].Label)
		}
	})

	t.Run("event with invalid diff summary", func(t *testing.T) {
		events := []dbq.DriftEvent{
			{
				ID:          4,
				Domain:      "bad.com",
				DiffSummary: []byte("not json"),
				Severity:    "minor",
			},
		}

		result := convertDriftEvents(events)
		if len(result[0].Fields) != 0 {
			t.Errorf("expected 0 fields for invalid JSON, got %d", len(result[0].Fields))
		}
	})
}

func TestBuildHashHistory(t *testing.T) {
	t.Run("empty input", func(t *testing.T) {
		result := buildHashHistory(nil)
		if len(result) != 0 {
			t.Errorf("expected 0 entries, got %d", len(result))
		}
	})

	t.Run("single analysis", func(t *testing.T) {
		hash := "abc123def456"
		ts := pgtype.Timestamp{
			Time:  time.Date(2026, 2, 10, 12, 0, 0, 0, time.UTC),
			Valid: true,
		}
		analyses := []dbq.DomainAnalysis{
			{ID: 1, PostureHash: &hash, CreatedAt: ts},
		}

		result := buildHashHistory(analyses)
		if len(result) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(result))
		}
		if result[0].ID != 1 {
			t.Errorf("expected ID=1, got %d", result[0].ID)
		}
		if result[0].PostureHash != "abc123def456" {
			t.Errorf("unexpected PostureHash: %q", result[0].PostureHash)
		}
		if result[0].PostureHashShort != "abc123def456" {
			t.Errorf("unexpected PostureHashShort: %q", result[0].PostureHashShort)
		}
		if result[0].HashChanged {
			t.Error("expected HashChanged=false for single entry")
		}
		if result[0].CreatedAt != "10 Feb 2026 12:00 UTC" {
			t.Errorf("unexpected CreatedAt: %q", result[0].CreatedAt)
		}
	})

	t.Run("hash changes detected", func(t *testing.T) {
		hash1 := "aaaa1111bbbb2222cccc3333"
		hash2 := "dddd4444eeee5555ffff6666"
		hash3 := "dddd4444eeee5555ffff6666"
		ts1 := pgtype.Timestamp{Time: time.Date(2026, 2, 10, 0, 0, 0, 0, time.UTC), Valid: true}
		ts2 := pgtype.Timestamp{Time: time.Date(2026, 2, 11, 0, 0, 0, 0, time.UTC), Valid: true}
		ts3 := pgtype.Timestamp{Time: time.Date(2026, 2, 12, 0, 0, 0, 0, time.UTC), Valid: true}

		analyses := []dbq.DomainAnalysis{
			{ID: 1, PostureHash: &hash1, CreatedAt: ts1},
			{ID: 2, PostureHash: &hash2, CreatedAt: ts2},
			{ID: 3, PostureHash: &hash3, CreatedAt: ts3},
		}

		result := buildHashHistory(analyses)
		if len(result) != 3 {
			t.Fatalf("expected 3 entries, got %d", len(result))
		}

		changed := 0
		for _, e := range result {
			if e.HashChanged {
				changed++
			}
		}
		if changed != 1 {
			t.Errorf("expected exactly 1 hash change, got %d", changed)
		}
	})

	t.Run("nil posture hash", func(t *testing.T) {
		analyses := []dbq.DomainAnalysis{
			{ID: 1, PostureHash: nil},
		}

		result := buildHashHistory(analyses)
		if result[0].PostureHash != "" {
			t.Errorf("expected empty PostureHash, got %q", result[0].PostureHash)
		}
	})

	t.Run("preserves chronological order", func(t *testing.T) {
		hash1 := "hash_a"
		hash2 := "hash_b"
		analyses := []dbq.DomainAnalysis{
			{ID: 1, PostureHash: &hash1},
			{ID: 2, PostureHash: &hash2},
		}

		result := buildHashHistory(analyses)
		if result[0].ID != 1 || result[1].ID != 2 {
			t.Errorf("expected IDs [1,2], got [%d,%d]", result[0].ID, result[1].ID)
		}
	})
}

func TestDriftConstants(t *testing.T) {
	if templateDrift != "drift.html" {
		t.Errorf("unexpected templateDrift: %q", templateDrift)
	}
}

func TestNewDriftHandler(t *testing.T) {
	h := NewDriftHandler(nil, nil)
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
}
