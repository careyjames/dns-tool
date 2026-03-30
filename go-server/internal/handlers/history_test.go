package handlers

import (
	"encoding/json"
	"testing"
	"time"

	"dnstool/go-server/internal/dbq"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestBuildHistoryItem(t *testing.T) {
	spf := "pass"
	dmarc := "fail"
	dkim := "none"
	dur := 3.14

	t.Run("all fields populated", func(t *testing.T) {
		ts := pgtype.Timestamp{Time: time.Date(2026, 3, 20, 16, 45, 0, 0, time.UTC), Valid: true}
		fullResults, _ := json.Marshal(map[string]any{"_tool_version": "v3.0.0"})

		row := dbq.DomainAnalysis{
			ID:               10,
			Domain:           "history.com",
			AsciiDomain:      "history.com",
			SpfStatus:        &spf,
			DmarcStatus:      &dmarc,
			DkimStatus:       &dkim,
			AnalysisDuration: &dur,
			CreatedAt:        ts,
			FullResults:      fullResults,
		}

		item := buildHistoryItem(row)
		if item.ID != 10 {
			t.Errorf("ID = %d, want 10", item.ID)
		}
		if item.Domain != "history.com" {
			t.Errorf("Domain = %q", item.Domain)
		}
		if item.SpfStatus != "pass" {
			t.Errorf("SpfStatus = %q", item.SpfStatus)
		}
		if item.DmarcStatus != "fail" {
			t.Errorf("DmarcStatus = %q", item.DmarcStatus)
		}
		if item.DkimStatus != "none" {
			t.Errorf("DkimStatus = %q", item.DkimStatus)
		}
		if item.AnalysisDuration != 3.14 {
			t.Errorf("AnalysisDuration = %f", item.AnalysisDuration)
		}
		if item.CreatedDate != "20 Mar 2026" {
			t.Errorf("CreatedDate = %q", item.CreatedDate)
		}
		if item.CreatedTime != "16:45 UTC" {
			t.Errorf("CreatedTime = %q", item.CreatedTime)
		}
		if item.ToolVersion != "v3.0.0" {
			t.Errorf("ToolVersion = %q", item.ToolVersion)
		}
	})

	t.Run("nil fields", func(t *testing.T) {
		row := dbq.DomainAnalysis{
			ID:          5,
			Domain:      "nil.com",
			AsciiDomain: "nil.com",
			CreatedAt:   pgtype.Timestamp{Valid: false},
		}

		item := buildHistoryItem(row)
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
		if item.CreatedTime != "" {
			t.Errorf("CreatedTime = %q, want empty", item.CreatedTime)
		}
		if item.ToolVersion != "" {
			t.Errorf("ToolVersion = %q, want empty", item.ToolVersion)
		}
	})

	t.Run("full_results without tool version", func(t *testing.T) {
		fullResults, _ := json.Marshal(map[string]any{"other_key": "value"})
		row := dbq.DomainAnalysis{
			ID:          6,
			Domain:      "notool.com",
			AsciiDomain: "notool.com",
			FullResults: fullResults,
		}
		item := buildHistoryItem(row)
		if item.ToolVersion != "" {
			t.Errorf("ToolVersion = %q, want empty", item.ToolVersion)
		}
	})

	t.Run("invalid json in full_results", func(t *testing.T) {
		row := dbq.DomainAnalysis{
			ID:          7,
			Domain:      "bad.com",
			AsciiDomain: "bad.com",
			FullResults: json.RawMessage(`{invalid`),
		}
		item := buildHistoryItem(row)
		if item.ToolVersion != "" {
			t.Errorf("ToolVersion = %q, want empty for invalid JSON", item.ToolVersion)
		}
	})
}

func TestBuildHistoryItemToolVersionWrongType(t *testing.T) {
	fullResults, _ := json.Marshal(map[string]any{"_tool_version": 123})
	row := dbq.DomainAnalysis{
		ID:          8,
		Domain:      "wrongtype.com",
		AsciiDomain: "wrongtype.com",
		FullResults: fullResults,
	}
	item := buildHistoryItem(row)
	if item.ToolVersion != "" {
		t.Errorf("ToolVersion = %q, want empty for non-string _tool_version", item.ToolVersion)
	}
}

func TestBuildHistoryItemEmptyFullResults(t *testing.T) {
	row := dbq.DomainAnalysis{
		ID:          9,
		Domain:      "empty.com",
		AsciiDomain: "empty.com",
		FullResults: json.RawMessage(``),
	}
	item := buildHistoryItem(row)
	if item.ToolVersion != "" {
		t.Errorf("ToolVersion = %q, want empty", item.ToolVersion)
	}
}

func TestBuildHistoryItemPartialFields(t *testing.T) {
	spf := "pass"
	row := dbq.DomainAnalysis{
		ID:          10,
		Domain:      "partial.com",
		AsciiDomain: "partial.com",
		SpfStatus:   &spf,
		CreatedAt:   pgtype.Timestamp{Time: time.Date(2026, 12, 31, 23, 59, 0, 0, time.UTC), Valid: true},
	}
	item := buildHistoryItem(row)
	if item.SpfStatus != "pass" {
		t.Errorf("SpfStatus = %q, want pass", item.SpfStatus)
	}
	if item.DmarcStatus != "" {
		t.Errorf("DmarcStatus = %q, want empty", item.DmarcStatus)
	}
	if item.DkimStatus != "" {
		t.Errorf("DkimStatus = %q, want empty", item.DkimStatus)
	}
	if item.CreatedDate != "31 Dec 2026" {
		t.Errorf("CreatedDate = %q", item.CreatedDate)
	}
	if item.CreatedTime != "23:59 UTC" {
		t.Errorf("CreatedTime = %q", item.CreatedTime)
	}
	if item.AnalysisDuration != 0.0 {
		t.Errorf("AnalysisDuration = %f, want 0", item.AnalysisDuration)
	}
}

func TestBuildHistoryItemAsciiDomain(t *testing.T) {
	row := dbq.DomainAnalysis{
		ID:          11,
		Domain:      "münchen.de",
		AsciiDomain: "xn--mnchen-3ya.de",
	}
	item := buildHistoryItem(row)
	if item.Domain != "münchen.de" {
		t.Errorf("Domain = %q", item.Domain)
	}
	if item.AsciiDomain != "xn--mnchen-3ya.de" {
		t.Errorf("AsciiDomain = %q", item.AsciiDomain)
	}
}

func TestHistoryConstants(t *testing.T) {
	if templateHistory != "history.html" {
		t.Errorf("unexpected templateHistory: %q", templateHistory)
	}
	if mapKeyHistory != "history" {
		t.Errorf("unexpected mapKeyHistory: %q", mapKeyHistory)
	}
}
