package handlers

import (
	"encoding/json"
	"testing"
	"time"

	"dnstool/go-server/internal/dbq"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestBuildDossierItem(t *testing.T) {
	spf := "pass"
	dmarc := "fail"
	dkim := "none"
	dur := 1.234
	hash := "abc123"

	t.Run("all fields populated", func(t *testing.T) {
		ts := pgtype.Timestamp{Time: time.Date(2026, 2, 15, 14, 30, 0, 0, time.UTC), Valid: true}
		fullResults, _ := json.Marshal(map[string]any{"_tool_version": "v1.0.0"})

		row := dbq.ListUserAnalysesRow{
			ID:               42,
			Domain:           "example.com",
			AsciiDomain:      "example.com",
			SpfStatus:        &spf,
			DmarcStatus:      &dmarc,
			DkimStatus:       &dkim,
			AnalysisDuration: &dur,
			PostureHash:      &hash,
			CreatedAt:        ts,
			FullResults:      fullResults,
		}

		item := buildDossierItem(row)
		if item.ID != 42 {
			t.Errorf("ID = %d, want 42", item.ID)
		}
		if item.Domain != "example.com" {
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
		if item.AnalysisDuration != 1.234 {
			t.Errorf("AnalysisDuration = %f", item.AnalysisDuration)
		}
		if item.PostureHash != "abc123" {
			t.Errorf("PostureHash = %q", item.PostureHash)
		}
		if item.CreatedDate != "15 Feb 2026" {
			t.Errorf("CreatedDate = %q", item.CreatedDate)
		}
		if item.CreatedTime != "14:30 UTC" {
			t.Errorf("CreatedTime = %q", item.CreatedTime)
		}
		if item.ToolVersion != "v1.0.0" {
			t.Errorf("ToolVersion = %q", item.ToolVersion)
		}
		if !item.AnalysisSuccess {
			t.Error("expected AnalysisSuccess = true")
		}
	})

	t.Run("nil fields", func(t *testing.T) {
		row := dbq.ListUserAnalysesRow{
			ID:          1,
			Domain:      "test.com",
			AsciiDomain: "test.com",
			CreatedAt:   pgtype.Timestamp{Valid: false},
		}

		item := buildDossierItem(row)
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
		if item.PostureHash != "" {
			t.Errorf("PostureHash = %q, want empty", item.PostureHash)
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
		fullResults, _ := json.Marshal(map[string]any{"other": "data"})
		row := dbq.ListUserAnalysesRow{
			ID:          2,
			Domain:      "x.com",
			AsciiDomain: "x.com",
			FullResults: fullResults,
		}
		item := buildDossierItem(row)
		if item.ToolVersion != "" {
			t.Errorf("ToolVersion = %q, want empty", item.ToolVersion)
		}
	})
}

func TestBuildDossierItemFromSearch(t *testing.T) {
	spf := "pass"
	dur := 2.5

	t.Run("all fields populated", func(t *testing.T) {
		ts := pgtype.Timestamp{Time: time.Date(2026, 1, 10, 9, 0, 0, 0, time.UTC), Valid: true}
		fullResults, _ := json.Marshal(map[string]any{"_tool_version": "v2.0.0"})

		row := dbq.SearchUserAnalysesRow{
			ID:               99,
			Domain:           "search.com",
			AsciiDomain:      "search.com",
			SpfStatus:        &spf,
			AnalysisDuration: &dur,
			CreatedAt:        ts,
			FullResults:      fullResults,
		}

		item := buildDossierItemFromSearch(row)
		if item.ID != 99 {
			t.Errorf("ID = %d, want 99", item.ID)
		}
		if item.SpfStatus != "pass" {
			t.Errorf("SpfStatus = %q", item.SpfStatus)
		}
		if item.AnalysisDuration != 2.5 {
			t.Errorf("AnalysisDuration = %f", item.AnalysisDuration)
		}
		if item.CreatedDate != "10 Jan 2026" {
			t.Errorf("CreatedDate = %q", item.CreatedDate)
		}
		if item.ToolVersion != "v2.0.0" {
			t.Errorf("ToolVersion = %q", item.ToolVersion)
		}
	})

	t.Run("nil fields", func(t *testing.T) {
		row := dbq.SearchUserAnalysesRow{
			ID:          3,
			Domain:      "nil.com",
			AsciiDomain: "nil.com",
		}
		item := buildDossierItemFromSearch(row)
		if item.SpfStatus != "" || item.DmarcStatus != "" || item.DkimStatus != "" {
			t.Error("expected empty statuses for nil fields")
		}
		if item.AnalysisDuration != 0.0 {
			t.Error("expected 0 duration for nil")
		}
	})
}

func TestBuildDossierItemInvalidJSON(t *testing.T) {
	row := dbq.ListUserAnalysesRow{
		ID:          8,
		Domain:      "badjson.com",
		AsciiDomain: "badjson.com",
		FullResults: json.RawMessage(`{not valid json`),
	}
	item := buildDossierItem(row)
	if item.ToolVersion != "" {
		t.Errorf("ToolVersion = %q, want empty for invalid JSON", item.ToolVersion)
	}
	if !item.AnalysisSuccess {
		t.Error("expected AnalysisSuccess = true even with invalid JSON")
	}
}

func TestBuildDossierItemFromSearchInvalidJSON(t *testing.T) {
	row := dbq.SearchUserAnalysesRow{
		ID:          9,
		Domain:      "badjson2.com",
		AsciiDomain: "badjson2.com",
		FullResults: json.RawMessage(`!!!`),
	}
	item := buildDossierItemFromSearch(row)
	if item.ToolVersion != "" {
		t.Errorf("ToolVersion = %q, want empty for invalid JSON", item.ToolVersion)
	}
}

func TestBuildDossierItemToolVersionWrongType(t *testing.T) {
	fullResults, _ := json.Marshal(map[string]any{"_tool_version": 42})
	row := dbq.ListUserAnalysesRow{
		ID:          10,
		Domain:      "wrongtype.com",
		AsciiDomain: "wrongtype.com",
		FullResults: fullResults,
	}
	item := buildDossierItem(row)
	if item.ToolVersion != "" {
		t.Errorf("ToolVersion = %q, want empty for non-string _tool_version", item.ToolVersion)
	}
}

func TestBuildDossierItemFromSearchAllFields(t *testing.T) {
	spf := "pass"
	dmarc := "fail"
	dkim := "none"
	dur := 5.5
	hash := "xyz789"
	ts := pgtype.Timestamp{Time: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC), Valid: true}
	fullResults, _ := json.Marshal(map[string]any{"_tool_version": "v4.0.0"})

	row := dbq.SearchUserAnalysesRow{
		ID:               100,
		Domain:           "full.example.com",
		AsciiDomain:      "full.example.com",
		SpfStatus:        &spf,
		DmarcStatus:      &dmarc,
		DkimStatus:       &dkim,
		AnalysisDuration: &dur,
		PostureHash:      &hash,
		CreatedAt:        ts,
		FullResults:      fullResults,
	}

	item := buildDossierItemFromSearch(row)
	if item.DmarcStatus != "fail" {
		t.Errorf("DmarcStatus = %q, want fail", item.DmarcStatus)
	}
	if item.DkimStatus != "none" {
		t.Errorf("DkimStatus = %q, want none", item.DkimStatus)
	}
	if item.PostureHash != "xyz789" {
		t.Errorf("PostureHash = %q, want xyz789", item.PostureHash)
	}
	if item.CreatedDate != "1 Jun 2026" {
		t.Errorf("CreatedDate = %q", item.CreatedDate)
	}
	if item.CreatedTime != "12:00 UTC" {
		t.Errorf("CreatedTime = %q", item.CreatedTime)
	}
	if item.ToolVersion != "v4.0.0" {
		t.Errorf("ToolVersion = %q", item.ToolVersion)
	}
}

func TestBuildDossierItemEmptyFullResults(t *testing.T) {
	row := dbq.ListUserAnalysesRow{
		ID:          11,
		Domain:      "empty.com",
		AsciiDomain: "empty.com",
		FullResults: json.RawMessage(``),
	}
	item := buildDossierItem(row)
	if item.ToolVersion != "" {
		t.Errorf("ToolVersion = %q, want empty for empty FullResults", item.ToolVersion)
	}
}

func TestDossierConstants(t *testing.T) {
	if mapKeyDossier != "dossier" {
		t.Errorf("unexpected mapKeyDossier: %q", mapKeyDossier)
	}
	if templateDossier != "dossier.html" {
		t.Errorf("unexpected templateDossier: %q", templateDossier)
	}
}
