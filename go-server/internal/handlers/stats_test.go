package handlers

import (
	"dnstool/go-server/internal/config"
	"testing"
)

func TestTopN_Empty(t *testing.T) {
	result := topN(nil, 10)
	if len(result) != 0 {
		t.Errorf("expected 0 entries, got %d", len(result))
	}
}

func TestTopN_LessThanN(t *testing.T) {
	m := map[string]int{"a": 5, "b": 3}
	result := topN(m, 10)
	if len(result) != 2 {
		t.Errorf("expected 2 entries, got %d", len(result))
	}
}

func TestTopN_MoreThanN(t *testing.T) {
	m := map[string]int{"a": 5, "b": 3, "c": 8}
	result := topN(m, 2)
	if len(result) != 2 {
		t.Errorf("expected 2 entries, got %d", len(result))
	}
	if result[0].Count < result[1].Count {
		t.Error("expected sorted by count descending")
	}
}

func TestTopNPages_Empty(t *testing.T) {
	result := topNPages(nil, 10)
	if len(result) != 0 {
		t.Errorf("expected 0 entries, got %d", len(result))
	}
}

func TestTopNPages_Sorting(t *testing.T) {
	m := map[string]int{"/": 100, "/about": 50, "/faq": 75}
	result := topNPages(m, 3)
	if len(result) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(result))
	}
	if result[0].Count != 100 {
		t.Errorf("first entry count = %d, want 100", result[0].Count)
	}
}

func TestComputeSummary_Empty(t *testing.T) {
	h := &AnalyticsHandler{Config: &config.Config{}}
	summary := h.computeSummary(nil, nil)
	if summary.DaysTracked != 0 {
		t.Errorf("DaysTracked = %d, want 0", summary.DaysTracked)
	}
	if summary.AvgDailyPageviews != 0 {
		t.Errorf("AvgDailyPageviews = %d", summary.AvgDailyPageviews)
	}
}

func TestComputeSummary_WithData(t *testing.T) {
	h := &AnalyticsHandler{Config: &config.Config{}}
	days := []AnalyticsDay{
		{
			Date:                  "2026-03-01",
			Pageviews:             100,
			UniqueVisitors:        50,
			AnalysesRun:           10,
			UniqueDomainsAnalyzed: 5,
			ReferrerSources:       map[string]int{"google": 30},
			TopPages:              map[string]int{"/": 80},
		},
		{
			Date:                  "2026-03-02",
			Pageviews:             200,
			UniqueVisitors:        80,
			AnalysesRun:           20,
			UniqueDomainsAnalyzed: 15,
			ReferrerSources:       map[string]int{"google": 40, "bing": 10},
			TopPages:              map[string]int{"/": 120, "/about": 30},
		},
	}
	summary := h.computeSummary(nil, days)
	if summary.TotalPageviews != 300 {
		t.Errorf("TotalPageviews = %d, want 300", summary.TotalPageviews)
	}
	if summary.TotalUniqueVisitors != 130 {
		t.Errorf("TotalUniqueVisitors = %d, want 130", summary.TotalUniqueVisitors)
	}
	if summary.DaysTracked != 2 {
		t.Errorf("DaysTracked = %d, want 2", summary.DaysTracked)
	}
	if summary.AvgDailyPageviews != 150 {
		t.Errorf("AvgDailyPageviews = %d, want 150", summary.AvgDailyPageviews)
	}
}
