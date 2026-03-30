package handlers

import (
	"testing"
)

func TestBuildPagination_FirstPage(t *testing.T) {
	pd := BuildPagination(1, 10, 100)
	if !pd.HasNext {
		t.Error("expected HasNext = true")
	}
	if pd.HasPrev {
		t.Error("expected HasPrev = false for first page")
	}
	if pd.NextPage != 2 {
		t.Errorf("NextPage = %d, want 2", pd.NextPage)
	}
	if pd.PrevPage != 0 {
		t.Errorf("PrevPage = %d, want 0", pd.PrevPage)
	}
}

func TestBuildPagination_LastPage(t *testing.T) {
	pd := BuildPagination(10, 10, 100)
	if pd.HasNext {
		t.Error("expected HasNext = false for last page")
	}
	if !pd.HasPrev {
		t.Error("expected HasPrev = true")
	}
}

func TestBuildPagination_MiddlePage(t *testing.T) {
	pd := BuildPagination(5, 10, 100)
	if !pd.HasNext {
		t.Error("expected HasNext = true")
	}
	if !pd.HasPrev {
		t.Error("expected HasPrev = true")
	}
	if pd.Total != 100 {
		t.Errorf("Total = %d, want 100", pd.Total)
	}
}

func TestBuildPagination_SinglePage(t *testing.T) {
	pd := BuildPagination(1, 1, 5)
	if pd.HasNext {
		t.Error("expected HasNext = false")
	}
	if pd.HasPrev {
		t.Error("expected HasPrev = false")
	}
}

func TestIterPages_SmallTotal(t *testing.T) {
	pages := iterPages(1, 3)
	if len(pages) != 3 {
		t.Errorf("expected 3 pages, got %d", len(pages))
	}
	if !pages[0].IsActive {
		t.Error("first page should be active")
	}
}

func TestIterPages_LargeTotal_HasGaps(t *testing.T) {
	pages := iterPages(50, 100)
	hasGap := false
	for _, p := range pages {
		if p.IsGap {
			hasGap = true
			break
		}
	}
	if !hasGap {
		t.Error("expected gaps in large pagination")
	}
}

func TestIterPages_LeftEdge(t *testing.T) {
	pages := iterPages(1, 20)
	if pages[0].Number != 1 {
		t.Error("first page should be 1")
	}
	if pages[0].IsActive != true {
		t.Error("page 1 should be active")
	}
}

func TestFlashMessage_Struct(t *testing.T) {
	fm := FlashMessage{Category: "danger", Message: "Error occurred"}
	if fm.Category != "danger" {
		t.Errorf("Category = %q", fm.Category)
	}
	if fm.Message != "Error occurred" {
		t.Errorf("Message = %q", fm.Message)
	}
}

func TestAnalysisItem_Struct(t *testing.T) {
	item := AnalysisItem{
		ID:              1,
		Domain:          "example.com",
		SpfStatus:       "pass",
		DmarcStatus:     "pass",
		DkimStatus:      "pass",
		AnalysisSuccess: true,
	}
	if item.Domain != "example.com" {
		t.Errorf("Domain = %q", item.Domain)
	}
}

func TestDiffItem_Struct(t *testing.T) {
	di := DiffItem{
		Label:   "SPF Status",
		Changed: true,
		StatusA: "pass",
		StatusB: "fail",
	}
	if !di.Changed {
		t.Error("expected Changed = true")
	}
}

func TestDiffChange_Struct(t *testing.T) {
	dc := DiffChange{
		Field:  "policy",
		OldStr: "none",
		NewStr: "reject",
	}
	if dc.Field != "policy" {
		t.Errorf("Field = %q", dc.Field)
	}
}
