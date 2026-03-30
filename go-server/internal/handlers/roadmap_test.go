package handlers

import (
	"testing"
)

func TestRoadmapItemStruct(t *testing.T) {
	item := RoadmapItem{
		Title:    "Test Feature",
		Version:  "v1.0.0",
		Date:     "Feb 2026",
		Notes:    "Some notes",
		Type:     "Feature",
		Priority: "High",
	}
	if item.Title != "Test Feature" {
		t.Errorf("Title = %q, want 'Test Feature'", item.Title)
	}
	if item.Version != "v1.0.0" {
		t.Errorf("Version = %q, want 'v1.0.0'", item.Version)
	}
	if item.Priority != "High" {
		t.Errorf("Priority = %q, want 'High'", item.Priority)
	}
}

func TestNewRoadmapHandler(t *testing.T) {
	h := NewRoadmapHandler(nil)
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
}

func TestRoadmapPageConstants(t *testing.T) {
	if roadmapDateFeb2026 != "Feb 2026" {
		t.Errorf("roadmapDateFeb2026 = %q", roadmapDateFeb2026)
	}
	if roadmapTypeFeature != "Feature" {
		t.Errorf("roadmapTypeFeature = %q", roadmapTypeFeature)
	}
	if priorityLow != "Low" {
		t.Errorf("priorityLow = %q", priorityLow)
	}
	if priorityHigh != "High" {
		t.Errorf("priorityHigh = %q", priorityHigh)
	}
	if strMedium != "Medium" {
		t.Errorf("strMedium = %q", strMedium)
	}
	if strQuality != "Quality" {
		t.Errorf("strQuality = %q", strQuality)
	}
}

func TestRoadmapItemFields(t *testing.T) {
	item := RoadmapItem{
		Title:    "DoH/DoT Detection",
		Version:  "v27.0.0",
		Date:     "Mar 2026",
		Notes:    "Encrypted transport",
		Type:     "Feature",
		Priority: "High",
	}
	if item.Notes != "Encrypted transport" {
		t.Errorf("Notes = %q, want 'Encrypted transport'", item.Notes)
	}
	if item.Date != "Mar 2026" {
		t.Errorf("Date = %q, want 'Mar 2026'", item.Date)
	}
	if item.Type != "Feature" {
		t.Errorf("Type = %q, want 'Feature'", item.Type)
	}
}

func TestNewRoadmapHandlerNonNil(t *testing.T) {
	h := NewRoadmapHandler(nil)
	if h.Config != nil {
		t.Error("expected nil config when passing nil")
	}
}

func TestRoadmapVersionConstants(t *testing.T) {
	if roadmapVersionV2620 != "v26.20.0+" {
		t.Errorf("roadmapVersionV2620 = %q", roadmapVersionV2620)
	}
	if strV262594 != "v26.25.94" {
		t.Errorf("strV262594 = %q", strV262594)
	}
	if strV262602 != "v26.26.02" {
		t.Errorf("strV262602 = %q", strV262602)
	}
	if strV262605 != "v26.26.05" {
		t.Errorf("strV262605 = %q", strV262605)
	}
}

func TestRoadmapItemZeroValue(t *testing.T) {
	var item RoadmapItem
	if item.Title != "" || item.Version != "" || item.Priority != "" {
		t.Error("expected zero-value RoadmapItem to have empty fields")
	}
}
