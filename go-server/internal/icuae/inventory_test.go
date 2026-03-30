package icuae

import (
	"testing"
)

func TestGetTestInventory_NonNil(t *testing.T) {
	inv := GetTestInventory()
	if inv == nil {
		t.Fatal("GetTestInventory returned nil")
	}
}

func TestGetTestInventory_Categories(t *testing.T) {
	inv := GetTestInventory()
	if len(inv.Categories) == 0 {
		t.Fatal("expected non-empty Categories")
	}
	for i, cat := range inv.Categories {
		if cat.Name == "" {
			t.Errorf("Categories[%d].Name is empty", i)
		}
		if cat.Standard == "" {
			t.Errorf("Categories[%d].Standard is empty", i)
		}
		if cat.Cases <= 0 {
			t.Errorf("Categories[%d].Cases = %d, want > 0", i, cat.Cases)
		}
		if cat.Icon == "" {
			t.Errorf("Categories[%d].Icon is empty", i)
		}
	}
}

func TestGetTestInventory_TotalCases(t *testing.T) {
	inv := GetTestInventory()
	sum := 0
	for _, cat := range inv.Categories {
		sum += cat.Cases
	}
	if inv.TotalCases != sum {
		t.Errorf("TotalCases = %d, but sum of category cases = %d", inv.TotalCases, sum)
	}
}

func TestGetTestInventory_TotalDimensions(t *testing.T) {
	inv := GetTestInventory()
	if inv.TotalDimensions <= 0 {
		t.Errorf("TotalDimensions = %d, want > 0", inv.TotalDimensions)
	}
}

func TestGetTestInventory_KnownCategories(t *testing.T) {
	inv := GetTestInventory()
	expected := []string{
		"Score-to-Grade Boundaries",
		"Currentness",
		"TTL Compliance",
		"Completeness",
		"Source Credibility",
		"TTL Relevance",
		"Integration & Constants",
	}
	if len(inv.Categories) != len(expected) {
		t.Fatalf("expected %d categories, got %d", len(expected), len(inv.Categories))
	}
	for i, name := range expected {
		if inv.Categories[i].Name != name {
			t.Errorf("Categories[%d].Name = %q, want %q", i, inv.Categories[i].Name, name)
		}
	}
}
