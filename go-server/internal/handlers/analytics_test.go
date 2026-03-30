package handlers

import (
	"sort"
	"testing"
)

func TestTopN_NIsZero(t *testing.T) {
	m := map[string]int{"google": 10, "bing": 5}
	result := topN(m, 0)
	if len(result) != 0 {
		t.Errorf("expected 0 entries for n=0, got %d", len(result))
	}
}

func TestTopNPages_NIsZero(t *testing.T) {
	m := map[string]int{"/home": 10, "/about": 5}
	result := topNPages(m, 0)
	if len(result) != 0 {
		t.Errorf("expected 0 entries for n=0, got %d", len(result))
	}
}

func TestTopN_TieBreaking(t *testing.T) {
	m := map[string]int{"a": 10, "b": 10, "c": 10}
	result := topN(m, 3)
	if len(result) != 3 {
		t.Fatalf("expected 3, got %d", len(result))
	}
	sources := make([]string, len(result))
	for i, r := range result {
		sources[i] = r.Source
	}
	sort.Strings(sources)
	expected := []string{"a", "b", "c"}
	for i, s := range sources {
		if s != expected[i] {
			t.Errorf("sources[%d] = %q, want %q", i, s, expected[i])
		}
	}
}

func TestTopN_SingleEntry(t *testing.T) {
	m := map[string]int{"solo": 42}
	result := topN(m, 1)
	if len(result) != 1 {
		t.Fatalf("expected 1, got %d", len(result))
	}
	if result[0].Source != "solo" || result[0].Count != 42 {
		t.Errorf("result = %+v", result[0])
	}
}

func TestTopNPages_SingleEntry(t *testing.T) {
	m := map[string]int{"/solo": 99}
	result := topNPages(m, 1)
	if len(result) != 1 {
		t.Fatalf("expected 1, got %d", len(result))
	}
	if result[0].Path != "/solo" || result[0].Count != 99 {
		t.Errorf("result = %+v", result[0])
	}
}
