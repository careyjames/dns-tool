package analyzer

import (
	"testing"
)

func TestMapKeysUtil(t *testing.T) {
	m := map[string]any{"a": 1, "b": 2, "c": 3}
	keys := mapKeys(m)
	if len(keys) != 3 {
		t.Errorf("mapKeys() len = %d, want 3", len(keys))
	}

	empty := mapKeys(map[string]any{})
	if len(empty) != 0 {
		t.Errorf("mapKeys(empty) len = %d, want 0", len(empty))
	}
}

func TestMinIntUtil(t *testing.T) {
	if minInt(3, 5) != 3 {
		t.Error("minInt(3,5) should be 3")
	}
	if minInt(5, 3) != 3 {
		t.Error("minInt(5,3) should be 3")
	}
	if minInt(4, 4) != 4 {
		t.Error("minInt(4,4) should be 4")
	}
}

func TestMaxIntUtil(t *testing.T) {
	if maxInt(3, 5) != 5 {
		t.Error("maxInt(3,5) should be 5")
	}
	if maxInt(5, 3) != 5 {
		t.Error("maxInt(5,3) should be 5")
	}
	if maxInt(4, 4) != 4 {
		t.Error("maxInt(4,4) should be 4")
	}
}

func TestJsonUnmarshalUtil(t *testing.T) {
	var result map[string]any
	err := jsonUnmarshal([]byte(`{"key":"value"}`), &result)
	if err != nil {
		t.Errorf("jsonUnmarshal() unexpected error: %v", err)
	}
	if result["key"] != "value" {
		t.Errorf("expected key=value, got %v", result["key"])
	}

	err = jsonUnmarshal([]byte(`invalid`), &result)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}
