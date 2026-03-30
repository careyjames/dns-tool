package handlers

import (
	"strings"
	"testing"
)

func TestOwlBadgePNG_NotEmpty(t *testing.T) {
	if owlBadgePNG == "" {
		t.Fatal("owlBadgePNG should not be empty")
	}
}

func TestOwlBadgePNG_HasDataURIPrefix(t *testing.T) {
	if !strings.HasPrefix(owlBadgePNG, "data:image/png;base64,") {
		t.Error("owlBadgePNG should start with data:image/png;base64,")
	}
}

func TestOwlBadgePNG_HasContent(t *testing.T) {
	parts := strings.SplitN(owlBadgePNG, ",", 2)
	if len(parts) != 2 || len(parts[1]) < 100 {
		t.Error("owlBadgePNG should contain substantial base64 data")
	}
}
