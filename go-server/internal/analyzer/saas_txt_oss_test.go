//go:build !intel

package analyzer

import (
	"testing"
)

func TestMatchSaaSPatterns_OSS_NoOp(t *testing.T) {
	seen := make(map[string]bool)
	var services []map[string]any
	matchSaaSPatterns("google-site-verification=abc", seen, &services)
	if len(services) != 0 {
		t.Errorf("OSS stub should not add services, got %d", len(services))
	}
}

func TestSaaSPatterns_OSS_Empty(t *testing.T) {
	if len(saasPatterns) != 0 {
		t.Errorf("saasPatterns should be empty in OSS build, got %d", len(saasPatterns))
	}
}
