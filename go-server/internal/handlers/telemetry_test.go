package handlers

import (
	"dnstool/go-server/internal/config"
	"testing"
)

func TestNewTelemetryHandler(t *testing.T) {
	h := NewTelemetryHandler(nil, &config.Config{})
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
	if h.DB != nil {
		t.Error("expected nil DB")
	}
}
