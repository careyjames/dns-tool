package handlers

import (
	"testing"
	"time"

	"dnstool/go-server/internal/telemetry"
)

func TestBuildProviderEntries(t *testing.T) {
	t.Run("empty slice", func(t *testing.T) {
		entries := buildProviderEntries(nil)
		if len(entries) != 0 {
			t.Errorf("expected 0 entries, got %d", len(entries))
		}
	})

	t.Run("single healthy provider", func(t *testing.T) {
		stats := []telemetry.ProviderStats{
			{
				Name:           "test-provider",
				State:          telemetry.Healthy,
				TotalRequests:  100,
				SuccessCount:   95,
				FailureCount:   5,
				ConsecFailures: 0,
				AvgLatencyMs:   50.0,
				P95LatencyMs:   120.0,
				InCooldown:     false,
			},
		}
		entries := buildProviderEntries(stats)
		if len(entries) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(entries))
		}
		e := entries[0]
		if e["name"] != "test-provider" {
			t.Errorf("name = %v", e["name"])
		}
		if e["state"] != "healthy" {
			t.Errorf("state = %v", e["state"])
		}
		if e["total_requests"] != int64(100) {
			t.Errorf("total_requests = %v", e["total_requests"])
		}
		if e["success_count"] != int64(95) {
			t.Errorf("success_count = %v", e["success_count"])
		}
		if e["in_cooldown"] != false {
			t.Errorf("in_cooldown = %v", e["in_cooldown"])
		}
		if _, ok := e["last_error"]; ok {
			t.Error("should not have last_error when empty")
		}
		if _, ok := e["last_error_time"]; ok {
			t.Error("should not have last_error_time when nil")
		}
		if _, ok := e["last_success_time"]; ok {
			t.Error("should not have last_success_time when nil")
		}
	})

	t.Run("provider with error and times", func(t *testing.T) {
		now := time.Now()
		stats := []telemetry.ProviderStats{
			{
				Name:            "failing-provider",
				State:           telemetry.Degraded,
				TotalRequests:   50,
				SuccessCount:    30,
				FailureCount:    20,
				ConsecFailures:  3,
				LastError:       "connection refused",
				LastErrorTime:   &now,
				LastSuccessTime: &now,
				AvgLatencyMs:    200.0,
				P95LatencyMs:    500.0,
				InCooldown:      true,
			},
		}
		entries := buildProviderEntries(stats)
		if len(entries) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(entries))
		}
		e := entries[0]
		if e["last_error"] != "connection refused" {
			t.Errorf("last_error = %v", e["last_error"])
		}
		if _, ok := e["last_error_time"]; !ok {
			t.Error("should have last_error_time")
		}
		if _, ok := e["last_success_time"]; !ok {
			t.Error("should have last_success_time")
		}
		if e["in_cooldown"] != true {
			t.Error("expected in_cooldown to be true")
		}
		if e["consecutive_failures"] != 3 {
			t.Errorf("consecutive_failures = %v", e["consecutive_failures"])
		}
	})

	t.Run("multiple providers", func(t *testing.T) {
		stats := []telemetry.ProviderStats{
			{Name: "a", State: telemetry.Healthy},
			{Name: "b", State: telemetry.Degraded},
			{Name: "c", State: telemetry.Unhealthy},
		}
		entries := buildProviderEntries(stats)
		if len(entries) != 3 {
			t.Fatalf("expected 3 entries, got %d", len(entries))
		}
	})
}

func TestComputeOverallHealth(t *testing.T) {
	t.Run("all healthy", func(t *testing.T) {
		stats := []telemetry.ProviderStats{
			{State: telemetry.Healthy},
			{State: telemetry.Healthy},
		}
		if got := computeOverallHealth(stats); got != "healthy" {
			t.Errorf("got %q, want healthy", got)
		}
	})

	t.Run("one degraded", func(t *testing.T) {
		stats := []telemetry.ProviderStats{
			{State: telemetry.Healthy},
			{State: telemetry.Degraded},
		}
		if got := computeOverallHealth(stats); got != "degraded" {
			t.Errorf("got %q, want degraded", got)
		}
	})

	t.Run("one unhealthy returns immediately", func(t *testing.T) {
		stats := []telemetry.ProviderStats{
			{State: telemetry.Healthy},
			{State: telemetry.Unhealthy},
			{State: telemetry.Degraded},
		}
		if got := computeOverallHealth(stats); got != "unhealthy" {
			t.Errorf("got %q, want unhealthy", got)
		}
	})

	t.Run("empty returns healthy", func(t *testing.T) {
		if got := computeOverallHealth(nil); got != "healthy" {
			t.Errorf("got %q, want healthy", got)
		}
	})
}

func TestNewHealthHandler(t *testing.T) {
	h := NewHealthHandler(nil, nil)
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
	if h.DB != nil {
		t.Error("expected nil DB")
	}
	if h.Analyzer != nil {
		t.Error("expected nil Analyzer")
	}
	if h.StartTime.IsZero() {
		t.Error("expected StartTime to be set")
	}
}
