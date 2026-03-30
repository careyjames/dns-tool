package logging

import (
	"log/slog"
	"testing"
)

func TestScanStarted(t *testing.T) {
	attrs := ScanStarted("example.com", "trace-123", 42)
	if len(attrs) < 4 {
		t.Fatalf("expected at least 4 attrs, got %d", len(attrs))
	}

	m := attrMap(attrs)
	if m[AttrEvent] != EventScanStarted {
		t.Errorf("event = %q, want %q", m[AttrEvent], EventScanStarted)
	}
	if m[AttrCategory] != CategoryScan {
		t.Errorf("category = %q, want %q", m[AttrCategory], CategoryScan)
	}
	if m[AttrDomain] != "example.com" {
		t.Errorf("domain = %q", m[AttrDomain])
	}
}

func TestScanCompleted(t *testing.T) {
	attrs := ScanCompleted("example.com", "trace-456", 10, 1500)
	m := attrMap(attrs)

	if m[AttrEvent] != EventScanCompleted {
		t.Errorf("event = %q", m[AttrEvent])
	}
	if m[AttrOutcome] != "success" {
		t.Errorf("outcome = %q, want 'success'", m[AttrOutcome])
	}
}

func TestScanFailed(t *testing.T) {
	attrs := ScanFailed("example.com", "trace-789", "resolver timeout")
	m := attrMap(attrs)

	if m[AttrEvent] != EventScanFailed {
		t.Errorf("event = %q", m[AttrEvent])
	}
	if m[AttrOutcome] != "failure" {
		t.Errorf("outcome = %q", m[AttrOutcome])
	}
	if m[AttrErrorChain] != "resolver timeout" {
		t.Errorf("error_chain = %q", m[AttrErrorChain])
	}
}

func TestPhaseStarted(t *testing.T) {
	attrs := PhaseStarted("example.com", "trace-1", "dns", "spf_lookup")
	m := attrMap(attrs)

	if m[AttrPhaseGroup] != "dns" {
		t.Errorf("phase_group = %q", m[AttrPhaseGroup])
	}
	if m[AttrPhaseTask] != "spf_lookup" {
		t.Errorf("phase_task = %q", m[AttrPhaseTask])
	}
}

func TestPhaseFinished(t *testing.T) {
	attrs := PhaseFinished("example.com", "trace-2", "dns", "spf_lookup", 150, "success")
	m := attrMap(attrs)

	if m[AttrEvent] != EventPhaseFinished {
		t.Errorf("event = %q", m[AttrEvent])
	}
	if m[AttrOutcome] != "success" {
		t.Errorf("outcome = %q", m[AttrOutcome])
	}
}

func TestSecurityEvent(t *testing.T) {
	attrs := SecurityEvent(EventCSRFReject, "trace-3", "10.0.0.1",
		slog.String("path", "/login"),
	)
	m := attrMap(attrs)

	if m[AttrEvent] != EventCSRFReject {
		t.Errorf("event = %q", m[AttrEvent])
	}
	if m[AttrCategory] != CategorySecurity {
		t.Errorf("category = %q", m[AttrCategory])
	}
	if m[AttrRemoteAddr] != "10.0.0.1" {
		t.Errorf("remote_addr = %q", m[AttrRemoteAddr])
	}
	if m["path"] != "/login" {
		t.Errorf("path = %q", m["path"])
	}
}

func TestExternalCall(t *testing.T) {
	attrs := ExternalCall("ipinfo", "trace-4", 200, 350, "success")
	m := attrMap(attrs)

	if m[AttrExternalService] != "ipinfo" {
		t.Errorf("external_service = %q", m[AttrExternalService])
	}
	if m[AttrEvent] != EventExternalCall {
		t.Errorf("event = %q", m[AttrEvent])
	}
}

func TestAttrsToAny(t *testing.T) {
	attrs := []slog.Attr{
		slog.String("key1", "value1"),
		slog.Int("key2", 42),
	}
	result := AttrsToAny(attrs)
	if len(result) != 4 {
		t.Fatalf("expected 4 items, got %d", len(result))
	}
	if result[0] != "key1" {
		t.Errorf("result[0] = %v, want 'key1'", result[0])
	}
}

func TestAttrsToAny_Empty(t *testing.T) {
	result := AttrsToAny(nil)
	if len(result) != 0 {
		t.Errorf("expected 0 items, got %d", len(result))
	}
}

func TestConstants(t *testing.T) {
	if CategoryScan != "scan" {
		t.Errorf("CategoryScan = %q", CategoryScan)
	}
	if CategorySecurity != "security" {
		t.Errorf("CategorySecurity = %q", CategorySecurity)
	}
	if EventScanStarted != "scan_started" {
		t.Errorf("EventScanStarted = %q", EventScanStarted)
	}
	if AttrEvent != "event" {
		t.Errorf("AttrEvent = %q", AttrEvent)
	}
	if AttrTraceID != "trace_id" {
		t.Errorf("AttrTraceID = %q", AttrTraceID)
	}
}

func attrMap(attrs []slog.Attr) map[string]string {
	m := make(map[string]string)
	for _, a := range attrs {
		m[a.Key] = a.Value.String()
	}
	return m
}
