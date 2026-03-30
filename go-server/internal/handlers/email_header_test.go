package handlers

import (
	"testing"

	"dnstool/go-server/internal/config"
)

func TestNewEmailHeaderHandler(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0.0"}
	h := NewEmailHeaderHandler(cfg)
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
	if h.Config != cfg {
		t.Error("expected Config to be set")
	}
}

func TestEmailHeaderConstants(t *testing.T) {
	if emailHeaderTemplate != "email_header.html" {
		t.Errorf("unexpected emailHeaderTemplate: %q", emailHeaderTemplate)
	}
	if activePageEmailHeader != "email-header" {
		t.Errorf("unexpected activePageEmailHeader: %q", activePageEmailHeader)
	}
	if maxHeaderSize != 256*1024 {
		t.Errorf("unexpected maxHeaderSize: %d", maxHeaderSize)
	}
	if strShowform != "ShowForm" {
		t.Errorf("unexpected strShowform: %q", strShowform)
	}
}

func TestEmailHeaderHandlerConfigAssignment(t *testing.T) {
	cfg := &config.Config{
		AppVersion:      "26.25.25",
		MaintenanceNote: "test note",
	}
	h := NewEmailHeaderHandler(cfg)
	if h.Config.AppVersion != "26.25.25" {
		t.Errorf("expected AppVersion=26.25.25, got %q", h.Config.AppVersion)
	}
	if h.Config.MaintenanceNote != "test note" {
		t.Errorf("expected MaintenanceNote='test note', got %q", h.Config.MaintenanceNote)
	}
}

func TestMaxHeaderSizeValue(t *testing.T) {
	expected := 256 * 1024
	if maxHeaderSize != expected {
		t.Errorf("maxHeaderSize = %d, want %d (256 KB)", maxHeaderSize, expected)
	}
	if maxHeaderSize < 1024 {
		t.Error("maxHeaderSize should be at least 1 KB")
	}
}
