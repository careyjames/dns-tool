package handlers

import (
	"testing"

	"dnstool/go-server/internal/config"
)

func TestMaxZoneFileSizeAuth(t *testing.T) {
	expected := int64(2 << 20)
	if maxZoneFileSizeAuth != expected {
		t.Errorf("maxZoneFileSizeAuth = %d, want %d", maxZoneFileSizeAuth, expected)
	}
	if maxZoneFileSizeAuth != 2*1024*1024 {
		t.Errorf("maxZoneFileSizeAuth should be 2 MB (2097152), got %d", maxZoneFileSizeAuth)
	}
}

func TestMaxZoneFileSizeUnauth(t *testing.T) {
	expected := int64(1 << 20)
	if maxZoneFileSizeUnauth != expected {
		t.Errorf("maxZoneFileSizeUnauth = %d, want %d", maxZoneFileSizeUnauth, expected)
	}
	if maxZoneFileSizeUnauth != 1*1024*1024 {
		t.Errorf("maxZoneFileSizeUnauth should be 1 MB (1048576), got %d", maxZoneFileSizeUnauth)
	}
}

func TestMaxZoneFileSizeAuthGreaterThanUnauth(t *testing.T) {
	if maxZoneFileSizeAuth <= maxZoneFileSizeUnauth {
		t.Errorf("auth limit (%d) must be greater than unauth limit (%d)", maxZoneFileSizeAuth, maxZoneFileSizeUnauth)
	}
}

func TestTplZone(t *testing.T) {
	if tplZone != "zone.html" {
		t.Errorf("tplZone = %q, want %q", tplZone, "zone.html")
	}
}

func TestNewZoneHandler(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0.0"}
	h := NewZoneHandler(nil, cfg)
	if h == nil {
		t.Fatal("expected non-nil ZoneHandler")
	}
	if h.DB != nil {
		t.Error("expected nil DB")
	}
	if h.Config != cfg {
		t.Error("expected Config to match")
	}
	if h.Config.AppVersion != "1.0.0" {
		t.Errorf("expected AppVersion '1.0.0', got %s", h.Config.AppVersion)
	}
}

func TestNewZoneHandlerWithConfig(t *testing.T) {
	cfg := &config.Config{
		AppVersion:      "2.0.0",
		MaintenanceNote: "test note",
	}
	h := NewZoneHandler(nil, cfg)
	if h.Config.MaintenanceNote != "test note" {
		t.Errorf("expected MaintenanceNote 'test note', got %s", h.Config.MaintenanceNote)
	}
}

func TestMaxZoneFileSizeAuthIs2MB(t *testing.T) {
	if maxZoneFileSizeAuth < 1024*1024 {
		t.Error("maxZoneFileSizeAuth should be at least 1 MB")
	}
	if maxZoneFileSizeAuth > 10*1024*1024 {
		t.Error("maxZoneFileSizeAuth should not exceed 10 MB")
	}
}

func TestZoneHandlerStructFields(t *testing.T) {
	cfg := &config.Config{
		AppVersion:      "3.0.0",
		MaintenanceNote: "maintenance",
		BetaPages:       map[string]bool{"zone": true},
	}
	h := NewZoneHandler(nil, cfg)
	if h.Config.AppVersion != "3.0.0" {
		t.Errorf("AppVersion = %q, want %q", h.Config.AppVersion, "3.0.0")
	}
	if h.Config.MaintenanceNote != "maintenance" {
		t.Errorf("MaintenanceNote = %q, want %q", h.Config.MaintenanceNote, "maintenance")
	}
	if !h.Config.BetaPages["zone"] {
		t.Error("BetaPages[zone] should be true")
	}
}

func TestFlashMessageStruct(t *testing.T) {
	tests := []struct {
		name     string
		category string
		message  string
	}{
		{"danger flash", "danger", "Something went wrong"},
		{"warning flash", "warning", "No records found"},
		{"success flash", "success", "Upload complete"},
		{"info flash", "info", "Processing..."},
		{"empty message", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fm := FlashMessage{Category: tt.category, Message: tt.message}
			if fm.Category != tt.category {
				t.Errorf("Category = %q, want %q", fm.Category, tt.category)
			}
			if fm.Message != tt.message {
				t.Errorf("Message = %q, want %q", fm.Message, tt.message)
			}
		})
	}
}

func TestZoneHandlerNilDB(t *testing.T) {
	h := NewZoneHandler(nil, &config.Config{})
	if h.DB != nil {
		t.Error("expected DB to be nil")
	}
}

func TestZoneHandlerNilConfig(t *testing.T) {
	h := NewZoneHandler(nil, nil)
	if h == nil {
		t.Fatal("expected non-nil handler even with nil config")
	}
	if h.Config != nil {
		t.Error("expected nil Config")
	}
}

func TestMaxZoneFileSizeExactValues(t *testing.T) {
	if maxZoneFileSizeAuth != 2097152 {
		t.Errorf("maxZoneFileSizeAuth = %d, want exactly 2097152 (2 MB)", maxZoneFileSizeAuth)
	}
	if maxZoneFileSizeUnauth != 1048576 {
		t.Errorf("maxZoneFileSizeUnauth = %d, want exactly 1048576 (1 MB)", maxZoneFileSizeUnauth)
	}
}

func TestMaxZoneFileSizeBitShift(t *testing.T) {
	authCalc := int64(2 << 20)
	authManual := int64(2 * 1024 * 1024)
	if authCalc != authManual {
		t.Errorf("auth bit shift %d != manual %d", authCalc, authManual)
	}
	if maxZoneFileSizeAuth != authCalc {
		t.Errorf("maxZoneFileSizeAuth = %d, want %d", maxZoneFileSizeAuth, authCalc)
	}
	unauthCalc := int64(1 << 20)
	unauthManual := int64(1 * 1024 * 1024)
	if unauthCalc != unauthManual {
		t.Errorf("unauth bit shift %d != manual %d", unauthCalc, unauthManual)
	}
	if maxZoneFileSizeUnauth != unauthCalc {
		t.Errorf("maxZoneFileSizeUnauth = %d, want %d", maxZoneFileSizeUnauth, unauthCalc)
	}
}

func TestZoneHandlerConfigPropagation(t *testing.T) {
	tests := []struct {
		name      string
		version   string
		maint     string
		betaPages map[string]bool
	}{
		{"empty config", "", "", nil},
		{"full config", "4.0.0", "scheduled maintenance", map[string]bool{"zone": true, "drift": false}},
		{"version only", "1.2.3", "", nil},
		{"maintenance only", "", "down for updates", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				AppVersion:      tt.version,
				MaintenanceNote: tt.maint,
				BetaPages:       tt.betaPages,
			}
			h := NewZoneHandler(nil, cfg)
			if h.Config.AppVersion != tt.version {
				t.Errorf("AppVersion = %q, want %q", h.Config.AppVersion, tt.version)
			}
			if h.Config.MaintenanceNote != tt.maint {
				t.Errorf("MaintenanceNote = %q, want %q", h.Config.MaintenanceNote, tt.maint)
			}
		})
	}
}

func TestFlashMessageVariousCategories(t *testing.T) {
	categories := []string{"danger", "warning", "success", "info", "primary", "secondary"}
	for _, cat := range categories {
		fm := FlashMessage{Category: cat, Message: "test message for " + cat}
		if fm.Category != cat {
			t.Errorf("Category = %q, want %q", fm.Category, cat)
		}
		if fm.Message == "" {
			t.Error("expected non-empty message")
		}
	}
}

func TestFlashMessageLongContent(t *testing.T) {
	longMsg := ""
	for i := 0; i < 50; i++ {
		longMsg += "error detail "
	}
	fm := FlashMessage{Category: "danger", Message: longMsg}
	if fm.Message != longMsg {
		t.Error("FlashMessage should preserve long messages")
	}
}

func TestTplZoneConstant(t *testing.T) {
	if tplZone == "" {
		t.Error("tplZone should not be empty")
	}
	if tplZone != "zone.html" {
		t.Errorf("tplZone = %q, want zone.html", tplZone)
	}
}

func TestZoneHandlerDBFieldType(t *testing.T) {
	h := &ZoneHandler{}
	if h.DB != nil {
		t.Error("zero-value DB should be nil")
	}
	if h.Config != nil {
		t.Error("zero-value Config should be nil")
	}
}
