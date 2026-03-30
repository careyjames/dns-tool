// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package config

import (
	"os"
	"testing"
)

func setEnv(t *testing.T, key, value string) {
	t.Helper()
	t.Setenv(key, value)
}

func TestLoad_MissingDatabaseURL(t *testing.T) {
	setEnv(t, "DATABASE_URL", "")
	setEnv(t, "SESSION_SECRET", "test-secret")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing DATABASE_URL")
	}
}

func TestLoad_MissingSessionSecret(t *testing.T) {
	setEnv(t, "DATABASE_URL", "postgres://test")
	setEnv(t, "SESSION_SECRET", "")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing SESSION_SECRET")
	}
}

func TestLoad_DefaultPort(t *testing.T) {
	setEnv(t, "DATABASE_URL", "postgres://test")
	setEnv(t, "SESSION_SECRET", "test-secret")
	setEnv(t, "PORT", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Port != "5000" {
		t.Errorf("expected default port 5000, got %s", cfg.Port)
	}
}

func TestLoad_CustomPort(t *testing.T) {
	setEnv(t, "DATABASE_URL", "postgres://test")
	setEnv(t, "SESSION_SECRET", "test-secret")
	setEnv(t, "PORT", "8080")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Port != "8080" {
		t.Errorf("expected port 8080, got %s", cfg.Port)
	}
}

func TestLoad_SMTPProbeMode_Default(t *testing.T) {
	setEnv(t, "DATABASE_URL", "postgres://test")
	setEnv(t, "SESSION_SECRET", "test-secret")
	setEnv(t, "SMTP_PROBE_MODE", "")
	setEnv(t, "PROBE_API_URL", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.SMTPProbeMode != "skip" {
		t.Errorf("expected SMTP probe mode 'skip', got %s", cfg.SMTPProbeMode)
	}
}

func TestLoad_SMTPProbeMode_RemoteAutoDetect(t *testing.T) {
	setEnv(t, "DATABASE_URL", "postgres://test")
	setEnv(t, "SESSION_SECRET", "test-secret")
	setEnv(t, "SMTP_PROBE_MODE", "")
	setEnv(t, "PROBE_API_URL", "https://probe.example.com")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.SMTPProbeMode != "remote" {
		t.Errorf("expected SMTP probe mode 'remote', got %s", cfg.SMTPProbeMode)
	}
}

func TestLoad_SectionTuning_Defaults(t *testing.T) {
	setEnv(t, "DATABASE_URL", "postgres://test")
	setEnv(t, "SESSION_SECRET", "test-secret")
	setEnv(t, "SECTION_TUNING", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.SectionTuning["ai"] != "Beta" {
		t.Errorf("expected ai section tuning 'Beta', got %s", cfg.SectionTuning["ai"])
	}
	if cfg.SectionTuning["smtp"] != "Beta" {
		t.Errorf("expected smtp section tuning 'Beta', got %s", cfg.SectionTuning["smtp"])
	}
}

func TestLoad_SectionTuning_EnvOverride(t *testing.T) {
	setEnv(t, "DATABASE_URL", "postgres://test")
	setEnv(t, "SESSION_SECRET", "test-secret")
	setEnv(t, "SECTION_TUNING", "ai=Stable,smtp=GA")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.SectionTuning["ai"] != "Stable" {
		t.Errorf("expected ai='Stable', got %s", cfg.SectionTuning["ai"])
	}
	if cfg.SectionTuning["smtp"] != "GA" {
		t.Errorf("expected smtp='GA', got %s", cfg.SectionTuning["smtp"])
	}
}

func TestLoad_BaseURL_Default(t *testing.T) {
	setEnv(t, "DATABASE_URL", "postgres://test")
	setEnv(t, "SESSION_SECRET", "test-secret")
	setEnv(t, "BASE_URL", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.BaseURL != "https://dnstool.it-help.tech" {
		t.Errorf("expected default base URL, got %s", cfg.BaseURL)
	}
	if cfg.GoogleRedirectURL != "https://dnstool.it-help.tech/auth/callback" {
		t.Errorf("expected default redirect URL, got %s", cfg.GoogleRedirectURL)
	}
}

func TestLoad_BaseURL_Custom(t *testing.T) {
	setEnv(t, "DATABASE_URL", "postgres://test")
	setEnv(t, "SESSION_SECRET", "test-secret")
	setEnv(t, "BASE_URL", "https://dev.example.com")
	setEnv(t, "GOOGLE_REDIRECT_URL", "")
	os.Unsetenv("REPLIT_DEV_DOMAIN")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.BaseURL != "https://dev.example.com" {
		t.Errorf("expected custom base URL, got %s", cfg.BaseURL)
	}
	if cfg.IsDevEnvironment != false {
		t.Error("expected IsDevEnvironment=false without REPLIT_DEV_DOMAIN")
	}
}

func TestLoad_IsDevEnvironment_ReplitDevDomain(t *testing.T) {
	setEnv(t, "DATABASE_URL", "postgres://test")
	setEnv(t, "SESSION_SECRET", "test-secret")
	setEnv(t, "REPLIT_DEV_DOMAIN", "test.picard.replit.dev")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.IsDevEnvironment != true {
		t.Error("expected IsDevEnvironment=true when REPLIT_DEV_DOMAIN is set")
	}
	t.Cleanup(func() { os.Unsetenv("REPLIT_DEV_DOMAIN") })
}

func TestLoad_GoogleRedirectURL_Override(t *testing.T) {
	setEnv(t, "DATABASE_URL", "postgres://test")
	setEnv(t, "SESSION_SECRET", "test-secret")
	setEnv(t, "GOOGLE_REDIRECT_URL", "https://custom.example.com/callback")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.GoogleRedirectURL != "https://custom.example.com/callback" {
		t.Errorf("expected custom redirect URL, got %s", cfg.GoogleRedirectURL)
	}
}

func TestLoad_AppVersion(t *testing.T) {
	setEnv(t, "DATABASE_URL", "postgres://test")
	setEnv(t, "SESSION_SECRET", "test-secret")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.AppVersion != Version {
		t.Errorf("expected AppVersion=%s, got %s", Version, cfg.AppVersion)
	}
}

func TestLoad_InitialAdminEmail_Trimmed(t *testing.T) {
	setEnv(t, "DATABASE_URL", "postgres://test")
	setEnv(t, "SESSION_SECRET", "test-secret")
	setEnv(t, "INITIAL_ADMIN_EMAIL", "  admin@example.com  ")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.InitialAdminEmail != "admin@example.com" {
		t.Errorf("expected trimmed email, got '%s'", cfg.InitialAdminEmail)
	}
}

func TestLoad_ProbeAPIKey(t *testing.T) {
	setEnv(t, "DATABASE_URL", "postgres://test")
	setEnv(t, "SESSION_SECRET", "test-secret")
	setEnv(t, "PROBE_API_KEY", "test-key-123")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ProbeAPIKey != "test-key-123" {
		t.Errorf("expected ProbeAPIKey='test-key-123', got %s", cfg.ProbeAPIKey)
	}
}

func TestLoad_MaintenanceNote(t *testing.T) {
	setEnv(t, "DATABASE_URL", "postgres://test")
	setEnv(t, "SESSION_SECRET", "test-secret")
	setEnv(t, "MAINTENANCE_NOTE", "System maintenance at midnight")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.MaintenanceNote != "System maintenance at midnight" {
		t.Errorf("expected maintenance note, got '%s'", cfg.MaintenanceNote)
	}
}

func TestLoad_EnvPassthrough(t *testing.T) {
	setEnv(t, "DATABASE_URL", "postgres://test")
	setEnv(t, "SESSION_SECRET", "test-secret")
	setEnv(t, "GOOGLE_CLIENT_ID", "google-id")
	setEnv(t, "GOOGLE_CLIENT_SECRET", "google-secret")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.GoogleClientID != "google-id" {
		t.Errorf("expected GoogleClientID, got '%s'", cfg.GoogleClientID)
	}
	if cfg.GoogleClientSecret != "google-secret" {
		t.Errorf("expected GoogleClientSecret, got '%s'", cfg.GoogleClientSecret)
	}
}

func TestLoad_ReplitDeployment_ForcesNotDev(t *testing.T) {
	setEnv(t, "DATABASE_URL", "postgres://test")
	setEnv(t, "SESSION_SECRET", "test-secret")
	setEnv(t, "REPLIT_DEPLOYMENT", "1")
	setEnv(t, "REPLIT_DEV_DOMAIN", "some-domain.replit.dev")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.IsDevEnvironment {
		t.Error("expected IsDevEnvironment=false when REPLIT_DEPLOYMENT is set, even with REPLIT_DEV_DOMAIN present")
	}
}

func TestLoad_IsDevEnvironment_EmptyBaseURL(t *testing.T) {
	setEnv(t, "DATABASE_URL", "postgres://test")
	setEnv(t, "SESSION_SECRET", "test-secret")
	os.Unsetenv("BASE_URL")
	os.Unsetenv("REPLIT_DEV_DOMAIN")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.IsDevEnvironment != false {
		t.Error("expected IsDevEnvironment=false when REPLIT_DEV_DOMAIN is not set")
	}
}
