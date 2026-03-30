// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"dnstool/go-server/internal/config"
	"dnstool/go-server/internal/db"
)

func setupTestDB(t *testing.T) *db.Database {
	t.Helper()
	database := getTestDB(t)

	_, thisFile, _, _ := runtime.Caller(0)
	schemaPath := filepath.Join(filepath.Dir(thisFile), "..", "..", "db", "schema", "schema.sql")
	schemaSQL, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("failed to read schema.sql: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, err = database.Pool.Exec(ctx, string(schemaSQL))
	if err != nil {
		t.Logf("schema already applied or partial apply (expected on re-runs): %v", err)
	}

	return database
}

func cleanupTestDB(t *testing.T, database *db.Database) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tables := []string{
		"drift_notifications",
		"notification_endpoints",
		"domain_watchlist",
		"drift_events",
		"zone_imports",
		"user_analyses",
		"site_analytics",
		"ice_regressions",
		"ice_maturity",
		"ice_results",
		"ice_test_runs",
		"ice_protocols",
		"sessions",
		"analysis_stats",
		"data_governance_events",
		"domain_analyses",
		"users",
	}

	for _, table := range tables {
		_, err := database.Pool.Exec(ctx, "TRUNCATE TABLE "+table+" CASCADE")
		if err != nil {
			t.Logf("truncate %s: %v", table, err)
		}
	}
}

func testConfig() *config.Config {
	return &config.Config{
		DatabaseURL:      os.Getenv("DATABASE_URL"),
		SessionSecret:    "test-secret",
		Port:             "5000",
		AppVersion:       "test",
		SMTPProbeMode:    "skip",
		BaseURL:          "https://dnstool.it-help.tech",
		IsDevEnvironment: true,
		SectionTuning:    map[string]string{},
		BetaPages:        map[string]bool{},
	}
}

func TestGetTestDB(t *testing.T) {
	database := setupTestDB(t)
	cleanupTestDB(t, database)
}
