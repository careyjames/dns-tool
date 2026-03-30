// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package db

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunSeedMigrations_NoDir(t *testing.T) {
	d := &Database{}
	d.RunSeedMigrations("/nonexistent/dir/that/does/not/exist")
}

func TestRunSeedMigrations_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	d := &Database{}
	d.RunSeedMigrations(dir)
}

func TestRunSeedMigrations_SkipsNonSeedFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "001_schema.sql"), []byte("CREATE TABLE test (id INT);"), 0644); err != nil {
		t.Fatal(err)
	}
	d := &Database{}
	d.RunSeedMigrations(dir)
}

func TestRunSeedMigrations_SkipsDirectories(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "seed_subdir"), 0755); err != nil {
		t.Fatal(err)
	}
	d := &Database{}
	d.RunSeedMigrations(dir)
}

func TestRunSeedMigrations_SkipsNonSQL(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "seed_data.txt"), []byte("not sql"), 0644); err != nil {
		t.Fatal(err)
	}
	d := &Database{}
	d.RunSeedMigrations(dir)
}

func TestRunSeedMigrations_MatchesSeedPattern(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "013_seed_findings.sql"), []byte("SELECT 1;"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "001_schema.sql"), []byte("SELECT 1;"), 0644); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	seedCount := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") && strings.Contains(e.Name(), "seed") {
			seedCount++
		}
	}
	if seedCount != 1 {
		t.Errorf("expected 1 seed file matched, got %d", seedCount)
	}
}
