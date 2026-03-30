// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny plumbing
package db

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (d *Database) RunSeedMigrations(migrationsDir string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		slog.Warn("seed: cannot read migrations directory", "dir", migrationsDir, "error", err)
		return
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		if !strings.Contains(entry.Name(), "seed") {
			continue
		}

		path := filepath.Join(migrationsDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			slog.Warn("seed: cannot read migration file", "file", entry.Name(), "error", err)
			continue
		}

		_, err = d.Pool.Exec(ctx, string(data))
		if err != nil {
			slog.Warn("seed: migration failed", "file", entry.Name(), "error", err)
			continue
		}
		slog.Info("seed: migration applied", "file", entry.Name())
	}
}
