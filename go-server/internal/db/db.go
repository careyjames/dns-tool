// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny plumbing
package db

import (
        "context"
        "fmt"
        "log/slog"
        "net/url"
        "os"
        "time"

        "dnstool/go-server/internal/dbq"

        "github.com/jackc/pgx/v5/pgxpool"
)

type Database struct {
        Pool    *pgxpool.Pool
        Queries *dbq.Queries
}

func Connect(databaseURL string) (*Database, error) {
        if os.Getenv("REPLIT_DEPLOYMENT") != "" {
                if u, err := url.Parse(databaseURL); err == nil && u.Hostname() == "helium" {
                        return nil, fmt.Errorf("misconfiguration: production deployment is using development database host 'helium'; set DATABASE_URL in production app secrets to the production database connection string")
                }
        }
        const maxRetries = 5
        const retryDelay = 3 * time.Second
        var lastErr error
        for attempt := 1; attempt <= maxRetries; attempt++ {
                db, err := connectWithPoolSize(databaseURL, 10, 2)
                if err == nil {
                        return db, nil
                }
                lastErr = err
                if attempt < maxRetries {
                        slog.Warn("Database connection attempt failed, retrying",
                                "attempt", attempt,
                                "max_retries", maxRetries,
                                "retry_in", retryDelay.String(),
                                "error", err)
                        time.Sleep(retryDelay)
                }
        }
        return nil, lastErr
}

func ConnectForTests(databaseURL string) (*Database, error) {
        return connectWithPoolSize(databaseURL, 2, 0)
}

func connectWithPoolSize(databaseURL string, maxConns, minConns int32) (*Database, error) {
        config, err := pgxpool.ParseConfig(databaseURL)
        if err != nil {
                return nil, fmt.Errorf("failed to parse database URL: %w", err)
        }

        config.MaxConns = maxConns
        config.MinConns = minConns
        config.MaxConnLifetime = 5 * time.Minute
        config.MaxConnIdleTime = 2 * time.Minute
        config.HealthCheckPeriod = 30 * time.Second

        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()

        pool, err := pgxpool.NewWithConfig(ctx, config)
        if err != nil {
                return nil, fmt.Errorf("failed to connect to database: %w", err)
        }

        if err := pool.Ping(ctx); err != nil {
                pool.Close()
                return nil, fmt.Errorf("failed to ping database: %w", err)
        }

        slog.Info("Database connected successfully")
        return &Database{
                Pool:    pool,
                Queries: dbq.New(pool),
        }, nil
}

func (d *Database) Close() {
        if d.Pool != nil {
                d.Pool.Close()
                slog.Info("Database connection closed")
        }
}

func (d *Database) HealthCheck(ctx context.Context) error {
        return d.Pool.Ping(ctx)
}
