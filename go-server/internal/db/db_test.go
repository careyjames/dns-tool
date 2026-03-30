// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package db_test

import (
        "context"
        "os"
        "testing"
        "time"

        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/dbq"
)

func getTestDB(t *testing.T) *db.Database {
        t.Helper()
        dbURL := os.Getenv("DATABASE_URL")
        if dbURL == "" {
                t.Skip("DATABASE_URL not set, skipping integration test")
        }
        database, err := db.ConnectForTests(dbURL)
        if err != nil {
                t.Fatalf("Failed to connect to database: %v", err)
        }
        t.Cleanup(func() { database.Close() })
        return database
}

func TestHealthCheck(t *testing.T) {
        database := getTestDB(t)
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()

        if err := database.HealthCheck(ctx); err != nil {
                t.Fatalf("Health check failed: %v", err)
        }
}

func TestListSuccessfulAnalyses(t *testing.T) {
        database := getTestDB(t)
        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()

        analyses, err := database.Queries.ListSuccessfulAnalyses(ctx, dbq.ListSuccessfulAnalysesParams{
                Limit:  5,
                Offset: 0,
        })
        if err != nil {
                t.Fatalf("ListSuccessfulAnalyses failed: %v", err)
        }

        t.Logf("Found %d successful analyses", len(analyses))
        for _, a := range analyses {
                t.Logf("  - %s (ID: %d)", a.Domain, a.ID)
        }
}

func TestCountAllAnalyses(t *testing.T) {
        database := getTestDB(t)
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()

        count, err := database.Queries.CountAllAnalyses(ctx)
        if err != nil {
                t.Fatalf("CountAllAnalyses failed: %v", err)
        }
        t.Logf("Total analyses in database: %d", count)
}

func TestListRecentStats(t *testing.T) {
        database := getTestDB(t)
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()

        stats, err := database.Queries.ListRecentStats(ctx, 5)
        if err != nil {
                t.Fatalf("ListRecentStats failed: %v", err)
        }
        t.Logf("Found %d recent stat entries", len(stats))
}

func TestListPopularDomains(t *testing.T) {
        database := getTestDB(t)
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()

        domains, err := database.Queries.ListPopularDomains(ctx, 5)
        if err != nil {
                t.Fatalf("ListPopularDomains failed: %v", err)
        }
        t.Logf("Top %d popular domains:", len(domains))
        for _, d := range domains {
                t.Logf("  - %s (%d analyses)", d.Domain, d.Count)
        }
}

func TestCountryDistribution(t *testing.T) {
        database := getTestDB(t)
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()

        countries, err := database.Queries.ListCountryDistribution(ctx, 5)
        if err != nil {
                t.Fatalf("ListCountryDistribution failed: %v", err)
        }
        t.Logf("Top %d countries:", len(countries))
        for _, c := range countries {
                name := ""
                if c.CountryName != nil {
                        name = *c.CountryName
                }
                code := ""
                if c.CountryCode != nil {
                        code = *c.CountryCode
                }
                t.Logf("  - %s (%s): %d", name, code, c.Count)
        }
}
