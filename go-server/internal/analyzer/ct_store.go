// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"dnstool/go-server/internal/dbq"
)

// CTStore provides persistent storage for Certificate Transparency subdomain data.
//
// PHILOSOPHY: CT logs (RFC 6962) are append-only, immutable historical records.
// A certificate, once issued, is a historical fact — it cannot be "un-issued."
// Caching CT discovery data does NOT violate our promise of live, fresh analysis
// because the discovery layer (which certificates exist) is distinct from the
// liveness layer (which subdomains currently resolve in DNS). We always perform
// fresh DNS resolution to determine if a discovered subdomain is currently active.
//
// This is the same architectural principle used by crt.sh, Censys, Certspotter,
// and every CT aggregator: cache the historical discovery, verify liveness live.
type CTStore interface {
	Get(ctx context.Context, domain string) ([]map[string]any, bool)
	Set(ctx context.Context, domain string, data []map[string]any, source string)
}

type DBTX interface {
	GetCTCache(ctx context.Context, domain string) (dbq.CtSubdomainCache, error)
	UpsertCTCache(ctx context.Context, arg dbq.UpsertCTCacheParams) error
	PurgeCTCacheExpired(ctx context.Context) error
}

type pgCTStore struct {
	q DBTX
}

func NewPgCTStore(q DBTX) CTStore {
	return &pgCTStore{q: q}
}

func (s *pgCTStore) Get(ctx context.Context, domain string) ([]map[string]any, bool) {
	row, err := s.q.GetCTCache(ctx, domain)
	if err != nil {
		return nil, false
	}

	var subdomains []map[string]any
	if err := json.Unmarshal(row.Subdomains, &subdomains); err != nil {
		slog.Warn("CT cache: failed to unmarshal stored subdomains", mapKeyDomain, domain, mapKeyError, err)
		return nil, false
	}

	slog.Info("CT cache: database hit",
		mapKeyDomain, domain,
		"unique_count", row.UniqueCount,
		mapKeySource, row.Source,
		"age", time.Since(row.FetchedAt.Time).Round(time.Minute).String(),
	)
	return subdomains, true
}

func (s *pgCTStore) Set(ctx context.Context, domain string, data []map[string]any, source string) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		slog.Warn("CT cache: failed to marshal subdomains for storage", mapKeyDomain, domain, mapKeyError, err)
		return
	}

	err = s.q.UpsertCTCache(ctx, dbq.UpsertCTCacheParams{
		Domain:      domain,
		Subdomains:  jsonData,
		UniqueCount: int32(len(data)),
		Source:      source,
	})
	if err != nil {
		slog.Warn("CT cache: failed to persist", mapKeyDomain, domain, mapKeyError, err)
		return
	}
	slog.Info("CT cache: persisted to database", mapKeyDomain, domain, "count", len(data), mapKeySource, source)
}

func WithCTStore(store CTStore) Option {
	return func(a *Analyzer) {
		a.CTStore = store
	}
}
