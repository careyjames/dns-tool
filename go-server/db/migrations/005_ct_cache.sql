-- Migration 005: CT Subdomain Cache + SecurityTrails Budget Tracking
--
-- PHILOSOPHY NOTE: Certificate Transparency logs (RFC 6962) are append-only,
-- immutable historical records. Caching CT data does NOT violate our "live data"
-- promise because certificates are historical facts — they were issued, and that
-- fact never changes. What IS live is DNS resolution (is the subdomain currently
-- active?), which we always check fresh via DNS probing. The CT cache stores
-- the historical discovery layer; the live enrichment layer remains real-time.
--
-- This is the same reason crt.sh, Censys, and every CT aggregator caches:
-- you cannot "un-issue" a certificate.

-- CT subdomain cache: persistent storage for CT log discoveries
-- Survives server restarts; 24h TTL (CT data changes slowly)
CREATE TABLE IF NOT EXISTS ct_subdomain_cache (
    domain        VARCHAR(255) PRIMARY KEY,
    subdomains    JSONB NOT NULL DEFAULT '[]',
    unique_count  INTEGER NOT NULL DEFAULT 0,
    source        VARCHAR(50) NOT NULL DEFAULT 'crt.sh',
    fetched_at    TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMP NOT NULL DEFAULT (NOW() + INTERVAL '24 hours')
);

CREATE INDEX IF NOT EXISTS ix_ct_cache_expires ON ct_subdomain_cache (expires_at);
CREATE INDEX IF NOT EXISTS ix_ct_cache_fetched ON ct_subdomain_cache (fetched_at DESC);

-- SecurityTrails monthly budget tracking (survives restarts)
CREATE TABLE IF NOT EXISTS securitytrails_budget (
    month_key       VARCHAR(7) PRIMARY KEY,  -- e.g. '2026-03'
    calls_used      INTEGER NOT NULL DEFAULT 0,
    domains_enriched JSONB NOT NULL DEFAULT '[]',
    last_called_at  TIMESTAMP,
    created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP NOT NULL DEFAULT NOW()
);
