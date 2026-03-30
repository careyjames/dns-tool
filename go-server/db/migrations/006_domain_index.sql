-- Migration 006: Domain Index + Priority Domains
-- Creates a registry of every domain ever analyzed with the tool,
-- plus a priority_domains table for domains that always get CT enrichment first.

-- Domain index: historical registry of every domain ever scanned
CREATE TABLE IF NOT EXISTS domain_index (
    domain        VARCHAR(255) PRIMARY KEY,
    first_seen    TIMESTAMP NOT NULL DEFAULT NOW(),
    last_seen     TIMESTAMP NOT NULL DEFAULT NOW(),
    total_scans   INTEGER NOT NULL DEFAULT 1,
    last_score    REAL,
    has_dane      BOOLEAN NOT NULL DEFAULT FALSE,
    has_dnssec    BOOLEAN NOT NULL DEFAULT FALSE,
    has_mta_sts   BOOLEAN NOT NULL DEFAULT FALSE,
    tags          TEXT[] NOT NULL DEFAULT '{}'
);

CREATE INDEX ix_domain_index_last_seen ON domain_index (last_seen DESC);
CREATE INDEX ix_domain_index_total_scans ON domain_index (total_scans DESC);
CREATE INDEX ix_domain_index_tags ON domain_index USING GIN (tags);

-- Priority domains: always enriched first in CT intelligence pipeline.
-- These are domains with advanced DNS features (DANE, DNSSEC) that we
-- track as reference implementations and industry benchmarks.
CREATE TABLE IF NOT EXISTS priority_domains (
    domain        VARCHAR(255) PRIMARY KEY,
    reason        TEXT NOT NULL,
    added_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    enabled       BOOLEAN NOT NULL DEFAULT TRUE
);

-- Seed priority domains: advanced DNS exemplars we always want to track.
-- These implement DANE, DNSSEC, and other cutting-edge protocols.
INSERT INTO priority_domains (domain, reason) VALUES
    ('nlnetlabs.nl',         'DANE pioneer, DNSSEC research lab'),
    ('nlnet.nl',             'DANE/DNSSEC funding organization'),
    ('google.com',           'Industry benchmark, massive DNS infrastructure'),
    ('apple.com',            'Industry benchmark, platform vendor'),
    ('microsoft.com',        'Industry benchmark, enterprise email leader'),
    ('ithelpsd.com',         'Our domain — dogfooding, DANE/DNSSEC showcase'),
    ('cloudflare.com',       'DNS infrastructure leader, DNSSEC'),
    ('letsencrypt.org',      'Certificate authority, CT log participant'),
    ('posteo.de',            'DANE email pioneer, German privacy provider'),
    ('mailbox.org',          'DANE email provider, German hosting'),
    ('nic.cz',               'Czech NIC — DANE/DNSSEC national deployment'),
    ('sidn.nl',              'Dutch registry — DNSSEC pioneer'),
    ('freebsd.org',          'DANE-enabled, open source infrastructure'),
    ('fedoraproject.org',    'DANE-enabled, open source infrastructure'),
    ('ietf.org',             'Standards body — should practice what they preach')
ON CONFLICT (domain) DO NOTHING;

-- Backfill domain_index from existing analyses
INSERT INTO domain_index (domain, first_seen, last_seen, total_scans)
SELECT domain,
       MIN(created_at) AS first_seen,
       MAX(created_at) AS last_seen,
       COUNT(*)        AS total_scans
FROM domain_analyses
WHERE analysis_success = TRUE
GROUP BY domain
ON CONFLICT (domain) DO UPDATE SET
    last_seen   = EXCLUDED.last_seen,
    total_scans = EXCLUDED.total_scans;
