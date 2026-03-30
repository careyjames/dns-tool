-- 012_confidence_scores.sql — Normalized confidence scores table
-- Extracts per-scan confidence data from JSON blobs for independent trending

CREATE TABLE IF NOT EXISTS confidence_scores (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         UUID,
    domain          TEXT NOT NULL,
    protocol        TEXT NOT NULL CHECK (protocol IN (
        'SPF','DKIM','DMARC','DNSSEC','DANE','CAA','MTA-STS','BIMI','TLS-RPT','MX','NS','SOA'
    )),
    score           NUMERIC(5,4) NOT NULL CHECK (score >= 0 AND score <= 1),
    grade           TEXT CHECK (grade IN ('A+','A','A-','B+','B','B-','C+','C','C-','D','F')),
    resolver_count  SMALLINT,
    resolver_agreement NUMERIC(5,4),
    evidence_factors    JSONB NOT NULL DEFAULT '{}'::jsonb,
    calibrated_score    NUMERIC(5,4),
    raw_score           NUMERIC(5,4),
    source          TEXT NOT NULL DEFAULT 'scan' CHECK (source IN ('scan','manual','import','recalibration')),
    scanned_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_confidence_scores_domain ON confidence_scores (domain);
CREATE INDEX IF NOT EXISTS idx_confidence_scores_protocol ON confidence_scores (protocol);
CREATE INDEX IF NOT EXISTS idx_confidence_scores_domain_protocol ON confidence_scores (domain, protocol);
CREATE INDEX IF NOT EXISTS idx_confidence_scores_scanned_at ON confidence_scores (scanned_at);
CREATE INDEX IF NOT EXISTS idx_confidence_scores_scan_id ON confidence_scores (scan_id);
