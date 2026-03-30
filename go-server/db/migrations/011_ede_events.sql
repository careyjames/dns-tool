-- 011_ede_events.sql — Empirical Disclosure Events (EDE) migration
-- Migrates ephemeral integrity_stats.json to durable PostgreSQL

CREATE TABLE IF NOT EXISTS ede_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ede_id          TEXT NOT NULL UNIQUE,
    event_date      DATE NOT NULL,
    commit_ref      TEXT NOT NULL,
    category        TEXT NOT NULL CHECK (category IN (
        'scoring_calibration','evidence_reinterpretation','drift_detection',
        'resolver_trust','false_positive','confidence_decay',
        'governance_correction','citation_error','overclaim','standards_misattribution'
    )),
    severity        TEXT NOT NULL CHECK (severity IN ('critical','significant','moderate','minor')),
    title           TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','closed')),
    attribution     TEXT NOT NULL CHECK (attribution IN ('Human Error','AI Error','Both','Process Gap')),
    protocols_affected  JSONB NOT NULL DEFAULT '[]'::jsonb,
    confidence_impact   TEXT,
    resolution          TEXT,
    bayesian_note       TEXT,
    correction_action   TEXT,
    prevention_rule     TEXT,
    authoritative_source TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ede_events_category ON ede_events (category);
CREATE INDEX IF NOT EXISTS idx_ede_events_severity ON ede_events (severity);
CREATE INDEX IF NOT EXISTS idx_ede_events_status ON ede_events (status);
CREATE INDEX IF NOT EXISTS idx_ede_events_attribution ON ede_events (attribution);
CREATE INDEX IF NOT EXISTS idx_ede_events_date ON ede_events (event_date);

CREATE TABLE IF NOT EXISTS ede_amendments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ede_event_id    UUID NOT NULL REFERENCES ede_events(id) ON DELETE CASCADE,
    amendment_date  DATE NOT NULL,
    ground          TEXT NOT NULL CHECK (ground IN ('FACTUAL_ERROR','DIGNITY_OF_EXPRESSION')),
    field_changed   TEXT NOT NULL,
    original_value  TEXT NOT NULL,
    corrected_to    TEXT NOT NULL,
    evidence        TEXT,
    rationale       TEXT,
    justification   TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ede_amendments_event ON ede_amendments (ede_event_id);
