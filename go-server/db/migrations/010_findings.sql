CREATE TABLE findings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    public_id       TEXT UNIQUE NOT NULL,

    kind            TEXT NOT NULL CHECK (kind IN (
        'defect', 'weakness', 'incident', 'compliance_gap',
        'claim_integrity', 'design_debt'
    )),
    domain          TEXT NOT NULL CHECK (domain IN (
        'security', 'accessibility', 'ux', 'performance',
        'seo', 'content', 'design_system', 'architecture'
    )),

    title           TEXT NOT NULL,
    symptom_md      TEXT NOT NULL,
    hypothesis_md   TEXT,
    root_cause_md   TEXT,

    severity        SMALLINT NOT NULL CHECK (severity BETWEEN 0 AND 4),
    priority        SMALLINT NOT NULL CHECK (priority BETWEEN 0 AND 3),
    status          TEXT NOT NULL DEFAULT 'DETAINED' CHECK (status IN (
        'DETAINED', 'VERIFIED', 'UNDER_INTERROGATION', 'CONTAINED',
        'RENDERED', 'REGRESSED', 'EXTRADITED', 'DISMISSED'
    )),

    canonical_rule_id       TEXT NOT NULL,
    fingerprint_version     SMALLINT NOT NULL DEFAULT 1,
    fingerprint_sha256      CHAR(64) NOT NULL,

    evidence_grade  TEXT NOT NULL CHECK (evidence_grade IN (
        'measured', 'reproduced', 'static_analysis', 'inferred'
    )),
    confidence      NUMERIC(3,2) NOT NULL CHECK (confidence BETWEEN 0 AND 1),

    blast_radius    TEXT NOT NULL CHECK (blast_radius IN (
        'component', 'page', 'flow', 'sitewide'
    )),
    visibility      TEXT NOT NULL CHECK (visibility IN (
        'internal', 'edge_case', 'common', 'critical_path', 'conference_demo'
    )),

    standard_refs   JSONB NOT NULL DEFAULT '[]'::JSONB,

    duplicate_of    UUID REFERENCES findings(id),
    regression_of   UUID REFERENCES findings(id),

    source_team     TEXT NOT NULL DEFAULT '',
    owner           TEXT,

    introduced_commit   TEXT,
    fixed_commit        TEXT,
    fixed_release       TEXT,

    legacy_bsi_id       TEXT,
    legacy_threat_level TEXT,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX findings_canonical_uq
    ON findings (canonical_rule_id, fingerprint_version, fingerprint_sha256)
    WHERE duplicate_of IS NULL;

CREATE INDEX idx_findings_kind ON findings (kind);
CREATE INDEX idx_findings_domain ON findings (domain);
CREATE INDEX idx_findings_severity ON findings (severity);
CREATE INDEX idx_findings_status ON findings (status);
CREATE INDEX idx_findings_public_id ON findings (public_id);

CREATE TABLE observations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id  UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,

    source_team     TEXT NOT NULL,
    build_id        TEXT,
    route           TEXT,
    component       TEXT,
    browser         TEXT,
    viewport        TEXT,
    repro_steps_md  TEXT,

    evidence_sha256 CHAR(64) NOT NULL,
    raw_evidence    JSONB NOT NULL DEFAULT '{}'::JSONB,

    observed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_observations_finding ON observations (finding_id);

CREATE TABLE finding_events (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id  UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,

    actor       TEXT NOT NULL,
    event_type  TEXT NOT NULL CHECK (event_type IN (
        'status_change', 'note', 'fix_linked', 'regression', 'verification'
    )),
    from_status TEXT,
    to_status   TEXT,

    commit_sha  TEXT,
    note_md     TEXT,

    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_finding_events_finding ON finding_events (finding_id);
CREATE INDEX idx_finding_events_type ON finding_events (event_type);
