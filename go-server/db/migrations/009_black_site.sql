CREATE TABLE black_site_detainees (
    id              SERIAL PRIMARY KEY,
    bsi_id          VARCHAR(10) NOT NULL UNIQUE,
    sha_hash        VARCHAR(6) NOT NULL,
    title           TEXT NOT NULL,
    threat_level    VARCHAR(20) NOT NULL CHECK (threat_level IN ('APT', 'ZERO-DAY', 'EXPLOIT', 'CVE', 'IOC')),
    status          VARCHAR(30) NOT NULL DEFAULT 'DETAINED' CHECK (status IN ('DETAINED', 'UNDER INTERROGATION', 'RENDERED', 'EXTRADITED')),
    captured_by     TEXT NOT NULL DEFAULT '',
    file_references TEXT NOT NULL DEFAULT '',
    interrogation_notes TEXT NOT NULL DEFAULT '',
    witness_statement   TEXT NOT NULL DEFAULT '',
    damage_assessment   TEXT NOT NULL DEFAULT '',
    recommended_remedy  TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_bsd_threat_level ON black_site_detainees (threat_level);
CREATE INDEX idx_bsd_status ON black_site_detainees (status);
CREATE INDEX idx_bsd_bsi_id ON black_site_detainees (bsi_id);

CREATE TABLE black_site_renditions (
    id              SERIAL PRIMARY KEY,
    detainee_id     INTEGER NOT NULL REFERENCES black_site_detainees(id),
    rendered_at     TIMESTAMP NOT NULL DEFAULT NOW(),
    commit_hash     VARCHAR(40) NOT NULL,
    rendered_by     TEXT NOT NULL DEFAULT '',
    method          TEXT NOT NULL DEFAULT '',
    notes           TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_bsr_detainee_id ON black_site_renditions (detainee_id);
CREATE INDEX idx_bsr_rendered_at ON black_site_renditions (rendered_at DESC);
