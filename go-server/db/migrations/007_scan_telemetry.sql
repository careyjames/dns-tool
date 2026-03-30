CREATE TABLE scan_phase_telemetry (
    id              SERIAL PRIMARY KEY,
    analysis_id     INT NOT NULL REFERENCES domain_analyses(id) ON DELETE CASCADE,
    phase_group     TEXT NOT NULL,
    phase_task      TEXT NOT NULL,
    started_at_ms   INT NOT NULL,
    duration_ms     INT NOT NULL,
    record_count    INT DEFAULT 0,
    error           TEXT,
    created_at      TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_spt_analysis ON scan_phase_telemetry(analysis_id);
CREATE INDEX idx_spt_phase ON scan_phase_telemetry(phase_group);

CREATE TABLE scan_telemetry_hash (
    analysis_id     INT PRIMARY KEY REFERENCES domain_analyses(id) ON DELETE CASCADE,
    total_duration_ms INT NOT NULL,
    phase_count     INT NOT NULL,
    sha3_512        TEXT NOT NULL,
    created_at      TIMESTAMP DEFAULT NOW()
);
