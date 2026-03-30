CREATE TABLE IF NOT EXISTS system_log_entries (
    id         SERIAL PRIMARY KEY,
    timestamp  TIMESTAMP NOT NULL DEFAULT NOW(),
    level      VARCHAR(10) NOT NULL DEFAULT 'INFO',
    message    TEXT NOT NULL DEFAULT '',
    event      VARCHAR(50) NOT NULL DEFAULT '',
    category   VARCHAR(30) NOT NULL DEFAULT '',
    domain     VARCHAR(255) NOT NULL DEFAULT '',
    trace_id   VARCHAR(64) NOT NULL DEFAULT '',
    attrs      JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sle_timestamp ON system_log_entries (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_sle_level ON system_log_entries (level);
CREATE INDEX IF NOT EXISTS idx_sle_category ON system_log_entries (category) WHERE category != '';
CREATE INDEX IF NOT EXISTS idx_sle_domain ON system_log_entries (domain) WHERE domain != '';
CREATE INDEX IF NOT EXISTS idx_sle_trace_id ON system_log_entries (trace_id) WHERE trace_id != '';
CREATE INDEX IF NOT EXISTS idx_sle_event ON system_log_entries (event) WHERE event != '';
