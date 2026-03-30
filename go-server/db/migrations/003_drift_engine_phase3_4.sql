-- Migration 003: Drift Engine Phase 3–4 — Timeline, Watchlist, Notifications
-- Applied: 2026-02-22
-- Operator: admin
-- Status: PENDING
--
-- Phase 3: drift_events table persists every drift detection event with
-- field-level diff summary, enabling timeline visualization without
-- recomputing diffs from full_results.
--
-- Phase 4: domain_watchlist for scheduled re-analysis, notification_endpoints
-- for webhook delivery, drift_notifications for delivery tracking.

-- Phase 3: Drift Events (timeline)
CREATE TABLE IF NOT EXISTS drift_events (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) NOT NULL,
    analysis_id INTEGER NOT NULL REFERENCES domain_analyses(id) ON DELETE CASCADE,
    prev_analysis_id INTEGER NOT NULL REFERENCES domain_analyses(id) ON DELETE CASCADE,
    current_hash VARCHAR(128) NOT NULL,
    previous_hash VARCHAR(128) NOT NULL,
    diff_summary JSONB NOT NULL DEFAULT '[]',
    severity VARCHAR(20) NOT NULL DEFAULT 'info',
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_drift_events_domain ON drift_events (domain, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_drift_events_analysis ON drift_events (analysis_id);

-- Phase 4: Domain Watchlist
CREATE TABLE IF NOT EXISTS domain_watchlist (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL,
    cadence VARCHAR(20) NOT NULL DEFAULT 'daily',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_run_at TIMESTAMP,
    next_run_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    CONSTRAINT domain_watchlist_unique UNIQUE (user_id, domain)
);

CREATE INDEX IF NOT EXISTS ix_domain_watchlist_next_run ON domain_watchlist (next_run_at) WHERE enabled = TRUE;
CREATE INDEX IF NOT EXISTS ix_domain_watchlist_user ON domain_watchlist (user_id);

-- Phase 4: Notification Endpoints
CREATE TABLE IF NOT EXISTS notification_endpoints (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    endpoint_type VARCHAR(20) NOT NULL DEFAULT 'webhook',
    url TEXT NOT NULL,
    secret VARCHAR(128),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_notification_endpoints_user ON notification_endpoints (user_id);

-- Phase 4: Drift Notifications (delivery tracking)
CREATE TABLE IF NOT EXISTS drift_notifications (
    id SERIAL PRIMARY KEY,
    drift_event_id INTEGER NOT NULL REFERENCES drift_events(id) ON DELETE CASCADE,
    endpoint_id INTEGER NOT NULL REFERENCES notification_endpoints(id) ON DELETE CASCADE,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    response_code INTEGER,
    response_body TEXT,
    delivered_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_drift_notifications_event ON drift_notifications (drift_event_id);
CREATE INDEX IF NOT EXISTS ix_drift_notifications_status ON drift_notifications (status) WHERE status = 'pending';
