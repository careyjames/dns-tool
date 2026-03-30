-- name: InsertDriftEvent :one
INSERT INTO drift_events (domain, analysis_id, prev_analysis_id, current_hash, previous_hash, diff_summary, severity)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id, created_at;

-- name: ListDriftEventsByDomain :many
SELECT id, domain, analysis_id, prev_analysis_id, current_hash, previous_hash, diff_summary, severity, created_at
FROM drift_events
WHERE domain = $1
ORDER BY created_at DESC
LIMIT $2;

-- name: CountDriftEventsByDomain :one
SELECT COUNT(*) FROM drift_events WHERE domain = $1;

-- name: GetDriftEvent :one
SELECT * FROM drift_events WHERE id = $1;

-- name: ListRecentDriftEvents :many
SELECT id, domain, analysis_id, prev_analysis_id, current_hash, previous_hash, diff_summary, severity, created_at
FROM drift_events
ORDER BY created_at DESC
LIMIT $1;
