-- name: ListEDEEvents :many
SELECT * FROM ede_events
ORDER BY event_date DESC;

-- name: GetEDEEvent :one
SELECT * FROM ede_events
WHERE ede_id = $1;

-- name: CountEDEEvents :one
SELECT
    COUNT(*) AS total,
    COUNT(*) FILTER (WHERE status = 'open') AS open,
    COUNT(*) FILTER (WHERE status = 'closed') AS closed,
    COUNT(*) FILTER (WHERE category = 'scoring_calibration') AS recalibrations
FROM ede_events;

-- name: ListEDEAmendments :many
SELECT a.*, e.ede_id
FROM ede_amendments a
JOIN ede_events e ON e.id = a.ede_event_id
ORDER BY a.amendment_date DESC;

-- name: ListEDEAmendmentsByEvent :many
SELECT * FROM ede_amendments
WHERE ede_event_id = $1
ORDER BY amendment_date;

-- name: ListEDEEventsByCategory :many
SELECT * FROM ede_events
WHERE category = $1
ORDER BY event_date DESC;

-- name: ListEDEEventsBySeverity :many
SELECT * FROM ede_events
WHERE severity = $1
ORDER BY event_date DESC;

-- name: ListEDEEventsByAttribution :many
SELECT * FROM ede_events
WHERE attribution = $1
ORDER BY event_date DESC;

-- name: CountEDEByAttribution :many
SELECT attribution, COUNT(*) AS count
FROM ede_events
GROUP BY attribution
ORDER BY count DESC;

-- name: CountEDEByCategory :many
SELECT category, COUNT(*) AS count
FROM ede_events
GROUP BY category
ORDER BY count DESC;
