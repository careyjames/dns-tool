-- name: InsertWatchlistEntry :one
INSERT INTO domain_watchlist (user_id, domain, cadence, next_run_at)
VALUES ($1, $2, $3, $4)
RETURNING id, created_at;

-- name: ListWatchlistByUser :many
SELECT * FROM domain_watchlist
WHERE user_id = $1
ORDER BY created_at DESC;

-- name: GetWatchlistEntry :one
SELECT * FROM domain_watchlist WHERE id = $1 AND user_id = $2;

-- name: UpdateWatchlistCadence :exec
UPDATE domain_watchlist SET cadence = $3, next_run_at = $4
WHERE id = $1 AND user_id = $2;

-- name: ToggleWatchlistEntry :exec
UPDATE domain_watchlist SET enabled = $3
WHERE id = $1 AND user_id = $2;

-- name: DeleteWatchlistEntry :exec
DELETE FROM domain_watchlist WHERE id = $1 AND user_id = $2;

-- name: CountWatchlistByUser :one
SELECT COUNT(*) FROM domain_watchlist WHERE user_id = $1;

-- name: ListDueWatchlistEntries :many
SELECT w.id, w.user_id, w.domain, w.cadence, w.last_run_at, w.next_run_at
FROM domain_watchlist w
WHERE w.enabled = TRUE
  AND (w.next_run_at IS NULL OR w.next_run_at <= NOW())
ORDER BY w.next_run_at ASC NULLS FIRST
LIMIT $1;

-- name: MarkWatchlistRun :exec
UPDATE domain_watchlist SET last_run_at = NOW(), next_run_at = $2
WHERE id = $1;

-- name: InsertNotificationEndpoint :one
INSERT INTO notification_endpoints (user_id, endpoint_type, url, secret)
VALUES ($1, $2, $3, $4)
RETURNING id, created_at;

-- name: ListNotificationEndpointsByUser :many
SELECT * FROM notification_endpoints
WHERE user_id = $1
ORDER BY created_at DESC;

-- name: DeleteNotificationEndpoint :exec
DELETE FROM notification_endpoints WHERE id = $1 AND user_id = $2;

-- name: ToggleNotificationEndpoint :exec
UPDATE notification_endpoints SET enabled = $3
WHERE id = $1 AND user_id = $2;

-- name: ListEnabledEndpointsByUser :many
SELECT * FROM notification_endpoints
WHERE user_id = $1 AND enabled = TRUE;

-- name: InsertDriftNotification :one
INSERT INTO drift_notifications (drift_event_id, endpoint_id, status)
VALUES ($1, $2, $3)
RETURNING id;

-- name: UpdateDriftNotificationStatus :exec
UPDATE drift_notifications SET status = $2, response_code = $3, response_body = $4, delivered_at = NOW()
WHERE id = $1;

-- name: ListEndpointsForWatchedDomain :many
SELECT e.id AS endpoint_id, e.endpoint_type, e.url, e.secret
FROM domain_watchlist w
JOIN notification_endpoints e ON e.user_id = w.user_id AND e.enabled = TRUE
WHERE w.domain = $1 AND w.enabled = TRUE;

-- name: ListPendingNotifications :many
SELECT n.id, n.drift_event_id, n.endpoint_id, n.status,
       e.url, e.secret, e.endpoint_type,
       d.domain, d.diff_summary, d.severity
FROM drift_notifications n
JOIN notification_endpoints e ON n.endpoint_id = e.id AND e.enabled = TRUE
JOIN drift_events d ON n.drift_event_id = d.id
WHERE n.status = 'pending'
ORDER BY n.created_at ASC
LIMIT $1;
