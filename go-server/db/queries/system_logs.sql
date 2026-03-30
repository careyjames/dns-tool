-- name: ListSystemLogs :many
SELECT id, timestamp, level, message, event, category, domain, trace_id, attrs
FROM system_log_entries
WHERE
    (sqlc.narg('level')::text IS NULL OR level = sqlc.narg('level'))
    AND (sqlc.narg('category')::text IS NULL OR category = sqlc.narg('category'))
    AND (sqlc.narg('domain_filter')::text IS NULL OR domain ILIKE '%' || sqlc.narg('domain_filter') || '%')
    AND (sqlc.narg('trace_id_filter')::text IS NULL OR trace_id = sqlc.narg('trace_id_filter'))
    AND (sqlc.narg('after_ts')::timestamp IS NULL OR timestamp >= sqlc.narg('after_ts'))
    AND (sqlc.narg('before_ts')::timestamp IS NULL OR timestamp <= sqlc.narg('before_ts'))
ORDER BY timestamp DESC
LIMIT sqlc.arg('max_rows');

-- name: CountSystemLogs :one
SELECT count(*) FROM system_log_entries;

-- name: PruneSystemLogs :exec
DELETE FROM system_log_entries
WHERE id NOT IN (
    SELECT id FROM system_log_entries
    ORDER BY timestamp DESC
    LIMIT $1
);

-- name: GetLogLevelCounts :many
SELECT level, count(*) as cnt
FROM system_log_entries
WHERE timestamp > NOW() - INTERVAL '24 hours'
GROUP BY level
ORDER BY cnt DESC;

-- name: GetRecentLogEvents :many
SELECT event, count(*) as cnt
FROM system_log_entries
WHERE timestamp > NOW() - INTERVAL '24 hours'
  AND event != ''
GROUP BY event
ORDER BY cnt DESC
LIMIT 20;
