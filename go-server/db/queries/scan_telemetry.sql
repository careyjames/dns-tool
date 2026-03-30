-- name: InsertPhaseTelemetry :exec
INSERT INTO scan_phase_telemetry (analysis_id, phase_group, phase_task, started_at_ms, duration_ms, record_count, error)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: InsertTelemetryHash :exec
INSERT INTO scan_telemetry_hash (analysis_id, total_duration_ms, phase_count, sha3_512)
VALUES ($1, $2, $3, $4);

-- name: GetTelemetryByAnalysis :many
SELECT id, analysis_id, phase_group, phase_task, started_at_ms, duration_ms, record_count, error, created_at
FROM scan_phase_telemetry
WHERE analysis_id = $1
ORDER BY started_at_ms, phase_task;

-- name: GetTelemetryHash :one
SELECT analysis_id, total_duration_ms, phase_count, sha3_512, created_at
FROM scan_telemetry_hash
WHERE analysis_id = $1;

-- name: GetTelemetryTrends :many
SELECT spt.phase_group,
       DATE(spt.created_at) AS trend_date,
       AVG(spt.duration_ms)::INT AS avg_duration_ms,
       COUNT(*) AS sample_count
FROM scan_phase_telemetry spt
WHERE spt.created_at >= NOW() - INTERVAL '7 days'
GROUP BY spt.phase_group, DATE(spt.created_at)
ORDER BY trend_date, spt.phase_group;

-- name: GetSlowestPhases :many
SELECT phase_group, phase_task, AVG(duration_ms)::INT AS avg_ms,
       PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY duration_ms)::INT AS p50_ms,
       PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY duration_ms)::INT AS p95_ms,
       PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY duration_ms)::INT AS p99_ms,
       COUNT(*) AS sample_count
FROM scan_phase_telemetry
WHERE created_at >= NOW() - INTERVAL '7 days'
GROUP BY phase_group, phase_task
ORDER BY p95_ms DESC
LIMIT $1;

-- name: GetRecentTelemetrySummaries :many
SELECT sth.analysis_id, da.ascii_domain, sth.total_duration_ms, sth.phase_count, sth.sha3_512, sth.created_at
FROM scan_telemetry_hash sth
JOIN domain_analyses da ON da.id = sth.analysis_id
ORDER BY sth.created_at DESC
LIMIT $1;

-- name: GetPipelineStageStats :many
SELECT phase_group,
       COUNT(DISTINCT analysis_id) AS scan_count,
       AVG(duration_ms)::INT AS avg_ms,
       PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY duration_ms)::INT AS p50_ms,
       PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY duration_ms)::INT AS p95_ms,
       PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY duration_ms)::INT AS p99_ms,
       MIN(duration_ms) AS min_ms,
       MAX(duration_ms) AS max_ms,
       SUM(record_count)::BIGINT AS total_records,
       SUM(CASE WHEN error <> '' THEN 1 ELSE 0 END)::INT AS error_count
FROM scan_phase_telemetry
WHERE created_at >= NOW() - INTERVAL '30 days'
GROUP BY phase_group
ORDER BY AVG(started_at_ms);

-- name: GetPipelineEndToEndStats :one
SELECT COUNT(*) AS total_scans,
       AVG(total_duration_ms)::INT AS avg_total_ms,
       PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY total_duration_ms)::INT AS p50_total_ms,
       PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY total_duration_ms)::INT AS p95_total_ms,
       PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY total_duration_ms)::INT AS p99_total_ms,
       MIN(total_duration_ms) AS min_total_ms,
       MAX(total_duration_ms) AS max_total_ms
FROM scan_telemetry_hash
WHERE created_at >= NOW() - INTERVAL '30 days';

-- name: GetPipelineDurationDistribution :many
SELECT
    CASE
        WHEN total_duration_ms < 2000 THEN '0-2s'
        WHEN total_duration_ms < 5000 THEN '2-5s'
        WHEN total_duration_ms < 10000 THEN '5-10s'
        WHEN total_duration_ms < 20000 THEN '10-20s'
        WHEN total_duration_ms < 30000 THEN '20-30s'
        WHEN total_duration_ms < 60000 THEN '30-60s'
        ELSE '60s+'
    END AS bucket,
    COUNT(*) AS count
FROM scan_telemetry_hash
WHERE created_at >= NOW() - INTERVAL '30 days'
GROUP BY bucket
ORDER BY MIN(total_duration_ms);

-- name: GetDriftSeverityDistribution :many
SELECT severity, COUNT(*) AS count
FROM drift_events
WHERE created_at >= NOW() - INTERVAL '30 days'
GROUP BY severity
ORDER BY count DESC;
