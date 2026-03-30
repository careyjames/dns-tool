-- name: GetStatsByDate :one
SELECT * FROM analysis_stats WHERE date = $1;

-- name: ListRecentStats :many
SELECT * FROM analysis_stats
ORDER BY date DESC
LIMIT $1;

-- name: UpsertDailyStats :exec
INSERT INTO analysis_stats (date, total_analyses, successful_analyses, failed_analyses, unique_domains, avg_analysis_time, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
ON CONFLICT (date) DO UPDATE SET
    total_analyses = $2,
    successful_analyses = $3,
    failed_analyses = $4,
    unique_domains = $5,
    avg_analysis_time = $6,
    updated_at = NOW();

-- name: IncrementDailyStats :exec
UPDATE analysis_stats SET
    total_analyses = COALESCE(total_analyses, 0) + 1,
    successful_analyses = CASE WHEN $2::boolean THEN COALESCE(successful_analyses, 0) + 1 ELSE successful_analyses END,
    failed_analyses = CASE WHEN NOT $2::boolean THEN COALESCE(failed_analyses, 0) + 1 ELSE failed_analyses END,
    avg_analysis_time = CASE
        WHEN COALESCE(total_analyses, 0) = 0 THEN $3::double precision
        ELSE (COALESCE(avg_analysis_time, 0) * COALESCE(total_analyses, 0) + $3::double precision) / (COALESCE(total_analyses, 0) + 1)
    END,
    updated_at = NOW()
WHERE date = $1;

-- name: InsertDailyStats :exec
INSERT INTO analysis_stats (date, total_analyses, successful_analyses, failed_analyses, unique_domains, avg_analysis_time, created_at, updated_at)
VALUES ($1, 1, CASE WHEN $2::boolean THEN 1 ELSE 0 END, CASE WHEN NOT $2::boolean THEN 1 ELSE 0 END, 0, $3, NOW(), NOW());

-- name: SumAnalysisStats :one
SELECT 
    COALESCE(SUM(total_analyses), 0)::bigint AS total,
    COALESCE(SUM(successful_analyses), 0)::bigint AS successful,
    COALESCE(SUM(failed_analyses), 0)::bigint AS failed
FROM analysis_stats;

-- name: CountUniqueDomainsByDate :one
SELECT COUNT(DISTINCT domain) FROM domain_analyses
WHERE created_at::date = $1;

-- name: UpdateUniqueDomainCount :exec
UPDATE analysis_stats SET unique_domains = $2, updated_at = NOW() WHERE date = $1;

-- name: CountRemediatedDomains :one
SELECT COUNT(DISTINCT domain)::bigint AS count
FROM drift_events
WHERE diff_summary @> '[{"Severity": "success"}]'::jsonb;
