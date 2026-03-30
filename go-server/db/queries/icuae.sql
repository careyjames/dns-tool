-- name: ICuAEInsertScanScore :one
INSERT INTO icuae_scan_scores (domain, overall_score, overall_grade, resolver_count, record_count, app_version)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, created_at;

-- name: ICuAEInsertDimensionScore :exec
INSERT INTO icuae_dimension_scores (scan_id, dimension, score, grade, record_types_evaluated, record_types_list)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: ICuAEGetAggregateStats :one
SELECT
    COUNT(*)::integer AS total_scans,
    COALESCE(AVG(overall_score), 0)::real AS avg_score,
    COALESCE(STDDEV_POP(overall_score), 0)::real AS stddev_score,
    MAX(created_at) AS last_evaluated_at
FROM icuae_scan_scores;

-- name: ICuAEGetGradeDistribution :many
SELECT
    overall_grade AS grade,
    COUNT(*)::integer AS count
FROM icuae_scan_scores
GROUP BY overall_grade
ORDER BY overall_grade ASC;

-- name: ICuAEGetDimensionAverages :many
SELECT
    dimension,
    COALESCE(AVG(score), 0)::real AS avg_score,
    COALESCE(STDDEV_POP(score), 0)::real AS stddev_score,
    COUNT(*)::integer AS sample_count
FROM icuae_dimension_scores
GROUP BY dimension
ORDER BY dimension ASC;

-- name: ICuAEGetRecentTrend :many
SELECT
    overall_score,
    created_at
FROM icuae_scan_scores
ORDER BY created_at DESC
LIMIT $1;
