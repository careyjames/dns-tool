-- name: InsertUserAnalysis :exec
INSERT INTO user_analyses (user_id, analysis_id)
VALUES ($1, $2)
ON CONFLICT (user_id, analysis_id) DO NOTHING;

-- name: ListUserAnalyses :many
SELECT da.id, da.domain, da.ascii_domain,
       da.spf_status, da.dmarc_status, da.dkim_status,
       da.analysis_success, da.analysis_duration,
       da.posture_hash, da.created_at, da.full_results
FROM user_analyses ua
JOIN domain_analyses da ON ua.analysis_id = da.id
WHERE ua.user_id = $1
  AND da.analysis_success = TRUE
  AND da.full_results IS NOT NULL
ORDER BY ua.created_at DESC
LIMIT $2 OFFSET $3;

-- name: CountUserAnalyses :one
SELECT COUNT(*) FROM user_analyses ua
JOIN domain_analyses da ON ua.analysis_id = da.id
WHERE ua.user_id = $1
  AND da.analysis_success = TRUE
  AND da.full_results IS NOT NULL;

-- name: SearchUserAnalyses :many
SELECT da.id, da.domain, da.ascii_domain,
       da.spf_status, da.dmarc_status, da.dkim_status,
       da.analysis_success, da.analysis_duration,
       da.posture_hash, da.created_at, da.full_results
FROM user_analyses ua
JOIN domain_analyses da ON ua.analysis_id = da.id
WHERE ua.user_id = $1
  AND da.analysis_success = TRUE
  AND da.full_results IS NOT NULL
  AND (da.domain ILIKE $2 OR da.ascii_domain ILIKE $2)
ORDER BY ua.created_at DESC
LIMIT $3 OFFSET $4;

-- name: CountSearchUserAnalyses :one
SELECT COUNT(*) FROM user_analyses ua
JOIN domain_analyses da ON ua.analysis_id = da.id
WHERE ua.user_id = $1
  AND da.analysis_success = TRUE
  AND da.full_results IS NOT NULL
  AND (da.domain ILIKE $2 OR da.ascii_domain ILIKE $2);

-- name: ListUserUniqueDomains :many
SELECT da.domain, COUNT(*) AS scan_count,
       MAX(da.created_at) AS last_scanned
FROM user_analyses ua
JOIN domain_analyses da ON ua.analysis_id = da.id
WHERE ua.user_id = $1
  AND da.analysis_success = TRUE
GROUP BY da.domain
ORDER BY MAX(da.created_at) DESC
LIMIT $2;
