-- name: GetAnalysisByID :one
SELECT * FROM domain_analyses WHERE id = $1;

-- name: GetRecentAnalysisByDomain :one
SELECT * FROM domain_analyses
WHERE domain = $1
ORDER BY created_at DESC
LIMIT 1;

-- name: ListSuccessfulAnalyses :many
SELECT * FROM domain_analyses
WHERE full_results IS NOT NULL AND analysis_success = TRUE AND private = FALSE AND scan_flag = FALSE
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: SearchSuccessfulAnalyses :many
SELECT * FROM domain_analyses
WHERE full_results IS NOT NULL
  AND analysis_success = TRUE
  AND private = FALSE
  AND scan_flag = FALSE
  AND (domain ILIKE $1 OR ascii_domain ILIKE $1)
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: CountSuccessfulAnalyses :one
SELECT COUNT(*) FROM domain_analyses
WHERE full_results IS NOT NULL AND analysis_success = TRUE AND private = FALSE AND scan_flag = FALSE;

-- name: CountSearchSuccessfulAnalyses :one
SELECT COUNT(*) FROM domain_analyses
WHERE full_results IS NOT NULL
  AND analysis_success = TRUE
  AND private = FALSE
  AND scan_flag = FALSE
  AND (domain ILIKE $1 OR ascii_domain ILIKE $1);

-- name: ListAnalysesByDomain :many
SELECT * FROM domain_analyses
WHERE domain = $1
  AND full_results IS NOT NULL
  AND analysis_success = TRUE
ORDER BY created_at DESC
LIMIT $2;

-- name: InsertAnalysis :one
INSERT INTO domain_analyses (
    domain, ascii_domain,
    basic_records, authoritative_records,
    spf_status, spf_records,
    dmarc_status, dmarc_policy, dmarc_records,
    dkim_status, dkim_selectors,
    registrar_name, registrar_source,
    ct_subdomains, full_results,
    country_code, country_name,
    analysis_success, error_message, analysis_duration,
    posture_hash, private, has_user_selectors,
    scan_flag, scan_source, scan_ip,
    created_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, NOW()
) RETURNING id, created_at;

-- name: UpdateAnalysis :exec
UPDATE domain_analyses SET
    basic_records = $2,
    authoritative_records = $3,
    spf_status = $4,
    spf_records = $5,
    dmarc_status = $6,
    dmarc_policy = $7,
    dmarc_records = $8,
    dkim_status = $9,
    dkim_selectors = $10,
    registrar_name = $11,
    registrar_source = $12,
    ct_subdomains = $13,
    full_results = $14,
    country_code = $15,
    country_name = $16,
    analysis_duration = $17,
    updated_at = NOW()
WHERE id = $1;

-- name: CountAllAnalyses :one
SELECT COUNT(*) FROM domain_analyses;

-- name: CountSuccessfulAnalysesTotal :one
SELECT COUNT(*) FROM domain_analyses WHERE analysis_success = TRUE;

-- name: CountUniqueDomainsTotal :one
SELECT COUNT(DISTINCT domain) FROM domain_analyses;

-- name: ListPopularDomains :many
SELECT domain, COUNT(id) AS count
FROM domain_analyses
GROUP BY domain
ORDER BY COUNT(id) DESC
LIMIT $1;

-- name: ListCountryDistribution :many
SELECT country_code, country_name, COUNT(id) AS count
FROM domain_analyses
WHERE country_code IS NOT NULL AND country_code <> ''
GROUP BY country_code, country_name
ORDER BY COUNT(id) DESC
LIMIT $1;

-- name: ExportSuccessfulAnalyses :many
SELECT id, domain, ascii_domain, created_at, updated_at,
       analysis_duration, country_code, country_name, full_results
FROM domain_analyses
WHERE full_results IS NOT NULL AND analysis_success = TRUE AND private = FALSE AND scan_flag = FALSE
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: ListScannerAlerts :many
SELECT id, domain, scan_source, scan_ip, analysis_success, created_at
FROM domain_analyses
WHERE scan_flag = TRUE
ORDER BY created_at DESC
LIMIT $1;

-- name: CountScannerAlerts :one
SELECT COUNT(*) FROM domain_analyses WHERE scan_flag = TRUE;

-- name: ListFailedAnalyses :many
SELECT id, domain, error_message, created_at
FROM domain_analyses
WHERE analysis_success = FALSE
  AND private = FALSE
  AND scan_flag = FALSE
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountFailedAnalyses :one
SELECT COUNT(*) FROM domain_analyses
WHERE analysis_success = FALSE
  AND private = FALSE
  AND scan_flag = FALSE;

-- name: GetPreviousPostureHash :one
SELECT posture_hash, created_at FROM domain_analyses
WHERE domain = $1
  AND analysis_success = TRUE
  AND posture_hash IS NOT NULL
  AND posture_hash <> ''
ORDER BY created_at DESC
LIMIT 1;

-- name: GetPreviousAnalysisForDrift :one
SELECT id, posture_hash, full_results, created_at FROM domain_analyses
WHERE domain = $1
  AND analysis_success = TRUE
  AND posture_hash IS NOT NULL
  AND posture_hash <> ''
  AND full_results IS NOT NULL
ORDER BY created_at DESC
LIMIT 1;

-- name: GetPostureHashBefore :one
SELECT posture_hash, created_at FROM domain_analyses
WHERE domain = $1
  AND id < $2
  AND analysis_success = TRUE
  AND posture_hash IS NOT NULL
  AND posture_hash <> ''
ORDER BY created_at DESC
LIMIT 1;

-- name: GetPreviousAnalysisForDriftBefore :one
SELECT id, posture_hash, full_results, created_at FROM domain_analyses
WHERE domain = $1
  AND id < $2
  AND analysis_success = TRUE
  AND posture_hash IS NOT NULL
  AND posture_hash <> ''
  AND full_results IS NOT NULL
ORDER BY created_at DESC
LIMIT 1;

-- name: GetNewerAnalysisForDomain :one
SELECT id, created_at FROM domain_analyses
WHERE ascii_domain = $1
  AND id > $2
  AND analysis_success = TRUE
  AND full_results IS NOT NULL
ORDER BY created_at DESC
LIMIT 1;

-- name: CheckAnalysisOwnership :one
SELECT EXISTS(
    SELECT 1 FROM user_analyses
    WHERE analysis_id = $1 AND user_id = $2
) AS is_owner;

-- name: GetRecentHashedAnalyses :many
SELECT id, domain, posture_hash, full_results, created_at FROM domain_analyses
WHERE posture_hash IS NOT NULL
  AND posture_hash <> ''
  AND full_results IS NOT NULL
  AND analysis_success = TRUE
ORDER BY created_at DESC
LIMIT $1;

-- name: ListHashedAnalyses :many
SELECT id, domain, posture_hash, created_at FROM domain_analyses
WHERE posture_hash IS NOT NULL
  AND posture_hash <> ''
  AND analysis_success = TRUE
  AND private = FALSE
  AND scan_flag = FALSE
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountHashedAnalyses :one
SELECT COUNT(*) FROM domain_analyses
WHERE posture_hash IS NOT NULL
  AND posture_hash <> ''
  AND analysis_success = TRUE
  AND private = FALSE
  AND scan_flag = FALSE;

-- name: UpdateWaybackURL :exec
UPDATE domain_analyses SET wayback_url = $2 WHERE id = $1;
