-- name: GetCTCache :one
SELECT domain, subdomains, unique_count, source, fetched_at, expires_at
FROM ct_subdomain_cache
WHERE domain = $1 AND expires_at > NOW();

-- name: UpsertCTCache :exec
INSERT INTO ct_subdomain_cache (domain, subdomains, unique_count, source, fetched_at, expires_at)
VALUES ($1, $2, $3, $4, NOW(), NOW() + INTERVAL '24 hours')
ON CONFLICT (domain) DO UPDATE SET
    subdomains = EXCLUDED.subdomains,
    unique_count = EXCLUDED.unique_count,
    source = EXCLUDED.source,
    fetched_at = NOW(),
    expires_at = NOW() + INTERVAL '24 hours';

-- name: PurgeCTCacheExpired :exec
DELETE FROM ct_subdomain_cache WHERE expires_at < NOW();

-- name: GetTopAnalyzedDomains :many
SELECT domain, COUNT(*) AS analysis_count
FROM domain_analyses
WHERE analysis_success = TRUE
  AND created_at > NOW() - INTERVAL '30 days'
GROUP BY domain
ORDER BY analysis_count DESC
LIMIT $1;

-- name: GetSTBudget :one
SELECT month_key, calls_used, domains_enriched, last_called_at
FROM securitytrails_budget
WHERE month_key = $1;

-- name: UpsertSTBudget :exec
INSERT INTO securitytrails_budget (month_key, calls_used, domains_enriched, last_called_at, updated_at)
VALUES ($1, $2, $3, NOW(), NOW())
ON CONFLICT (month_key) DO UPDATE SET
    calls_used = EXCLUDED.calls_used,
    domains_enriched = EXCLUDED.domains_enriched,
    last_called_at = NOW(),
    updated_at = NOW();
