-- name: UpsertDomainIndex :exec
INSERT INTO domain_index (domain, first_seen, last_seen, total_scans, last_score, has_dane, has_dnssec, has_mta_sts)
VALUES ($1, NOW(), NOW(), 1, $2, $3, $4, $5)
ON CONFLICT (domain) DO UPDATE SET
    last_seen   = NOW(),
    total_scans = domain_index.total_scans + 1,
    last_score  = EXCLUDED.last_score,
    has_dane    = EXCLUDED.has_dane,
    has_dnssec  = EXCLUDED.has_dnssec,
    has_mta_sts = EXCLUDED.has_mta_sts;

-- name: GetDomainIndexEntry :one
SELECT * FROM domain_index WHERE domain = $1;

-- name: CountDomainIndex :one
SELECT COUNT(*) FROM domain_index;

-- name: ListDomainIndexRecent :many
SELECT domain, first_seen, last_seen, total_scans, last_score, has_dane, has_dnssec, has_mta_sts, tags
FROM domain_index
ORDER BY last_seen DESC
LIMIT $1;

-- name: ListDomainIndexByScans :many
SELECT domain, first_seen, last_seen, total_scans, last_score, has_dane, has_dnssec, has_mta_sts, tags
FROM domain_index
ORDER BY total_scans DESC
LIMIT $1;

-- name: SearchDomainIndex :many
SELECT domain, first_seen, last_seen, total_scans, last_score, has_dane, has_dnssec, has_mta_sts, tags
FROM domain_index
WHERE domain ILIKE $1
ORDER BY total_scans DESC
LIMIT $2;

-- name: ListPriorityDomains :many
SELECT domain, reason FROM priority_domains WHERE enabled = TRUE ORDER BY domain;

-- name: InsertPriorityDomain :exec
INSERT INTO priority_domains (domain, reason) VALUES ($1, $2)
ON CONFLICT (domain) DO UPDATE SET reason = EXCLUDED.reason, enabled = TRUE;

-- name: DisablePriorityDomain :exec
UPDATE priority_domains SET enabled = FALSE WHERE domain = $1;
