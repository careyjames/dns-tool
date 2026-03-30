-- name: ListFindings :many
SELECT * FROM findings
ORDER BY severity, priority, public_id;

-- name: ListFindingsBySeverity :many
SELECT * FROM findings
WHERE severity = $1
ORDER BY priority, public_id;

-- name: ListFindingsByKind :many
SELECT * FROM findings
WHERE kind = $1
ORDER BY severity, priority, public_id;

-- name: ListFindingsByDomain :many
SELECT * FROM findings
WHERE domain = $1
ORDER BY severity, priority, public_id;

-- name: ListFindingsByStatus :many
SELECT * FROM findings
WHERE status = $1
ORDER BY severity, priority, public_id;

-- name: GetFinding :one
SELECT * FROM findings
WHERE public_id = $1;

-- name: GetFindingByID :one
SELECT * FROM findings
WHERE id = $1;

-- name: CountFindingsBySeverity :many
SELECT severity, COUNT(*) as count
FROM findings
GROUP BY severity
ORDER BY severity;

-- name: CountFindingsByKind :many
SELECT kind, COUNT(*) as count
FROM findings
GROUP BY kind
ORDER BY kind;

-- name: CountFindingsByDomain :many
SELECT domain, COUNT(*) as count
FROM findings
GROUP BY domain
ORDER BY domain;

-- name: CountFindingsByStatus :many
SELECT status, COUNT(*) as count
FROM findings
GROUP BY status
ORDER BY status;

-- name: CountFindingsTotal :one
SELECT COUNT(*) as count FROM findings;

-- name: CreateFinding :one
INSERT INTO findings (
    public_id, kind, domain, title, symptom_md, hypothesis_md, root_cause_md,
    severity, priority, status, canonical_rule_id, fingerprint_version,
    fingerprint_sha256, evidence_grade, confidence, blast_radius, visibility,
    standard_refs, source_team, owner, introduced_commit, legacy_bsi_id, legacy_threat_level
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23
) RETURNING *;

-- name: UpdateFindingStatus :exec
UPDATE findings
SET status = $2, updated_at = NOW()
WHERE public_id = $1;

-- name: UpdateFindingFix :exec
UPDATE findings
SET status = 'RENDERED', fixed_commit = $2, fixed_release = $3, root_cause_md = $4, updated_at = NOW()
WHERE public_id = $1;

-- name: CreateObservation :one
INSERT INTO observations (
    finding_id, source_team, build_id, route, component,
    browser, viewport, repro_steps_md, evidence_sha256, raw_evidence
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
) RETURNING *;

-- name: ListObservationsForFinding :many
SELECT * FROM observations
WHERE finding_id = $1
ORDER BY observed_at DESC;

-- name: CreateFindingEvent :one
INSERT INTO finding_events (
    finding_id, actor, event_type, from_status, to_status, commit_sha, note_md
) VALUES (
    $1, $2, $3, $4, $5, $6, $7
) RETURNING *;

-- name: ListFindingEvents :many
SELECT fe.*, f.public_id, f.title, f.severity
FROM finding_events fe
JOIN findings f ON f.id = fe.finding_id
ORDER BY fe.created_at DESC;

-- name: ListFindingEventsForFinding :many
SELECT * FROM finding_events
WHERE finding_id = $1
ORDER BY created_at DESC;
