-- name: ListDetainees :many
SELECT * FROM black_site_detainees
ORDER BY
    CASE threat_level
        WHEN 'APT' THEN 1
        WHEN 'ZERO-DAY' THEN 2
        WHEN 'EXPLOIT' THEN 3
        WHEN 'CVE' THEN 4
        WHEN 'IOC' THEN 5
    END,
    bsi_id;

-- name: ListDetaineesByThreatLevel :many
SELECT * FROM black_site_detainees
WHERE threat_level = $1
ORDER BY bsi_id;

-- name: GetDetainee :one
SELECT * FROM black_site_detainees
WHERE bsi_id = $1;

-- name: GetDetaineeByID :one
SELECT * FROM black_site_detainees
WHERE id = $1;

-- name: CountDetaineesByThreatLevel :many
SELECT threat_level, COUNT(*) as count
FROM black_site_detainees
GROUP BY threat_level
ORDER BY
    CASE threat_level
        WHEN 'APT' THEN 1
        WHEN 'ZERO-DAY' THEN 2
        WHEN 'EXPLOIT' THEN 3
        WHEN 'CVE' THEN 4
        WHEN 'IOC' THEN 5
    END;

-- name: CountDetaineesByStatus :many
SELECT status, COUNT(*) as count
FROM black_site_detainees
GROUP BY status
ORDER BY status;

-- name: CountDetaineesTotal :one
SELECT COUNT(*) as count FROM black_site_detainees;

-- name: CreateDetainee :one
INSERT INTO black_site_detainees (
    bsi_id, sha_hash, title, threat_level, status,
    captured_by, file_references, interrogation_notes,
    witness_statement, damage_assessment, recommended_remedy
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
) RETURNING *;

-- name: UpdateDetaineeStatus :exec
UPDATE black_site_detainees
SET status = $2, updated_at = NOW()
WHERE bsi_id = $1;

-- name: CreateRendition :one
INSERT INTO black_site_renditions (
    detainee_id, commit_hash, rendered_by, method, notes
) VALUES (
    $1, $2, $3, $4, $5
) RETURNING *;

-- name: ListRenditions :many
SELECT r.*, d.bsi_id, d.sha_hash, d.title, d.threat_level
FROM black_site_renditions r
JOIN black_site_detainees d ON d.id = r.detainee_id
ORDER BY r.rendered_at DESC;

-- name: ListRenditionsForDetainee :many
SELECT * FROM black_site_renditions
WHERE detainee_id = $1
ORDER BY rendered_at DESC;
