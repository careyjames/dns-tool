-- name: InsertZoneImport :one
INSERT INTO zone_imports (user_id, domain, sha256_hash, original_filename, file_size, record_count, retained, zone_data, drift_summary)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING id, created_at;

-- name: ListUserZoneImports :many
SELECT id, domain, sha256_hash, original_filename, file_size, record_count, retained, created_at
FROM zone_imports
WHERE user_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;
