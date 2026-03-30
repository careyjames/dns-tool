-- name: ICAEGetAllMaturity :many
SELECT protocol, layer, maturity, total_runs, consecutive_passes,
       first_pass_at, last_regression_at, last_evaluated_at
FROM ice_maturity
ORDER BY protocol ASC, layer ASC;

-- name: ICAEGetMaturity :one
SELECT protocol, layer, maturity, total_runs, consecutive_passes,
       first_pass_at, last_regression_at, last_evaluated_at
FROM ice_maturity
WHERE protocol = $1 AND layer = $2;

-- name: ICAEInsertTestRun :one
INSERT INTO ice_test_runs (app_version, git_commit, run_type, total_cases, total_passed, total_failed, duration_ms)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id, created_at;

-- name: ICAEInsertResult :exec
INSERT INTO ice_results (run_id, protocol, layer, case_id, case_name, passed, expected, actual, rfc_section, notes)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

-- name: ICAEUpdateMaturity :exec
UPDATE ice_maturity SET
    maturity = $3,
    total_runs = $4,
    consecutive_passes = $5,
    first_pass_at = $6,
    last_regression_at = $7,
    last_evaluated_at = NOW(),
    updated_at = NOW()
WHERE protocol = $1 AND layer = $2;

-- name: ICAEInsertRegression :exec
INSERT INTO ice_regressions (protocol, layer, run_id, previous_maturity, new_maturity, failed_cases, notes)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: ICAEGetRecentRegressions :many
SELECT protocol, layer, previous_maturity, new_maturity, failed_cases, notes, created_at
FROM ice_regressions
ORDER BY created_at DESC
LIMIT $1;

-- name: ICAEGetLatestRun :one
SELECT id, app_version, git_commit, run_type, total_cases, total_passed, total_failed, duration_ms, created_at
FROM ice_test_runs
ORDER BY created_at DESC
LIMIT 1;

-- name: ICAEGetResultsByRun :many
SELECT protocol, layer, case_id, case_name, passed, expected, actual, rfc_section, notes
FROM ice_results
WHERE run_id = $1
ORDER BY protocol ASC, layer ASC, case_id ASC;

-- name: ICAEGetFailedResultsByRun :many
SELECT protocol, layer, case_id, case_name, expected, actual, rfc_section, notes
FROM ice_results
WHERE run_id = $1 AND passed = false
ORDER BY protocol ASC, layer ASC, case_id ASC;

-- name: ICAECountResultsByProtocol :many
SELECT protocol, layer,
       COUNT(*) AS total,
       COUNT(*) FILTER (WHERE passed = true) AS passed,
       COUNT(*) FILTER (WHERE passed = false) AS failed
FROM ice_results
WHERE run_id = $1
GROUP BY protocol, layer
ORDER BY protocol ASC, layer ASC;

-- name: ICAEUpsertMaturity :exec
INSERT INTO ice_maturity (protocol, layer, maturity, total_runs, consecutive_passes, first_pass_at, last_regression_at, last_evaluated_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
ON CONFLICT (protocol, layer) DO UPDATE SET
    maturity = $3,
    total_runs = $4,
    consecutive_passes = $5,
    first_pass_at = $6,
    last_regression_at = $7,
    last_evaluated_at = NOW(),
    updated_at = NOW();
