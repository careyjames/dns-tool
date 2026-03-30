-- name: GetUserByGoogleSub :one
SELECT * FROM users WHERE google_sub = $1;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: UpsertUser :one
INSERT INTO users (email, name, google_sub, role, last_login_at)
VALUES ($1, $2, $3, $4, NOW())
ON CONFLICT (google_sub)
DO UPDATE SET name = $2, email = $1, last_login_at = NOW()
RETURNING *;

-- name: CreateSession :exec
INSERT INTO sessions (id, user_id, expires_at) VALUES ($1, $2, $3);

-- name: GetSession :one
SELECT s.*, u.email, u.name, u.role, u.google_sub
FROM sessions s
JOIN users u ON s.user_id = u.id
WHERE s.id = $1 AND s.expires_at > NOW();

-- name: UpdateSessionLastSeen :exec
UPDATE sessions SET last_seen_at = NOW() WHERE id = $1;

-- name: DeleteSession :exec
DELETE FROM sessions WHERE id = $1;

-- name: CountAdminUsers :one
SELECT COUNT(*) FROM users WHERE role = 'admin';

-- name: PromoteUserToAdmin :exec
UPDATE users SET role = 'admin' WHERE id = $1;

-- name: DeleteExpiredSessions :exec
DELETE FROM sessions WHERE expires_at < NOW();
