// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "bytes"
        "context"
        "fmt"
        "log/slog"
        "net/http"
        "os/exec"
        "strings"
        "time"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/icae"

        "github.com/gin-gonic/gin"
)

const timeFormatAdmin = "2006-01-02 15:04"

const (
        opsCSSCohesion      = "css-cohesion"
        opsFeatureInventory = "feature-inventory"
        opsScientificColors = "scientific-colors"
        opsRenderDiagrams   = "render-diagrams"
        opsFigmaBundle      = "figma-bundle"
        opsFigmaVerify      = "figma-verify"
        opsMiroSync         = "miro-sync"
        opsFullPipeline     = "full-pipeline"

        errDeleteUserData  = "Failed to delete user data"

        mapKeyAdmin        = "admin"
        mapKeyCspNonce     = "csp_nonce"
        mapKeyCsrfToken    = "csrf_token"
        mapKeyError        = "error"
        mapKeyUserId       = "user_id"
        strActivepage      = "ActivePage"
        strAppversion      = "AppVersion"
        strBetapages       = "BetaPages"
        strCspnonce        = "CspNonce"
        strCsrftoken       = "CsrfToken"
        strMaintenancenote = "MaintenanceNote"
)

type AdminHandler struct {
        DB                    *db.Database
        Config                *config.Config
        BackpressureCountFunc func() int64
}

func NewAdminHandler(database *db.Database, cfg *config.Config, bpFunc func() int64) *AdminHandler {
        return &AdminHandler{DB: database, Config: cfg, BackpressureCountFunc: bpFunc}
}

type AdminUser struct {
        ID             int32
        Email          string
        Name           string
        Role           string
        CreatedAt      string
        LastLoginAt    string
        SessionCount   int
        ActiveSessions int
}

type AdminAnalysis struct {
        ID               int32
        Domain           string
        Success          bool
        Duration         string
        CreatedAt        string
        CountryCode      string
        ScanIP           string
        Private          bool
        HasUserSelectors bool
        ScanFlag         bool
        ScanSource       string
}

type AdminStats struct {
        TotalUsers         int64
        TotalAnalyses      int64
        UniqueDomainsCount int64
        PrivateAnalyses    int64
        TotalSessions      int64
        ActiveSessions     int64
        ScannerAlerts      int64
}

type AdminScannerAlert struct {
        ID        int32
        Domain    string
        Source    string
        IP        string
        Success   bool
        CreatedAt string
}

type AdminICAERun struct {
        ID          int32
        AppVersion  string
        TotalCases  int32
        TotalPassed int32
        TotalFailed int32
        DurationMs  int32
        CreatedAt   string
}

func (h *AdminHandler) Dashboard(c *gin.Context) {
        nonce, _ := c.Get(mapKeyCspNonce)
        csrfToken, _ := c.Get(mapKeyCsrfToken)
        ctx := c.Request.Context()

        users := h.fetchUsers(ctx)
        recentAnalyses := h.fetchRecentAnalyses(ctx)
        stats := h.fetchStats(ctx)
        icaeRuns := h.fetchICAERuns(ctx)
        scannerAlerts := h.fetchScannerAlerts(ctx)

        icaeMetrics := icae.LoadReportMetrics(ctx, h.DB.Queries)

        var bpCount int64
        if h.BackpressureCountFunc != nil {
                bpCount = h.BackpressureCountFunc()
        }

        data := gin.H{
                strAppversion:            h.Config.AppVersion,
                strMaintenancenote:       h.Config.MaintenanceNote,
                strBetapages:             h.Config.BetaPages,
                strCspnonce:              nonce,
                strCsrftoken:             csrfToken,
                strActivepage:            mapKeyAdmin,
                "Users":                  users,
                "RecentAnalyses":         recentAnalyses,
                "Stats":                  stats,
                "ICAERuns":               icaeRuns,
                "ScannerAlerts":          scannerAlerts,
                "ICAEMetrics":            icaeMetrics,
                "BackpressureRejections": bpCount,
        }
        mergeAuthData(c, h.Config, data)
        c.HTML(http.StatusOK, "admin.html", data)
}

func (h *AdminHandler) fetchUsers(ctx context.Context) []AdminUser {
        rows, err := h.DB.Pool.Query(ctx,
                `SELECT u.id, u.email, u.name, u.role, u.created_at, COALESCE(u.last_login_at, u.created_at),
                        COALESCE(s.total, 0), COALESCE(s.active, 0)
                 FROM users u
                 LEFT JOIN (
                     SELECT user_id,
                            COUNT(*) AS total,
                            COUNT(*) FILTER (WHERE expires_at > NOW()) AS active
                     FROM sessions GROUP BY user_id
                 ) s ON s.user_id = u.id
                 ORDER BY u.last_login_at DESC NULLS LAST`)
        if err != nil {
                slog.Error("Admin: failed to fetch users", mapKeyError, err)
                return nil
        }
        defer func() { rows.Close() }()

        var users []AdminUser
        for rows.Next() {
                var u AdminUser
                var createdAt, lastLoginAt time.Time
                if err := rows.Scan(&u.ID, &u.Email, &u.Name, &u.Role, &createdAt, &lastLoginAt,
                        &u.SessionCount, &u.ActiveSessions); err != nil {
                        slog.Error("Admin: failed to scan user row", mapKeyError, err)
                        continue
                }
                u.CreatedAt = createdAt.Format(timeFormatAdmin)
                u.LastLoginAt = lastLoginAt.Format(timeFormatAdmin)
                users = append(users, u)
        }
        if err := rows.Err(); err != nil {
                slog.Error("Admin: rows iteration error (users)", mapKeyError, err)
        }
        return users
}

func (h *AdminHandler) fetchRecentAnalyses(ctx context.Context) []AdminAnalysis {
        rows, err := h.DB.Pool.Query(ctx,
                `SELECT id, domain, analysis_success, analysis_duration, created_at,
                        COALESCE(country_code, ''), COALESCE(scan_ip, ''), private, has_user_selectors,
                        scan_flag, COALESCE(scan_source, '')
                 FROM domain_analyses
                 ORDER BY created_at DESC LIMIT 25`)
        if err != nil {
                slog.Error("Admin: failed to fetch analyses", mapKeyError, err)
                return nil
        }
        defer func() { rows.Close() }()

        var analyses []AdminAnalysis
        for rows.Next() {
                var a AdminAnalysis
                var success *bool
                var duration *float64
                var createdAt time.Time
                if err := rows.Scan(&a.ID, &a.Domain, &success, &duration, &createdAt,
                        &a.CountryCode, &a.ScanIP, &a.Private, &a.HasUserSelectors, &a.ScanFlag, &a.ScanSource); err != nil {
                        slog.Error("Admin: failed to scan analysis row", mapKeyError, err)
                        continue
                }
                if success != nil {
                        a.Success = *success
                }
                if duration != nil {
                        a.Duration = fmt.Sprintf("%.1fs", *duration)
                } else {
                        a.Duration = "—"
                }
                a.CreatedAt = createdAt.Format(timeFormatAdmin)
                analyses = append(analyses, a)
        }
        if err := rows.Err(); err != nil {
                slog.Error("Admin: rows iteration error (analyses)", mapKeyError, err)
        }
        return analyses
}

func (h *AdminHandler) fetchStats(ctx context.Context) AdminStats {
        var s AdminStats
        queries := []struct {
                sql  string
                dest *int64
        }{
                {`SELECT COUNT(*) FROM users`, &s.TotalUsers},
                {`SELECT COUNT(*) FROM domain_analyses`, &s.TotalAnalyses},
                {`SELECT COUNT(DISTINCT domain) FROM domain_analyses`, &s.UniqueDomainsCount},
                {`SELECT COUNT(*) FROM domain_analyses WHERE private = TRUE`, &s.PrivateAnalyses},
                {`SELECT COUNT(*) FROM sessions`, &s.TotalSessions},
                {`SELECT COUNT(*) FROM sessions WHERE expires_at > NOW()`, &s.ActiveSessions},
                {`SELECT COUNT(*) FROM domain_analyses WHERE scan_flag = TRUE`, &s.ScannerAlerts},
        }
        for _, q := range queries {
                if err := h.DB.Pool.QueryRow(ctx, q.sql).Scan(q.dest); err != nil {
                        slog.Error("Admin: stat query failed", "query", q.sql, mapKeyError, err)
                }
        }
        return s
}

func (h *AdminHandler) fetchICAERuns(ctx context.Context) []AdminICAERun {
        rows, err := h.DB.Pool.Query(ctx,
                `SELECT id, app_version, total_cases, total_passed, total_failed, duration_ms, created_at
                 FROM ice_test_runs ORDER BY created_at DESC LIMIT 10`)
        if err != nil {
                slog.Error("Admin: failed to fetch ICAE runs", mapKeyError, err)
                return nil
        }
        defer func() { rows.Close() }()

        var runs []AdminICAERun
        for rows.Next() {
                var r AdminICAERun
                var createdAt time.Time
                if err := rows.Scan(&r.ID, &r.AppVersion, &r.TotalCases, &r.TotalPassed,
                        &r.TotalFailed, &r.DurationMs, &createdAt); err != nil {
                        slog.Error("Admin: failed to scan ICAE run row", mapKeyError, err)
                        continue
                }
                r.CreatedAt = createdAt.Format(timeFormatAdmin)
                runs = append(runs, r)
        }
        if err := rows.Err(); err != nil {
                slog.Error("Admin: rows iteration error (ICAE runs)", mapKeyError, err)
        }
        return runs
}

func (h *AdminHandler) fetchScannerAlerts(ctx context.Context) []AdminScannerAlert {
        rows, err := h.DB.Pool.Query(ctx,
                `SELECT id, domain, COALESCE(scan_source, 'Unknown'), COALESCE(scan_ip, ''),
                        analysis_success, created_at
                 FROM domain_analyses
                 WHERE scan_flag = TRUE
                 ORDER BY created_at DESC LIMIT 25`)
        if err != nil {
                slog.Error("Admin: failed to fetch scanner alerts", mapKeyError, err)
                return nil
        }
        defer func() { rows.Close() }()

        var alerts []AdminScannerAlert
        for rows.Next() {
                var a AdminScannerAlert
                var success *bool
                var createdAt time.Time
                if err := rows.Scan(&a.ID, &a.Domain, &a.Source, &a.IP, &success, &createdAt); err != nil {
                        slog.Error("Admin: failed to scan scanner alert row", mapKeyError, err)
                        continue
                }
                if success != nil {
                        a.Success = *success
                }
                a.CreatedAt = createdAt.Format(timeFormatAdmin)
                alerts = append(alerts, a)
        }
        if err := rows.Err(); err != nil {
                slog.Error("Admin: rows iteration error (scanner alerts)", mapKeyError, err)
        }
        return alerts
}

func (h *AdminHandler) DeleteUser(c *gin.Context) {
        idStr := c.Param("id")
        var userID int32
        if _, err := fmt.Sscanf(idStr, "%d", &userID); err != nil {
                c.String(http.StatusBadRequest, "Invalid user ID")
                return
        }

        var role string
        err := h.DB.Pool.QueryRow(c.Request.Context(), `SELECT role FROM users WHERE id = $1`, userID).Scan(&role)
        if err != nil {
                c.String(http.StatusNotFound, "User not found")
                return
        }
        if role == mapKeyAdmin {
                c.String(http.StatusForbidden, "Cannot delete admin users from the dashboard")
                return
        }

        ctx := c.Request.Context()
        tx, err := h.DB.Pool.Begin(ctx)
        if err != nil {
                slog.Error("Admin: failed to begin transaction", mapKeyError, err)
                c.String(http.StatusInternalServerError, "Database error")
                return
        }
        defer tx.Rollback(ctx)

        if _, err = tx.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID); err != nil {
                slog.Error("Admin: failed to delete sessions", mapKeyError, err, mapKeyUserId, userID)
                c.String(http.StatusInternalServerError, errDeleteUserData)
                return
        }
        if _, err = tx.Exec(ctx, `DELETE FROM user_analyses WHERE user_id = $1`, userID); err != nil {
                slog.Error("Admin: failed to delete user analyses", mapKeyError, err, mapKeyUserId, userID)
                c.String(http.StatusInternalServerError, errDeleteUserData)
                return
        }
        if _, err = tx.Exec(ctx, `DELETE FROM zone_imports WHERE user_id = $1`, userID); err != nil {
                slog.Error("Admin: failed to delete zone imports", mapKeyError, err, mapKeyUserId, userID)
                c.String(http.StatusInternalServerError, errDeleteUserData)
                return
        }
        _, err = tx.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
        if err != nil {
                slog.Error("Admin: failed to delete user", mapKeyError, err, mapKeyUserId, userID)
                c.String(http.StatusInternalServerError, "Failed to delete user")
                return
        }

        if err := tx.Commit(ctx); err != nil {
                slog.Error("Admin: failed to commit user deletion", mapKeyError, err)
                c.String(http.StatusInternalServerError, "Failed to commit")
                return
        }

        slog.Info("Admin: user deleted", mapKeyUserId, userID)
        c.Redirect(http.StatusSeeOther, "/ops")
}

func (h *AdminHandler) ResetUserSessions(c *gin.Context) {
        idStr := c.Param("id")
        var userID int32
        if _, err := fmt.Sscanf(idStr, "%d", &userID); err != nil {
                c.String(http.StatusBadRequest, "Invalid user ID")
                return
        }

        var exists bool
        err := h.DB.Pool.QueryRow(c.Request.Context(), `SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)`, userID).Scan(&exists)
        if err != nil || !exists {
                c.String(http.StatusNotFound, "User not found")
                return
        }

        _, err = h.DB.Pool.Exec(c.Request.Context(), `DELETE FROM sessions WHERE user_id = $1`, userID)
        if err != nil {
                slog.Error("Admin: failed to reset sessions", mapKeyError, err, mapKeyUserId, userID)
                c.String(http.StatusInternalServerError, "Failed to reset sessions")
                return
        }

        slog.Info("Admin: sessions reset for user", mapKeyUserId, userID)
        c.Redirect(http.StatusSeeOther, "/ops")
}

func (h *AdminHandler) PurgeExpiredSessions(c *gin.Context) {
        result, err := h.DB.Pool.Exec(c.Request.Context(),
                `DELETE FROM sessions WHERE expires_at <= NOW()`)
        if err != nil {
                slog.Error("Admin: failed to purge expired sessions", mapKeyError, err)
                c.String(http.StatusInternalServerError, "Failed to purge sessions")
                return
        }

        count := result.RowsAffected()
        slog.Info("Admin: expired sessions purged", "count", count)
        c.Redirect(http.StatusSeeOther, "/ops")
}

const (
        cmdNode    = "node"
        mapKeyTask = "task"
)

type opsTask struct {
        ID      string
        Label   string
        Icon    string
        Command string
        Args    []string
}

var opsWhitelist = map[string]opsTask{
        opsCSSCohesion: {
                ID:      opsCSSCohesion,
                Label:   "CSS Cohesion Audit",
                Icon:    "palette",
                Command: cmdNode,
                Args:    []string{"scripts/audit-css-cohesion.js"},
        },
        opsFeatureInventory: {
                ID:      opsFeatureInventory,
                Label:   "Feature Inventory",
                Icon:    "boxes-stacked",
                Command: cmdNode,
                Args:    []string{"scripts/feature-inventory.js"},
        },
        opsScientificColors: {
                ID:      opsScientificColors,
                Label:   "Scientific Color Validation",
                Icon:    "flask",
                Command: cmdNode,
                Args:    []string{"scripts/validate-scientific-colors.js"},
        },
        opsRenderDiagrams: {
                ID:      opsRenderDiagrams,
                Label:   "Render Mermaid Diagrams",
                Icon:    "diagram-project",
                Command: "bash",
                Args:    []string{"scripts/render-diagrams.sh"},
        },
        opsFigmaBundle: {
                ID:      opsFigmaBundle,
                Label:   "Figma Asset Bundle",
                Icon:    "box-archive",
                Command: cmdNode,
                Args:    []string{"scripts/figma-asset-bundle.mjs"},
        },
        opsFigmaVerify: {
                ID:      opsFigmaVerify,
                Label:   "Figma Verification",
                Icon:    "magnifying-glass-chart",
                Command: cmdNode,
                Args:    []string{"scripts/figma-verify.mjs"},
        },
        opsMiroSync: {
                ID:      opsMiroSync,
                Label:   "Sync Diagrams to Miro",
                Icon:    "arrow-up-from-bracket",
                Command: cmdNode,
                Args:    []string{"scripts/sync-mermaid-miro.mjs"},
        },
        opsFullPipeline: {
                ID:      opsFullPipeline,
                Label:   "Full Pipeline Sync",
                Icon:    "rotate",
                Command: cmdNode,
                Args:    []string{"scripts/sync-pipeline.mjs"},
        },
}

func (h *AdminHandler) RunOperation(c *gin.Context) {
        taskID := c.Param("task")
        task, ok := opsWhitelist[taskID]
        if !ok {
                slog.Warn("Admin: unknown operation requested", mapKeyTask, taskID)
                c.String(http.StatusBadRequest, "Unknown operation")
                return
        }

        slog.Info("Admin: running operation", mapKeyTask, task.ID, "command", task.Command, "args", task.Args)

        ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
        defer cancel()

        cmd := exec.CommandContext(ctx, task.Command, task.Args...)
        var stdout, stderr bytes.Buffer
        cmd.Stdout = &stdout
        cmd.Stderr = &stderr

        err := cmd.Run()
        output := strings.TrimSpace(stdout.String())
        errOutput := strings.TrimSpace(stderr.String())

        success := err == nil
        combined := output
        if errOutput != "" {
                if combined != "" {
                        combined += "\n" + errOutput
                } else {
                        combined = errOutput
                }
        }

        if !success {
                slog.Warn("Admin: operation failed", mapKeyTask, task.ID, mapKeyError, err, "stderr", errOutput)
        } else {
                slog.Info("Admin: operation completed", mapKeyTask, task.ID)
        }

        nonce, _ := c.Get(mapKeyCspNonce)
        csrfToken, _ := c.Get(mapKeyCsrfToken)

        data := gin.H{
                strAppversion:      h.Config.AppVersion,
                strMaintenancenote: h.Config.MaintenanceNote,
                strBetapages:       h.Config.BetaPages,
                strCspnonce:        nonce,
                strCsrftoken:       csrfToken,
                strActivepage:      mapKeyAdmin,
                "OpResult": gin.H{
                        "Task":    task,
                        "Success": success,
                        "Output":  combined,
                },
                "OpsTasks": opsTaskList(),
        }
        mergeAuthData(c, h.Config, data)
        c.HTML(http.StatusOK, "admin_ops.html", data)
}

func (h *AdminHandler) OperationsPage(c *gin.Context) {
        nonce, _ := c.Get(mapKeyCspNonce)
        csrfToken, _ := c.Get(mapKeyCsrfToken)

        data := gin.H{
                strAppversion:      h.Config.AppVersion,
                strMaintenancenote: h.Config.MaintenanceNote,
                strBetapages:       h.Config.BetaPages,
                strCspnonce:        nonce,
                strCsrftoken:       csrfToken,
                strActivepage:      mapKeyAdmin,
                "OpsTasks":         opsTaskList(),
        }
        mergeAuthData(c, h.Config, data)
        c.HTML(http.StatusOK, "admin_ops.html", data)
}

func opsTaskList() []opsTask {
        order := []string{opsCSSCohesion, opsFeatureInventory, opsScientificColors, opsRenderDiagrams, opsFigmaBundle, opsFigmaVerify, opsMiroSync, opsFullPipeline}
        tasks := make([]opsTask, 0, len(order))
        for _, id := range order {
                if t, ok := opsWhitelist[id]; ok {
                        tasks = append(tasks, t)
                }
        }
        return tasks
}
