// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.

// dns-tool:scrutiny plumbing
package middleware

import (
        "context"
        "log/slog"
        "net/http"
        "net/url"
        "strings"
        "time"

        "dnstool/go-server/internal/dbq"
        "dnstool/go-server/internal/entitlements"

        "github.com/gin-gonic/gin"
        "github.com/jackc/pgx/v5/pgxpool"
)

const (
        mapKeyAuthenticated = "authenticated"
        mapKeyUserRole      = "user_role"
        msgAuthRequired     = "Authentication required"
)

const sessionCookieName = "_dns_session"

func SessionLoader(pool *pgxpool.Pool) gin.HandlerFunc {
        queries := dbq.New(pool)
        return func(c *gin.Context) {
                cookie, err := c.Cookie(sessionCookieName)
                if err != nil || cookie == "" {
                        c.Next()
                        return
                }

                session, err := queries.GetSession(c.Request.Context(), cookie)
                if err != nil {
                        c.Next()
                        return
                }

                c.Set("user_id", session.UserID)
                c.Set("user_email", session.Email)
                c.Set("user_name", session.Name)
                c.Set(mapKeyUserRole, session.Role)
                c.Set("session_id", session.ID)
                c.Set(mapKeyAuthenticated, true)

                go func(token string) {
                        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
                        defer cancel()
                        if err := queries.UpdateSessionLastSeen(ctx, token); err != nil {
                                slog.Debug("update session last seen", "error", err)
                        }
                }(cookie)

                c.Next()
        }
}

func RequireAuth() gin.HandlerFunc {
        return func(c *gin.Context) {
                auth, exists := c.Get(mapKeyAuthenticated)
                authed, ok := auth.(bool)
                if !ok {
                        authed = false
                }
                if !exists || !authed {
                        c.JSON(http.StatusUnauthorized, gin.H{
                                mapKeyError: msgAuthRequired,
                        })
                        c.Abort()
                        return
                }
                c.Next()
        }
}

func wantsHTML(c *gin.Context) bool {
        accept := c.GetHeader("Accept")
        return strings.Contains(accept, "text/html")
}

func RequireAdmin() gin.HandlerFunc {
        return func(c *gin.Context) {
                auth, exists := c.Get(mapKeyAuthenticated)
                authed, ok := auth.(bool)
                if !ok {
                        authed = false
                }
                if !exists || !authed {
                        if wantsHTML(c) {
                                c.Redirect(http.StatusFound, "/auth/login?next="+url.QueryEscape(c.Request.URL.Path))
                                c.Abort()
                                return
                        }
                        c.JSON(http.StatusUnauthorized, gin.H{
                                mapKeyError: msgAuthRequired,
                        })
                        c.Abort()
                        return
                }
                role, exists := c.Get(mapKeyUserRole)
                if !exists || role != "admin" {
                        if wantsHTML(c) {
                                c.Redirect(http.StatusFound, "/")
                                c.Abort()
                                return
                        }
                        c.JSON(http.StatusForbidden, gin.H{
                                mapKeyError: "Administrator access required",
                        })
                        c.Abort()
                        return
                }
                c.Next()
        }
}

func RequireFeature(feature entitlements.Feature) gin.HandlerFunc {
        return func(c *gin.Context) {
                plan := resolveCurrentPlan(c)
                if !entitlements.HasAccess(plan, feature) {
                        if plan == entitlements.PlanAnonymous {
                                c.JSON(http.StatusUnauthorized, gin.H{
                                        mapKeyError: msgAuthRequired,
                                })
                        } else {
                                c.JSON(http.StatusForbidden, gin.H{
                                        mapKeyError: "Upgrade required for this feature",
                                })
                        }
                        c.Abort()
                        return
                }
                c.Next()
        }
}

func HasFeature(c *gin.Context, feature entitlements.Feature) bool {
        return entitlements.HasAccess(resolveCurrentPlan(c), feature)
}

func CurrentPlan(c *gin.Context) entitlements.Plan {
        return resolveCurrentPlan(c)
}

func resolveCurrentPlan(c *gin.Context) entitlements.Plan {
        auth, exists := c.Get(mapKeyAuthenticated)
        authed, ok := auth.(bool)
        if !ok {
                authed = false
        }
        if !exists || !authed {
                return entitlements.PlanAnonymous
        }
        role, _ := c.Get(mapKeyUserRole)
        roleStr, _ := role.(string)

        // S1135 suppressed: Stripe integration is a tracked roadmap item (Phase 5).
        // TODO: check subscription status when Stripe is integrated
        subscriptionActive := false

        return entitlements.ResolvePlan(true, roleStr, subscriptionActive)
}

func GetAuthTemplateData(c *gin.Context) map[string]any {
        data := map[string]any{}
        plan := resolveCurrentPlan(c)
        data["UserPlan"] = string(plan)
        data["HasFeaturePersonalHistory"] = entitlements.HasAccess(plan, entitlements.FeaturePersonalHistory)
        data["HasFeatureWatchlist"] = entitlements.HasAccess(plan, entitlements.FeatureWatchlist)
        data["HasFeatureDossier"] = entitlements.HasAccess(plan, entitlements.FeatureDossier)
        data["HasFeatureZoneUpload"] = entitlements.HasAccess(plan, entitlements.FeatureZoneUpload)
        data["HasFeatureBulkScan"] = entitlements.HasAccess(plan, entitlements.FeatureBulkScan)
        data["HasFeatureAPIKeys"] = entitlements.HasAccess(plan, entitlements.FeatureAPIKeys)
        data["HasFeatureBulkExport"] = entitlements.HasAccess(plan, entitlements.FeatureBulkExport)

        if auth, exists := c.Get(mapKeyAuthenticated); exists {
                authed, ok := auth.(bool)
                if !ok || !authed {
                        return data
                }
                email, _ := c.Get("user_email")  //nolint:errcheck // value used for template data
                name, _ := c.Get("user_name")    //nolint:errcheck // value used for template data
                role, _ := c.Get(mapKeyUserRole) //nolint:errcheck // value used for template data
                data["Authenticated"] = true
                data["UserEmail"] = email
                data["UserName"] = name
                data["UserRole"] = role
        }
        return data
}
