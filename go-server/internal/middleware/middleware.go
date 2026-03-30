// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny plumbing
package middleware

import (
        "context"
        "crypto/rand"
        "encoding/base64"
        "fmt"
        "log/slog"
        "net/http"
        "net/url"
        "os"
        "strings"
        "time"

        "github.com/gin-gonic/gin"
        "github.com/google/uuid"
)

type contextKey string

const (
        CSPNonceKey contextKey = "csp_nonce"
        TraceIDKey  contextKey = "trace_id"

        ginKeyCSPNonce     = "csp_nonce"
        ginKeyTraceID      = "trace_id"
        ginKeyRequestStart = "request_start"
        ginKeyCSRFToken    = "csrf_token"
)

func generateNonce() string {
        b := make([]byte, 16)
        if _, err := rand.Read(b); err != nil {
                slog.Error("rand.Read failed", "error", err)
        }
        return base64.URLEncoding.EncodeToString(b)
}

func RequestContext() gin.HandlerFunc {
        return func(c *gin.Context) {
                nonce := generateNonce()
                traceID := uuid.New().String()[:8]
                start := time.Now()

                c.Set(ginKeyCSPNonce, nonce)
                c.Set(ginKeyTraceID, traceID)
                c.Set(ginKeyRequestStart, start)

                ctx := context.WithValue(c.Request.Context(), CSPNonceKey, nonce)
                ctx = context.WithValue(ctx, TraceIDKey, traceID)
                c.Request = c.Request.WithContext(ctx)

                c.Next()

                duration := time.Since(start)
                slog.Info("Request completed",
                        ginKeyTraceID, traceID,
                        "method", c.Request.Method,
                        "path", c.Request.URL.Path,
                        "status", c.Writer.Status(),
                        "duration_ms", fmt.Sprintf("%.1f", float64(duration.Microseconds())/1000.0),
                )
        }
}

func SecurityHeaders(isDev ...bool) gin.HandlerFunc {
        devMode := len(isDev) > 0 && isDev[0]
        return func(c *gin.Context) {
                if strings.HasPrefix(c.Request.URL.Path, "/static/") {
                        c.Header("X-Content-Type-Options", "nosniff")
                        c.Header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; object-src 'none'; base-uri 'none'")
                        c.Next()
                        return
                }

                nonceStr := extractNonceStr(c)
                setCommonSecurityHeaders(c, devMode)
                c.Header("Content-Security-Policy", buildCSP(c, nonceStr, devMode))
                c.Next()
        }
}

func extractNonceStr(c *gin.Context) string {
        nonce, exists := c.Get(ginKeyCSPNonce)
        if !exists {
                return ""
        }
        if s, ok := nonce.(string); ok {
                return s
        }
        return ""
}

func setCommonSecurityHeaders(c *gin.Context, devMode bool) {
        c.Header("X-Content-Type-Options", "nosniff")
        if !devMode {
                if c.Request.URL.Path == "/signature" || strings.HasPrefix(c.Request.URL.Path, "/docs/") {
                        c.Header("X-Frame-Options", "SAMEORIGIN")
                } else {
                        c.Header("X-Frame-Options", "DENY")
                }
        }
        c.Header("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
        c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
        c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=(), usb=(), accelerometer=(), gyroscope=(), magnetometer=(), midi=(), screen-wake-lock=(), xr-spatial-tracking=(), interest-cohort=(), browsing-topics=()")
        if devMode {
                c.Header("Cross-Origin-Opener-Policy", "same-origin-allow-popups")
                c.Header("Cross-Origin-Resource-Policy", "cross-origin")
        } else {
                c.Header("Cross-Origin-Opener-Policy", "same-origin")
                c.Header("Cross-Origin-Resource-Policy", "same-origin")
        }
        c.Header("X-Permitted-Cross-Domain-Policies", "none")
}

func buildCSP(c *gin.Context, nonceStr string, devMode bool) string {
        replitWidget := replitWidgetCSP()

        connectSrc := "connect-src 'self'; "
        if devMode {
                connectSrc = "connect-src 'self' https://replit.com https://*.replit.com https://*.replit.dev; "
        } else if replitWidget {
                connectSrc = "connect-src 'self' https://replit.com https://*.replit.com; "
        }

        frameAncestors := "frame-ancestors 'none'; "
        if devMode {
                frameAncestors = "frame-ancestors https://replit.com https://*.replit.com https://*.replit.dev https://*.replit.app https://*.picard.replit.dev; "
        } else if strings.HasPrefix(c.Request.URL.Path, "/docs/") {
                frameAncestors = "frame-ancestors 'self'; "
        }

        frameSrc := "frame-src 'none'; "
        if c.Request.URL.Path == "/signature" || c.Request.URL.Path == "/corpus" {
                frameSrc = "frame-src 'self'; "
        } else if c.Request.URL.Path == "/video/forgotten-domain" {
                frameSrc = "frame-src https://www.youtube-nocookie.com; "
        } else if replitWidget {
                frameSrc = "frame-src https://replit.com https://*.replit.com; "
        }

        scriptSrc := fmt.Sprintf("script-src 'self' 'nonce-%s'; ", nonceStr)
        if replitWidget && !devMode {
                scriptSrc = fmt.Sprintf("script-src 'self' 'nonce-%s' https://replit.com https://*.replit.com; ", nonceStr)
        }

        upgradeDirective := ""
        if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
                upgradeDirective = "upgrade-insecure-requests;"
        }

        return fmt.Sprintf(
                "default-src 'none'; "+
                        "%s"+
                        "style-src 'self' 'nonce-%s'; "+
                        "font-src 'self'; "+
                        "img-src 'self' data: blob:; "+
                        "%s"+
                        "%s"+
                        "base-uri 'none'; "+
                        "form-action 'self'; "+
                        "manifest-src 'self'; "+
                        "object-src 'none'; "+
                        "%s"+
                        "media-src 'self'; "+
                        "worker-src 'self'; "+
                        "%s",
                scriptSrc, nonceStr, connectSrc, frameAncestors, frameSrc, upgradeDirective,
        )
}

func replitWidgetCSP() bool {
        return os.Getenv("REPLIT_DEPLOYMENT") != ""
}

func Recovery(appVersion string, opts ...map[string]any) gin.HandlerFunc {
        var extraData map[string]any
        if len(opts) > 0 {
                extraData = opts[0]
        }
        return func(c *gin.Context) {
                defer func() {
                        if err := recover(); err != nil {
                                traceID, _ := c.Get(ginKeyTraceID) //nolint:errcheck // value used for logging only
                                slog.Error("Panic recovered",
                                        ginKeyTraceID, traceID,
                                        "error", fmt.Sprintf("%v", err),
                                        "path", c.Request.URL.Path,
                                )
                                nonce, _ := c.Get(ginKeyCSPNonce)      //nolint:errcheck // value used for template rendering
                                csrfToken, _ := c.Get(ginKeyCSRFToken) //nolint:errcheck // value used for template rendering
                                type flashMsg struct {
                                        Category string
                                        Message  string
                                }
                                data := gin.H{
                                        "AppVersion":    appVersion,
                                        "CspNonce":      nonce,
                                        "CsrfToken":     csrfToken,
                                        "ActivePage":    "home",
                                        "FlashMessages": []flashMsg{{Category: "danger", Message: "An internal error occurred. Please try again."}},
                                }
                                for k, v := range extraData {
                                        data[k] = v
                                }
                                c.HTML(http.StatusInternalServerError, "index.html", data)
                                c.Abort()
                        }
                }()
                c.Next()
        }
}

func CanonicalHostRedirect(canonicalURL string) gin.HandlerFunc {
        parsed, err := url.Parse(canonicalURL)
        if err != nil || parsed.Host == "" {
                slog.Warn("CanonicalHostRedirect: invalid canonical URL, middleware disabled", "url", canonicalURL)
                return func(c *gin.Context) { c.Next() }
        }
        canonicalHost := parsed.Host
        canonicalScheme := parsed.Scheme
        if canonicalScheme == "" {
                canonicalScheme = "https"
        }

        return func(c *gin.Context) {
                host := c.Request.Host
                if idx := strings.LastIndex(host, ":"); idx > 0 {
                        host = host[:idx]
                }

                if host == canonicalHost {
                        c.Next()
                        return
                }

                if strings.HasSuffix(host, ".replit.app") || strings.HasSuffix(host, ".replit.dev") {
                        target := canonicalScheme + "://" + canonicalHost + c.Request.URL.RequestURI()
                        c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
                        c.Redirect(http.StatusFound, target)
                        c.Abort()
                        return
                }

                c.Next()
        }
}
