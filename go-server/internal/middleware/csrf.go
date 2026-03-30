// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny plumbing
package middleware

import (
        "crypto/hmac"
        "crypto/rand"
        "crypto/sha256"
        "encoding/base64"
        "fmt"
        "log/slog"
        "net/http"
        "net/url"
        "strings"

        "dnstool/go-server/internal/logging"

        "github.com/gin-gonic/gin"
)

const (
        csrfCookieName = "_csrf"
        csrfFormField  = "csrf_token"
        csrfHeaderName = "X-CSRF-Token"
        csrfTokenLen   = 32
        csrfMaxAge     = 3600
)

type CSRFMiddleware struct {
        secret []byte
}

func NewCSRFMiddleware(secret string) *CSRFMiddleware {
        return &CSRFMiddleware{
                secret: []byte(secret),
        }
}

func (m *CSRFMiddleware) generateToken() string {
        b := make([]byte, csrfTokenLen)
        if _, err := rand.Read(b); err != nil {
                slog.Error("rand.Read failed", "error", err)
        }
        return base64.URLEncoding.EncodeToString(b)
}

func (m *CSRFMiddleware) sign(token string) string {
        mac := hmac.New(sha256.New, m.secret)
        mac.Write([]byte(token))
        return base64.URLEncoding.EncodeToString(mac.Sum(nil))
}

func (m *CSRFMiddleware) makeSignedToken(token string) string {
        return token + "." + m.sign(token)
}

func (m *CSRFMiddleware) validateSignedToken(signed string) (string, bool) {
        for i := len(signed) - 1; i >= 0; i-- {
                if signed[i] == '.' {
                        token := signed[:i]
                        sig := signed[i+1:]
                        expectedSig := m.sign(token)
                        if hmac.Equal([]byte(sig), []byte(expectedSig)) {
                                return token, true
                        }
                        return "", false
                }
        }
        return "", false
}

func isCSRFExempt(path string) bool {
        return strings.HasPrefix(path, "/api/") ||
                path == "/go/health" ||
                path == "/robots.txt" ||
                path == "/sitemap.xml" ||
                path == "/manifest.json" ||
                path == "/sw.js"
}

func (m *CSRFMiddleware) Handler() gin.HandlerFunc {
        return func(c *gin.Context) {
                if c.Request.Method == "GET" || c.Request.Method == "HEAD" || c.Request.Method == "OPTIONS" {
                        token := m.ensureToken(c)
                        c.Set(csrfFormField, token)
                        c.Next()
                        return
                }

                if isCSRFExempt(c.Request.URL.Path) {
                        c.Next()
                        return
                }

                cookie, err := c.Cookie(csrfCookieName)
                if err != nil || cookie == "" {
                        m.rejectCSRF(c, "missing CSRF cookie")
                        return
                }

                token, valid := m.validateSignedToken(cookie)
                if !valid {
                        m.rejectCSRF(c, "invalid CSRF cookie signature")
                        return
                }

                submitted := c.PostForm(csrfFormField)
                if submitted == "" {
                        submitted = c.GetHeader(csrfHeaderName)
                }

                if submitted == "" || submitted != token {
                        m.rejectCSRF(c, "CSRF token mismatch")
                        return
                }

                c.Set(csrfFormField, token)
                c.Next()
        }
}

func (m *CSRFMiddleware) ensureToken(c *gin.Context) string {
        cookie, err := c.Cookie(csrfCookieName)
        if err == nil && cookie != "" {
                if token, valid := m.validateSignedToken(cookie); valid {
                        return token
                }
        }

        token := m.generateToken()
        signedToken := m.makeSignedToken(token)

        http.SetCookie(c.Writer, &http.Cookie{
                Name:     csrfCookieName,
                Value:    signedToken,
                Path:     "/",
                MaxAge:   csrfMaxAge,
                HttpOnly: true,
                Secure:   true,
                SameSite: http.SameSiteStrictMode,
        })

        return token
}

func (m *CSRFMiddleware) rejectCSRF(c *gin.Context, reason string) {
        traceID, _ := c.Get(ginKeyTraceID) //nolint:errcheck // value used for logging only
        tid := fmt.Sprintf("%v", traceID)
        slog.LogAttrs(c.Request.Context(), slog.LevelWarn, "CSRF validation failed",
                append(logging.SecurityEvent(logging.EventCSRFReject, tid, c.ClientIP()),
                        slog.String("reason", reason),
                        slog.String("method", c.Request.Method),
                        slog.String("path", c.Request.URL.Path),
                )...,
        )

        domain := c.PostForm("domain")
        if domain == "" {
                domain = c.Query("domain")
        }
        if domain != "" {
                c.Redirect(http.StatusSeeOther, "/?domain="+url.QueryEscape(domain)+"&flash=Session+expired.+Please+try+again.")
        } else {
                c.Redirect(http.StatusSeeOther, "/?flash=Session+expired.+Please+try+again.")
        }
        c.Abort()
}

func GetCSRFToken(c *gin.Context) string {
        token, exists := c.Get(csrfFormField)
        if !exists {
                return ""
        }
        return fmt.Sprintf("%v", token)
}

func CSRFHiddenInput(c *gin.Context) string {
        token := GetCSRFToken(c)
        return fmt.Sprintf(`<input type="hidden" name="%s" value="%s">`, csrfFormField, token)
}
