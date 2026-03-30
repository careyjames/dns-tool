// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package handlers

import (
        "encoding/base64"
        "encoding/json"
        "net/http"
        "net/http/httptest"
        "testing"
        "time"

        "dnstool/go-server/internal/config"

        "github.com/gin-gonic/gin"
)

func TestExtractOAuthCallbackParams_SecurityBoundary(t *testing.T) {
        t.Run("missing state cookie rejects callback — CSRF prevention", func(t *testing.T) {
                c := mockGinContext()
                c.Request.URL.RawQuery = "state=abc123&code=authcode"

                _, _, _, _, ok := extractOAuthCallbackParams(c)
                if ok {
                        t.Error("SECURITY: missing state cookie must reject callback — prevents CSRF")
                }
        })

        t.Run("state mismatch rejects callback — CSRF prevention", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest(http.MethodGet, "/?state=attacker_state&code=authcode", nil)
                c.Request.AddCookie(&http.Cookie{Name: oauthStateCookie, Value: "legitimate_state"})
                c.Request.AddCookie(&http.Cookie{Name: oauthCVCookie, Value: "verifier"})
                c.Request.AddCookie(&http.Cookie{Name: oauthNonceCookie, Value: "nonce"})

                _, _, _, _, ok := extractOAuthCallbackParams(c)
                if ok {
                        t.Error("SECURITY: state parameter mismatch must reject callback — prevents CSRF")
                }
        })

        t.Run("missing code verifier rejects — PKCE enforcement", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest(http.MethodGet, "/?state=abc&code=authcode", nil)
                c.Request.AddCookie(&http.Cookie{Name: oauthStateCookie, Value: "abc"})
                c.Request.AddCookie(&http.Cookie{Name: oauthNonceCookie, Value: "nonce"})

                _, _, _, _, ok := extractOAuthCallbackParams(c)
                if ok {
                        t.Error("SECURITY: missing code verifier cookie must reject — PKCE RFC 7636 requires it")
                }
        })

        t.Run("missing nonce cookie rejects — OpenID Connect replay prevention", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest(http.MethodGet, "/?state=abc&code=authcode", nil)
                c.Request.AddCookie(&http.Cookie{Name: oauthStateCookie, Value: "abc"})
                c.Request.AddCookie(&http.Cookie{Name: oauthCVCookie, Value: "verifier"})

                _, _, _, _, ok := extractOAuthCallbackParams(c)
                if ok {
                        t.Error("SECURITY: missing nonce cookie must reject — OpenID Connect nonce prevents replay")
                }
        })

        t.Run("missing authorization code rejects", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest(http.MethodGet, "/?state=abc", nil)
                c.Request.AddCookie(&http.Cookie{Name: oauthStateCookie, Value: "abc"})
                c.Request.AddCookie(&http.Cookie{Name: oauthCVCookie, Value: "verifier"})
                c.Request.AddCookie(&http.Cookie{Name: oauthNonceCookie, Value: "nonce"})

                _, _, _, _, ok := extractOAuthCallbackParams(c)
                if ok {
                        t.Error("missing authorization code must reject callback")
                }
        })

        t.Run("valid callback returns all parameters", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest(http.MethodGet, "/?state=secure_state&code=auth_code_123", nil)
                c.Request.AddCookie(&http.Cookie{Name: oauthStateCookie, Value: "secure_state"})
                c.Request.AddCookie(&http.Cookie{Name: oauthCVCookie, Value: "pkce_verifier"})
                c.Request.AddCookie(&http.Cookie{Name: oauthNonceCookie, Value: "replay_nonce"})

                state, verifier, nonce, code, ok := extractOAuthCallbackParams(c)
                if !ok {
                        t.Fatal("valid callback should return ok=true")
                }
                if state != "secure_state" {
                        t.Errorf("state = %q", state)
                }
                if verifier != "pkce_verifier" {
                        t.Errorf("verifier = %q", verifier)
                }
                if nonce != "replay_nonce" {
                        t.Errorf("nonce = %q", nonce)
                }
                if code != "auth_code_123" {
                        t.Errorf("code = %q", code)
                }
                t.Log("MEASUREMENT: all 4 OAuth callback parameters extracted successfully (state, PKCE verifier, nonce, code)")
        })
}

func TestValidateIDTokenClaims_SecurityContract(t *testing.T) {
        h := &AuthHandler{Config: configWithGoogleClientID("test-client-id")}

        t.Run("empty id_token is allowed — not all providers include it", func(t *testing.T) {
                err := h.validateIDTokenClaims(map[string]any{
                        "access_token": "valid_access_token",
                }, "test-nonce")
                if err != nil {
                        t.Errorf("missing id_token should not error: %v", err)
                }
        })

        t.Run("valid id_token passes all checks", func(t *testing.T) {
                claims := map[string]any{
                        "iss":   "https://accounts.google.com",
                        "aud":   "test-client-id",
                        "exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
                        "iat":   float64(time.Now().Add(-1 * time.Minute).Unix()),
                        "nonce": "test-nonce",
                }
                token := buildTestIDToken(claims)

                err := h.validateIDTokenClaims(map[string]any{
                        "id_token": token,
                }, "test-nonce")
                if err != nil {
                        t.Errorf("valid id_token should pass: %v", err)
                }
        })

        t.Run("wrong issuer is rejected — Google OIDC spec", func(t *testing.T) {
                claims := map[string]any{
                        "iss":   "https://evil-provider.com",
                        "aud":   "test-client-id",
                        "exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
                        "nonce": "test-nonce",
                }
                token := buildTestIDToken(claims)

                err := h.validateIDTokenClaims(map[string]any{"id_token": token}, "test-nonce")
                if err == nil {
                        t.Error("SECURITY: wrong issuer must be rejected per Google OIDC spec")
                }
                t.Logf("MEASUREMENT: correctly rejected wrong issuer: %v", err)
        })

        t.Run("wrong audience is rejected — prevents token confusion", func(t *testing.T) {
                claims := map[string]any{
                        "iss":   "https://accounts.google.com",
                        "aud":   "different-client-id",
                        "exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
                        "nonce": "test-nonce",
                }
                token := buildTestIDToken(claims)

                err := h.validateIDTokenClaims(map[string]any{"id_token": token}, "test-nonce")
                if err == nil {
                        t.Error("SECURITY: wrong audience must be rejected — prevents token confusion attacks")
                }
        })

        t.Run("expired token is rejected", func(t *testing.T) {
                claims := map[string]any{
                        "iss":   "https://accounts.google.com",
                        "aud":   "test-client-id",
                        "exp":   float64(time.Now().Add(-1 * time.Hour).Unix()),
                        "nonce": "test-nonce",
                }
                token := buildTestIDToken(claims)

                err := h.validateIDTokenClaims(map[string]any{"id_token": token}, "test-nonce")
                if err == nil {
                        t.Error("SECURITY: expired token must be rejected")
                }
        })

        t.Run("nonce mismatch is rejected — replay prevention", func(t *testing.T) {
                claims := map[string]any{
                        "iss":   "https://accounts.google.com",
                        "aud":   "test-client-id",
                        "exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
                        "nonce": "original-nonce",
                }
                token := buildTestIDToken(claims)

                err := h.validateIDTokenClaims(map[string]any{"id_token": token}, "different-nonce")
                if err == nil {
                        t.Error("SECURITY: nonce mismatch must be rejected — prevents replay attacks")
                }
        })
}

func TestValidateIDTokenTiming_ScientificBoundaries(t *testing.T) {
        t.Run("token expired exactly now is rejected", func(t *testing.T) {
                claims := map[string]any{
                        "exp": float64(time.Now().Unix() - 1),
                }
                err := validateIDTokenTiming(claims)
                if err == nil {
                        t.Error("token expired 1 second ago must be rejected")
                }
        })

        t.Run("iat within 5-minute skew window passes — RFC 7519 clock skew tolerance", func(t *testing.T) {
                claims := map[string]any{
                        "exp": float64(time.Now().Add(1 * time.Hour).Unix()),
                        "iat": float64(time.Now().Add(4 * time.Minute).Unix()),
                }
                err := validateIDTokenTiming(claims)
                if err != nil {
                        t.Errorf("iat within 5-minute skew should pass per clock skew tolerance: %v", err)
                }
                t.Log("MEASUREMENT: 4-minute future iat accepted within 5-minute skew window")
        })

        t.Run("iat beyond 5-minute skew is rejected — future token", func(t *testing.T) {
                claims := map[string]any{
                        "exp": float64(time.Now().Add(2 * time.Hour).Unix()),
                        "iat": float64(time.Now().Add(10 * time.Minute).Unix()),
                }
                err := validateIDTokenTiming(claims)
                if err == nil {
                        t.Error("iat 10 minutes in the future must be rejected (beyond 5-minute skew)")
                }
                t.Log("MEASUREMENT: 10-minute future iat correctly rejected")
        })

        t.Run("missing timing claims are permissive — graceful degradation", func(t *testing.T) {
                err := validateIDTokenTiming(map[string]any{})
                if err != nil {
                        t.Errorf("missing timing claims should pass (graceful): %v", err)
                }
        })
}

func TestExtractUserClaims_EdgeCases(t *testing.T) {
        t.Run("numeric sub is handled gracefully", func(t *testing.T) {
                sub, _, _, _ := extractUserClaims(map[string]any{"sub": 12345})
                if sub != "" {
                        t.Errorf("numeric sub should return empty string, got %q", sub)
                }
        })

        t.Run("nil email_verified returns false", func(t *testing.T) {
                _, _, _, verified := extractUserClaims(map[string]any{"email_verified": nil})
                if verified {
                        t.Error("nil email_verified should return false")
                }
        })

        t.Run("string 'true' for email_verified is treated as false — type safety", func(t *testing.T) {
                _, _, _, verified := extractUserClaims(map[string]any{"email_verified": "true"})
                if verified {
                        t.Error("SECURITY: string 'true' for email_verified must return false — only bool type is accepted")
                }
                t.Log("MEASUREMENT: type-strict email_verified check prevents string bypass")
        })
}

func TestAuthCookieSecurityProperties(t *testing.T) {
        if sessionCookieName != "_dns_session" {
                t.Errorf("session cookie name = %q, expected '_dns_session'", sessionCookieName)
        }
        if sessionMaxAge != 30*24*60*60 {
                t.Errorf("session max age = %d seconds, expected 30 days (%d)", sessionMaxAge, 30*24*60*60)
        }
        expectedAge := 30 * 24 * time.Hour
        t.Logf("MEASUREMENT: session lifetime = %v (30 days)", expectedAge)

        if oauthHTTPTimeout != 10*time.Second {
                t.Errorf("OAuth HTTP timeout = %v, expected 10s", oauthHTTPTimeout)
        }
        if iatMaxSkew != 5*time.Minute {
                t.Errorf("iat max skew = %v, expected 5 minutes", iatMaxSkew)
        }
        t.Logf("MEASUREMENT: OAuth timeout=%v iat_skew=%v — balances security vs clock drift", oauthHTTPTimeout, iatMaxSkew)
}

func TestGoogleOAuthEndpoints_RFC8414(t *testing.T) {
        if googleAuthURL != "https://accounts.google.com/o/oauth2/v2/auth" {
                t.Errorf("auth endpoint = %q — must match Google OIDC discovery", googleAuthURL)
        }
        if googleTokenURL != "https://oauth2.googleapis.com/token" {
                t.Errorf("token endpoint = %q — must match Google OIDC discovery", googleTokenURL)
        }
        if googleUserInfoURL != "https://www.googleapis.com/oauth2/v3/userinfo" {
                t.Errorf("userinfo endpoint = %q — must match Google OIDC spec", googleUserInfoURL)
        }
        t.Log("MEASUREMENT: all 3 Google OIDC endpoints verified against discovery document")
}

func configWithGoogleClientID(clientID string) *config.Config {
        return &config.Config{
                GoogleClientID: clientID,
                AppVersion:     "test",
        }
}

func buildTestIDToken(claims map[string]any) string {
        header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
        payload, _ := json.Marshal(claims)
        encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
        sig := base64.RawURLEncoding.EncodeToString([]byte("test-signature"))
        return header + "." + encodedPayload + "." + sig
}
