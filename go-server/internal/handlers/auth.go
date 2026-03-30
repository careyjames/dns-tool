// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.

// dns-tool:scrutiny design
package handlers

import (
        "context"
        "crypto/rand"
        "crypto/sha256"
        "encoding/base64"
        "encoding/hex"
        "encoding/json"
        "fmt"
        "io"
        "log/slog"
        "net/http"
        "net/url"
        "strings"
        "time"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/dbq"

        "github.com/gin-gonic/gin"
        "github.com/jackc/pgx/v5/pgtype"
        "github.com/jackc/pgx/v5/pgxpool"
)

const (
        googleAuthURL     = "https://accounts.google.com/o/oauth2/v2/auth"
        googleTokenURL    = "https://oauth2.googleapis.com/token"
        googleUserInfoURL = "https://www.googleapis.com/oauth2/v3/userinfo"
        oauthStateCookie  = "_oauth_state"
        oauthCVCookie     = "_oauth_cv"
        oauthNonceCookie  = "_oauth_nonce"
        sessionCookieName = "_dns_session"
        sessionMaxAge     = 30 * 24 * 60 * 60
        oauthHTTPTimeout  = 10 * time.Second
        iatMaxSkew        = 5 * time.Minute

        mapKeyEmail = "email"
)

type AuthHandler struct {
        Config    *config.Config
        Pool      *pgxpool.Pool
        Queries   *dbq.Queries
        authStore AuthStore
}

func (h *AuthHandler) store() AuthStore {
        if h.authStore != nil {
                return h.authStore
        }
        if h.Queries != nil {
                return h.Queries
        }
        return nil
}

func NewAuthHandler(cfg *config.Config, pool *pgxpool.Pool) *AuthHandler {
        return &AuthHandler{
                Config:  cfg,
                Pool:    pool,
                Queries: dbq.New(pool),
        }
}

func generateRandomBase64URL(n int) (string, error) {
        b := make([]byte, n)
        if _, err := rand.Read(b); err != nil {
                return "", err
        }
        return base64.RawURLEncoding.EncodeToString(b), nil
}

func generateSessionID() (string, error) {
        b := make([]byte, 32)
        if _, err := rand.Read(b); err != nil {
                return "", err
        }
        return hex.EncodeToString(b), nil
}

func computeCodeChallenge(verifier string) string {
        h := sha256.Sum256([]byte(verifier))
        return base64.RawURLEncoding.EncodeToString(h[:])
}

func (h *AuthHandler) Login(c *gin.Context) {
        state, err := generateRandomBase64URL(32)
        if err != nil {
                slog.Error("Failed to generate OAuth state", mapKeyError, err)
                c.Redirect(http.StatusFound, "/")
                return
        }

        codeVerifier, err := generateRandomBase64URL(48)
        if err != nil {
                slog.Error("Failed to generate PKCE code verifier", mapKeyError, err)
                c.Redirect(http.StatusFound, "/")
                return
        }

        nonce, err := generateRandomBase64URL(32)
        if err != nil {
                slog.Error("Failed to generate OIDC nonce", mapKeyError, err)
                c.Redirect(http.StatusFound, "/")
                return
        }

        codeChallenge := computeCodeChallenge(codeVerifier)

        c.SetSameSite(http.SameSiteLaxMode)
        c.SetCookie(oauthStateCookie, state, 600, "/", "", true, true)
        c.SetCookie(oauthCVCookie, codeVerifier, 600, "/", "", true, true)
        c.SetCookie(oauthNonceCookie, nonce, 600, "/", "", true, true)

        params := url.Values{
                "client_id":             {h.Config.GoogleClientID},
                "redirect_uri":          {h.Config.GoogleRedirectURL},
                "response_type":         {"code"},
                "scope":                 {"openid email profile"},
                "state":                 {state},
                "code_challenge":        {codeChallenge},
                "code_challenge_method": {"S256"},
                "access_type":           {"online"},
                "prompt":                {"select_account"},
                "nonce":                 {nonce},
        }

        authURL := googleAuthURL + "?" + params.Encode()
        c.Redirect(http.StatusFound, authURL)
}

func (h *AuthHandler) Callback(c *gin.Context) {
        _, codeVerifier, nonceCookie, code, ok := extractOAuthCallbackParams(c)
        if !ok {
                c.Redirect(http.StatusFound, "/")
                return
        }

        tokenData, err := h.exchangeCode(code, codeVerifier)
        if err != nil {
                slog.Error("OAuth callback: token exchange failed", mapKeyError, err)
                c.Redirect(http.StatusFound, "/")
                return
        }
        if err := h.validateIDTokenClaims(tokenData, nonceCookie); err != nil {
                slog.Error("OAuth callback: ID token validation failed", mapKeyError, err)
                c.Redirect(http.StatusFound, "/")
                return
        }

        accessToken, ok := tokenData["access_token"].(string)
        if !ok || accessToken == "" {
                slog.Error("OAuth callback: no access_token in response")
                c.Redirect(http.StatusFound, "/")
                return
        }

        userInfo, err := h.fetchUserInfo(accessToken)
        if err != nil {
                slog.Error("OAuth callback: failed to fetch user info", mapKeyError, err)
                c.Redirect(http.StatusFound, "/")
                return
        }

        sub, email, name, emailVerified := extractUserClaims(userInfo)
        if sub == "" || email == "" || !emailVerified {
                slog.Error("OAuth callback: missing sub/email or email not verified",
                        "sub_present", sub != "",
                        "email_present", email != "",
                        "email_verified", emailVerified,
                )
                c.Redirect(http.StatusFound, "/")
                return
        }

        ctx := c.Request.Context()

        role, shouldBootstrapAdmin := h.determineRole(ctx, email)

        user, err := h.store().UpsertUser(ctx, dbq.UpsertUserParams{
                Email:     email,
                Name:      name,
                GoogleSub: sub,
                Role:      role,
        })
        if err != nil {
                slog.Error("OAuth callback: failed to upsert user", mapKeyError, err, mapKeyEmail, email)
                c.Redirect(http.StatusFound, "/")
                return
        }

        user.Role = h.bootstrapAdminIfNeeded(ctx, user.ID, user.Role, shouldBootstrapAdmin, email)

        sessionID, err := h.createUserSession(ctx, user.ID)
        if err != nil {
                c.Redirect(http.StatusFound, "/")
                return
        }

        h.finalizeLogin(c, sessionID, user, name, email)
}

func (h *AuthHandler) bootstrapAdminIfNeeded(ctx context.Context, userID int32, currentRole string, shouldBootstrap bool, email string) string {
        if !shouldBootstrap || currentRole == mapKeyAdmin {
                return currentRole
        }
        if err := h.store().PromoteUserToAdmin(ctx, userID); err != nil {
                slog.Error("OAuth callback: failed to promote user to admin", mapKeyError, err, mapKeyUserId, userID)
                return currentRole
        }
        slog.Warn("AUDIT: Existing user promoted to admin via bootstrap",
                mapKeyEmail, email,
                mapKeyUserId, userID,
        )
        return mapKeyAdmin
}

func (h *AuthHandler) finalizeLogin(c *gin.Context, sessionID string, user dbq.User, name, email string) {
        c.SetSameSite(http.SameSiteLaxMode)
        c.SetCookie(sessionCookieName, sessionID, sessionMaxAge, "/", "", true, true)
        c.SetCookie(oauthStateCookie, "", -1, "/", "", true, true)
        c.SetCookie(oauthCVCookie, "", -1, "/", "", true, true)
        c.SetCookie(oauthNonceCookie, "", -1, "/", "", true, true)

        slog.Info("User authenticated", mapKeyEmail, email, "role", user.Role, mapKeyUserId, user.ID)

        if user.Role == mapKeyAdmin {
                go h.seedAdminWatchlist(context.Background(), user.ID)
        }

        firstLogin := user.CreatedAt.Valid && user.LastLoginAt.Valid &&
                user.LastLoginAt.Time.Sub(user.CreatedAt.Time).Abs() < 5*time.Second
        if firstLogin {
                c.Redirect(http.StatusFound, "/?welcome="+url.QueryEscape(name))
        } else {
                c.Redirect(http.StatusFound, "/")
        }
}

func extractOAuthCallbackParams(c *gin.Context) (string, string, string, string, bool) {
        stateCookie, err := c.Cookie(oauthStateCookie)
        if err != nil || stateCookie == "" {
                slog.Warn("OAuth callback: missing state cookie")
                return "", "", "", "", false
        }

        stateParam := c.Query("state")
        if stateParam == "" || stateParam != stateCookie {
                slog.Warn("OAuth callback: state mismatch")
                return "", "", "", "", false
        }

        codeVerifier, err := c.Cookie(oauthCVCookie)
        if err != nil || codeVerifier == "" {
                slog.Warn("OAuth callback: missing code verifier cookie")
                return "", "", "", "", false
        }

        nonceCookie, err := c.Cookie(oauthNonceCookie)
        if err != nil || nonceCookie == "" {
                slog.Warn("OAuth callback: missing nonce cookie")
                return "", "", "", "", false
        }

        code := c.Query("code")
        if code == "" {
                slog.Warn("OAuth callback: missing authorization code")
                return "", "", "", "", false
        }

        return stateCookie, codeVerifier, nonceCookie, code, true
}

func extractUserClaims(userInfo map[string]any) (string, string, string, bool) {
        sub, ok := userInfo["sub"].(string)
        if !ok {
                sub = ""
        }
        email, ok := userInfo[mapKeyEmail].(string)
        if !ok {
                email = ""
        }
        name, ok := userInfo["name"].(string)
        if !ok {
                name = ""
        }
        emailVerified, ok := userInfo["email_verified"].(bool)
        if !ok {
                emailVerified = false
        }
        return sub, email, name, emailVerified
}

func (h *AuthHandler) determineRole(ctx context.Context, email string) (string, bool) {
        role := "user"
        shouldBootstrapAdmin := false
        if h.Config.InitialAdminEmail != "" {
                slog.Debug("Admin bootstrap check",
                        "login_email", email,
                        "initial_admin_email", h.Config.InitialAdminEmail,
                        "match", strings.EqualFold(email, h.Config.InitialAdminEmail),
                )
        }
        if h.Config.InitialAdminEmail != "" && strings.EqualFold(email, h.Config.InitialAdminEmail) {
                adminCount, countErr := h.store().CountAdminUsers(ctx)
                if countErr != nil {
                        slog.Error("Failed to count admin users", mapKeyError, countErr)
                } else if adminCount == 0 {
                        role = mapKeyAdmin
                        shouldBootstrapAdmin = true
                        slog.Warn("AUDIT: Admin bootstrap triggered",
                                mapKeyEmail, email,
                                "reason", "zero_admin_users",
                                "initial_admin_email", h.Config.InitialAdminEmail,
                        )
                }
        }
        return role, shouldBootstrapAdmin
}

func (h *AuthHandler) createUserSession(ctx context.Context, userID int32) (string, error) {
        sessionID, err := generateSessionID()
        if err != nil {
                slog.Error("OAuth callback: failed to generate session ID", mapKeyError, err)
                return "", err
        }

        expiresAt := time.Now().Add(30 * 24 * time.Hour)
        err = h.store().CreateSession(ctx, dbq.CreateSessionParams{
                ID:     sessionID,
                UserID: userID,
                ExpiresAt: pgtype.Timestamp{
                        Time:  expiresAt,
                        Valid: true,
                },
        })
        if err != nil {
                slog.Error("OAuth callback: failed to create session", mapKeyError, err)
                return "", err
        }
        return sessionID, nil
}

func (h *AuthHandler) Logout(c *gin.Context) {
        cookie, err := c.Cookie(sessionCookieName)
        if err == nil && cookie != "" {
                if delErr := h.store().DeleteSession(c.Request.Context(), cookie); delErr != nil {
                        slog.Warn("Logout: failed to delete session (cookie will still be cleared)", mapKeyError, delErr)
                }
        }

        c.SetSameSite(http.SameSiteLaxMode)
        c.SetCookie(sessionCookieName, "", -1, "/", "", true, true)
        c.Redirect(http.StatusFound, "/")
}

func (h *AuthHandler) validateIDTokenClaims(tokenData map[string]any, expectedNonce string) error {
        idTokenStr, ok := tokenData["id_token"].(string)
        if !ok || idTokenStr == "" {
                return nil
        }

        claims, err := parseIDTokenPayload(idTokenStr)
        if err != nil {
                return err
        }

        if err := validateIDTokenIssuerAndAudience(claims, h.Config.GoogleClientID); err != nil {
                return err
        }

        if err := validateIDTokenTiming(claims); err != nil {
                return err
        }

        return validateIDTokenNonce(claims, expectedNonce)
}

func parseIDTokenPayload(idTokenStr string) (map[string]any, error) {
        parts := strings.SplitN(idTokenStr, ".", 3)
        if len(parts) != 3 {
                return nil, fmt.Errorf("malformed id_token: expected 3 parts, got %d", len(parts))
        }
        payload, err := base64.RawURLEncoding.DecodeString(parts[1])
        if err != nil {
                return nil, fmt.Errorf("decoding id_token payload: %w", err)
        }
        var claims map[string]any
        if err := json.Unmarshal(payload, &claims); err != nil {
                return nil, fmt.Errorf("parsing id_token claims: %w", err)
        }
        return claims, nil
}

func validateIDTokenIssuerAndAudience(claims map[string]any, expectedClientID string) error {
        iss, ok := claims["iss"].(string)
        if !ok {
                iss = ""
        }
        if iss != "https://accounts.google.com" && iss != "accounts.google.com" {
                return fmt.Errorf("invalid issuer: %s", iss)
        }
        aud, ok := claims["aud"].(string)
        if !ok {
                aud = ""
        }
        if aud != expectedClientID {
                return fmt.Errorf("invalid audience: %s", aud)
        }
        return nil
}

func validateIDTokenTiming(claims map[string]any) error {
        now := time.Now()
        exp, ok := claims["exp"].(float64)
        if !ok {
                exp = 0
        }
        if exp > 0 && now.Unix() > int64(exp) {
                return fmt.Errorf("id_token expired at %v", time.Unix(int64(exp), 0))
        }
        if iat, ok := claims["iat"].(float64); ok && iat > 0 {
                issuedAt := time.Unix(int64(iat), 0)
                if now.Before(issuedAt.Add(-iatMaxSkew)) {
                        return fmt.Errorf("id_token issued in the future: iat=%v", issuedAt)
                }
        }
        return nil
}

func validateIDTokenNonce(claims map[string]any, expectedNonce string) error {
        if expectedNonce == "" {
                return nil
        }
        tokenNonce, ok := claims["nonce"].(string)
        if !ok {
                tokenNonce = ""
        }
        if tokenNonce == "" {
                return fmt.Errorf("id_token missing nonce claim")
        }
        if tokenNonce != expectedNonce {
                return fmt.Errorf("id_token nonce mismatch")
        }
        return nil
}

var oauthHTTPClient = &http.Client{
        Timeout: oauthHTTPTimeout,
}

func (h *AuthHandler) exchangeCode(code, codeVerifier string) (map[string]any, error) {
        data := url.Values{
                "code":          {code},
                "client_id":     {h.Config.GoogleClientID},
                "client_secret": {h.Config.GoogleClientSecret},
                "redirect_uri":  {h.Config.GoogleRedirectURL},
                "grant_type":    {"authorization_code"},
                "code_verifier": {codeVerifier},
        }

        resp, err := oauthHTTPClient.PostForm(googleTokenURL, data)
        if err != nil {
                return nil, fmt.Errorf("token request failed: %w", err)
        }
        defer safeClose(resp.Body, "token response body")

        body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
        if err != nil {
                return nil, fmt.Errorf("reading token response: %w", err)
        }

        if resp.StatusCode != http.StatusOK {
                return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
        }

        var result map[string]any
        if err := json.Unmarshal(body, &result); err != nil {
                return nil, fmt.Errorf("parsing token response: %w", err)
        }

        return result, nil
}

func (h *AuthHandler) fetchUserInfo(accessToken string) (map[string]any, error) {
        req, err := http.NewRequest("GET", googleUserInfoURL, nil)
        if err != nil {
                return nil, fmt.Errorf("creating userinfo request: %w", err)
        }
        req.Header.Set("Authorization", "Bearer "+accessToken)

        resp, err := oauthHTTPClient.Do(req)
        if err != nil {
                return nil, fmt.Errorf("userinfo request failed: %w", err)
        }
        defer safeClose(resp.Body, "userinfo response body")

        body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
        if err != nil {
                return nil, fmt.Errorf("reading userinfo response: %w", err)
        }

        if resp.StatusCode != http.StatusOK {
                return nil, fmt.Errorf("userinfo endpoint returned %d: %s", resp.StatusCode, string(body))
        }

        var result map[string]any
        if err := json.Unmarshal(body, &result); err != nil {
                return nil, fmt.Errorf("parsing userinfo response: %w", err)
        }

        return result, nil
}

func missionCriticalDomainsFromBaseURL(baseURL string) []string {
        host := baseURL
        if idx := strings.Index(host, "://"); idx >= 0 {
                host = host[idx+3:]
        }
        host = strings.TrimRight(host, "/")
        host = strings.SplitN(host, ":", 2)[0]

        domains := []string{host}
        parts := strings.SplitN(host, ".", 2)
        if len(parts) == 2 {
                root := parts[1]
                if strings.Contains(root, ".") && root != host {
                        domains = append([]string{root}, domains...)
                }
        }
        return domains
}

func (h *AuthHandler) seedAdminWatchlist(ctx context.Context, userID int32) {
        existing, err := h.store().ListWatchlistByUser(ctx, userID)
        if err != nil {
                slog.Error("Admin watchlist seed: failed to list existing entries", mapKeyError, err)
                return
        }
        domainSet := make(map[string]bool, len(existing))
        for _, e := range existing {
                domainSet[e.Domain] = true
        }
        for _, domain := range missionCriticalDomainsFromBaseURL(h.Config.BaseURL) {
                if domainSet[domain] {
                        continue
                }
                _, err := h.store().InsertWatchlistEntry(ctx, dbq.InsertWatchlistEntryParams{
                        UserID:    userID,
                        Domain:    domain,
                        Cadence:   "daily",
                        NextRunAt: pgtype.Timestamp{Time: time.Now().UTC().Add(24 * time.Hour), Valid: true},
                })
                if err != nil {
                        slog.Error("Admin watchlist seed: failed to insert domain", "domain", domain, mapKeyError, err)
                } else {
                        slog.Info("Admin watchlist seed: added mission-critical domain", "domain", domain, mapKeyUserId, userID)
                }
        }

        h.seedDiscordEndpoint(ctx, userID)
}

func (h *AuthHandler) seedDiscordEndpoint(ctx context.Context, userID int32) {
        if h.Config.DiscordWebhookURL == "" {
                return
        }
        endpoints, err := h.store().ListNotificationEndpointsByUser(ctx, userID)
        if err != nil {
                slog.Error("Admin watchlist seed: failed to list endpoints", mapKeyError, err)
                return
        }
        for _, ep := range endpoints {
                if ep.Url == h.Config.DiscordWebhookURL {
                        return
                }
        }
        _, err = h.store().InsertNotificationEndpoint(ctx, dbq.InsertNotificationEndpointParams{
                UserID:       userID,
                EndpointType: "discord",
                Url:          h.Config.DiscordWebhookURL,
                Secret:       nil,
        })
        if err != nil {
                slog.Error("Admin watchlist seed: failed to insert Discord endpoint", mapKeyError, err)
        } else {
                slog.Info("Admin watchlist seed: added Discord webhook endpoint", mapKeyUserId, userID)
        }
}
