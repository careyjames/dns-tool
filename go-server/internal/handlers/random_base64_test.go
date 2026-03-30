package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"dnstool/go-server/internal/config"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestGenerateRandomBase64URL_CB5(t *testing.T) {
	s, err := generateRandomBase64URL(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s) == 0 {
		t.Error("expected non-empty string")
	}
	s2, _ := generateRandomBase64URL(32)
	if s == s2 {
		t.Error("expected different random values")
	}
}

func TestGenerateSessionID_CB5(t *testing.T) {
	id, err := generateSessionID()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(id) != 64 {
		t.Errorf("expected 64 hex chars, got %d", len(id))
	}
}

func TestComputeCodeChallenge_CB5(t *testing.T) {
	challenge := computeCodeChallenge("test-verifier")
	if challenge == "" {
		t.Error("expected non-empty challenge")
	}
	challenge2 := computeCodeChallenge("test-verifier")
	if challenge != challenge2 {
		t.Error("same input should produce same challenge")
	}
	challenge3 := computeCodeChallenge("different-verifier")
	if challenge == challenge3 {
		t.Error("different inputs should produce different challenges")
	}
}

func TestExtractUserClaims_CB5(t *testing.T) {
	t.Run("valid claims", func(t *testing.T) {
		info := map[string]any{
			"sub":            "12345",
			"email":          "user@example.com",
			"name":           "Test User",
			"email_verified": true,
		}
		sub, email, name, verified := extractUserClaims(info)
		if sub != "12345" || email != "user@example.com" || name != "Test User" || !verified {
			t.Errorf("unexpected claims: sub=%q email=%q name=%q verified=%v", sub, email, name, verified)
		}
	})
	t.Run("missing claims", func(t *testing.T) {
		info := map[string]any{}
		sub, email, name, verified := extractUserClaims(info)
		if sub != "" || email != "" || name != "" || verified {
			t.Error("expected empty values for missing claims")
		}
	})
}

func TestParseIDTokenPayload_CB5(t *testing.T) {
	t.Run("valid token", func(t *testing.T) {
		claims := map[string]any{"iss": "https://accounts.google.com", "sub": "123"}
		payload, _ := json.Marshal(claims)
		encoded := base64.RawURLEncoding.EncodeToString(payload)
		token := fmt.Sprintf("header.%s.signature", encoded)
		result, err := parseIDTokenPayload(token)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result["iss"] != "https://accounts.google.com" {
			t.Errorf("unexpected issuer: %v", result["iss"])
		}
	})
	t.Run("malformed token", func(t *testing.T) {
		_, err := parseIDTokenPayload("not.a.valid.token.too.many.parts")
		if err == nil {
			t.Error("expected error for malformed token")
		}
	})
	t.Run("two parts only", func(t *testing.T) {
		_, err := parseIDTokenPayload("only.two")
		if err == nil {
			t.Error("expected error for two-part token")
		}
	})
	t.Run("invalid base64", func(t *testing.T) {
		_, err := parseIDTokenPayload("header.!!!invalid!!!.sig")
		if err == nil {
			t.Error("expected error for invalid base64")
		}
	})
	t.Run("invalid JSON", func(t *testing.T) {
		encoded := base64.RawURLEncoding.EncodeToString([]byte("not json"))
		token := fmt.Sprintf("header.%s.signature", encoded)
		_, err := parseIDTokenPayload(token)
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})
}

func TestValidateIDTokenIssuerAndAudience_CB5(t *testing.T) {
	t.Run("valid google issuer", func(t *testing.T) {
		claims := map[string]any{
			"iss": "https://accounts.google.com",
			"aud": "my-client-id",
		}
		err := validateIDTokenIssuerAndAudience(claims, "my-client-id")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
	t.Run("valid short issuer", func(t *testing.T) {
		claims := map[string]any{
			"iss": "accounts.google.com",
			"aud": "my-client-id",
		}
		err := validateIDTokenIssuerAndAudience(claims, "my-client-id")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
	t.Run("invalid issuer", func(t *testing.T) {
		claims := map[string]any{
			"iss": "https://evil.com",
			"aud": "my-client-id",
		}
		err := validateIDTokenIssuerAndAudience(claims, "my-client-id")
		if err == nil {
			t.Error("expected error for invalid issuer")
		}
	})
	t.Run("invalid audience", func(t *testing.T) {
		claims := map[string]any{
			"iss": "https://accounts.google.com",
			"aud": "wrong-client-id",
		}
		err := validateIDTokenIssuerAndAudience(claims, "my-client-id")
		if err == nil {
			t.Error("expected error for invalid audience")
		}
	})
}

func TestValidateIDTokenTiming_CB5(t *testing.T) {
	t.Run("valid timing", func(t *testing.T) {
		claims := map[string]any{
			"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
			"iat": float64(time.Now().Add(-1 * time.Minute).Unix()),
		}
		err := validateIDTokenTiming(claims)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
	t.Run("expired token", func(t *testing.T) {
		claims := map[string]any{
			"exp": float64(time.Now().Add(-1 * time.Hour).Unix()),
		}
		err := validateIDTokenTiming(claims)
		if err == nil {
			t.Error("expected error for expired token")
		}
	})
	t.Run("future iat", func(t *testing.T) {
		claims := map[string]any{
			"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
			"iat": float64(time.Now().Add(1 * time.Hour).Unix()),
		}
		err := validateIDTokenTiming(claims)
		if err == nil {
			t.Error("expected error for future iat")
		}
	})
	t.Run("no timing claims", func(t *testing.T) {
		claims := map[string]any{}
		err := validateIDTokenTiming(claims)
		if err != nil {
			t.Errorf("unexpected error with no timing: %v", err)
		}
	})
}

func TestValidateIDTokenNonce_CB5(t *testing.T) {
	t.Run("matching nonce", func(t *testing.T) {
		claims := map[string]any{"nonce": "abc123"}
		err := validateIDTokenNonce(claims, "abc123")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
	t.Run("mismatched nonce", func(t *testing.T) {
		claims := map[string]any{"nonce": "abc123"}
		err := validateIDTokenNonce(claims, "different")
		if err == nil {
			t.Error("expected error for mismatched nonce")
		}
	})
	t.Run("missing nonce in token", func(t *testing.T) {
		claims := map[string]any{}
		err := validateIDTokenNonce(claims, "expected")
		if err == nil {
			t.Error("expected error for missing nonce")
		}
	})
	t.Run("empty expected nonce", func(t *testing.T) {
		claims := map[string]any{"nonce": "abc123"}
		err := validateIDTokenNonce(claims, "")
		if err != nil {
			t.Errorf("unexpected error with empty expected: %v", err)
		}
	})
}

func TestExtractOAuthCallbackParams_CB5(t *testing.T) {
	t.Run("missing state cookie", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/callback?state=abc&code=xyz", nil)
		_, _, _, _, ok := extractOAuthCallbackParams(c)
		if ok {
			t.Error("expected false with missing state cookie")
		}
	})
	t.Run("state mismatch", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/callback?state=wrong&code=xyz", nil)
		c.Request.AddCookie(&http.Cookie{Name: "_oauth_state", Value: "correct"})
		_, _, _, _, ok := extractOAuthCallbackParams(c)
		if ok {
			t.Error("expected false with state mismatch")
		}
	})
	t.Run("missing code verifier", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/callback?state=abc&code=xyz", nil)
		c.Request.AddCookie(&http.Cookie{Name: "_oauth_state", Value: "abc"})
		_, _, _, _, ok := extractOAuthCallbackParams(c)
		if ok {
			t.Error("expected false with missing code verifier")
		}
	})
	t.Run("missing nonce", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/callback?state=abc&code=xyz", nil)
		c.Request.AddCookie(&http.Cookie{Name: "_oauth_state", Value: "abc"})
		c.Request.AddCookie(&http.Cookie{Name: "_oauth_cv", Value: "verifier123"})
		_, _, _, _, ok := extractOAuthCallbackParams(c)
		if ok {
			t.Error("expected false with missing nonce")
		}
	})
	t.Run("missing code param", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/callback?state=abc", nil)
		c.Request.AddCookie(&http.Cookie{Name: "_oauth_state", Value: "abc"})
		c.Request.AddCookie(&http.Cookie{Name: "_oauth_cv", Value: "verifier123"})
		c.Request.AddCookie(&http.Cookie{Name: "_oauth_nonce", Value: "nonce123"})
		_, _, _, _, ok := extractOAuthCallbackParams(c)
		if ok {
			t.Error("expected false with missing code param")
		}
	})
	t.Run("all params present", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/callback?state=abc&code=xyz", nil)
		c.Request.AddCookie(&http.Cookie{Name: "_oauth_state", Value: "abc"})
		c.Request.AddCookie(&http.Cookie{Name: "_oauth_cv", Value: "verifier123"})
		c.Request.AddCookie(&http.Cookie{Name: "_oauth_nonce", Value: "nonce123"})
		state, cv, nonce, code, ok := extractOAuthCallbackParams(c)
		if !ok {
			t.Error("expected true with all params present")
		}
		if state != "abc" || cv != "verifier123" || nonce != "nonce123" || code != "xyz" {
			t.Errorf("unexpected values: state=%q cv=%q nonce=%q code=%q", state, cv, nonce, code)
		}
	})
}

func TestNewFailuresHandler_CB5(t *testing.T) {
	cfg := &config.Config{AppVersion: "test"}
	h := NewFailuresHandler(nil, cfg)
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
}

func TestNewAnalyticsHandler_CB5(t *testing.T) {
	cfg := &config.Config{AppVersion: "test"}
	h := NewAnalyticsHandler(nil, cfg)
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
}

func TestNewStatsHandler_CB5(t *testing.T) {
	cfg := &config.Config{AppVersion: "test"}
	h := NewStatsHandler(nil, cfg)
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
}
