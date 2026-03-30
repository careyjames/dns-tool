package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestComputeCodeChallenge(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := computeCodeChallenge(verifier)
	if challenge == "" {
		t.Fatal("expected non-empty challenge")
	}
	if len(challenge) == 0 {
		t.Error("challenge should not be empty")
	}
	challenge2 := computeCodeChallenge(verifier)
	if challenge != challenge2 {
		t.Error("same verifier should produce same challenge")
	}
	different := computeCodeChallenge("different-verifier")
	if different == challenge {
		t.Error("different verifiers should produce different challenges")
	}
}

func TestGenerateRandomBase64URL(t *testing.T) {
	result, err := generateRandomBase64URL(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == "" {
		t.Error("expected non-empty result")
	}
	result2, err := generateRandomBase64URL(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == result2 {
		t.Error("two random values should differ")
	}
}

func TestGenerateSessionID(t *testing.T) {
	id, err := generateSessionID()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(id) != 64 {
		t.Errorf("expected 64 hex chars, got %d", len(id))
	}
	id2, err := generateSessionID()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id == id2 {
		t.Error("two session IDs should differ")
	}
}

func TestExtractUserClaims(t *testing.T) {
	tests := []struct {
		name              string
		userInfo          map[string]any
		wantSub           string
		wantEmail         string
		wantName          string
		wantEmailVerified bool
	}{
		{
			"all present",
			map[string]any{"sub": "123", "email": "a@b.com", "name": "Alice", "email_verified": true},
			"123", "a@b.com", "Alice", true,
		},
		{
			"missing fields",
			map[string]any{},
			"", "", "", false,
		},
		{
			"wrong types",
			map[string]any{"sub": 123, "email": true, "name": 456, "email_verified": "yes"},
			"", "", "", false,
		},
		{
			"email not verified",
			map[string]any{"sub": "s1", "email": "x@y.com", "name": "Bob", "email_verified": false},
			"s1", "x@y.com", "Bob", false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sub, email, name, verified := extractUserClaims(tt.userInfo)
			if sub != tt.wantSub {
				t.Errorf("sub = %q, want %q", sub, tt.wantSub)
			}
			if email != tt.wantEmail {
				t.Errorf("email = %q, want %q", email, tt.wantEmail)
			}
			if name != tt.wantName {
				t.Errorf("name = %q, want %q", name, tt.wantName)
			}
			if verified != tt.wantEmailVerified {
				t.Errorf("verified = %v, want %v", verified, tt.wantEmailVerified)
			}
		})
	}
}

func TestParseIDTokenPayload(t *testing.T) {
	t.Run("valid token", func(t *testing.T) {
		payload := map[string]any{"iss": "https://accounts.google.com", "sub": "123"}
		payloadBytes, _ := json.Marshal(payload)
		encoded := base64.RawURLEncoding.EncodeToString(payloadBytes)
		token := "header." + encoded + ".signature"

		claims, err := parseIDTokenPayload(token)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if claims["iss"] != "https://accounts.google.com" {
			t.Errorf("iss = %v", claims["iss"])
		}
		if claims["sub"] != "123" {
			t.Errorf("sub = %v", claims["sub"])
		}
	})

	t.Run("malformed token - too few parts", func(t *testing.T) {
		_, err := parseIDTokenPayload("only.two")
		if err == nil {
			t.Error("expected error for malformed token")
		}
	})

	t.Run("invalid base64", func(t *testing.T) {
		_, err := parseIDTokenPayload("header.!!!invalid!!!.sig")
		if err == nil {
			t.Error("expected error for invalid base64")
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		encoded := base64.RawURLEncoding.EncodeToString([]byte("not json"))
		_, err := parseIDTokenPayload("header." + encoded + ".sig")
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})
}

func TestValidateIDTokenIssuerAndAudience(t *testing.T) {
	tests := []struct {
		name     string
		claims   map[string]any
		clientID string
		wantErr  bool
	}{
		{"valid google.com issuer", map[string]any{"iss": "https://accounts.google.com", "aud": "my-client"}, "my-client", false},
		{"valid accounts.google.com issuer", map[string]any{"iss": "accounts.google.com", "aud": "my-client"}, "my-client", false},
		{"invalid issuer", map[string]any{"iss": "https://evil.com", "aud": "my-client"}, "my-client", true},
		{"wrong audience", map[string]any{"iss": "https://accounts.google.com", "aud": "wrong-client"}, "my-client", true},
		{"missing issuer", map[string]any{"aud": "my-client"}, "my-client", true},
		{"missing audience", map[string]any{"iss": "https://accounts.google.com"}, "my-client", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateIDTokenIssuerAndAudience(tt.claims, tt.clientID)
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateIDTokenNonce(t *testing.T) {
	tests := []struct {
		name          string
		claims        map[string]any
		expectedNonce string
		wantErr       bool
	}{
		{"empty expected nonce", map[string]any{}, "", false},
		{"matching nonce", map[string]any{"nonce": "abc123"}, "abc123", false},
		{"mismatched nonce", map[string]any{"nonce": "abc123"}, "xyz789", true},
		{"missing nonce in token", map[string]any{}, "abc123", true},
		{"empty nonce in token", map[string]any{"nonce": ""}, "abc123", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateIDTokenNonce(tt.claims, tt.expectedNonce)
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateIDTokenTiming(t *testing.T) {
	t.Run("valid token", func(t *testing.T) {
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
			"iat": float64(time.Now().Add(10 * time.Minute).Unix()),
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
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestMissionCriticalDomainsFromBaseURL(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		want    []string
	}{
		{"full URL with subdomain", "https://app.example.com", []string{"example.com", "app.example.com"}},
		{"full URL no subdomain", "https://example.com", []string{"example.com"}},
		{"URL with port", "https://app.example.com:8080", []string{"example.com", "app.example.com"}},
		{"URL with trailing slash", "https://example.com/", []string{"example.com"}},
		{"no scheme", "app.example.com", []string{"example.com", "app.example.com"}},
		{"bare domain", "example.com", []string{"example.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := missionCriticalDomainsFromBaseURL(tt.baseURL)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i, d := range got {
				if d != tt.want[i] {
					t.Errorf("got[%d] = %q, want %q", i, d, tt.want[i])
				}
			}
		})
	}
}

func TestComputeCodeChallengeDeterministic(t *testing.T) {
	v1 := "test-verifier-value"
	c1 := computeCodeChallenge(v1)
	c2 := computeCodeChallenge(v1)
	c3 := computeCodeChallenge(v1)
	if c1 != c2 || c2 != c3 {
		t.Error("computeCodeChallenge must be deterministic")
	}

	if len(c1) != 43 {
		t.Errorf("expected base64url-encoded SHA256 (43 chars), got %d", len(c1))
	}
}

func TestGenerateRandomBase64URLLengths(t *testing.T) {
	for _, n := range []int{1, 16, 32, 48, 64} {
		result, err := generateRandomBase64URL(n)
		if err != nil {
			t.Fatalf("n=%d: unexpected error: %v", n, err)
		}
		if result == "" {
			t.Errorf("n=%d: expected non-empty result", n)
		}
	}
}

func TestMissionCriticalDomainsFromBaseURLEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		want    []string
	}{
		{"http scheme", "http://app.example.com", []string{"example.com", "app.example.com"}},
		{"deep subdomain", "https://a.b.c.example.com", []string{"b.c.example.com", "a.b.c.example.com"}},
		{"ip-like host", "https://127.0.0.1", []string{"0.0.1", "127.0.0.1"}},
		{"single label", "localhost", []string{"localhost"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := missionCriticalDomainsFromBaseURL(tt.baseURL)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i, d := range got {
				if d != tt.want[i] {
					t.Errorf("got[%d] = %q, want %q", i, d, tt.want[i])
				}
			}
		})
	}
}

func TestExtractUserClaimsPartialFields(t *testing.T) {
	tests := []struct {
		name              string
		userInfo          map[string]any
		wantSub           string
		wantEmail         string
		wantName          string
		wantEmailVerified bool
	}{
		{
			"only sub",
			map[string]any{"sub": "abc"},
			"abc", "", "", false,
		},
		{
			"only email verified true with no email",
			map[string]any{"email_verified": true},
			"", "", "", true,
		},
		{
			"nil map values",
			map[string]any{"sub": nil, "email": nil, "name": nil, "email_verified": nil},
			"", "", "", false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sub, email, name, verified := extractUserClaims(tt.userInfo)
			if sub != tt.wantSub {
				t.Errorf("sub = %q, want %q", sub, tt.wantSub)
			}
			if email != tt.wantEmail {
				t.Errorf("email = %q, want %q", email, tt.wantEmail)
			}
			if name != tt.wantName {
				t.Errorf("name = %q, want %q", name, tt.wantName)
			}
			if verified != tt.wantEmailVerified {
				t.Errorf("verified = %v, want %v", verified, tt.wantEmailVerified)
			}
		})
	}
}

func TestValidateIDTokenTimingEdgeCases(t *testing.T) {
	t.Run("iat within skew window passes", func(t *testing.T) {
		claims := map[string]any{
			"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
			"iat": float64(time.Now().Add(2 * time.Minute).Unix()),
		}
		err := validateIDTokenTiming(claims)
		if err != nil {
			t.Errorf("iat within 5min skew should pass: %v", err)
		}
	})

	t.Run("zero exp ignored", func(t *testing.T) {
		claims := map[string]any{
			"exp": float64(0),
		}
		err := validateIDTokenTiming(claims)
		if err != nil {
			t.Errorf("zero exp should be ignored: %v", err)
		}
	})
}

func TestParseIDTokenPayloadEdgeCases(t *testing.T) {
	t.Run("empty payload", func(t *testing.T) {
		encoded := base64.RawURLEncoding.EncodeToString([]byte("{}"))
		claims, err := parseIDTokenPayload("h." + encoded + ".s")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(claims) != 0 {
			t.Errorf("expected empty claims, got %v", claims)
		}
	})

	t.Run("four parts still works", func(t *testing.T) {
		encoded := base64.RawURLEncoding.EncodeToString([]byte(`{"a":"b"}`))
		claims, err := parseIDTokenPayload("h." + encoded + ".s.extra")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if claims["a"] != "b" {
			t.Errorf("claims = %v", claims)
		}
	})
}

func TestValidateIDTokenIssuerAndAudienceEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		claims   map[string]any
		clientID string
		wantErr  bool
	}{
		{"empty client ID matches empty aud", map[string]any{"iss": "https://accounts.google.com", "aud": ""}, "", false},
		{"nil claims values", map[string]any{}, "client", true},
		{"iss with trailing slash", map[string]any{"iss": "https://accounts.google.com/", "aud": "c"}, "c", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateIDTokenIssuerAndAudience(tt.claims, tt.clientID)
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestAuthConstants(t *testing.T) {
	if googleAuthURL != "https://accounts.google.com/o/oauth2/v2/auth" {
		t.Errorf("unexpected googleAuthURL: %q", googleAuthURL)
	}
	if googleTokenURL != "https://oauth2.googleapis.com/token" {
		t.Errorf("unexpected googleTokenURL: %q", googleTokenURL)
	}
	if sessionCookieName != "_dns_session" {
		t.Errorf("unexpected sessionCookieName: %q", sessionCookieName)
	}
	if sessionMaxAge != 30*24*60*60 {
		t.Errorf("unexpected sessionMaxAge: %d", sessionMaxAge)
	}
	if oauthHTTPTimeout != 10*time.Second {
		t.Errorf("unexpected oauthHTTPTimeout: %v", oauthHTTPTimeout)
	}
	if iatMaxSkew != 5*time.Minute {
		t.Errorf("unexpected iatMaxSkew: %v", iatMaxSkew)
	}
}

func TestSecurityTrailsErrorMessage(t *testing.T) {
	tests := []struct {
		name    string
		errMsg  string
		wantSub string
	}{
		{"rate limited", "rate_limited", "rate limit"},
		{"auth failed", "auth_failed", "rejected"},
		{"connection error", "connection_error", "Could not connect"},
		{"unknown", "something_else", "unexpected"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := securityTrailsErrorMessage(errors.New(tt.errMsg))
			if got == "" {
				t.Error("expected non-empty message")
			}
		})
	}
}

func TestIPInfoErrorMessage(t *testing.T) {
	tests := []struct {
		name    string
		errMsg  string
		wantSub string
	}{
		{"rate limit", "rate limit exceeded", "rate limit"},
		{"invalid token", "invalid token provided", "rejected"},
		{"expired token", "token expired", "rejected"},
		{"other error", "something went wrong", "temporarily unavailable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ipInfoErrorMessage(errors.New(tt.errMsg))
			if got == "" {
				t.Error("expected non-empty message")
			}
		})
	}
}
