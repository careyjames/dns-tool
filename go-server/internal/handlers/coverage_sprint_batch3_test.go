package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"dnstool/go-server/internal/config"

	"github.com/gin-gonic/gin"
)

func TestBatch3_LoginRedirect(t *testing.T) {
	cfg := &config.Config{
		GoogleClientID:     "test-client-id",
		GoogleClientSecret: "test-secret",
		GoogleRedirectURL:  "https://test.example.com/auth/callback",
	}
	h := &AuthHandler{
		Config:    cfg,
		authStore: &mockAuthStore{},
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/auth/login", nil)

	h.Login(c)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "accounts.google.com") {
		t.Errorf("expected redirect to accounts.google.com, got %q", loc)
	}
	if !strings.Contains(loc, "client_id=test-client-id") {
		t.Errorf("expected client_id in redirect URL, got %q", loc)
	}
	if !strings.Contains(loc, "redirect_uri=") {
		t.Errorf("expected redirect_uri in redirect URL, got %q", loc)
	}
	if !strings.Contains(loc, "code_challenge=") {
		t.Errorf("expected code_challenge (PKCE) in redirect URL, got %q", loc)
	}

	cookies := w.Result().Cookies()
	cookieNames := make(map[string]bool)
	for _, ck := range cookies {
		cookieNames[ck.Name] = true
	}
	if !cookieNames[oauthStateCookie] {
		t.Error("expected state cookie to be set")
	}
	if !cookieNames[oauthCVCookie] {
		t.Error("expected code verifier cookie to be set")
	}
	if !cookieNames[oauthNonceCookie] {
		t.Error("expected nonce cookie to be set")
	}
}

func TestBatch3_LogoutDeletesSessionAndRedirects(t *testing.T) {
	deleteCalled := false
	mock := &mockAuthStore{
		deleteSessionFn: func(ctx context.Context, id string) error {
			deleteCalled = true
			if id != "test-session-123" {
				t.Errorf("expected session id %q, got %q", "test-session-123", id)
			}
			return nil
		},
	}
	h := &AuthHandler{
		Config:    &config.Config{},
		authStore: mock,
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/auth/logout", nil)
	c.Request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "test-session-123"})

	h.Logout(c)

	if !deleteCalled {
		t.Error("expected DeleteSession to be called")
	}
	if w.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc != "/" {
		t.Errorf("expected redirect to /, got %q", loc)
	}

	for _, ck := range w.Result().Cookies() {
		if ck.Name == sessionCookieName && ck.MaxAge < 0 {
			return
		}
	}
	t.Error("expected session cookie to be cleared (MaxAge < 0)")
}

func TestBatch3_LogoutNoCookie(t *testing.T) {
	deleteCalled := false
	mock := &mockAuthStore{
		deleteSessionFn: func(ctx context.Context, id string) error {
			deleteCalled = true
			return nil
		},
	}
	h := &AuthHandler{
		Config:    &config.Config{},
		authStore: mock,
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/auth/logout", nil)

	h.Logout(c)

	if deleteCalled {
		t.Error("DeleteSession should not be called when no session cookie exists")
	}
	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
}

func TestBatch3_DetermineRole_CountAdminError(t *testing.T) {
	mock := &mockAuthStore{
		countAdminUsersFn: func(ctx context.Context) (int64, error) {
			return 0, errors.New("database unreachable")
		},
	}
	h := &AuthHandler{
		Config:    &config.Config{InitialAdminEmail: "admin@example.com"},
		authStore: mock,
	}

	role, shouldBootstrap := h.determineRole(context.Background(), "admin@example.com")
	if role != "user" {
		t.Errorf("expected role %q on error, got %q", "user", role)
	}
	if shouldBootstrap {
		t.Error("shouldBootstrap should be false when CountAdminUsers returns error")
	}
}

func TestBatch3_ZoneUploadForm(t *testing.T) {
	r := gin.New()
	r.SetHTMLTemplate(mustParseMinimalTemplate("zone.html"))

	cfg := defaultTestConfig
	h := &ZoneHandler{
		DB:     nil,
		Config: &cfg,
	}
	r.GET("/zone", h.UploadForm)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/zone", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestBatch3_RenderZoneFlash(t *testing.T) {
	r := gin.New()
	r.SetHTMLTemplate(mustParseMinimalTemplate("zone.html"))

	cfg := defaultTestConfig
	h := &ZoneHandler{
		DB:     nil,
		Config: &cfg,
	}

	r.GET("/zone-flash", func(c *gin.Context) {
		h.renderZoneFlash(c, "test-nonce", "test-csrf", "warning", "Test warning message")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/zone-flash", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestBatch3_RenderZoneFlashDanger(t *testing.T) {
	r := gin.New()
	r.SetHTMLTemplate(mustParseMinimalTemplate("zone.html"))

	cfg := defaultTestConfig
	h := &ZoneHandler{
		DB:     nil,
		Config: &cfg,
	}

	r.GET("/zone-flash-danger", func(c *gin.Context) {
		h.renderZoneFlash(c, nil, nil, "danger", "Something went wrong")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/zone-flash-danger", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestBatch3_SecurityTrailsErrorMessage(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		contains string
	}{
		{"rate_limited", "rate_limited", "rate limit"},
		{"auth_failed", "auth_failed", "API key was rejected"},
		{"connection_error", "connection_error", "Could not connect"},
		{"unknown_error", "some random error", "unexpected error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := securityTrailsErrorMessage(errors.New(tt.errMsg))
			if !strings.Contains(result, tt.contains) {
				t.Errorf("securityTrailsErrorMessage(%q) = %q, want it to contain %q", tt.errMsg, result, tt.contains)
			}
		})
	}
}

func TestBatch3_IPInfoErrorMessage(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		contains string
	}{
		{"rate_limit", "rate limit exceeded", "rate limit"},
		{"invalid_token", "invalid token provided", "Token was rejected"},
		{"expired_token", "token has expired", "Token was rejected"},
		{"generic_error", "network timeout", "Could not retrieve data"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ipInfoErrorMessage(errors.New(tt.errMsg))
			if !strings.Contains(result, tt.contains) {
				t.Errorf("ipInfoErrorMessage(%q) = %q, want it to contain %q", tt.errMsg, result, tt.contains)
			}
		})
	}
}

func TestBatch3_ApplySecurityTrailsNeighborhood_Empty(t *testing.T) {
	results := make(map[string]any)
	applySecurityTrailsNeighborhood([]string{}, "example.com", "example.com", results)

	neighborhood, ok := results["neighborhood"].([]map[string]any)
	if !ok {
		t.Fatal("expected neighborhood key in results")
	}
	if len(neighborhood) != 0 {
		t.Errorf("expected empty neighborhood, got %d entries", len(neighborhood))
	}
}

func TestBatch3_ApplySecurityTrailsNeighborhood_FiltersSelf(t *testing.T) {
	results := make(map[string]any)
	domains := []string{"example.com", "EXAMPLE.COM", "other.com", "another.net"}
	applySecurityTrailsNeighborhood(domains, "example.com", "example.com", results)

	neighborhood, ok := results["neighborhood"].([]map[string]any)
	if !ok {
		t.Fatal("expected neighborhood key in results")
	}
	for _, n := range neighborhood {
		d := n["domain"].(string)
		if strings.EqualFold(d, "example.com") {
			t.Errorf("target domain should be filtered out, but found %q", d)
		}
	}
	if len(neighborhood) != 2 {
		t.Errorf("expected 2 neighbors (other.com, another.net), got %d", len(neighborhood))
	}
}

func TestBatch3_ApplySecurityTrailsNeighborhood_UniqueDomains(t *testing.T) {
	results := make(map[string]any)
	domains := []string{"a.com", "b.com", "c.com"}
	applySecurityTrailsNeighborhood(domains, "target.com", "target.com", results)

	neighborhood, ok := results["neighborhood"].([]map[string]any)
	if !ok {
		t.Fatal("expected neighborhood key in results")
	}
	if len(neighborhood) != 3 {
		t.Errorf("expected 3 neighbors, got %d", len(neighborhood))
	}

	total, ok := results["neighborhood_total"].(int)
	if !ok || total != 3 {
		t.Errorf("expected neighborhood_total=3, got %v", results["neighborhood_total"])
	}

	source, ok := results["neighborhood_source"].(string)
	if !ok || source != "SecurityTrails" {
		t.Errorf("expected neighborhood_source=SecurityTrails, got %v", results["neighborhood_source"])
	}

	stEnabled, ok := results["st_enabled"].(bool)
	if !ok || !stEnabled {
		t.Errorf("expected st_enabled=true, got %v", results["st_enabled"])
	}
}

func TestBatch3_ApplySecurityTrailsNeighborhood_CapsTo10(t *testing.T) {
	results := make(map[string]any)
	domains := make([]string, 15)
	for i := range domains {
		domains[i] = strings.Replace("domainXX.com", "XX", string(rune('a'+i)), 1)
	}
	applySecurityTrailsNeighborhood(domains, "target.com", "target.com", results)

	neighborhood, ok := results["neighborhood"].([]map[string]any)
	if !ok {
		t.Fatal("expected neighborhood key")
	}
	if len(neighborhood) > 10 {
		t.Errorf("expected at most 10 neighbors, got %d", len(neighborhood))
	}
}

func TestBatch3_ApplySecurityTrailsNeighborhood_FiltersAsciiDomain(t *testing.T) {
	results := make(map[string]any)
	domains := []string{"xn--nxasmq6b.com", "other.com"}
	applySecurityTrailsNeighborhood(domains, "unicode.com", "xn--nxasmq6b.com", results)

	neighborhood, ok := results["neighborhood"].([]map[string]any)
	if !ok {
		t.Fatal("expected neighborhood key")
	}
	if len(neighborhood) != 1 {
		t.Errorf("expected 1 neighbor after filtering ascii domain, got %d", len(neighborhood))
	}
	if neighborhood[0]["domain"] != "other.com" {
		t.Errorf("expected other.com, got %v", neighborhood[0]["domain"])
	}
}
