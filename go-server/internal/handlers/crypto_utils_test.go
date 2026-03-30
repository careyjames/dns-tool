package handlers

import (
        "encoding/base64"
        "encoding/json"
        "fmt"
        htmltemplate "html/template"
        "net/http"
        "net/http/httptest"
        "strings"
        "testing"
        "time"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/dbq"

        "github.com/gin-gonic/gin"
)

func TestGenerateRandomBase64URL_CB8(t *testing.T) {
        s, err := generateRandomBase64URL(32)
        if err != nil {
                t.Fatal(err)
        }
        if len(s) == 0 {
                t.Fatal("expected non-empty string")
        }
        s2, _ := generateRandomBase64URL(32)
        if s == s2 {
                t.Fatal("expected unique values")
        }
}

func TestGenerateSessionID_CB8(t *testing.T) {
        sid, err := generateSessionID()
        if err != nil {
                t.Fatal(err)
        }
        if len(sid) != 64 {
                t.Fatalf("expected 64 hex chars, got %d", len(sid))
        }
        sid2, _ := generateSessionID()
        if sid == sid2 {
                t.Fatal("expected unique session IDs")
        }
}

func TestComputeCodeChallenge_CB8(t *testing.T) {
        verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        challenge := computeCodeChallenge(verifier)
        if challenge == "" {
                t.Fatal("expected non-empty challenge")
        }
        if challenge == verifier {
                t.Fatal("challenge should differ from verifier")
        }
        challenge2 := computeCodeChallenge(verifier)
        if challenge != challenge2 {
                t.Fatal("same verifier should produce same challenge")
        }
}

func TestExtractUserClaims_CB8(t *testing.T) {
        t.Run("full claims", func(t *testing.T) {
                info := map[string]any{
                        "sub":            "12345",
                        "email":          "user@example.com",
                        "name":           "Test User",
                        "email_verified": true,
                }
                sub, email, name, verified := extractUserClaims(info)
                if sub != "12345" || email != "user@example.com" || name != "Test User" || !verified {
                        t.Fatalf("unexpected: sub=%q email=%q name=%q verified=%v", sub, email, name, verified)
                }
        })
        t.Run("empty map", func(t *testing.T) {
                sub, email, name, verified := extractUserClaims(map[string]any{})
                if sub != "" || email != "" || name != "" || verified {
                        t.Fatalf("expected empty strings and false, got sub=%q email=%q name=%q verified=%v", sub, email, name, verified)
                }
        })
        t.Run("wrong types", func(t *testing.T) {
                info := map[string]any{
                        "sub":            123,
                        "email_verified": "true",
                }
                sub, _, _, verified := extractUserClaims(info)
                if sub != "" || verified {
                        t.Fatal("expected defaults for wrong types")
                }
        })
}

func TestParseIDTokenPayload_CB8(t *testing.T) {
        t.Run("valid token", func(t *testing.T) {
                claims := map[string]any{
                        "sub":   "12345",
                        "email": "test@example.com",
                        "iss":   "https://accounts.google.com",
                }
                payload, _ := json.Marshal(claims)
                header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
                body := base64.RawURLEncoding.EncodeToString(payload)
                sig := base64.RawURLEncoding.EncodeToString([]byte("fake-sig"))
                token := header + "." + body + "." + sig

                result, err := parseIDTokenPayload(token)
                if err != nil {
                        t.Fatal(err)
                }
                if result["sub"] != "12345" {
                        t.Fatalf("expected sub=12345, got %v", result["sub"])
                }
        })
        t.Run("malformed token", func(t *testing.T) {
                _, err := parseIDTokenPayload("not.a.valid.token.with.dots")
                if err == nil {
                        t.Error("expected error for malformed token with too many dots")
                }
        })
        t.Run("two parts only", func(t *testing.T) {
                _, err := parseIDTokenPayload("header.body")
                if err == nil {
                        t.Fatal("expected error for 2-part token")
                }
        })
        t.Run("invalid base64", func(t *testing.T) {
                _, err := parseIDTokenPayload("header.!!!invalid!!!.sig")
                if err == nil {
                        t.Fatal("expected error for invalid base64")
                }
        })
        t.Run("invalid json", func(t *testing.T) {
                body := base64.RawURLEncoding.EncodeToString([]byte("not-json"))
                _, err := parseIDTokenPayload("header." + body + ".sig")
                if err == nil {
                        t.Fatal("expected error for invalid json")
                }
        })
}

func TestValidateIDTokenIssuerAndAudience_CB8(t *testing.T) {
        t.Run("valid google issuer", func(t *testing.T) {
                claims := map[string]any{
                        "iss": "https://accounts.google.com",
                        "aud": "my-client-id",
                }
                err := validateIDTokenIssuerAndAudience(claims, "my-client-id")
                if err != nil {
                        t.Fatal(err)
                }
        })
        t.Run("short google issuer", func(t *testing.T) {
                claims := map[string]any{
                        "iss": "accounts.google.com",
                        "aud": "client123",
                }
                err := validateIDTokenIssuerAndAudience(claims, "client123")
                if err != nil {
                        t.Fatal(err)
                }
        })
        t.Run("invalid issuer", func(t *testing.T) {
                claims := map[string]any{
                        "iss": "https://evil.example.com",
                        "aud": "client123",
                }
                err := validateIDTokenIssuerAndAudience(claims, "client123")
                if err == nil {
                        t.Fatal("expected error for invalid issuer")
                }
        })
        t.Run("wrong audience", func(t *testing.T) {
                claims := map[string]any{
                        "iss": "https://accounts.google.com",
                        "aud": "wrong-client",
                }
                err := validateIDTokenIssuerAndAudience(claims, "correct-client")
                if err == nil {
                        t.Fatal("expected error for wrong audience")
                }
        })
}

func TestValidateIDTokenTiming_CB8(t *testing.T) {
        t.Run("valid timing", func(t *testing.T) {
                claims := map[string]any{
                        "exp": float64(time.Now().Add(1 * time.Hour).Unix()),
                        "iat": float64(time.Now().Add(-1 * time.Minute).Unix()),
                }
                err := validateIDTokenTiming(claims)
                if err != nil {
                        t.Fatal(err)
                }
        })
        t.Run("expired token", func(t *testing.T) {
                claims := map[string]any{
                        "exp": float64(time.Now().Add(-1 * time.Hour).Unix()),
                }
                err := validateIDTokenTiming(claims)
                if err == nil {
                        t.Fatal("expected error for expired token")
                }
        })
        t.Run("no timing claims", func(t *testing.T) {
                err := validateIDTokenTiming(map[string]any{})
                if err != nil {
                        t.Fatal(err)
                }
        })
        t.Run("far future iat", func(t *testing.T) {
                claims := map[string]any{
                        "iat": float64(time.Now().Add(1 * time.Hour).Unix()),
                }
                err := validateIDTokenTiming(claims)
                if err == nil {
                        t.Fatal("expected error for future iat")
                }
        })
}

func TestValidateIDTokenNonce_CB8(t *testing.T) {
        t.Run("matching nonce", func(t *testing.T) {
                claims := map[string]any{"nonce": "abc123"}
                err := validateIDTokenNonce(claims, "abc123")
                if err != nil {
                        t.Fatal(err)
                }
        })
        t.Run("mismatched nonce", func(t *testing.T) {
                claims := map[string]any{"nonce": "abc123"}
                err := validateIDTokenNonce(claims, "xyz789")
                if err == nil {
                        t.Fatal("expected error for nonce mismatch")
                }
        })
        t.Run("missing nonce in token", func(t *testing.T) {
                err := validateIDTokenNonce(map[string]any{}, "expected-nonce")
                if err == nil {
                        t.Fatal("expected error for missing nonce")
                }
        })
        t.Run("empty expected nonce", func(t *testing.T) {
                err := validateIDTokenNonce(map[string]any{}, "")
                if err != nil {
                        t.Fatal(err)
                }
        })
}

func TestMissionCriticalDomainsFromBaseURL_CB8(t *testing.T) {
        tests := []struct {
                input string
                want  int
        }{
                {"https://dnstool.it-help.tech", 2},
                {"https://example.com", 1},
                {"http://localhost:5000", 1},
                {"https://sub.example.co.uk", 2},
        }
        for _, tc := range tests {
                t.Run(tc.input, func(t *testing.T) {
                        domains := missionCriticalDomainsFromBaseURL(tc.input)
                        if len(domains) < 1 {
                                t.Fatalf("expected at least 1 domain, got %d", len(domains))
                        }
                })
        }
        t.Run("contains host", func(t *testing.T) {
                domains := missionCriticalDomainsFromBaseURL("https://dnstool.it-help.tech")
                found := false
                for _, d := range domains {
                        if d == "dnstool.it-help.tech" {
                                found = true
                        }
                }
                if !found {
                        t.Fatalf("expected dnstool.it-help.tech in %v", domains)
                }
        })
}

func TestReportModeTemplate_CB8(t *testing.T) {
        tests := []struct {
                mode string
                want string
        }{
                {"E", "results.html"},
                {"C", "results_covert.html"},
                {"Z", "results.html"},
                {"CZ", "results_covert.html"},
                {"B", "results_executive.html"},
                {"", "results.html"},
                {"X", "results.html"},
        }
        for _, tc := range tests {
                t.Run(tc.mode, func(t *testing.T) {
                        got := reportModeTemplate(tc.mode)
                        if got != tc.want {
                                t.Fatalf("reportModeTemplate(%q) = %q, want %q", tc.mode, got, tc.want)
                        }
                })
        }
}

func TestIsCovertMode_CB8(t *testing.T) {
        if isCovertMode("E") {
                t.Fatal("E should not be covert")
        }
        if !isCovertMode("C") {
                t.Fatal("C should be covert")
        }
        if !isCovertMode("CZ") {
                t.Fatal("CZ should be covert")
        }
        if isCovertMode("Z") {
                t.Fatal("Z should not be covert")
        }
        if isCovertMode("B") {
                t.Fatal("B should not be covert")
        }
        if !isCovertMode("EC") {
                t.Fatal("EC should be covert")
        }
}

func TestDerefString_CB8(t *testing.T) {
        s := "hello"
        if derefString(&s) != "hello" {
                t.Fatal("expected hello")
        }
        if derefString(nil) != "" {
                t.Fatal("expected empty for nil")
        }
}

func TestLogEphemeralReason_CB8(t *testing.T) {
        logEphemeralReason("example.com", true, false)
        logEphemeralReason("example.com", false, true)
        logEphemeralReason("example.com", false, false)
}

func TestRenderErrorPage_CB8(t *testing.T) {
        gin.SetMode(gin.TestMode)
        router := gin.New()
        tmpl := parseTestTemplate("results.html", "index.html")
        router.SetHTMLTemplate(tmpl)

        h := &AnalysisHandler{Config: &config.Config{}}
        router.GET("/error", func(c *gin.Context) {
                c.Set("csp_nonce", "test")
                c.Set("csrf_token", "test")
                h.renderErrorPage(c, http.StatusNotFound, "test", "test", "danger", "Not found")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/error", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusNotFound {
                t.Fatalf("expected 404, got %d", w.Code)
        }
}

func TestRenderRestrictedAccess_CB8(t *testing.T) {
        gin.SetMode(gin.TestMode)
        router := gin.New()
        tmpl := parseTestTemplate("results.html", "index.html")
        router.SetHTMLTemplate(tmpl)

        h := &AnalysisHandler{Config: &config.Config{}}
        router.GET("/restricted", func(c *gin.Context) {
                c.Set("csp_nonce", "test")
                c.Set("csrf_token", "test")
                h.renderRestrictedAccess(c, "test", "test")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/restricted", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusNotFound {
                t.Fatalf("expected 404 (unauthenticated falls through to not found), got %d", w.Code)
        }
}

func TestIndexFlashData_CB8(t *testing.T) {
        gin.SetMode(gin.TestMode)
        h := &AnalysisHandler{Config: &config.Config{BaseURL: "https://example.com"}}
        c, _ := gin.CreateTestContext(httptest.NewRecorder())
        c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

        data := h.indexFlashData(c, "nonce", "csrf", "danger", "Something went wrong")
        if data["CspNonce"] != "nonce" {
                t.Fatalf("expected nonce, got %v", data["CspNonce"])
        }
        if data["BaseURL"] != "https://example.com" {
                t.Fatalf("expected BaseURL=https://example.com, got %v", data["BaseURL"])
        }
        msgs, ok := data["FlashMessages"].([]FlashMessage)
        if !ok || len(msgs) == 0 {
                t.Fatal("expected flash messages")
        }
        if msgs[0].Message != "Something went wrong" {
                t.Fatalf("expected 'Something went wrong', got %q", msgs[0].Message)
        }
}

func TestApplyWelcomeOrFlash_CB8(t *testing.T) {
        gin.SetMode(gin.TestMode)

        t.Run("welcome param", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest(http.MethodGet, "/?welcome=Alice", nil)
                data := gin.H{}
                applyWelcomeOrFlash(c, data)
                if data["WelcomeName"] != "Alice" {
                        t.Fatalf("expected WelcomeName=Alice, got %v", data["WelcomeName"])
                }
        })

        t.Run("welcome truncated", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                long := strings.Repeat("x", 200)
                c.Request = httptest.NewRequest(http.MethodGet, "/?welcome="+long, nil)
                data := gin.H{}
                applyWelcomeOrFlash(c, data)
                name := data["WelcomeName"].(string)
                if len(name) != 100 {
                        t.Fatalf("expected truncated to 100, got %d", len(name))
                }
        })

        t.Run("flash param", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest(http.MethodGet, "/?flash=hello&flash_cat=success", nil)
                data := gin.H{}
                applyWelcomeOrFlash(c, data)
                msgs := data["FlashMessages"].([]FlashMessage)
                if msgs[0].Category != "success" {
                        t.Fatalf("expected category=success, got %q", msgs[0].Category)
                }
        })

        t.Run("flash with domain", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest(http.MethodGet, "/?flash=err&domain=example.com", nil)
                data := gin.H{}
                applyWelcomeOrFlash(c, data)
                if data["PrefillDomain"] != "example.com" {
                        t.Fatalf("expected PrefillDomain=example.com, got %v", data["PrefillDomain"])
                }
        })

        t.Run("flash invalid category", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest(http.MethodGet, "/?flash=msg&flash_cat=info", nil)
                data := gin.H{}
                applyWelcomeOrFlash(c, data)
                msgs := data["FlashMessages"].([]FlashMessage)
                if msgs[0].Category != "warning" {
                        t.Fatalf("expected fallback to warning, got %q", msgs[0].Category)
                }
        })
}

func TestAnalysisDuration_CB8(t *testing.T) {
        dur := float64(2.5)
        analysis := dbq.DomainAnalysis{AnalysisDuration: &dur}
        d := analysisDuration(analysis)
        if d != 2.5 {
                t.Fatalf("expected 2.5, got %f", d)
        }
        analysis2 := dbq.DomainAnalysis{}
        d2 := analysisDuration(analysis2)
        if d2 != 0.0 {
                t.Fatalf("expected 0.0, got %f", d2)
        }
}

func TestComputeDriftFromPrev_CB8(t *testing.T) {
        t.Run("empty hash", func(t *testing.T) {
                prev := prevAnalysisSnapshot{}
                di := computeDriftFromPrev("current-hash", prev, map[string]any{})
                if di.Detected {
                        t.Fatal("expected no drift for nil hash")
                }
        })
        t.Run("same hash", func(t *testing.T) {
                hash := "abc"
                prev := prevAnalysisSnapshot{
                        ID:   1,
                        Hash: &hash,
                }
                di := computeDriftFromPrev("abc", prev, map[string]any{})
                if di.Detected {
                        t.Fatal("expected no drift for same hash")
                }
        })
        t.Run("different hash", func(t *testing.T) {
                hash := "old"
                prev := prevAnalysisSnapshot{
                        ID:          1,
                        Hash:        &hash,
                        FullResults: []byte(`{"basic_records":{"A":["1.2.3.4"]}}`),
                }
                di := computeDriftFromPrev("new", prev, map[string]any{"basic_records": map[string]any{"A": []any{"5.6.7.8"}}})
                if !di.Detected {
                        t.Fatal("expected drift for different hash")
                }
        })
        t.Run("different hash with created_at", func(t *testing.T) {
                hash := "old"
                prev := prevAnalysisSnapshot{
                        ID:             1,
                        Hash:           &hash,
                        CreatedAtValid: true,
                        CreatedAt:      time.Now().Add(-24 * time.Hour),
                }
                di := computeDriftFromPrev("new", prev, map[string]any{})
                if !di.Detected {
                        t.Fatal("expected drift")
                }
                if di.PrevTime == "" {
                        t.Fatal("expected PrevTime to be set")
                }
        })
}

func strPtrCB8(s string) *string {
        return &s
}

func parseTestTemplate(names ...string) *htmltemplate.Template {
        tmpl := htmltemplate.New("root")
        for _, n := range names {
                htmltemplate.Must(tmpl.New(n).Parse(fmt.Sprintf(`{{define "%s"}}OK{{end}}`, n)))
        }
        return tmpl
}

func TestResolveReportMode_CB8(t *testing.T) {
        gin.SetMode(gin.TestMode)
        t.Run("default", func(t *testing.T) {
                c, _ := gin.CreateTestContext(httptest.NewRecorder())
                c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
                mode := resolveReportMode(c)
                if mode != "E" {
                        t.Fatalf("expected E, got %q", mode)
                }
        })
        t.Run("executive", func(t *testing.T) {
                c, _ := gin.CreateTestContext(httptest.NewRecorder())
                c.Request = httptest.NewRequest(http.MethodGet, "/?mode=E", nil)
                mode := resolveReportMode(c)
                if mode != "E" {
                        t.Fatalf("expected E, got %q", mode)
                }
        })
}
