package handlers

import (
        "context"
        "encoding/json"
        "errors"
        "html/template"
        "net/http"
        "net/http/httptest"
        "testing"

        "dnstool/go-server/internal/dbq"

        "github.com/gin-gonic/gin"
        "github.com/jackc/pgx/v5/pgtype"
)

func apiRouter(h *AnalysisHandler) *gin.Engine {
        gin.SetMode(gin.TestMode)
        r := gin.New()
        tmpl := template.Must(template.New("").Parse(
                `{{define "index.html"}}ok{{end}}` +
                        `{{define "results.html"}}ok{{end}}`,
        ))
        r.SetHTMLTemplate(tmpl)
        return r
}

func TestCheckPrivateAccess_NotPrivate(t *testing.T) {
        h := newViewModeHandler(&mockAnalysisStore{})
        c := mockGinContext()
        if !h.checkPrivateAccess(c, 1, false) {
                t.Error("expected true for non-private analysis")
        }
}

func TestCheckPrivateAccess_PrivateNoAuth(t *testing.T) {
        h := newViewModeHandler(&mockAnalysisStore{})
        c := mockGinContext()
        if h.checkPrivateAccess(c, 1, true) {
                t.Error("expected false for unauthenticated private analysis")
        }
}

func TestCheckPrivateAccess_PrivateAuthNoUID(t *testing.T) {
        h := newViewModeHandler(&mockAnalysisStore{})
        c := mockGinContext()
        c.Set("authenticated", true)
        if h.checkPrivateAccess(c, 1, true) {
                t.Error("expected false when authenticated but no user_id")
        }
}

func TestCheckPrivateAccess_PrivateAuthWrongType(t *testing.T) {
        h := newViewModeHandler(&mockAnalysisStore{})
        c := mockGinContext()
        c.Set("authenticated", true)
        c.Set("user_id", "not-an-int")
        if h.checkPrivateAccess(c, 1, true) {
                t.Error("expected false when user_id is wrong type")
        }
}

func TestCheckPrivateAccess_PrivateOwner(t *testing.T) {
        var capturedArgs dbq.CheckAnalysisOwnershipParams
        h := newViewModeHandler(&mockAnalysisStore{
                CheckAnalysisOwnershipFn: func(ctx context.Context, arg dbq.CheckAnalysisOwnershipParams) (bool, error) {
                        capturedArgs = arg
                        return true, nil
                },
        })
        c := mockGinContext()
        c.Set("authenticated", true)
        c.Set("user_id", int32(42))
        if !h.checkPrivateAccess(c, 99, true) {
                t.Error("expected true for owner of private analysis")
        }
        if capturedArgs.AnalysisID != 99 {
                t.Errorf("expected analysisID=99, got %d", capturedArgs.AnalysisID)
        }
        if capturedArgs.UserID != 42 {
                t.Errorf("expected userID=42, got %d", capturedArgs.UserID)
        }
}

func TestCheckPrivateAccess_PrivateNotOwner(t *testing.T) {
        h := newViewModeHandler(&mockAnalysisStore{
                CheckAnalysisOwnershipFn: func(ctx context.Context, arg dbq.CheckAnalysisOwnershipParams) (bool, error) {
                        return false, nil
                },
        })
        c := mockGinContext()
        c.Set("authenticated", true)
        c.Set("user_id", int32(42))
        if h.checkPrivateAccess(c, 1, true) {
                t.Error("expected false for non-owner of private analysis")
        }
}

func TestCheckPrivateAccess_PrivateDBError(t *testing.T) {
        h := newViewModeHandler(&mockAnalysisStore{
                CheckAnalysisOwnershipFn: func(ctx context.Context, arg dbq.CheckAnalysisOwnershipParams) (bool, error) {
                        return false, errors.New("db error")
                },
        })
        c := mockGinContext()
        c.Set("authenticated", true)
        c.Set("user_id", int32(42))
        if h.checkPrivateAccess(c, 1, true) {
                t.Error("expected false on db error")
        }
}

func TestAPIAnalysis_Success(t *testing.T) {
        results := map[string]any{"analysis_success": true, "_tool_version": "26.37.0"}
        resultsJSON, _ := json.Marshal(results)

        h := newViewModeHandler(&mockAnalysisStore{
                GetAnalysisByIDFn: func(ctx context.Context, id int32) (dbq.DomainAnalysis, error) {
                        return dbq.DomainAnalysis{
                                ID: id, Domain: "example.com", AsciiDomain: "example.com",
                                FullResults: resultsJSON,
                                CreatedAt:   pgtype.Timestamp{Valid: true},
                        }, nil
                },
        })
        r := apiRouter(h)
        r.GET("/api/analysis/:id", h.APIAnalysis)

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/api/analysis/1", nil)
        r.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }
        if ct := w.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
                t.Errorf("unexpected content-type: %s", ct)
        }
        if sha3 := w.Header().Get("X-SHA3-512"); sha3 == "" {
                t.Error("expected X-SHA3-512 header to be set")
        } else if len(sha3) != 128 {
                t.Errorf("expected 128-char SHA3-512 hash, got %d chars", len(sha3))
        }
}

func TestAPIAnalysis_Download(t *testing.T) {
        results := map[string]any{"analysis_success": true, "_tool_version": "26.37.0"}
        resultsJSON, _ := json.Marshal(results)

        h := newViewModeHandler(&mockAnalysisStore{
                GetAnalysisByIDFn: func(ctx context.Context, id int32) (dbq.DomainAnalysis, error) {
                        return dbq.DomainAnalysis{
                                ID: id, Domain: "example.com", AsciiDomain: "example.com",
                                FullResults: resultsJSON,
                                CreatedAt:   pgtype.Timestamp{Valid: true},
                        }, nil
                },
        })
        r := apiRouter(h)
        r.GET("/api/analysis/:id", h.APIAnalysis)

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/api/analysis/1?download=1", nil)
        r.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }
        if cd := w.Header().Get("Content-Disposition"); cd == "" {
                t.Error("expected Content-Disposition header for download")
        }
}

func TestAPIAnalysis_InvalidID(t *testing.T) {
        h := newViewModeHandler(&mockAnalysisStore{})
        r := apiRouter(h)
        r.GET("/api/analysis/:id", h.APIAnalysis)

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/api/analysis/abc", nil)
        r.ServeHTTP(w, req)

        if w.Code != http.StatusBadRequest {
                t.Fatalf("expected 400, got %d", w.Code)
        }
}

func TestAPIAnalysisChecksum_JSON(t *testing.T) {
        results := map[string]any{"analysis_success": true, "_tool_version": "26.37.0"}
        resultsJSON, _ := json.Marshal(results)

        h := newViewModeHandler(&mockAnalysisStore{
                GetAnalysisByIDFn: func(ctx context.Context, id int32) (dbq.DomainAnalysis, error) {
                        return dbq.DomainAnalysis{
                                ID: id, Domain: "example.com", AsciiDomain: "example.com",
                                FullResults: resultsJSON,
                                CreatedAt:   pgtype.Timestamp{Valid: true},
                        }, nil
                },
        })
        r := apiRouter(h)
        r.GET("/api/analysis/:id/checksum", h.APIAnalysisChecksum)

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/api/analysis/1/checksum", nil)
        r.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }
        var resp map[string]any
        if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
                t.Fatalf("expected valid JSON: %v", err)
        }
        if resp["algorithm"] != "SHA-3-512" {
                t.Errorf("expected SHA-3-512 algorithm, got %v", resp["algorithm"])
        }
}

func TestAPIAnalysisChecksum_SHA3Format(t *testing.T) {
        results := map[string]any{"analysis_success": true, "_tool_version": "26.37.0"}
        resultsJSON, _ := json.Marshal(results)

        h := newViewModeHandler(&mockAnalysisStore{
                GetAnalysisByIDFn: func(ctx context.Context, id int32) (dbq.DomainAnalysis, error) {
                        return dbq.DomainAnalysis{
                                ID: id, Domain: "example.com", AsciiDomain: "example.com",
                                FullResults: resultsJSON,
                                CreatedAt:   pgtype.Timestamp{Valid: true},
                        }, nil
                },
        })
        r := apiRouter(h)
        r.GET("/api/analysis/:id/checksum", h.APIAnalysisChecksum)

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/api/analysis/1/checksum?format=sha3", nil)
        r.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }
        if ct := w.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
                t.Errorf("expected text/plain, got %s", ct)
        }
        body := w.Body.String()
        if len(body) == 0 {
                t.Error("expected non-empty sha3 file body")
        }
}

func TestAPIAnalysisChecksum_NotFound(t *testing.T) {
        h := newViewModeHandler(&mockAnalysisStore{
                GetAnalysisByIDFn: func(ctx context.Context, id int32) (dbq.DomainAnalysis, error) {
                        return dbq.DomainAnalysis{}, errors.New("not found")
                },
        })
        r := apiRouter(h)
        r.GET("/api/analysis/:id/checksum", h.APIAnalysisChecksum)

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/api/analysis/999/checksum", nil)
        r.ServeHTTP(w, req)

        if w.Code != http.StatusNotFound {
                t.Fatalf("expected 404, got %d", w.Code)
        }
}

func TestAPIDNSHistory_EmptyDomain(t *testing.T) {
        h := newViewModeHandler(&mockAnalysisStore{})
        r := apiRouter(h)
        r.GET("/api/dns-history", h.APIDNSHistory)

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/api/dns-history", nil)
        r.ServeHTTP(w, req)

        if w.Code != http.StatusBadRequest {
                t.Fatalf("expected 400, got %d", w.Code)
        }
}

func TestAPIDNSHistory_InvalidDomain(t *testing.T) {
        h := newViewModeHandler(&mockAnalysisStore{})
        r := apiRouter(h)
        r.GET("/api/dns-history", h.APIDNSHistory)

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/api/dns-history?domain=not..valid", nil)
        r.ServeHTTP(w, req)

        if w.Code != http.StatusBadRequest {
                t.Fatalf("expected 400, got %d", w.Code)
        }
}

func TestAPIDNSHistory_NoAPIKey(t *testing.T) {
        h := newViewModeHandler(&mockAnalysisStore{})
        r := apiRouter(h)
        r.GET("/api/dns-history", h.APIDNSHistory)

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/api/dns-history?domain=example.com", nil)
        r.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }
        var resp map[string]any
        if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
                t.Fatalf("failed to unmarshal response: %v", err)
        }
        if resp["status"] != "no_key" {
                t.Errorf("expected status=no_key, got %v", resp["status"])
        }
}

func TestExtractPostureRisk_NilResults(t *testing.T) {
        label, color := extractPostureRisk(nil)
        if label != "Unknown" {
                t.Errorf("expected Unknown, got %s", label)
        }
        if color != "" {
                t.Errorf("expected empty color, got %s", color)
        }
}

func TestExtractPostureRisk_NoPosture(t *testing.T) {
        label, _ := extractPostureRisk(map[string]any{})
        if label != "Unknown" {
                t.Errorf("expected Unknown, got %s", label)
        }
}

func TestExtractPostureRisk_WithPosture(t *testing.T) {
        results := map[string]any{
                "posture": map[string]any{
                        "label": "Low Risk",
                        "color": "success",
                },
        }
        label, color := extractPostureRisk(results)
        if label != "Low Risk" {
                t.Errorf("expected Low Risk, got %s", label)
        }
        if color != "success" {
                t.Errorf("expected success, got %s", color)
        }
}

func TestExtractPostureRisk_GradeFallback(t *testing.T) {
        results := map[string]any{
                "posture": map[string]any{
                        "grade": "A+",
                },
        }
        label, _ := extractPostureRisk(results)
        if label != "A+" {
                t.Errorf("expected A+, got %s", label)
        }
}

func TestRiskColorToHex_Extended(t *testing.T) {
        tests := []struct {
                color    string
                expected string
        }{
                {"success", hexGreen},
                {"warning", hexYellow},
                {"danger", colorDanger},
                {"unknown", colorGrey},
                {"", colorGrey},
        }
        for _, tt := range tests {
                t.Run(tt.color, func(t *testing.T) {
                        got := riskColorToHex(tt.color)
                        if got != tt.expected {
                                t.Errorf("riskColorToHex(%q) = %q, want %q", tt.color, got, tt.expected)
                        }
                })
        }
}

func TestNormalizeRiskColor(t *testing.T) {
        tests := []struct {
                label    string
                color    string
                expected string
        }{
                {"Low Risk", "success", "success"},
                {"High Risk", "warning", "warning"},
                {"Critical", "danger", "danger"},
                {"Low Risk", "", "success"},
                {"High Risk", "", "danger"},
                {"Critical", "", "danger"},
                {"Medium Risk", "", "warning"},
                {"Unknown", "", ""},
        }
        for _, tt := range tests {
                t.Run(tt.label+"_"+tt.color, func(t *testing.T) {
                        got := normalizeRiskColor(tt.label, tt.color)
                        if got != tt.expected {
                                t.Errorf("normalizeRiskColor(%q, %q) = %q, want %q", tt.label, tt.color, got, tt.expected)
                        }
                })
        }
}

func TestUnmarshalResults_Empty(t *testing.T) {
        r := unmarshalResults(nil, "test")
        if r != nil {
                t.Error("expected nil for empty input")
        }
}

func TestUnmarshalResults_Valid(t *testing.T) {
        data := []byte(`{"domain": "example.com"}`)
        r := unmarshalResults(data, "test")
        if r == nil {
                t.Fatal("expected non-nil result")
        }
        if r["domain"] != "example.com" {
                t.Errorf("unexpected domain: %v", r["domain"])
        }
}

func TestUnmarshalResults_Invalid(t *testing.T) {
        data := []byte(`{invalid json}`)
        r := unmarshalResults(data, "test")
        if r != nil {
                t.Error("expected nil for invalid JSON")
        }
}

func TestExtractPostureRisk_PostureNotMap(t *testing.T) {
        results := map[string]any{"posture": "not-a-map"}
        label, _ := extractPostureRisk(results)
        if label != "Unknown" {
                t.Errorf("expected Unknown for non-map posture, got %s", label)
        }
}
