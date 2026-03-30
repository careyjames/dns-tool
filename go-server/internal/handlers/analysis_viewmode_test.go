package handlers

import (
        "context"
        "encoding/json"
        "errors"
        "html/template"
        "net/http"
        "net/http/httptest"
        "strings"
        "testing"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/dbq"

        "github.com/gin-gonic/gin"
        "github.com/jackc/pgx/v5/pgtype"
)

func newViewModeHandler(store AnalysisStore) *AnalysisHandler {
        return &AnalysisHandler{
                Config: &config.Config{
                        AppVersion:      "test",
                        MaintenanceNote: "",
                        BetaPages:       map[string]bool{},
                        SectionTuning:   map[string]string{},
                        BaseURL:         "https://test.example.com",
                },
                analysisStore: store,
        }
}

func viewModeRouter(h *AnalysisHandler) *gin.Engine {
        gin.SetMode(gin.TestMode)
        r := gin.New()
        tmpl := template.Must(template.New("").Parse(
                `{{define "index.html"}}TMPL:index{{end}}` +
                        `{{define "results.html"}}TMPL:results ReportMode={{.ReportMode}} CovertMode={{.CovertMode}}{{end}}` +
                        `{{define "results_covert.html"}}TMPL:covert ReportMode={{.ReportMode}} CovertMode={{.CovertMode}}{{end}}` +
                        `{{define "results_executive.html"}}TMPL:executive ReportMode={{.ReportMode}} CovertMode={{.CovertMode}}{{end}}` +
                        `{{define "results_zone.html"}}TMPL:zone ReportMode={{.ReportMode}} CovertMode={{.CovertMode}}{{end}}` +
                        `{{define "results_covert_zone.html"}}TMPL:covert_zone ReportMode={{.ReportMode}} CovertMode={{.CovertMode}}{{end}}`,
        ))
        r.SetHTMLTemplate(tmpl)
        return r
}

func validAnalysis(resultsJSON json.RawMessage) dbq.DomainAnalysis {
        return dbq.DomainAnalysis{
                ID:          1,
                Domain:      "example.com",
                AsciiDomain: "example.com",
                FullResults: resultsJSON,
                CreatedAt:   pgtype.Timestamp{Valid: true},
        }
}

func TestViewMode_InvalidID(t *testing.T) {
        h := newViewModeHandler(&mockAnalysisStore{})
        r := viewModeRouter(h)
        r.GET("/report/:id", func(c *gin.Context) { h.viewAnalysisWithMode(c, "E") })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/report/abc", nil)
        r.ServeHTTP(w, req)

        if w.Code != http.StatusBadRequest {
                t.Fatalf("expected 400, got %d", w.Code)
        }
}

func TestViewMode_NotFound(t *testing.T) {
        h := newViewModeHandler(&mockAnalysisStore{
                GetAnalysisByIDFn: func(ctx context.Context, id int32) (dbq.DomainAnalysis, error) {
                        return dbq.DomainAnalysis{}, errors.New("not found")
                },
        })
        r := viewModeRouter(h)
        r.GET("/report/:id", func(c *gin.Context) { h.viewAnalysisWithMode(c, "E") })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/report/999", nil)
        r.ServeHTTP(w, req)

        if w.Code != http.StatusNotFound {
                t.Fatalf("expected 404, got %d", w.Code)
        }
}

func TestViewMode_EmptyResults(t *testing.T) {
        h := newViewModeHandler(&mockAnalysisStore{
                GetAnalysisByIDFn: func(ctx context.Context, id int32) (dbq.DomainAnalysis, error) {
                        return dbq.DomainAnalysis{
                                ID: id, Domain: "example.com", AsciiDomain: "example.com",
                                FullResults: nil,
                        }, nil
                },
        })
        r := viewModeRouter(h)
        r.GET("/report/:id", func(c *gin.Context) { h.viewAnalysisWithMode(c, "E") })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/report/1", nil)
        r.ServeHTTP(w, req)

        if w.Code != http.StatusGone {
                t.Fatalf("expected 410, got %d", w.Code)
        }
}

func TestViewMode_NullResults(t *testing.T) {
        h := newViewModeHandler(&mockAnalysisStore{
                GetAnalysisByIDFn: func(ctx context.Context, id int32) (dbq.DomainAnalysis, error) {
                        return dbq.DomainAnalysis{
                                ID: id, Domain: "example.com", AsciiDomain: "example.com",
                                FullResults: json.RawMessage("null"),
                        }, nil
                },
        })
        r := viewModeRouter(h)
        r.GET("/report/:id", func(c *gin.Context) { h.viewAnalysisWithMode(c, "E") })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/report/1", nil)
        r.ServeHTTP(w, req)

        if w.Code != http.StatusGone {
                t.Fatalf("expected 410, got %d", w.Code)
        }
}

func TestViewMode_Success(t *testing.T) {
        results := map[string]any{"analysis_success": true, "_tool_version": "26.37.0", "domain": "example.com"}
        resultsJSON, _ := json.Marshal(results)
        hash := "abc123"
        a := validAnalysis(resultsJSON)
        a.PostureHash = &hash

        h := newViewModeHandler(&mockAnalysisStore{
                GetAnalysisByIDFn: func(ctx context.Context, id int32) (dbq.DomainAnalysis, error) {
                        return a, nil
                },
                GetPreviousAnalysisForDriftBeforeFn: func(ctx context.Context, arg dbq.GetPreviousAnalysisForDriftBeforeParams) (dbq.GetPreviousAnalysisForDriftBeforeRow, error) {
                        return dbq.GetPreviousAnalysisForDriftBeforeRow{}, errors.New("no previous")
                },
        })
        r := viewModeRouter(h)
        r.GET("/report/:id", func(c *gin.Context) { h.viewAnalysisWithMode(c, "E") })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/report/1", nil)
        r.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }
        body := w.Body.String()
        if !strings.Contains(body, "TMPL:results") {
                t.Errorf("expected results template for mode E, got body: %s", body)
        }
        if !strings.Contains(body, "ReportMode=E") {
                t.Errorf("expected ReportMode=E in body: %s", body)
        }
        if !strings.Contains(body, "CovertMode=false") {
                t.Errorf("expected CovertMode=false in body: %s", body)
        }
}

func TestViewMode_CovertMode(t *testing.T) {
        results := map[string]any{"analysis_success": true, "_tool_version": "26.37.0"}
        resultsJSON, _ := json.Marshal(results)

        h := newViewModeHandler(&mockAnalysisStore{
                GetAnalysisByIDFn: func(ctx context.Context, id int32) (dbq.DomainAnalysis, error) {
                        return validAnalysis(resultsJSON), nil
                },
                GetPreviousAnalysisForDriftBeforeFn: func(ctx context.Context, arg dbq.GetPreviousAnalysisForDriftBeforeParams) (dbq.GetPreviousAnalysisForDriftBeforeRow, error) {
                        return dbq.GetPreviousAnalysisForDriftBeforeRow{}, errors.New("none")
                },
        })
        r := viewModeRouter(h)
        r.GET("/report/:id", func(c *gin.Context) { h.viewAnalysisWithMode(c, "C") })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/report/1", nil)
        r.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }
        body := w.Body.String()
        if !strings.Contains(body, "TMPL:covert") {
                t.Errorf("expected covert template, got body: %s", body)
        }
        if !strings.Contains(body, "ReportMode=C") {
                t.Errorf("expected ReportMode=C in body: %s", body)
        }
        if !strings.Contains(body, "CovertMode=true") {
                t.Errorf("expected CovertMode=true in body: %s", body)
        }
}

func TestViewMode_TLDForceZone(t *testing.T) {
        results := map[string]any{"analysis_success": true, "_tool_version": "26.37.0"}
        resultsJSON, _ := json.Marshal(results)
        a := validAnalysis(resultsJSON)
        a.AsciiDomain = "com"
        a.Domain = "com"

        h := newViewModeHandler(&mockAnalysisStore{
                GetAnalysisByIDFn: func(ctx context.Context, id int32) (dbq.DomainAnalysis, error) {
                        return a, nil
                },
                GetPreviousAnalysisForDriftBeforeFn: func(ctx context.Context, arg dbq.GetPreviousAnalysisForDriftBeforeParams) (dbq.GetPreviousAnalysisForDriftBeforeRow, error) {
                        return dbq.GetPreviousAnalysisForDriftBeforeRow{}, errors.New("none")
                },
        })
        r := viewModeRouter(h)
        r.GET("/report/:id", func(c *gin.Context) { h.viewAnalysisWithMode(c, "E") })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/report/1", nil)
        r.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }
        body := w.Body.String()
        if !strings.Contains(body, "TMPL:results") {
                t.Errorf("expected results template for TLD (E→Z uses default), got body: %s", body)
        }
        if !strings.Contains(body, "ReportMode=Z") {
                t.Errorf("expected ReportMode=Z for TLD, got body: %s", body)
        }
}

func TestViewMode_PrivateRestricted(t *testing.T) {
        results := map[string]any{"analysis_success": true}
        resultsJSON, _ := json.Marshal(results)

        h := newViewModeHandler(&mockAnalysisStore{
                GetAnalysisByIDFn: func(ctx context.Context, id int32) (dbq.DomainAnalysis, error) {
                        a := validAnalysis(resultsJSON)
                        a.Private = true
                        return a, nil
                },
                CheckAnalysisOwnershipFn: func(ctx context.Context, arg dbq.CheckAnalysisOwnershipParams) (bool, error) {
                        return false, nil
                },
        })
        r := viewModeRouter(h)
        r.GET("/report/:id", func(c *gin.Context) { h.viewAnalysisWithMode(c, "E") })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/report/1", nil)
        r.ServeHTTP(w, req)

        if w.Code != http.StatusNotFound {
                t.Fatalf("expected 404 for unauthenticated private access, got %d", w.Code)
        }
}

func TestViewMode_WaitSecondsQuery(t *testing.T) {
        results := map[string]any{"analysis_success": true, "_tool_version": "26.37.0"}
        resultsJSON, _ := json.Marshal(results)

        h := newViewModeHandler(&mockAnalysisStore{
                GetAnalysisByIDFn: func(ctx context.Context, id int32) (dbq.DomainAnalysis, error) {
                        return validAnalysis(resultsJSON), nil
                },
                GetPreviousAnalysisForDriftBeforeFn: func(ctx context.Context, arg dbq.GetPreviousAnalysisForDriftBeforeParams) (dbq.GetPreviousAnalysisForDriftBeforeRow, error) {
                        return dbq.GetPreviousAnalysisForDriftBeforeRow{}, errors.New("none")
                },
        })
        r := viewModeRouter(h)
        r.GET("/report/:id", func(c *gin.Context) { h.viewAnalysisWithMode(c, "E") })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/report/1?wait_seconds=5&wait_reason=async", nil)
        r.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }
}

func TestRenderErrorPage(t *testing.T) {
        h := newViewModeHandler(&mockAnalysisStore{})
        r := viewModeRouter(h)
        r.GET("/test-error", func(c *gin.Context) {
                h.renderErrorPage(c, http.StatusTeapot, "", "", "danger", "test error message")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/test-error", nil)
        r.ServeHTTP(w, req)

        if w.Code != http.StatusTeapot {
                t.Fatalf("expected 418, got %d", w.Code)
        }
}

func TestRenderRestrictedAccess_Unauthenticated(t *testing.T) {
        h := newViewModeHandler(&mockAnalysisStore{})
        r := viewModeRouter(h)
        r.GET("/test-restricted", func(c *gin.Context) {
                h.renderRestrictedAccess(c, "", "")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/test-restricted", nil)
        r.ServeHTTP(w, req)

        if w.Code != http.StatusNotFound {
                t.Fatalf("expected 404 for unauthenticated, got %d", w.Code)
        }
}

func TestRenderRestrictedAccess_Authenticated(t *testing.T) {
        h := newViewModeHandler(&mockAnalysisStore{})
        r := viewModeRouter(h)
        r.GET("/test-restricted", func(c *gin.Context) {
                c.Set("authenticated", true)
                h.renderRestrictedAccess(c, "", "")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/test-restricted", nil)
        r.ServeHTTP(w, req)

        if w.Code != http.StatusForbidden {
                t.Fatalf("expected 403 for authenticated restricted, got %d", w.Code)
        }
}

func TestIndexFlashData(t *testing.T) {
        h := newViewModeHandler(&mockAnalysisStore{})
        c := mockGinContext()
        data := h.indexFlashData(c, "nonce-val", "csrf-val", "warning", "test message")

        if data["AppVersion"] != "test" {
                t.Errorf("expected AppVersion=test, got %v", data["AppVersion"])
        }
        if data["CspNonce"] != "nonce-val" {
                t.Errorf("expected CspNonce=nonce-val, got %v", data["CspNonce"])
        }
        flashes, ok := data["FlashMessages"].([]FlashMessage)
        if !ok || len(flashes) != 1 {
                t.Fatalf("expected 1 flash message, got %v", data["FlashMessages"])
        }
        if flashes[0].Category != "warning" || flashes[0].Message != "test message" {
                t.Errorf("unexpected flash: %+v", flashes[0])
        }
}

func TestComputeDriftFromPrev_NoChange(t *testing.T) {
        hash := "abc123"
        prev := prevAnalysisSnapshot{Hash: &hash, ID: 1}
        di := computeDriftFromPrev("abc123", prev, map[string]any{})
        if di.Detected {
                t.Error("expected no drift when hashes match")
        }
}

func TestComputeDriftFromPrev_NilHash(t *testing.T) {
        prev := prevAnalysisSnapshot{Hash: nil, ID: 1}
        di := computeDriftFromPrev("abc123", prev, map[string]any{})
        if di.Detected {
                t.Error("expected no drift when prev hash is nil")
        }
}

func TestComputeDriftFromPrev_EmptyHash(t *testing.T) {
        empty := ""
        prev := prevAnalysisSnapshot{Hash: &empty, ID: 1}
        di := computeDriftFromPrev("abc123", prev, map[string]any{})
        if di.Detected {
                t.Error("expected no drift when prev hash is empty")
        }
}

func TestComputeDriftFromPrev_Changed(t *testing.T) {
        prevHash := "old-hash"
        prev := prevAnalysisSnapshot{Hash: &prevHash, ID: 42, CreatedAtValid: true}
        di := computeDriftFromPrev("new-hash", prev, map[string]any{})
        if !di.Detected {
                t.Error("expected drift detected")
        }
        if di.PrevHash != "old-hash" {
                t.Errorf("expected prev hash old-hash, got %s", di.PrevHash)
        }
        if di.PrevID != 42 {
                t.Errorf("expected prev ID 42, got %d", di.PrevID)
        }
}

func TestComputeDriftFromPrev_WithPrevResults(t *testing.T) {
        prevHash := "old-hash"
        prevResults := map[string]any{"spf": map[string]any{"record": "v=spf1 include:old.com ~all"}}
        prevJSON, _ := json.Marshal(prevResults)
        prev := prevAnalysisSnapshot{
                Hash:        &prevHash,
                ID:          10,
                FullResults: prevJSON,
        }
        currentResults := map[string]any{"spf": map[string]any{"record": "v=spf1 include:new.com ~all"}}
        di := computeDriftFromPrev("new-hash", prev, currentResults)
        if !di.Detected {
                t.Error("expected drift detected with prev results")
        }
        _ = di.Fields
}

func TestViewAnalysisStatic_VM(t *testing.T) {
        results := map[string]any{"analysis_success": true, "_tool_version": "26.37.0"}
        resultsJSON, _ := json.Marshal(results)

        h := newViewModeHandler(&mockAnalysisStore{
                GetAnalysisByIDFn: func(ctx context.Context, id int32) (dbq.DomainAnalysis, error) {
                        return validAnalysis(resultsJSON), nil
                },
                GetPreviousAnalysisForDriftBeforeFn: func(ctx context.Context, arg dbq.GetPreviousAnalysisForDriftBeforeParams) (dbq.GetPreviousAnalysisForDriftBeforeRow, error) {
                        return dbq.GetPreviousAnalysisForDriftBeforeRow{}, errors.New("none")
                },
        })
        r := viewModeRouter(h)
        r.GET("/report/:id", h.ViewAnalysisStatic)

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/report/1", nil)
        r.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }
}

func TestViewAnalysis_VM(t *testing.T) {
        results := map[string]any{"analysis_success": true, "_tool_version": "26.37.0"}
        resultsJSON, _ := json.Marshal(results)

        h := newViewModeHandler(&mockAnalysisStore{
                GetAnalysisByIDFn: func(ctx context.Context, id int32) (dbq.DomainAnalysis, error) {
                        return validAnalysis(resultsJSON), nil
                },
                GetPreviousAnalysisForDriftBeforeFn: func(ctx context.Context, arg dbq.GetPreviousAnalysisForDriftBeforeParams) (dbq.GetPreviousAnalysisForDriftBeforeRow, error) {
                        return dbq.GetPreviousAnalysisForDriftBeforeRow{}, errors.New("none")
                },
        })
        r := viewModeRouter(h)
        r.GET("/report/:id", h.ViewAnalysis)

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/report/1", nil)
        r.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }
}

func TestViewAnalysisExecutive_VM(t *testing.T) {
        results := map[string]any{"analysis_success": true, "_tool_version": "26.37.0"}
        resultsJSON, _ := json.Marshal(results)

        h := newViewModeHandler(&mockAnalysisStore{
                GetAnalysisByIDFn: func(ctx context.Context, id int32) (dbq.DomainAnalysis, error) {
                        return validAnalysis(resultsJSON), nil
                },
                GetPreviousAnalysisForDriftBeforeFn: func(ctx context.Context, arg dbq.GetPreviousAnalysisForDriftBeforeParams) (dbq.GetPreviousAnalysisForDriftBeforeRow, error) {
                        return dbq.GetPreviousAnalysisForDriftBeforeRow{}, errors.New("none")
                },
        })
        r := viewModeRouter(h)
        r.GET("/report/:id", h.ViewAnalysisExecutive)

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/report/1", nil)
        r.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }
}
