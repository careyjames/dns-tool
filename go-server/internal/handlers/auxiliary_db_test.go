package handlers

import (
        "context"
        "encoding/json"
        "errors"
        "net/http"
        "net/http/httptest"
        "strings"
        "testing"
        "time"

        "dnstool/go-server/internal/citation"
        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/dbq"

        "github.com/gin-gonic/gin"
        "github.com/jackc/pgx/v5/pgtype"
)

func TestProgressStore_NewToken(t *testing.T) {
        ps := &ProgressStore{}
        token, progress := ps.NewToken()
        if token == "" {
                t.Error("expected non-empty token")
        }
        if progress == nil {
                t.Fatal("expected non-nil progress")
        }
        if progress.phases == nil {
                t.Error("expected non-nil phases map")
        }
}

func TestProgressStore_GetAndUpdate(t *testing.T) {
        ps := &ProgressStore{}
        token, progress := ps.NewToken()

        progress.UpdatePhase("dns_basic", "running", 100)

        retrieved := ps.Get(token)
        if retrieved == nil {
                t.Fatal("expected non-nil progress from Get")
        }

        data := retrieved.toJSON()
        phases, ok := data["phases"].(map[string]any)
        if !ok {
                t.Fatal("expected phases in JSON output")
        }
        dnsBasic, ok := phases["dns_basic"].(map[string]any)
        if !ok {
                t.Fatal("expected dns_basic phase in output")
        }
        if dnsBasic["status"] != "running" {
                t.Errorf("dns_basic status = %v, want running", dnsBasic["status"])
        }
}

func TestProgressStore_GetMissing(t *testing.T) {
        ps := &ProgressStore{}
        got := ps.Get("nonexistent-token")
        if got != nil {
                t.Error("expected nil for missing token")
        }
}

func TestProgressStore_CloseStopsCleanup(t *testing.T) {
        ps := NewProgressStore()
        token, _ := ps.NewToken()
        if ps.Get(token) == nil {
                t.Fatal("expected non-nil progress before close")
        }
        ps.Close()
        ps.Close()
}

func TestAnalysisHandler_Close(t *testing.T) {
        h := &AnalysisHandler{
                ProgressStore: NewProgressStore(),
        }
        h.Close()
        h.Close()
}

func TestAnalysisHandler_Close_NilStore(t *testing.T) {
        h := &AnalysisHandler{}
        h.Close()
}

func TestProgressStore_Close_ZeroValue(t *testing.T) {
        ps := &ProgressStore{}
        ps.Close()
}

func TestProgressStore_LifecyclePendingRunningDone(t *testing.T) {
        ps := &ProgressStore{}
        _, progress := ps.NewToken()

        data := progress.toJSON()
        phases := data["phases"].(map[string]any)
        dns := phases["dns_records"].(map[string]any)
        if dns["status"] != "pending" {
                t.Errorf("initial dns_records status = %v, want pending", dns["status"])
        }

        time.Sleep(2 * time.Millisecond)
        progress.UpdatePhase("dns_records", "running", 0)
        data = progress.toJSON()
        phases = data["phases"].(map[string]any)
        dns = phases["dns_records"].(map[string]any)
        if dns["status"] != "running" {
                t.Errorf("after running signal, dns_records status = %v, want running", dns["status"])
        }
        startedAt, _ := dns["started_at_ms"].(int)
        if startedAt == 0 {
                startedAtF, _ := dns["started_at_ms"].(float64)
                if startedAtF == 0 {
                        t.Error("started_at_ms should be > 0 after running signal with delay")
                }
        }

        time.Sleep(2 * time.Millisecond)
        progress.UpdatePhase("dns_records", "done", 100)
        progress.UpdatePhase("dns_records", "done", 200)
        progress.UpdatePhase("dns_records", "done", 150)
        data = progress.toJSON()
        phases = data["phases"].(map[string]any)
        dns = phases["dns_records"].(map[string]any)
        if dns["status"] != "done" {
                t.Errorf("after all tasks complete, dns_records status = %v, want done", dns["status"])
        }
        completedAt, _ := dns["completed_at_ms"].(int)
        if completedAt == 0 {
                completedAtF, _ := dns["completed_at_ms"].(float64)
                if completedAtF == 0 {
                        t.Error("completed_at_ms should be > 0 when done with delay")
                }
        }
}

func TestProgressStore_MakeProgressCallback(t *testing.T) {
        ps := &ProgressStore{}
        _, progress := ps.NewToken()

        cb := progress.MakeProgressCallback()
        cb("dns_records", "running", 0)

        data := progress.toJSON()
        phases := data["phases"].(map[string]any)
        dns := phases["dns_records"].(map[string]any)
        if dns["status"] != "running" {
                t.Errorf("callback running: dns_records status = %v, want running", dns["status"])
        }

        cb("dns_records", "done", 200)
        cb("dns_records", "done", 300)
        cb("dns_records", "done", 100)

        data = progress.toJSON()
        phases = data["phases"].(map[string]any)
        dns = phases["dns_records"].(map[string]any)
        if dns["status"] != "done" {
                t.Errorf("callback done: dns_records status = %v, want done", dns["status"])
        }
}

func TestScanProgressHandler_NotFound(t *testing.T) {
        ps := &ProgressStore{}

        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/scan/progress/unknown-token", nil)
        c.Params = gin.Params{{Key: "token", Value: "unknown-token"}}

        handler := ScanProgressHandler(ps)
        handler(c)

        if w.Code != http.StatusNotFound {
                t.Errorf("expected 404, got %d", w.Code)
        }

        var body map[string]any
        if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
                t.Fatalf("failed to parse JSON: %v", err)
        }
        if _, ok := body["error"]; !ok {
                t.Error("expected error field in response")
        }
}

func TestScanProgressHandler_Success(t *testing.T) {
        ps := &ProgressStore{}
        token, progress := ps.NewToken()

        progress.UpdatePhase("dns_basic", "done", 150)

        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/scan/progress/"+token, nil)
        c.Params = gin.Params{{Key: "token", Value: token}}

        handler := ScanProgressHandler(ps)
        handler(c)

        if w.Code != http.StatusOK {
                t.Errorf("expected 200, got %d", w.Code)
        }

        var body map[string]any
        if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
                t.Fatalf("failed to parse JSON: %v", err)
        }
        if body["status"] != "running" {
                t.Errorf("status = %v, want running", body["status"])
        }
        phases, ok := body["phases"].(map[string]any)
        if !ok {
                t.Fatal("expected phases in response")
        }
        if _, ok := phases["dns_basic"]; !ok {
                t.Error("expected dns_basic in phases")
        }
}

func TestParsePageParam_Default(t *testing.T) {
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
        if got := parsePageParam(c); got != 1 {
                t.Errorf("parsePageParam() = %d, want 1", got)
        }
}

func TestParsePageParam_Valid(t *testing.T) {
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/?page=3", nil)
        if got := parsePageParam(c); got != 3 {
                t.Errorf("parsePageParam() = %d, want 3", got)
        }
}

func TestParsePageParam_Invalid(t *testing.T) {
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/?page=abc", nil)
        if got := parsePageParam(c); got != 1 {
                t.Errorf("parsePageParam() = %d, want 1", got)
        }
}

func TestParsePageParam_Negative(t *testing.T) {
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/?page=-1", nil)
        if got := parsePageParam(c); got != 1 {
                t.Errorf("parsePageParam() = %d, want 1", got)
        }
}

func TestConvertAuditRows_Empty(t *testing.T) {
        entries := convertAuditRows([]dbq.ListHashedAnalysesRow{})
        if len(entries) != 0 {
                t.Errorf("expected 0 entries, got %d", len(entries))
        }
}

func TestConvertAuditRows_WithData(t *testing.T) {
        hash := "sha256:abcdef1234567890"
        now := time.Now()
        rows := []dbq.ListHashedAnalysesRow{
                {
                        ID:          42,
                        Domain:      "example.com",
                        PostureHash: &hash,
                        CreatedAt:   pgtype.Timestamp{Time: now, Valid: true},
                },
                {
                        ID:          43,
                        Domain:      "test.org",
                        PostureHash: nil,
                        CreatedAt:   pgtype.Timestamp{Valid: false},
                },
        }

        entries := convertAuditRows(rows)
        if len(entries) != 2 {
                t.Fatalf("expected 2 entries, got %d", len(entries))
        }

        if entries[0].ID != 42 {
                t.Errorf("entries[0].ID = %d, want 42", entries[0].ID)
        }
        if entries[0].Domain != "example.com" {
                t.Errorf("entries[0].Domain = %q", entries[0].Domain)
        }
        if entries[0].Hash != hash {
                t.Errorf("entries[0].Hash = %q, want %q", entries[0].Hash, hash)
        }
        if entries[0].Timestamp == "" {
                t.Error("entries[0].Timestamp should not be empty")
        }

        if entries[1].Hash != "" {
                t.Errorf("entries[1].Hash = %q, want empty", entries[1].Hash)
        }
        if entries[1].Timestamp != "" {
                t.Errorf("entries[1].Timestamp = %q, want empty", entries[1].Timestamp)
        }
}

type mockAuditStore struct {
        countHashedAnalysesFn func(ctx context.Context) (int64, error)
        listHashedAnalysesFn  func(ctx context.Context, arg dbq.ListHashedAnalysesParams) ([]dbq.ListHashedAnalysesRow, error)
}

func (m *mockAuditStore) CountHashedAnalyses(ctx context.Context) (int64, error) {
        if m.countHashedAnalysesFn != nil {
                return m.countHashedAnalysesFn(ctx)
        }
        return 0, nil
}

func (m *mockAuditStore) ListHashedAnalyses(ctx context.Context, arg dbq.ListHashedAnalysesParams) ([]dbq.ListHashedAnalysesRow, error) {
        if m.listHashedAnalysesFn != nil {
                return m.listHashedAnalysesFn(ctx, arg)
        }
        return nil, nil
}

func TestLoadAuditData_NilDB(t *testing.T) {
        h := &ConfidenceHandler{
                Config: &config.Config{},
        }

        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/?page=1", nil)

        data, page := h.loadAuditData(c, 1)
        if data == nil {
                t.Fatal("expected non-nil audit data")
        }
        if page != 1 {
                t.Errorf("page = %d, want 1", page)
        }
        if len(data.Entries) != 0 {
                t.Errorf("expected 0 entries, got %d", len(data.Entries))
        }
}

func TestLoadAuditData_WithData(t *testing.T) {
        hash := "testhash"
        now := time.Now()
        mock := &mockAuditStore{
                countHashedAnalysesFn: func(ctx context.Context) (int64, error) {
                        return 120, nil
                },
                listHashedAnalysesFn: func(ctx context.Context, arg dbq.ListHashedAnalysesParams) ([]dbq.ListHashedAnalysesRow, error) {
                        return []dbq.ListHashedAnalysesRow{
                                {ID: 1, Domain: "example.com", PostureHash: &hash, CreatedAt: pgtype.Timestamp{Time: now, Valid: true}},
                        }, nil
                },
        }

        h := &ConfidenceHandler{
                Config:     &config.Config{},
                auditStore: mock,
        }

        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/?page=1", nil)

        data, page := h.loadAuditData(c, 1)
        if data == nil {
                t.Fatal("expected non-nil audit data")
        }
        if page != 1 {
                t.Errorf("page = %d, want 1", page)
        }
        if data.Total != 120 {
                t.Errorf("Total = %d, want 120", data.Total)
        }
        if data.TotalPages != 3 {
                t.Errorf("TotalPages = %d, want 3", data.TotalPages)
        }
        if len(data.Entries) != 1 {
                t.Errorf("expected 1 entry, got %d", len(data.Entries))
        }
        if !data.HasNext {
                t.Error("expected HasNext = true")
        }
        if data.HasPrev {
                t.Error("expected HasPrev = false for page 1")
        }
}

type mockLookupStore struct {
        GetAnalysisByIDFn          func(ctx context.Context, id int32) (dbq.DomainAnalysis, error)
        CheckAnalysisOwnershipFn   func(ctx context.Context, arg dbq.CheckAnalysisOwnershipParams) (bool, error)
        GetRecentAnalysisByDomainFn func(ctx context.Context, domain string) (dbq.DomainAnalysis, error)
}

func (m *mockLookupStore) GetAnalysisByID(ctx context.Context, id int32) (dbq.DomainAnalysis, error) {
        if m.GetAnalysisByIDFn != nil {
                return m.GetAnalysisByIDFn(ctx, id)
        }
        return dbq.DomainAnalysis{}, errors.New("not found")
}

func (m *mockLookupStore) CheckAnalysisOwnership(ctx context.Context, arg dbq.CheckAnalysisOwnershipParams) (bool, error) {
        if m.CheckAnalysisOwnershipFn != nil {
                return m.CheckAnalysisOwnershipFn(ctx, arg)
        }
        return false, nil
}

func (m *mockLookupStore) GetRecentAnalysisByDomain(ctx context.Context, domain string) (dbq.DomainAnalysis, error) {
        if m.GetRecentAnalysisByDomainFn != nil {
                return m.GetRecentAnalysisByDomainFn(ctx, domain)
        }
        return dbq.DomainAnalysis{}, errors.New("not found")
}

func TestBadgeResolveAnalysis_MissingParams(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/badge", nil)

        h := &BadgeHandler{
                Config:      &config.Config{},
                lookupStore: &mockLookupStore{},
        }

        _, _, _, _, _, ok := h.resolveAnalysis(c)
        if ok {
                t.Error("expected ok=false when no domain or id param")
        }
        if w.Code != http.StatusBadRequest {
                t.Errorf("expected 400, got %d", w.Code)
        }
}

func TestBadgeResolveAnalysis_InvalidID(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/badge?id=abc", nil)

        h := &BadgeHandler{
                Config:      &config.Config{},
                lookupStore: &mockLookupStore{},
        }

        _, _, _, _, _, ok := h.resolveAnalysis(c)
        if ok {
                t.Error("expected ok=false for invalid id")
        }
        if w.Code != http.StatusBadRequest {
                t.Errorf("expected 400, got %d", w.Code)
        }
}

func TestBadgeResolveAnalysis_ByIDNotFound(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/badge?id=999", nil)

        h := &BadgeHandler{
                Config:      &config.Config{},
                lookupStore: &mockLookupStore{},
        }

        _, _, _, _, _, ok := h.resolveAnalysis(c)
        if ok {
                t.Error("expected ok=false for not-found id")
        }
        if w.Code != http.StatusNotFound {
                t.Errorf("expected 404, got %d", w.Code)
        }
}

func TestBadgeResolveAnalysis_ByIDPrivate(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/badge?id=1", nil)

        mock := &mockLookupStore{
                GetAnalysisByIDFn: func(ctx context.Context, id int32) (dbq.DomainAnalysis, error) {
                        return dbq.DomainAnalysis{ID: 1, Private: true}, nil
                },
        }
        h := &BadgeHandler{
                Config:      &config.Config{},
                lookupStore: mock,
        }

        _, _, _, _, _, ok := h.resolveAnalysis(c)
        if ok {
                t.Error("expected ok=false for private analysis badge")
        }
}

func TestBadgeResolveAnalysis_ByIDSuccess(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/badge?id=1", nil)

        mock := &mockLookupStore{
                GetAnalysisByIDFn: func(ctx context.Context, id int32) (dbq.DomainAnalysis, error) {
                        return dbq.DomainAnalysis{
                                ID:          1,
                                Domain:      "example.com",
                                FullResults: json.RawMessage(`{"spf_analysis":{"status":"pass"}}`),
                                CreatedAt:   pgtype.Timestamp{Time: time.Now(), Valid: true},
                        }, nil
                },
        }
        h := &BadgeHandler{
                Config:      &config.Config{},
                lookupStore: mock,
        }

        domain, results, _, scanID, _, ok := h.resolveAnalysis(c)
        if !ok {
                t.Error("expected ok=true for valid analysis")
        }
        if domain != "example.com" {
                t.Errorf("expected domain=example.com, got %s", domain)
        }
        if results == nil {
                t.Error("expected non-nil results")
        }
        if scanID != 1 {
                t.Errorf("expected scanID=1, got %d", scanID)
        }
}

func TestBadgeResolveAnalysis_ByDomainInvalid(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/badge?domain=not..valid", nil)

        h := &BadgeHandler{
                Config:      &config.Config{},
                lookupStore: &mockLookupStore{},
        }

        _, _, _, _, _, ok := h.resolveAnalysis(c)
        if ok {
                t.Error("expected ok=false for invalid domain")
        }
}

func TestBadgeResolveAnalysis_ByDomainNotScanned(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/badge?domain=example.com", nil)

        h := &BadgeHandler{
                Config:      &config.Config{},
                lookupStore: &mockLookupStore{},
        }

        _, _, _, _, _, ok := h.resolveAnalysis(c)
        if ok {
                t.Error("expected ok=false for not-scanned domain")
        }
}

func TestBadgeResolveAnalysis_ByDomainSuccess(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/badge?domain=example.com", nil)

        mock := &mockLookupStore{
                GetRecentAnalysisByDomainFn: func(ctx context.Context, domain string) (dbq.DomainAnalysis, error) {
                        return dbq.DomainAnalysis{
                                ID:          5,
                                Domain:      "example.com",
                                FullResults: json.RawMessage(`{"dmarc_analysis":{"policy":"reject"}}`),
                                CreatedAt:   pgtype.Timestamp{Time: time.Now(), Valid: true},
                        }, nil
                },
        }
        h := &BadgeHandler{
                Config:      &config.Config{},
                lookupStore: mock,
        }

        domain, results, _, scanID, _, ok := h.resolveAnalysis(c)
        if !ok {
                t.Error("expected ok=true")
        }
        if domain != "example.com" {
                t.Errorf("expected example.com, got %s", domain)
        }
        if results == nil {
                t.Error("expected non-nil results")
        }
        if scanID != 5 {
                t.Errorf("expected scanID=5, got %d", scanID)
        }
}

func TestCitationAuthorities_Unfiltered(t *testing.T) {
        gin.SetMode(gin.TestMode)
        reg := citation.Global()
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/api/authorities", nil)

        h := &CitationHandler{
                Config:   &config.Config{},
                Registry: reg,
        }

        h.Authorities(c)
        if w.Code != http.StatusOK {
                t.Errorf("expected 200, got %d", w.Code)
        }
        var resp map[string]interface{}
        if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
                t.Fatalf("invalid JSON response: %v", err)
        }
        if _, ok := resp["count"]; !ok {
                t.Error("expected count field in response")
        }
        if _, ok := resp["entries"]; !ok {
                t.Error("expected entries field in response")
        }
}

func TestCitationAuthorities_Filtered(t *testing.T) {
        gin.SetMode(gin.TestMode)
        reg := citation.Global()
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/api/authorities?type=RFC&area=email", nil)

        h := &CitationHandler{
                Config:   &config.Config{},
                Registry: reg,
        }

        h.Authorities(c)
        if w.Code != http.StatusOK {
                t.Errorf("expected 200, got %d", w.Code)
        }
}

func TestCitationSoftwareCitation_BibTeX(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/api/citation?format=bibtex", nil)

        h := &CitationHandler{
                Config:   &config.Config{AppVersion: "1.0.0"},
                Registry: citation.Global(),
        }

        h.SoftwareCitation(c)
        if w.Code != http.StatusOK {
                t.Errorf("expected 200, got %d", w.Code)
        }
        body := w.Body.String()
        if !strings.Contains(body, "@software") {
                t.Error("expected BibTeX @software entry")
        }
}

func TestCitationSoftwareCitation_RIS(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/api/citation?format=ris", nil)

        h := &CitationHandler{
                Config:   &config.Config{AppVersion: "1.0.0"},
                Registry: citation.Global(),
        }

        h.SoftwareCitation(c)
        if w.Code != http.StatusOK {
                t.Errorf("expected 200, got %d", w.Code)
        }
        body := w.Body.String()
        if !strings.Contains(body, "TY  - COMP") {
                t.Error("expected RIS TY - COMP entry")
        }
}

func TestCitationSoftwareCitation_CSLJSON(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/api/citation?format=csljson", nil)

        h := &CitationHandler{
                Config:   &config.Config{AppVersion: "1.0.0"},
                Registry: citation.Global(),
        }

        h.SoftwareCitation(c)
        if w.Code != http.StatusOK {
                t.Errorf("expected 200, got %d", w.Code)
        }
}

func TestCitationSoftwareCitation_InvalidFormat(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/api/citation?format=invalid", nil)

        h := &CitationHandler{
                Config:   &config.Config{AppVersion: "1.0.0"},
                Registry: citation.Global(),
        }

        h.SoftwareCitation(c)
        if w.Code != http.StatusBadRequest {
                t.Errorf("expected 400, got %d", w.Code)
        }
}

func TestAnalysisCitation_InvalidID(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/api/citation/abc", nil)
        c.Params = gin.Params{{Key: "id", Value: "abc"}}

        h := &CitationHandler{
                Config:      &config.Config{},
                Registry:    citation.Global(),
                lookupStore: &mockLookupStore{},
        }

        h.AnalysisCitation(c)
        if w.Code != http.StatusBadRequest {
                t.Errorf("expected 400, got %d", w.Code)
        }
}

func TestAnalysisCitation_NotFound(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/api/citation/999?format=bibtex", nil)
        c.Params = gin.Params{{Key: "id", Value: "999"}}

        h := &CitationHandler{
                Config:      &config.Config{},
                Registry:    citation.Global(),
                lookupStore: &mockLookupStore{},
        }

        h.AnalysisCitation(c)
        if w.Code != http.StatusNotFound {
                t.Errorf("expected 404, got %d", w.Code)
        }
}

func TestAnalysisCitation_PublicSuccess(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/api/citation/1?format=bibtex", nil)
        c.Params = gin.Params{{Key: "id", Value: "1"}}

        mock := &mockLookupStore{
                GetAnalysisByIDFn: func(ctx context.Context, id int32) (dbq.DomainAnalysis, error) {
                        return dbq.DomainAnalysis{
                                ID:          1,
                                Domain:      "example.com",
                                Private:     false,
                                FullResults: json.RawMessage(`{"spf_analysis":{"status":"pass"}}`),
                        }, nil
                },
        }
        h := &CitationHandler{
                Config:      &config.Config{AppVersion: "1.0.0"},
                Registry:    citation.Global(),
                lookupStore: mock,
        }

        h.AnalysisCitation(c)
        if w.Code != http.StatusOK {
                t.Errorf("expected 200, got %d", w.Code)
        }
        body := w.Body.String()
        if !strings.Contains(body, "@") {
                t.Error("expected BibTeX content in response")
        }
}

func TestAnalysisCitation_PrivateNoAuth(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/api/citation/1?format=csljson", nil)
        c.Params = gin.Params{{Key: "id", Value: "1"}}

        mock := &mockLookupStore{
                GetAnalysisByIDFn: func(ctx context.Context, id int32) (dbq.DomainAnalysis, error) {
                        return dbq.DomainAnalysis{ID: 1, Private: true}, nil
                },
        }
        h := &CitationHandler{
                Config:      &config.Config{},
                Registry:    citation.Global(),
                lookupStore: mock,
        }

        h.AnalysisCitation(c)
        if w.Code != http.StatusNotFound {
                t.Errorf("expected 404 for private citation without auth, got %d", w.Code)
        }
}

func TestAnalysisCitation_PrivateOwner(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/api/citation/1?format=ris", nil)
        c.Params = gin.Params{{Key: "id", Value: "1"}}
        c.Set(mapKeyAuthenticated, true)
        c.Set(mapKeyUserId, int32(42))

        mock := &mockLookupStore{
                GetAnalysisByIDFn: func(ctx context.Context, id int32) (dbq.DomainAnalysis, error) {
                        return dbq.DomainAnalysis{
                                ID:          1,
                                Private:     true,
                                FullResults: json.RawMessage(`{}`),
                        }, nil
                },
                CheckAnalysisOwnershipFn: func(ctx context.Context, arg dbq.CheckAnalysisOwnershipParams) (bool, error) {
                        if arg.UserID == 42 && arg.AnalysisID == 1 {
                                return true, nil
                        }
                        return false, nil
                },
        }
        h := &CitationHandler{
                Config:      &config.Config{AppVersion: "1.0.0"},
                Registry:    citation.Global(),
                lookupStore: mock,
        }

        h.AnalysisCitation(c)
        if w.Code != http.StatusOK {
                t.Errorf("expected 200 for private citation by owner, got %d", w.Code)
        }
}

func TestRecordDailyStats_NilExecer(t *testing.T) {
        h := &AnalysisHandler{
                Config: &config.Config{},
        }
        h.recordDailyStats(true, 1.5)
}
