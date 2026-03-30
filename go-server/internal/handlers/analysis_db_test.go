package handlers

import (
        "context"
        "encoding/json"
        "errors"
        "net/http"
        "net/http/httptest"
        "strings"
        "sync"
        "sync/atomic"
        "testing"
        "time"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/dbq"

        "github.com/gin-gonic/gin"
        "github.com/jackc/pgx/v5/pgconn"
        "github.com/jackc/pgx/v5/pgtype"
)

type mockAnalysisStore struct {
        InsertAnalysisFn                  func(ctx context.Context, arg dbq.InsertAnalysisParams) (dbq.InsertAnalysisRow, error)
        UpsertDomainIndexFn               func(ctx context.Context, arg dbq.UpsertDomainIndexParams) error
        GetPreviousAnalysisForDriftFn     func(ctx context.Context, domain string) (dbq.GetPreviousAnalysisForDriftRow, error)
        GetPreviousAnalysisForDriftBeforeFn func(ctx context.Context, arg dbq.GetPreviousAnalysisForDriftBeforeParams) (dbq.GetPreviousAnalysisForDriftBeforeRow, error)
        InsertDriftEventFn                func(ctx context.Context, arg dbq.InsertDriftEventParams) (dbq.InsertDriftEventRow, error)
        ListEndpointsForWatchedDomainFn   func(ctx context.Context, domain string) ([]dbq.ListEndpointsForWatchedDomainRow, error)
        InsertDriftNotificationFn         func(ctx context.Context, arg dbq.InsertDriftNotificationParams) (int32, error)
        InsertPhaseTelemetryFn            func(ctx context.Context, arg dbq.InsertPhaseTelemetryParams) error
        InsertTelemetryHashFn             func(ctx context.Context, arg dbq.InsertTelemetryHashParams) error
        InsertUserAnalysisFn              func(ctx context.Context, arg dbq.InsertUserAnalysisParams) error
        UpdateWaybackURLFn                func(ctx context.Context, arg dbq.UpdateWaybackURLParams) error
        CountHashedAnalysesFn             func(ctx context.Context) (int64, error)
        ListHashedAnalysesFn              func(ctx context.Context, arg dbq.ListHashedAnalysesParams) ([]dbq.ListHashedAnalysesRow, error)
        GetAnalysisByIDFn                 func(ctx context.Context, id int32) (dbq.DomainAnalysis, error)
        CheckAnalysisOwnershipFn          func(ctx context.Context, arg dbq.CheckAnalysisOwnershipParams) (bool, error)
        GetRecentAnalysisByDomainFn       func(ctx context.Context, domain string) (dbq.DomainAnalysis, error)
}

func (m *mockAnalysisStore) InsertAnalysis(ctx context.Context, arg dbq.InsertAnalysisParams) (dbq.InsertAnalysisRow, error) {
        if m.InsertAnalysisFn != nil {
                return m.InsertAnalysisFn(ctx, arg)
        }
        return dbq.InsertAnalysisRow{}, nil
}

func (m *mockAnalysisStore) UpsertDomainIndex(ctx context.Context, arg dbq.UpsertDomainIndexParams) error {
        if m.UpsertDomainIndexFn != nil {
                return m.UpsertDomainIndexFn(ctx, arg)
        }
        return nil
}

func (m *mockAnalysisStore) GetPreviousAnalysisForDrift(ctx context.Context, domain string) (dbq.GetPreviousAnalysisForDriftRow, error) {
        if m.GetPreviousAnalysisForDriftFn != nil {
                return m.GetPreviousAnalysisForDriftFn(ctx, domain)
        }
        return dbq.GetPreviousAnalysisForDriftRow{}, nil
}

func (m *mockAnalysisStore) GetPreviousAnalysisForDriftBefore(ctx context.Context, arg dbq.GetPreviousAnalysisForDriftBeforeParams) (dbq.GetPreviousAnalysisForDriftBeforeRow, error) {
        if m.GetPreviousAnalysisForDriftBeforeFn != nil {
                return m.GetPreviousAnalysisForDriftBeforeFn(ctx, arg)
        }
        return dbq.GetPreviousAnalysisForDriftBeforeRow{}, nil
}

func (m *mockAnalysisStore) InsertDriftEvent(ctx context.Context, arg dbq.InsertDriftEventParams) (dbq.InsertDriftEventRow, error) {
        if m.InsertDriftEventFn != nil {
                return m.InsertDriftEventFn(ctx, arg)
        }
        return dbq.InsertDriftEventRow{}, nil
}

func (m *mockAnalysisStore) ListEndpointsForWatchedDomain(ctx context.Context, domain string) ([]dbq.ListEndpointsForWatchedDomainRow, error) {
        if m.ListEndpointsForWatchedDomainFn != nil {
                return m.ListEndpointsForWatchedDomainFn(ctx, domain)
        }
        return nil, nil
}

func (m *mockAnalysisStore) InsertDriftNotification(ctx context.Context, arg dbq.InsertDriftNotificationParams) (int32, error) {
        if m.InsertDriftNotificationFn != nil {
                return m.InsertDriftNotificationFn(ctx, arg)
        }
        return 0, nil
}

func (m *mockAnalysisStore) InsertPhaseTelemetry(ctx context.Context, arg dbq.InsertPhaseTelemetryParams) error {
        if m.InsertPhaseTelemetryFn != nil {
                return m.InsertPhaseTelemetryFn(ctx, arg)
        }
        return nil
}

func (m *mockAnalysisStore) InsertTelemetryHash(ctx context.Context, arg dbq.InsertTelemetryHashParams) error {
        if m.InsertTelemetryHashFn != nil {
                return m.InsertTelemetryHashFn(ctx, arg)
        }
        return nil
}

func (m *mockAnalysisStore) InsertUserAnalysis(ctx context.Context, arg dbq.InsertUserAnalysisParams) error {
        if m.InsertUserAnalysisFn != nil {
                return m.InsertUserAnalysisFn(ctx, arg)
        }
        return nil
}

func (m *mockAnalysisStore) UpdateWaybackURL(ctx context.Context, arg dbq.UpdateWaybackURLParams) error {
        if m.UpdateWaybackURLFn != nil {
                return m.UpdateWaybackURLFn(ctx, arg)
        }
        return nil
}

func (m *mockAnalysisStore) CountHashedAnalyses(ctx context.Context) (int64, error) {
        if m.CountHashedAnalysesFn != nil {
                return m.CountHashedAnalysesFn(ctx)
        }
        return 0, nil
}

func (m *mockAnalysisStore) ListHashedAnalyses(ctx context.Context, arg dbq.ListHashedAnalysesParams) ([]dbq.ListHashedAnalysesRow, error) {
        if m.ListHashedAnalysesFn != nil {
                return m.ListHashedAnalysesFn(ctx, arg)
        }
        return nil, nil
}

func (m *mockAnalysisStore) GetAnalysisByID(ctx context.Context, id int32) (dbq.DomainAnalysis, error) {
        if m.GetAnalysisByIDFn != nil {
                return m.GetAnalysisByIDFn(ctx, id)
        }
        return dbq.DomainAnalysis{}, nil
}

func (m *mockAnalysisStore) CheckAnalysisOwnership(ctx context.Context, arg dbq.CheckAnalysisOwnershipParams) (bool, error) {
        if m.CheckAnalysisOwnershipFn != nil {
                return m.CheckAnalysisOwnershipFn(ctx, arg)
        }
        return false, nil
}

func (m *mockAnalysisStore) GetRecentAnalysisByDomain(ctx context.Context, domain string) (dbq.DomainAnalysis, error) {
        if m.GetRecentAnalysisByDomainFn != nil {
                return m.GetRecentAnalysisByDomainFn(ctx, domain)
        }
        return dbq.DomainAnalysis{}, nil
}

type mockStatsExecer struct {
        ExecFn func(ctx context.Context, sql string, arguments ...interface{}) (pgconn.CommandTag, error)
}

func (m *mockStatsExecer) Exec(ctx context.Context, sql string, arguments ...interface{}) (pgconn.CommandTag, error) {
        if m.ExecFn != nil {
                return m.ExecFn(ctx, sql, arguments...)
        }
        return pgconn.NewCommandTag(""), nil
}

func TestSaveAnalysis_SuccessPath(t *testing.T) {
        var insertCalled atomic.Int32
        var upsertCalled atomic.Int32
        var capturedParams dbq.InsertAnalysisParams

        mock := &mockAnalysisStore{
                InsertAnalysisFn: func(ctx context.Context, arg dbq.InsertAnalysisParams) (dbq.InsertAnalysisRow, error) {
                        insertCalled.Add(1)
                        capturedParams = arg
                        return dbq.InsertAnalysisRow{
                                ID: 42,
                                CreatedAt: pgtype.Timestamp{
                                        Time:  time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
                                        Valid: true,
                                },
                        }, nil
                },
                UpsertDomainIndexFn: func(ctx context.Context, arg dbq.UpsertDomainIndexParams) error {
                        upsertCalled.Add(1)
                        return nil
                },
        }

        h := &AnalysisHandler{
                Config:        &config.Config{AppVersion: "test-v1"},
                analysisStore: mock,
        }

        ctx := context.Background()
        id, ts := h.saveAnalysis(ctx, saveAnalysisInput{
                domain:      "example.com",
                asciiDomain: "example.com",
                results:     map[string]any{"domain_exists": true},
                duration:    1.5,
                countryCode: "US",
                countryName: "United States",
        })

        if id != 42 {
                t.Errorf("expected analysisID=42, got %d", id)
        }
        if ts == "" {
                t.Error("expected non-empty timestamp")
        }
        if insertCalled.Load() != 1 {
                t.Errorf("InsertAnalysis called %d times, want 1", insertCalled.Load())
        }
        if capturedParams.Domain != "example.com" {
                t.Errorf("InsertAnalysis domain=%q, want %q", capturedParams.Domain, "example.com")
        }
        if capturedParams.AsciiDomain != "example.com" {
                t.Errorf("InsertAnalysis ascii_domain=%q, want %q", capturedParams.AsciiDomain, "example.com")
        }

        time.Sleep(100 * time.Millisecond)
        if upsertCalled.Load() < 1 {
                t.Error("UpsertDomainIndex should be called for successful analyses")
        }
}

func TestSaveAnalysis_InsertError(t *testing.T) {
        mock := &mockAnalysisStore{
                InsertAnalysisFn: func(ctx context.Context, arg dbq.InsertAnalysisParams) (dbq.InsertAnalysisRow, error) {
                        return dbq.InsertAnalysisRow{}, errors.New("db connection refused")
                },
        }

        h := &AnalysisHandler{
                Config:        &config.Config{AppVersion: "test-v1"},
                analysisStore: mock,
        }

        id, ts := h.saveAnalysis(context.Background(), saveAnalysisInput{
                domain:      "fail.example",
                asciiDomain: "fail.example",
                results:     map[string]any{"domain_exists": true},
                duration:    0.5,
        })

        if id != 0 {
                t.Errorf("expected ID=0 on insert error, got %d", id)
        }
        if ts == "" {
                t.Error("expected non-empty timestamp even on error")
        }
        _, err := time.Parse("2006-01-02 15:04:05 UTC", ts)
        if err != nil {
                t.Errorf("timestamp not in expected format: %v", err)
        }
}

func TestDetectHistoricalDrift_NoPrevious(t *testing.T) {
        mock := &mockAnalysisStore{
                GetPreviousAnalysisForDriftBeforeFn: func(ctx context.Context, arg dbq.GetPreviousAnalysisForDriftBeforeParams) (dbq.GetPreviousAnalysisForDriftBeforeRow, error) {
                        return dbq.GetPreviousAnalysisForDriftBeforeRow{}, errors.New("no rows")
                },
        }

        h := &AnalysisHandler{
                Config:        &config.Config{},
                analysisStore: mock,
        }

        drift := h.detectHistoricalDrift(context.Background(), "abc123hash", "example.com", 10, map[string]any{})

        if drift.Detected {
                t.Error("expected Detected=false when no previous analysis")
        }
        if drift.PrevID != 0 {
                t.Errorf("expected PrevID=0, got %d", drift.PrevID)
        }
        if drift.PrevHash != "" {
                t.Errorf("expected empty PrevHash, got %q", drift.PrevHash)
        }
}

func TestDetectHistoricalDrift_DriftDetected(t *testing.T) {
        prevHash := "oldhash123456789"
        currentHash := "newhash987654321"
        prevResults := map[string]any{
                "spf_analysis": map[string]any{"status": "pass"},
        }
        prevJSON, _ := json.Marshal(prevResults)

        mock := &mockAnalysisStore{
                GetPreviousAnalysisForDriftBeforeFn: func(ctx context.Context, arg dbq.GetPreviousAnalysisForDriftBeforeParams) (dbq.GetPreviousAnalysisForDriftBeforeRow, error) {
                        return dbq.GetPreviousAnalysisForDriftBeforeRow{
                                ID:          5,
                                PostureHash: &prevHash,
                                FullResults: prevJSON,
                                CreatedAt: pgtype.Timestamp{
                                        Time:  time.Date(2025, 1, 10, 8, 0, 0, 0, time.UTC),
                                        Valid: true,
                                },
                        }, nil
                },
        }

        h := &AnalysisHandler{
                Config:        &config.Config{},
                analysisStore: mock,
        }

        currentResults := map[string]any{
                "spf_analysis": map[string]any{"status": "fail"},
        }
        drift := h.detectHistoricalDrift(context.Background(), currentHash, "example.com", 10, currentResults)

        if !drift.Detected {
                t.Error("expected Detected=true when hashes differ")
        }
        if drift.PrevID != 5 {
                t.Errorf("expected PrevID=5, got %d", drift.PrevID)
        }
        if drift.PrevHash != prevHash {
                t.Errorf("expected PrevHash=%q, got %q", prevHash, drift.PrevHash)
        }
        if drift.PrevTime == "" {
                t.Error("expected PrevTime to be set")
        }
}

func TestDetectHistoricalDrift_NoDrift(t *testing.T) {
        sameHash := "samehash123456789"

        mock := &mockAnalysisStore{
                GetPreviousAnalysisForDriftBeforeFn: func(ctx context.Context, arg dbq.GetPreviousAnalysisForDriftBeforeParams) (dbq.GetPreviousAnalysisForDriftBeforeRow, error) {
                        return dbq.GetPreviousAnalysisForDriftBeforeRow{
                                ID:          5,
                                PostureHash: &sameHash,
                                CreatedAt: pgtype.Timestamp{
                                        Time:  time.Date(2025, 1, 10, 8, 0, 0, 0, time.UTC),
                                        Valid: true,
                                },
                        }, nil
                },
        }

        h := &AnalysisHandler{
                Config:        &config.Config{},
                analysisStore: mock,
        }

        drift := h.detectHistoricalDrift(context.Background(), sameHash, "example.com", 10, map[string]any{})

        if drift.Detected {
                t.Error("expected Detected=false when hashes match")
        }
}

func TestPersistDriftEvent_SuccessAndNotify(t *testing.T) {
        var notifMu sync.Mutex
        var notifCalls []dbq.InsertDriftNotificationParams

        mock := &mockAnalysisStore{
                InsertDriftEventFn: func(ctx context.Context, arg dbq.InsertDriftEventParams) (dbq.InsertDriftEventRow, error) {
                        return dbq.InsertDriftEventRow{
                                ID: 99,
                                CreatedAt: pgtype.Timestamp{
                                        Time:  time.Now(),
                                        Valid: true,
                                },
                        }, nil
                },
                ListEndpointsForWatchedDomainFn: func(ctx context.Context, domain string) ([]dbq.ListEndpointsForWatchedDomainRow, error) {
                        return []dbq.ListEndpointsForWatchedDomainRow{
                                {EndpointID: 1, EndpointType: "webhook", Url: "https://hook1.example.com"},
                                {EndpointID: 2, EndpointType: "webhook", Url: "https://hook2.example.com"},
                        }, nil
                },
                InsertDriftNotificationFn: func(ctx context.Context, arg dbq.InsertDriftNotificationParams) (int32, error) {
                        notifMu.Lock()
                        notifCalls = append(notifCalls, arg)
                        notifMu.Unlock()
                        return int32(len(notifCalls)), nil
                },
        }

        h := &AnalysisHandler{
                Config:        &config.Config{},
                analysisStore: mock,
        }

        drift := driftInfo{
                Detected: true,
                PrevHash: "oldhash",
                PrevID:   5,
        }

        h.persistDriftEvent("example.com", 42, drift, "newhash")

        notifMu.Lock()
        defer notifMu.Unlock()
        if len(notifCalls) != 2 {
                t.Errorf("expected 2 InsertDriftNotification calls, got %d", len(notifCalls))
        }
        for _, nc := range notifCalls {
                if nc.DriftEventID != 99 {
                        t.Errorf("expected DriftEventID=99, got %d", nc.DriftEventID)
                }
                if nc.Status != "pending" {
                        t.Errorf("expected Status='pending', got %q", nc.Status)
                }
        }
}

func TestPersistDriftEvent_NoEndpoints(t *testing.T) {
        var notifCalled atomic.Int32

        mock := &mockAnalysisStore{
                InsertDriftEventFn: func(ctx context.Context, arg dbq.InsertDriftEventParams) (dbq.InsertDriftEventRow, error) {
                        return dbq.InsertDriftEventRow{ID: 50}, nil
                },
                ListEndpointsForWatchedDomainFn: func(ctx context.Context, domain string) ([]dbq.ListEndpointsForWatchedDomainRow, error) {
                        return nil, nil
                },
                InsertDriftNotificationFn: func(ctx context.Context, arg dbq.InsertDriftNotificationParams) (int32, error) {
                        notifCalled.Add(1)
                        return 0, nil
                },
        }

        h := &AnalysisHandler{
                Config:        &config.Config{},
                analysisStore: mock,
        }

        drift := driftInfo{
                Detected: true,
                PrevHash: "oldhash",
                PrevID:   3,
        }

        h.persistDriftEvent("nodeps.example", 10, drift, "newhash")

        if notifCalled.Load() != 0 {
                t.Errorf("InsertDriftNotification should not be called when no endpoints, got %d calls", notifCalled.Load())
        }
}

func TestQueueDriftNotifications_Multiple(t *testing.T) {
        var notifMu sync.Mutex
        var notifCalls []dbq.InsertDriftNotificationParams

        mock := &mockAnalysisStore{
                ListEndpointsForWatchedDomainFn: func(ctx context.Context, domain string) ([]dbq.ListEndpointsForWatchedDomainRow, error) {
                        return []dbq.ListEndpointsForWatchedDomainRow{
                                {EndpointID: 10, EndpointType: "webhook", Url: "https://a.example.com"},
                                {EndpointID: 20, EndpointType: "email", Url: "admin@example.com"},
                                {EndpointID: 30, EndpointType: "webhook", Url: "https://b.example.com"},
                        }, nil
                },
                InsertDriftNotificationFn: func(ctx context.Context, arg dbq.InsertDriftNotificationParams) (int32, error) {
                        notifMu.Lock()
                        notifCalls = append(notifCalls, arg)
                        notifMu.Unlock()
                        return int32(len(notifCalls)), nil
                },
        }

        h := &AnalysisHandler{
                Config:        &config.Config{},
                analysisStore: mock,
        }

        h.queueDriftNotifications("example.com", 77)

        notifMu.Lock()
        defer notifMu.Unlock()
        if len(notifCalls) != 3 {
                t.Fatalf("expected 3 InsertDriftNotification calls, got %d", len(notifCalls))
        }

        endpointIDs := map[int32]bool{}
        for _, nc := range notifCalls {
                endpointIDs[nc.EndpointID] = true
                if nc.DriftEventID != 77 {
                        t.Errorf("expected DriftEventID=77, got %d", nc.DriftEventID)
                }
        }
        for _, eid := range []int32{10, 20, 30} {
                if !endpointIDs[eid] {
                        t.Errorf("expected notification for endpoint %d", eid)
                }
        }
}

func TestRecordDailyStats_ExecCalled(t *testing.T) {
        var execCalled atomic.Int32
        var capturedSQL string
        var sqlMu sync.Mutex

        mockExec := &mockStatsExecer{
                ExecFn: func(ctx context.Context, sql string, arguments ...interface{}) (pgconn.CommandTag, error) {
                        execCalled.Add(1)
                        sqlMu.Lock()
                        capturedSQL = sql
                        sqlMu.Unlock()
                        return pgconn.NewCommandTag("INSERT 0 1"), nil
                },
        }

        h := &AnalysisHandler{
                Config:    &config.Config{},
                statsExec: mockExec,
        }

        h.recordDailyStats(true, 2.5)

        if execCalled.Load() != 1 {
                t.Errorf("Exec called %d times, want 1", execCalled.Load())
        }

        sqlMu.Lock()
        defer sqlMu.Unlock()
        if !strings.Contains(capturedSQL, "INSERT INTO analysis_stats") {
                t.Errorf("SQL should contain INSERT INTO analysis_stats, got %q", capturedSQL)
        }
        if !strings.Contains(capturedSQL, "ON CONFLICT") {
                t.Errorf("SQL should contain ON CONFLICT for upsert, got %q", capturedSQL)
        }
}

func TestBuildAnalysisJSON_ProvenanceAndHash(t *testing.T) {
        fullResults := json.RawMessage(`{"spf_analysis":{"status":"pass"}}`)
        analysis := dbq.DomainAnalysis{
                ID:          1,
                Domain:      "example.com",
                AsciiDomain: "example.com",
                FullResults: fullResults,
                CreatedAt:   pgtype.Timestamp{Time: time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC), Valid: true},
                UpdatedAt:   pgtype.Timestamp{Time: time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC), Valid: true},
                AnalysisSuccess: boolPtr(true),
                SpfStatus:   optStr("pass"),
                DmarcStatus: optStr("pass"),
                DmarcPolicy: optStr("reject"),
                DkimStatus:  optStr("pass"),
        }

        h := &AnalysisHandler{
                Config:        &config.Config{AppVersion: "26.37.11"},
                analysisStore: &mockAnalysisStore{},
        }

        jsonBytes, fileHash := h.buildAnalysisJSON(context.Background(), analysis)

        if len(jsonBytes) == 0 {
                t.Fatal("buildAnalysisJSON returned empty bytes")
        }
        if fileHash == "" {
                t.Fatal("buildAnalysisJSON returned empty hash")
        }
        if len(fileHash) != 128 {
                t.Errorf("SHA-3-512 hash should be 128 hex chars, got %d", len(fileHash))
        }

        var parsed map[string]interface{}
        if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
                t.Fatalf("buildAnalysisJSON output is not valid JSON: %v", err)
        }

        if parsed["domain"] != "example.com" {
                t.Errorf("expected domain=example.com, got %v", parsed["domain"])
        }

        provenance, ok := parsed["provenance"].(map[string]interface{})
        if !ok {
                t.Fatal("provenance field missing or not a map")
        }
        if provenance["tool_version"] != "26.37.11" {
                t.Errorf("expected tool_version=26.37.11, got %v", provenance["tool_version"])
        }
        if provenance["hash_algorithm"] != "SHA-3-512" {
                t.Errorf("expected hash_algorithm=SHA-3-512, got %v", provenance["hash_algorithm"])
        }
        if provenance["hash_standard"] != "NIST FIPS 202 (Keccak)" {
                t.Errorf("expected hash_standard=NIST FIPS 202 (Keccak), got %v", provenance["hash_standard"])
        }

        engines, ok := provenance["engines"].(map[string]interface{})
        if !ok {
                t.Fatal("engines field missing from provenance")
        }
        if _, hasICAE := engines["icae"]; !hasICAE {
                t.Error("provenance.engines should contain icae")
        }
        if _, hasICuAE := engines["icuae"]; !hasICuAE {
                t.Error("provenance.engines should contain icuae")
        }

        dec := json.NewDecoder(strings.NewReader(string(jsonBytes)))
        tok, _ := dec.Token()
        if delim, ok := tok.(json.Delim); !ok || delim != '{' {
                t.Fatal("expected JSON object opening brace")
        }
        var prevKey string
        for dec.More() {
                tok, _ = dec.Token()
                key, ok := tok.(string)
                if !ok {
                        continue
                }
                if key < prevKey {
                        t.Errorf("JSON keys not alphabetically ordered: %q came after %q", key, prevKey)
                        break
                }
                prevKey = key
                var skip json.RawMessage
                _ = dec.Decode(&skip)
        }
}

func TestBuildAnalysisJSON_Deterministic(t *testing.T) {
        analysis := dbq.DomainAnalysis{
                ID:          42,
                Domain:      "test.org",
                AsciiDomain: "test.org",
                FullResults: json.RawMessage(`{}`),
                CreatedAt:   pgtype.Timestamp{Time: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Valid: true},
                UpdatedAt:   pgtype.Timestamp{Time: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Valid: true},
        }

        h := &AnalysisHandler{
                Config:        &config.Config{AppVersion: "1.0.0"},
                analysisStore: &mockAnalysisStore{},
        }

        _, hash1 := h.buildAnalysisJSON(context.Background(), analysis)
        _, hash2 := h.buildAnalysisJSON(context.Background(), analysis)

        if hash1 != hash2 {
                t.Errorf("buildAnalysisJSON should be deterministic: hash1=%s hash2=%s", hash1, hash2)
        }
}

func TestLoadAnalysisForAPI_InvalidID(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/api/analysis/abc", nil)
        c.Params = gin.Params{{Key: "id", Value: "abc"}}

        h := &AnalysisHandler{
                Config:        &config.Config{},
                analysisStore: &mockAnalysisStore{},
        }

        _, ok := h.loadAnalysisForAPI(c)
        if ok {
                t.Error("expected ok=false for invalid ID")
        }
        if w.Code != http.StatusBadRequest {
                t.Errorf("expected 400, got %d", w.Code)
        }
}

func TestLoadAnalysisForAPI_NotFound(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/api/analysis/999", nil)
        c.Params = gin.Params{{Key: "id", Value: "999"}}

        mock := &mockAnalysisStore{
                GetAnalysisByIDFn: func(ctx context.Context, id int32) (dbq.DomainAnalysis, error) {
                        return dbq.DomainAnalysis{}, errors.New("not found")
                },
        }
        h := &AnalysisHandler{
                Config:        &config.Config{},
                analysisStore: mock,
        }

        _, ok := h.loadAnalysisForAPI(c)
        if ok {
                t.Error("expected ok=false for not-found analysis")
        }
        if w.Code != http.StatusNotFound {
                t.Errorf("expected 404, got %d", w.Code)
        }
}

func TestLoadAnalysisForAPI_Success(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/api/analysis/1", nil)
        c.Params = gin.Params{{Key: "id", Value: "1"}}

        expected := dbq.DomainAnalysis{
                ID:      1,
                Domain:  "example.com",
                Private: false,
        }
        mock := &mockAnalysisStore{
                GetAnalysisByIDFn: func(ctx context.Context, id int32) (dbq.DomainAnalysis, error) {
                        return expected, nil
                },
        }
        h := &AnalysisHandler{
                Config:        &config.Config{},
                analysisStore: mock,
        }

        analysis, ok := h.loadAnalysisForAPI(c)
        if !ok {
                t.Error("expected ok=true for valid analysis")
        }
        if analysis.Domain != "example.com" {
                t.Errorf("expected domain=example.com, got %s", analysis.Domain)
        }
}

func TestLoadAnalysisForAPI_PrivateNotOwner(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/api/analysis/1", nil)
        c.Params = gin.Params{{Key: "id", Value: "1"}}

        mock := &mockAnalysisStore{
                GetAnalysisByIDFn: func(ctx context.Context, id int32) (dbq.DomainAnalysis, error) {
                        return dbq.DomainAnalysis{ID: 1, Private: true}, nil
                },
        }
        h := &AnalysisHandler{
                Config:        &config.Config{},
                analysisStore: mock,
        }

        _, ok := h.loadAnalysisForAPI(c)
        if ok {
                t.Error("expected ok=false for private analysis without auth")
        }
        if w.Code != http.StatusNotFound {
                t.Errorf("expected 404 for private analysis without auth, got %d", w.Code)
        }
}

func optStr(s string) *string { return &s }
func boolPtr(b bool) *bool   { return &b }
