// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import (
        "encoding/json"
        "net/http"
        "net/http/httptest"
        "testing"
        "time"

        "dnstool/go-server/internal/analyzer"
        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/dbq"

        "github.com/gin-gonic/gin"
        "github.com/jackc/pgx/v5/pgtype"
)

func TestComputeDriftFromPrev_SameHash_B4(t *testing.T) {
        h := "abc123"
        d := computeDriftFromPrev("abc123", prevAnalysisSnapshot{Hash: &h, ID: 1}, nil)
        if d.Detected {
                t.Error("expected no drift when hashes match")
        }
}

func TestComputeDriftFromPrev_DriftDetected_B4(t *testing.T) {
        prev := "oldhash1234567890"
        now := time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC)
        d := computeDriftFromPrev("newhash", prevAnalysisSnapshot{
                Hash:           &prev,
                ID:             42,
                CreatedAtValid: true,
                CreatedAt:      now,
        }, map[string]any{"spf": "pass"})
        if !d.Detected {
                t.Fatal("expected drift to be detected")
        }
        if d.PrevHash != prev {
                t.Errorf("PrevHash = %q, want %q", d.PrevHash, prev)
        }
        if d.PrevID != 42 {
                t.Errorf("PrevID = %d, want 42", d.PrevID)
        }
        if d.PrevTime == "" {
                t.Error("PrevTime should be set when CreatedAtValid is true")
        }
}

func TestComputeDriftFromPrev_WithFullResults_B4(t *testing.T) {
        prev := "oldhash"
        prevResults := map[string]any{"spf": "pass"}
        prevJSON, _ := json.Marshal(prevResults)
        d := computeDriftFromPrev("newhash", prevAnalysisSnapshot{
                Hash:        &prev,
                ID:          10,
                FullResults: json.RawMessage(prevJSON),
        }, map[string]any{"spf": "fail"})
        if !d.Detected {
                t.Fatal("expected drift")
        }
}

func TestComputeDriftFromPrev_NoCreatedAt_B4(t *testing.T) {
        prev := "oldhash"
        d := computeDriftFromPrev("newhash", prevAnalysisSnapshot{
                Hash:           &prev,
                ID:             5,
                CreatedAtValid: false,
        }, nil)
        if !d.Detected {
                t.Fatal("expected drift")
        }
        if d.PrevTime != "" {
                t.Error("PrevTime should be empty when CreatedAtValid is false")
        }
}

func TestConvertDriftEvents_Empty_B4(t *testing.T) {
        result := convertDriftEvents(nil)
        if len(result) != 0 {
                t.Errorf("expected empty, got %d", len(result))
        }
}

func TestConvertDriftEvents_WithData_B4(t *testing.T) {
        now := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
        fields := []analyzer.PostureDiffField{{Label: "spf", Severity: "warning"}}
        diffJSON, _ := json.Marshal(fields)
        events := []dbq.DriftEvent{
                {
                        ID:             1,
                        Domain:         "example.com",
                        AnalysisID:     100,
                        PrevAnalysisID: 99,
                        CurrentHash:    "aaaa1111222233334444555566667777",
                        PreviousHash:   "bbbb1111222233334444555566667777",
                        Severity:       "warning",
                        CreatedAt:      pgtype.Timestamp{Time: now, Valid: true},
                        DiffSummary:    diffJSON,
                },
        }
        result := convertDriftEvents(events)
        if len(result) != 1 {
                t.Fatalf("expected 1 event, got %d", len(result))
        }
        ev := result[0]
        if ev.Domain != "example.com" {
                t.Errorf("domain = %q", ev.Domain)
        }
        if ev.CurrentHashShort != "aaaa111122223333" {
                t.Errorf("short hash = %q", ev.CurrentHashShort)
        }
        if ev.CreatedAt == "" {
                t.Error("CreatedAt should be formatted")
        }
        if len(ev.Fields) != 1 {
                t.Errorf("Fields = %d, want 1", len(ev.Fields))
        }
}

func TestConvertDriftEvents_InvalidDiffJSON_B4(t *testing.T) {
        events := []dbq.DriftEvent{
                {
                        ID:          2,
                        Domain:      "test.com",
                        CurrentHash: "aabbccdd",
                        DiffSummary: []byte(`not valid json`),
                },
        }
        result := convertDriftEvents(events)
        if len(result) != 1 {
                t.Fatal("expected 1 event")
        }
        if result[0].Fields != nil {
                t.Error("Fields should be nil for invalid JSON")
        }
}

func TestBuildHashHistory_Empty_B4(t *testing.T) {
        result := buildHashHistory(nil)
        if len(result) != 0 {
                t.Errorf("expected empty, got %d", len(result))
        }
}

func TestBuildHashHistory_WithData_B4(t *testing.T) {
        h1 := "hash_a_1234567890abcdef"
        h2 := "hash_b_1234567890abcdef"
        now := time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)
        analyses := []dbq.DomainAnalysis{
                {ID: 3, PostureHash: &h2, CreatedAt: pgtype.Timestamp{Time: now.Add(1 * time.Hour), Valid: true}},
                {ID: 2, PostureHash: &h1, CreatedAt: pgtype.Timestamp{Time: now, Valid: true}},
                {ID: 1, PostureHash: &h1, CreatedAt: pgtype.Timestamp{Time: now.Add(-1 * time.Hour), Valid: true}},
        }
        result := buildHashHistory(analyses)
        if len(result) != 3 {
                t.Fatalf("expected 3, got %d", len(result))
        }
        foundChanged := false
        for _, e := range result {
                if e.HashChanged {
                        foundChanged = true
                }
        }
        if !foundChanged {
                t.Error("expected at least one HashChanged entry")
        }
}

func TestBuildHashHistory_NilHash_B4(t *testing.T) {
        analyses := []dbq.DomainAnalysis{
                {ID: 1, PostureHash: nil},
        }
        result := buildHashHistory(analyses)
        if len(result) != 1 {
                t.Fatal("expected 1")
        }
        if result[0].PostureHash != "" {
                t.Error("expected empty PostureHash for nil")
        }
}

func TestLogEphemeralReason_AllBranches(t *testing.T) {
        logEphemeralReason("example.com", true, true)
        logEphemeralReason("example.com", false, false)
        logEphemeralReason("example.com", false, true)
}

func TestRedactDignityAmendments_B4(t *testing.T) {
        event := &IntegrityEvent{
                Amendments: []EDEAmendment{
                        {Ground: "DIGNITY_OF_EXPRESSION", OriginalValue: "sensitive-data"},
                        {Ground: "OTHER_GROUND", OriginalValue: "keep-this"},
                },
        }
        redactDignityAmendments(event)
        if event.Amendments[0].OriginalValue != "[REDACTED — DIGNITY_OF_EXPRESSION]" {
                t.Errorf("dignity amendment not redacted: %q", event.Amendments[0].OriginalValue)
        }
        if event.Amendments[1].OriginalValue != "keep-this" {
                t.Error("non-dignity amendment should not be redacted")
        }
}

func TestRedactDignityAmendments_AlreadyRedacted_B4(t *testing.T) {
        event := &IntegrityEvent{
                Amendments: []EDEAmendment{
                        {Ground: "DIGNITY_OF_EXPRESSION", OriginalValue: "[REDACTED — DIGNITY_OF_EXPRESSION]"},
                },
        }
        redactDignityAmendments(event)
        if event.Amendments[0].OriginalValue != "[REDACTED — DIGNITY_OF_EXPRESSION]" {
                t.Error("should remain redacted")
        }
}

func TestRedactDignityAmendments_Empty_B4(t *testing.T) {
        event := &IntegrityEvent{}
        redactDignityAmendments(event)
}

func TestHashEvent_B4(t *testing.T) {
        event := &IntegrityEvent{
                Category: "test",
                Title:    "test event",
        }
        hashEvent(event)
        if event.EventHash == "" {
                t.Error("EventHash should be populated")
        }
        if len(event.EventHash) != 128 {
                t.Errorf("SHA3-512 hex length = %d, want 128", len(event.EventHash))
        }
}

func TestHashEvent_Deterministic_B4(t *testing.T) {
        e1 := &IntegrityEvent{Category: "a", Title: "b"}
        e2 := &IntegrityEvent{Category: "a", Title: "b"}
        hashEvent(e1)
        hashEvent(e2)
        if e1.EventHash != e2.EventHash {
                t.Error("same input should produce same hash")
        }
}

func TestScanProgressStore_NewToken_B4(t *testing.T) {
        ps := NewProgressStore()
        defer ps.Close()
        token, sp := ps.NewToken()
        if token == "" {
                t.Fatal("token should not be empty")
        }
        if sp == nil {
                t.Fatal("scanProgress should not be nil")
        }
}

func TestScanProgressStore_GetAndDelete_B4(t *testing.T) {
        ps := NewProgressStore()
        defer ps.Close()
        token, _ := ps.NewToken()
        sp := ps.Get(token)
        if sp == nil {
                t.Fatal("should find token")
        }
        sp2 := ps.Get("nonexistent-token")
        if sp2 != nil {
                t.Error("should not find missing token")
        }
        ps.Delete(token)
        sp3 := ps.Get(token)
        if sp3 != nil {
                t.Error("should not find deleted token")
        }
}

func TestScanProgress_MarkComplete_B4(t *testing.T) {
        ps := NewProgressStore()
        defer ps.Close()
        _, sp := ps.NewToken()
        sp.UpdatePhase("dns", "running", 100)
        sp.MarkComplete(42, "/analysis/42")
        j := sp.toJSON()
        if j["status"] != "complete" {
                t.Errorf("status = %v, want complete", j["status"])
        }
        if j["analysis_id"] != int32(42) {
                t.Errorf("analysis_id = %v", j["analysis_id"])
        }
        if j["redirect_url"] != "/analysis/42" {
                t.Errorf("redirect = %v", j["redirect_url"])
        }
}

func TestScanProgress_MarkFailed_B4(t *testing.T) {
        ps := NewProgressStore()
        defer ps.Close()
        _, sp := ps.NewToken()
        sp.MarkFailed("test failure")
        j := sp.toJSON()
        if j["status"] != "failed" {
                t.Errorf("status = %v, want failed", j["status"])
        }
        if j["error"] != "test failure" {
                t.Errorf("error = %v", j["error"])
        }
}

func TestScanProgress_MakeProgressCallback_B4(t *testing.T) {
        ps := NewProgressStore()
        defer ps.Close()
        _, sp := ps.NewToken()
        cb := sp.MakeProgressCallback()
        if cb == nil {
                t.Fatal("callback should not be nil")
        }
        cb("dns", "running", 50)
        j := sp.toJSON()
        phases, ok := j["phases"].(map[string]any)
        if !ok {
                t.Fatal("phases should be a map")
        }
        if _, exists := phases["dns"]; !exists {
                t.Error("dns phase should exist after callback")
        }
}

func TestScanProgress_UpdatePhase_Lifecycle_B4(t *testing.T) {
        ps := NewProgressStore()
        defer ps.Close()
        _, sp := ps.NewToken()

        sp.UpdatePhase("spf", "running", 200)
        j := sp.toJSON()
        phases := j["phases"].(map[string]any)
        spf := phases["spf"].(map[string]any)
        if spf["status"] != "running" {
                t.Errorf("status = %v", spf["status"])
        }

        sp.UpdatePhase("spf", "done", 300)
        j = sp.toJSON()
        phases = j["phases"].(map[string]any)
        spf = phases["spf"].(map[string]any)
        if spf["status"] != "done" {
                t.Errorf("status = %v, want done", spf["status"])
        }

        sp.UpdatePhase("spf", "running", 400)
        j = sp.toJSON()
        phases = j["phases"].(map[string]any)
        spf = phases["spf"].(map[string]any)
        if spf["status"] != "done" {
                t.Error("should remain done after subsequent update")
        }
}

func TestStoreTelemetry_EarlyExits_B4(t *testing.T) {
        h := &AnalysisHandler{}
        h.storeTelemetry(nil, 0, nil, true)
        h.storeTelemetry(nil, 0, map[string]any{"spf": "pass"}, false)
        h.storeTelemetry(nil, 42, map[string]any{"spf": "pass"}, false)
        h.storeTelemetry(nil, 42, map[string]any{"_scan_telemetry": "not-a-struct"}, false)
}

func TestRecordCurrencyIfEligible_EarlyExits_B4(t *testing.T) {
        h := &AnalysisHandler{}
        h.recordCurrencyIfEligible(true, true, "example.com", nil)
        h.recordCurrencyIfEligible(false, false, "example.com", nil)
        h.recordCurrencyIfEligible(false, true, "example.com", map[string]any{})
}

func TestApplyDevNullHeaders_Set_B4(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

        applyDevNullHeaders(c, true)
        if w.Header().Get("X-Hacker") == "" {
                t.Error("X-Hacker should be set")
        }
        if w.Header().Get("X-Persistence") != "/dev/null" {
                t.Errorf("X-Persistence = %q", w.Header().Get("X-Persistence"))
        }
}

func TestApplyDevNullHeaders_Unset_B4(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

        applyDevNullHeaders(c, false)
        if w.Header().Get("X-Hacker") != "" {
                t.Error("X-Hacker should not be set")
        }
}

func TestResolveCovertMode_B4(t *testing.T) {
        gin.SetMode(gin.TestMode)
        tests := []struct {
                name   string
                covert string
                domain string
                want   string
        }{
                {"normal", "", "example.com", "E"},
                {"covert", "1", "example.com", "C"},
                {"tld", "", "com", "Z"},
                {"covert_tld", "1", "com", "CZ"},
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        w := httptest.NewRecorder()
                        c, _ := gin.CreateTestContext(w)
                        url := "/?covert=" + tc.covert
                        c.Request = httptest.NewRequest(http.MethodGet, url, nil)
                        got := resolveCovertMode(c, tc.domain)
                        if got != tc.want {
                                t.Errorf("resolveCovertMode = %q, want %q", got, tc.want)
                        }
                })
        }
}

func TestExtractAuthInfo_B4(t *testing.T) {
        gin.SetMode(gin.TestMode)

        t.Run("no_auth", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
                isAuth, uid := extractAuthInfo(c)
                if isAuth || uid != 0 {
                        t.Error("should not be authenticated")
                }
        })

        t.Run("authenticated", func(t *testing.T) {
                w := httptest.NewRecorder()
                c, _ := gin.CreateTestContext(w)
                c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
                c.Set("authenticated", true)
                c.Set("user_id", int32(99))
                isAuth, uid := extractAuthInfo(c)
                if !isAuth || uid != 99 {
                        t.Errorf("isAuth=%v uid=%d", isAuth, uid)
                }
        })
}

func TestNewTopologyHandler_B4(t *testing.T) {
        cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{"topology": true}}
        h := NewTopologyHandler(cfg)
        if h == nil || h.Config.AppVersion != "1.0" {
                t.Error("handler not initialized correctly")
        }
}

func TestNewVideoHandler_B4(t *testing.T) {
        cfg := &config.Config{AppVersion: "2.0"}
        h := NewVideoHandler(cfg)
        if h == nil {
                t.Fatal("handler should not be nil")
        }
}

func TestNewTelemetryHandler_B4(t *testing.T) {
        cfg := &config.Config{AppVersion: "3.0"}
        h := NewTelemetryHandler(nil, cfg)
        if h == nil || h.Config.AppVersion != "3.0" {
                t.Error("handler not initialized correctly")
        }
}

func TestNewPipelineHandler_B4(t *testing.T) {
        cfg := &config.Config{AppVersion: "4.0"}
        h := NewPipelineHandler(nil, cfg)
        if h == nil {
                t.Fatal("handler should not be nil")
        }
}

func TestStoreAnimInCache_B4(t *testing.T) {
        animCacheMu.Lock()
        animCache = make(map[string]*animCacheEntry)
        animCacheMu.Unlock()

        data := []byte("test-animation-data")
        etag := storeAnimInCache("test-key-b4", data)
        if etag == "" {
                t.Fatal("etag should not be empty")
        }

        animCacheMu.RLock()
        entry, ok := animCache["test-key-b4"]
        animCacheMu.RUnlock()
        if !ok {
                t.Fatal("entry should be in cache")
        }
        if string(entry.data) != "test-animation-data" {
                t.Error("data mismatch")
        }

        animCacheMu.Lock()
        animCache = make(map[string]*animCacheEntry)
        animCacheMu.Unlock()
}

func TestEvictLRUAnimEntry_B4(t *testing.T) {
        animCacheMu.Lock()
        animCache = make(map[string]*animCacheEntry)
        now := time.Now()
        animCache["old-b4"] = &animCacheEntry{data: []byte("a"), lastAccess: now.Add(-1 * time.Hour)}
        animCache["new-b4"] = &animCacheEntry{data: []byte("b"), lastAccess: now}
        evictLRUAnimEntry()
        _, oldExists := animCache["old-b4"]
        _, newExists := animCache["new-b4"]
        animCacheMu.Unlock()

        if oldExists {
                t.Error("old entry should have been evicted")
        }
        if !newExists {
                t.Error("new entry should remain")
        }

        animCacheMu.Lock()
        animCache = make(map[string]*animCacheEntry)
        animCacheMu.Unlock()
}

func TestServeAnimFromCache_Miss_B4(t *testing.T) {
        gin.SetMode(gin.TestMode)
        animCacheMu.Lock()
        animCache = make(map[string]*animCacheEntry)
        animCacheMu.Unlock()

        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/badge.apng", nil)

        served := serveAnimFromCache(c, "missing-key-b4", "apng")
        if served {
                t.Error("should return false for cache miss")
        }

        animCacheMu.Lock()
        animCache = make(map[string]*animCacheEntry)
        animCacheMu.Unlock()
}

func TestServeAnimFromCache_Hit_B4(t *testing.T) {
        gin.SetMode(gin.TestMode)
        animCacheMu.Lock()
        animCache = make(map[string]*animCacheEntry)
        animCache["hit-key-b4"] = &animCacheEntry{
                data:       []byte("cached-data"),
                createdAt:  time.Now(),
                lastAccess: time.Now(),
                etag:       `"abc123b4"`,
        }
        animCacheMu.Unlock()

        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/badge.apng", nil)

        served := serveAnimFromCache(c, "hit-key-b4", "apng")
        if !served {
                t.Error("should return true for cache hit")
        }
        if w.Code != http.StatusOK {
                t.Errorf("status = %d, want 200", w.Code)
        }
        if w.Header().Get("ETag") != `"abc123b4"` {
                t.Errorf("ETag = %q", w.Header().Get("ETag"))
        }

        animCacheMu.Lock()
        animCache = make(map[string]*animCacheEntry)
        animCacheMu.Unlock()
}

func TestServeAnimFromCache_Expired_B4(t *testing.T) {
        gin.SetMode(gin.TestMode)
        animCacheMu.Lock()
        animCache = make(map[string]*animCacheEntry)
        animCache["expired-b4"] = &animCacheEntry{
                data:       []byte("stale"),
                createdAt:  time.Now().Add(-time.Duration(animCacheMaxAge+10) * time.Second),
                lastAccess: time.Now(),
                etag:       `"oldb4"`,
        }
        animCacheMu.Unlock()

        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/badge.apng", nil)

        served := serveAnimFromCache(c, "expired-b4", "apng")
        if served {
                t.Error("should return false for expired entry")
        }

        animCacheMu.Lock()
        animCache = make(map[string]*animCacheEntry)
        animCacheMu.Unlock()
}

func TestGetStringFromResults_AllPaths_B4(t *testing.T) {
        results := map[string]any{
                "spf":   "v=spf1 include:example.com",
                "dmarc": map[string]any{"policy": "reject"},
                "count": 42,
        }

        got := getStringFromResults(results, "spf", "")
        if got == nil || *got != "v=spf1 include:example.com" {
                t.Error("top-level string lookup failed")
        }

        got = getStringFromResults(results, "dmarc", "policy")
        if got == nil || *got != "reject" {
                t.Error("nested string lookup failed")
        }

        if getStringFromResults(results, "missing", "") != nil {
                t.Error("missing key should return nil")
        }

        if getStringFromResults(results, "count", "") != nil {
                t.Error("non-string value should return nil")
        }

        if getStringFromResults(results, "dmarc", "missing") != nil {
                t.Error("missing nested key should return nil")
        }

        if getStringFromResults(results, "spf", "sub") != nil {
                t.Error("non-map section should return nil")
        }
}

func TestExtractReportsAndDurations_InvalidJSON_B4(t *testing.T) {
        analyses := []dbq.DomainAnalysis{{FullResults: []byte(`invalid`)}}
        reports, durations := extractReportsAndDurations(analyses)
        if len(reports) != 0 || len(durations) != 0 {
                t.Error("should skip invalid JSON")
        }
}

func TestExtractReportsAndDurations_NilResults_B4(t *testing.T) {
        analyses := []dbq.DomainAnalysis{{FullResults: nil}}
        reports, durations := extractReportsAndDurations(analyses)
        if len(reports) != 0 || len(durations) != 0 {
                t.Error("should skip nil FullResults")
        }
}

func TestAnalysisTimestamp_WithUpdate_B4(t *testing.T) {
        now := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
        later := time.Date(2025, 6, 2, 12, 0, 0, 0, time.UTC)
        a := dbq.DomainAnalysis{
                CreatedAt: pgtype.Timestamp{Time: now, Valid: true},
                UpdatedAt: pgtype.Timestamp{Time: later, Valid: true},
        }
        ts := analysisTimestamp(a)
        if ts == "" {
                t.Error("should format timestamp")
        }
}

func TestAnalysisDuration_B4(t *testing.T) {
        if analysisDuration(dbq.DomainAnalysis{}) != 0.0 {
                t.Error("nil should return 0")
        }
        d := 2.5
        if analysisDuration(dbq.DomainAnalysis{AnalysisDuration: &d}) != 2.5 {
                t.Error("should return value")
        }
}

func TestRecordUserAnalysisAsync_SkipPaths_B4(t *testing.T) {
        h := &AnalysisHandler{}
        h.recordUserAnalysisAsync(sideEffectsParams{isAuthenticated: false, userID: 0})
        h.recordUserAnalysisAsync(sideEffectsParams{isAuthenticated: true, userID: 0})
}

func TestNewStatsHandler_B4(t *testing.T) {
        cfg := &config.Config{AppVersion: "1.0"}
        h := NewStatsHandler(nil, cfg)
        if h == nil || h.Config.AppVersion != "1.0" {
                t.Error("handler not initialized correctly")
        }
}
