package handlers

import (
        "encoding/json"
        "net/http"
        "net/http/httptest"
        "net/url"
        "strings"
        "testing"
        "time"

        "dnstool/go-server/internal/analyzer"

        "github.com/gin-gonic/gin"
)

func TestShouldArchiveToWayback_AllConditionsTrue(t *testing.T) {
        if !shouldArchiveToWayback(42, true, false, false, false) {
                t.Fatal("expected true when all conditions met")
        }
}

func TestShouldArchiveToWayback_ZeroID(t *testing.T) {
        if shouldArchiveToWayback(0, true, false, false, false) {
                t.Fatal("expected false for zero analysis ID")
        }
}

func TestShouldArchiveToWayback_FailedAnalysis(t *testing.T) {
        if shouldArchiveToWayback(42, false, false, false, false) {
                t.Fatal("expected false for failed analysis")
        }
}

func TestShouldArchiveToWayback_Ephemeral(t *testing.T) {
        if shouldArchiveToWayback(42, true, true, false, false) {
                t.Fatal("expected false for ephemeral scan")
        }
}

func TestShouldArchiveToWayback_Private(t *testing.T) {
        if shouldArchiveToWayback(42, true, false, true, false) {
                t.Fatal("expected false for private scan")
        }
}

func TestShouldArchiveToWayback_Flagged(t *testing.T) {
        if shouldArchiveToWayback(42, true, false, false, true) {
                t.Fatal("expected false for flagged scan")
        }
}

func TestComputeDriftSeverity_NoFields(t *testing.T) {
        if got := computeDriftSeverity(nil); got != "info" {
                t.Fatalf("expected info, got %s", got)
        }
}

func TestComputeDriftSeverity_AllInfo(t *testing.T) {
        fields := []analyzer.PostureDiffField{
                {Label: "SPF", Severity: "info"},
                {Label: "DKIM", Severity: "info"},
        }
        if got := computeDriftSeverity(fields); got != "info" {
                t.Fatalf("expected info, got %s", got)
        }
}

func TestComputeDriftSeverity_WarningEscalation(t *testing.T) {
        fields := []analyzer.PostureDiffField{
                {Label: "SPF", Severity: "info"},
                {Label: "DMARC", Severity: "warning"},
                {Label: "DKIM", Severity: "info"},
        }
        if got := computeDriftSeverity(fields); got != "warning" {
                t.Fatalf("expected warning, got %s", got)
        }
}

func TestComputeDriftSeverity_CriticalOverridesAll(t *testing.T) {
        fields := []analyzer.PostureDiffField{
                {Label: "SPF", Severity: "warning"},
                {Label: "DNSSEC", Severity: "critical"},
                {Label: "DKIM", Severity: "info"},
        }
        if got := computeDriftSeverity(fields); got != "critical" {
                t.Fatalf("expected critical, got %s", got)
        }
}

func TestComputeDriftSeverity_CriticalFirst(t *testing.T) {
        fields := []analyzer.PostureDiffField{
                {Label: "DNSSEC", Severity: "critical"},
                {Label: "SPF", Severity: "info"},
        }
        if got := computeDriftSeverity(fields); got != "critical" {
                t.Fatalf("expected critical, got %s", got)
        }
}

func TestShouldPersistResult_NormalCase(t *testing.T) {
        persist, reason := shouldPersistResult(false, false, true, true)
        if !persist || reason != "" {
                t.Fatalf("expected persist=true, reason='', got persist=%v, reason=%s", persist, reason)
        }
}

func TestShouldPersistResult_DevNull(t *testing.T) {
        persist, reason := shouldPersistResult(false, true, true, true)
        if persist || reason != "devnull" {
                t.Fatalf("expected persist=false, reason=devnull, got persist=%v, reason=%s", persist, reason)
        }
}

func TestShouldPersistResult_Ephemeral(t *testing.T) {
        persist, reason := shouldPersistResult(true, false, true, true)
        if persist || reason != "ephemeral" {
                t.Fatalf("expected persist=false, reason=ephemeral, got persist=%v, reason=%s", persist, reason)
        }
}

func TestShouldPersistResult_NonexistentDomain(t *testing.T) {
        persist, reason := shouldPersistResult(false, false, false, true)
        if persist || reason != "nonexistent_domain" {
                t.Fatalf("expected persist=false, reason=nonexistent_domain, got persist=%v, reason=%s", persist, reason)
        }
}

func TestShouldPersistResult_NonexistentButFailed(t *testing.T) {
        persist, reason := shouldPersistResult(false, false, false, false)
        if !persist || reason != "" {
                t.Fatalf("failed analysis on nonexistent domain should still persist, got persist=%v, reason=%s", persist, reason)
        }
}

func TestShouldPersistResult_DevNullTakesPrecedence(t *testing.T) {
        persist, reason := shouldPersistResult(true, true, true, true)
        if persist || reason != "devnull" {
                t.Fatalf("devnull should take precedence over ephemeral, got persist=%v, reason=%s", persist, reason)
        }
}

func TestShouldRunICAE_NormalCase(t *testing.T) {
        if !shouldRunICAE(false, true) {
                t.Fatal("expected true for non-ephemeral existing domain")
        }
}

func TestShouldRunICAE_Ephemeral(t *testing.T) {
        if shouldRunICAE(true, true) {
                t.Fatal("expected false for ephemeral")
        }
}

func TestShouldRunICAE_DomainNotExists(t *testing.T) {
        if shouldRunICAE(false, false) {
                t.Fatal("expected false for nonexistent domain")
        }
}

func TestShouldRecordUserAssociation_Valid(t *testing.T) {
        if !shouldRecordUserAssociation(true, 42) {
                t.Fatal("expected true for authenticated user with valid ID")
        }
}

func TestShouldRecordUserAssociation_NotAuthenticated(t *testing.T) {
        if shouldRecordUserAssociation(false, 42) {
                t.Fatal("expected false for unauthenticated user")
        }
}

func TestShouldRecordUserAssociation_ZeroID(t *testing.T) {
        if shouldRecordUserAssociation(true, 0) {
                t.Fatal("expected false for zero user ID")
        }
}

func TestShouldRecordUserAssociation_NegativeID(t *testing.T) {
        if shouldRecordUserAssociation(true, -1) {
                t.Fatal("expected false for negative user ID")
        }
}

func TestComputeDriftFromPrev_NilHash_B9(t *testing.T) {
        di := computeDriftFromPrev("abc123", prevAnalysisSnapshot{Hash: nil}, nil)
        if di.Detected {
                t.Fatal("expected no drift for nil previous hash")
        }
}

func TestComputeDriftFromPrev_EmptyHash_B9(t *testing.T) {
        empty := ""
        di := computeDriftFromPrev("abc123", prevAnalysisSnapshot{Hash: &empty}, nil)
        if di.Detected {
                t.Fatal("expected no drift for empty previous hash")
        }
}

func TestComputeDriftFromPrev_SameHash_B9(t *testing.T) {
        h := "abc123"
        di := computeDriftFromPrev("abc123", prevAnalysisSnapshot{Hash: &h}, nil)
        if di.Detected {
                t.Fatal("expected no drift when hashes match")
        }
}

func TestComputeDriftFromPrev_DifferentHash_B9(t *testing.T) {
        prev := "old_hash_value"
        di := computeDriftFromPrev("new_hash_value", prevAnalysisSnapshot{
                Hash: &prev,
                ID:   100,
        }, nil)
        if !di.Detected {
                t.Fatal("expected drift detected for different hashes")
        }
        if di.PrevHash != "old_hash_value" {
                t.Fatalf("expected PrevHash=old_hash_value, got %s", di.PrevHash)
        }
        if di.PrevID != 100 {
                t.Fatalf("expected PrevID=100, got %d", di.PrevID)
        }
}

func TestComputeDriftFromPrev_WithCreatedAt_B9(t *testing.T) {
        prev := "old_hash"
        ts := time.Date(2026, 3, 15, 14, 30, 0, 0, time.UTC)
        di := computeDriftFromPrev("new_hash", prevAnalysisSnapshot{
                Hash:           &prev,
                ID:             50,
                CreatedAtValid: true,
                CreatedAt:      ts,
        }, nil)
        if !di.Detected {
                t.Fatal("expected drift detected")
        }
        if di.PrevTime == "" {
                t.Fatal("expected PrevTime to be formatted")
        }
        if di.PrevTime != "15 Mar 2026 14:30 UTC" {
                t.Fatalf("expected formatted time, got %s", di.PrevTime)
        }
}

func TestComputeDriftFromPrev_WithResults_B9(t *testing.T) {
        prev := "old_hash"
        prevResults := map[string]any{
                "spf_analysis":   map[string]any{"status": "pass"},
                "dmarc_analysis": map[string]any{"status": "pass"},
        }
        prevJSON, _ := json.Marshal(prevResults)
        currResults := map[string]any{
                "spf_analysis":   map[string]any{"status": "fail"},
                "dmarc_analysis": map[string]any{"status": "pass"},
        }
        di := computeDriftFromPrev("new_hash", prevAnalysisSnapshot{
                Hash:        &prev,
                ID:          50,
                FullResults: prevJSON,
        }, currResults)
        if !di.Detected {
                t.Fatal("expected drift detected")
        }
        if len(di.Fields) == 0 {
                t.Fatal("expected at least one drift field for SPF status change")
        }
}

func TestResultsDomainExists_True(t *testing.T) {
        results := map[string]any{"domain_exists": true}
        if !resultsDomainExists(results) {
                t.Fatal("expected true for domain_exists=true")
        }
}

func TestResultsDomainExists_False(t *testing.T) {
        results := map[string]any{"domain_exists": false}
        if resultsDomainExists(results) {
                t.Fatal("expected false for domain_exists=false")
        }
}

func TestResultsDomainExists_Missing(t *testing.T) {
        results := map[string]any{}
        if !resultsDomainExists(results) {
                t.Fatal("expected true when domain_exists key is missing (default)")
        }
}

func TestResultsDomainExists_WrongType(t *testing.T) {
        results := map[string]any{"domain_exists": "yes"}
        if !resultsDomainExists(results) {
                t.Fatal("expected true when domain_exists is wrong type (default)")
        }
}

func TestIsAnalysisFailure_Success(t *testing.T) {
        results := map[string]any{"analysis_success": true}
        failed, msg := isAnalysisFailure(results)
        if failed {
                t.Fatal("expected not failed for success=true")
        }
        if msg != "" {
                t.Fatalf("expected empty message, got %s", msg)
        }
}

func TestIsAnalysisFailure_FailedWithError(t *testing.T) {
        results := map[string]any{
                "analysis_success": false,
                "error":            "timeout",
        }
        failed, msg := isAnalysisFailure(results)
        if !failed {
                t.Fatal("expected failed=true")
        }
        if msg != "timeout" {
                t.Fatalf("expected error=timeout, got %s", msg)
        }
}

func TestIsAnalysisFailure_FailedNoError(t *testing.T) {
        results := map[string]any{"analysis_success": false}
        failed, _ := isAnalysisFailure(results)
        if failed {
                t.Fatal("expected failed=false when error key missing")
        }
}

func TestIsAnalysisFailure_MissingKey(t *testing.T) {
        results := map[string]any{}
        failed, _ := isAnalysisFailure(results)
        if failed {
                t.Fatal("expected failed=false when key missing")
        }
}

func TestExtractAnalysisError_Success(t *testing.T) {
        results := map[string]any{"analysis_success": true}
        success, errPtr := extractAnalysisError(results)
        if !success {
                t.Fatal("expected success=true")
        }
        if errPtr != nil {
                t.Fatal("expected nil error for success")
        }
}

func TestExtractAnalysisError_Failure(t *testing.T) {
        results := map[string]any{
                "analysis_success": false,
                "error":            "dns timeout",
        }
        success, errPtr := extractAnalysisError(results)
        if success {
                t.Fatal("expected success=false")
        }
        if errPtr == nil || *errPtr != "dns timeout" {
                t.Fatal("expected error message 'dns timeout'")
        }
}

func TestExtractDomainInput_PostForm(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        form := url.Values{"domain": {"  example.com  "}}
        c.Request = httptest.NewRequest(http.MethodPost, "/analyze", strings.NewReader(form.Encode()))
        c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        result := extractDomainInput(c)
        if result != "example.com" {
                t.Fatalf("expected 'example.com', got '%s'", result)
        }
}

func TestExtractDomainInput_QueryParam(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/analyze?domain=test.org", nil)
        result := extractDomainInput(c)
        if result != "test.org" {
                t.Fatalf("expected 'test.org', got '%s'", result)
        }
}

func TestExtractDomainInput_Empty(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/analyze", nil)
        result := extractDomainInput(c)
        if result != "" {
                t.Fatalf("expected empty, got '%s'", result)
        }
}

func TestLogEphemeralReason_AllPaths(t *testing.T) {
        logEphemeralReason("example.com", true, true)
        logEphemeralReason("example.com", false, false)
        logEphemeralReason("example.com", false, true)
}

func TestShouldArchiveToWayback_ExhaustiveMatrix(t *testing.T) {
        tests := []struct {
                name     string
                id       int32
                success  bool
                eph      bool
                priv     bool
                flagged  bool
                expected bool
        }{
                {"all_true", 1, true, false, false, false, true},
                {"zero_id", 0, true, false, false, false, false},
                {"negative_id", -1, true, false, false, false, false},
                {"failed", 1, false, false, false, false, false},
                {"ephemeral", 1, true, true, false, false, false},
                {"private", 1, true, false, true, false, false},
                {"flagged", 1, true, false, false, true, false},
                {"all_false_flags", 1, true, false, false, false, true},
                {"multiple_false", 1, true, true, true, true, false},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := shouldArchiveToWayback(tt.id, tt.success, tt.eph, tt.priv, tt.flagged)
                        if got != tt.expected {
                                t.Fatalf("shouldArchiveToWayback(%d, %v, %v, %v, %v) = %v, want %v",
                                        tt.id, tt.success, tt.eph, tt.priv, tt.flagged, got, tt.expected)
                        }
                })
        }
}

func TestShouldPersistResult_ExhaustiveMatrix(t *testing.T) {
        tests := []struct {
                name    string
                eph     bool
                devnull bool
                exists  bool
                success bool
                persist bool
                reason  string
        }{
                {"normal_persist", false, false, true, true, true, ""},
                {"normal_persist_failed", false, false, true, false, true, ""},
                {"devnull", false, true, true, true, false, "devnull"},
                {"devnull_overrides_ephemeral", true, true, true, true, false, "devnull"},
                {"ephemeral", true, false, true, true, false, "ephemeral"},
                {"nonexistent_success", false, false, false, true, false, "nonexistent_domain"},
                {"nonexistent_failed", false, false, false, false, true, ""},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        persist, reason := shouldPersistResult(tt.eph, tt.devnull, tt.exists, tt.success)
                        if persist != tt.persist || reason != tt.reason {
                                t.Fatalf("shouldPersistResult(%v,%v,%v,%v) = (%v,%s), want (%v,%s)",
                                        tt.eph, tt.devnull, tt.exists, tt.success, persist, reason, tt.persist, tt.reason)
                        }
                })
        }
}

func TestStoreTelemetry_EarlyExits(t *testing.T) {
        h := &AnalysisHandler{}
        h.storeTelemetry(nil, 0, nil, false)
        h.storeTelemetry(nil, 42, nil, true)
}
