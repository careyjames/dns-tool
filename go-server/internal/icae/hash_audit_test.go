package icae

import (
        "encoding/json"
        "testing"

        "dnstool/go-server/internal/dbq"

        "github.com/jackc/pgx/v5/pgtype"
)

func TestAuditHashIntegrity_NilQueries(t *testing.T) {
        result := AuditHashIntegrity(nil, nil, 100)
        if result != nil {
                t.Error("expected nil for nil queries")
        }
}

func TestHashAuditResult_Struct(t *testing.T) {
        result := &HashAuditResult{
                TotalAudited:    10,
                TotalVerified:   8,
                TotalFailed:     1,
                TotalMissing:    1,
                TotalHashedInDB: 10,
                IntegrityPct:    80,
        }
        if result.IntegrityPct != 80 {
                t.Errorf("IntegrityPct = %d", result.IntegrityPct)
        }
}

func TestAuditSingleRow_NilHash(t *testing.T) {
        row := dbq.GetRecentHashedAnalysesRow{
                PostureHash: nil,
        }
        result := &HashAuditResult{}
        auditSingleRow(row, result)
        if result.TotalMissing != 1 {
                t.Errorf("TotalMissing = %d, want 1", result.TotalMissing)
        }
}

func TestAuditSingleRow_EmptyHash(t *testing.T) {
        empty := ""
        row := dbq.GetRecentHashedAnalysesRow{
                PostureHash: &empty,
        }
        result := &HashAuditResult{}
        auditSingleRow(row, result)
        if result.TotalMissing != 1 {
                t.Errorf("TotalMissing = %d, want 1", result.TotalMissing)
        }
}

func TestAuditSingleRow_InvalidJSON(t *testing.T) {
        hash := "abc123"
        row := dbq.GetRecentHashedAnalysesRow{
                PostureHash: &hash,
                FullResults: []byte("{invalid json}"),
                Domain:      "test.com",
                ID:          1,
        }
        result := &HashAuditResult{}
        auditSingleRow(row, result)
        if result.TotalFailed != 1 {
                t.Errorf("TotalFailed = %d, want 1", result.TotalFailed)
        }
        if len(result.FailedDomains) != 1 || result.FailedDomains[0] != "test.com" {
                t.Errorf("FailedDomains = %v", result.FailedDomains)
        }
}

func TestAuditSingleRow_ValidResults_Mismatch(t *testing.T) {
        hash := "wronghash"
        fullResults := map[string]any{"spf_analysis": map[string]any{"status": "pass"}}
        jsonBytes, _ := json.Marshal(fullResults)
        row := dbq.GetRecentHashedAnalysesRow{
                PostureHash: &hash,
                FullResults: jsonBytes,
                Domain:      "mismatch.com",
                ID:          2,
        }
        result := &HashAuditResult{}
        auditSingleRow(row, result)
        if result.TotalFailed != 1 {
                t.Errorf("TotalFailed = %d, want 1", result.TotalFailed)
        }
}

func TestAuditSingleRow_ValidResults_Match(t *testing.T) {
        fullResults := map[string]any{"spf_analysis": map[string]any{"status": "pass"}}
        jsonBytes, _ := json.Marshal(fullResults)

        var parsed map[string]any
        json.Unmarshal(jsonBytes, &parsed)
        recomputed := recomputeHash(strPtr("short"), parsed)

        row := dbq.GetRecentHashedAnalysesRow{
                PostureHash: &recomputed,
                FullResults: jsonBytes,
                Domain:      "match.com",
                ID:          3,
                CreatedAt:   pgtype.Timestamp{Valid: true},
        }
        result := &HashAuditResult{}
        auditSingleRow(row, result)
        if result.TotalVerified != 1 {
                t.Errorf("TotalVerified = %d, want 1", result.TotalVerified)
        }
}

func TestRecomputeHash_SHA256Length(t *testing.T) {
        hash64 := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        result := recomputeHash(&hash64, map[string]any{})
        if result == "" {
                t.Error("expected non-empty hash")
        }
}

func TestRecomputeHash_NonSHA256Length(t *testing.T) {
        hashShort := "shorthash"
        result := recomputeHash(&hashShort, map[string]any{})
        if result == "" {
                t.Error("expected non-empty hash")
        }
}
