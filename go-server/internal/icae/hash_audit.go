// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package icae

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"dnstool/go-server/internal/analyzer"
	"dnstool/go-server/internal/dbq"
)

type HashAuditResult struct {
	TotalAudited    int
	TotalVerified   int
	TotalFailed     int
	TotalMissing    int
	TotalHashedInDB int
	LastVerifiedAt  string
	FailedDomains   []string
	IntegrityPct    int
}

func AuditHashIntegrity(ctx context.Context, queries *dbq.Queries, limit int32) *HashAuditResult {
	if queries == nil {
		return nil
	}

	rows, err := queries.GetRecentHashedAnalyses(ctx, limit)
	if err != nil {
		slog.Warn("ICAE hash audit: failed to query analyses", "error", err)
		return nil
	}

	result := &HashAuditResult{}
	for _, row := range rows {
		auditSingleRow(row, result)
	}

	if result.TotalAudited > 0 {
		result.IntegrityPct = (result.TotalVerified * 100) / result.TotalAudited
	}

	return result
}

func auditSingleRow(row dbq.GetRecentHashedAnalysesRow, result *HashAuditResult) {
	if row.PostureHash == nil || *row.PostureHash == "" {
		result.TotalMissing++
		return
	}

	result.TotalAudited++

	var fullResults map[string]any
	if err := json.Unmarshal(row.FullResults, &fullResults); err != nil {
		slog.Warn("ICAE hash audit: failed to parse full_results",
			"id", row.ID, "domain", row.Domain, "error", err)
		result.TotalFailed++
		result.FailedDomains = append(result.FailedDomains, row.Domain)
		return
	}

	recomputed := recomputeHash(row.PostureHash, fullResults)
	if recomputed == *row.PostureHash {
		result.TotalVerified++
		if result.LastVerifiedAt == "" && row.CreatedAt.Valid {
			result.LastVerifiedAt = row.CreatedAt.Time.Format(time.DateOnly)
		}
	} else {
		result.TotalFailed++
		result.FailedDomains = append(result.FailedDomains, row.Domain)
		slog.Warn("ICAE hash audit: posture hash mismatch",
			"id", row.ID, "domain", row.Domain,
			"stored", *row.PostureHash, "recomputed", recomputed)
	}
}

func recomputeHash(storedHash *string, fullResults map[string]any) string {
	if len(*storedHash) == 64 {
		return analyzer.CanonicalPostureHashLegacySHA256(fullResults)
	}
	return analyzer.CanonicalPostureHash(fullResults)
}
