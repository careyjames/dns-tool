// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package icae

import (
	"context"
	"log/slog"
	"time"

	"dnstool/go-server/internal/dbq"

	"github.com/jackc/pgx/v5/pgtype"
)

type EvalDB interface {
	ICAEInsertTestRun(ctx context.Context, arg dbq.ICAEInsertTestRunParams) (dbq.ICAEInsertTestRunRow, error)
	ICAEGetMaturity(ctx context.Context, arg dbq.ICAEGetMaturityParams) (dbq.ICAEGetMaturityRow, error)
	ICAEUpsertMaturity(ctx context.Context, arg dbq.ICAEUpsertMaturityParams) error
}

func EvaluateAndRecord(ctx context.Context, queries EvalDB, appVersion string) {
	runner := NewRunner(appVersion, "", "full")
	runner.Register(AnalysisTestCases()...)
	runner.Register(CollectionTestCases()...)

	summary := runner.Run()

	slog.Info("ICAE evaluation complete",
		"total", summary.TotalCases,
		"passed", summary.TotalPassed,
		"failed", summary.TotalFailed,
		"duration_ms", summary.DurationMs,
	)

	_, err := queries.ICAEInsertTestRun(ctx, dbq.ICAEInsertTestRunParams{
		AppVersion:  appVersion,
		GitCommit:   "",
		RunType:     "full",
		TotalCases:  int32(summary.TotalCases),
		TotalPassed: int32(summary.TotalPassed),
		TotalFailed: int32(summary.TotalFailed),
		DurationMs:  int32(summary.DurationMs),
	})
	if err != nil {
		slog.Warn("ICAE: failed to insert test run", "error", err)
	}

	byProto := SummarizeByProtocol(summary.Results)

	for proto, layers := range byProto {
		for layer, stats := range layers {
			updateMaturityForProtoLayer(ctx, queries, proto, layer, stats)
		}
	}
}

func updateMaturityForProtoLayer(ctx context.Context, queries EvalDB, proto, layer string, stats struct {
	Total  int
	Passed int
	Failed int
}) {
	allPassed := stats.Failed == 0

	existing, err := queries.ICAEGetMaturity(ctx, dbq.ICAEGetMaturityParams{
		Protocol: proto,
		Layer:    layer,
	})

	totalRuns, consecutivePasses, firstPassAt, lastRegressionAt := computeRunStats(err, existing, allPassed)

	var fp *time.Time
	if firstPassAt.Valid {
		fp = &firstPassAt.Time
	}
	var lr *time.Time
	if lastRegressionAt.Valid {
		lr = &lastRegressionAt.Time
	}
	newMaturity := ComputeMaturity(int(consecutivePasses), fp, lr)

	upsertErr := queries.ICAEUpsertMaturity(ctx, dbq.ICAEUpsertMaturityParams{
		Protocol:          proto,
		Layer:             layer,
		Maturity:          newMaturity,
		TotalRuns:         totalRuns,
		ConsecutivePasses: consecutivePasses,
		FirstPassAt:       firstPassAt,
		LastRegressionAt:  lastRegressionAt,
	})
	if upsertErr != nil {
		slog.Warn("ICAE: failed to upsert maturity",
			"protocol", proto,
			"layer", layer,
			"error", upsertErr,
		)
	}
}

func computeRunStats(err error, existing dbq.ICAEGetMaturityRow, allPassed bool) (int32, int32, pgtype.Timestamp, pgtype.Timestamp) {
	var totalRuns int32
	var consecutivePasses int32
	var firstPassAt pgtype.Timestamp
	var lastRegressionAt pgtype.Timestamp

	if err == nil {
		totalRuns = existing.TotalRuns + 1
		if allPassed {
			consecutivePasses = existing.ConsecutivePasses + 1
		}
		firstPassAt = existing.FirstPassAt
		lastRegressionAt = existing.LastRegressionAt
	} else {
		totalRuns = 1
		if allPassed {
			consecutivePasses = 1
		}
	}

	if allPassed && !firstPassAt.Valid {
		now := time.Now()
		firstPassAt = pgtype.Timestamp{Time: now, Valid: true}
	}

	if !allPassed {
		now := time.Now()
		lastRegressionAt = pgtype.Timestamp{Time: now, Valid: true}
	}

	return totalRuns, consecutivePasses, firstPassAt, lastRegressionAt
}
