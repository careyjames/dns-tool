package icae

import (
	"errors"
	"testing"

	"dnstool/go-server/internal/dbq"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestComputeRunStats_NoExisting_AllPassed(t *testing.T) {
	totalRuns, consecutivePasses, firstPassAt, _ := computeRunStats(
		errors.New("not found"), dbq.ICAEGetMaturityRow{}, true,
	)
	if totalRuns != 1 {
		t.Errorf("totalRuns = %d, want 1", totalRuns)
	}
	if consecutivePasses != 1 {
		t.Errorf("consecutivePasses = %d, want 1", consecutivePasses)
	}
	if !firstPassAt.Valid {
		t.Error("expected firstPassAt to be set on first pass")
	}
}

func TestComputeRunStats_NoExisting_NotAllPassed(t *testing.T) {
	totalRuns, consecutivePasses, firstPassAt, lastRegressionAt := computeRunStats(
		errors.New("not found"), dbq.ICAEGetMaturityRow{}, false,
	)
	if totalRuns != 1 {
		t.Errorf("totalRuns = %d, want 1", totalRuns)
	}
	if consecutivePasses != 0 {
		t.Errorf("consecutivePasses = %d, want 0", consecutivePasses)
	}
	if firstPassAt.Valid {
		t.Error("firstPassAt should not be set when not all passed")
	}
	if !lastRegressionAt.Valid {
		t.Error("expected lastRegressionAt to be set on failure")
	}
}

func TestComputeRunStats_Existing_AllPassed(t *testing.T) {
	existing := dbq.ICAEGetMaturityRow{
		TotalRuns:         5,
		ConsecutivePasses: 3,
		FirstPassAt:       pgtype.Timestamp{Valid: false},
		LastRegressionAt:  pgtype.Timestamp{Valid: false},
	}
	totalRuns, consecutivePasses, _, _ := computeRunStats(nil, existing, true)
	if totalRuns != 6 {
		t.Errorf("totalRuns = %d, want 6", totalRuns)
	}
	if consecutivePasses != 4 {
		t.Errorf("consecutivePasses = %d, want 4", consecutivePasses)
	}
}

func TestComputeRunStats_Existing_NotAllPassed(t *testing.T) {
	existing := dbq.ICAEGetMaturityRow{
		TotalRuns:         5,
		ConsecutivePasses: 3,
		FirstPassAt:       pgtype.Timestamp{Valid: false},
		LastRegressionAt:  pgtype.Timestamp{Valid: false},
	}
	totalRuns, consecutivePasses, _, lastRegressionAt := computeRunStats(nil, existing, false)
	if totalRuns != 6 {
		t.Errorf("totalRuns = %d, want 6", totalRuns)
	}
	if consecutivePasses != 0 {
		t.Errorf("consecutivePasses = %d, want 0 after failure", consecutivePasses)
	}
	if !lastRegressionAt.Valid {
		t.Error("expected lastRegressionAt to be set on failure")
	}
}

func TestComputeRunStats_ExistingWithFirstPass_Preserved(t *testing.T) {
	existing := dbq.ICAEGetMaturityRow{
		TotalRuns:         10,
		ConsecutivePasses: 5,
		FirstPassAt:       pgtype.Timestamp{Valid: true},
		LastRegressionAt:  pgtype.Timestamp{Valid: false},
	}
	_, _, firstPassAt, _ := computeRunStats(nil, existing, true)
	if !firstPassAt.Valid {
		t.Error("existing firstPassAt should be preserved")
	}
}
