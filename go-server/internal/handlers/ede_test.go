package handlers

import (
	"encoding/json"
	"testing"

	"dnstool/go-server/internal/dbq"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestMapSingleEvent_AllNil(t *testing.T) {
	e := dbq.EdeEvent{
		EdeID:       "EDE-001",
		Category:    "scoring_calibration",
		Severity:    "low",
		Title:       "Test",
		Status:      "open",
		Attribution: "system",
		CommitRef:   "abc123",
		EventDate:   pgtype.Date{Valid: false},
	}
	ev := mapSingleEvent(e)
	if ev.ID != "EDE-001" {
		t.Errorf("ID = %q, want EDE-001", ev.ID)
	}
	if ev.Date != "" {
		t.Error("expected empty date for invalid timestamp")
	}
	if ev.ConfidenceImpact != "" {
		t.Error("expected empty confidence impact")
	}
}

func TestMapSingleEvent_WithOptionalFields(t *testing.T) {
	ci := "-0.02"
	res := "Fixed in v26"
	bn := "Bayesian update"
	ca := "Recalibrate"
	pr := "Add guard"
	as := "RFC 7208"
	e := dbq.EdeEvent{
		EdeID:               "EDE-002",
		Category:            "drift_detection",
		Severity:            "medium",
		Title:               "Drift",
		Status:              "closed",
		Attribution:         "human",
		CommitRef:           "def456",
		ConfidenceImpact:    &ci,
		Resolution:          &res,
		BayesianNote:        &bn,
		CorrectionAction:    &ca,
		PreventionRule:      &pr,
		AuthoritativeSource: &as,
	}
	ev := mapSingleEvent(e)
	if ev.ConfidenceImpact != "-0.02" {
		t.Errorf("ConfidenceImpact = %q", ev.ConfidenceImpact)
	}
	if ev.Resolution != "Fixed in v26" {
		t.Errorf("Resolution = %q", ev.Resolution)
	}
}

func TestUnmarshalProtocols_EmptyInput(t *testing.T) {
	e := dbq.EdeEvent{ProtocolsAffected: nil}
	result := unmarshalProtocols(e)
	if result != nil {
		t.Error("expected nil for empty protocols")
	}
}

func TestUnmarshalProtocols_ValidJSON(t *testing.T) {
	data, _ := json.Marshal([]string{"SPF", "DMARC"})
	e := dbq.EdeEvent{ProtocolsAffected: data, EdeID: "E1"}
	result := unmarshalProtocols(e)
	if len(result) != 2 {
		t.Fatalf("expected 2 protocols, got %d", len(result))
	}
}

func TestUnmarshalProtocols_InvalidJSON(t *testing.T) {
	e := dbq.EdeEvent{ProtocolsAffected: []byte("{invalid}"), EdeID: "E2"}
	result := unmarshalProtocols(e)
	if result != nil {
		t.Error("expected nil for invalid JSON")
	}
}

func TestRedactDignityAmendments(t *testing.T) {
	event := &IntegrityEvent{
		Amendments: []EDEAmendment{
			{Ground: "DIGNITY_OF_EXPRESSION", OriginalValue: "sensitive text"},
			{Ground: "FACTUAL_ERROR", OriginalValue: "factual text"},
		},
	}
	redactDignityAmendments(event)
	if event.Amendments[0].OriginalValue != "[REDACTED — DIGNITY_OF_EXPRESSION]" {
		t.Errorf("expected redacted, got %q", event.Amendments[0].OriginalValue)
	}
	if event.Amendments[1].OriginalValue != "factual text" {
		t.Error("FACTUAL_ERROR amendment should not be redacted")
	}
}

func TestRedactDignityAmendments_AlreadyRedacted(t *testing.T) {
	event := &IntegrityEvent{
		Amendments: []EDEAmendment{
			{Ground: "DIGNITY_OF_EXPRESSION", OriginalValue: "[REDACTED — DIGNITY_OF_EXPRESSION]"},
		},
	}
	redactDignityAmendments(event)
	if event.Amendments[0].OriginalValue != "[REDACTED — DIGNITY_OF_EXPRESSION]" {
		t.Error("already-redacted value should remain unchanged")
	}
}

func TestHashEvent(t *testing.T) {
	event := &IntegrityEvent{
		ID:    "EDE-001",
		Title: "Test Event",
	}
	hashEvent(event)
	if event.EventHash == "" {
		t.Error("expected non-empty event hash")
	}
	if len(event.EventHash) != 128 {
		t.Errorf("expected 128-char SHA-3 hash, got %d chars", len(event.EventHash))
	}
}
