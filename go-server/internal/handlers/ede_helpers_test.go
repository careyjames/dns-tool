// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1
package handlers

import (
        "strings"
        "testing"
        "time"

        "dnstool/go-server/internal/dbq"

        "github.com/jackc/pgx/v5/pgtype"
)

func TestEdeTaxonomy(t *testing.T) {
        tax := edeTaxonomy()
        if len(tax) != 10 {
                t.Fatalf("edeTaxonomy() returned %d entries, want 10", len(tax))
        }
        expected := map[string]string{
                "scoring_calibration":       "Scoring Calibration",
                "evidence_reinterpretation": "Evidence Reinterpretation",
                "drift_detection":           "Drift Detection",
                "resolver_trust":            "Resolver Trust",
                "false_positive":            "False Positive",
                "confidence_decay":          "Confidence Decay",
                "governance_correction":     "Governance Correction",
                "citation_error":            "Citation Error",
                "overclaim":                 "Overclaim",
                "standards_misattribution":  "Standards Misattribution",
        }
        for k, v := range expected {
                got, ok := tax[k]
                if !ok {
                        t.Errorf("edeTaxonomy() missing key %q", k)
                        continue
                }
                if got != v {
                        t.Errorf("edeTaxonomy()[%q] = %q, want %q", k, got, v)
                }
        }
}

func TestEdeTamperPolicy(t *testing.T) {
        p := edeTamperPolicy()
        if !p.Enabled {
                t.Error("edeTamperPolicy().Enabled = false, want true")
        }
        if p.Effective != "2026-03-07" {
                t.Errorf("edeTamperPolicy().Effective = %q, want %q", p.Effective, "2026-03-07")
        }
        if !strings.Contains(p.Standard, "SHA-3-512") {
                t.Errorf("edeTamperPolicy().Standard = %q, want it to contain SHA-3-512", p.Standard)
        }
        if p.AmendmentRule == "" {
                t.Error("edeTamperPolicy().AmendmentRule is empty")
        }
}

func TestUnmarshalProtocols_Valid(t *testing.T) {
        e := dbq.EdeEvent{
                EdeID:             "EDE-001",
                ProtocolsAffected: []byte(`["SPF","DKIM"]`),
        }
        got := unmarshalProtocols(e)
        if len(got) != 2 {
                t.Fatalf("unmarshalProtocols() returned %d items, want 2", len(got))
        }
        if got[0] != "SPF" {
                t.Errorf("got[0] = %q, want SPF", got[0])
        }
        if got[1] != "DKIM" {
                t.Errorf("got[1] = %q, want DKIM", got[1])
        }
}

func TestUnmarshalProtocols_Empty(t *testing.T) {
        e := dbq.EdeEvent{EdeID: "EDE-002"}
        got := unmarshalProtocols(e)
        if got != nil {
                t.Errorf("unmarshalProtocols(empty) = %v, want nil", got)
        }
}

func TestUnmarshalProtocols_Invalid(t *testing.T) {
        e := dbq.EdeEvent{
                EdeID:             "EDE-003",
                ProtocolsAffected: []byte(`not-json`),
        }
        got := unmarshalProtocols(e)
        if got != nil {
                t.Errorf("unmarshalProtocols(invalid) = %v, want nil", got)
        }
}

func edeStrPtr(s string) *string { return &s }

func TestMapSingleEvent_AllFields(t *testing.T) {
        e := dbq.EdeEvent{
                EdeID:               "EDE-010",
                EventDate:           pgtype.Date{Time: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), Valid: true},
                CommitRef:           "abc123",
                Category:            "scoring_calibration",
                Severity:            "high",
                Title:               "Test Event",
                Status:              "open",
                Attribution:         "engine",
                ConfidenceImpact:    edeStrPtr("moderate"),
                Resolution:          edeStrPtr("resolved via patch"),
                BayesianNote:        edeStrPtr("posterior updated"),
                CorrectionAction:    edeStrPtr("recalibrate"),
                PreventionRule:      edeStrPtr("add guard"),
                AuthoritativeSource: edeStrPtr("RFC 7489"),
        }
        ev := mapSingleEvent(e)
        if ev.ID != "EDE-010" {
                t.Errorf("ID = %q, want EDE-010", ev.ID)
        }
        if ev.Date != "2026-03-01" {
                t.Errorf("Date = %q, want 2026-03-01", ev.Date)
        }
        if ev.Commit != "abc123" {
                t.Errorf("Commit = %q", ev.Commit)
        }
        if ev.Category != "scoring_calibration" {
                t.Errorf("Category = %q", ev.Category)
        }
        if ev.Severity != "high" {
                t.Errorf("Severity = %q", ev.Severity)
        }
        if ev.Title != "Test Event" {
                t.Errorf("Title = %q", ev.Title)
        }
        if ev.Status != "open" {
                t.Errorf("Status = %q", ev.Status)
        }
        if ev.Attribution != "engine" {
                t.Errorf("Attribution = %q", ev.Attribution)
        }
        if ev.ConfidenceImpact != "moderate" {
                t.Errorf("ConfidenceImpact = %q", ev.ConfidenceImpact)
        }
        if ev.Resolution != "resolved via patch" {
                t.Errorf("Resolution = %q", ev.Resolution)
        }
        if ev.BayesianNote != "posterior updated" {
                t.Errorf("BayesianNote = %q", ev.BayesianNote)
        }
        if ev.CorrectionAction != "recalibrate" {
                t.Errorf("CorrectionAction = %q", ev.CorrectionAction)
        }
        if ev.PreventionRule != "add guard" {
                t.Errorf("PreventionRule = %q", ev.PreventionRule)
        }
        if ev.AuthoritativeSource != "RFC 7489" {
                t.Errorf("AuthoritativeSource = %q", ev.AuthoritativeSource)
        }
}

func TestMapSingleEvent_NilOptionals(t *testing.T) {
        e := dbq.EdeEvent{
                EdeID:     "EDE-020",
                CommitRef: "def456",
                Category:  "drift_detection",
                Severity:  "low",
                Title:     "Minimal Event",
                Status:    "closed",
                Attribution: "manual",
        }
        ev := mapSingleEvent(e)
        if ev.ID != "EDE-020" {
                t.Errorf("ID = %q", ev.ID)
        }
        if ev.Date != "" {
                t.Errorf("Date = %q, want empty for invalid pgtype.Date", ev.Date)
        }
        if ev.ConfidenceImpact != "" {
                t.Errorf("ConfidenceImpact = %q, want empty", ev.ConfidenceImpact)
        }
        if ev.Resolution != "" {
                t.Errorf("Resolution = %q, want empty", ev.Resolution)
        }
        if ev.BayesianNote != "" {
                t.Errorf("BayesianNote = %q, want empty", ev.BayesianNote)
        }
        if ev.CorrectionAction != "" {
                t.Errorf("CorrectionAction = %q, want empty", ev.CorrectionAction)
        }
        if ev.PreventionRule != "" {
                t.Errorf("PreventionRule = %q, want empty", ev.PreventionRule)
        }
        if ev.AuthoritativeSource != "" {
                t.Errorf("AuthoritativeSource = %q, want empty", ev.AuthoritativeSource)
        }
}

func TestMapDBEvents_Empty(t *testing.T) {
        events, protocols := mapDBEvents([]dbq.EdeEvent{}, map[string][]EDEAmendment{})
        if len(events) != 0 {
                t.Errorf("mapDBEvents(empty) returned %d events, want 0", len(events))
        }
        if len(protocols) != 0 {
                t.Errorf("mapDBEvents(empty) returned %d protocols, want 0", len(protocols))
        }
}

func TestMapDBEvents_WithAmendments(t *testing.T) {
        dbEvents := []dbq.EdeEvent{
                {
                        EdeID:             "EDE-100",
                        CommitRef:         "aaa111",
                        Category:          "false_positive",
                        Severity:          "medium",
                        Title:             "FP Event",
                        Status:            "open",
                        Attribution:       "engine",
                        ProtocolsAffected: []byte(`["SPF","DKIM"]`),
                        EventDate:         pgtype.Date{Time: time.Date(2026, 2, 15, 0, 0, 0, 0, time.UTC), Valid: true},
                },
                {
                        EdeID:             "EDE-101",
                        CommitRef:         "bbb222",
                        Category:          "overclaim",
                        Severity:          "low",
                        Title:             "Overclaim Event",
                        Status:            "closed",
                        Attribution:       "manual",
                        ProtocolsAffected: []byte(`["DMARC"]`),
                        EventDate:         pgtype.Date{Time: time.Date(2026, 2, 10, 0, 0, 0, 0, time.UTC), Valid: true},
                },
        }

        amendmentMap := map[string][]EDEAmendment{
                "EDE-100": {
                        {
                                Ground:        "FACTUAL_ERROR",
                                FieldChanged:  "severity",
                                OriginalValue: "low",
                                CorrectedTo:   "medium",
                                Justification: "re-evaluated impact",
                        },
                },
        }

        events, protocols := mapDBEvents(dbEvents, amendmentMap)
        if len(events) != 2 {
                t.Fatalf("mapDBEvents returned %d events, want 2", len(events))
        }

        if events[0].ID != "EDE-100" {
                t.Errorf("events[0].ID = %q, want EDE-100", events[0].ID)
        }
        if len(events[0].Amendments) != 1 {
                t.Fatalf("events[0].Amendments = %d, want 1", len(events[0].Amendments))
        }
        if events[0].Amendments[0].Ground != "FACTUAL_ERROR" {
                t.Errorf("amendment ground = %q", events[0].Amendments[0].Ground)
        }

        if events[1].ID != "EDE-101" {
                t.Errorf("events[1].ID = %q, want EDE-101", events[1].ID)
        }
        if len(events[1].Amendments) != 0 {
                t.Errorf("events[1].Amendments = %d, want 0", len(events[1].Amendments))
        }

        if len(protocols) < 2 {
                t.Errorf("expected at least 2 unique protocols, got %d", len(protocols))
        }

        protocolSet := map[string]bool{}
        for _, p := range protocols {
                protocolSet[p] = true
        }
        for _, expected := range []string{"SPF", "DKIM", "DMARC"} {
                if !protocolSet[expected] {
                        t.Errorf("protocols missing %q", expected)
                }
        }

        for _, ev := range events {
                if ev.EventHash == "" {
                        t.Errorf("event %q has empty EventHash", ev.ID)
                }
        }
}
