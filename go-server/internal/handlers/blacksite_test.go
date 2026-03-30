package handlers

import (
        "testing"

        "dnstool/go-server/internal/dbq"

        "github.com/jackc/pgx/v5/pgtype"
)

func TestSeverityLabels(t *testing.T) {
        expected := map[int]string{
                0: "S0 — Red Notice",
                1: "S1 — Critical Path",
                2: "S2 — Major",
                3: "S3 — Contained",
                4: "S4 — Minor",
        }
        for k, want := range expected {
                if got := severityLabels[k]; got != want {
                        t.Errorf("severityLabels[%d] = %q, want %q", k, got, want)
                }
        }
}

func TestPriorityLabels(t *testing.T) {
        for i := 0; i <= 3; i++ {
                if _, ok := priorityLabels[i]; !ok {
                        t.Errorf("missing priorityLabels[%d]", i)
                }
        }
}

func TestStatusDisplay(t *testing.T) {
        for _, status := range []string{"DETAINED", "VERIFIED", "UNDER_INTERROGATION", "CONTAINED", "RENDERED", "REGRESSED", "EXTRADITED", "DISMISSED"} {
                if _, ok := statusDisplay[status]; !ok {
                        t.Errorf("missing statusDisplay[%q]", status)
                }
                if _, ok := statusCSS[status]; !ok {
                        t.Errorf("missing statusCSS[%q]", status)
                }
        }
}

func TestStringOrEmpty_Nil(t *testing.T) {
        if got := stringOrEmpty(nil); got != "" {
                t.Errorf("stringOrEmpty(nil) = %q, want empty", got)
        }
}

func TestStringOrEmpty_NonNil(t *testing.T) {
        s := "hello"
        if got := stringOrEmpty(&s); got != "hello" {
                t.Errorf("stringOrEmpty = %q, want %q", got, "hello")
        }
}

func TestBucketBySeverity_Empty(t *testing.T) {
        buckets := bucketBySeverity(nil)
        for i := 0; i <= 4; i++ {
                if len(buckets[i]) != 0 {
                        t.Errorf("expected empty bucket for severity %d", i)
                }
        }
}

func TestBuildSeverityMap_Empty(t *testing.T) {
        m := buildSeverityMap(nil)
        if len(m) != 0 {
                t.Errorf("expected empty map, got %d entries", len(m))
        }
}

func TestBuildSeverityMap_WithData(t *testing.T) {
        counts := []dbq.CountFindingsBySeverityRow{
                {Severity: 0, Count: 5},
                {Severity: 2, Count: 3},
        }
        m := buildSeverityMap(counts)
        if m[0] != 5 {
                t.Errorf("m[0] = %d, want 5", m[0])
        }
        if m[2] != 3 {
                t.Errorf("m[2] = %d, want 3", m[2])
        }
}

func TestBuildKindMap(t *testing.T) {
        counts := []dbq.CountFindingsByKindRow{
                {Kind: "defect", Count: 10},
                {Kind: "weakness", Count: 5},
        }
        m := buildKindMap(counts)
        if m["defect"] != 10 {
                t.Errorf("m[defect] = %d, want 10", m["defect"])
        }
}

func TestBuildStatusMap(t *testing.T) {
        counts := []dbq.CountFindingsByStatusRow{
                {Status: "DETAINED", Count: 7},
        }
        m := buildStatusMap(counts)
        if m["DETAINED"] != 7 {
                t.Errorf("m[DETAINED] = %d, want 7", m["DETAINED"])
        }
}

func TestBuildEventViews_Empty(t *testing.T) {
        events := buildEventViews(nil)
        if len(events) != 0 {
                t.Errorf("expected 0 events, got %d", len(events))
        }
}

func TestBuildEventViews_WithData(t *testing.T) {
        toStatus := "RENDERED"
        eventsRaw := []dbq.ListFindingEventsRow{
                {
                        PublicID:  "BSI-001",
                        Title:     "Test Finding",
                        Severity:  2,
                        Actor:     "system",
                        EventType: "status_change",
                        ToStatus:  &toStatus,
                        CreatedAt: pgtype.Timestamptz{Valid: false},
                },
        }
        events := buildEventViews(eventsRaw)
        if len(events) != 1 {
                t.Fatalf("expected 1 event, got %d", len(events))
        }
        if events[0].ToStatus != "RENDERED" {
                t.Errorf("ToStatus = %q, want RENDERED", events[0].ToStatus)
        }
        if events[0].CreatedAt != "" {
                t.Errorf("CreatedAt should be empty for invalid timestamp")
        }
}
