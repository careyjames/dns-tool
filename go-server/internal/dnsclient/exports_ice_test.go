package dnsclient

import (
        "testing"
)

func TestExportFindConsensus_Unanimous(t *testing.T) {
        results := map[string][]string{
                "8.8.8.8": {"1.2.3.4"},
                "1.1.1.1": {"1.2.3.4"},
                "9.9.9.9": {"1.2.3.4"},
        }
        records, allSame, discrepancies := ExportFindConsensus(results)
        if !allSame {
                t.Error("expected allSame=true for unanimous results")
        }
        if len(discrepancies) != 0 {
                t.Errorf("expected 0 discrepancies, got %d", len(discrepancies))
        }
        if len(records) != 1 || records[0] != "1.2.3.4" {
                t.Errorf("records = %v, want [1.2.3.4]", records)
        }
}

func TestExportFindConsensus_WithDissenter(t *testing.T) {
        results := map[string][]string{
                "8.8.8.8": {"1.2.3.4"},
                "1.1.1.1": {"1.2.3.4"},
                "9.9.9.9": {"5.6.7.8"},
        }
        records, allSame, discrepancies := ExportFindConsensus(results)
        if allSame {
                t.Error("expected allSame=false with dissenter")
        }
        if len(discrepancies) == 0 {
                t.Error("expected discrepancies")
        }
        if len(records) != 1 || records[0] != "1.2.3.4" {
                t.Errorf("expected majority record 1.2.3.4, got %v", records)
        }
}

func TestExportFindConsensus_AllEmpty(t *testing.T) {
        results := map[string][]string{
                "8.8.8.8": {},
                "1.1.1.1": {},
        }
        records, allSame, discrepancies := ExportFindConsensus(results)
        if !allSame {
                t.Error("expected allSame=true for all-empty results")
        }
        if records != nil {
                t.Errorf("expected nil records for all-empty, got %v", records)
        }
        if len(discrepancies) != 0 {
                t.Errorf("expected 0 discrepancies, got %d", len(discrepancies))
        }
}

func TestExportFindConsensus_NilInput(t *testing.T) {
        records, allSame, discrepancies := ExportFindConsensus(nil)
        if records != nil {
                t.Errorf("expected nil records for nil input, got %v", records)
        }
        if !allSame {
                t.Error("expected allSame=true for nil input")
        }
        if len(discrepancies) != 0 {
                t.Errorf("expected 0 discrepancies for nil input, got %d", len(discrepancies))
        }
}

func TestExportFindConsensus_SingleResolver(t *testing.T) {
        results := map[string][]string{
                "8.8.8.8": {"1.2.3.4", "5.6.7.8"},
        }
        records, allSame, _ := ExportFindConsensus(results)
        if !allSame {
                t.Error("expected allSame=true for single resolver")
        }
        if len(records) != 2 {
                t.Errorf("expected 2 records, got %d", len(records))
        }
}
