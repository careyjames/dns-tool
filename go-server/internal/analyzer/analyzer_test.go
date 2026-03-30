// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer_test

import (
        "testing"

        "dnstool/go-server/internal/analyzer"
)

var requiredSections = []string{
        "basic_records", "spf_analysis", "dmarc_analysis", "dkim_analysis",
        "registrar_info", "posture", "dane_analysis", "mta_sts_analysis",
        "tlsrpt_analysis", "bimi_analysis", "caa_analysis", "dnssec_analysis",
}

var validStatusValues = []string{
        "success", "warning", "error", "info", "n/a", "timeout", "unknown", "partial",
}

var validPostureColors = []string{
        "success", "info", "warning", "danger", "secondary",
}

var validMailClassifications = []string{
        "email_enabled", "email_minimal", "email_passive",
        "no_mail_verified", "no_mail_partial", "no_mail_intent", "unknown",
}

func isValidStatus(s string) bool {
        for _, v := range validStatusValues {
                if s == v {
                        return true
                }
        }
        return false
}

func isValidPostureColor(c string) bool {
        for _, v := range validPostureColors {
                if c == v {
                        return true
                }
        }
        return false
}

func TestRequiredSectionsExhaustive(t *testing.T) {
        for _, section := range requiredSections {
                if section == "" {
                        t.Error("empty section name in required sections")
                }
        }

        seen := make(map[string]bool)
        for _, section := range requiredSections {
                if seen[section] {
                        t.Errorf("duplicate section: %s", section)
                }
                seen[section] = true
        }

        if len(requiredSections) != 12 {
                t.Errorf("expected 12 required sections, got %d", len(requiredSections))
        }
}

func TestValidStatusValues(t *testing.T) {
        expected := map[string]bool{
                "success": true, "warning": true, "error": true, "info": true,
                "n/a": true, "timeout": true, "unknown": true, "partial": true,
        }

        for _, status := range validStatusValues {
                if !expected[status] {
                        t.Errorf("unexpected status value: %s", status)
                }
        }

        if len(validStatusValues) != len(expected) {
                t.Errorf("expected %d status values, got %d", len(expected), len(validStatusValues))
        }

        if !isValidStatus("success") {
                t.Error("success should be valid")
        }
        if isValidStatus("invalid") {
                t.Error("invalid should not be valid")
        }
}

func TestValidPostureColors(t *testing.T) {
        expected := map[string]bool{
                "success": true, "info": true, "warning": true,
                "danger": true, "secondary": true,
        }

        for _, color := range validPostureColors {
                if !expected[color] {
                        t.Errorf("unexpected posture color: %s", color)
                }
        }

        if len(validPostureColors) != len(expected) {
                t.Errorf("expected %d posture colors, got %d", len(expected), len(validPostureColors))
        }

        a := analyzer.New(analyzer.WithInitialIANAFetch(false))
        results := map[string]any{
                "spf_analysis":     map[string]any{"status": "success"},
                "dmarc_analysis":   map[string]any{"status": "success", "policy": "reject"},
                "dkim_analysis":    map[string]any{"status": "success"},
                "mta_sts_analysis": map[string]any{"status": "success"},
                "tlsrpt_analysis":  map[string]any{"status": "success"},
                "bimi_analysis":    map[string]any{"status": "success"},
                "dane_analysis":    map[string]any{"has_dane": true},
                "caa_analysis":     map[string]any{"status": "success"},
                "dnssec_analysis":  map[string]any{"status": "success"},
        }
        posture := a.CalculatePosture(results)
        color, _ := posture["color"].(string)
        if !isValidPostureColor(color) {
                t.Errorf("posture returned invalid color: %s", color)
        }
}

func emailSpoofingVerdict(spfOK, dmarcOK bool, dmarcPolicy string) string {
        dmarcEnforced := dmarcPolicy == "reject" || dmarcPolicy == "quarantine"
        if spfOK && dmarcOK && dmarcEnforced {
                return "protected"
        }
        if spfOK && dmarcOK && dmarcPolicy == "none" {
                return "monitoring"
        }
        if spfOK || dmarcOK {
                return "partial"
        }
        return "vulnerable"
}

func TestEmailSpoofingVerdictProtected(t *testing.T) {
        tests := []struct {
                name   string
                policy string
        }{
                {"reject", "reject"},
                {"quarantine", "quarantine"},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        verdict := emailSpoofingVerdict(true, true, tt.policy)
                        if verdict != "protected" {
                                t.Errorf("expected protected, got %s", verdict)
                        }
                })
        }
}

func TestEmailSpoofingVerdictMonitoring(t *testing.T) {
        verdict := emailSpoofingVerdict(true, true, "none")
        if verdict != "monitoring" {
                t.Errorf("expected monitoring, got %s", verdict)
        }
}

func TestEmailSpoofingVerdictPartial(t *testing.T) {
        tests := []struct {
                name    string
                spfOK   bool
                dmarcOK bool
                policy  string
        }{
                {"spf_only", true, false, ""},
                {"dmarc_only", false, true, ""},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        verdict := emailSpoofingVerdict(tt.spfOK, tt.dmarcOK, tt.policy)
                        if verdict != "partial" {
                                t.Errorf("expected partial, got %s", verdict)
                        }
                })
        }
}

func TestEmailSpoofingVerdictVulnerable(t *testing.T) {
        verdict := emailSpoofingVerdict(false, false, "")
        if verdict != "vulnerable" {
                t.Errorf("expected vulnerable, got %s", verdict)
        }
}
