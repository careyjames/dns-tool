package analyzer

import (
        "testing"
)

func TestComputePostureDiff_NoDifferences(t *testing.T) {
        prev := map[string]any{
                "spf_analysis": map[string]any{"status": "pass"},
        }
        curr := map[string]any{
                "spf_analysis": map[string]any{"status": "pass"},
        }
        diffs := ComputePostureDiff(prev, curr)
        if len(diffs) != 0 {
                t.Errorf("expected 0 diffs, got %d", len(diffs))
        }
}

func TestComputePostureDiff_SPFStatusChange(t *testing.T) {
        prev := map[string]any{
                "spf_analysis": map[string]any{"status": "pass"},
        }
        curr := map[string]any{
                "spf_analysis": map[string]any{"status": "fail"},
        }
        diffs := ComputePostureDiff(prev, curr)
        found := false
        for _, d := range diffs {
                if d.Label == "SPF Status" {
                        found = true
                        if d.Previous != "pass" {
                                t.Errorf("Previous = %q, want 'pass'", d.Previous)
                        }
                        if d.Current != "fail" {
                                t.Errorf("Current = %q, want 'fail'", d.Current)
                        }
                }
        }
        if !found {
                t.Error("expected SPF Status diff")
        }
}

func TestComputePostureDiff_DMARCPolicyChange(t *testing.T) {
        prev := map[string]any{
                "dmarc_analysis": map[string]any{"policy": "none"},
        }
        curr := map[string]any{
                "dmarc_analysis": map[string]any{"policy": "reject"},
        }
        diffs := ComputePostureDiff(prev, curr)
        found := false
        for _, d := range diffs {
                if d.Label == "DMARC Policy" {
                        found = true
                        if d.Severity != "success" {
                                t.Errorf("Severity = %q, want 'success'", d.Severity)
                        }
                }
        }
        if !found {
                t.Error("expected DMARC Policy diff")
        }
}

func TestComputePostureDiff_EmptyMaps(t *testing.T) {
        diffs := ComputePostureDiff(map[string]any{}, map[string]any{})
        if len(diffs) != 0 {
                t.Errorf("expected 0 diffs for empty maps, got %d", len(diffs))
        }
}

func TestComputePostureDiff_NilMaps(t *testing.T) {
        diffs := ComputePostureDiff(nil, nil)
        if len(diffs) != 0 {
                t.Errorf("expected 0 diffs for nil maps, got %d", len(diffs))
        }
}

func TestComputePostureDiff_DANEPresenceChange(t *testing.T) {
        prev := map[string]any{
                "dane_analysis": map[string]any{"has_dane": true},
        }
        curr := map[string]any{
                "dane_analysis": map[string]any{"has_dane": false},
        }
        diffs := ComputePostureDiff(prev, curr)
        found := false
        for _, d := range diffs {
                if d.Label == "DANE Present" {
                        found = true
                }
        }
        if !found {
                t.Error("expected DANE Present diff")
        }
}

func TestComputePostureDiff_MultipleChanges(t *testing.T) {
        prev := map[string]any{
                "spf_analysis":   map[string]any{"status": "pass"},
                "dmarc_analysis": map[string]any{"status": "pass", "policy": "reject"},
                "dkim_analysis":  map[string]any{"status": "pass"},
        }
        curr := map[string]any{
                "spf_analysis":   map[string]any{"status": "fail"},
                "dmarc_analysis": map[string]any{"status": "missing", "policy": "none"},
                "dkim_analysis":  map[string]any{"status": "pass"},
        }
        diffs := ComputePostureDiff(prev, curr)
        if len(diffs) < 3 {
                t.Errorf("expected at least 3 diffs, got %d", len(diffs))
        }
}

func TestDisplayVal_Empty(t *testing.T) {
        if v := displayVal(""); v != "(none)" {
                t.Errorf("displayVal('') = %q, want '(none)'", v)
        }
}

func TestDisplayVal_Whitespace(t *testing.T) {
        if v := displayVal("   "); v != "(none)" {
                t.Errorf("displayVal('   ') = %q, want '(none)'", v)
        }
}

func TestDisplayVal_Normal(t *testing.T) {
        if v := displayVal("pass"); v != "pass" {
                t.Errorf("displayVal('pass') = %q, want 'pass'", v)
        }
}

func TestClassifyDriftSeverity_DMARCPolicy(t *testing.T) {
        tests := []struct {
                prev, curr, want string
        }{
                {"reject", "none", "danger"},
                {"none", "reject", "success"},
                {"reject", "reject", "info"},
                {"quarantine", "reject", "success"},
                {"reject", "quarantine", "danger"},
        }
        for _, tt := range tests {
                got := classifyDriftSeverity("DMARC Policy", tt.prev, tt.curr)
                if got != tt.want {
                        t.Errorf("classifyDriftSeverity('DMARC Policy', %q, %q) = %q, want %q", tt.prev, tt.curr, got, tt.want)
                }
        }
}

func TestClassifyDriftSeverity_Status(t *testing.T) {
        tests := []struct {
                label, prev, curr, want string
        }{
                {"SPF Status", "pass", "fail", "danger"},
                {"SPF Status", "fail", "pass", "success"},
                {"SPF Status", "pass", "configured", "warning"},
                {"DANE Present", "enabled", "missing", "danger"},
        }
        for _, tt := range tests {
                got := classifyDriftSeverity(tt.label, tt.prev, tt.curr)
                if got != tt.want {
                        t.Errorf("classifyDriftSeverity(%q, %q, %q) = %q, want %q", tt.label, tt.prev, tt.curr, got, tt.want)
                }
        }
}

func TestClassifyDriftSeverity_Records(t *testing.T) {
        got := classifyDriftSeverity("SPF Records", "v=spf1 a -all", "v=spf1 ~all")
        if got != "warning" {
                t.Errorf("expected 'warning', got %q", got)
        }
}

func TestClassifyDriftSeverity_Default(t *testing.T) {
        got := classifyDriftSeverity("Mail Posture", "restrictive", "permissive")
        if got != "info" {
                t.Errorf("expected 'info', got %q", got)
        }
}

