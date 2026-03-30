//go:build intel

package analyzer

import (
	"testing"
)

func TestClassifyDriftSeverity_Intel_DMARCPolicyDowngrade(t *testing.T) {
	got := classifyDriftSeverity("DMARC Policy", "reject", "none")
	if got != "danger" {
		t.Errorf("DMARC downgrade severity = %q, want danger", got)
	}
}

func TestClassifyDriftSeverity_Intel_DMARCPolicyUpgrade(t *testing.T) {
	got := classifyDriftSeverity("DMARC Policy", "none", "reject")
	if got != "success" {
		t.Errorf("DMARC upgrade severity = %q, want success", got)
	}
}

func TestClassifyDriftSeverity_Intel_DMARCPolicySame(t *testing.T) {
	got := classifyDriftSeverity("DMARC Policy", "reject", "reject")
	if got != "info" {
		t.Errorf("DMARC same severity = %q, want info", got)
	}
}

func TestClassifyDriftSeverity_Intel_StatusChange(t *testing.T) {
	got := classifyDriftSeverity("SPF Status", "pass", "fail")
	if got != "danger" {
		t.Errorf("status pass->fail = %q, want danger", got)
	}
}

func TestClassifyDriftSeverity_Intel_StatusImproved(t *testing.T) {
	got := classifyDriftSeverity("SPF Status", "fail", "pass")
	if got != "success" {
		t.Errorf("status fail->pass = %q, want success", got)
	}
}

func TestClassifyDriftSeverity_Intel_DANEPresent(t *testing.T) {
	got := classifyDriftSeverity("DANE Present", "found", "not found")
	if got != "danger" {
		t.Errorf("DANE found->not found = %q, want danger", got)
	}
}

func TestClassifyDriftSeverity_Intel_RecordsChange(t *testing.T) {
	got := classifyDriftSeverity("MX Records", "old", "new")
	if got != "warning" {
		t.Errorf("records change = %q, want warning", got)
	}
}

func TestClassifyDriftSeverity_Intel_SelectorsChange(t *testing.T) {
	got := classifyDriftSeverity("DKIM Selectors", "old", "new")
	if got != "warning" {
		t.Errorf("selectors change = %q, want warning", got)
	}
}

func TestClassifyDriftSeverity_Intel_TagsChange(t *testing.T) {
	got := classifyDriftSeverity("SPF Tags", "old", "new")
	if got != "warning" {
		t.Errorf("tags change = %q, want warning", got)
	}
}

func TestClassifyDriftSeverity_Intel_Default(t *testing.T) {
	got := classifyDriftSeverity("Some Other Field", "old", "new")
	if got != "info" {
		t.Errorf("default severity = %q, want info", got)
	}
}

func TestNormalizeStatusVal_Intel_Trim(t *testing.T) {
	got := normalizeStatusVal("  Pass  ")
	if got != "pass" {
		t.Errorf("normalizeStatusVal = %q, want 'pass'", got)
	}
}

func TestNormalizeStatusVal_Intel_StripParenthetical(t *testing.T) {
	got := normalizeStatusVal("pass (with warnings)")
	if got != "pass" {
		t.Errorf("normalizeStatusVal = %q, want 'pass'", got)
	}
}

func TestClassifyPolicyChange_Intel_AllCombinations(t *testing.T) {
	tests := []struct {
		prev, curr, want string
	}{
		{"reject", "none", "danger"},
		{"reject", "quarantine", "danger"},
		{"quarantine", "none", "danger"},
		{"none", "reject", "success"},
		{"none", "quarantine", "success"},
		{"quarantine", "reject", "success"},
		{"none", "none", "info"},
		{"reject", "reject", "info"},
		{"", "", "info"},
	}
	for _, tt := range tests {
		got := classifyPolicyChange(tt.prev, tt.curr)
		if got != tt.want {
			t.Errorf("classifyPolicyChange(%q, %q) = %q, want %q", tt.prev, tt.curr, got, tt.want)
		}
	}
}

func TestClassifyStatusChange_Intel_GoodToBad(t *testing.T) {
	good := []string{"pass", "valid", "configured", "found", "active", "enabled", "secure"}
	bad := []string{"fail", "missing", "none", "not found", "not configured", "", "insecure"}

	for _, g := range good {
		for _, b := range bad {
			got := classifyStatusChange(g, b)
			if got != "danger" {
				t.Errorf("classifyStatusChange(%q, %q) = %q, want danger", g, b, got)
			}
		}
	}
}

func TestClassifyStatusChange_Intel_BadToGood(t *testing.T) {
	got := classifyStatusChange("fail", "pass")
	if got != "success" {
		t.Errorf("classifyStatusChange(fail, pass) = %q, want success", got)
	}
}

func TestClassifyStatusChange_Intel_Neutral(t *testing.T) {
	got := classifyStatusChange("pass", "valid")
	if got != "warning" {
		t.Errorf("classifyStatusChange(pass, valid) = %q, want warning", got)
	}
}
