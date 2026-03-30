package analyzer

import (
	"testing"
)

func TestCountSPFLookupMechanisms_Empty(t *testing.T) {
	r := countSPFLookupMechanisms("")
	if r.lookupCount != 0 {
		t.Fatalf("expected 0 lookups, got %d", r.lookupCount)
	}
}

func TestCountSPFLookupMechanisms_Includes(t *testing.T) {
	r := countSPFLookupMechanisms("v=spf1 include:_spf.google.com include:servers.mcsv.net ~all")
	if r.lookupCount < 2 {
		t.Fatalf("expected at least 2 lookups, got %d", r.lookupCount)
	}
	if len(r.includes) != 2 {
		t.Fatalf("expected 2 includes, got %d", len(r.includes))
	}
}

func TestCountSPFLookupMechanisms_AMechanism(t *testing.T) {
	r := countSPFLookupMechanisms("v=spf1 a:/24 ~all")
	if r.lookupCount != 1 {
		t.Fatalf("expected 1 lookup for a mechanism, got %d", r.lookupCount)
	}
	found := false
	for _, m := range r.lookupMechanisms {
		if m == "a mechanism" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected 'a mechanism' in lookupMechanisms")
	}
}

func TestCountSPFLookupMechanisms_MXMechanism(t *testing.T) {
	r := countSPFLookupMechanisms("v=spf1 mx:/24 ~all")
	if r.lookupCount != 1 {
		t.Fatalf("expected 1 lookup for mx mechanism, got %d", r.lookupCount)
	}
}

func TestCountSPFLookupMechanisms_PTRMechanism(t *testing.T) {
	r := countSPFLookupMechanisms("v=spf1 ptr:/24 ~all")
	if r.lookupCount != 1 {
		t.Fatalf("expected 1 lookup for ptr mechanism, got %d", r.lookupCount)
	}
	if len(r.issues) == 0 {
		t.Fatal("expected PTR deprecation issue")
	}
}

func TestCountSPFLookupMechanisms_Exists(t *testing.T) {
	r := countSPFLookupMechanisms("v=spf1 exists:%{i}.spf.example.com ~all")
	if r.lookupCount != 1 {
		t.Fatalf("expected 1 lookup for exists mechanism, got %d", r.lookupCount)
	}
}

func TestCountSPFLookupMechanisms_Redirect(t *testing.T) {
	r := countSPFLookupMechanisms("v=spf1 redirect=_spf.example.com")
	if r.lookupCount != 1 {
		t.Fatalf("expected 1 lookup for redirect, got %d", r.lookupCount)
	}
}

func TestClassifyAllQualifier(t *testing.T) {
	tests := []struct {
		name         string
		spf          string
		wantPerm     *string
		wantMech     *string
		wantIssueLen int
	}{
		{"no all", "v=spf1 include:example.com", nil, nil, 0},
		{"-all", "v=spf1 -all", strPtr("STRICT"), strPtr("-all"), 0},
		{"~all", "v=spf1 ~all", strPtr("SOFT"), strPtr("~all"), 0},
		{"+all", "v=spf1 +all", strPtr("DANGEROUS"), strPtr("+all"), 1},
		{"?all", "v=spf1 ?all", strPtr("NEUTRAL"), strPtr("?all"), 1},
		{"bare all", "v=spf1 all", strPtr("DANGEROUS"), strPtr("+all"), 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perm, mech, issues := classifyAllQualifier(tt.spf)
			if tt.wantPerm == nil && perm != nil {
				t.Fatalf("expected nil perm, got %v", *perm)
			}
			if tt.wantPerm != nil {
				if perm == nil {
					t.Fatal("expected non-nil perm")
				}
				if *perm != *tt.wantPerm {
					t.Fatalf("expected perm=%s, got %s", *tt.wantPerm, *perm)
				}
			}
			if tt.wantMech == nil && mech != nil {
				t.Fatalf("expected nil mech, got %v", *mech)
			}
			if tt.wantMech != nil {
				if mech == nil {
					t.Fatal("expected non-nil mech")
				}
				if *mech != *tt.wantMech {
					t.Fatalf("expected mech=%s, got %s", *tt.wantMech, *mech)
				}
			}
			if len(issues) != tt.wantIssueLen {
				t.Fatalf("expected %d issues, got %d: %v", tt.wantIssueLen, len(issues), issues)
			}
		})
	}
}

func TestParseSPFMechanisms_NoMailIntent(t *testing.T) {
	r := parseSPFMechanisms("v=spf1 -all")
	if !r.noMailIntent {
		t.Fatal("expected noMailIntent=true for 'v=spf1 -all'")
	}
}

func TestParseSPFMechanisms_WithIncludes(t *testing.T) {
	r := parseSPFMechanisms("v=spf1 include:_spf.google.com -all")
	if r.noMailIntent {
		t.Fatal("expected noMailIntent=false")
	}
	if len(r.includes) != 1 {
		t.Fatalf("expected 1 include, got %d", len(r.includes))
	}
	if r.permissiveness == nil || *r.permissiveness != "STRICT" {
		t.Fatal("expected STRICT permissiveness")
	}
	if len(r.issues) == 0 {
		t.Fatal("expected RFC 7489 issue for -all with senders")
	}
}

func TestParseSPFMechanisms_SoftFail(t *testing.T) {
	r := parseSPFMechanisms("v=spf1 include:example.com ~all")
	if r.permissiveness == nil || *r.permissiveness != "SOFT" {
		t.Fatal("expected SOFT permissiveness")
	}
}

func TestClassifySPFRecords(t *testing.T) {
	tests := []struct {
		name      string
		records   []string
		wantValid int
		wantLike  int
	}{
		{"empty", []string{}, 0, 0},
		{"valid spf1", []string{"v=spf1 -all"}, 1, 0},
		{"bare v=spf1", []string{"v=spf1"}, 1, 0},
		{"spf-like", []string{"spf2.0/mfrom -all"}, 0, 1},
		{"non-spf", []string{"google-site-verification=abc"}, 0, 0},
		{"empty record", []string{""}, 0, 0},
		{"multiple valid", []string{"v=spf1 -all", "v=spf1 ~all"}, 2, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, like := classifySPFRecords(tt.records)
			if len(valid) != tt.wantValid {
				t.Fatalf("expected %d valid, got %d", tt.wantValid, len(valid))
			}
			if len(like) != tt.wantLike {
				t.Fatalf("expected %d like, got %d", tt.wantLike, len(like))
			}
		})
	}
}

func TestEvaluateSPFRecordSet_Multiple(t *testing.T) {
	result := evaluateSPFRecordSet([]string{"v=spf1 -all", "v=spf1 ~all"})
	found := false
	for _, issue := range result.issues {
		if issue == "Multiple SPF records (hard fail)" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected multiple SPF records issue")
	}
}

func TestEvaluateSPFRecordSet_SingleOverLimit(t *testing.T) {
	spf := "v=spf1 include:a.com include:b.com include:c.com include:d.com include:e.com include:f.com include:g.com include:h.com include:i.com include:j.com include:k.com ~all"
	result := evaluateSPFRecordSet([]string{spf})
	if result.lookupCount <= 10 {
		t.Fatalf("expected >10 lookups, got %d", result.lookupCount)
	}
}

func TestEvaluateSPFRecordSet_SingleAtLimit(t *testing.T) {
	spf := "v=spf1 include:a.com include:b.com include:c.com include:d.com include:e.com include:f.com include:g.com include:h.com include:i.com include:j.com ~all"
	result := evaluateSPFRecordSet([]string{spf})
	if result.lookupCount != 10 {
		t.Fatalf("expected 10 lookups, got %d", result.lookupCount)
	}
	found := false
	for _, issue := range result.issues {
		if issue == "At lookup limit (10/10)" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected at-limit issue")
	}
}

func TestEvaluateSPFRecordSet_Empty(t *testing.T) {
	result := evaluateSPFRecordSet(nil)
	if result.lookupCount != 0 {
		t.Fatalf("expected 0 lookups, got %d", result.lookupCount)
	}
}

func TestExtractRedirectTarget(t *testing.T) {
	tests := []struct {
		name   string
		record string
		want   string
	}{
		{"no redirect", "v=spf1 ~all", ""},
		{"redirect", "v=spf1 redirect=_spf.example.com", "_spf.example.com"},
		{"redirect with dot", "v=spf1 redirect=_spf.example.com.", "_spf.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRedirectTarget(tt.record)
			if got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestHasAllMechanism(t *testing.T) {
	tests := []struct {
		record string
		want   bool
	}{
		{"v=spf1 -all", true},
		{"v=spf1 ~all", true},
		{"v=spf1 +all", true},
		{"v=spf1 ?all", true},
		{"v=spf1 redirect=other.com", false},
		{"v=spf1 include:example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.record, func(t *testing.T) {
			if got := hasAllMechanism(tt.record); got != tt.want {
				t.Fatalf("hasAllMechanism(%q) = %v, want %v", tt.record, got, tt.want)
			}
		})
	}
}

func TestBuildSPFVerdict(t *testing.T) {
	tests := []struct {
		name       string
		state      *spfEvalState
		validSPF   []string
		spfLike    []string
		wantStatus string
	}{
		{
			"multiple SPF records",
			&spfEvalState{},
			[]string{"v=spf1 -all", "v=spf1 ~all"},
			nil,
			mapKeyError,
		},
		{
			"no SPF with spf-like",
			&spfEvalState{},
			nil,
			[]string{"spf2.0/mfrom -all"},
			mapKeyWarning,
		},
		{
			"no SPF records at all",
			&spfEvalState{},
			nil,
			nil,
			"missing",
		},
		{
			"exceeds lookup limit",
			&spfEvalState{lookupCount: 11},
			[]string{"v=spf1 -all"},
			nil,
			mapKeyError,
		},
		{
			"at lookup limit",
			&spfEvalState{lookupCount: 10},
			[]string{"v=spf1 -all"},
			nil,
			mapKeyWarning,
		},
		{
			"dangerous +all",
			&spfEvalState{permissiveness: strPtr("DANGEROUS")},
			[]string{"v=spf1 +all"},
			nil,
			mapKeyError,
		},
		{
			"neutral ?all",
			&spfEvalState{permissiveness: strPtr("NEUTRAL")},
			[]string{"v=spf1 ?all"},
			nil,
			mapKeyWarning,
		},
		{
			"no mail intent",
			&spfEvalState{noMailIntent: true},
			[]string{"v=spf1 -all"},
			nil,
			mapKeySuccess,
		},
		{
			"strict -all",
			&spfEvalState{permissiveness: strPtr("STRICT"), lookupCount: 3},
			[]string{"v=spf1 include:example.com -all"},
			nil,
			mapKeySuccess,
		},
		{
			"soft ~all",
			&spfEvalState{permissiveness: strPtr("SOFT"), lookupCount: 3},
			[]string{"v=spf1 include:example.com ~all"},
			nil,
			mapKeySuccess,
		},
		{
			"valid no qualifier info",
			&spfEvalState{lookupCount: 2},
			[]string{"v=spf1 include:example.com"},
			nil,
			mapKeySuccess,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, _ := buildSPFVerdict(tt.state, tt.validSPF, tt.spfLike)
			if status != tt.wantStatus {
				t.Fatalf("expected status=%s, got %s", tt.wantStatus, status)
			}
		})
	}
}
