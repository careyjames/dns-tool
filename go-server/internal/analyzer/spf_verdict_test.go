package analyzer

import (
	"strings"
	"testing"
)

func TestCountSPFLookupMechanisms_AllMechanisms(t *testing.T) {
	spf := "v=spf1 include:a.com a:/24 mx:/24 ptr:/24 exists:%{i}.example.com redirect=b.com ~all"
	r := countSPFLookupMechanisms(spf)

	if r.lookupCount < 6 {
		t.Fatalf("expected at least 6 lookups, got %d", r.lookupCount)
	}
	if len(r.includes) != 1 {
		t.Fatalf("expected 1 include, got %d", len(r.includes))
	}
	if len(r.issues) == 0 {
		t.Fatal("expected PTR deprecation issue")
	}

	hasMech := map[string]bool{}
	for _, m := range r.lookupMechanisms {
		hasMech[m] = true
	}
	if !hasMech["a mechanism"] {
		t.Fatal("expected 'a mechanism' in lookupMechanisms")
	}
	if !hasMech["mx mechanism"] {
		t.Fatal("expected 'mx mechanism' in lookupMechanisms")
	}
	if !hasMech["ptr mechanism (deprecated)"] {
		t.Fatal("expected 'ptr mechanism (deprecated)' in lookupMechanisms")
	}
	if !hasMech["exists mechanism"] {
		t.Fatal("expected 'exists mechanism' in lookupMechanisms")
	}
}

func TestCountSPFLookupMechanisms_MultipleIncludes(t *testing.T) {
	spf := "v=spf1 include:a.com include:b.com include:c.com ~all"
	r := countSPFLookupMechanisms(spf)
	if len(r.includes) != 3 {
		t.Fatalf("expected 3 includes, got %d", len(r.includes))
	}
	if r.lookupCount != 3 {
		t.Fatalf("expected 3 lookups, got %d", r.lookupCount)
	}
}

func TestCountSPFLookupMechanisms_NoMechanisms(t *testing.T) {
	r := countSPFLookupMechanisms("v=spf1 -all")
	if r.lookupCount != 0 {
		t.Fatalf("expected 0 lookups for bare record, got %d", r.lookupCount)
	}
	if len(r.lookupMechanisms) != 0 {
		t.Fatalf("expected no mechanisms, got %v", r.lookupMechanisms)
	}
}

func TestClassifyAllQualifier_CaseInsensitive(t *testing.T) {
	perm, mech, _ := classifyAllQualifier("v=spf1 -ALL")
	if perm == nil || *perm != "STRICT" {
		t.Fatal("expected STRICT for -ALL (uppercase)")
	}
	if mech == nil || *mech != "-all" {
		t.Fatalf("expected -all mechanism, got %v", mech)
	}
}

func TestParseSPFMechanisms_StrictWithSendersRFCWarning(t *testing.T) {
	r := parseSPFMechanisms("v=spf1 include:example.com a:/24 -all")
	found := false
	for _, issue := range r.issues {
		if strings.Contains(issue, "RFC 7489") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected RFC 7489 warning for -all with senders")
	}
}

func TestParseSPFMechanisms_NoMailIntentQuoted(t *testing.T) {
	r := parseSPFMechanisms("\"v=spf1 -all\"")
	if !r.noMailIntent {
		t.Fatal("expected noMailIntent=true for quoted 'v=spf1 -all'")
	}
}

func TestParseSPFMechanisms_NotNoMailWithIncludes(t *testing.T) {
	r := parseSPFMechanisms("v=spf1 include:example.com -all")
	if r.noMailIntent {
		t.Fatal("expected noMailIntent=false when includes are present")
	}
}

func TestParseSPFMechanisms_SoftFailNoRFCWarning(t *testing.T) {
	r := parseSPFMechanisms("v=spf1 include:example.com ~all")
	for _, issue := range r.issues {
		if strings.Contains(issue, "RFC 7489:") {
			t.Fatal("should not have RFC 7489 warning for ~all")
		}
	}
}

func TestClassifySPFRecords_CaseInsensitive(t *testing.T) {
	valid, _ := classifySPFRecords([]string{"V=SPF1 -all"})
	if len(valid) != 1 {
		t.Fatalf("expected 1 valid for uppercase, got %d", len(valid))
	}
}

func TestClassifySPFRecords_MixedRecords(t *testing.T) {
	records := []string{
		"v=spf1 include:example.com ~all",
		"spf2.0/mfrom -all",
		"google-site-verification=abc",
		"",
	}
	valid, like := classifySPFRecords(records)
	if len(valid) != 1 {
		t.Fatalf("expected 1 valid, got %d", len(valid))
	}
	if len(like) != 1 {
		t.Fatalf("expected 1 spf-like, got %d", len(like))
	}
}

func TestEvaluateSPFRecordSet_SingleValid(t *testing.T) {
	result := evaluateSPFRecordSet([]string{"v=spf1 include:example.com ~all"})
	if result.lookupCount != 1 {
		t.Fatalf("expected 1 lookup, got %d", result.lookupCount)
	}
	if result.permissiveness == nil || *result.permissiveness != "SOFT" {
		t.Fatal("expected SOFT permissiveness")
	}
}

func TestBuildSPFVerdict_Messages(t *testing.T) {
	tests := []struct {
		name        string
		state       *spfEvalState
		validSPF    []string
		spfLike     []string
		wantStatus  string
		wantContain string
	}{
		{
			"multiple SPF message",
			&spfEvalState{},
			[]string{"v=spf1 -all", "v=spf1 ~all"},
			nil,
			"error",
			"Multiple SPF records",
		},
		{
			"missing with spf-like message",
			&spfEvalState{},
			nil,
			[]string{"spf2.0"},
			"warning",
			"SPF-like record",
		},
		{
			"exceeds limit message",
			&spfEvalState{lookupCount: 12},
			[]string{"v=spf1 -all"},
			nil,
			"error",
			"exceeds 10 DNS lookup limit",
		},
		{
			"at limit message",
			&spfEvalState{lookupCount: 10},
			[]string{"v=spf1 -all"},
			nil,
			"warning",
			"at lookup limit",
		},
		{
			"no mail message",
			&spfEvalState{noMailIntent: true},
			[]string{"v=spf1 -all"},
			nil,
			"success",
			"no mail allowed",
		},
		{
			"strict message",
			&spfEvalState{permissiveness: strPtr("STRICT"), lookupCount: 3},
			[]string{"v=spf1 -all"},
			nil,
			"success",
			"strict enforcement",
		},
		{
			"soft message",
			&spfEvalState{permissiveness: strPtr("SOFT"), lookupCount: 5},
			[]string{"v=spf1 ~all"},
			nil,
			"success",
			"soft fail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, msg := buildSPFVerdict(tt.state, tt.validSPF, tt.spfLike)
			if status != tt.wantStatus {
				t.Fatalf("expected status=%s, got %s", tt.wantStatus, status)
			}
			if !strings.Contains(strings.ToLower(msg), strings.ToLower(tt.wantContain)) {
				t.Fatalf("expected message to contain %q, got %q", tt.wantContain, msg)
			}
		})
	}
}

func TestExtractRedirectTarget_CaseInsensitive(t *testing.T) {
	got := extractRedirectTarget("v=spf1 REDIRECT=_spf.example.com")
	if got != "_spf.example.com" {
		t.Fatalf("expected _spf.example.com, got %q", got)
	}
}

func TestHasAllMechanism_BareAll(t *testing.T) {
	if !hasAllMechanism("v=spf1 all") {
		t.Fatal("expected true for bare 'all'")
	}
}

func TestBuildSPFVerdict_DangerousMessage(t *testing.T) {
	status, msg := buildSPFVerdict(
		&spfEvalState{permissiveness: strPtr("DANGEROUS")},
		[]string{"v=spf1 +all"},
		nil,
	)
	if status != "error" {
		t.Fatalf("expected error, got %s", status)
	}
	if !strings.Contains(msg, "+all") {
		t.Fatalf("expected +all in message, got %q", msg)
	}
}

func TestBuildSPFVerdict_NeutralMessage(t *testing.T) {
	status, msg := buildSPFVerdict(
		&spfEvalState{permissiveness: strPtr("NEUTRAL")},
		[]string{"v=spf1 ?all"},
		nil,
	)
	if status != "warning" {
		t.Fatalf("expected warning, got %s", status)
	}
	if !strings.Contains(msg, "?all") {
		t.Fatalf("expected ?all in message, got %q", msg)
	}
}

func TestBuildSPFVerdict_MissingNoSpfLike(t *testing.T) {
	status, msg := buildSPFVerdict(&spfEvalState{}, nil, nil)
	if status != "missing" {
		t.Fatalf("expected missing, got %s", status)
	}
	if !strings.Contains(msg, "No SPF") {
		t.Fatalf("expected 'No SPF' in message, got %q", msg)
	}
}

func TestBuildSPFVerdict_ValidNoQualifier(t *testing.T) {
	status, msg := buildSPFVerdict(
		&spfEvalState{lookupCount: 2},
		[]string{"v=spf1 include:example.com"},
		nil,
	)
	if status != "success" {
		t.Fatalf("expected success, got %s", status)
	}
	if !strings.Contains(msg, "2/10") {
		t.Fatalf("expected lookup count in message, got %q", msg)
	}
}

func TestParseSPFMechanisms_PlusAllDangerous(t *testing.T) {
	r := parseSPFMechanisms("v=spf1 +all")
	if r.permissiveness == nil || *r.permissiveness != "DANGEROUS" {
		t.Fatal("expected DANGEROUS permissiveness for +all")
	}
	found := false
	for _, issue := range r.issues {
		if strings.Contains(issue, "+all") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected issue about +all")
	}
}

func TestParseSPFMechanisms_NeutralAll(t *testing.T) {
	r := parseSPFMechanisms("v=spf1 ?all")
	if r.permissiveness == nil || *r.permissiveness != "NEUTRAL" {
		t.Fatal("expected NEUTRAL permissiveness for ?all")
	}
}
