package analyzer

import (
	"testing"
)

func TestCheckRedirectTermination_EmptyTarget(t *testing.T) {
	visited := map[string]bool{}
	issue, stop := checkRedirectTermination("v=spf1 include:example.com ~all", "", visited, 2)
	if !stop {
		t.Fatal("expected stop=true for empty target")
	}
	if issue != "" {
		t.Fatalf("expected no issue, got %q", issue)
	}
}

func TestCheckRedirectTermination_HasAll(t *testing.T) {
	visited := map[string]bool{}
	issue, stop := checkRedirectTermination("v=spf1 include:example.com ~all", "other.com", visited, 2)
	if !stop {
		t.Fatal("expected stop=true when current record has all mechanism")
	}
	if issue != "" {
		t.Fatalf("expected no issue, got %q", issue)
	}
}

func TestCheckRedirectTermination_LoopDetected(t *testing.T) {
	visited := map[string]bool{"loop.com": true}
	issue, stop := checkRedirectTermination("v=spf1 redirect=loop.com", "loop.com", visited, 2)
	if !stop {
		t.Fatal("expected stop=true for loop detection")
	}
	if issue == "" {
		t.Fatal("expected a loop issue message")
	}
}

func TestCheckRedirectTermination_LookupLimitExceeded(t *testing.T) {
	visited := map[string]bool{}
	issue, stop := checkRedirectTermination("v=spf1 redirect=next.com", "next.com", visited, 11)
	if !stop {
		t.Fatal("expected stop=true when lookups > 10")
	}
	if issue == "" {
		t.Fatal("expected a lookup limit issue message")
	}
}

func TestCheckRedirectTermination_NormalContinue(t *testing.T) {
	visited := map[string]bool{}
	issue, stop := checkRedirectTermination("v=spf1 redirect=next.com", "next.com", visited, 3)
	if stop {
		t.Fatal("expected stop=false for normal continue")
	}
	if issue != "" {
		t.Fatalf("expected no issue, got %q", issue)
	}
}

func TestRedirectChainToMaps_Empty(t *testing.T) {
	result := redirectChainToMaps(nil)
	if len(result) != 0 {
		t.Fatalf("expected empty slice, got %d elements", len(result))
	}
}

func TestRedirectChainToMaps_SingleHop(t *testing.T) {
	chain := []spfRedirectHop{
		{Domain: "example.com", SPFRecord: "v=spf1 -all"},
	}
	result := redirectChainToMaps(chain)
	if len(result) != 1 {
		t.Fatalf("expected 1 map, got %d", len(result))
	}
	if result[0]["domain"] != "example.com" {
		t.Fatalf("expected domain=example.com, got %v", result[0]["domain"])
	}
	if result[0]["spf_record"] != "v=spf1 -all" {
		t.Fatalf("expected spf_record=v=spf1 -all, got %v", result[0]["spf_record"])
	}
}

func TestRedirectChainToMaps_MultipleHops(t *testing.T) {
	chain := []spfRedirectHop{
		{Domain: "a.com", SPFRecord: "v=spf1 redirect=b.com"},
		{Domain: "b.com", SPFRecord: "v=spf1 redirect=c.com"},
		{Domain: "c.com", SPFRecord: "v=spf1 -all"},
	}
	result := redirectChainToMaps(chain)
	if len(result) != 3 {
		t.Fatalf("expected 3 maps, got %d", len(result))
	}
	for i, hop := range chain {
		if result[i]["domain"] != hop.Domain {
			t.Errorf("hop %d: expected domain=%s, got %v", i, hop.Domain, result[i]["domain"])
		}
		if result[i]["spf_record"] != hop.SPFRecord {
			t.Errorf("hop %d: expected spf_record=%s, got %v", i, hop.SPFRecord, result[i]["spf_record"])
		}
	}
}

func strPtr(s string) *string { return &s }

func TestMergeResolvedSPF_MergesMechanisms(t *testing.T) {
	s := &spfEvalState{
		lookupMechanisms: []string{"include:a.com"},
		includes:         []string{"a.com"},
	}

	mergeResolvedSPF("v=spf1 include:b.com ~all", s)

	if len(s.lookupMechanisms) < 2 {
		t.Fatalf("expected merged mechanisms, got %v", s.lookupMechanisms)
	}
	if len(s.includes) < 2 {
		t.Fatalf("expected merged includes, got %v", s.includes)
	}

	if s.permissiveness == nil || *s.permissiveness != "SOFT" {
		t.Fatalf("expected permissiveness=SOFT, got %v", s.permissiveness)
	}
	if s.allMechanism == nil || *s.allMechanism != "~all" {
		t.Fatalf("expected allMechanism=~all, got %v", s.allMechanism)
	}
	if s.noMailIntent {
		t.Fatal("expected noMailIntent=false")
	}
}

func TestMergeResolvedSPF_OverwritesPermissiveness(t *testing.T) {
	s := &spfEvalState{
		permissiveness: strPtr("SOFT"),
		allMechanism:   strPtr("~all"),
	}

	mergeResolvedSPF("v=spf1 -all", s)

	if s.permissiveness == nil || *s.permissiveness != "STRICT" {
		t.Fatalf("expected permissiveness overwritten to STRICT, got %v", s.permissiveness)
	}
	if s.allMechanism == nil || *s.allMechanism != "-all" {
		t.Fatalf("expected allMechanism overwritten to -all, got %v", s.allMechanism)
	}
}

func TestMergeResolvedSPF_SetsNoMailIntent(t *testing.T) {
	s := &spfEvalState{}

	mergeResolvedSPF("v=spf1 -all", s)

	if !s.noMailIntent {
		t.Fatal("expected noMailIntent=true for 'v=spf1 -all'")
	}
}

func TestMergeResolvedSPF_PreservesExistingNoMail(t *testing.T) {
	s := &spfEvalState{noMailIntent: true}

	mergeResolvedSPF("v=spf1 include:x.com ~all", s)

	if !s.noMailIntent {
		t.Fatal("expected noMailIntent to remain true")
	}
}
