package analyzer

import (
	"strings"
	"testing"
)

func TestSPFRFCAttack_LookupLimitBoundary(t *testing.T) {
	tests := []struct {
		name            string
		spf             string
		wantLookupCount int
	}{
		{
			"exactly 10 lookups",
			"v=spf1 include:a.com include:b.com include:c.com include:d.com include:e.com include:f.com include:g.com include:h.com include:i.com include:j.com ~all",
			10,
		},
		{
			"exactly 11 lookups exceeds limit",
			"v=spf1 include:a.com include:b.com include:c.com include:d.com include:e.com include:f.com include:g.com include:h.com include:i.com include:j.com include:k.com ~all",
			11,
		},
		{
			"mixed mechanisms at boundary",
			"v=spf1 include:a.com include:b.com include:c.com include:d.com include:e.com include:f.com include:g.com a mx ~all",
			9,
		},
		{
			"all mechanism types combined",
			"v=spf1 include:a.com include:b.com include:c.com include:d.com include:e.com a mx ptr exists:%{i}.example.com redirect=z.com",
			10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := countSPFLookupMechanisms(strings.ToLower(tt.spf))
			if r.lookupCount != tt.wantLookupCount {
				t.Fatalf("expected %d lookups, got %d", tt.wantLookupCount, r.lookupCount)
			}
		})
	}
}

func TestSPFRFCAttack_LookupLimitVerdict(t *testing.T) {
	tests := []struct {
		name       string
		count      int
		wantStatus string
	}{
		{"at limit returns warning", 10, "warning"},
		{"over limit returns error", 11, "error"},
		{"well under limit returns success", 3, "success"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &spfEvalState{lookupCount: tt.count, permissiveness: strPtr("SOFT")}
			status, _ := buildSPFVerdict(s, []string{"v=spf1 ~all"}, nil)
			if status != tt.wantStatus {
				t.Fatalf("expected status=%s, got %s", tt.wantStatus, status)
			}
		})
	}
}

func TestSPFRFCAttack_PlusAllDangerous(t *testing.T) {
	tests := []struct {
		name string
		spf  string
	}{
		{"explicit +all", "v=spf1 +all"},
		{"bare all defaults to +all", "v=spf1 all"},
		{"+all with includes", "v=spf1 include:example.com +all"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := parseSPFMechanisms(tt.spf)
			if r.permissiveness == nil || *r.permissiveness != "DANGEROUS" {
				t.Fatal("expected DANGEROUS permissiveness for open relay")
			}
			foundIssue := false
			for _, issue := range r.issues {
				if strings.Contains(issue, "+all") {
					foundIssue = true
				}
			}
			if !foundIssue {
				t.Fatal("expected issue about +all allowing anyone to send")
			}
		})
	}
}

func TestSPFRFCAttack_PlusAllVerdict(t *testing.T) {
	s := &spfEvalState{permissiveness: strPtr("DANGEROUS")}
	status, msg := buildSPFVerdict(s, []string{"v=spf1 +all"}, nil)
	if status != "error" {
		t.Fatalf("expected error status for +all, got %s", status)
	}
	if !strings.Contains(msg, "+all") {
		t.Fatalf("expected message to mention +all, got %q", msg)
	}
}

func TestSPFRFCAttack_PTRDeprecation(t *testing.T) {
	r := countSPFLookupMechanisms("v=spf1 ptr ~all")
	if len(r.issues) == 0 {
		t.Fatal("expected PTR deprecation issue per RFC 7208 §5.5")
	}
	foundDeprecated := false
	for _, issue := range r.issues {
		if strings.Contains(strings.ToLower(issue), "deprecated") {
			foundDeprecated = true
		}
	}
	if !foundDeprecated {
		t.Fatal("expected deprecation warning for ptr mechanism")
	}
	foundMech := false
	for _, m := range r.lookupMechanisms {
		if strings.Contains(m, "ptr") && strings.Contains(m, "deprecated") {
			foundMech = true
		}
	}
	if !foundMech {
		t.Fatal("expected 'ptr mechanism (deprecated)' in lookupMechanisms")
	}
}

func TestSPFRFCAttack_RedirectLoopDetection(t *testing.T) {
	visited := map[string]bool{
		"a.com": true,
	}
	issue, stop := checkRedirectTermination("v=spf1 redirect=a.com", "a.com", visited, 5)
	if !stop {
		t.Fatal("expected loop detection to stop processing")
	}
	if !strings.Contains(issue, "loop") {
		t.Fatalf("expected loop detection issue, got %q", issue)
	}
}

func TestSPFRFCAttack_RedirectExceedsLookupLimit(t *testing.T) {
	visited := map[string]bool{}
	issue, stop := checkRedirectTermination("v=spf1 redirect=b.com", "b.com", visited, 11)
	if !stop {
		t.Fatal("expected stop when cumulative lookups exceed 10")
	}
	if !strings.Contains(issue, "lookup limit") {
		t.Fatalf("expected lookup limit issue, got %q", issue)
	}
}

func TestSPFRFCAttack_EmptySPFRecord(t *testing.T) {
	valid, like := classifySPFRecords([]string{""})
	if len(valid) != 0 {
		t.Fatalf("empty record should not be classified as valid, got %d valid", len(valid))
	}
	if len(like) != 0 {
		t.Fatalf("empty record should not be classified as spf-like, got %d like", len(like))
	}
}

func TestSPFRFCAttack_MultipleSPFRecords(t *testing.T) {
	valid, _ := classifySPFRecords([]string{"v=spf1 -all", "v=spf1 ~all"})
	if len(valid) != 2 {
		t.Fatalf("expected 2 valid SPF records, got %d", len(valid))
	}

	s := &spfEvalState{}
	status, msg := buildSPFVerdict(s, valid, nil)
	if status != "error" {
		t.Fatalf("multiple SPF records should produce error, got %s", status)
	}
	if !strings.Contains(msg, "Multiple SPF") {
		t.Fatalf("expected 'Multiple SPF' in message, got %q", msg)
	}

	result := evaluateSPFRecordSet(valid)
	foundMultiple := false
	for _, issue := range result.issues {
		if strings.Contains(issue, "Multiple SPF") {
			foundMultiple = true
		}
	}
	if !foundMultiple {
		t.Fatal("evaluateSPFRecordSet should report multiple SPF records issue")
	}
}

func TestSPFRFCAttack_CaseSensitivity(t *testing.T) {
	tests := []struct {
		name string
		spf  string
	}{
		{"uppercase V=SPF1", "V=SPF1 -all"},
		{"mixed case", "v=SpF1 -ALL"},
		{"all caps", "V=SPF1 INCLUDE:EXAMPLE.COM ~ALL"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, _ := classifySPFRecords([]string{tt.spf})
			if len(valid) != 1 {
				t.Fatalf("case-insensitive SPF should be classified as valid, got %d", len(valid))
			}
		})
	}
}

func TestSPFRFCAttack_CaseSensitivityMechanisms(t *testing.T) {
	r := parseSPFMechanisms("V=SPF1 INCLUDE:EXAMPLE.COM ~ALL")
	if len(r.includes) != 1 {
		t.Fatalf("expected 1 include from uppercase record, got %d", len(r.includes))
	}
	if r.permissiveness == nil || *r.permissiveness != "SOFT" {
		t.Fatal("expected SOFT permissiveness from uppercase ~ALL")
	}
}

func TestSPFRFCAttack_OverlyLongRecord(t *testing.T) {
	var parts []string
	parts = append(parts, "v=spf1")
	for i := 0; i < 30; i++ {
		parts = append(parts, "include:very-long-subdomain-name-that-makes-record-huge"+string(rune('a'+i))+".example.com")
	}
	parts = append(parts, "~all")
	longSPF := strings.Join(parts, " ")

	if len(longSPF) <= 450 {
		t.Fatalf("test record should exceed 450 chars, got %d", len(longSPF))
	}

	r := parseSPFMechanisms(longSPF)
	if r.lookupCount != 30 {
		t.Fatalf("expected 30 lookups, got %d", r.lookupCount)
	}

	s := &spfEvalState{lookupCount: r.lookupCount, permissiveness: r.permissiveness}
	status, _ := buildSPFVerdict(s, []string{longSPF}, nil)
	if status != "error" {
		t.Fatalf("overly long record with 30 lookups should produce error, got %s", status)
	}
}

func TestSPFRFCAttack_BareSPFRecord(t *testing.T) {
	valid, _ := classifySPFRecords([]string{"v=spf1"})
	if len(valid) != 1 {
		t.Fatalf("bare 'v=spf1' should be classified as valid, got %d", len(valid))
	}

	r := parseSPFMechanisms("v=spf1")
	if r.lookupCount != 0 {
		t.Fatalf("bare v=spf1 should have 0 lookups, got %d", r.lookupCount)
	}
	if r.permissiveness != nil {
		t.Fatalf("bare v=spf1 with no all mechanism should have nil permissiveness, got %v", *r.permissiveness)
	}
}

func TestSPFRFCAttack_NeutralAllNoProtection(t *testing.T) {
	r := parseSPFMechanisms("v=spf1 ?all")
	if r.permissiveness == nil || *r.permissiveness != "NEUTRAL" {
		t.Fatal("expected NEUTRAL permissiveness for ?all")
	}
	foundIssue := false
	for _, issue := range r.issues {
		if strings.Contains(issue, "no protection") {
			foundIssue = true
		}
	}
	if !foundIssue {
		t.Fatal("expected issue about ?all providing no protection")
	}

	s := &spfEvalState{permissiveness: r.permissiveness}
	status, _ := buildSPFVerdict(s, []string{"v=spf1 ?all"}, nil)
	if status != "warning" {
		t.Fatalf("expected warning status for ?all, got %s", status)
	}
}

func TestSPFRFCAttack_NoMailIntent(t *testing.T) {
	tests := []struct {
		name string
		spf  string
		want bool
	}{
		{"v=spf1 -all", "v=spf1 -all", true},
		{"quoted v=spf1 -all", "\"v=spf1 -all\"", true},
		{"with whitespace", "  v=spf1   -all  ", true},
		{"with include not no-mail", "v=spf1 include:example.com -all", false},
		{"soft fail not no-mail", "v=spf1 ~all", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := parseSPFMechanisms(tt.spf)
			if r.noMailIntent != tt.want {
				t.Fatalf("expected noMailIntent=%v, got %v", tt.want, r.noMailIntent)
			}
		})
	}
}

func TestSPFRFCAttack_NoMailIntentVerdict(t *testing.T) {
	s := &spfEvalState{noMailIntent: true}
	status, msg := buildSPFVerdict(s, []string{"v=spf1 -all"}, nil)
	if status != "success" {
		t.Fatalf("no-mail intent should produce success, got %s", status)
	}
	if !strings.Contains(strings.ToLower(msg), "no mail") {
		t.Fatalf("expected 'no mail' in message, got %q", msg)
	}
}

func TestSPFRFCAttack_SPFLikeButNotValid(t *testing.T) {
	tests := []struct {
		name string
		spf  string
	}{
		{"spf2.0", "spf2.0/mfrom -all"},
		{"spf in middle", "some-spf-like-record"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, like := classifySPFRecords([]string{tt.spf})
			if len(valid) != 0 {
				t.Fatal("spf-like record should not be classified as valid")
			}
			if len(like) != 1 {
				t.Fatalf("expected 1 spf-like record, got %d", len(like))
			}
		})
	}

	s := &spfEvalState{}
	status, msg := buildSPFVerdict(s, nil, []string{"spf2.0/mfrom -all"})
	if status != "warning" {
		t.Fatalf("spf-like without valid SPF should produce warning, got %s", status)
	}
	if !strings.Contains(msg, "SPF-like") {
		t.Fatalf("expected 'SPF-like' in message, got %q", msg)
	}
}

func TestSPFRFCAttack_MissingRecord(t *testing.T) {
	s := &spfEvalState{}
	status, msg := buildSPFVerdict(s, nil, nil)
	if status != "missing" {
		t.Fatalf("expected missing status when no SPF, got %s", status)
	}
	if !strings.Contains(msg, "No SPF") {
		t.Fatalf("expected 'No SPF' in message, got %q", msg)
	}
}

func TestSPFRFCAttack_StrictAllWithSendersRFCWarning(t *testing.T) {
	r := parseSPFMechanisms("v=spf1 include:example.com -all")
	foundRFC := false
	for _, issue := range r.issues {
		if strings.Contains(issue, "RFC 7489") {
			foundRFC = true
		}
	}
	if !foundRFC {
		t.Fatal("expected RFC 7489 warning about -all preventing DKIM check")
	}
}

func TestSPFRFCAttack_SoftFailNoRFCWarning(t *testing.T) {
	r := parseSPFMechanisms("v=spf1 include:example.com ~all")
	for _, issue := range r.issues {
		if strings.Contains(issue, "RFC 7489:") {
			t.Fatal("~all should not trigger RFC 7489 warning")
		}
	}
}

func TestSPFRFCAttack_RedirectExtraction(t *testing.T) {
	tests := []struct {
		name   string
		record string
		want   string
	}{
		{"basic redirect", "v=spf1 redirect=_spf.example.com", "_spf.example.com"},
		{"redirect with trailing dot", "v=spf1 redirect=_spf.example.com.", "_spf.example.com"},
		{"no redirect", "v=spf1 include:example.com ~all", ""},
		{"uppercase redirect", "v=spf1 REDIRECT=_spf.example.com", "_spf.example.com"},
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

func TestSPFRFCAttack_HasAllMechanism(t *testing.T) {
	tests := []struct {
		record string
		want   bool
	}{
		{"v=spf1 -all", true},
		{"v=spf1 ~all", true},
		{"v=spf1 +all", true},
		{"v=spf1 ?all", true},
		{"v=spf1 all", true},
		{"v=spf1 redirect=other.com", false},
		{"v=spf1 include:example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.record, func(t *testing.T) {
			got := hasAllMechanism(tt.record)
			if got != tt.want {
				t.Fatalf("hasAllMechanism(%q) = %v, want %v", tt.record, got, tt.want)
			}
		})
	}
}

func TestSPFRFCAttack_ExistsMechanism(t *testing.T) {
	r := countSPFLookupMechanisms("v=spf1 exists:%{i}._spf.example.com ~all")
	if r.lookupCount != 1 {
		t.Fatalf("expected 1 lookup for exists mechanism, got %d", r.lookupCount)
	}
	foundExists := false
	for _, m := range r.lookupMechanisms {
		if strings.Contains(m, "exists") {
			foundExists = true
		}
	}
	if !foundExists {
		t.Fatal("expected 'exists mechanism' in lookupMechanisms")
	}
}

func TestSPFRFCAttack_EvaluateSPFRecordSetEdgeCases(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		result := evaluateSPFRecordSet(nil)
		if result.lookupCount != 0 {
			t.Fatalf("expected 0 lookups for nil, got %d", result.lookupCount)
		}
	})

	t.Run("empty slice", func(t *testing.T) {
		result := evaluateSPFRecordSet([]string{})
		if result.lookupCount != 0 {
			t.Fatalf("expected 0 lookups for empty, got %d", result.lookupCount)
		}
	})

	t.Run("single at limit", func(t *testing.T) {
		spf := "v=spf1 include:a.com include:b.com include:c.com include:d.com include:e.com include:f.com include:g.com include:h.com include:i.com include:j.com ~all"
		result := evaluateSPFRecordSet([]string{spf})
		if result.lookupCount != 10 {
			t.Fatalf("expected 10 lookups, got %d", result.lookupCount)
		}
		found := false
		for _, issue := range result.issues {
			if strings.Contains(issue, "10/10") {
				found = true
			}
		}
		if !found {
			t.Fatal("expected at-limit issue")
		}
	})

	t.Run("single over limit", func(t *testing.T) {
		spf := "v=spf1 include:a.com include:b.com include:c.com include:d.com include:e.com include:f.com include:g.com include:h.com include:i.com include:j.com include:k.com ~all"
		result := evaluateSPFRecordSet([]string{spf})
		found := false
		for _, issue := range result.issues {
			if strings.Contains(issue, "Exceeds 10 DNS lookup limit") {
				found = true
			}
		}
		if !found {
			t.Fatal("expected exceeds-limit issue")
		}
	})
}

func TestSPFRFCAttack_RedirectTerminationCases(t *testing.T) {
	t.Run("empty target stops", func(t *testing.T) {
		_, stop := checkRedirectTermination("v=spf1 -all", "", map[string]bool{}, 5)
		if !stop {
			t.Fatal("empty target should stop")
		}
	})

	t.Run("record with all stops", func(t *testing.T) {
		_, stop := checkRedirectTermination("v=spf1 -all", "next.com", map[string]bool{}, 5)
		if !stop {
			t.Fatal("record with all mechanism should stop")
		}
	})

	t.Run("normal redirect continues", func(t *testing.T) {
		_, stop := checkRedirectTermination("v=spf1 redirect=next.com", "next.com", map[string]bool{}, 5)
		if stop {
			t.Fatal("normal redirect should continue")
		}
	})
}

func TestSPFRFCAttack_AllQualifierVariants(t *testing.T) {
	tests := []struct {
		name     string
		spf      string
		wantPerm string
		wantMech string
	}{
		{"hard fail", "v=spf1 -all", "STRICT", "-all"},
		{"soft fail", "v=spf1 ~all", "SOFT", "~all"},
		{"pass (explicit)", "v=spf1 +all", "DANGEROUS", "+all"},
		{"pass (implicit)", "v=spf1 all", "DANGEROUS", "+all"},
		{"neutral", "v=spf1 ?all", "NEUTRAL", "?all"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perm, mech, _ := classifyAllQualifier(tt.spf)
			if perm == nil {
				t.Fatal("expected non-nil permissiveness")
			}
			if *perm != tt.wantPerm {
				t.Fatalf("expected perm=%s, got %s", tt.wantPerm, *perm)
			}
			if mech == nil {
				t.Fatal("expected non-nil mechanism")
			}
			if *mech != tt.wantMech {
				t.Fatalf("expected mech=%s, got %s", tt.wantMech, *mech)
			}
		})
	}
}

func TestSPFRFCAttack_MergeResolvedSPF(t *testing.T) {
	s := &spfEvalState{
		lookupCount:      2,
		lookupMechanisms: []string{"include:first.com"},
		includes:         []string{"first.com"},
	}
	mergeResolvedSPF("v=spf1 include:second.com ~all", s)

	if len(s.includes) != 2 {
		t.Fatalf("expected 2 includes after merge, got %d", len(s.includes))
	}
	if s.permissiveness == nil || *s.permissiveness != "SOFT" {
		t.Fatal("expected SOFT permissiveness from resolved record")
	}
}

func TestSPFRFCAttack_RedirectChainToMaps(t *testing.T) {
	chain := []spfRedirectHop{
		{Domain: "a.com", SPFRecord: "v=spf1 redirect=b.com"},
		{Domain: "b.com", SPFRecord: "v=spf1 -all"},
	}
	maps := redirectChainToMaps(chain)
	if len(maps) != 2 {
		t.Fatalf("expected 2 maps, got %d", len(maps))
	}
	if maps[0]["domain"] != "a.com" {
		t.Fatalf("expected first domain=a.com, got %v", maps[0]["domain"])
	}
	if maps[1]["spf_record"] != "v=spf1 -all" {
		t.Fatalf("expected second spf_record='v=spf1 -all', got %v", maps[1]["spf_record"])
	}
}
