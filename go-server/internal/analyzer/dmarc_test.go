package analyzer

import (
	"strings"
	"testing"
)

func TestParseDMARCTags_Defaults(t *testing.T) {
	tags := parseDMARCTags("v=dmarc1;")
	if tags.pct != 100 {
		t.Fatalf("expected pct=100, got %d", tags.pct)
	}
	if tags.aspf != "relaxed" {
		t.Fatalf("expected aspf=relaxed, got %s", tags.aspf)
	}
	if tags.adkim != "relaxed" {
		t.Fatalf("expected adkim=relaxed, got %s", tags.adkim)
	}
	if tags.policy != nil {
		t.Fatalf("expected nil policy, got %v", *tags.policy)
	}
}

func TestParseDMARCTags_FullRecord(t *testing.T) {
	record := "v=dmarc1; p=reject; sp=quarantine; pct=50; aspf=s; adkim=s; rua=mailto:dmarc@example.com; ruf=mailto:forensic@example.com; np=reject; t=y; psd=y"
	tags := parseDMARCTags(record)

	if tags.policy == nil || *tags.policy != "reject" {
		t.Fatal("expected policy=reject")
	}
	if tags.subdomainPolicy == nil || *tags.subdomainPolicy != "quarantine" {
		t.Fatal("expected sp=quarantine")
	}
	if tags.pct != 50 {
		t.Fatalf("expected pct=50, got %d", tags.pct)
	}
	if tags.aspf != "strict" {
		t.Fatalf("expected aspf=strict, got %s", tags.aspf)
	}
	if tags.adkim != "strict" {
		t.Fatalf("expected adkim=strict, got %s", tags.adkim)
	}
	if tags.rua == nil {
		t.Fatal("expected rua to be set")
	}
	if tags.ruf == nil {
		t.Fatal("expected ruf to be set")
	}
	if tags.npPolicy == nil || *tags.npPolicy != "reject" {
		t.Fatal("expected np=reject")
	}
	if tags.tTesting == nil || *tags.tTesting != "y" {
		t.Fatal("expected t=y")
	}
	if tags.psdFlag == nil || *tags.psdFlag != "y" {
		t.Fatal("expected psd=y")
	}
}

func TestClassifyDMARCPolicyVerdict(t *testing.T) {
	tests := []struct {
		name       string
		policy     string
		pct        int
		wantStatus string
	}{
		{"none", "none", 100, "warning"},
		{"reject full", "reject", 100, "success"},
		{"reject partial", "reject", 50, "warning"},
		{"quarantine full", "quarantine", 100, "success"},
		{"quarantine partial", "quarantine", 25, "warning"},
		{"unknown policy", "xyz", 100, "info"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, _, _ := classifyDMARCPolicyVerdict(tt.policy, tt.pct)
			if status != tt.wantStatus {
				t.Fatalf("expected status=%s, got %s", tt.wantStatus, status)
			}
		})
	}
}

func TestClassifyEnforcementLevel(t *testing.T) {
	status, msg, issues := classifyEnforcementLevel("reject", 100, "excellent")
	if status != "success" {
		t.Fatalf("expected success, got %s", status)
	}
	if !strings.Contains(msg, "excellent") {
		t.Fatalf("expected message to contain 'excellent', got %s", msg)
	}
	if issues != nil {
		t.Fatalf("expected no issues, got %v", issues)
	}

	status, _, issues = classifyEnforcementLevel("reject", 50, "excellent")
	if status != "warning" {
		t.Fatalf("expected warning for partial, got %s", status)
	}
	if len(issues) == 0 {
		t.Fatal("expected issues for partial enforcement")
	}
}

func TestCheckDMARCSubdomainIssues(t *testing.T) {
	reject := "reject"
	none := "none"

	issues := checkDMARCSubdomainIssues(dmarcTags{policy: &reject, subdomainPolicy: &none})
	if len(issues) == 0 {
		t.Fatal("expected subdomain issue for sp=none with p=reject")
	}

	issues = checkDMARCSubdomainIssues(dmarcTags{policy: &reject})
	found := false
	for _, i := range issues {
		if strings.Contains(i, "np=") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected np= suggestion")
	}

	pNone := "none"
	issues = checkDMARCSubdomainIssues(dmarcTags{policy: &pNone})
	if len(issues) != 0 {
		t.Fatalf("expected no issues for p=none, got %v", issues)
	}

	issues = checkDMARCSubdomainIssues(dmarcTags{})
	if len(issues) != 0 {
		t.Fatalf("expected no issues for nil policy, got %v", issues)
	}
}

func TestCheckDMARCReportingIssues(t *testing.T) {
	issues := checkDMARCReportingIssues(dmarcTags{})
	if len(issues) == 0 {
		t.Fatal("expected issue for missing rua")
	}

	rua := "mailto:dmarc@example.com"
	issues = checkDMARCReportingIssues(dmarcTags{rua: &rua})
	if len(issues) != 0 {
		t.Fatalf("expected no issues when rua is set, got %v", issues)
	}
}

func TestBuildRUFNote(t *testing.T) {
	ruf := "mailto:forensic@example.com"
	result := buildRUFNote(dmarcTags{ruf: &ruf})
	if result["status"] != "present" {
		t.Fatalf("expected status=present, got %v", result["status"])
	}

	result = buildRUFNote(dmarcTags{})
	if result["status"] != "absent" {
		t.Fatalf("expected status=absent, got %v", result["status"])
	}
}

func TestEvaluateDMARCPolicy(t *testing.T) {
	reject := "reject"
	status, _, _ := evaluateDMARCPolicy(dmarcTags{policy: &reject, pct: 100, aspf: "relaxed", adkim: "relaxed"})
	if status != "success" {
		t.Fatalf("expected success, got %s", status)
	}

	status, _, _ = evaluateDMARCPolicy(dmarcTags{pct: 100, aspf: "relaxed", adkim: "relaxed"})
	if status != "info" {
		t.Fatalf("expected info for nil policy, got %s", status)
	}
}

func TestClassifyDMARCRecords(t *testing.T) {
	tests := []struct {
		name      string
		records   []string
		wantValid int
		wantLike  int
	}{
		{"empty", []string{}, 0, 0},
		{"valid v=dmarc1;", []string{"v=dmarc1; p=reject"}, 1, 0},
		{"bare v=dmarc1", []string{"v=dmarc1"}, 1, 0},
		{"v=dmarc1 with space", []string{"v=dmarc1 p=reject"}, 1, 0},
		{"dmarc-like", []string{"dmarc record not valid"}, 0, 1},
		{"non-dmarc", []string{"google-site-verification=abc"}, 0, 0},
		{"empty record", []string{""}, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, like := classifyDMARCRecords(tt.records)
			if len(valid) != tt.wantValid {
				t.Fatalf("expected %d valid, got %d", tt.wantValid, len(valid))
			}
			if len(like) != tt.wantLike {
				t.Fatalf("expected %d like, got %d", tt.wantLike, len(like))
			}
		})
	}
}

func TestEvaluateDMARCRecordSet(t *testing.T) {
	status, _, _, _ := evaluateDMARCRecordSet(nil)
	if status != "error" {
		t.Fatalf("expected error for no records, got %s", status)
	}

	status, _, issues, _ := evaluateDMARCRecordSet([]string{"v=dmarc1; p=reject", "v=dmarc1; p=none"})
	if status != "error" {
		t.Fatalf("expected error for multiple records, got %s", status)
	}
	if len(issues) == 0 {
		t.Fatal("expected issues for multiple records")
	}

	status, _, _, tags := evaluateDMARCRecordSet([]string{"v=dmarc1; p=reject; rua=mailto:d@example.com"})
	if status != "success" {
		t.Fatalf("expected success for single valid record, got %s", status)
	}
	if tags.policy == nil || *tags.policy != "reject" {
		t.Fatal("expected tags.policy=reject")
	}
}

func TestBuildDMARCbisTags(t *testing.T) {
	np := "reject"
	tt := "y"
	psd := "y"

	result := buildDMARCbisTags(dmarcTags{npPolicy: &np, tTesting: &tt, psdFlag: &psd})
	if result["np"] != "reject" {
		t.Fatalf("expected np=reject, got %s", result["np"])
	}
	if result["t"] != "y" {
		t.Fatalf("expected t=y, got %s", result["t"])
	}
	if result["psd"] != "y" {
		t.Fatalf("expected psd=y, got %s", result["psd"])
	}

	result = buildDMARCbisTags(dmarcTags{})
	if len(result) != 0 {
		t.Fatalf("expected empty map, got %v", result)
	}
}

func TestEnsureStringSlices(t *testing.T) {
	m := map[string]any{
		"a": nil,
		"b": []string{"x"},
		"c": nil,
	}
	ensureStringSlices(m, "a", "b", "c")
	if m["a"] == nil {
		t.Fatal("expected a to be non-nil")
	}
	if m["b"] == nil {
		t.Fatal("expected b to remain non-nil")
	}
}

func TestDetectMisplacedDMARC(t *testing.T) {
	result := DetectMisplacedDMARC([]string{"google-site-verification=abc"})
	if result["detected"].(bool) {
		t.Fatal("expected detected=false for non-DMARC records")
	}

	result = DetectMisplacedDMARC([]string{"v=dmarc1; p=reject"})
	if !result["detected"].(bool) {
		t.Fatal("expected detected=true for misplaced DMARC")
	}
	if result["policy_hint"] != "reject" {
		t.Fatalf("expected policy_hint=reject, got %v", result["policy_hint"])
	}
}

func TestExtractMailtoDomains(t *testing.T) {
	tests := []struct {
		name string
		rua  string
		want []string
	}{
		{"empty", "", nil},
		{"single", "mailto:dmarc@example.com", []string{"example.com"}},
		{"multiple", "mailto:a@example.com,mailto:b@other.org", []string{"example.com", "other.org"}},
		{"trailing dot", "mailto:dmarc@example.com.", []string{"example.com"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractMailtoDomains(tt.rua)
			if len(got) != len(tt.want) {
				t.Fatalf("expected %d domains, got %d: %v", len(tt.want), len(got), got)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("expected %s, got %s", tt.want[i], got[i])
				}
			}
		})
	}
}
