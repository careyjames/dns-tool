package analyzer

import (
	"strings"
	"testing"
)

func TestParseDMARCTags_PolicyNone(t *testing.T) {
	tags := parseDMARCTags("v=dmarc1; p=none")
	if tags.policy == nil || *tags.policy != "none" {
		t.Fatal("expected policy=none")
	}
}

func TestParseDMARCTags_PolicyQuarantine(t *testing.T) {
	tags := parseDMARCTags("v=dmarc1; p=quarantine; pct=75")
	if tags.policy == nil || *tags.policy != "quarantine" {
		t.Fatal("expected policy=quarantine")
	}
	if tags.pct != 75 {
		t.Fatalf("expected pct=75, got %d", tags.pct)
	}
}

func TestParseDMARCTags_CaseInsensitive(t *testing.T) {
	tags := parseDMARCTags("V=DMARC1; P=REJECT; ASPF=S; ADKIM=S")
	if tags.policy == nil || *tags.policy != "reject" {
		t.Fatal("expected policy=reject (lowercase)")
	}
	if tags.aspf != "strict" {
		t.Fatalf("expected aspf=strict, got %s", tags.aspf)
	}
	if tags.adkim != "strict" {
		t.Fatalf("expected adkim=strict, got %s", tags.adkim)
	}
}

func TestParseDMARCTags_RelaxedAlignmentDefaults(t *testing.T) {
	tags := parseDMARCTags("v=dmarc1; p=reject")
	if tags.aspf != "relaxed" {
		t.Fatalf("expected default aspf=relaxed, got %s", tags.aspf)
	}
	if tags.adkim != "relaxed" {
		t.Fatalf("expected default adkim=relaxed, got %s", tags.adkim)
	}
}

func TestParseDMARCTags_RUAExtraction(t *testing.T) {
	tags := parseDMARCTags("v=dmarc1; p=reject; rua=mailto:dmarc@example.com")
	if tags.rua == nil {
		t.Fatal("expected rua to be set")
	}
	if !strings.Contains(*tags.rua, "mailto:dmarc@example.com") {
		t.Fatalf("expected rua to contain mailto address, got %s", *tags.rua)
	}
}

func TestParseDMARCTags_NoRUF(t *testing.T) {
	tags := parseDMARCTags("v=dmarc1; p=reject; rua=mailto:d@example.com")
	if tags.ruf != nil {
		t.Fatalf("expected ruf=nil, got %v", *tags.ruf)
	}
}

func TestParseDMARCTags_NpPolicy(t *testing.T) {
	tags := parseDMARCTags("v=dmarc1; p=reject; np=quarantine")
	if tags.npPolicy == nil || *tags.npPolicy != "quarantine" {
		t.Fatal("expected np=quarantine")
	}
}

func TestClassifyDMARCPolicyVerdict_Messages(t *testing.T) {
	tests := []struct {
		name        string
		policy      string
		pct         int
		wantContain string
	}{
		{"none message", "none", 100, "monitoring"},
		{"reject full message", "reject", 100, "excellent"},
		{"quarantine full message", "quarantine", 100, "good"},
		{"reject partial message", "reject", 50, "50%"},
		{"unknown message", "xyz", 100, "unclear"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, msg, _ := classifyDMARCPolicyVerdict(tt.policy, tt.pct)
			if !strings.Contains(strings.ToLower(msg), strings.ToLower(tt.wantContain)) {
				t.Fatalf("expected message to contain %q, got %q", tt.wantContain, msg)
			}
		})
	}
}

func TestClassifyDMARCPolicyVerdict_NoneIssues(t *testing.T) {
	_, _, issues := classifyDMARCPolicyVerdict("none", 100)
	if len(issues) == 0 {
		t.Fatal("expected issues for p=none")
	}
	found := false
	for _, issue := range issues {
		if strings.Contains(issue, "p=none") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected p=none issue")
	}
}

func TestClassifyEnforcementLevel_PartialIssue(t *testing.T) {
	_, _, issues := classifyEnforcementLevel("quarantine", 25, "good")
	if len(issues) == 0 {
		t.Fatal("expected issue for partial enforcement")
	}
	if !strings.Contains(issues[0], "25%") {
		t.Fatalf("expected 25%% in issue, got %s", issues[0])
	}
}

func TestCheckDMARCSubdomainIssues_RejectWithSpNone(t *testing.T) {
	reject := "reject"
	none := "none"
	issues := checkDMARCSubdomainIssues(dmarcTags{policy: &reject, subdomainPolicy: &none})
	found := false
	for _, issue := range issues {
		if strings.Contains(issue, "sp=none") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected sp=none issue")
	}
}

func TestCheckDMARCSubdomainIssues_QuarantineNoNp(t *testing.T) {
	quarantine := "quarantine"
	issues := checkDMARCSubdomainIssues(dmarcTags{policy: &quarantine})
	found := false
	for _, issue := range issues {
		if strings.Contains(issue, "np=") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected np= suggestion for quarantine policy")
	}
}

func TestCheckDMARCSubdomainIssues_WithNpSet(t *testing.T) {
	reject := "reject"
	npReject := "reject"
	spReject := "reject"
	issues := checkDMARCSubdomainIssues(dmarcTags{policy: &reject, subdomainPolicy: &spReject, npPolicy: &npReject})
	for _, issue := range issues {
		if strings.Contains(issue, "np=") {
			t.Fatal("should not suggest np= when np is set")
		}
	}
}

func TestCheckDMARCReportingIssues_MissingRUA(t *testing.T) {
	issues := checkDMARCReportingIssues(dmarcTags{})
	if len(issues) == 0 {
		t.Fatal("expected issue for missing rua")
	}
	if !strings.Contains(issues[0], "rua") {
		t.Fatalf("expected rua issue, got %s", issues[0])
	}
}

func TestBuildRUFNote_PresentContent(t *testing.T) {
	ruf := "mailto:f@example.com"
	note := buildRUFNote(dmarcTags{ruf: &ruf})
	if note["status"] != "present" {
		t.Fatal("expected status=present")
	}
	if note["summary"] == nil || note["summary"] == "" {
		t.Fatal("expected summary to be set")
	}
	if note["detail"] == nil || note["detail"] == "" {
		t.Fatal("expected detail to be set")
	}
}

func TestBuildRUFNote_AbsentContent(t *testing.T) {
	note := buildRUFNote(dmarcTags{})
	if note["status"] != "absent" {
		t.Fatal("expected status=absent")
	}
	summary := note["summary"].(string)
	if !strings.Contains(summary, "correct") {
		t.Fatalf("expected 'correct' in absent summary, got %s", summary)
	}
}

func TestEvaluateDMARCPolicy_NilPolicy(t *testing.T) {
	status, msg, _ := evaluateDMARCPolicy(dmarcTags{pct: 100, aspf: "relaxed", adkim: "relaxed"})
	if status != "info" {
		t.Fatalf("expected info, got %s", status)
	}
	if !strings.Contains(msg, "unclear") {
		t.Fatalf("expected 'unclear' in message, got %s", msg)
	}
}

func TestEvaluateDMARCPolicy_RejectWithReporting(t *testing.T) {
	reject := "reject"
	rua := "mailto:d@example.com"
	status, _, issues := evaluateDMARCPolicy(dmarcTags{policy: &reject, pct: 100, aspf: "relaxed", adkim: "relaxed", rua: &rua})
	if status != "success" {
		t.Fatalf("expected success, got %s", status)
	}
	for _, issue := range issues {
		if strings.Contains(issue, "rua") {
			t.Fatal("should not have rua issue when rua is set")
		}
	}
}

func TestEvaluateDMARCPolicy_NoneAccumulatesIssues(t *testing.T) {
	none := "none"
	_, _, issues := evaluateDMARCPolicy(dmarcTags{policy: &none, pct: 100, aspf: "relaxed", adkim: "relaxed"})
	if len(issues) < 2 {
		t.Fatalf("expected at least 2 issues (policy + reporting), got %d: %v", len(issues), issues)
	}
}

func TestClassifyDMARCRecords_CaseInsensitive(t *testing.T) {
	valid, _ := classifyDMARCRecords([]string{"V=DMARC1; p=reject"})
	if len(valid) != 1 {
		t.Fatalf("expected 1 valid for uppercase, got %d", len(valid))
	}
}

func TestClassifyDMARCRecords_MultipleValid(t *testing.T) {
	valid, _ := classifyDMARCRecords([]string{"v=dmarc1; p=reject", "v=dmarc1; p=none"})
	if len(valid) != 2 {
		t.Fatalf("expected 2 valid, got %d", len(valid))
	}
}

func TestClassifyDMARCRecords_SpaceDelimited(t *testing.T) {
	valid, _ := classifyDMARCRecords([]string{"v=dmarc1 p=reject"})
	if len(valid) != 1 {
		t.Fatalf("expected 1 valid for space-delimited, got %d", len(valid))
	}
}

func TestEvaluateDMARCRecordSet_SingleRejectTags(t *testing.T) {
	status, _, _, tags := evaluateDMARCRecordSet([]string{"v=dmarc1; p=reject; pct=50; rua=mailto:d@e.com"})
	if status != "warning" {
		t.Fatalf("expected warning for pct=50, got %s", status)
	}
	if tags.pct != 50 {
		t.Fatalf("expected pct=50, got %d", tags.pct)
	}
}

func TestBuildDMARCbisTags_PartialFields(t *testing.T) {
	np := "reject"
	result := buildDMARCbisTags(dmarcTags{npPolicy: &np})
	if result["np"] != "reject" {
		t.Fatalf("expected np=reject, got %s", result["np"])
	}
	if _, ok := result["t"]; ok {
		t.Fatal("expected no t key")
	}
	if _, ok := result["psd"]; ok {
		t.Fatal("expected no psd key")
	}
}

func TestDetectMisplacedDMARC_Empty(t *testing.T) {
	result := DetectMisplacedDMARC(nil)
	if result["detected"].(bool) {
		t.Fatal("expected detected=false for nil records")
	}
}

func TestDetectMisplacedDMARC_NoPolicyHint(t *testing.T) {
	result := DetectMisplacedDMARC([]string{"v=dmarc1"})
	if !result["detected"].(bool) {
		t.Fatal("expected detected=true")
	}
	if result["policy_hint"] != "" {
		t.Fatalf("expected empty policy_hint for bare dmarc record, got %v", result["policy_hint"])
	}
}

func TestDetectMisplacedDMARC_Message(t *testing.T) {
	result := DetectMisplacedDMARC([]string{"v=dmarc1; p=none"})
	msg := result["message"].(string)
	if !strings.Contains(msg, "_dmarc") {
		t.Fatalf("expected _dmarc mention in message, got %s", msg)
	}
}

func TestExtractMailtoDomains_NoDomain(t *testing.T) {
	result := ExtractMailtoDomains("mailto:nodomain")
	if len(result) != 0 {
		t.Fatalf("expected 0 domains for no @ sign, got %v", result)
	}
}

func TestExtractMailtoDomains_CaseInsensitive(t *testing.T) {
	result := ExtractMailtoDomains("MAILTO:dmarc@EXAMPLE.COM")
	if len(result) != 1 {
		t.Fatalf("expected 1 domain, got %d", len(result))
	}
	if result[0] != "example.com" {
		t.Fatalf("expected example.com (lowercase), got %s", result[0])
	}
}

func TestDetectUnknownDMARCTags_NoUnknown(t *testing.T) {
	unknown := detectUnknownDMARCTags("v=dmarc1; p=reject; rua=mailto:d@e.com; aspf=s; adkim=s; pct=100")
	if len(unknown) != 0 {
		t.Fatalf("expected 0 unknown tags, got %v", unknown)
	}
}

func TestDetectUnknownDMARCTags_Typo(t *testing.T) {
	unknown := detectUnknownDMARCTags("v=dmarc1; plicy=reject; rua=mailto:d@e.com")
	if len(unknown) != 1 {
		t.Fatalf("expected 1 unknown tag, got %v", unknown)
	}
	if !strings.Contains(unknown[0], "plicy") {
		t.Fatalf("expected 'plicy' in unknown tag, got %s", unknown[0])
	}
}

func TestDetectUnknownDMARCTags_MultipleUnknown(t *testing.T) {
	unknown := detectUnknownDMARCTags("v=dmarc1; p=reject; policey=reject; xyz=abc")
	if len(unknown) != 2 {
		t.Fatalf("expected 2 unknown tags, got %v", unknown)
	}
}

func TestDetectUnknownDMARCTags_DMARCbisTags(t *testing.T) {
	unknown := detectUnknownDMARCTags("v=dmarc1; p=reject; np=reject; t=y; psd=y")
	if len(unknown) != 0 {
		t.Fatalf("expected 0 unknown for DMARCbis tags, got %v", unknown)
	}
}

func TestDetectUnknownDMARCTags_FoRiRfKnown(t *testing.T) {
	unknown := detectUnknownDMARCTags("v=dmarc1; p=reject; fo=1; ri=86400; rf=afrf")
	if len(unknown) != 0 {
		t.Fatalf("expected 0 unknown for fo/ri/rf tags, got %v", unknown)
	}
}

func TestCheckDMARCUnknownTags_GeneratesIssue(t *testing.T) {
	tags := parseDMARCTags("v=dmarc1; plicy=reject; p=none")
	issues := checkDMARCUnknownTags(tags)
	if len(issues) != 1 {
		t.Fatalf("expected 1 issue, got %d: %v", len(issues), issues)
	}
	if !strings.Contains(issues[0], "plicy") {
		t.Fatalf("expected 'plicy' in issue, got %s", issues[0])
	}
	if !strings.Contains(issues[0], "RFC 7489") {
		t.Fatalf("expected RFC reference in issue, got %s", issues[0])
	}
}

func TestCheckDMARCUnknownTags_NoUnknown(t *testing.T) {
	tags := parseDMARCTags("v=dmarc1; p=reject; rua=mailto:d@e.com")
	issues := checkDMARCUnknownTags(tags)
	if len(issues) != 0 {
		t.Fatalf("expected no issues for clean record, got %v", issues)
	}
}

func TestEnsureStringSlices_NewKey(t *testing.T) {
	m := map[string]any{
		"existing": []string{"a"},
	}
	ensureStringSlices(m, "existing", "missing")
	if m["missing"] == nil {
		t.Fatal("expected missing key to be initialized")
	}
	if m["existing"].([]string)[0] != "a" {
		t.Fatal("expected existing key to be preserved")
	}
}
