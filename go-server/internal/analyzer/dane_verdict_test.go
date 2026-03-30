package analyzer

import (
	"strings"
	"testing"
)

func TestLookupNameEmptyMap(t *testing.T) {
	got := lookupName(map[int]string{}, 0)
	if !strings.Contains(got, "Unknown") {
		t.Errorf("expected Unknown for empty map, got %q", got)
	}
}

func TestParseTLSAEntryFields(t *testing.T) {
	rec, ok := parseTLSAEntry("2 0 1 aabbcc", "mx.test.com", "_25._tcp.mx.test.com")
	if !ok {
		t.Fatal("expected ok")
	}
	if rec["usage"] != 2 {
		t.Errorf("usage = %v, want 2", rec["usage"])
	}
	if rec["selector"] != 0 {
		t.Errorf("selector = %v, want 0", rec["selector"])
	}
	if rec["matching_type"] != 1 {
		t.Errorf("matching_type = %v, want 1", rec["matching_type"])
	}
	if rec["tlsa_name"] != "_25._tcp.mx.test.com" {
		t.Errorf("tlsa_name = %v", rec["tlsa_name"])
	}
	if rec["usage_name"] != "DANE-TA (Trust anchor)" {
		t.Errorf("usage_name = %v", rec["usage_name"])
	}
	if rec["selector_name"] != "Full certificate" {
		t.Errorf("selector_name = %v", rec["selector_name"])
	}
	if rec["matching_name"] != "SHA-256" {
		t.Errorf("matching_name = %v", rec["matching_name"])
	}
	if rec["recommendation"] != nil {
		t.Error("expected no recommendation for usage 2")
	}
}

func TestParseTLSAEntryUsage0Recommendation(t *testing.T) {
	rec, ok := parseTLSAEntry("0 1 1 aabb", "mx.test.com", "_25._tcp.mx.test.com")
	if !ok {
		t.Fatal("expected ok")
	}
	if rec["recommendation"] == nil {
		t.Error("expected recommendation for usage 0")
	}
}

func TestParseTLSAEntryCertTruncation(t *testing.T) {
	longCert := strings.Repeat("ab", 40)
	rec, ok := parseTLSAEntry("3 1 1 "+longCert, "mx.test.com", "_25._tcp.mx.test.com")
	if !ok {
		t.Fatal("expected ok")
	}
	certDisplay := rec["certificate_data"].(string)
	if len(certDisplay) > 70 {
		t.Errorf("certificate_data not truncated: len=%d", len(certDisplay))
	}
	if !strings.HasSuffix(certDisplay, "...") {
		t.Error("expected truncated cert to end with ...")
	}
}

func TestParseTLSAEntryShortCert(t *testing.T) {
	rec, ok := parseTLSAEntry("3 1 1 ab", "mx.test.com", "_25._tcp.mx.test.com")
	if !ok {
		t.Fatal("expected ok")
	}
	certDisplay := rec["certificate_data"].(string)
	if certDisplay != "ab" {
		t.Errorf("expected 'ab', got %q", certDisplay)
	}
}

func TestExtractMXHostsTrailingDot(t *testing.T) {
	hosts := extractMXHosts([]string{"10 mx.example.com."})
	if len(hosts) != 1 {
		t.Fatalf("expected 1, got %d", len(hosts))
	}
	if hosts[0] != "mx.example.com" {
		t.Errorf("expected mx.example.com, got %q", hosts[0])
	}
}

func TestCollectTLSAIssuesNoIssues(t *testing.T) {
	records := []map[string]any{
		{"usage": 3, "matching_type": 1, "mx_host": "mx.example.com"},
	}
	issues := collectTLSAIssues(records)
	if len(issues) != 0 {
		t.Errorf("expected 0 issues, got %d", len(issues))
	}
}

func TestCollectTLSAIssuesBothFlags(t *testing.T) {
	records := []map[string]any{
		{"usage": 1, "matching_type": 0, "mx_host": "mx.example.com"},
	}
	issues := collectTLSAIssues(records)
	if len(issues) != 2 {
		t.Errorf("expected 2 issues (PKIX + exact match), got %d", len(issues))
	}
}

func TestFindMissingHostsAllPresent(t *testing.T) {
	missing := findMissingHosts(
		[]string{"mx1.example.com", "mx2.example.com"},
		[]string{"mx1.example.com", "mx2.example.com"},
	)
	if len(missing) != 0 {
		t.Errorf("expected 0 missing, got %d", len(missing))
	}
}

func TestBuildDANEVerdictAllHostsWithDANE(t *testing.T) {
	tlsa := []map[string]any{
		{"usage": 3, "matching_type": 1, "mx_host": "mx1.example.com"},
		{"usage": 3, "matching_type": 1, "mx_host": "mx2.example.com"},
	}
	status, msg, _ := buildDANEVerdict(tlsa,
		[]string{"mx1.example.com", "mx2.example.com"},
		[]string{"mx1.example.com", "mx2.example.com"}, nil)
	if status != "success" {
		t.Errorf("expected success, got %q", status)
	}
	if !strings.Contains(msg, "all") {
		t.Errorf("expected 'all' in message, got %q", msg)
	}
}

func TestBuildDANEVerdictPartialCoverage(t *testing.T) {
	tlsa := []map[string]any{
		{"usage": 3, "matching_type": 1, "mx_host": "mx1.example.com"},
	}
	status, msg, issues := buildDANEVerdict(tlsa,
		[]string{"mx1.example.com"},
		[]string{"mx1.example.com", "mx2.example.com", "mx3.example.com"}, nil)
	if status != "warning" {
		t.Errorf("expected warning, got %q", status)
	}
	if !strings.Contains(msg, "partially") {
		t.Errorf("expected 'partially' in message, got %q", msg)
	}
	found := false
	for _, issue := range issues {
		if strings.Contains(issue, "Missing DANE") {
			found = true
		}
	}
	if !found {
		t.Error("expected 'Missing DANE' issue")
	}
}

func TestBuildDANEVerdictNoTLSAWithCapability(t *testing.T) {
	cap := map[string]any{
		mapKeyDaneInbound:  true,
		mapKeyProviderName: "Proton Mail",
	}
	status, msg, _ := buildDANEVerdictNoTLSA([]string{"mx.protonmail.ch"}, cap)
	if status != statusInfo {
		t.Errorf("expected info, got %q", status)
	}
	if !strings.Contains(msg, "No DANE/TLSA") {
		t.Errorf("expected standard message, got %q", msg)
	}
}

func TestBuildTransportDescriptionNoDANE(t *testing.T) {
	cap := map[string]any{
		mapKeyDaneInbound:  false,
		mapKeyDaneOutbound: false,
		mapKeyProviderName: "Microsoft 365",
		mapKeyAlternative:  "",
	}
	desc := buildTransportDescription(cap)
	if !strings.Contains(desc, "Microsoft 365") {
		t.Errorf("expected provider name in desc, got %q", desc)
	}
}

func TestDeploymentGuidanceInboundSupported(t *testing.T) {
	cap := map[string]any{mapKeyDaneInbound: true, mapKeyAlternative: ""}
	got := deploymentGuidance(cap)
	if !strings.Contains(got, "Publish TLSA") {
		t.Errorf("expected publish guidance, got %q", got)
	}
}

func TestDeploymentGuidanceNoInboundNoAlt(t *testing.T) {
	cap := map[string]any{mapKeyDaneInbound: false, mapKeyAlternative: ""}
	got := deploymentGuidance(cap)
	if !strings.Contains(got, "MTA-STS") {
		t.Errorf("expected MTA-STS suggestion, got %q", got)
	}
}

func TestBuildProviderContextWithoutAlternative(t *testing.T) {
	cap := map[string]any{
		mapKeyProviderName: "Gmail",
		mapKeyDaneInbound:  false,
		mapKeyDaneOutbound: true,
	}
	ctx := buildProviderContext(cap)
	if ctx[mapKeyProviderName] != "Gmail" {
		t.Errorf("expected Gmail, got %v", ctx[mapKeyProviderName])
	}
	if _, ok := ctx["alternative_protection"]; ok {
		t.Error("expected no alternative_protection when not in cap")
	}
}

func TestApplyMXCapability(t *testing.T) {
	base := newBaseDANEResult()
	cap := map[string]any{
		mapKeyProviderName: "Test Provider",
		mapKeyDaneInbound:  true,
		mapKeyDaneOutbound: true,
		mapKeyAlternative:  "MTA-STS",
	}
	applyMXCapability(base, cap, "example.com")
	if base["mx_provider"] == nil {
		t.Error("expected mx_provider set")
	}
	if base[mapKeyDaneDeployable] != true {
		t.Error("expected dane_deployable true for inbound-capable provider")
	}
	ts := base["transport_security"].(map[string]any)
	if ts["smtp_inbound"] != true {
		t.Error("expected smtp_inbound true")
	}
}

func TestApplyMXCapabilityNoInbound(t *testing.T) {
	base := newBaseDANEResult()
	cap := map[string]any{
		mapKeyProviderName: "NoDANE Corp",
		mapKeyDaneInbound:  false,
		mapKeyDaneOutbound: false,
		mapKeyAlternative:  "",
	}
	applyMXCapability(base, cap, "example.com")
	ts := base["transport_security"].(map[string]any)
	if ts["smtp_inbound"] != false {
		t.Error("expected smtp_inbound false")
	}
}

func TestPluralSuffixEdgeCases(t *testing.T) {
	if pluralSuffix(10) != "s" {
		t.Error("expected 's' for 10")
	}
	if pluralSuffix(-1) != "" {
		t.Error("expected empty for -1")
	}
}
