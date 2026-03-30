package analyzer

import (
	"strings"
	"testing"
)

func TestDANERFCAttackInvalidUsageFields(t *testing.T) {
	tests := []struct {
		name      string
		entry     string
		wantOK    bool
		wantUsage int
		wantName  string
	}{
		{"usage 0 valid PKIX-TA", "0 1 1 abcdef1234", true, 0, "PKIX-TA (CA constraint)"},
		{"usage 1 valid PKIX-EE", "1 1 1 abcdef1234", true, 1, "PKIX-EE (Certificate constraint)"},
		{"usage 2 valid DANE-TA", "2 1 1 abcdef1234", true, 2, "DANE-TA (Trust anchor)"},
		{"usage 3 valid DANE-EE", "3 1 1 abcdef1234", true, 3, "DANE-EE (Domain-issued certificate)"},
		{"usage 4 outside range", "4 1 1 abcdef1234", true, 4, "Unknown (4)"},
		{"usage 255 outside range", "255 1 1 abcdef1234", true, 255, "Unknown (255)"},
		{"usage -1 negative parsed as 0 by Atoi failure", "-1 1 1 abcdef1234", true, -1, "Unknown (-1)"},
		{"usage 99 far outside range", "99 0 1 abcdef1234", true, 99, "Unknown (99)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, ok := parseTLSAEntry(tt.entry, "mx.example.com", "_25._tcp.mx.example.com")
			if ok != tt.wantOK {
				t.Fatalf("parseTLSAEntry() ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if usage := rec["usage"].(int); usage != tt.wantUsage {
				t.Errorf("usage = %d, want %d", usage, tt.wantUsage)
			}
			if uname := rec["usage_name"].(string); uname != tt.wantName {
				t.Errorf("usage_name = %q, want %q", uname, tt.wantName)
			}
		})
	}
}

func TestDANERFCAttackInvalidSelectorFields(t *testing.T) {
	tests := []struct {
		name         string
		entry        string
		wantSelector int
		wantName     string
	}{
		{"selector 0 full cert", "3 0 1 abcdef", 0, "Full certificate"},
		{"selector 1 pubkey", "3 1 1 abcdef", 1, "Public key only (SubjectPublicKeyInfo)"},
		{"selector 2 outside range", "3 2 1 abcdef", 2, "Unknown (2)"},
		{"selector 99 far outside", "3 99 1 abcdef", 99, "Unknown (99)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, ok := parseTLSAEntry(tt.entry, "mx.example.com", "_25._tcp.mx.example.com")
			if !ok {
				t.Fatal("expected ok")
			}
			if sel := rec["selector"].(int); sel != tt.wantSelector {
				t.Errorf("selector = %d, want %d", sel, tt.wantSelector)
			}
			if sname := rec["selector_name"].(string); sname != tt.wantName {
				t.Errorf("selector_name = %q, want %q", sname, tt.wantName)
			}
		})
	}
}

func TestDANERFCAttackInvalidMatchingTypeFields(t *testing.T) {
	tests := []struct {
		name      string
		entry     string
		wantMType int
		wantName  string
	}{
		{"matching 0 exact", "3 1 0 abcdef", 0, "Exact match"},
		{"matching 1 SHA-256", "3 1 1 abcdef", 1, "SHA-256"},
		{"matching 2 SHA-512", "3 1 2 abcdef", 2, "SHA-512"},
		{"matching 3 outside range", "3 1 3 abcdef", 3, "Unknown (3)"},
		{"matching 255 outside range", "3 1 255 abcdef", 255, "Unknown (255)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, ok := parseTLSAEntry(tt.entry, "mx.example.com", "_25._tcp.mx.example.com")
			if !ok {
				t.Fatal("expected ok")
			}
			if mt := rec["matching_type"].(int); mt != tt.wantMType {
				t.Errorf("matching_type = %d, want %d", mt, tt.wantMType)
			}
			if mname := rec["matching_name"].(string); mname != tt.wantName {
				t.Errorf("matching_name = %q, want %q", mname, tt.wantName)
			}
		})
	}
}

func TestDANERFCAttackMalformedCertData(t *testing.T) {
	tests := []struct {
		name   string
		entry  string
		wantOK bool
	}{
		{"valid hex data", "3 1 1 aabbccddee", true},
		{"odd length hex still parsed", "3 1 1 abc", true},
		{"non-hex chars still parsed", "3 1 1 xyz!@#", true},
		{"empty cert data no 4th field", "3 1 1", false},
		{"only whitespace after fields", "3 1 1 ", false},
		{"multi-part cert data joined", "3 1 1 aabb ccdd eeff", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := parseTLSAEntry(tt.entry, "mx.example.com", "_25._tcp.mx.example.com")
			if ok != tt.wantOK {
				t.Errorf("parseTLSAEntry() ok = %v, want %v", ok, tt.wantOK)
			}
		})
	}
}

func TestDANERFCAttackEmptyTLSARecordData(t *testing.T) {
	tests := []struct {
		name   string
		entry  string
		wantOK bool
	}{
		{"completely empty", "", false},
		{"only spaces", "   ", false},
		{"single field", "3", false},
		{"two fields", "3 1", false},
		{"three fields no cert", "3 1 1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := parseTLSAEntry(tt.entry, "mx.example.com", "_25._tcp.mx.example.com")
			if ok != tt.wantOK {
				t.Errorf("parseTLSAEntry(%q) ok = %v, want %v", tt.entry, ok, tt.wantOK)
			}
		})
	}
}

func TestDANERFCAttackUsage2vs3Recommendations(t *testing.T) {
	tests := []struct {
		name          string
		usage         string
		wantRecommend bool
	}{
		{"usage 0 PKIX-TA gets recommendation", "0", true},
		{"usage 1 PKIX-EE gets recommendation", "1", true},
		{"usage 2 DANE-TA no recommendation", "2", false},
		{"usage 3 DANE-EE no recommendation", "3", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := tt.usage + " 1 1 abcdef1234567890"
			rec, ok := parseTLSAEntry(entry, "mx.example.com", "_25._tcp.mx.example.com")
			if !ok {
				t.Fatal("expected ok")
			}
			hasRecommend := rec["recommendation"] != nil
			if hasRecommend != tt.wantRecommend {
				t.Errorf("recommendation present = %v, want %v", hasRecommend, tt.wantRecommend)
			}
			if hasRecommend {
				rtext := rec["recommendation"].(string)
				if !strings.Contains(rtext, "RFC 7672") {
					t.Errorf("recommendation should reference RFC 7672, got: %s", rtext)
				}
			}
		})
	}
}

func TestDANERFCAttackTLSAWithoutDNSSEC(t *testing.T) {
	tlsa := []map[string]any{
		{"usage": 3, "matching_type": 1, "mx_host": "mx1.example.com"},
	}
	status, msg, issues := buildDANEVerdict(tlsa, []string{"mx1.example.com"}, []string{"mx1.example.com"}, nil)
	if status != "success" {
		t.Errorf("expected success status, got %q", status)
	}
	if msg == "" {
		t.Error("expected non-empty message")
	}
	_ = issues
}

func TestDANERFCAttackPartialMXCoverage(t *testing.T) {
	tests := []struct {
		name          string
		allTLSA       []map[string]any
		hostsWithDANE []string
		mxHosts       []string
		wantStatus    string
	}{
		{
			"all MX covered",
			[]map[string]any{
				{"usage": 3, "matching_type": 1, "mx_host": "mx1.example.com"},
				{"usage": 3, "matching_type": 1, "mx_host": "mx2.example.com"},
			},
			[]string{"mx1.example.com", "mx2.example.com"},
			[]string{"mx1.example.com", "mx2.example.com"},
			"success",
		},
		{
			"one of two MX covered",
			[]map[string]any{
				{"usage": 3, "matching_type": 1, "mx_host": "mx1.example.com"},
			},
			[]string{"mx1.example.com"},
			[]string{"mx1.example.com", "mx2.example.com"},
			"warning",
		},
		{
			"one of three MX covered",
			[]map[string]any{
				{"usage": 3, "matching_type": 1, "mx_host": "mx1.example.com"},
			},
			[]string{"mx1.example.com"},
			[]string{"mx1.example.com", "mx2.example.com", "mx3.example.com"},
			"warning",
		},
		{
			"no TLSA at all",
			nil,
			nil,
			[]string{"mx1.example.com", "mx2.example.com"},
			statusInfo,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, msg, issues := buildDANEVerdict(tt.allTLSA, tt.hostsWithDANE, tt.mxHosts, nil)
			if status != tt.wantStatus {
				t.Errorf("status = %q, want %q", status, tt.wantStatus)
			}
			if msg == "" {
				t.Error("expected non-empty message")
			}
			if tt.wantStatus == "warning" {
				found := false
				for _, iss := range issues {
					if strings.Contains(iss, "Missing DANE") {
						found = true
						break
					}
				}
				if !found {
					t.Error("warning verdict should include missing DANE issue")
				}
			}
		})
	}
}

func TestDANERFCAttackPartialMXCoverageMissingHostsCapped(t *testing.T) {
	tlsa := []map[string]any{
		{"usage": 3, "matching_type": 1, "mx_host": "mx1.example.com"},
	}
	mxHosts := []string{"mx1.example.com", "mx2.example.com", "mx3.example.com", "mx4.example.com", "mx5.example.com"}
	_, _, issues := buildDANEVerdict(tlsa, []string{"mx1.example.com"}, mxHosts, nil)

	for _, iss := range issues {
		if strings.Contains(iss, "Missing DANE") {
			parts := strings.Split(strings.TrimPrefix(iss, "Missing DANE for: "), ", ")
			if len(parts) > 3 {
				t.Errorf("missing hosts should be capped at 3, got %d", len(parts))
			}
			break
		}
	}
}

func TestDANERFCAttackCollectTLSAIssuesUsage01(t *testing.T) {
	records := []map[string]any{
		{"usage": 0, "matching_type": 1, "mx_host": "mx1.example.com"},
		{"usage": 1, "matching_type": 1, "mx_host": "mx2.example.com"},
	}
	issues := collectTLSAIssues(records)
	if len(issues) != 2 {
		t.Errorf("expected 2 issues for PKIX-based usages, got %d", len(issues))
	}
	for _, iss := range issues {
		if !strings.Contains(iss, "RFC 7672") {
			t.Errorf("issue should reference RFC 7672, got: %s", iss)
		}
	}
}

func TestDANERFCAttackCollectTLSAIssuesExactMatch(t *testing.T) {
	records := []map[string]any{
		{"usage": 3, "matching_type": 0, "mx_host": "mx1.example.com"},
	}
	issues := collectTLSAIssues(records)
	if len(issues) != 1 {
		t.Errorf("expected 1 issue for exact match, got %d", len(issues))
	}
	if !strings.Contains(issues[0], "SHA-256") {
		t.Errorf("issue should recommend SHA-256, got: %s", issues[0])
	}
}

func TestDANERFCAttackCollectTLSAIssuesCombined(t *testing.T) {
	records := []map[string]any{
		{"usage": 0, "matching_type": 0, "mx_host": "mx1.example.com"},
	}
	issues := collectTLSAIssues(records)
	if len(issues) != 2 {
		t.Errorf("expected 2 issues (PKIX usage + exact match), got %d", len(issues))
	}
}

func TestDANERFCAttackCollectTLSAIssuesClean(t *testing.T) {
	records := []map[string]any{
		{"usage": 3, "matching_type": 1, "mx_host": "mx1.example.com"},
		{"usage": 2, "matching_type": 2, "mx_host": "mx2.example.com"},
	}
	issues := collectTLSAIssues(records)
	if len(issues) != 0 {
		t.Errorf("expected 0 issues for clean DANE-TA/DANE-EE with SHA, got %d", len(issues))
	}
}

func TestDANERFCAttackBuildDANEVerdictNoTLSAProviderBlocked(t *testing.T) {
	cap := map[string]any{
		mapKeyDaneInbound:  false,
		mapKeyProviderName: "Microsoft 365",
	}
	status, msg, _ := buildDANEVerdictNoTLSA([]string{"mx.outlook.com"}, cap)
	if status != statusInfo {
		t.Errorf("status = %q, want %q", status, statusInfo)
	}
	if !strings.Contains(msg, "Microsoft 365") {
		t.Errorf("message should mention provider, got: %s", msg)
	}
	if !strings.Contains(msg, "does not support") {
		t.Errorf("message should say provider does not support DANE, got: %s", msg)
	}
}

func TestDANERFCAttackBuildDANEVerdictNoTLSANoProvider(t *testing.T) {
	status, msg, _ := buildDANEVerdictNoTLSA([]string{"mx1.example.com", "mx2.example.com"}, nil)
	if status != statusInfo {
		t.Errorf("status = %q, want %q", status, statusInfo)
	}
	if !strings.Contains(msg, "2 MX host") {
		t.Errorf("message should mention checked host count, got: %s", msg)
	}
}

func TestDANERFCAttackCertDataTruncation(t *testing.T) {
	longCert := strings.Repeat("ab", 50)
	entry := "3 1 1 " + longCert
	rec, ok := parseTLSAEntry(entry, "mx.example.com", "_25._tcp.mx.example.com")
	if !ok {
		t.Fatal("expected ok")
	}
	certDisplay := rec["certificate_data"].(string)
	if len(longCert) > 64 && !strings.HasSuffix(certDisplay, "...") {
		t.Errorf("long cert data should be truncated with ..., got: %s", certDisplay)
	}
}

func TestDANERFCAttackFullRecordFormat(t *testing.T) {
	rec, ok := parseTLSAEntry("3 1 1 aabbccdd", "mx.example.com", "_25._tcp.mx.example.com")
	if !ok {
		t.Fatal("expected ok")
	}
	fullRecord := rec["full_record"].(string)
	if !strings.HasPrefix(fullRecord, "3 1 1 ") {
		t.Errorf("full_record should start with '3 1 1 ', got: %s", fullRecord)
	}
}

func TestDANERFCAttackExtractMXHostsEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		records []string
		want    int
	}{
		{"trailing dots stripped", []string{"10 mx.example.com."}, 1},
		{"no trailing dot", []string{"10 mx.example.com"}, 1},
		{"bare dot rejected", []string{"."}, 0},
		{"empty string", []string{""}, 0},
		{"multiple priorities same host", []string{"10 mx.example.com.", "20 mx.example.com."}, 1},
		{"mixed formats", []string{"10 mx1.example.com.", "mx2.example.com."}, 2},
		{"whitespace heavy", []string{"  10  mx.example.com.  "}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractMXHosts(tt.records)
			if len(got) != tt.want {
				t.Errorf("extractMXHosts() len = %d, want %d", len(got), tt.want)
			}
		})
	}
}

func TestDANERFCAttackNewBaseDANEResultRequiredFields(t *testing.T) {
	r := newBaseDANEResult()
	requiredKeys := []string{
		"status", "has_dane", "mx_hosts_checked", "mx_hosts_with_dane",
		"tlsa_records", "requires_dnssec", "issues", "dane_deployable",
		"dnssec_chain_status", "dnssec_required_note",
	}
	for _, key := range requiredKeys {
		if _, ok := r[key]; !ok {
			t.Errorf("newBaseDANEResult() missing required key %q", key)
		}
	}
	if r["requires_dnssec"] != true {
		t.Error("RFC 6698 requires DNSSEC — requires_dnssec must be true")
	}
	note := r["dnssec_required_note"].(string)
	if !strings.Contains(note, "RFC 6698") {
		t.Errorf("dnssec_required_note should reference RFC 6698, got: %s", note)
	}
}

func TestDANERFCAttackBuildTransportDescriptionEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		cap  map[string]any
		want string
	}{
		{
			"full DANE support",
			map[string]any{mapKeyDaneInbound: true, mapKeyDaneOutbound: true, mapKeyProviderName: "Postfix", mapKeyAlternative: ""},
			"Full DANE support — inbound and outbound SMTP protected",
		},
		{
			"outbound only",
			map[string]any{mapKeyDaneInbound: false, mapKeyDaneOutbound: true, mapKeyProviderName: "Gmail", mapKeyAlternative: ""},
			"Outbound DANE verification supported; inbound requires alternative (e.g., MTA-STS)",
		},
		{
			"no support with alternative",
			map[string]any{mapKeyDaneInbound: false, mapKeyDaneOutbound: false, mapKeyProviderName: "O365", mapKeyAlternative: "MTA-STS"},
			"O365 does not support DANE. Consider MTA-STS as an alternative for transport security.",
		},
		{
			"no support no alternative",
			map[string]any{mapKeyDaneInbound: false, mapKeyDaneOutbound: false, mapKeyProviderName: "HostedMail", mapKeyAlternative: ""},
			"HostedMail does not support DANE.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildTransportDescription(tt.cap)
			if got != tt.want {
				t.Errorf("buildTransportDescription() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDANERFCAttackDeploymentGuidanceVariations(t *testing.T) {
	tests := []struct {
		name     string
		cap      map[string]any
		contains string
	}{
		{
			"inbound supported",
			map[string]any{mapKeyDaneInbound: true, mapKeyAlternative: ""},
			"supports DANE",
		},
		{
			"no inbound with alternative",
			map[string]any{mapKeyDaneInbound: false, mapKeyAlternative: "MTA-STS"},
			"MTA-STS",
		},
		{
			"no inbound no alternative",
			map[string]any{mapKeyDaneInbound: false, mapKeyAlternative: ""},
			"MTA-STS",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deploymentGuidance(tt.cap)
			if !strings.Contains(got, tt.contains) {
				t.Errorf("deploymentGuidance() = %q, should contain %q", got, tt.contains)
			}
		})
	}
}

func TestDANERFCAttackLookupNameBoundary(t *testing.T) {
	tests := []struct {
		name   string
		m      map[int]string
		key    int
		expect string
	}{
		{"usage boundary low", daneUsageNames, -1, "Unknown (-1)"},
		{"usage boundary high", daneUsageNames, 4, "Unknown (4)"},
		{"selector boundary", daneSelectorNames, 2, "Unknown (2)"},
		{"matching boundary", daneMatchingNames, 3, "Unknown (3)"},
		{"matching max", daneMatchingNames, 999, "Unknown (999)"},
		{"empty map", map[int]string{}, 0, "Unknown (0)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := lookupName(tt.m, tt.key)
			if got != tt.expect {
				t.Errorf("lookupName() = %q, want %q", got, tt.expect)
			}
		})
	}
}
