package analyzer

import (
	"testing"
)

func TestLookupName(t *testing.T) {
	tests := []struct {
		name   string
		m      map[int]string
		key    int
		expect string
	}{
		{"known usage", daneUsageNames, 0, "PKIX-TA (CA constraint)"},
		{"known usage 3", daneUsageNames, 3, "DANE-EE (Domain-issued certificate)"},
		{"unknown usage", daneUsageNames, 99, "Unknown (99)"},
		{"selector 0", daneSelectorNames, 0, "Full certificate"},
		{"selector 1", daneSelectorNames, 1, "Public key only (SubjectPublicKeyInfo)"},
		{"unknown selector", daneSelectorNames, 5, "Unknown (5)"},
		{"matching 1", daneMatchingNames, 1, "SHA-256"},
		{"matching 2", daneMatchingNames, 2, "SHA-512"},
		{"unknown matching", daneMatchingNames, 9, "Unknown (9)"},
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

func TestParseTLSAEntry(t *testing.T) {
	tests := []struct {
		name      string
		entry     string
		mxHost    string
		tlsaName  string
		wantOK    bool
		wantUsage int
	}{
		{"valid DANE-EE", "3 1 1 abcdef1234567890", "mx.example.com", "_25._tcp.mx.example.com", true, 3},
		{"valid PKIX-TA", "0 0 1 abcdef", "mx.example.com", "_25._tcp.mx.example.com", true, 0},
		{"too short", "3 1", "mx.example.com", "_25._tcp.mx.example.com", false, 0},
		{"empty", "", "mx.example.com", "_25._tcp.mx.example.com", false, 0},
		{"long cert data truncated", "3 1 1 " + longString(100), "mx.example.com", "_25._tcp.mx.example.com", true, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, ok := parseTLSAEntry(tt.entry, tt.mxHost, tt.tlsaName)
			if ok != tt.wantOK {
				t.Fatalf("parseTLSAEntry() ok = %v, want %v", ok, tt.wantOK)
			}
			if ok {
				if usage, _ := rec["usage"].(int); usage != tt.wantUsage {
					t.Errorf("usage = %d, want %d", usage, tt.wantUsage)
				}
				if rec["mx_host"] != tt.mxHost {
					t.Errorf("mx_host = %v, want %v", rec["mx_host"], tt.mxHost)
				}
			}
		})
	}
}

func TestParseTLSAEntryRecommendation(t *testing.T) {
	rec, ok := parseTLSAEntry("1 1 1 abcdef", "mx.example.com", "_25._tcp.mx.example.com")
	if !ok {
		t.Fatal("expected ok")
	}
	if rec["recommendation"] == nil {
		t.Error("expected recommendation for usage 1")
	}

	rec2, ok2 := parseTLSAEntry("3 1 1 abcdef", "mx.example.com", "_25._tcp.mx.example.com")
	if !ok2 {
		t.Fatal("expected ok")
	}
	if rec2["recommendation"] != nil {
		t.Error("expected no recommendation for usage 3")
	}
}

func TestExtractMXHosts(t *testing.T) {
	tests := []struct {
		name    string
		records []string
		want    int
	}{
		{"priority and host", []string{"10 mx1.example.com.", "20 mx2.example.com."}, 2},
		{"host only", []string{"mx1.example.com."}, 1},
		{"duplicates", []string{"10 mx1.example.com.", "20 mx1.example.com."}, 1},
		{"empty", []string{}, 0},
		{"dot only", []string{"."}, 0},
		{"whitespace", []string{"  10 mx.example.com.  "}, 1},
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

func TestPluralSuffix(t *testing.T) {
	if pluralSuffix(1) != "" {
		t.Error("expected empty for 1")
	}
	if pluralSuffix(2) != "s" {
		t.Error("expected 's' for 2")
	}
	if pluralSuffix(0) != "" {
		t.Error("expected empty for 0")
	}
}

func TestCollectTLSAIssues(t *testing.T) {
	records := []map[string]any{
		{"usage": 0, "matching_type": 1, "mx_host": "mx1.example.com"},
		{"usage": 3, "matching_type": 0, "mx_host": "mx2.example.com"},
		{"usage": 3, "matching_type": 1, "mx_host": "mx3.example.com"},
	}
	issues := collectTLSAIssues(records)
	if len(issues) != 2 {
		t.Errorf("expected 2 issues, got %d", len(issues))
	}
}

func TestFindMissingHosts(t *testing.T) {
	missing := findMissingHosts(
		[]string{"mx1.example.com", "mx2.example.com", "mx3.example.com"},
		[]string{"mx1.example.com"},
	)
	if len(missing) != 2 {
		t.Errorf("expected 2 missing, got %d", len(missing))
	}

	none := findMissingHosts([]string{"a"}, []string{"a"})
	if len(none) != 0 {
		t.Errorf("expected 0 missing, got %d", len(none))
	}

	many := findMissingHosts([]string{"a", "b", "c", "d", "e"}, []string{})
	if len(many) != 3 {
		t.Errorf("expected max 3 missing, got %d", len(many))
	}
}

func TestBuildDANEVerdictNoTLSA(t *testing.T) {
	status, msg, _ := buildDANEVerdictNoTLSA([]string{"mx1.example.com"}, nil)
	if status != statusInfo {
		t.Errorf("status = %q, want %q", status, statusInfo)
	}
	if msg == "" {
		t.Error("expected non-empty message")
	}

	cap := map[string]any{
		mapKeyDaneInbound:  false,
		mapKeyProviderName: "Microsoft 365",
	}
	status2, msg2, _ := buildDANEVerdictNoTLSA([]string{"mx1.example.com"}, cap)
	if status2 != statusInfo {
		t.Errorf("status = %q, want %q", status2, statusInfo)
	}
	if msg2 == "" {
		t.Error("expected non-empty message")
	}
}

func TestBuildDANEVerdict(t *testing.T) {
	tlsa := []map[string]any{
		{"usage": 3, "matching_type": 1, "mx_host": "mx1.example.com"},
	}

	status, _, _ := buildDANEVerdict(tlsa, []string{"mx1.example.com"}, []string{"mx1.example.com"}, nil)
	if status != "success" {
		t.Errorf("expected success, got %q", status)
	}

	status2, _, _ := buildDANEVerdict(tlsa, []string{"mx1.example.com"}, []string{"mx1.example.com", "mx2.example.com"}, nil)
	if status2 != "warning" {
		t.Errorf("expected warning for partial, got %q", status2)
	}

	status3, _, _ := buildDANEVerdict(nil, nil, []string{"mx1.example.com"}, nil)
	if status3 != statusInfo {
		t.Errorf("expected info for no TLSA, got %q", status3)
	}
}

func TestBuildTransportDescription(t *testing.T) {
	tests := []struct {
		name string
		cap  map[string]any
		want string
	}{
		{"full", map[string]any{mapKeyDaneInbound: true, mapKeyDaneOutbound: true, mapKeyProviderName: "Test", mapKeyAlternative: ""}, "Full DANE support — inbound and outbound SMTP protected"},
		{"outbound only", map[string]any{mapKeyDaneInbound: false, mapKeyDaneOutbound: true, mapKeyProviderName: "Test", mapKeyAlternative: ""}, "Outbound DANE verification supported; inbound requires alternative (e.g., MTA-STS)"},
		{"none with alt", map[string]any{mapKeyDaneInbound: false, mapKeyDaneOutbound: false, mapKeyProviderName: "Test", mapKeyAlternative: "MTA-STS"}, "Test does not support DANE. Consider MTA-STS as an alternative for transport security."},
		{"none no alt", map[string]any{mapKeyDaneInbound: false, mapKeyDaneOutbound: false, mapKeyProviderName: "Test", mapKeyAlternative: ""}, "Test does not support DANE."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildTransportDescription(tt.cap)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDeploymentGuidance(t *testing.T) {
	inbound := map[string]any{mapKeyDaneInbound: true, mapKeyAlternative: ""}
	got := deploymentGuidance(inbound)
	if got == "" {
		t.Error("expected non-empty guidance")
	}

	noInbound := map[string]any{mapKeyDaneInbound: false, mapKeyAlternative: "MTA-STS"}
	got2 := deploymentGuidance(noInbound)
	if got2 == "" {
		t.Error("expected non-empty guidance")
	}

	noAlt := map[string]any{mapKeyDaneInbound: false, mapKeyAlternative: ""}
	got3 := deploymentGuidance(noAlt)
	if got3 == "" {
		t.Error("expected non-empty guidance")
	}
}

func TestBuildProviderContext(t *testing.T) {
	cap := map[string]any{
		mapKeyProviderName: "Test Provider",
		mapKeyDaneInbound:  true,
		mapKeyDaneOutbound: false,
		mapKeyAlternative:  "MTA-STS",
	}
	ctx := buildProviderContext(cap)
	if ctx[mapKeyProviderName] != "Test Provider" {
		t.Error("expected provider name")
	}
	if ctx["alternative_protection"] != "MTA-STS" {
		t.Error("expected alternative_protection")
	}
}

func TestNewBaseDANEResult(t *testing.T) {
	r := newBaseDANEResult()
	if r["status"] != statusInfo {
		t.Error("expected info status")
	}
	if r["has_dane"] != false {
		t.Error("expected has_dane false")
	}
	if r["requires_dnssec"] != true {
		t.Error("expected requires_dnssec true")
	}
}

func longString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	return string(b)
}
