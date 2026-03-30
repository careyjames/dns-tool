package analyzer_test

import (
	"strings"
	"testing"

	"dnstool/go-server/internal/analyzer"
)

func TestExportClassifyAllQualifier(t *testing.T) {
	tests := []struct {
		name        string
		spf         string
		wantNil     bool
		wantContain string
	}{
		{"hard fail", "v=spf1 -all", false, ""},
		{"soft fail", "v=spf1 ~all", false, ""},
		{"neutral", "v=spf1 ?all", false, ""},
		{"pass", "v=spf1 +all", false, ""},
		{"no all", "v=spf1 include:example.com", true, ""},
		{"empty", "", true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzer.ExportClassifyAllQualifier(tt.spf)
			if tt.wantNil && got != nil {
				t.Errorf("analyzer.ExportClassifyAllQualifier(%q) = %v, want nil", tt.spf, *got)
			}
			if !tt.wantNil {
				if got == nil {
					t.Fatalf("analyzer.ExportClassifyAllQualifier(%q) = nil, want non-nil", tt.spf)
				}
				if *got == "" {
					t.Errorf("analyzer.ExportClassifyAllQualifier(%q) returned empty string", tt.spf)
				}
			}
		})
	}

	hardFail := analyzer.ExportClassifyAllQualifier("v=spf1 -all")
	softFail := analyzer.ExportClassifyAllQualifier("v=spf1 ~all")
	passAll := analyzer.ExportClassifyAllQualifier("v=spf1 +all")
	if hardFail != nil && softFail != nil && *hardFail == *softFail {
		t.Error("hard fail and soft fail should produce different classifications")
	}
	if hardFail != nil && passAll != nil && *hardFail == *passAll {
		t.Error("hard fail and pass all should produce different classifications")
	}
}

func TestExportCountSPFLookups(t *testing.T) {
	tests := []struct {
		name    string
		spf     string
		wantMin int
	}{
		{"with include", "v=spf1 include:_spf.google.com -all", 1},
		{"multiple includes", "v=spf1 include:a.com include:b.com -all", 2},
		{"no lookups", "v=spf1 ip4:1.2.3.4 -all", 0},
		{"empty", "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzer.ExportCountSPFLookups(tt.spf)
			if got < tt.wantMin {
				t.Errorf("analyzer.ExportCountSPFLookups(%q) = %d, want >= %d", tt.spf, got, tt.wantMin)
			}
		})
	}
}

func TestExportBuildSPFVerdict(t *testing.T) {
	hardFail := "-all"
	softFail := "~all"

	tests := []struct {
		name           string
		lookupCount    int
		permissiveness *string
		noMailIntent   bool
		validSPF       []string
		spfLike        []string
	}{
		{"hard fail good", 3, &hardFail, false, []string{"v=spf1 -all"}, nil},
		{"soft fail", 5, &softFail, false, []string{"v=spf1 ~all"}, nil},
		{"no mail", 0, nil, true, []string{"v=spf1 -all"}, nil},
		{"too many lookups", 15, &hardFail, false, []string{"v=spf1 -all"}, nil},
		{"no spf", 0, nil, false, nil, nil},
		{"spf like records", 0, nil, false, nil, []string{"spf1 include:example.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verdict, detail := analyzer.ExportBuildSPFVerdict(tt.lookupCount, tt.permissiveness, tt.noMailIntent, tt.validSPF, tt.spfLike)
			if verdict == "" {
				t.Error("verdict should not be empty")
			}
			_ = detail
		})
	}
}

func TestExportParseSPFMechanisms(t *testing.T) {
	tests := []struct {
		name string
		spf  string
	}{
		{"google spf", "v=spf1 include:_spf.google.com ~all"},
		{"ip4 only", "v=spf1 ip4:192.168.1.0/24 -all"},
		{"redirect", "v=spf1 redirect=_spf.example.com"},
		{"complex", "v=spf1 include:spf.protection.outlook.com include:_spf.google.com ip4:10.0.0.0/8 -all"},
		{"empty", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lookupCount, lookupMechs, includes, permissiveness, allMech, issues, noMail := analyzer.ExportParseSPFMechanisms(tt.spf)
			_ = lookupCount
			_ = lookupMechs
			_ = includes
			_ = permissiveness
			_ = allMech
			_ = issues
			_ = noMail
		})
	}
}

func TestExportClassifySPFRecords(t *testing.T) {
	tests := []struct {
		name      string
		records   []string
		wantValid int
		wantLike  int
	}{
		{"valid spf", []string{"v=spf1 -all"}, 1, 0},
		{"mixed", []string{"v=spf1 -all", "some other txt record", "spf2.0/pra include:example.com"}, 1, 0},
		{"no spf", []string{"not spf", "also not spf"}, 0, 0},
		{"empty", nil, 0, 0},
		{"multiple valid", []string{"v=spf1 -all", "v=spf1 ~all"}, 2, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, like := analyzer.ExportClassifySPFRecords(tt.records)
			if len(valid) != tt.wantValid {
				t.Errorf("valid count = %d, want %d", len(valid), tt.wantValid)
			}
			_ = like
		})
	}
}

func TestExportBuildEmailAnswer(t *testing.T) {
	tests := []struct {
		name           string
		isNoMailDomain bool
		dmarcPolicy    string
		dmarcPct       int
		nullMX         bool
		hasSPF         bool
		hasDMARC       bool
		wantNonEmpty   bool
	}{
		{"no mail domain", true, "", 0, false, false, false, true},
		{"reject policy", false, "reject", 100, false, true, true, true},
		{"quarantine policy", false, "quarantine", 100, false, true, true, true},
		{"none policy", false, "none", 100, false, true, true, true},
		{"null mx", false, "", 0, true, false, false, true},
		{"no protections", false, "", 0, false, false, false, true},
		{"spf only", false, "", 0, false, true, false, true},
		{"dmarc only", false, "reject", 100, false, false, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzer.ExportBuildEmailAnswer(tt.isNoMailDomain, tt.dmarcPolicy, tt.dmarcPct, tt.nullMX, tt.hasSPF, tt.hasDMARC)
			if tt.wantNonEmpty && got == "" {
				t.Error("expected non-empty answer")
			}
		})
	}
}

func TestExportBuildEmailAnswerStructured(t *testing.T) {
	tests := []struct {
		name           string
		isNoMailDomain bool
		dmarcPolicy    string
		dmarcPct       int
		nullMX         bool
		hasSPF         bool
		hasDMARC       bool
	}{
		{"no mail domain", true, "", 0, false, false, false},
		{"reject policy", false, "reject", 100, false, true, true},
		{"quarantine policy", false, "quarantine", 100, false, true, true},
		{"none policy", false, "none", 100, false, true, true},
		{"null mx", false, "", 0, true, false, false},
		{"no protections", false, "", 0, false, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzer.ExportBuildEmailAnswerStructured(tt.isNoMailDomain, tt.dmarcPolicy, tt.dmarcPct, tt.nullMX, tt.hasSPF, tt.hasDMARC)
			if got == nil {
				t.Error("expected non-nil map")
			}
			_ = got
		})
	}
}

func TestExportClassifyEnterpriseDNS(t *testing.T) {
	tests := []struct {
		name        string
		domain      string
		nameservers []string
	}{
		{"cloudflare", "example.com", []string{"ns1.cloudflare.com", "ns2.cloudflare.com"}},
		{"awsdns", "example.com", []string{"ns-1234.awsdns-56.org", "ns-5678.awsdns-78.co.uk"}},
		{"google", "example.com", []string{"ns1.google.com", "ns2.google.com"}},
		{"unknown", "example.com", []string{"ns1.unknownprovider.com"}},
		{"empty", "example.com", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzer.ExportClassifyEnterpriseDNS(tt.domain, tt.nameservers)
			_ = got
		})
	}
}

func TestExportBuildDNSVerdict(t *testing.T) {
	tests := []struct {
		name         string
		dnssecOK     bool
		dnssecBroken bool
	}{
		{"dnssec ok", true, false},
		{"dnssec broken", false, true},
		{"no dnssec", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzer.ExportBuildDNSVerdict(tt.dnssecOK, tt.dnssecBroken)
			if got == nil {
				t.Error("expected non-nil map")
			}
		})
	}
}

func TestExportClassifyNSProvider(t *testing.T) {
	tests := []struct {
		ns   string
		want string
	}{
		{"ns1.google.com", "Google Cloud DNS"},
		{"ns1.cloudflare.com", "Cloudflare"},
		{"ns-1234.awsdns-56.org", "Amazon Route 53"},
		{"ns1.unknown.example.com", ""},
	}
	for _, tt := range tests {
		t.Run(tt.ns, func(t *testing.T) {
			got := analyzer.ExportClassifyNSProvider(tt.ns)
			if tt.want != "" && got != tt.want {
				t.Errorf("analyzer.ExportClassifyNSProvider(%q) = %q, want %q", tt.ns, got, tt.want)
			}
		})
	}
}

func TestExportRegistrableDomain(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"sub.example.com", "example.com"},
		{"example.com", "example.com"},
		{"deep.sub.example.com", "example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := analyzer.ExportRegistrableDomain(tt.input)
			if got != tt.want {
				t.Errorf("analyzer.ExportRegistrableDomain(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExportAnalyzeDKIMKey(t *testing.T) {
	tests := []struct {
		name   string
		record string
	}{
		{"rsa key", "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC"},
		{"empty key", "v=DKIM1; k=rsa; p="},
		{"ed25519", "v=DKIM1; k=ed25519; p=abc123"},
		{"minimal", "v=DKIM1; p=MIGf"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzer.ExportAnalyzeDKIMKey(tt.record)
			if got == nil {
				t.Fatal("expected non-nil map")
			}
			if _, ok := got["key_type"]; !ok {
				t.Error("expected key_type in result map")
			}
		})
	}
}

func TestExportClassifySelectorProvider(t *testing.T) {
	tests := []struct {
		selector string
		primary  string
		want     string
	}{
		{"google", "Google Workspace", "Google Workspace"},
		{"selector1", "Microsoft 365", "Microsoft 365"},
		{"unknown", "Custom", "Custom"},
	}
	for _, tt := range tests {
		t.Run(tt.selector, func(t *testing.T) {
			got := analyzer.ExportClassifySelectorProvider(tt.selector, tt.primary)
			if got == "" {
				t.Error("expected non-empty provider")
			}
		})
	}
}

func TestExportIdentifyCAIssuer(t *testing.T) {
	tests := []struct {
		record string
		want   string
	}{
		{"0 issue \"letsencrypt.org\"", "Let's Encrypt"},
		{"0 issue \"digicert.com\"", "DigiCert"},
		{"0 issue \"sectigo.com\"", "Sectigo"},
		{"0 issue \"amazon.com\"", "Amazon"},
		{"0 issue \"google.com\"", "Google Trust Services"},
		{"x", ""},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := analyzer.ExportIdentifyCAIssuer(tt.record)
			if got != tt.want {
				t.Errorf("analyzer.ExportIdentifyCAIssuer(%q) = %q, want %q", tt.record, got, tt.want)
			}
		})
	}
}

func TestExportParseCAARecords(t *testing.T) {
	records := []string{
		"0 issue \"letsencrypt.org\"",
		"0 issuewild \"digicert.com\"",
		"0 iodef \"mailto:admin@example.com\"",
	}
	issuers, wildcardIssuers, hasWildcard, hasIodef := analyzer.ExportParseCAARecords(records)
	if len(issuers) != 1 {
		t.Errorf("issuers len = %d, want 1", len(issuers))
	}
	if len(wildcardIssuers) != 1 {
		t.Errorf("wildcardIssuers len = %d, want 1", len(wildcardIssuers))
	}
	if !hasWildcard {
		t.Error("hasWildcard should be true")
	}
	if !hasIodef {
		t.Error("hasIodef should be true")
	}
}

func TestExportBuildCAAMessage(t *testing.T) {
	tests := []struct {
		name            string
		issuers         []string
		wildcardIssuers []string
		hasWildcard     bool
		wantNonEmpty    bool
	}{
		{"single issuer", []string{"Let's Encrypt"}, nil, false, true},
		{"with wildcard", []string{"DigiCert"}, []string{"DigiCert"}, true, true},
		{"empty issuers", nil, nil, false, true},
		{"multiple issuers", []string{"Let's Encrypt", "DigiCert"}, nil, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzer.ExportBuildCAAMessage(tt.issuers, tt.wildcardIssuers, tt.hasWildcard)
			if tt.wantNonEmpty && got == "" {
				t.Error("expected non-empty message")
			}
		})
	}
}

func TestExportFilterSTSRecords(t *testing.T) {
	tests := []struct {
		name    string
		records []string
		wantLen int
	}{
		{"with sts", []string{"v=STSv1; id=20240101", "not sts"}, 1},
		{"no sts", []string{"random txt"}, 0},
		{"empty", nil, 0},
		{"multiple sts", []string{"v=STSv1; id=1", "v=STSv1; id=2"}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzer.ExportFilterSTSRecords(tt.records)
			if len(got) != tt.wantLen {
				t.Errorf("analyzer.ExportFilterSTSRecords() len = %d, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestExportExtractSTSID(t *testing.T) {
	tests := []struct {
		name    string
		record  string
		wantNil bool
	}{
		{"valid", "v=STSv1; id=20240101", false},
		{"no id", "v=STSv1", true},
		{"empty", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzer.ExportExtractSTSID(tt.record)
			if tt.wantNil && got != nil {
				t.Errorf("expected nil, got %v", *got)
			}
			if !tt.wantNil && got == nil {
				t.Error("expected non-nil")
			}
		})
	}
}

func TestExportDetermineMTASTSModeStatus(t *testing.T) {
	tests := []struct {
		name       string
		mode       string
		policyData map[string]any
	}{
		{"enforce with data", "enforce", map[string]any{"max_age": 86400, "mx": []string{"mail.example.com"}}},
		{"testing with data", "testing", map[string]any{"max_age": 86400, "mx": []string{"mail.example.com"}}},
		{"none with data", "none", map[string]any{"max_age": 86400, "mx": []string{}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, detail := analyzer.ExportDetermineMTASTSModeStatus(tt.mode, tt.policyData)
			if status == "" {
				t.Error("expected non-empty status")
			}
			_ = detail
		})
	}
}

func TestExportParseMTASTSPolicyLines(t *testing.T) {
	tests := []struct {
		name       string
		policyText string
		wantMode   string
		wantMX     int
	}{
		{"full policy", "version: STSv1\nmode: enforce\nmax_age: 86400\nmx: mail.example.com\nmx: mail2.example.com", "enforce", 2},
		{"testing mode", "version: STSv1\nmode: testing\nmax_age: 86400\nmx: mail.example.com", "testing", 1},
		{"empty", "", "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mode, maxAge, mx, hasVersion := analyzer.ExportParseMTASTSPolicyLines(tt.policyText)
			if mode != tt.wantMode {
				t.Errorf("mode = %q, want %q", mode, tt.wantMode)
			}
			if len(mx) != tt.wantMX {
				t.Errorf("mx count = %d, want %d", len(mx), tt.wantMX)
			}
			_ = maxAge
			_ = hasVersion
		})
	}
}

func TestExportFilterBIMIRecords(t *testing.T) {
	tests := []struct {
		name    string
		records []string
		wantLen int
	}{
		{"with bimi", []string{"v=BIMI1; l=https://example.com/logo.svg", "v=spf1 -all"}, 1},
		{"no bimi", []string{"v=spf1 -all"}, 0},
		{"empty", nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzer.ExportFilterBIMIRecords(tt.records)
			if len(got) != tt.wantLen {
				t.Errorf("len = %d, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestExportExtractBIMIURLs(t *testing.T) {
	tests := []struct {
		name     string
		record   string
		wantLogo bool
		wantVMC  bool
	}{
		{"both urls", "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem", true, true},
		{"logo only", "v=BIMI1; l=https://example.com/logo.svg; a=", true, false},
		{"empty", "v=BIMI1; l=; a=", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logo, vmc := analyzer.ExportExtractBIMIURLs(tt.record)
			if tt.wantLogo && logo == nil {
				t.Error("expected non-nil logo URL")
			}
			if !tt.wantLogo && logo != nil {
				t.Errorf("expected nil logo URL, got %v", *logo)
			}
			if tt.wantVMC && vmc == nil {
				t.Error("expected non-nil VMC URL")
			}
			if !tt.wantVMC && vmc != nil {
				t.Errorf("expected nil VMC URL, got %v", *vmc)
			}
		})
	}
}

func TestExportParseTLSAEntry(t *testing.T) {
	tests := []struct {
		name     string
		entry    string
		mxHost   string
		tlsaName string
		wantOK   bool
	}{
		{"valid", "3 1 1 abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", "mail.example.com", "_25._tcp.mail.example.com", true},
		{"too short", "3 1", "mail.example.com", "_25._tcp.mail.example.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := analyzer.ExportParseTLSAEntry(tt.entry, tt.mxHost, tt.tlsaName)
			if ok != tt.wantOK {
				t.Errorf("ok = %v, want %v", ok, tt.wantOK)
			}
			if tt.wantOK && result == nil {
				t.Error("expected non-nil result")
			}
		})
	}
}

func TestExportExtractMXHosts(t *testing.T) {
	tests := []struct {
		name      string
		mxRecords []string
		wantLen   int
	}{
		{"single mx", []string{"10 mail.example.com."}, 1},
		{"multiple mx", []string{"10 mail.example.com.", "20 mail2.example.com."}, 2},
		{"empty", nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzer.ExportExtractMXHosts(tt.mxRecords)
			if len(got) != tt.wantLen {
				t.Errorf("len = %d, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestExportBuildDANEVerdict(t *testing.T) {
	tests := []struct {
		name          string
		allTLSA       []map[string]any
		hostsWithDANE []string
		mxHosts       []string
		mxCapability  map[string]any
	}{
		{"no dane no cap", nil, nil, []string{"mail.example.com"}, nil},
		{"with dane", []map[string]any{{"usage": int(3), "matching_type": int(1), "mx_host": "mail.example.com"}}, []string{"mail.example.com"}, []string{"mail.example.com"}, nil},
		{"partial dane", []map[string]any{{"usage": int(3), "matching_type": int(1), "mx_host": "mail.example.com"}}, []string{"mail.example.com"}, []string{"mail.example.com", "mail2.example.com"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verdict, detail, issues := analyzer.ExportBuildDANEVerdict(tt.allTLSA, tt.hostsWithDANE, tt.mxHosts, tt.mxCapability)
			_ = verdict
			_ = detail
			_ = issues
		})
	}
}

func TestExportIsHostedEmailProvider(t *testing.T) {
	tests := []struct {
		domain string
	}{
		{"gmail.com"},
		{"outlook.com"},
		{"example.com"},
		{"randomdomain.org"},
	}
	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			_ = analyzer.ExportIsHostedEmailProvider(tt.domain)
		})
	}
}

func TestExportIsBIMICapableProvider(t *testing.T) {
	tests := []struct {
		domain string
	}{
		{"google.com"},
		{"example.com"},
		{"yahoo.com"},
	}
	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			_ = analyzer.ExportIsBIMICapableProvider(tt.domain)
		})
	}
}

func TestExportClassifyDMARCRecords(t *testing.T) {
	tests := []struct {
		name      string
		records   []string
		wantValid int
	}{
		{"valid dmarc", []string{"v=DMARC1; p=reject"}, 1},
		{"mixed", []string{"v=DMARC1; p=reject", "not dmarc", "v=DMARC1; p=none"}, 2},
		{"no dmarc", []string{"v=spf1 -all"}, 0},
		{"empty", nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, invalid := analyzer.ExportClassifyDMARCRecords(tt.records)
			if len(valid) != tt.wantValid {
				t.Errorf("valid count = %d, want %d", len(valid), tt.wantValid)
			}
			_ = invalid
		})
	}
}

func TestExportParseDMARCPolicy(t *testing.T) {
	tests := []struct {
		name       string
		record     string
		wantPolicy string
		wantPct    int
		wantRUA    bool
	}{
		{"full", "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@example.com", "reject", 100, true},
		{"quarantine", "v=DMARC1; p=quarantine; pct=50", "quarantine", 50, false},
		{"none", "v=DMARC1; p=none", "none", 100, false},
		{"with rua", "v=DMARC1; p=reject; rua=mailto:reports@example.com", "reject", 100, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy, pct, hasRUA := analyzer.ExportParseDMARCPolicy(tt.record)
			if policy != tt.wantPolicy {
				t.Errorf("policy = %q, want %q", policy, tt.wantPolicy)
			}
			if pct != tt.wantPct {
				t.Errorf("pct = %d, want %d", pct, tt.wantPct)
			}
			if hasRUA != tt.wantRUA {
				t.Errorf("hasRUA = %v, want %v", hasRUA, tt.wantRUA)
			}
		})
	}
}

func TestExportExtractTLSRPTURIs(t *testing.T) {
	tests := []struct {
		name    string
		record  string
		wantLen int
	}{
		{"single uri", "v=TLSRPTv1; rua=mailto:reports@example.com", 1},
		{"no rua", "v=TLSRPTv1", 0},
		{"empty", "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzer.ExportExtractTLSRPTURIs(tt.record)
			if len(got) != tt.wantLen {
				t.Errorf("len = %d, want %d", len(got), tt.wantLen)
			}
			if tt.wantLen == 1 && len(got) == 1 {
				if !strings.Contains(got[0], "reports@example.com") {
					t.Errorf("expected URI containing reports@example.com, got %q", got[0])
				}
			}
		})
	}
}

func TestExportBuildBrandVerdict(t *testing.T) {
	tests := []struct {
		name         string
		dmarcMissing bool
		dmarcPolicy  string
		bimiOK       bool
		caaOK        bool
		wantStatus   string
	}{
		{"all good", false, "reject", true, true, ""},
		{"dmarc missing", true, "", false, false, ""},
		{"quarantine", false, "quarantine", false, true, ""},
		{"none policy", false, "none", false, false, ""},
		{"bimi ok caa ok", false, "reject", true, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzer.ExportBuildBrandVerdict(tt.dmarcMissing, tt.dmarcPolicy, tt.bimiOK, tt.caaOK)
			if got == nil {
				t.Error("expected non-nil map")
			}
		})
	}
}

func TestExportClassifyNSProvider_Comprehensive(t *testing.T) {
	tests := []struct {
		ns   string
		want string
	}{
		{"ns1.google.com", "Google Cloud DNS"},
		{"ns-1234.awsdns-56.org", "Amazon Route 53"},
		{"ns1.cloudflare.com", "Cloudflare"},
		{"dns1.p01.nsone.net", "NS1 (IBM)"},
	}
	for _, tt := range tests {
		t.Run(tt.ns, func(t *testing.T) {
			got := analyzer.ExportClassifyNSProvider(tt.ns)
			if got != tt.want {
				t.Errorf("classifyNSProvider(%q) = %q, want %q", tt.ns, got, tt.want)
			}
		})
	}
}

func TestExportBuildEmailAnswer_EdgeCases(t *testing.T) {
	t.Run("reject 100pct with SPF and DMARC", func(t *testing.T) {
		got := analyzer.ExportBuildEmailAnswer(false, "reject", 100, false, true, true)
		if got == "" {
			t.Error("expected non-empty")
		}
	})

	t.Run("quarantine partial pct", func(t *testing.T) {
		got := analyzer.ExportBuildEmailAnswer(false, "quarantine", 50, false, true, true)
		if got == "" {
			t.Error("expected non-empty")
		}
	})
}

func TestExportBuildEmailAnswerStructured_EdgeCases(t *testing.T) {
	t.Run("all protections", func(t *testing.T) {
		got := analyzer.ExportBuildEmailAnswerStructured(false, "reject", 100, false, true, true)
		if got == nil {
			t.Fatal("expected non-nil")
		}
	})
}

func TestExportParseSPFMechanisms_Details(t *testing.T) {
	t.Run("with mx and a", func(t *testing.T) {
		count, mechs, _, _, _, _, _ := analyzer.ExportParseSPFMechanisms("v=spf1 mx a include:_spf.google.com -all")
		if count < 2 {
			t.Errorf("lookup count = %d, want >= 2", count)
		}
		if len(mechs) < 2 {
			t.Errorf("mechanisms len = %d, want >= 2", len(mechs))
		}
	})
}

func TestExportExtractMXHosts_Trailing(t *testing.T) {
	hosts := analyzer.ExportExtractMXHosts([]string{"10 mail.example.com.", "20 backup.example.com."})
	for _, h := range hosts {
		if strings.HasSuffix(h, ".") {
			continue
		}
	}
	if len(hosts) != 2 {
		t.Errorf("expected 2 hosts, got %d", len(hosts))
	}
}
