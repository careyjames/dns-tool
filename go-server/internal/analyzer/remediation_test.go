package analyzer

import (
	"strings"
	"testing"
)

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		name    string
		results map[string]any
		want    string
	}{
		{"with domain", map[string]any{"domain": "example.com"}, "example.com"},
		{"empty map", map[string]any{}, "yourdomain.com"},
		{"nil map", nil, "yourdomain.com"},
		{"non-string domain", map[string]any{"domain": 123}, "yourdomain.com"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractDomain(tc.results)
			if got != tc.want {
				t.Errorf("extractDomain() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDkimSelectorForProvider(t *testing.T) {
	tests := []struct {
		provider string
		want     string
	}{
		{"Google Workspace", "google"},
		{"google", "google"},
		{"Microsoft 365", "selector1"},
		{"Office 365", "selector1"},
		{"Zoho", "selector1"},
		{"", "selector1"},
	}
	for _, tc := range tests {
		t.Run(tc.provider, func(t *testing.T) {
			got := dkimSelectorForProvider(tc.provider)
			if got != tc.want {
				t.Errorf("dkimSelectorForProvider(%q) = %q, want %q", tc.provider, got, tc.want)
			}
		})
	}
}

func TestDkimRecordExample(t *testing.T) {
	got := dkimRecordExample("example.com", "Google Workspace")
	if !strings.Contains(got, "google._domainkey.example.com") {
		t.Errorf("dkimRecordExample should contain google selector, got %q", got)
	}

	got = dkimRecordExample("test.org", "Microsoft 365")
	if !strings.Contains(got, "selector1._domainkey.test.org") {
		t.Errorf("dkimRecordExample should contain selector1, got %q", got)
	}
}

func TestFixToMap(t *testing.T) {
	f := fix{
		Title:         "Test Fix",
		Description:   "Test Description",
		DNSHost:       "example.com",
		DNSType:       "TXT",
		DNSValue:      "v=spf1 -all",
		DNSPurpose:    "Test purpose",
		DNSHostHelp:   "(root)",
		DNSRecord:     "example.com TXT v=spf1 -all",
		RFC:           "RFC 7208",
		RFCURL:        "https://example.com",
		SeverityLevel: sevCritical,
		Section:       "SPF",
	}

	m := fixToMap(f)

	if m["title"] != "Test Fix" {
		t.Errorf("title = %v", m["title"])
	}
	if m["fix"] != "Test Description" {
		t.Errorf("fix = %v", m["fix"])
	}
	if m["severity_label"] != severityCritical {
		t.Errorf("severity_label = %v", m["severity_label"])
	}
	if m["severity_color"] != colorCritical {
		t.Errorf("severity_color = %v", m["severity_color"])
	}
	if m["dns_host"] != "example.com" {
		t.Errorf("dns_host = %v", m["dns_host"])
	}
	if m["dns_record"] != "example.com TXT v=spf1 -all" {
		t.Errorf("dns_record = %v", m["dns_record"])
	}
	if m["section"] != "SPF" {
		t.Errorf("section = %v", m["section"])
	}
}

func TestFixToMap_NoDNS(t *testing.T) {
	f := fix{
		Title:         "Simple Fix",
		Description:   "No DNS",
		SeverityLevel: sevLow,
		Section:       "DKIM",
	}

	m := fixToMap(f)
	if _, ok := m["dns_host"]; ok {
		t.Error("dns_host should not be present when DNSHost is empty")
	}
	if _, ok := m["dns_record"]; ok {
		t.Error("dns_record should not be present when DNSRecord is empty")
	}
}

func TestSortFixes(t *testing.T) {
	fixes := []fix{
		{Title: "B", SeverityLevel: sevMedium},
		{Title: "A", SeverityLevel: sevCritical},
		{Title: "C", SeverityLevel: sevLow},
		{Title: "D", SeverityLevel: sevHigh},
		{Title: "A", SeverityLevel: sevMedium},
	}
	sortFixes(fixes)

	if fixes[0].SeverityLevel.Name != severityCritical {
		t.Errorf("first fix should be Critical, got %s", fixes[0].SeverityLevel.Name)
	}
	if fixes[1].SeverityLevel.Name != severityHigh {
		t.Errorf("second fix should be High, got %s", fixes[1].SeverityLevel.Name)
	}
	if fixes[2].Title != "A" || fixes[3].Title != "B" {
		t.Error("same-severity fixes should be sorted by title")
	}
	if fixes[4].SeverityLevel.Name != severityLow {
		t.Errorf("last fix should be Low, got %s", fixes[4].SeverityLevel.Name)
	}
}

func TestBuildSPFValue(t *testing.T) {
	tests := []struct {
		name      string
		includes  []string
		qualifier string
		want      string
	}{
		{"no includes", nil, "~all", "v=spf1 ~all"},
		{"one include", []string{"_spf.google.com"}, "-all", "v=spf1 include:_spf.google.com -all"},
		{"two includes", []string{"a.com", "b.com"}, "~all", "v=spf1 include:a.com include:b.com ~all"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildSPFValue(tc.includes, tc.qualifier)
			if got != tc.want {
				t.Errorf("buildSPFValue() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBuildSPFRecordExample(t *testing.T) {
	got := buildSPFRecordExample("example.com", []string{"_spf.google.com"}, "~all")
	want := "example.com TXT \"v=spf1 include:_spf.google.com ~all\""
	if got != want {
		t.Errorf("buildSPFRecordExample() = %q, want %q", got, want)
	}
}

func TestExtractSPFIncludes(t *testing.T) {
	tests := []struct {
		name    string
		results map[string]any
		want    int
	}{
		{"nil results", nil, 0},
		{"no spf_analysis", map[string]any{}, 0},
		{"string includes", map[string]any{"spf_analysis": map[string]any{"includes": []string{"a.com", "b.com"}}}, 2},
		{"any includes", map[string]any{"spf_analysis": map[string]any{"includes": []any{"a.com", "b.com"}}}, 2},
		{"no includes key", map[string]any{"spf_analysis": map[string]any{}}, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractSPFIncludes(tc.results)
			if len(got) != tc.want {
				t.Errorf("extractSPFIncludes() returned %d includes, want %d", len(got), tc.want)
			}
		})
	}
}

func TestAppendSPFFixes_Missing(t *testing.T) {
	ps := protocolState{spfMissing: true}
	fixes := appendSPFFixes(nil, ps, DKIMAbsent, nil, "example.com")
	if len(fixes) != 1 {
		t.Fatalf("expected 1 fix, got %d", len(fixes))
	}
	if fixes[0].Title != "Publish SPF Record" {
		t.Errorf("title = %q", fixes[0].Title)
	}
	if fixes[0].SeverityLevel.Name != severityCritical {
		t.Errorf("severity = %s", fixes[0].SeverityLevel.Name)
	}
}

func TestAppendSPFFixes_Dangerous(t *testing.T) {
	ps := protocolState{spfDangerous: true, spfOK: true}
	fixes := appendSPFFixes(nil, ps, DKIMAbsent, nil, "example.com")
	found := false
	for _, f := range fixes {
		if f.Title == "Remove Dangerous SPF +all" {
			found = true
			if f.SeverityLevel.Name != severityCritical {
				t.Errorf("severity = %s, want Critical", f.SeverityLevel.Name)
			}
		}
	}
	if !found {
		t.Error("expected 'Remove Dangerous SPF +all' fix")
	}
}

func TestAppendSPFFixes_Neutral(t *testing.T) {
	ps := protocolState{spfNeutral: true, spfOK: true}
	fixes := appendSPFFixes(nil, ps, DKIMAbsent, nil, "example.com")
	found := false
	for _, f := range fixes {
		if f.Title == "Upgrade SPF from ?all" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'Upgrade SPF from ?all' fix")
	}
}

func TestAppendSPFLookupFix(t *testing.T) {
	ps := protocolState{spfLookupExceeded: true, spfLookupCount: 12}
	fixes := appendSPFLookupFix(nil, ps)
	if len(fixes) != 1 {
		t.Fatalf("expected 1 fix, got %d", len(fixes))
	}
	if !strings.Contains(fixes[0].Description, "12") {
		t.Error("description should mention lookup count")
	}
}

func TestAppendSPFLookupFix_NotExceeded(t *testing.T) {
	ps := protocolState{spfLookupExceeded: false}
	fixes := appendSPFLookupFix(nil, ps)
	if len(fixes) != 0 {
		t.Errorf("expected 0 fixes, got %d", len(fixes))
	}
}

func TestAppendDMARCFixes_Missing(t *testing.T) {
	ps := protocolState{dmarcMissing: true}
	fixes := appendDMARCFixes(nil, ps, nil, "example.com")
	if len(fixes) != 1 {
		t.Fatalf("expected 1 fix, got %d", len(fixes))
	}
	if fixes[0].Title != "Publish DMARC Record" {
		t.Errorf("title = %q", fixes[0].Title)
	}
	if !strings.Contains(fixes[0].DNSHost, "_dmarc.example.com") {
		t.Errorf("DNSHost = %q", fixes[0].DNSHost)
	}
}

func TestAppendDMARCFixes_PolicyNone(t *testing.T) {
	ps := protocolState{dmarcPolicy: "none", dmarcOK: true, dmarcHasRua: true}
	fixes := appendDMARCFixes(nil, ps, nil, "example.com")
	found := false
	for _, f := range fixes {
		if f.Title == "Upgrade DMARC from p=none" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'Upgrade DMARC from p=none' fix")
	}
}

func TestAppendDMARCFixes_QuarantineFullPct(t *testing.T) {
	ps := protocolState{dmarcPolicy: "quarantine", dmarcPct: 100, dmarcOK: true, dmarcHasRua: true}
	fixes := appendDMARCFixes(nil, ps, nil, "example.com")
	found := false
	for _, f := range fixes {
		if f.Title == "Upgrade DMARC to Reject" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'Upgrade DMARC to Reject' fix")
	}
}

func TestAppendDMARCFixes_QuarantinePartialPct(t *testing.T) {
	ps := protocolState{dmarcPolicy: "quarantine", dmarcPct: 50, dmarcOK: true, dmarcHasRua: true}
	fixes := appendDMARCFixes(nil, ps, nil, "example.com")
	found := false
	for _, f := range fixes {
		if f.Title == "Increase DMARC Coverage" {
			found = true
			if !strings.Contains(f.Description, "50%") {
				t.Error("description should mention percentage")
			}
		}
	}
	if !found {
		t.Error("expected 'Increase DMARC Coverage' fix")
	}
}

func TestAppendDMARCFixes_NoRua(t *testing.T) {
	ps := protocolState{dmarcPolicy: "reject", dmarcOK: true, dmarcHasRua: false}
	fixes := appendDMARCFixes(nil, ps, nil, "example.com")
	found := false
	for _, f := range fixes {
		if f.Title == "Add DMARC Aggregate Reporting" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'Add DMARC Aggregate Reporting' fix")
	}
}

func TestAppendDKIMFixes_WeakKeys(t *testing.T) {
	ps := protocolState{}
	fixes := appendDKIMFixes(nil, ps, DKIMWeakKeysOnly, nil, "example.com")
	if len(fixes) != 1 {
		t.Fatalf("expected 1 fix, got %d", len(fixes))
	}
	if fixes[0].Title != "Upgrade DKIM Key Strength" {
		t.Errorf("title = %q", fixes[0].Title)
	}
}

func TestAppendDKIMFixes_Absent(t *testing.T) {
	ps := protocolState{}
	fixes := appendDKIMFixes(nil, ps, DKIMAbsent, nil, "example.com")
	if len(fixes) != 1 {
		t.Fatalf("expected 1 fix, got %d", len(fixes))
	}
	if fixes[0].Title != "Configure DKIM Signing" {
		t.Errorf("title = %q", fixes[0].Title)
	}
}

func TestAppendDKIMFixes_ThirdPartyOnly(t *testing.T) {
	ps := protocolState{}
	fixes := appendDKIMFixes(nil, ps, DKIMThirdPartyOnly, nil, "example.com")
	if len(fixes) != 1 {
		t.Fatalf("expected 1 fix, got %d", len(fixes))
	}
	if fixes[0].Title != "Add Primary Domain DKIM" {
		t.Errorf("title = %q", fixes[0].Title)
	}
}

func TestAppendDKIMFixes_Success(t *testing.T) {
	ps := protocolState{}
	fixes := appendDKIMFixes(nil, ps, DKIMSuccess, nil, "example.com")
	if len(fixes) != 0 {
		t.Errorf("expected 0 fixes for DKIMSuccess, got %d", len(fixes))
	}
}

func TestAppendCAAFixes(t *testing.T) {
	fixes := appendCAAFixes(nil, protocolState{caaOK: false}, "example.com")
	if len(fixes) != 1 {
		t.Fatalf("expected 1 fix, got %d", len(fixes))
	}
	if fixes[0].Title != "Add CAA Records" {
		t.Errorf("title = %q", fixes[0].Title)
	}

	fixes = appendCAAFixes(nil, protocolState{caaOK: true}, "example.com")
	if len(fixes) != 0 {
		t.Error("expected 0 fixes when CAA is OK")
	}
}

func TestAppendMTASTSFixes(t *testing.T) {
	fixes := appendMTASTSFixes(nil, protocolState{mtaStsOK: false}, "example.com")
	if len(fixes) != 1 {
		t.Fatalf("expected 1 fix, got %d", len(fixes))
	}
	if fixes[0].Title != "Deploy MTA-STS" {
		t.Errorf("title = %q", fixes[0].Title)
	}

	fixes = appendMTASTSFixes(nil, protocolState{mtaStsOK: true}, "example.com")
	if len(fixes) != 0 {
		t.Error("expected 0 fixes when MTA-STS is OK")
	}

	fixes = appendMTASTSFixes(nil, protocolState{isNoMailDomain: true}, "example.com")
	if len(fixes) != 0 {
		t.Error("expected 0 fixes for no-mail domain")
	}
}

func TestAppendTLSRPTFixes(t *testing.T) {
	fixes := appendTLSRPTFixes(nil, protocolState{tlsrptOK: false}, "example.com")
	if len(fixes) != 1 {
		t.Fatalf("expected 1 fix, got %d", len(fixes))
	}
	if fixes[0].Title != "Add TLS-RPT Reporting" {
		t.Errorf("title = %q", fixes[0].Title)
	}

	fixes = appendTLSRPTFixes(nil, protocolState{tlsrptOK: false, daneOK: true}, "example.com")
	if len(fixes) != 1 {
		t.Fatalf("expected 1 fix, got %d", len(fixes))
	}
	if !strings.Contains(fixes[0].Description, "DANE") {
		t.Error("description should mention DANE when daneOK")
	}

	fixes = appendTLSRPTFixes(nil, protocolState{tlsrptOK: false, mtaStsOK: true}, "example.com")
	if !strings.Contains(fixes[0].Description, "MTA-STS") {
		t.Error("description should mention MTA-STS when mtaStsOK")
	}

	fixes = appendTLSRPTFixes(nil, protocolState{tlsrptOK: true}, "example.com")
	if len(fixes) != 0 {
		t.Error("expected 0 fixes when TLS-RPT is OK")
	}
}

func TestAppendDNSSECFixes_Broken(t *testing.T) {
	ps := protocolState{dnssecBroken: true}
	fixes := appendDNSSECFixes(nil, ps)
	found := false
	for _, f := range fixes {
		if f.Title == "Fix Broken DNSSEC" {
			found = true
			if f.SeverityLevel.Name != severityCritical {
				t.Errorf("severity = %s, want Critical", f.SeverityLevel.Name)
			}
		}
	}
	if !found {
		t.Error("expected 'Fix Broken DNSSEC' fix")
	}
}

func TestAppendDNSSECFixes_NotEnabled(t *testing.T) {
	ps := protocolState{dnssecOK: false, dnssecBroken: false}
	fixes := appendDNSSECFixes(nil, ps)
	found := false
	for _, f := range fixes {
		if f.Title == "Enable DNSSEC" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'Enable DNSSEC' fix")
	}
}

func TestAppendDNSSECFixes_DeprecatedAlgo(t *testing.T) {
	ps := protocolState{dnssecOK: true, dnssecAlgoStrength: "deprecated"}
	fixes := appendDNSSECFixes(nil, ps)
	found := false
	for _, f := range fixes {
		if f.Title == "Migrate From Deprecated DNSSEC Algorithm" {
			found = true
			if f.SeverityLevel.Name != severityHigh {
				t.Errorf("severity = %s, want High", f.SeverityLevel.Name)
			}
		}
	}
	if !found {
		t.Error("expected deprecated algorithm fix")
	}
}

func TestAppendDNSSECFixes_LegacyAlgo(t *testing.T) {
	ps := protocolState{dnssecOK: true, dnssecAlgoStrength: "legacy"}
	fixes := appendDNSSECFixes(nil, ps)
	found := false
	for _, f := range fixes {
		if f.Title == "Upgrade From Legacy DNSSEC Algorithm" {
			found = true
		}
	}
	if !found {
		t.Error("expected legacy algorithm fix")
	}
}

func TestAppendDNSSECFixes_OK(t *testing.T) {
	ps := protocolState{dnssecOK: true, dnssecAlgoStrength: "strong"}
	fixes := appendDNSSECFixes(nil, ps)
	if len(fixes) != 0 {
		t.Errorf("expected 0 fixes when DNSSEC is OK with strong algo, got %d", len(fixes))
	}
}

func TestAppendDANEFixes_DANEWithoutDNSSEC(t *testing.T) {
	ps := protocolState{daneOK: true, dnssecOK: false}
	fixes := appendDANEFixes(nil, ps, nil, "example.com")
	if len(fixes) != 1 {
		t.Fatalf("expected 1 fix, got %d", len(fixes))
	}
	if fixes[0].Title != "DANE Requires DNSSEC" {
		t.Errorf("title = %q", fixes[0].Title)
	}
}

func TestAppendDANEFixes_Deployable(t *testing.T) {
	ps := protocolState{daneOK: false, dnssecOK: true}
	results := map[string]any{
		"mx_records": []any{map[string]any{"host": "mail.example.com."}},
	}
	fixes := appendDANEFixes(nil, ps, results, "example.com")
	found := false
	for _, f := range fixes {
		if f.Title == "Add DANE/TLSA Records" {
			found = true
			if !strings.Contains(f.DNSHost, "mail.example.com") {
				t.Errorf("DNSHost = %q, expected to contain mail.example.com", f.DNSHost)
			}
		}
	}
	if !found {
		t.Error("expected 'Add DANE/TLSA Records' fix")
	}
}

func TestAppendBIMIFixes(t *testing.T) {
	fixes := appendBIMIFixes(nil, protocolState{bimiOK: false, dmarcPolicy: "reject"}, "example.com")
	if len(fixes) != 1 {
		t.Fatalf("expected 1 fix, got %d", len(fixes))
	}
	if fixes[0].Title != "Add BIMI Record" {
		t.Errorf("title = %q", fixes[0].Title)
	}

	fixes = appendBIMIFixes(nil, protocolState{bimiOK: true, dmarcPolicy: "reject"}, "example.com")
	if len(fixes) != 0 {
		t.Error("expected 0 fixes when BIMI is OK")
	}

	fixes = appendBIMIFixes(nil, protocolState{bimiOK: false, dmarcPolicy: "none"}, "example.com")
	if len(fixes) != 0 {
		t.Error("expected 0 fixes when DMARC is not reject")
	}
}

func TestAppendNoMailHardeningFixes(t *testing.T) {
	ps := protocolState{spfHardFail: false, dmarcMissing: true}
	fixes := appendNoMailHardeningFixes(nil, ps, "example.com")
	if len(fixes) != 2 {
		t.Fatalf("expected 2 fixes, got %d", len(fixes))
	}

	ps = protocolState{spfHardFail: true, dmarcPolicy: "reject"}
	fixes = appendNoMailHardeningFixes(nil, ps, "example.com")
	if len(fixes) != 0 {
		t.Errorf("expected 0 fixes when fully hardened, got %d", len(fixes))
	}
}

func TestAppendProbableNoMailFixes(t *testing.T) {
	ps := protocolState{spfHardFail: false, dmarcMissing: true}
	fixes := appendProbableNoMailFixes(nil, ps, "example.com")
	if len(fixes) != 2 {
		t.Fatalf("expected 2 fixes, got %d", len(fixes))
	}

	ps = protocolState{spfHardFail: true, dmarcPolicy: "reject"}
	fixes = appendProbableNoMailFixes(nil, ps, "example.com")
	if len(fixes) != 0 {
		t.Errorf("expected 0 fixes when fully hardened, got %d", len(fixes))
	}
}

func TestExtractFirstMXHost(t *testing.T) {
	tests := []struct {
		name    string
		results map[string]any
		want    string
	}{
		{"with host", map[string]any{"mx_records": []any{map[string]any{"host": "mail.example.com."}}}, "mail.example.com"},
		{"with exchange", map[string]any{"mx_records": []any{map[string]any{"exchange": "mx.example.com."}}}, "mx.example.com"},
		{"from analysis", map[string]any{"mx_analysis": map[string]any{"mx_hosts": []any{"alt.example.com."}}}, "alt.example.com"},
		{"empty", map[string]any{}, "mail.yourdomain.com"},
		{"nil", nil, "mail.yourdomain.com"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractFirstMXHost(tc.results)
			if got != tc.want {
				t.Errorf("extractFirstMXHost() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBuildPerSection(t *testing.T) {
	fixes := []fix{
		{Title: "Fix1", Section: "SPF", SeverityLevel: sevHigh},
		{Title: "Fix2", Section: "SPF", SeverityLevel: sevMedium},
		{Title: "Fix3", Section: "DMARC", SeverityLevel: sevCritical},
		{Title: "Fix4", Section: "", SeverityLevel: sevLow},
	}
	sections := buildPerSection(fixes)
	spfFixes, ok := sections["SPF"].([]map[string]any)
	if !ok {
		t.Fatal("expected SPF section")
	}
	if len(spfFixes) != 2 {
		t.Errorf("SPF section should have 2 fixes, got %d", len(spfFixes))
	}
	dmarcFixes, ok := sections["DMARC"].([]map[string]any)
	if !ok {
		t.Fatal("expected DMARC section")
	}
	if len(dmarcFixes) != 1 {
		t.Errorf("DMARC section should have 1 fix, got %d", len(dmarcFixes))
	}
	if _, ok := sections[""]; ok {
		t.Error("empty section should not be in result")
	}
}

func TestComputeAchievablePosture(t *testing.T) {
	tests := []struct {
		name  string
		ps    protocolState
		fixes []fix
		want  string
	}{
		{"no fixes", protocolState{}, nil, "Secure"},
		{"low severity only", protocolState{}, []fix{{SeverityLevel: sevLow}, {SeverityLevel: sevMedium}}, "Secure"},
		{"one critical few fixes", protocolState{}, []fix{{SeverityLevel: sevCritical}}, "Low Risk"},
		{"many fixes with critical", protocolState{}, []fix{
			{SeverityLevel: sevCritical},
			{SeverityLevel: sevHigh},
			{SeverityLevel: sevMedium},
			{SeverityLevel: sevLow},
		}, "Moderate Risk"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := computeAchievablePosture(tc.ps, tc.fixes)
			if got != tc.want {
				t.Errorf("computeAchievablePosture() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCountCoreIssues(t *testing.T) {
	fixes := []fix{
		{SeverityLevel: sevCritical},
		{SeverityLevel: sevHigh},
		{SeverityLevel: sevMedium},
		{SeverityLevel: sevLow},
	}
	got := countCoreIssues(fixes)
	if got != 2 {
		t.Errorf("countCoreIssues() = %d, want 2", got)
	}
}

func TestHasSeverity(t *testing.T) {
	fixes := []fix{
		{SeverityLevel: sevHigh},
		{SeverityLevel: sevMedium},
	}
	if !hasSeverity(fixes, severityHigh) {
		t.Error("should find High severity")
	}
	if hasSeverity(fixes, severityCritical) {
		t.Error("should not find Critical severity")
	}
}

func TestFilterBySeverity(t *testing.T) {
	fixes := []fix{
		{Title: "A", SeverityLevel: sevHigh},
		{Title: "B", SeverityLevel: sevMedium},
		{Title: "C", SeverityLevel: sevHigh},
	}
	result := filterBySeverity(fixes, severityHigh)
	if len(result) != 2 {
		t.Errorf("filterBySeverity() returned %d, want 2", len(result))
	}
}

func TestJoinFixTitles(t *testing.T) {
	fixes := []fix{
		{Title: "Fix A"},
		{Title: "Fix B"},
		{Title: "Fix C"},
	}
	got := joinFixTitles(fixes)
	if got != "Fix A, Fix B, Fix C" {
		t.Errorf("joinFixTitles() = %q", got)
	}
}

func TestIsDANEDeployable(t *testing.T) {
	if isDANEDeployable(nil) {
		t.Error("nil should not be deployable")
	}
	if isDANEDeployable(map[string]any{}) {
		t.Error("empty should not be deployable")
	}
	if !isDANEDeployable(map[string]any{"dnssec_analysis": map[string]any{"status": "secure"}}) {
		t.Error("secure DNSSEC should be deployable")
	}
	if isDANEDeployable(map[string]any{"dnssec_analysis": map[string]any{"status": "insecure"}}) {
		t.Error("insecure DNSSEC should not be deployable")
	}
}

func TestProviderSupportsDANE(t *testing.T) {
	if !providerSupportsDANE("") {
		t.Error("empty provider should support DANE")
	}
}

func TestProviderSupportsBIMI(t *testing.T) {
	if !providerSupportsBIMI("") {
		t.Error("empty provider should support BIMI")
	}
}

func TestAppendSPFFixes_WithIncludes(t *testing.T) {
	ps := protocolState{spfMissing: true}
	results := map[string]any{
		"spf_analysis": map[string]any{
			"includes": []string{"_spf.google.com"},
		},
	}
	fixes := appendSPFFixes(nil, ps, DKIMAbsent, results, "example.com")
	if len(fixes) != 1 {
		t.Fatalf("expected 1 fix, got %d", len(fixes))
	}
	if !strings.Contains(fixes[0].DNSValue, "_spf.google.com") {
		t.Errorf("DNSValue should contain include, got %q", fixes[0].DNSValue)
	}
}

func TestAppendSPFFixes_LookupExceeded(t *testing.T) {
	ps := protocolState{spfOK: true, spfLookupExceeded: true, spfLookupCount: 15}
	fixes := appendSPFFixes(nil, ps, DKIMAbsent, nil, "example.com")
	found := false
	for _, f := range fixes {
		if f.Title == "Reduce SPF Lookup Count" {
			found = true
			if !strings.Contains(f.Description, "15") {
				t.Error("description should mention lookup count")
			}
		}
	}
	if !found {
		t.Error("expected 'Reduce SPF Lookup Count' fix")
	}
}

func TestAppendDKIMFixes_Inconclusive(t *testing.T) {
	ps := protocolState{}
	fixes := appendDKIMFixes(nil, ps, DKIMInconclusive, nil, "example.com")
	if len(fixes) != 1 {
		t.Fatalf("expected 1 fix for inconclusive, got %d", len(fixes))
	}
	if fixes[0].Title != "Configure DKIM Signing" {
		t.Errorf("title = %q", fixes[0].Title)
	}
}

func TestAppendDKIMFixes_ProviderInferred(t *testing.T) {
	ps := protocolState{}
	fixes := appendDKIMFixes(nil, ps, DKIMProviderInferred, nil, "example.com")
	if len(fixes) != 0 {
		t.Errorf("expected 0 fixes for DKIMProviderInferred, got %d", len(fixes))
	}
}

func TestAppendDKIMFixes_NoMailDomain(t *testing.T) {
	ps := protocolState{}
	fixes := appendDKIMFixes(nil, ps, DKIMNoMailDomain, nil, "example.com")
	if len(fixes) != 0 {
		t.Errorf("expected 0 fixes for DKIMNoMailDomain, got %d", len(fixes))
	}
}

func TestAppendDANEFixes_NoMailDomain(t *testing.T) {
	ps := protocolState{daneOK: false, dnssecOK: true, isNoMailDomain: true}
	fixes := appendDANEFixes(nil, ps, nil, "example.com")
	if len(fixes) != 0 {
		t.Errorf("expected 0 fixes for no-mail domain, got %d", len(fixes))
	}
}

func TestAppendDANEFixes_NeitherPresent(t *testing.T) {
	ps := protocolState{daneOK: false, dnssecOK: false}
	fixes := appendDANEFixes(nil, ps, nil, "example.com")
	if len(fixes) != 0 {
		t.Errorf("expected 0 fixes when neither DANE nor DNSSEC, got %d", len(fixes))
	}
}

func TestAppendMTASTSFixes_NoMailDomain(t *testing.T) {
	ps := protocolState{mtaStsOK: false, isNoMailDomain: true}
	fixes := appendMTASTSFixes(nil, ps, "example.com")
	if len(fixes) != 0 {
		t.Errorf("expected 0 fixes for no-mail domain, got %d", len(fixes))
	}
}

func TestAppendTLSRPTFixes_NoMailDomain(t *testing.T) {
	ps := protocolState{tlsrptOK: false, isNoMailDomain: true}
	fixes := appendTLSRPTFixes(nil, ps, "example.com")
	if len(fixes) != 0 {
		t.Errorf("expected 0 fixes for no-mail domain, got %d", len(fixes))
	}
}

func TestAppendBIMIFixes_NotReject(t *testing.T) {
	fixes := appendBIMIFixes(nil, protocolState{bimiOK: false, dmarcPolicy: "quarantine"}, "example.com")
	if len(fixes) != 0 {
		t.Error("expected 0 fixes when DMARC is not reject")
	}
}

func TestExtractMXHostFromRecords_EmptyList(t *testing.T) {
	got := extractMXHostFromRecords(map[string]any{"mx_records": []any{}})
	if got != "" {
		t.Errorf("empty list should return empty, got %q", got)
	}
}

func TestExtractMXHostFromRecords_NonMapEntry(t *testing.T) {
	got := extractMXHostFromRecords(map[string]any{"mx_records": []any{"not a map"}})
	if got != "" {
		t.Errorf("non-map entry should return empty, got %q", got)
	}
}

func TestExtractMXHostFromRecords_EmptyHost(t *testing.T) {
	got := extractMXHostFromRecords(map[string]any{"mx_records": []any{map[string]any{"host": ""}}})
	if got != "" {
		t.Errorf("empty host should return empty, got %q", got)
	}
}

func TestExtractMXHostFromAnalysis_EmptyHosts(t *testing.T) {
	got := extractMXHostFromAnalysis(map[string]any{"mx_analysis": map[string]any{"mx_hosts": []any{}}})
	if got != "" {
		t.Errorf("empty hosts should return empty, got %q", got)
	}
}

func TestExtractMXHostFromAnalysis_NonStringHost(t *testing.T) {
	got := extractMXHostFromAnalysis(map[string]any{"mx_analysis": map[string]any{"mx_hosts": []any{123}}})
	if got != "" {
		t.Errorf("non-string host should return empty, got %q", got)
	}
}

func TestExtractMXHostFromAnalysis_Nil(t *testing.T) {
	got := extractMXHostFromAnalysis(nil)
	if got != "" {
		t.Errorf("nil should return empty, got %q", got)
	}
}

func TestWeakKeysFix(t *testing.T) {
	f := weakKeysFix("example.com")
	if f.Title != "Upgrade DKIM Key Strength" {
		t.Errorf("title = %q", f.Title)
	}
	if f.SeverityLevel.Name != severityMedium {
		t.Errorf("severity = %s", f.SeverityLevel.Name)
	}
	if f.Section != sectionDKIM {
		t.Errorf("section = %q", f.Section)
	}
}

func TestCountCoreIssues_Empty(t *testing.T) {
	got := countCoreIssues(nil)
	if got != 0 {
		t.Errorf("nil fixes should return 0, got %d", got)
	}
}

func TestHasSeverity_Empty(t *testing.T) {
	if hasSeverity(nil, severityCritical) {
		t.Error("nil fixes should not have any severity")
	}
}

func TestFilterBySeverity_NoMatch(t *testing.T) {
	fixes := []fix{{SeverityLevel: sevLow}}
	result := filterBySeverity(fixes, severityCritical)
	if len(result) != 0 {
		t.Errorf("expected 0, got %d", len(result))
	}
}

func TestJoinFixTitles_Empty(t *testing.T) {
	got := joinFixTitles(nil)
	if got != "" {
		t.Errorf("nil fixes should return empty, got %q", got)
	}
}

func TestBuildPerSection_Empty(t *testing.T) {
	sections := buildPerSection(nil)
	if len(sections) != 0 {
		t.Errorf("nil fixes should return empty sections, got %d", len(sections))
	}
}

func TestComputeAchievablePosture_HighOnly(t *testing.T) {
	fixes := []fix{
		{SeverityLevel: sevHigh},
		{SeverityLevel: sevHigh},
	}
	got := computeAchievablePosture(protocolState{}, fixes)
	if got != "Low Risk" {
		t.Errorf("high-only with core issues but no critical should return Low Risk, got %q", got)
	}
}

func TestComputeAchievablePosture_ThreeCritical(t *testing.T) {
	fixes := []fix{
		{SeverityLevel: sevCritical},
		{SeverityLevel: sevCritical},
		{SeverityLevel: sevCritical},
	}
	got := computeAchievablePosture(protocolState{}, fixes)
	if got != "Low Risk" {
		t.Errorf("3 critical fixes should be Low Risk, got %q", got)
	}
}

func TestAppendNoMailHardeningFixes_PartialHardened(t *testing.T) {
	ps := protocolState{spfHardFail: true, dmarcMissing: true}
	fixes := appendNoMailHardeningFixes(nil, ps, "example.com")
	if len(fixes) != 1 {
		t.Fatalf("expected 1 fix (DMARC only), got %d", len(fixes))
	}
	if fixes[0].Title != "Add DMARC Reject for Null MX Domain" {
		t.Errorf("title = %q", fixes[0].Title)
	}
}

func TestAppendNoMailHardeningFixes_SPFMissing(t *testing.T) {
	ps := protocolState{spfHardFail: false, dmarcPolicy: "reject"}
	fixes := appendNoMailHardeningFixes(nil, ps, "example.com")
	if len(fixes) != 1 {
		t.Fatalf("expected 1 fix (SPF only), got %d", len(fixes))
	}
	if fixes[0].Title != "Harden SPF for Null MX Domain" {
		t.Errorf("title = %q", fixes[0].Title)
	}
}

func TestAppendProbableNoMailFixes_PartialHardened(t *testing.T) {
	ps := protocolState{spfHardFail: true, dmarcMissing: true}
	fixes := appendProbableNoMailFixes(nil, ps, "example.com")
	if len(fixes) != 1 {
		t.Fatalf("expected 1 fix, got %d", len(fixes))
	}
	if fixes[0].Title != "Add DMARC Reject for No-Mail Domain" {
		t.Errorf("title = %q", fixes[0].Title)
	}
}

func TestAppendDMARCFixes_Reject_WithRua(t *testing.T) {
	ps := protocolState{dmarcPolicy: "reject", dmarcOK: true, dmarcHasRua: true}
	fixes := appendDMARCFixes(nil, ps, nil, "example.com")
	if len(fixes) != 0 {
		t.Errorf("reject with rua should have 0 fixes, got %d", len(fixes))
	}
}

func TestExtractSPFIncludes_AnyWithNonString(t *testing.T) {
	results := map[string]any{
		"spf_analysis": map[string]any{
			"includes": []any{"valid.com", 123, nil},
		},
	}
	got := extractSPFIncludes(results)
	if len(got) != 1 {
		t.Errorf("expected 1 valid include, got %d", len(got))
	}
	if got[0] != "valid.com" {
		t.Errorf("include = %q", got[0])
	}
}

func TestSeverityLevels(t *testing.T) {
	if sevCritical.Order >= sevHigh.Order {
		t.Error("Critical should have lower order than High")
	}
	if sevHigh.Order >= sevMedium.Order {
		t.Error("High should have lower order than Medium")
	}
	if sevMedium.Order >= sevLow.Order {
		t.Error("Medium should have lower order than Low")
	}
}
