package analyzer

import (
	"testing"
)

func TestComputeInternalScore_AllPresent(t *testing.T) {
	ps := protocolState{
		spfOK: true, spfHardFail: true,
		dmarcOK: true, dmarcPolicy: "reject",
		dnssecOK: true, daneOK: true, mtaStsOK: true,
		tlsrptOK: true, caaOK: true, bimiOK: true,
	}
	score := computeInternalScore(ps, DKIMSuccess)
	if score != 100 {
		t.Errorf("full posture should score 100, got %d", score)
	}
}

func TestComputeInternalScore_Capped(t *testing.T) {
	ps := protocolState{
		spfOK: true, spfHardFail: true,
		dmarcOK: true, dmarcPolicy: "reject",
		dnssecOK: true, daneOK: true, mtaStsOK: true,
		tlsrptOK: true, caaOK: true, bimiOK: true,
	}
	score := computeInternalScore(ps, DKIMNoMailDomain)
	if score > 100 {
		t.Errorf("score should be capped at 100, got %d", score)
	}
}

func TestComputeSPFScore_AllCases(t *testing.T) {
	tests := []struct {
		name string
		ps   protocolState
		want int
	}{
		{"missing", protocolState{spfMissing: true}, 0},
		{"dangerous", protocolState{spfDangerous: true}, 5},
		{"hard fail", protocolState{spfHardFail: true}, 20},
		{"soft fail", protocolState{spfOK: true, spfWarning: true}, 15},
		{"ok default", protocolState{spfOK: true}, 15},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := computeSPFScore(tc.ps)
			if got != tc.want {
				t.Errorf("computeSPFScore() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestComputeDMARCScore_AllCases(t *testing.T) {
	tests := []struct {
		name string
		ps   protocolState
		want int
	}{
		{"missing", protocolState{dmarcMissing: true}, 0},
		{"reject", protocolState{dmarcPolicy: "reject"}, 30},
		{"quarantine full", protocolState{dmarcPolicy: "quarantine", dmarcPct: 100}, 25},
		{"quarantine partial", protocolState{dmarcPolicy: "quarantine", dmarcPct: 50}, 20},
		{"none with rua", protocolState{dmarcPolicy: "none", dmarcHasRua: true}, 10},
		{"none without rua", protocolState{dmarcPolicy: "none"}, 5},
		{"unknown policy", protocolState{dmarcPolicy: "something"}, 10},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := computeDMARCScore(tc.ps)
			if got != tc.want {
				t.Errorf("computeDMARCScore() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestComputeDKIMScore_AllStates(t *testing.T) {
	tests := []struct {
		name string
		ds   DKIMState
		want int
	}{
		{"success", DKIMSuccess, 15},
		{"provider inferred", DKIMProviderInferred, 12},
		{"third party only", DKIMThirdPartyOnly, 8},
		{"weak keys only", DKIMWeakKeysOnly, 5},
		{"no mail domain", DKIMNoMailDomain, 15},
		{"absent", DKIMAbsent, 0},
		{"inconclusive", DKIMInconclusive, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := computeDKIMScore(tc.ds)
			if got != tc.want {
				t.Errorf("computeDKIMScore() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestComputeAuxScore_Individual(t *testing.T) {
	tests := []struct {
		name string
		ps   protocolState
		want int
	}{
		{"dnssec only", protocolState{dnssecOK: true}, 10},
		{"dane only", protocolState{daneOK: true}, 5},
		{"mta-sts only", protocolState{mtaStsOK: true}, 5},
		{"tlsrpt only", protocolState{tlsrptOK: true}, 5},
		{"caa only", protocolState{caaOK: true}, 5},
		{"bimi only", protocolState{bimiOK: true}, 5},
		{"all", protocolState{dnssecOK: true, daneOK: true, mtaStsOK: true, tlsrptOK: true, caaOK: true, bimiOK: true}, 35},
		{"none", protocolState{}, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := computeAuxScore(tc.ps)
			if got != tc.want {
				t.Errorf("computeAuxScore() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestClassifyGrade_TLD(t *testing.T) {
	ps := protocolState{isTLD: true, dnssecOK: true}
	gi := gradeInput{}
	state, _, _, _ := classifyGrade(ps, gi)
	if state != riskLow {
		t.Errorf("TLD with DNSSEC should be Low Risk, got %q", state)
	}
}

func TestClassifyGrade_TLDNoDNSSEC(t *testing.T) {
	ps := protocolState{isTLD: true}
	gi := gradeInput{}
	state, _, _, _ := classifyGrade(ps, gi)
	if state != riskHigh {
		t.Errorf("TLD without DNSSEC should be High Risk, got %q", state)
	}
}

func TestClassifyGrade_NoMail(t *testing.T) {
	ps := protocolState{}
	gi := gradeInput{isNoMail: true, hasSPF: true, hasDMARC: true, dmarcStrict: true, dmarcFullEnforcing: true}
	state, _, _, _ := classifyGrade(ps, gi)
	if state != riskLow {
		t.Errorf("no-mail fully hardened should be Low Risk, got %q", state)
	}
}

func TestClassifyGrade_DNSSECBrokenOverrides(t *testing.T) {
	ps := protocolState{dnssecBroken: true, isTLD: true}
	gi := gradeInput{}
	state, _, color, _ := classifyGrade(ps, gi)
	if state != riskCritical {
		t.Errorf("DNSSEC broken should be Critical Risk, got %q", state)
	}
	if color != "danger" {
		t.Errorf("color should be danger, got %q", color)
	}
}

func TestClassifyMailGrade_CorePresent_Reject_WithDKIM(t *testing.T) {
	ps := protocolState{dmarcPolicy: "reject"}
	gi := gradeInput{hasSPF: true, hasDMARC: true, hasDKIM: true, corePresent: true, dmarcFullEnforcing: true}
	state, icon, color, _ := classifyMailCorePresent(ps, gi)
	if state != riskLow {
		t.Errorf("state = %q, want %q", state, riskLow)
	}
	if icon != iconShieldAlt {
		t.Errorf("icon = %q, want %q", icon, iconShieldAlt)
	}
	if color != "success" {
		t.Errorf("color = %q, want success", color)
	}
}

func TestClassifyMailGrade_CorePresent_Reject_NoDKIM(t *testing.T) {
	ps := protocolState{dmarcPolicy: "reject"}
	gi := gradeInput{hasSPF: true, hasDMARC: true, hasDKIM: false, corePresent: true, dmarcFullEnforcing: true}
	state, _, color, _ := classifyMailCorePresent(ps, gi)
	if state != riskMedium {
		t.Errorf("state = %q, want %q", state, riskMedium)
	}
	if color != "info" {
		t.Errorf("color = %q, want info", color)
	}
}

func TestClassifyMailGrade_PartialEnforcing(t *testing.T) {
	ps := protocolState{dmarcPolicy: "quarantine", dmarcPct: 50}
	gi := gradeInput{hasSPF: true, hasDMARC: true, corePresent: true, dmarcPartialEnforcing: true}
	state, _, _, msg := classifyMailCorePresent(ps, gi)
	if state != riskMedium {
		t.Errorf("state = %q, want %q", state, riskMedium)
	}
	if msg == "" {
		t.Error("expected non-empty message")
	}
}

func TestClassifyMailGrade_PolicyNone_WithRua(t *testing.T) {
	ps := protocolState{dmarcPolicy: "none", dmarcHasRua: true}
	gi := gradeInput{hasSPF: true, hasDMARC: true, corePresent: true}
	state, _, _, _ := classifyMailCorePresent(ps, gi)
	if state != riskMedium {
		t.Errorf("state = %q, want %q", state, riskMedium)
	}
}

func TestClassifyMailGrade_PolicyNone_NoRua(t *testing.T) {
	ps := protocolState{dmarcPolicy: "none", dmarcHasRua: false}
	gi := gradeInput{hasSPF: true, hasDMARC: true, corePresent: true}
	state, _, color, _ := classifyMailCorePresent(ps, gi)
	if state != riskHigh {
		t.Errorf("state = %q, want %q", state, riskHigh)
	}
	if color != "warning" {
		t.Errorf("color = %q, want warning", color)
	}
}

func TestClassifyMailGrade_DefaultCase(t *testing.T) {
	ps := protocolState{dmarcPolicy: "something_else"}
	gi := gradeInput{hasSPF: true, hasDMARC: true, corePresent: true}
	state, _, _, _ := classifyMailCorePresent(ps, gi)
	if state != riskMedium {
		t.Errorf("state = %q, want %q", state, riskMedium)
	}
}

func TestClassifyMailPartial(t *testing.T) {
	state, _, _, msg := classifyMailPartial(gradeInput{hasSPF: true})
	if state != riskHigh {
		t.Errorf("state = %q, want %q", state, riskHigh)
	}
	if msg == "" {
		t.Error("expected non-empty message")
	}

	state, _, _, msg = classifyMailPartial(gradeInput{hasDMARC: true})
	if state != riskHigh {
		t.Errorf("state = %q, want %q", state, riskHigh)
	}
	if msg == "" {
		t.Error("expected non-empty message for DMARC only")
	}
}

func TestClassifyNoMailGrade_AllBranches(t *testing.T) {
	tests := []struct {
		name string
		gi   gradeInput
		want string
	}{
		{"strict", gradeInput{hasSPF: true, hasDMARC: true, dmarcStrict: true, dmarcFullEnforcing: true}, riskLow},
		{"full enforcing not strict", gradeInput{hasSPF: true, hasDMARC: true, dmarcFullEnforcing: true}, riskLow},
		{"not enforcing", gradeInput{hasSPF: true, hasDMARC: true}, riskMedium},
		{"spf only", gradeInput{hasSPF: true}, riskHigh},
		{"dmarc only", gradeInput{hasDMARC: true}, riskHigh},
		{"nothing", gradeInput{}, riskCritical},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state, _, _, _ := classifyNoMailGrade(protocolState{}, tc.gi)
			if state != tc.want {
				t.Errorf("state = %q, want %q", state, tc.want)
			}
		})
	}
}

func TestClassifyRegistryGrade_AllCases(t *testing.T) {
	state, icon, color, _ := classifyRegistryGrade(protocolState{dnssecOK: true}, gradeInput{})
	if state != riskLow || icon != iconShieldAlt || color != "success" {
		t.Errorf("DNSSEC OK: state=%q icon=%q color=%q", state, icon, color)
	}

	state, icon, color, _ = classifyRegistryGrade(protocolState{}, gradeInput{})
	if state != riskHigh || icon != iconExclamationTriangle || color != "warning" {
		t.Errorf("No DNSSEC: state=%q icon=%q color=%q", state, icon, color)
	}
}

func TestApplyMonitoringSuffix(t *testing.T) {
	got := applyMonitoringSuffix(riskLow, []string{"note"})
	if got != riskLow {
		t.Errorf("with monitoring: got %q, want %q", got, riskLow)
	}
	got = applyMonitoringSuffix(riskMedium, nil)
	if got != riskMedium {
		t.Errorf("without monitoring: got %q, want %q", got, riskMedium)
	}
}

func TestBuildDescriptiveMessage_Variations(t *testing.T) {
	tests := []struct {
		name       string
		configured []string
		absent     []string
		monitoring []string
		wantEmpty  bool
	}{
		{"all populated", []string{"SPF"}, []string{"DANE"}, []string{"note"}, false},
		{"configured only", []string{"SPF", "DMARC"}, nil, nil, false},
		{"absent only", nil, []string{"DANE"}, nil, false},
		{"monitoring only", nil, nil, []string{"note"}, false},
		{"all nil", nil, nil, nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := buildDescriptiveMessage(protocolState{}, tc.configured, tc.absent, tc.monitoring)
			if tc.wantEmpty && msg != "Email security posture evaluated" {
				t.Errorf("expected default message, got %q", msg)
			}
			if !tc.wantEmpty && msg == "" {
				t.Error("expected non-empty message")
			}
		})
	}
}

func TestDetermineGrade(t *testing.T) {
	ps := protocolState{dmarcPolicy: "reject"}
	gi := gradeInput{hasSPF: true, hasDMARC: true, hasDKIM: true}
	state, icon, color, msg := determineGrade(ps, DKIMSuccess, gi)
	if state == "" || icon == "" || color == "" || msg == "" {
		t.Error("determineGrade should return non-empty values")
	}
}

func TestClassifySimpleProtocols_NonTLD(t *testing.T) {
	ps := protocolState{
		mtaStsOK: true, tlsrptOK: true, bimiOK: true,
		daneOK: true, dnssecOK: true, caaOK: true,
	}
	acc := &postureAccumulator{configured: []string{}, absent: []string{}, providerLimited: []string{}}
	classifySimpleProtocols(ps, false, acc)
	if len(acc.configured) != 6 {
		t.Errorf("expected 6 configured, got %d: %v", len(acc.configured), acc.configured)
	}
}

func TestClassifySimpleProtocols_TLD(t *testing.T) {
	ps := protocolState{dnssecOK: true}
	acc := &postureAccumulator{configured: []string{}, absent: []string{}, providerLimited: []string{}}
	classifySimpleProtocols(ps, true, acc)
	if len(acc.configured) != 1 || acc.configured[0] != "DNSSEC" {
		t.Errorf("TLD should only classify DNSSEC, got %v", acc.configured)
	}
}

func TestClassifySimpleProtocols_AllAbsent(t *testing.T) {
	ps := protocolState{}
	acc := &postureAccumulator{configured: []string{}, absent: []string{}, providerLimited: []string{}, issues: []string{}, recommendations: []string{}}
	classifySimpleProtocols(ps, false, acc)
	if len(acc.absent) < 5 {
		t.Errorf("expected at least 5 absent, got %d: %v", len(acc.absent), acc.absent)
	}
}

func TestClassifyDMARCSuccess_QuarantinePartialPct(t *testing.T) {
	ps := protocolState{dmarcOK: true, dmarcPolicy: "quarantine", dmarcPct: 50, dmarcHasRua: true}
	acc := &postureAccumulator{issues: []string{}, recommendations: []string{}, configured: []string{}, absent: []string{}, monitoring: []string{}}
	classifyDMARCSuccess(ps, acc)
	if len(acc.monitoring) == 0 {
		t.Error("quarantine at partial pct should add monitoring note")
	}
}

func TestClassifyDMARCSuccess_DefaultPolicy(t *testing.T) {
	ps := protocolState{dmarcOK: true, dmarcPolicy: "unknown_policy", dmarcHasRua: true}
	acc := &postureAccumulator{issues: []string{}, recommendations: []string{}, configured: []string{}, absent: []string{}, monitoring: []string{}}
	classifyDMARCSuccess(ps, acc)
	if len(acc.configured) == 0 {
		t.Error("unknown policy should still add to configured")
	}
}

func TestClassifyDMARCWarning(t *testing.T) {
	tests := []struct {
		name         string
		ps           protocolState
		wantRec      bool
		wantRecCount int
	}{
		{"warning none no rua", protocolState{dmarcWarning: true, dmarcOK: true, dmarcPolicy: "none", dmarcHasRua: false}, true, 2},
		{"warning none with rua", protocolState{dmarcWarning: true, dmarcOK: true, dmarcPolicy: "none", dmarcHasRua: true}, true, 1},
		{"warning reject with rua", protocolState{dmarcWarning: true, dmarcOK: true, dmarcPolicy: "reject", dmarcHasRua: true}, false, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			acc := &postureAccumulator{issues: []string{}, recommendations: []string{}, configured: []string{}, absent: []string{}, monitoring: []string{}}
			classifyDMARCWarning(tc.ps, acc)
			if len(acc.configured) == 0 {
				t.Error("should add to configured")
			}
			if len(acc.monitoring) == 0 {
				t.Error("should add monitoring note")
			}
		})
	}
}

func TestClassifyDMARCReportAuth_WithIssues(t *testing.T) {
	acc := &postureAccumulator{issues: []string{}, recommendations: []string{}, monitoring: []string{}}
	results := map[string]any{
		"dmarc_report_auth": map[string]any{
			"issues": []string{"some issue"},
			"external_domains": []any{
				map[string]any{"domain": "ext.com", "authorized": false},
			},
		},
	}
	classifyDMARCReportAuth(results, acc)
	if len(acc.monitoring) == 0 {
		t.Error("should add monitoring from issues")
	}
	if len(acc.recommendations) == 0 {
		t.Error("should add recommendation for unauthorized domain")
	}
}

func TestClassifyDMARCReportAuth_Authorized(t *testing.T) {
	acc := &postureAccumulator{issues: []string{}, recommendations: []string{}, monitoring: []string{}}
	results := map[string]any{
		"dmarc_report_auth": map[string]any{
			"external_domains": []any{
				map[string]any{"domain": "ext.com", "authorized": true},
			},
		},
	}
	classifyDMARCReportAuth(results, acc)
	if len(acc.recommendations) != 0 {
		t.Error("authorized domain should not add recommendation")
	}
}

func TestClassifyDMARCReportAuth_NoKey(t *testing.T) {
	acc := &postureAccumulator{issues: []string{}, recommendations: []string{}, monitoring: []string{}}
	classifyDMARCReportAuth(map[string]any{}, acc)
	if len(acc.monitoring) != 0 || len(acc.recommendations) != 0 {
		t.Error("no dmarc_report_auth should not add anything")
	}
}

func TestExtractMailFlags(t *testing.T) {
	ps := protocolState{
		spfOK: true, dmarcOK: true, dmarcWarning: false,
		dkimOK: true, isNoMailDomain: true,
		spfHardFail: true, dmarcPolicy: "reject",
	}
	results := map[string]any{
		"basic_records": map[string]any{"MX": []string{"mx.example.com"}},
	}
	mf := extractMailFlags(results, ps)
	if !mf.hasSPF {
		t.Error("hasSPF should be true")
	}
	if !mf.hasDMARC {
		t.Error("hasDMARC should be true")
	}
	if !mf.hasDKIM {
		t.Error("hasDKIM should be true")
	}
	if !mf.hasNullMX {
		t.Error("hasNullMX should be true")
	}
	if !mf.spfDenyAll {
		t.Error("spfDenyAll should be true")
	}
	if !mf.dmarcReject {
		t.Error("dmarcReject should be true")
	}
	if !mf.hasMX {
		t.Error("hasMX should be true")
	}
}

func TestExtractMailFlags_NoBasicRecords(t *testing.T) {
	ps := protocolState{}
	mf := extractMailFlags(map[string]any{}, ps)
	if mf.hasMX {
		t.Error("hasMX should be false without basic_records")
	}
}

func TestExtractMailFlags_DMARCWarning(t *testing.T) {
	ps := protocolState{dmarcWarning: true}
	mf := extractMailFlags(map[string]any{}, ps)
	if !mf.hasDMARC {
		t.Error("hasDMARC should be true when dmarcWarning is true")
	}
}

func TestExtractMailFlags_DKIMProvider(t *testing.T) {
	ps := protocolState{dkimProvider: true}
	mf := extractMailFlags(map[string]any{}, ps)
	if !mf.hasDKIM {
		t.Error("hasDKIM should be true when dkimProvider is true")
	}
}

func TestClassifyEmailSpoofability_AllClasses(t *testing.T) {
	tests := []struct {
		name     string
		ps       protocolState
		hasSPF   bool
		hasDMARC bool
		want     emailSpoofClass
	}{
		{"no mail", protocolState{isNoMailDomain: true}, true, true, emailSpoofNoMail},
		{"unprotected", protocolState{}, false, false, emailSpoofUnprotected},
		{"reject", protocolState{dmarcPolicy: "reject"}, true, true, emailSpoofReject},
		{"quarantine full", protocolState{dmarcPolicy: "quarantine", dmarcPct: 100}, true, true, emailSpoofQuarantineFull},
		{"quarantine partial", protocolState{dmarcPolicy: "quarantine", dmarcPct: 50}, true, true, emailSpoofQuarantinePartial},
		{"monitor only", protocolState{dmarcPolicy: "none"}, true, true, emailSpoofMonitorOnly},
		{"spf only", protocolState{}, true, false, emailSpoofSPFOnly},
		{"dmarc only", protocolState{}, false, true, emailSpoofDMARCOnly},
		{"uncertain policy", protocolState{dmarcPolicy: "weird"}, true, true, emailSpoofUncertain},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyEmailSpoofability(tc.ps, tc.hasSPF, tc.hasDMARC)
			if got != tc.want {
				t.Errorf("classifyEmailSpoofability() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestBuildEmailAnswer_AllClasses(t *testing.T) {
	tests := []struct {
		name     string
		ps       protocolState
		hasSPF   bool
		hasDMARC bool
	}{
		{"no mail", protocolState{isNoMailDomain: true}, false, false},
		{"unprotected", protocolState{}, false, false},
		{"reject", protocolState{dmarcPolicy: "reject"}, true, true},
		{"spf only", protocolState{}, true, false},
		{"dmarc only", protocolState{}, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			answer := buildEmailAnswer(tc.ps, tc.hasSPF, tc.hasDMARC)
			if answer == "" {
				t.Error("answer should not be empty")
			}
		})
	}
}

func TestBuildEmailAnswerStructured_AllClasses(t *testing.T) {
	tests := []struct {
		name     string
		ps       protocolState
		hasSPF   bool
		hasDMARC bool
		wantAns  string
		wantClr  string
	}{
		{"reject", protocolState{dmarcPolicy: "reject"}, true, true, "No", "success"},
		{"unprotected", protocolState{}, false, false, "Yes", "danger"},
		{"spf only", protocolState{}, true, false, "Likely", "danger"},
		{"dmarc only", protocolState{}, false, true, "Partially", "warning"},
		{"monitor", protocolState{dmarcPolicy: "none"}, true, true, "Yes", "danger"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildEmailAnswerStructured(tc.ps, tc.hasSPF, tc.hasDMARC)
			if got["answer"] != tc.wantAns {
				t.Errorf("answer = %q, want %q", got["answer"], tc.wantAns)
			}
			if got["color"] != tc.wantClr {
				t.Errorf("color = %q, want %q", got["color"], tc.wantClr)
			}
		})
	}
}

func TestBuildEmailVerdict_AllBranches(t *testing.T) {
	tests := []struct {
		name      string
		vi        verdictInput
		wantLabel string
		wantColor string
	}{
		{
			"enforcing reject",
			verdictInput{ps: protocolState{dmarcPolicy: "reject"}, hasSPF: true, hasDMARC: true, ds: DKIMSuccess},
			"Protected", "success",
		},
		{
			"spf only no dmarc",
			verdictInput{hasSPF: true, hasDMARC: false},
			"Basic", "warning",
		},
		{
			"no spf no dmarc",
			verdictInput{hasSPF: false, hasDMARC: false},
			"Exposed", "danger",
		},
		{
			"spf and dmarc none",
			verdictInput{ps: protocolState{dmarcPolicy: "none"}, hasSPF: true, hasDMARC: true},
			"Basic", "warning",
		},
		{
			"dmarc only no spf",
			verdictInput{hasSPF: false, hasDMARC: true},
			"Exposed", "danger",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			verdicts := map[string]any{}
			buildEmailVerdict(tc.vi, verdicts)
			v, ok := verdicts["email_spoofing"]
			if !ok {
				t.Fatal("missing email_spoofing verdict")
			}
			m := v.(map[string]any)
			if m["label"] != tc.wantLabel {
				t.Errorf("label = %v, want %v", m["label"], tc.wantLabel)
			}
			if m["color"] != tc.wantColor {
				t.Errorf("color = %v, want %v", m["color"], tc.wantColor)
			}
		})
	}
}

func TestBuildVerdicts_AllKeys(t *testing.T) {
	vi := verdictInput{
		ps:       protocolState{dmarcOK: true, dmarcPolicy: "reject", dnssecOK: true, caaOK: true, mtaStsOK: true},
		ds:       DKIMSuccess,
		hasSPF:   true,
		hasDMARC: true,
		hasDKIM:  true,
	}
	verdicts := buildVerdicts(vi)
	requiredKeys := []string{
		"email_spoofing", "brand_impersonation", "dns_tampering",
		"certificate_control", "transport",
		"email_answer", "email_answer_short", "email_answer_reason", "email_answer_color",
	}
	for _, k := range requiredKeys {
		if _, ok := verdicts[k]; !ok {
			t.Errorf("missing verdict key %q", k)
		}
	}
}

func TestBuildAISurfaceVerdicts_WithData(t *testing.T) {
	results := map[string]any{
		"ai_surface": map[string]any{
			"llms_txt":       map[string]any{"found": true, "full_found": true},
			"robots_txt":     map[string]any{"found": true, "blocks_ai_crawlers": true},
			"poisoning":      map[string]any{"ioc_count": float64(0)},
			"hidden_prompts": map[string]any{"artifact_count": float64(0)},
		},
	}
	verdicts := map[string]any{}
	buildAISurfaceVerdicts(results, verdicts)
	if _, ok := verdicts["ai_llms_txt"]; !ok {
		t.Error("missing ai_llms_txt verdict")
	}
	if _, ok := verdicts["ai_crawler_governance"]; !ok {
		t.Error("missing ai_crawler_governance verdict")
	}
	if _, ok := verdicts["ai_poisoning"]; !ok {
		t.Error("missing ai_poisoning verdict")
	}
	if _, ok := verdicts["ai_hidden_prompts"]; !ok {
		t.Error("missing ai_hidden_prompts verdict")
	}
}

func TestBuildAISurfaceVerdicts_NoData(t *testing.T) {
	verdicts := map[string]any{}
	buildAISurfaceVerdicts(map[string]any{}, verdicts)
	if len(verdicts) != 0 {
		t.Errorf("expected no verdicts without ai_surface data, got %d", len(verdicts))
	}
}

func TestGetNumericValue_AllTypes(t *testing.T) {
	tests := []struct {
		name string
		m    map[string]any
		key  string
		want float64
	}{
		{"float64", map[string]any{"x": float64(5.5)}, "x", 5.5},
		{"int", map[string]any{"x": 5}, "x", 5},
		{"int64", map[string]any{"x": int64(5)}, "x", 5},
		{"missing", map[string]any{}, "x", 0},
		{"string", map[string]any{"x": "bad"}, "x", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := getNumericValue(tc.m, tc.key)
			if got != tc.want {
				t.Errorf("getNumericValue() = %f, want %f", got, tc.want)
			}
		})
	}
}

func TestComputeMailVerdict_EdgeCases(t *testing.T) {
	verdict, badge := computeMailVerdict(mailFlags{hasSPF: true, hasDMARC: true})
	if verdict != "minimal" || badge != "Limited Protection" {
		t.Errorf("SPF+DMARC without DKIM: verdict=%q badge=%q", verdict, badge)
	}

	verdict, badge = computeMailVerdict(mailFlags{hasDMARC: true})
	if verdict != "minimal" || badge != "Limited Protection" {
		t.Errorf("DMARC only: verdict=%q badge=%q", verdict, badge)
	}
}

func TestClassifyCertificateCosts_NoCTData(t *testing.T) {
	acc := &postureAccumulator{recommendations: []string{}}
	classifyCertificateCosts(map[string]any{}, acc)
	if len(acc.recommendations) != 0 {
		t.Error("no ct_subdomains should not add recommendations")
	}
}

func TestClassifyCertificateCosts_NoCASummary(t *testing.T) {
	acc := &postureAccumulator{recommendations: []string{}}
	classifyCertificateCosts(map[string]any{
		"ct_subdomains": map[string]any{},
	}, acc)
	if len(acc.recommendations) != 0 {
		t.Error("no ca_summary should not add recommendations")
	}
}
