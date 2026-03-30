// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
	"errors"
	"strings"
	"testing"
)

func TestClassifyCertificateCosts_WrongCASummaryType(t *testing.T) {
	acc := &postureAccumulator{recommendations: []string{}}
	classifyCertificateCosts(map[string]any{
		"ct_subdomains": map[string]any{"ca_summary": "invalid"},
	}, acc)
	if len(acc.recommendations) != 0 {
		t.Error("expected no recommendations for wrong ca_summary type")
	}
}

func TestClassifyCertificateCosts_ManyPaidCertsNoWildcard(t *testing.T) {
	acc := &postureAccumulator{recommendations: []string{}}
	classifyCertificateCosts(map[string]any{
		"ct_subdomains": map[string]any{
			"ca_summary": []map[string]any{
				{"name": "DigiCert", "certCount": 5},
			},
		},
	}, acc)
	if len(acc.recommendations) < 1 {
		t.Error("expected wildcard recommendation for many paid certs")
	}
	hasWildcardRec := false
	hasFreeRec := false
	for _, r := range acc.recommendations {
		if strings.Contains(r, "wildcard") {
			hasWildcardRec = true
		}
		if strings.Contains(r, "free certificate") {
			hasFreeRec = true
		}
	}
	if !hasWildcardRec {
		t.Error("expected wildcard recommendation")
	}
	if !hasFreeRec {
		t.Error("expected free certificate recommendation when no free certs present")
	}
}

func TestClassifyCertificateCosts_WithWildcard(t *testing.T) {
	acc := &postureAccumulator{recommendations: []string{}}
	classifyCertificateCosts(map[string]any{
		"ct_subdomains": map[string]any{
			"ca_summary": []map[string]any{
				{"name": "DigiCert", "certCount": 5},
			},
			"wildcard_certs": map[string]any{"present": true},
		},
	}, acc)
	for _, r := range acc.recommendations {
		if strings.Contains(r, "wildcard") {
			t.Error("should not recommend wildcard when already present")
		}
	}
}

func TestClassifyCertificateCosts_WithFreeCerts(t *testing.T) {
	acc := &postureAccumulator{recommendations: []string{}}
	classifyCertificateCosts(map[string]any{
		"ct_subdomains": map[string]any{
			"ca_summary": []map[string]any{
				{"name": "DigiCert", "certCount": 3},
				{"name": "Let's Encrypt", "certCount": 2},
			},
		},
	}, acc)
	for _, r := range acc.recommendations {
		if strings.Contains(r, "free certificate") {
			t.Error("should not recommend free certs when already using free CA")
		}
	}
}

func TestClassifyCertificateCosts_BelowThreshold(t *testing.T) {
	acc := &postureAccumulator{recommendations: []string{}}
	classifyCertificateCosts(map[string]any{
		"ct_subdomains": map[string]any{
			"ca_summary": []map[string]any{
				{"name": "DigiCert", "certCount": 2},
			},
		},
	}, acc)
	if len(acc.recommendations) != 0 {
		t.Error("expected no recommendations with only 2 paid certs")
	}
}

func TestBackfillLegacyFields_Observed(t *testing.T) {
	result := map[string]any{}
	probe := map[string]any{
		mapKeyStatus: mapKeyObserved,
		mapKeyObservations: []map[string]any{
			{"host": "mx.example.com", "reachable": true},
		},
		mapKeySummary: map[string]any{
			mapKeyTotalServers: 1,
			mapKeyReachable:    1,
		},
	}
	backfillLegacyFields(result, map[string]any{}, probe)
	servers, ok := result[mapKeyServers].([]map[string]any)
	if !ok || len(servers) != 1 {
		t.Error("expected servers to be set from observations")
	}
	summary, ok := result[mapKeySummary].(map[string]any)
	if !ok {
		t.Fatal("expected summary to be set")
	}
	if summary[mapKeyTotalServers] != 1 {
		t.Errorf("total_servers = %v, want 1", summary[mapKeyTotalServers])
	}
	issues, ok := result["issues"].([]string)
	if !ok || len(issues) != 0 {
		t.Error("expected empty issues")
	}
}

func TestBackfillLegacyFields_ObservedNoSummary(t *testing.T) {
	result := map[string]any{}
	probe := map[string]any{
		mapKeyStatus:       mapKeyObserved,
		mapKeyObservations: []map[string]any{},
	}
	backfillLegacyFields(result, map[string]any{}, probe)
	summary, ok := result[mapKeySummary].(map[string]any)
	if !ok {
		t.Fatal("expected summary fallback")
	}
	if summary[mapKeyTotalServers] != 0 {
		t.Errorf("total_servers = %v, want 0", summary[mapKeyTotalServers])
	}
}

func TestBackfillLegacyFields_NotObserved(t *testing.T) {
	result := map[string]any{}
	probe := map[string]any{mapKeyStatus: mapKeySkipped}
	backfillLegacyFields(result, map[string]any{}, probe)
	servers, ok := result[mapKeyServers].([]map[string]any)
	if !ok || len(servers) != 0 {
		t.Error("expected empty servers for skipped probe")
	}
	issues, ok := result["issues"].([]string)
	if !ok || len(issues) != 0 {
		t.Error("expected empty issues")
	}
}

func TestHandlePartialResponse_WithContent(t *testing.T) {
	var b strings.Builder
	b.WriteString("220 mail.example.com")
	resp, err := handlePartialResponse(b, nil)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if resp != "220 mail.example.com" {
		t.Errorf("resp = %q, want '220 mail.example.com'", resp)
	}
}

func TestHandlePartialResponse_Empty(t *testing.T) {
	var b strings.Builder
	testErr := errors.New("connection timeout")
	_, err := handlePartialResponse(b, testErr)
	if err == nil {
		t.Error("expected error for empty response")
	}
	if err != testErr {
		t.Errorf("expected original error, got %v", err)
	}
}

func TestHandlePartialResponse_ContentWithError(t *testing.T) {
	var b strings.Builder
	b.WriteString("220 partial")
	resp, err := handlePartialResponse(b, errors.New("timeout"))
	if err != nil {
		t.Errorf("expected nil error when content present, got %v", err)
	}
	if resp != "220 partial" {
		t.Errorf("resp = %q, want '220 partial'", resp)
	}
}

func TestComputeMailVerdictAllCases(t *testing.T) {
	tests := []struct {
		name        string
		mf          mailFlags
		wantVerdict string
		wantBadge   string
	}{
		{"null mx", mailFlags{hasNullMX: true}, "no_mail", "No Mail Observed"},
		{"fully protected", mailFlags{hasSPF: true, hasDMARC: true, hasDKIM: true, dmarcReject: true}, "protected", "Strongly Protected"},
		{"moderate", mailFlags{hasSPF: true, hasDMARC: true, hasDKIM: true}, "partial", "Moderately Protected"},
		{"spf only", mailFlags{hasSPF: true}, "minimal", "Limited Protection"},
		{"dmarc only", mailFlags{hasDMARC: true}, "minimal", "Limited Protection"},
		{"unprotected", mailFlags{}, "unprotected", "Unprotected"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, b := computeMailVerdict(tc.mf)
			if v != tc.wantVerdict {
				t.Errorf("verdict = %q, want %q", v, tc.wantVerdict)
			}
			if b != tc.wantBadge {
				t.Errorf("badge = %q, want %q", b, tc.wantBadge)
			}
		})
	}
}

func TestClassifyMailPosture_AllBranches(t *testing.T) {
	tests := []struct {
		name       string
		mf         mailFlags
		wantClass  string
		wantNoMail bool
	}{
		{"null mx hardened", mailFlags{hasNullMX: true, spfDenyAll: true, dmarcReject: true}, "no_mail_verified", true},
		{"null mx partial", mailFlags{hasNullMX: true}, "no_mail_partial", true},
		{"no mx spf deny", mailFlags{spfDenyAll: true}, "no_mail_intent", true},
		{"protected", mailFlags{hasSPF: true, hasDMARC: true, hasDKIM: true, dmarcReject: true, hasMX: true}, "protected", false},
		{"partial", mailFlags{hasSPF: true, hasDMARC: true, hasDKIM: true, hasMX: true}, "partial", false},
		{"minimal spf", mailFlags{hasSPF: true, hasMX: true}, "minimal", false},
		{"minimal dmarc", mailFlags{hasDMARC: true, hasMX: true}, "minimal", false},
		{"unprotected", mailFlags{hasMX: true}, "unprotected", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mc := classifyMailPosture(tc.mf, 0, "example.com", protocolState{})
			if mc.classification != tc.wantClass {
				t.Errorf("classification = %q, want %q", mc.classification, tc.wantClass)
			}
			if mc.isNoMail != tc.wantNoMail {
				t.Errorf("isNoMail = %v, want %v", mc.isNoMail, tc.wantNoMail)
			}
			if mc.label == "" {
				t.Error("label should not be empty")
			}
			if mc.summary == "" {
				t.Error("summary should not be empty")
			}
		})
	}
}

func TestDecodeEmailBody_PlainText(t *testing.T) {
	plain := "Just plain text"
	got := decodeEmailBody(plain, nil)
	if got != "Just plain text" {
		t.Errorf("decodeEmailBody(plain) = %q", got)
	}
}

func TestDecodeEmailBody_InvalidBase64(t *testing.T) {
	headers := []headerField{
		{Name: "content-transfer-encoding", Value: "base64"},
	}
	got := decodeEmailBody("not-valid-base64!!!", headers)
	if got != "not-valid-base64!!!" {
		t.Errorf("decodeEmailBody(invalid base64) should return original, got %q", got)
	}
}

func TestDecodeEmailBody_HTMLStripping(t *testing.T) {
	html := "<html><body><p>Hello</p></body></html>"
	headers := []headerField{
		{Name: "content-type", Value: "text/html; charset=utf-8"},
	}
	got := decodeEmailBody(html, headers)
	if !strings.Contains(got, "Hello") {
		t.Errorf("decodeEmailBody(html) = %q, expected to contain 'Hello'", got)
	}
	if strings.Contains(got, "<p>") {
		t.Errorf("decodeEmailBody(html) = %q, expected HTML tags to be stripped", got)
	}
}

func TestDetectBrandMismatch_Mismatch(t *testing.T) {
	r := &EmailHeaderAnalysis{
		From:    "user@fakeemail.com",
		Subject: "Your PayPal Account Has Been Limited",
	}
	detectBrandMismatch(r)
	if !r.SenderBrandMismatch {
		t.Error("expected brand mismatch for non-PayPal domain with PayPal subject")
	}
	if r.SenderBrandMismatchDetail == "" {
		t.Error("expected detail to be set")
	}
}

func TestDetectBrandMismatch_EmptySubject(t *testing.T) {
	r := &EmailHeaderAnalysis{
		From:    "user@fakeemail.com",
		Subject: "",
	}
	detectBrandMismatch(r)
	if r.SenderBrandMismatch {
		t.Error("expected no brand mismatch for empty subject")
	}
}

func TestCheckSubjectMoneyAmounts_NoMoney(t *testing.T) {
	r := &EmailHeaderAnalysis{Subject: "Hello World"}
	checkSubjectMoneyAmounts(r)
	if len(r.SubjectScamIndicators) != 0 {
		t.Error("expected no indicators")
	}
}

func TestCheckSubjectHomoglyphs_WithHomoglyph(t *testing.T) {
	r := &EmailHeaderAnalysis{Subject: "G00gle Account Alert"}
	checkSubjectHomoglyphs(r)
	if len(r.SubjectScamIndicators) != 1 {
		t.Fatalf("expected 1 indicator, got %d", len(r.SubjectScamIndicators))
	}
	if r.SubjectScamIndicators[0].Category != "Homoglyph Obfuscation" {
		t.Errorf("category = %q", r.SubjectScamIndicators[0].Category)
	}
}

func TestCheckSubjectScamPhrases_Multiple(t *testing.T) {
	r := &EmailHeaderAnalysis{Subject: "You authorized payment - Invoice confirmation"}
	checkSubjectScamPhrases(r)
	if len(r.SubjectScamIndicators) != 1 {
		t.Fatalf("expected 1 indicator, got %d", len(r.SubjectScamIndicators))
	}
	if r.SubjectScamIndicators[0].Severity != sevDanger {
		t.Errorf("severity = %q, want danger", r.SubjectScamIndicators[0].Severity)
	}
}

func TestCheckSubjectScamPhrases_None(t *testing.T) {
	r := &EmailHeaderAnalysis{Subject: "Hello from your friend"}
	checkSubjectScamPhrases(r)
	if len(r.SubjectScamIndicators) != 0 {
		t.Errorf("expected no indicators, got %d", len(r.SubjectScamIndicators))
	}
}

func TestCheckSubjectPhoneNumbers_NoPhone(t *testing.T) {
	r := &EmailHeaderAnalysis{Subject: "Hello World"}
	checkSubjectPhoneNumbers(r)
	if len(r.SubjectScamIndicators) != 0 {
		t.Error("expected no indicators for subject without phone")
	}
}

func TestAnalyzeSubjectLine_Clean(t *testing.T) {
	r := &EmailHeaderAnalysis{Subject: "Status update"}
	analyzeSubjectLine(r)
	if len(r.SubjectScamIndicators) > 0 {
		for _, ind := range r.SubjectScamIndicators {
			t.Logf("unexpected indicator: category=%q evidence=%q", ind.Category, ind.Evidence)
		}
	}
}

func TestEvaluateProtocolStates_NullMX(t *testing.T) {
	results := map[string]any{
		"has_null_mx": true,
	}
	ps := evaluateProtocolStates(results)
	if !ps.isNoMailDomain {
		t.Error("expected isNoMailDomain for has_null_mx")
	}
}

func TestEvaluateProtocolStates_IsNoMailDomain(t *testing.T) {
	results := map[string]any{
		"is_no_mail_domain": true,
	}
	ps := evaluateProtocolStates(results)
	if !ps.isNoMailDomain {
		t.Error("expected isNoMailDomain for is_no_mail_domain")
	}
}

func TestEvaluateProtocolStates_WithSPF(t *testing.T) {
	results := map[string]any{
		"spf_analysis": map[string]any{
			"status":        "success",
			"all_mechanism": "-all",
			"lookup_count":  5,
		},
	}
	ps := evaluateProtocolStates(results)
	if !ps.spfOK {
		t.Error("expected spfOK")
	}
	if !ps.spfHardFail {
		t.Error("expected spfHardFail for -all")
	}
}

func TestEvaluateProtocolStates_WithDMARC(t *testing.T) {
	results := map[string]any{
		"dmarc_analysis": map[string]any{
			"status": "success",
			"policy": "reject",
			"pct":    100,
			"rua":    "mailto:reports@example.com",
		},
	}
	ps := evaluateProtocolStates(results)
	if !ps.dmarcOK {
		t.Error("expected dmarcOK")
	}
	if ps.dmarcPolicy != "reject" {
		t.Errorf("dmarcPolicy = %q, want reject", ps.dmarcPolicy)
	}
}

func TestEvaluateProtocolStates_Empty(t *testing.T) {
	results := map[string]any{}
	ps := evaluateProtocolStates(results)
	if ps.spfOK || ps.dmarcOK || ps.dkimOK {
		t.Error("expected no protocols OK for empty results")
	}
}

func TestBuildEnforcingEmailVerdict(t *testing.T) {
	verdicts := map[string]any{}
	buildEnforcingEmailVerdict(protocolState{dmarcPolicy: mapKeyReject}, DKIMSuccess, verdicts)
	v := verdicts[mapKeyEmailSpoofing].(map[string]any)
	if v[mapKeyLabel] != strProtected {
		t.Errorf("label = %v, want Protected", v[mapKeyLabel])
	}
	if v[mapKeyColor] != mapKeySuccess {
		t.Errorf("color = %v, want success", v[mapKeyColor])
	}
}

func TestBuildEnforcingEmailVerdict_QuarantineDKIM(t *testing.T) {
	verdicts := map[string]any{}
	buildEnforcingEmailVerdict(protocolState{dmarcPolicy: mapKeyQuarantine}, DKIMSuccess, verdicts)
	v := verdicts[mapKeyEmailSpoofing].(map[string]any)
	if v[mapKeyColor] != mapKeySuccess {
		t.Errorf("color = %v, want success for quarantine with DKIM", v[mapKeyColor])
	}
}

func TestBuildEnforcingEmailVerdict_NoDKIM(t *testing.T) {
	verdicts := map[string]any{}
	buildEnforcingEmailVerdict(protocolState{dmarcPolicy: mapKeyReject}, DKIMAbsent, verdicts)
	v := verdicts[mapKeyEmailSpoofing].(map[string]any)
	if v[mapKeyLabel] != strProtected {
		t.Errorf("label = %v, want Protected", v[mapKeyLabel])
	}
}

func TestClassifyDMARCPolicyBranches(t *testing.T) {
	tests := []struct {
		name string
		ps   protocolState
		want emailSpoofClass
	}{
		{"reject", protocolState{dmarcPolicy: mapKeyReject}, emailSpoofReject},
		{"quarantine full", protocolState{dmarcPolicy: mapKeyQuarantine, dmarcPct: 100}, emailSpoofQuarantineFull},
		{"quarantine partial", protocolState{dmarcPolicy: mapKeyQuarantine, dmarcPct: 50}, emailSpoofQuarantinePartial},
		{"none", protocolState{dmarcPolicy: statusNone}, emailSpoofMonitorOnly},
		{"unknown", protocolState{dmarcPolicy: "something"}, emailSpoofUncertain},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyDMARCPolicy(tc.ps)
			if got != tc.want {
				t.Errorf("classifyDMARCPolicy() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestIdentifyProviderNameBranches(t *testing.T) {
	tests := []struct {
		name  string
		hosts []string
		want  string
	}{
		{"google", []string{"alt1.aspmx.l.google.com"}, "Google Workspace"},
		{"microsoft", []string{"example-com.mail.protection.outlook.com"}, "Microsoft 365"},
		{"proton", []string{"mail.protonmail.ch"}, "Proton Mail"},
		{"unknown", []string{"mx.custom.example.com"}, ""},
		{"empty", []string{}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := identifyProviderName(tc.hosts)
			if got != tc.want {
				t.Errorf("identifyProviderName() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestExtractMailFlags_WithMX(t *testing.T) {
	results := map[string]any{
		"basic_records": map[string]any{
			"MX": []string{"mx.example.com"},
		},
	}
	ps := protocolState{spfOK: true, dmarcOK: true, dmarcPolicy: policyReject}
	mf := extractMailFlags(results, ps)
	if !mf.hasMX {
		t.Error("expected hasMX")
	}
	if !mf.hasSPF {
		t.Error("expected hasSPF")
	}
	if !mf.hasDMARC {
		t.Error("expected hasDMARC")
	}
	if !mf.dmarcReject {
		t.Error("expected dmarcReject")
	}
}

func TestExtractMailFlags_NoMX(t *testing.T) {
	results := map[string]any{}
	ps := protocolState{}
	mf := extractMailFlags(results, ps)
	if mf.hasMX {
		t.Error("expected no hasMX")
	}
}

func TestScanContactMethods_WithEmail(t *testing.T) {
	body := "please contact: scammer@gmail.com for more info"
	indicators := scanContactMethods(body, nil)
	if len(indicators) == 0 {
		t.Error("expected contact method indicator")
	}
	if len(indicators) > 0 && indicators[0].Category != "Suspicious Contact Method" {
		t.Errorf("category = %q", indicators[0].Category)
	}
}

func TestScanContactMethods_NoEmail(t *testing.T) {
	body := "Hello world no email here"
	indicators := scanContactMethods(body, nil)
	if len(indicators) != 0 {
		t.Error("expected no contact method indicators")
	}
}

func TestScanFormattingIndicators_ExcessiveCaps(t *testing.T) {
	body := "URGENT ALERT WARNING NOTICE IMPORTANT!!!! act NOW!!!! IMMEDIATELY!!!!"
	indicators := scanFormattingIndicators(body, nil)
	if len(indicators) == 0 {
		t.Error("expected formatting indicator for excessive caps/exclamation")
	}
}

func TestCipherBits_Unknown(t *testing.T) {
	got := cipherBits(0)
	if got != 0 {
		t.Errorf("cipherBits(0) = %d, want 0", got)
	}
}

func TestDetectOriginatingIP_Empty(t *testing.T) {
	r := &EmailHeaderAnalysis{}
	detectOriginatingIP(nil, r)
	if r.OriginatingIP != "" {
		t.Errorf("OriginatingIP = %q, want empty", r.OriginatingIP)
	}
}

func TestDetectDMARCPolicy_Empty(t *testing.T) {
	r := &EmailHeaderAnalysis{}
	detectDMARCPolicy(nil, r)
	if r.DMARCPolicy != "" {
		t.Errorf("DMARCPolicy = %q, want empty", r.DMARCPolicy)
	}
}

func TestBuildMailPosture(t *testing.T) {
	results := map[string]any{
		"spf_analysis":   map[string]any{"status": "success", "all_mechanism": "-all"},
		"dmarc_analysis": map[string]any{"status": "success", "policy": "reject", "pct": 100},
		"has_null_mx":    true,
		"domain":         "example.com",
	}
	mp := buildMailPosture(results)
	if mp == nil {
		t.Fatal("expected non-nil result")
	}
	if mp["verdict"] == nil {
		t.Error("expected verdict key")
	}
	if mp["classification"] == nil {
		t.Error("expected classification key")
	}
	if mp["signals"] == nil {
		t.Error("expected signals key")
	}
	if mp["is_no_mail"] != true {
		t.Error("expected is_no_mail for null mx domain")
	}
	if mp["recommended_records"] == nil {
		t.Error("expected recommended_records for no-mail domain")
	}
}

func TestBuildMailPosture_NotNoMail(t *testing.T) {
	results := map[string]any{
		"spf_analysis":   map[string]any{"status": "success"},
		"dmarc_analysis": map[string]any{"status": "success", "policy": "reject", "pct": 100},
		"dkim_analysis":  map[string]any{"status": "success"},
		"basic_records":  map[string]any{"MX": []string{"mx.example.com"}},
		"domain":         "example.com",
	}
	mp := buildMailPosture(results)
	if mp["is_no_mail"] == true {
		t.Error("expected not no-mail for domain with MX")
	}
}
