package analyzer

import (
	"testing"
)

func TestEvaluateSPFState(t *testing.T) {
	tests := []struct {
		name             string
		spf              map[string]any
		wantOK           bool
		wantMissing      bool
		wantHardFail     bool
		wantDangerous    bool
		wantNeutral      bool
		wantLookupExceed bool
	}{
		{"nil", nil, false, true, false, false, false, false},
		{"missing status", map[string]any{"status": "missing"}, false, true, false, false, false, false},
		{"error status", map[string]any{"status": "error"}, false, true, false, false, false, false},
		{"success", map[string]any{"status": "success"}, true, false, false, false, false, false},
		{"warning", map[string]any{"status": "warning"}, true, false, false, false, false, false},
		{"hard fail", map[string]any{"status": "success", "all_mechanism": "-all"}, true, false, true, false, false, false},
		{"dangerous +all", map[string]any{"status": "success", "all_mechanism": "+all"}, true, false, false, true, false, false},
		{"neutral ?all", map[string]any{"status": "success", "all_mechanism": "?all"}, true, false, false, false, true, false},
		{"lookup exceeded", map[string]any{"status": "success", "lookup_count": float64(12)}, true, false, false, false, false, true},
		{"lookup ok", map[string]any{"status": "success", "lookup_count": float64(8)}, true, false, false, false, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ok, _, missing, hardFail, dangerous, neutral, lookupExceed, _ := evaluateSPFState(tc.spf)
			if ok != tc.wantOK {
				t.Errorf("ok = %v, want %v", ok, tc.wantOK)
			}
			if missing != tc.wantMissing {
				t.Errorf("missing = %v, want %v", missing, tc.wantMissing)
			}
			if hardFail != tc.wantHardFail {
				t.Errorf("hardFail = %v, want %v", hardFail, tc.wantHardFail)
			}
			if dangerous != tc.wantDangerous {
				t.Errorf("dangerous = %v, want %v", dangerous, tc.wantDangerous)
			}
			if neutral != tc.wantNeutral {
				t.Errorf("neutral = %v, want %v", neutral, tc.wantNeutral)
			}
			if lookupExceed != tc.wantLookupExceed {
				t.Errorf("lookupExceed = %v, want %v", lookupExceed, tc.wantLookupExceed)
			}
		})
	}
}

func TestEvaluateDMARCState(t *testing.T) {
	tests := []struct {
		name        string
		dmarc       map[string]any
		wantOK      bool
		wantMissing bool
		wantPolicy  string
		wantHasRua  bool
	}{
		{"nil", nil, false, true, "", false},
		{"missing", map[string]any{"status": "missing"}, false, true, "", false},
		{"success reject", map[string]any{"status": "success", "policy": "reject"}, true, false, "reject", false},
		{"warning none", map[string]any{"status": "warning", "policy": "none"}, true, false, "none", false},
		{"with rua", map[string]any{"status": "success", "policy": "reject", "rua": "mailto:dmarc@example.com"}, true, false, "reject", true},
		{"empty rua", map[string]any{"status": "success", "policy": "reject", "rua": ""}, true, false, "reject", false},
		{"pct 50", map[string]any{"status": "success", "policy": "quarantine", "pct": float64(50)}, true, false, "quarantine", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ok, _, missing, hasRua, policy, _ := evaluateDMARCState(tc.dmarc)
			if ok != tc.wantOK {
				t.Errorf("ok = %v, want %v", ok, tc.wantOK)
			}
			if missing != tc.wantMissing {
				t.Errorf("missing = %v, want %v", missing, tc.wantMissing)
			}
			if policy != tc.wantPolicy {
				t.Errorf("policy = %q, want %q", policy, tc.wantPolicy)
			}
			if hasRua != tc.wantHasRua {
				t.Errorf("hasRua = %v, want %v", hasRua, tc.wantHasRua)
			}
		})
	}
}

func TestEvaluateDKIMStateFunc(t *testing.T) {
	tests := []struct {
		name     string
		dkim     map[string]any
		wantOK   bool
		wantProv bool
	}{
		{"nil", nil, false, false},
		{"missing", map[string]any{"status": "missing"}, false, false},
		{"success", map[string]any{"status": "success"}, true, false},
		{"with provider", map[string]any{"status": "success", "primary_provider": "Google Workspace"}, true, true},
		{"warning", map[string]any{"status": "warning"}, true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ok, prov, _, _, _, _ := evaluateDKIMState(tc.dkim)
			if ok != tc.wantOK {
				t.Errorf("ok = %v, want %v", ok, tc.wantOK)
			}
			if prov != tc.wantProv {
				t.Errorf("provider = %v, want %v", prov, tc.wantProv)
			}
		})
	}
}

func TestEvaluateSimpleProtocolState(t *testing.T) {
	if evaluateSimpleProtocolState(nil, "status") {
		t.Error("nil should return false")
	}
	if evaluateSimpleProtocolState(map[string]any{"status": "missing"}, "status") {
		t.Error("missing should return false")
	}
	if !evaluateSimpleProtocolState(map[string]any{"status": "success"}, "status") {
		t.Error("success should return true")
	}
	if evaluateSimpleProtocolState(map[string]any{"status": "warning"}, "status") {
		t.Error("warning should return false for simple protocol")
	}
}

func TestIsMissingRecord(t *testing.T) {
	tests := []struct {
		name string
		m    map[string]any
		want bool
	}{
		{"nil", nil, true},
		{"error", map[string]any{"status": "error"}, true},
		{"missing", map[string]any{"status": "missing"}, true},
		{"n/a", map[string]any{"status": "n/a"}, true},
		{"success", map[string]any{"status": "success"}, false},
		{"warning", map[string]any{"status": "warning"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isMissingRecord(tc.m)
			if got != tc.want {
				t.Errorf("isMissingRecord() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestHasNonEmptyString(t *testing.T) {
	if hasNonEmptyString(nil, "key") {
		t.Error("nil map should return false")
	}
	if hasNonEmptyString(map[string]any{"key": ""}, "key") {
		t.Error("empty string should return false")
	}
	if !hasNonEmptyString(map[string]any{"key": "value"}, "key") {
		t.Error("non-empty string should return true")
	}
	if hasNonEmptyString(map[string]any{"key": 123}, "key") {
		t.Error("non-string should return false")
	}
	if hasNonEmptyString(map[string]any{}, "missing") {
		t.Error("missing key should return false")
	}
}

func TestExtractIntField(t *testing.T) {
	tests := []struct {
		name string
		m    map[string]any
		key  string
		want int
	}{
		{"nil map", nil, "x", 0},
		{"missing key", map[string]any{}, "x", 0},
		{"int", map[string]any{"x": 42}, "x", 42},
		{"int64", map[string]any{"x": int64(42)}, "x", 42},
		{"float64", map[string]any{"x": float64(42)}, "x", 42},
		{"float32", map[string]any{"x": float32(42)}, "x", 42},
		{"string", map[string]any{"x": "42"}, "x", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractIntField(tc.m, tc.key)
			if got != tc.want {
				t.Errorf("extractIntField() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestExtractIntFieldDefault(t *testing.T) {
	if got := extractIntFieldDefault(nil, "x", 99); got != 99 {
		t.Errorf("nil map should return default, got %d", got)
	}
	if got := extractIntFieldDefault(map[string]any{}, "x", 99); got != 99 {
		t.Errorf("missing key should return default, got %d", got)
	}
	if got := extractIntFieldDefault(map[string]any{"x": 42}, "x", 99); got != 42 {
		t.Errorf("present key should return value, got %d", got)
	}
	if got := extractIntFieldDefault(map[string]any{"x": "bad"}, "x", 99); got != 99 {
		t.Errorf("non-numeric should return default, got %d", got)
	}
}

func TestEvaluateDKIMIssues(t *testing.T) {
	wk, tpo := evaluateDKIMIssues(nil)
	if wk || tpo {
		t.Error("nil should return false, false")
	}

	wk, tpo = evaluateDKIMIssues(map[string]any{"weak_keys": true})
	if !wk {
		t.Error("expected weak_keys true")
	}

	wk, tpo = evaluateDKIMIssues(map[string]any{"third_party_only": true})
	if !tpo {
		t.Error("expected third_party_only true")
	}

	wk, tpo = evaluateDKIMIssues(map[string]any{
		"issues": []any{"Key uses 1024-bit RSA", "Third-party signing only"},
	})
	if !wk {
		t.Error("expected weak keys from issues")
	}
	if !tpo {
		t.Error("expected third party from issues")
	}
}

func TestScanDKIMIssueStrings(t *testing.T) {
	wk, tpo := scanDKIMIssueStrings([]any{"weak key detected", "third-party only"})
	if !wk || !tpo {
		t.Error("expected both true")
	}

	wk, tpo = scanDKIMIssueStrings([]any{123, nil})
	if wk || tpo {
		t.Error("non-string issues should be skipped")
	}
}

func TestDetectProbableNoMail(t *testing.T) {
	if detectProbableNoMail(nil) {
		t.Error("nil should return false")
	}
	if detectProbableNoMail(map[string]any{}) {
		t.Error("no basic_records should return false")
	}
	if !detectProbableNoMail(map[string]any{"basic_records": map[string]any{}}) {
		t.Error("no MX should return true")
	}
	if detectProbableNoMail(map[string]any{"basic_records": map[string]any{"MX": []string{"mx.example.com"}}}) {
		t.Error("with MX should return false")
	}
	if detectProbableNoMail(map[string]any{"basic_records": map[string]any{}, "mx_records": []any{"mx.example.com"}}) {
		t.Error("with mx_records should return false")
	}
}

func TestEvaluateDANEState(t *testing.T) {
	ps := &protocolState{}
	evaluateDANEState(nil, ps)
	if ps.daneOK {
		t.Error("nil should not set daneOK")
	}

	ps = &protocolState{}
	evaluateDANEState(map[string]any{"status": "missing"}, ps)
	if ps.daneOK {
		t.Error("missing should not set daneOK")
	}

	ps = &protocolState{}
	evaluateDANEState(map[string]any{"has_dane": true}, ps)
	if !ps.daneOK {
		t.Error("has_dane true should set daneOK")
	}

	ps = &protocolState{}
	evaluateDANEState(map[string]any{"dane_deployable": false}, ps)
	if !ps.daneProviderLimited {
		t.Error("dane_deployable false should set daneProviderLimited")
	}
}

func TestEvaluateDNSSECState(t *testing.T) {
	ps := &protocolState{}
	evaluateDNSSECState(nil, ps)
	if ps.dnssecOK || ps.dnssecBroken {
		t.Error("nil should not set anything")
	}

	ps = &protocolState{}
	evaluateDNSSECState(map[string]any{"status": "success"}, ps)
	if !ps.dnssecOK {
		t.Error("success should set dnssecOK")
	}

	ps = &protocolState{}
	evaluateDNSSECState(map[string]any{"status": "bogus"}, ps)
	if ps.dnssecOK || ps.dnssecBroken {
		t.Error("bogus status should not set OK or broken (caught by isMissingRecord for error)")
	}

	ps = &protocolState{}
	evaluateDNSSECState(map[string]any{"status": "success", "algorithm_observation": map[string]any{"strength": "strong"}}, ps)
	if ps.dnssecAlgoStrength != "strong" {
		t.Errorf("algo strength = %q, want strong", ps.dnssecAlgoStrength)
	}
}

func TestClassifySPF(t *testing.T) {
	acc := &postureAccumulator{issues: []string{}, recommendations: []string{}, configured: []string{}, absent: []string{}, monitoring: []string{}}
	classifySPF(protocolState{spfMissing: true}, acc)
	if len(acc.absent) != 1 || acc.absent[0] != "SPF" {
		t.Error("missing SPF should add to absent")
	}
	if len(acc.issues) != 1 {
		t.Error("missing SPF should add an issue")
	}

	acc = &postureAccumulator{issues: []string{}, recommendations: []string{}, configured: []string{}, absent: []string{}, monitoring: []string{}}
	classifySPF(protocolState{spfDangerous: true, spfOK: true}, acc)
	if len(acc.issues) == 0 {
		t.Error("dangerous SPF should add an issue")
	}

	acc = &postureAccumulator{issues: []string{}, recommendations: []string{}, configured: []string{}, absent: []string{}, monitoring: []string{}}
	classifySPF(protocolState{spfOK: true, spfHardFail: true}, acc)
	if len(acc.configured) != 1 || acc.configured[0] != "SPF (hard fail)" {
		t.Errorf("hard fail should be configured as 'SPF (hard fail)', got %v", acc.configured)
	}

	acc = &postureAccumulator{issues: []string{}, recommendations: []string{}, configured: []string{}, absent: []string{}, monitoring: []string{}}
	classifySPF(protocolState{spfOK: true, spfWarning: true}, acc)
	if len(acc.monitoring) == 0 {
		t.Error("soft fail should add monitoring note")
	}
}

func TestClassifyDMARC(t *testing.T) {
	acc := &postureAccumulator{issues: []string{}, recommendations: []string{}, configured: []string{}, absent: []string{}, monitoring: []string{}}
	classifyDMARC(protocolState{dmarcMissing: true}, acc)
	if len(acc.absent) != 1 || acc.absent[0] != "DMARC" {
		t.Error("missing DMARC should add to absent")
	}

	acc = &postureAccumulator{issues: []string{}, recommendations: []string{}, configured: []string{}, absent: []string{}, monitoring: []string{}}
	classifyDMARC(protocolState{dmarcOK: true, dmarcPolicy: "reject"}, acc)
	if len(acc.configured) != 1 || acc.configured[0] != "DMARC (reject)" {
		t.Errorf("reject should be configured as 'DMARC (reject)', got %v", acc.configured)
	}

	acc = &postureAccumulator{issues: []string{}, recommendations: []string{}, configured: []string{}, absent: []string{}, monitoring: []string{}}
	classifyDMARC(protocolState{dmarcOK: true, dmarcPolicy: "none", dmarcHasRua: true}, acc)
	if len(acc.monitoring) == 0 {
		t.Error("none with rua should add monitoring note")
	}

	acc = &postureAccumulator{issues: []string{}, recommendations: []string{}, configured: []string{}, absent: []string{}, monitoring: []string{}}
	classifyDMARC(protocolState{dmarcOK: true, dmarcPolicy: "none", dmarcHasRua: false}, acc)
	if len(acc.issues) == 0 {
		t.Error("none without rua should add issue")
	}
}

func TestClassifyDKIMPosture(t *testing.T) {
	tests := []struct {
		name       string
		ds         DKIMState
		provider   string
		wantConf   bool
		wantAbsent bool
	}{
		{"success", DKIMSuccess, "", true, false},
		{"provider inferred", DKIMProviderInferred, "Google", true, false},
		{"absent", DKIMAbsent, "", false, true},
		{"inconclusive", DKIMInconclusive, "", false, true},
		{"weak keys", DKIMWeakKeysOnly, "", true, false},
		{"third party only", DKIMThirdPartyOnly, "", true, false},
		{"no mail", DKIMNoMailDomain, "", true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			acc := &postureAccumulator{issues: []string{}, recommendations: []string{}, configured: []string{}, absent: []string{}, monitoring: []string{}}
			classifyDKIMPosture(tc.ds, tc.provider, acc)
			if tc.wantConf && len(acc.configured) == 0 {
				t.Error("expected configured entry")
			}
			if tc.wantAbsent && len(acc.absent) == 0 {
				t.Error("expected absent entry")
			}
		})
	}
}

func TestClassifyPresence(t *testing.T) {
	acc := &postureAccumulator{configured: []string{}, absent: []string{}}
	classifyPresence(true, "MTA-STS", acc)
	if len(acc.configured) != 1 || acc.configured[0] != "MTA-STS" {
		t.Error("true should add to configured")
	}

	acc = &postureAccumulator{configured: []string{}, absent: []string{}}
	classifyPresence(false, "MTA-STS", acc)
	if len(acc.absent) != 1 || acc.absent[0] != "MTA-STS" {
		t.Error("false should add to absent")
	}
}

func TestClassifyDANE(t *testing.T) {
	acc := &postureAccumulator{configured: []string{}, absent: []string{}, providerLimited: []string{}}
	classifyDANE(protocolState{daneOK: true}, acc)
	if len(acc.configured) != 1 {
		t.Error("daneOK should add to configured")
	}

	acc = &postureAccumulator{configured: []string{}, absent: []string{}, providerLimited: []string{}}
	classifyDANE(protocolState{daneProviderLimited: true}, acc)
	if len(acc.providerLimited) != 1 {
		t.Error("daneProviderLimited should add to providerLimited")
	}

	acc = &postureAccumulator{configured: []string{}, absent: []string{}, providerLimited: []string{}}
	classifyDANE(protocolState{}, acc)
	if len(acc.absent) != 1 {
		t.Error("no dane should add to absent")
	}
}

func TestClassifyDNSSEC(t *testing.T) {
	acc := &postureAccumulator{issues: []string{}, recommendations: []string{}, configured: []string{}, absent: []string{}}
	classifyDNSSEC(protocolState{dnssecOK: true}, acc)
	if len(acc.configured) != 1 || acc.configured[0] != "DNSSEC" {
		t.Error("dnssecOK should add DNSSEC to configured")
	}

	acc = &postureAccumulator{issues: []string{}, recommendations: []string{}, configured: []string{}, absent: []string{}}
	classifyDNSSEC(protocolState{dnssecBroken: true}, acc)
	if len(acc.issues) == 0 {
		t.Error("broken DNSSEC should add issue")
	}

	acc = &postureAccumulator{issues: []string{}, recommendations: []string{}, configured: []string{}, absent: []string{}}
	classifyDNSSEC(protocolState{}, acc)
	if len(acc.absent) != 1 || acc.absent[0] != "DNSSEC" {
		t.Error("no DNSSEC should add to absent")
	}
}

func TestClassifyDanglingDNS(t *testing.T) {
	acc := &postureAccumulator{issues: []string{}, recommendations: []string{}}
	classifyDanglingDNS(map[string]any{}, acc)
	if len(acc.issues) != 0 {
		t.Error("no dangling_dns should not add issues")
	}

	acc = &postureAccumulator{issues: []string{}, recommendations: []string{}}
	classifyDanglingDNS(map[string]any{"dangling_dns": map[string]any{"dangling_count": 3}}, acc)
	if len(acc.issues) != 1 {
		t.Error("dangling count > 0 should add issue")
	}

	acc = &postureAccumulator{issues: []string{}, recommendations: []string{}}
	classifyDanglingDNS(map[string]any{"dangling_dns": map[string]any{"dangling_count": 0}}, acc)
	if len(acc.issues) != 0 {
		t.Error("dangling count 0 should not add issue")
	}
}

func TestExtractExternalDomainMaps(t *testing.T) {
	if extractExternalDomainMaps(nil) != nil {
		t.Error("nil should return nil")
	}

	typed := []map[string]any{{"domain": "a.com"}}
	got := extractExternalDomainMaps(typed)
	if len(got) != 1 {
		t.Error("typed slice should work")
	}

	untyped := []any{map[string]any{"domain": "b.com"}}
	got = extractExternalDomainMaps(untyped)
	if len(got) != 1 {
		t.Error("untyped slice should work")
	}

	got = extractExternalDomainMaps("invalid")
	if got != nil {
		t.Error("invalid type should return nil")
	}
}

func TestMatchesFreeCertAuthority(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"Let's Encrypt", true},
		{"ZeroSSL", true},
		{"let's encrypt authority", true},
		{"DigiCert", false},
		{"Comodo", false},
		{"Amazon CloudFront", true},
		{"R3", true},
		{"", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := matchesFreeCertAuthority(tc.name)
			if got != tc.want {
				t.Errorf("matchesFreeCertAuthority(%q) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

func TestEvaluateDeliberateMonitoring(t *testing.T) {
	ok, _ := evaluateDeliberateMonitoring(protocolState{}, 0)
	if ok {
		t.Error("should be false with no DMARC")
	}

	ok, note := evaluateDeliberateMonitoring(protocolState{dmarcOK: true, dmarcHasRua: true, spfOK: true, dmarcPolicy: "none"}, 3)
	if !ok {
		t.Error("should be true for monitoring phase")
	}
	if note == "" {
		t.Error("should have a note")
	}

	ok, _ = evaluateDeliberateMonitoring(protocolState{dmarcOK: true, dmarcHasRua: true, spfOK: true, dmarcPolicy: "quarantine", dmarcPct: 50}, 3)
	if !ok {
		t.Error("should be true for partial quarantine")
	}

	ok, _ = evaluateDeliberateMonitoring(protocolState{dmarcOK: true, dmarcHasRua: true, spfOK: true, dmarcPolicy: "quarantine", dmarcPct: 100}, 3)
	if !ok {
		t.Error("should be true for full quarantine")
	}

	ok, _ = evaluateDeliberateMonitoring(protocolState{dmarcOK: true, dmarcHasRua: true, spfOK: true, dmarcPolicy: "reject"}, 3)
	if ok {
		t.Error("reject should return false")
	}
}

func TestComputeInternalScore(t *testing.T) {
	score := computeInternalScore(protocolState{spfMissing: true, dmarcMissing: true}, DKIMAbsent)
	if score != 0 {
		t.Errorf("all missing should score 0, got %d", score)
	}

	score = computeInternalScore(protocolState{
		spfOK: true, spfHardFail: true,
		dmarcOK: true, dmarcPolicy: "reject",
		dnssecOK: true, daneOK: true, mtaStsOK: true, tlsrptOK: true, caaOK: true, bimiOK: true,
	}, DKIMSuccess)
	if score > 100 {
		t.Errorf("score should not exceed 100, got %d", score)
	}
}

func TestComputeSPFScore(t *testing.T) {
	if computeSPFScore(protocolState{spfMissing: true}) != 0 {
		t.Error("missing should be 0")
	}
	if computeSPFScore(protocolState{spfDangerous: true}) != 5 {
		t.Error("dangerous should be 5")
	}
	if computeSPFScore(protocolState{spfHardFail: true}) != 20 {
		t.Error("hard fail should be 20")
	}
	if computeSPFScore(protocolState{spfOK: true}) != 15 {
		t.Error("ok should be 15")
	}
}

func TestComputeDMARCScore(t *testing.T) {
	if computeDMARCScore(protocolState{dmarcMissing: true}) != 0 {
		t.Error("missing should be 0")
	}
	if computeDMARCScore(protocolState{dmarcPolicy: "reject"}) != 30 {
		t.Error("reject should be 30")
	}
	if computeDMARCScore(protocolState{dmarcPolicy: "quarantine", dmarcPct: 100}) != 25 {
		t.Error("quarantine 100% should be 25")
	}
	if computeDMARCScore(protocolState{dmarcPolicy: "quarantine", dmarcPct: 50}) != 20 {
		t.Error("quarantine partial should be 20")
	}
	if computeDMARCScore(protocolState{dmarcPolicy: "none", dmarcHasRua: true}) != 10 {
		t.Error("none with rua should be 10")
	}
	if computeDMARCScore(protocolState{dmarcPolicy: "none"}) != 5 {
		t.Error("none without rua should be 5")
	}
}

func TestComputeDKIMScore(t *testing.T) {
	if computeDKIMScore(DKIMAbsent) != 0 {
		t.Error("absent should be 0")
	}
	if computeDKIMScore(DKIMSuccess) != 15 {
		t.Error("success should be 15")
	}
	if computeDKIMScore(DKIMProviderInferred) != 12 {
		t.Error("provider inferred should be 12")
	}
	if computeDKIMScore(DKIMThirdPartyOnly) != 8 {
		t.Error("third party should be 8")
	}
	if computeDKIMScore(DKIMWeakKeysOnly) != 5 {
		t.Error("weak keys should be 5")
	}
	if computeDKIMScore(DKIMNoMailDomain) != 15 {
		t.Error("no mail should be 15")
	}
}

func TestComputeAuxScore(t *testing.T) {
	score := computeAuxScore(protocolState{dnssecOK: true, daneOK: true, mtaStsOK: true, tlsrptOK: true, caaOK: true, bimiOK: true})
	if score != 35 {
		t.Errorf("all aux should be 35, got %d", score)
	}
	score = computeAuxScore(protocolState{})
	if score != 0 {
		t.Errorf("no aux should be 0, got %d", score)
	}
}

func TestClassifyGrade_DNSSECBroken(t *testing.T) {
	ps := protocolState{dnssecBroken: true}
	gi := gradeInput{}
	state, _, color, _ := classifyGrade(ps, gi)
	if state != riskCritical {
		t.Errorf("state = %q, want %q", state, riskCritical)
	}
	if color != "danger" {
		t.Errorf("color = %q, want danger", color)
	}
}

func TestClassifyMailGrade_NoSPFNoDMARC(t *testing.T) {
	state, _, _, _ := classifyMailGrade(protocolState{}, gradeInput{})
	if state != riskCritical {
		t.Errorf("state = %q, want %q", state, riskCritical)
	}
}

func TestClassifyMailGrade_SPFOnly(t *testing.T) {
	state, _, _, _ := classifyMailGrade(protocolState{}, gradeInput{hasSPF: true})
	if state != riskHigh {
		t.Errorf("state = %q, want %q", state, riskHigh)
	}
}

func TestClassifyNoMailGrade(t *testing.T) {
	state, _, _, _ := classifyNoMailGrade(protocolState{}, gradeInput{hasSPF: true, hasDMARC: true, dmarcStrict: true, dmarcFullEnforcing: true})
	if state != riskLow {
		t.Errorf("state = %q, want %q", state, riskLow)
	}

	state, _, _, _ = classifyNoMailGrade(protocolState{}, gradeInput{hasSPF: true, hasDMARC: true})
	if state != riskMedium {
		t.Errorf("state = %q, want %q", state, riskMedium)
	}

	state, _, _, _ = classifyNoMailGrade(protocolState{}, gradeInput{hasSPF: true})
	if state != riskHigh {
		t.Errorf("state = %q, want %q", state, riskHigh)
	}

	state, _, _, _ = classifyNoMailGrade(protocolState{}, gradeInput{})
	if state != riskCritical {
		t.Errorf("state = %q, want %q", state, riskCritical)
	}
}

func TestClassifyRegistryGrade(t *testing.T) {
	state, _, _, _ := classifyRegistryGrade(protocolState{dnssecOK: true}, gradeInput{})
	if state != riskLow {
		t.Errorf("state = %q, want %q", state, riskLow)
	}
	state, _, _, _ = classifyRegistryGrade(protocolState{}, gradeInput{})
	if state != riskHigh {
		t.Errorf("state = %q, want %q", state, riskHigh)
	}
}

func TestBuildDescriptiveMessage(t *testing.T) {
	msg := buildDescriptiveMessage(protocolState{}, []string{"SPF", "DMARC"}, []string{"DANE"}, []string{"note"})
	if msg == "" {
		t.Error("expected non-empty message")
	}

	msg = buildDescriptiveMessage(protocolState{}, nil, nil, nil)
	if msg != "Email security posture evaluated" {
		t.Errorf("empty should return default, got %q", msg)
	}
}

func TestClassifyEmailSpoofability(t *testing.T) {
	tests := []struct {
		name     string
		ps       protocolState
		hasSPF   bool
		hasDMARC bool
		want     emailSpoofClass
	}{
		{"no mail", protocolState{isNoMailDomain: true}, false, false, emailSpoofNoMail},
		{"unprotected", protocolState{}, false, false, emailSpoofUnprotected},
		{"reject", protocolState{dmarcPolicy: "reject"}, true, true, emailSpoofReject},
		{"quarantine full", protocolState{dmarcPolicy: "quarantine", dmarcPct: 100}, true, true, emailSpoofQuarantineFull},
		{"quarantine partial", protocolState{dmarcPolicy: "quarantine", dmarcPct: 50}, true, true, emailSpoofQuarantinePartial},
		{"monitor only", protocolState{dmarcPolicy: "none"}, true, true, emailSpoofMonitorOnly},
		{"spf only", protocolState{}, true, false, emailSpoofSPFOnly},
		{"dmarc only", protocolState{}, false, true, emailSpoofDMARCOnly},
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

func TestPostureBuildEmailAnswerBasic(t *testing.T) {
	got := buildEmailAnswer(protocolState{dmarcPolicy: "reject"}, true, true)
	if got == "" {
		t.Error("should return non-empty answer")
	}

	got = buildEmailAnswer(protocolState{}, false, false)
	if got == "" {
		t.Error("should return non-empty answer for unprotected")
	}
}

func TestPostureBuildEmailAnswerStructuredBasic(t *testing.T) {
	got := buildEmailAnswerStructured(protocolState{dmarcPolicy: "reject"}, true, true)
	if got["answer"] != "No" {
		t.Errorf("answer = %q, want No", got["answer"])
	}
	if got["color"] != "success" {
		t.Errorf("color = %q, want success", got["color"])
	}
}

func TestComputeMailVerdict(t *testing.T) {
	tests := []struct {
		name      string
		mf        mailFlags
		wantVerd  string
		wantBadge string
	}{
		{"null mx", mailFlags{hasNullMX: true}, "no_mail", "No Mail Observed"},
		{"protected", mailFlags{hasSPF: true, hasDMARC: true, hasDKIM: true, dmarcReject: true}, "protected", "Strongly Protected"},
		{"partial", mailFlags{hasSPF: true, hasDMARC: true, hasDKIM: true}, "partial", "Moderately Protected"},
		{"minimal", mailFlags{hasSPF: true}, "minimal", "Limited Protection"},
		{"unprotected", mailFlags{}, "unprotected", "Unprotected"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			verdict, badge := computeMailVerdict(tc.mf)
			if verdict != tc.wantVerd {
				t.Errorf("verdict = %q, want %q", verdict, tc.wantVerd)
			}
			if badge != tc.wantBadge {
				t.Errorf("badge = %q, want %q", badge, tc.wantBadge)
			}
		})
	}
}

func TestBuildNoMailSignals(t *testing.T) {
	mf := mailFlags{hasNullMX: true, spfDenyAll: true, dmarcReject: true}
	signals, count := buildNoMailSignals(mf)
	if count != 3 {
		t.Errorf("count = %d, want 3", count)
	}
	if signals == nil {
		t.Fatal("signals should not be nil")
	}

	mf = mailFlags{}
	_, count = buildNoMailSignals(mf)
	if count != 0 {
		t.Errorf("count = %d, want 0", count)
	}
}

func TestBuildMissingSteps(t *testing.T) {
	steps := buildMissingSteps(mailFlags{})
	if len(steps) != 3 {
		t.Errorf("all missing should return 3 steps, got %d", len(steps))
	}

	steps = buildMissingSteps(mailFlags{hasSPF: true, hasDMARC: true, hasDKIM: true})
	if len(steps) != 0 {
		t.Errorf("all present should return 0 steps, got %d", len(steps))
	}
}

func TestClassifyMailPosture(t *testing.T) {
	mc := classifyMailPosture(mailFlags{hasNullMX: true, spfDenyAll: true, dmarcReject: true}, 3, "example.com", protocolState{})
	if mc.classification != "no_mail_verified" {
		t.Errorf("classification = %q", mc.classification)
	}
	if !mc.isNoMail {
		t.Error("should be no-mail")
	}

	mc = classifyMailPosture(mailFlags{hasNullMX: true}, 1, "example.com", protocolState{})
	if mc.classification != "no_mail_partial" {
		t.Errorf("classification = %q", mc.classification)
	}

	mc = classifyMailPosture(mailFlags{spfDenyAll: true}, 1, "example.com", protocolState{})
	if mc.classification != "no_mail_intent" {
		t.Errorf("classification = %q", mc.classification)
	}

	mc = classifyMailPosture(mailFlags{hasSPF: true, hasDMARC: true, hasDKIM: true, dmarcReject: true}, 0, "example.com", protocolState{})
	if mc.classification != "protected" {
		t.Errorf("classification = %q", mc.classification)
	}

	mc = classifyMailPosture(mailFlags{hasSPF: true, hasDMARC: true, hasDKIM: true}, 0, "example.com", protocolState{})
	if mc.classification != "partial" {
		t.Errorf("classification = %q", mc.classification)
	}

	mc = classifyMailPosture(mailFlags{hasSPF: true}, 0, "example.com", protocolState{})
	if mc.classification != "minimal" {
		t.Errorf("classification = %q", mc.classification)
	}

	mc = classifyMailPosture(mailFlags{}, 0, "example.com", protocolState{})
	if mc.classification != "unprotected" {
		t.Errorf("classification = %q", mc.classification)
	}
}

func TestBuildNoMailRecommendedRecords(t *testing.T) {
	records := buildNoMailRecommendedRecords(mailFlags{}, "example.com")
	if len(records) != 3 {
		t.Errorf("expected 3 records, got %d", len(records))
	}

	records = buildNoMailRecommendedRecords(mailFlags{hasNullMX: true, spfDenyAll: true, dmarcReject: true}, "example.com")
	if len(records) != 0 {
		t.Errorf("expected 0 records, got %d", len(records))
	}
}

func TestBuildNoMailStructuredRecords(t *testing.T) {
	records := buildNoMailStructuredRecords(mailFlags{}, "example.com")
	if len(records) != 3 {
		t.Errorf("expected 3 records, got %d", len(records))
	}

	records = buildNoMailStructuredRecords(mailFlags{hasNullMX: true, spfDenyAll: true, dmarcReject: true}, "example.com")
	if len(records) != 0 {
		t.Errorf("expected 0 records, got %d", len(records))
	}
}

func TestGetVerdict(t *testing.T) {
	got := getVerdict(map[string]any{"spf_analysis": map[string]any{"status": "success"}}, "spf_analysis")
	if got != "success" {
		t.Errorf("got %q, want success", got)
	}

	got = getVerdict(map[string]any{}, "spf_analysis")
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}

	got = getVerdict(nil, "spf_analysis")
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestPostureGetNumericValueBasic(t *testing.T) {
	if getNumericValue(map[string]any{"x": float64(5)}, "x") != 5 {
		t.Error("float64")
	}
	if getNumericValue(map[string]any{"x": 5}, "x") != 5 {
		t.Error("int")
	}
	if getNumericValue(map[string]any{"x": int64(5)}, "x") != 5 {
		t.Error("int64")
	}
	if getNumericValue(map[string]any{}, "x") != 0 {
		t.Error("missing key")
	}
	if getNumericValue(map[string]any{"x": "bad"}, "x") != 0 {
		t.Error("string should return 0")
	}
}

func TestEvaluateProtocolStates(t *testing.T) {
	results := map[string]any{
		"spf_analysis":     map[string]any{"status": "success", "all_mechanism": "-all"},
		"dmarc_analysis":   map[string]any{"status": "success", "policy": "reject", "rua": "mailto:x@y.com"},
		"dkim_analysis":    map[string]any{"status": "success", "primary_provider": "Google Workspace"},
		"mta_sts_analysis": map[string]any{"status": "success"},
		"tlsrpt_analysis":  map[string]any{"status": "success"},
		"bimi_analysis":    map[string]any{"status": "success"},
		"caa_analysis":     map[string]any{"status": "success"},
		"dnssec_analysis":  map[string]any{"status": "success"},
		"dane_analysis":    map[string]any{"has_dane": true},
	}
	ps := evaluateProtocolStates(results)
	if !ps.spfOK {
		t.Error("spfOK should be true")
	}
	if !ps.spfHardFail {
		t.Error("spfHardFail should be true")
	}
	if !ps.dmarcOK {
		t.Error("dmarcOK should be true")
	}
	if ps.dmarcPolicy != "reject" {
		t.Errorf("dmarcPolicy = %q", ps.dmarcPolicy)
	}
	if !ps.dkimOK {
		t.Error("dkimOK should be true")
	}
	if !ps.mtaStsOK {
		t.Error("mtaStsOK should be true")
	}
	if !ps.tlsrptOK {
		t.Error("tlsrptOK should be true")
	}
	if !ps.bimiOK {
		t.Error("bimiOK should be true")
	}
	if !ps.caaOK {
		t.Error("caaOK should be true")
	}
	if !ps.dnssecOK {
		t.Error("dnssecOK should be true")
	}
	if !ps.daneOK {
		t.Error("daneOK should be true")
	}
}

func TestEvaluateProtocolStates_NoMail(t *testing.T) {
	results := map[string]any{
		"has_null_mx": true,
	}
	ps := evaluateProtocolStates(results)
	if !ps.isNoMailDomain {
		t.Error("should be no-mail domain")
	}

	results = map[string]any{
		"is_no_mail_domain": true,
	}
	ps = evaluateProtocolStates(results)
	if !ps.isNoMailDomain {
		t.Error("should be no-mail domain via is_no_mail_domain")
	}
}

func TestEvaluateProtocolStates_ProbableNoMail(t *testing.T) {
	results := map[string]any{
		"basic_records": map[string]any{},
	}
	ps := evaluateProtocolStates(results)
	if !ps.probableNoMail {
		t.Error("no MX should be probable no-mail")
	}
}
