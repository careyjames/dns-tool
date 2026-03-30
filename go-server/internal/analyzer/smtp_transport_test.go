package analyzer

import (
	"crypto/tls"
	"errors"
	"testing"
)

func TestExtractTLSRPTURIs(t *testing.T) {
	tests := []struct {
		name   string
		record string
		want   []string
	}{
		{"single mailto", "v=TLSRPTv1; rua=mailto:tls@example.com", []string{"mailto:tls@example.com"}},
		{"multiple uris", "v=TLSRPTv1; rua=mailto:tls@a.com,https://report.example.com/tls", []string{"mailto:tls@a.com", "https://report.example.com/tls"}},
		{"no rua", "v=TLSRPTv1;", nil},
		{"empty record", "", nil},
		{"rua with spaces", "v=TLSRPTv1; rua= mailto:a@b.com , mailto:c@d.com ", []string{"mailto:a@b.com", "mailto:c@d.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractTLSRPTURIs(tt.record)
			if len(got) != len(tt.want) {
				t.Errorf("extractTLSRPTURIs(%q) = %v, want %v", tt.record, got, tt.want)
				return
			}
			for i, v := range got {
				if v != tt.want[i] {
					t.Errorf("extractTLSRPTURIs(%q)[%d] = %q, want %q", tt.record, i, v, tt.want[i])
				}
			}
		})
	}
}

func TestComputePolicyVerdict(t *testing.T) {
	tests := []struct {
		name    string
		policy  map[string]any
		signals []string
		want    string
	}{
		{
			"enforce mta-sts",
			map[string]any{
				"mta_sts": map[string]any{"present": true, "mode": "enforce"},
				"dane":    map[string]any{"present": false},
			},
			[]string{"sig1"},
			"enforced",
		},
		{
			"dane present",
			map[string]any{
				"mta_sts": map[string]any{"present": false, "mode": "none"},
				"dane":    map[string]any{"present": true},
			},
			[]string{"sig1"},
			"enforced",
		},
		{
			"testing mode",
			map[string]any{
				"mta_sts": map[string]any{"present": true, "mode": "testing"},
				"dane":    map[string]any{"present": false},
			},
			[]string{"sig1"},
			"monitored",
		},
		{
			"signals only",
			map[string]any{
				"mta_sts": map[string]any{"present": false, "mode": "none"},
				"dane":    map[string]any{"present": false},
			},
			[]string{"provider signal"},
			"opportunistic",
		},
		{
			"no signals",
			map[string]any{
				"mta_sts": map[string]any{"present": false, "mode": "none"},
				"dane":    map[string]any{"present": false},
			},
			[]string{},
			"none",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computePolicyVerdict(tt.policy, tt.signals)
			if got != tt.want {
				t.Errorf("computePolicyVerdict() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSmtpProbeVerdictFromSummary(t *testing.T) {
	tests := []struct {
		name    string
		summary smtpSummary
		want    string
	}{
		{"all tls", smtpSummary{Reachable: 3, StartTLSSupport: 3, ValidCerts: 3}, "all_tls"},
		{"partial tls", smtpSummary{Reachable: 3, StartTLSSupport: 2, ValidCerts: 1}, "partial_tls"},
		{"no tls", smtpSummary{Reachable: 3, StartTLSSupport: 0, ValidCerts: 0}, "no_tls"},
		{"starttls but no valid certs", smtpSummary{Reachable: 2, StartTLSSupport: 2, ValidCerts: 1}, "partial_tls"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := smtpProbeVerdictFromSummary(&tt.summary)
			if got != tt.want {
				t.Errorf("smtpProbeVerdictFromSummary() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDerivePrimaryStatus(t *testing.T) {
	tests := []struct {
		name   string
		policy map[string]any
		probe  map[string]any
		want   string
	}{
		{
			"observed all_tls enforced",
			map[string]any{"verdict": "enforced"},
			map[string]any{"status": "observed", "probe_verdict": "all_tls"},
			"success",
		},
		{
			"observed all_tls no policy",
			map[string]any{"verdict": "none"},
			map[string]any{"status": "observed", "probe_verdict": "all_tls"},
			"success",
		},
		{
			"observed partial_tls",
			map[string]any{"verdict": "none"},
			map[string]any{"status": "observed", "probe_verdict": "partial_tls"},
			"warning",
		},
		{
			"observed no_tls",
			map[string]any{"verdict": "none"},
			map[string]any{"status": "observed", "probe_verdict": "no_tls"},
			"error",
		},
		{
			"not observed enforced",
			map[string]any{"verdict": "enforced"},
			map[string]any{"status": "skipped"},
			"success",
		},
		{
			"not observed monitored",
			map[string]any{"verdict": "monitored"},
			map[string]any{"status": "skipped"},
			"info",
		},
		{
			"not observed opportunistic",
			map[string]any{"verdict": "opportunistic"},
			map[string]any{"status": "skipped"},
			"inferred",
		},
		{
			"not observed none",
			map[string]any{"verdict": "none"},
			map[string]any{"status": "skipped"},
			"info",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := derivePrimaryStatus(tt.policy, tt.probe)
			if got != tt.want {
				t.Errorf("derivePrimaryStatus() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDerivePrimaryMessage(t *testing.T) {
	tests := []struct {
		name    string
		policy  map[string]any
		probe   map[string]any
		mxHosts []string
		wantSub string
	}{
		{
			"no mx",
			map[string]any{"verdict": "none", "signals": []string{}},
			map[string]any{"status": "skipped"},
			[]string{},
			"No MX records found",
		},
		{
			"enforced",
			map[string]any{"verdict": "enforced", "signals": []string{"sig1"}},
			map[string]any{"status": "skipped"},
			[]string{"mx.example.com"},
			"enforced via DNS policy",
		},
		{
			"monitored",
			map[string]any{"verdict": "monitored", "signals": []string{"sig1"}},
			map[string]any{"status": "skipped"},
			[]string{"mx.example.com"},
			"monitoring mode",
		},
		{
			"none",
			map[string]any{"verdict": "none", "signals": []string{}},
			map[string]any{"status": "skipped"},
			[]string{"mx.example.com"},
			"No transport encryption policy",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := derivePrimaryMessage(tt.policy, tt.probe, tt.mxHosts)
			if got == "" || !smtpContainsStr(got, tt.wantSub) {
				t.Errorf("derivePrimaryMessage() = %q, want substring %q", got, tt.wantSub)
			}
		})
	}
}

func smtpContainsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || smtpFindSubstring(s, sub))
}

func smtpFindSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestBuildInferenceNote(t *testing.T) {
	tests := []struct {
		name  string
		probe map[string]any
		empty bool
	}{
		{"observed", map[string]any{"status": "observed"}, true},
		{"skipped", map[string]any{"status": "skipped"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildInferenceNote(tt.probe)
			if tt.empty && got != "" {
				t.Errorf("expected empty, got %q", got)
			}
			if !tt.empty && got == "" {
				t.Error("expected non-empty inference note")
			}
		})
	}
}

func TestBuildInferenceSignals(t *testing.T) {
	tests := []struct {
		name      string
		policy    map[string]any
		telemetry map[string]any
		wantLen   int
	}{
		{
			"no signals no tlsrpt",
			map[string]any{"signals": []string{}},
			map[string]any{"tlsrpt_configured": false},
			0,
		},
		{
			"signals with tlsrpt adds signal",
			map[string]any{"signals": []string{"MTA-STS signal"}},
			map[string]any{"tlsrpt_configured": true},
			2,
		},
		{
			"signals already has TLS-RPT",
			map[string]any{"signals": []string{"TLS-RPT configured"}},
			map[string]any{"tlsrpt_configured": true},
			1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildInferenceSignals(tt.policy, tt.telemetry)
			if len(got) != tt.wantLen {
				t.Errorf("buildInferenceSignals() len = %d, want %d, got %v", len(got), tt.wantLen, got)
			}
		})
	}
}

func TestBuildTelemetrySection(t *testing.T) {
	tests := []struct {
		name           string
		ai             AnalysisInputs
		wantConfigured bool
	}{
		{
			"nil tlsrpt",
			AnalysisInputs{},
			false,
		},
		{
			"success tlsrpt",
			AnalysisInputs{TLSRPTResult: map[string]any{"status": "success", "record": "v=TLSRPTv1; rua=mailto:tls@example.com"}},
			true,
		},
		{
			"failed tlsrpt",
			AnalysisInputs{TLSRPTResult: map[string]any{"status": "error"}},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildTelemetrySection(tt.ai)
			configured, _ := got["tlsrpt_configured"].(bool)
			if configured != tt.wantConfigured {
				t.Errorf("buildTelemetrySection() tlsrpt_configured = %v, want %v", configured, tt.wantConfigured)
			}
		})
	}
}

func TestIdentifyProviderName(t *testing.T) {
	tests := []struct {
		name    string
		mxHosts []string
		want    string
	}{
		{"google", []string{"aspmx.l.google.com"}, "Google Workspace"},
		{"microsoft", []string{"mail.protection.outlook.com"}, "Microsoft 365"},
		{"protonmail", []string{"mail.protonmail.ch"}, "Proton Mail"},
		{"unknown", []string{"mx.customdomain.net"}, ""},
		{"empty", []string{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := identifyProviderName(tt.mxHosts)
			if got != tt.want {
				t.Errorf("identifyProviderName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInferFromProvider(t *testing.T) {
	tests := []struct {
		name    string
		mxHosts []string
		empty   bool
	}{
		{"google provider", []string{"aspmx.l.google.com"}, false},
		{"unknown", []string{"mx.example.com"}, true},
		{"empty", []string{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inferFromProvider(tt.mxHosts)
			if tt.empty && got != "" {
				t.Errorf("expected empty, got %q", got)
			}
			if !tt.empty && got == "" {
				t.Error("expected non-empty provider signal")
			}
		})
	}
}

func TestMarshalRemoteProbeBody(t *testing.T) {
	tests := []struct {
		name    string
		mxHosts []string
		wantNil bool
		wantErr string
	}{
		{"normal hosts", []string{"mx1.example.com", "mx2.example.com"}, false, ""},
		{"more than 5 hosts truncated", []string{"a", "b", "c", "d", "e", "f", "g"}, false, ""},
		{"empty hosts", []string{}, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, errMsg := marshalRemoteProbeBody(tt.mxHosts)
			if tt.wantNil && body != nil {
				t.Error("expected nil body")
			}
			if !tt.wantNil && body == nil {
				t.Error("expected non-nil body")
			}
			if errMsg != tt.wantErr {
				t.Errorf("marshalRemoteProbeBody() err = %q, want %q", errMsg, tt.wantErr)
			}
		})
	}
}

func TestClassifyRemoteProbeStatus(t *testing.T) {
	tests := []struct {
		name string
		code int
		want string
	}{
		{"ok", 200, ""},
		{"unauthorized", 401, "authentication failed (401)"},
		{"rate limited", 429, "rate limited (429)"},
		{"server error", 500, "HTTP 500"},
		{"not found", 404, "HTTP 404"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyRemoteProbeStatus(tt.code)
			if got != tt.want {
				t.Errorf("classifyRemoteProbeStatus(%d) = %q, want %q", tt.code, got, tt.want)
			}
		})
	}
}

func TestClassifySMTPError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"timeout", errors.New("connection timeout"), "Connection timeout"},
		{"deadline", errors.New("i/o deadline exceeded"), "Connection timeout"},
		{"refused", errors.New("connection refused"), "Connection refused"},
		{"unreachable", errors.New("network unreachable"), "Network unreachable"},
		{"dns", errors.New("no such host"), "DNS resolution failed"},
		{"other", errors.New("something else"), "something else"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifySMTPError(tt.err)
			if got != tt.want {
				t.Errorf("classifySMTPError() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTlsVersionString(t *testing.T) {
	tests := []struct {
		name    string
		version uint16
		want    string
	}{
		{"tls 1.3", tls.VersionTLS13, "TLSv1.3"},
		{"tls 1.2", tls.VersionTLS12, "TLSv1.2"},
		{"tls 1.1", tls.VersionTLS11, "TLSv1.1"},
		{"tls 1.0", tls.VersionTLS10, "TLSv1.0"},
		{"unknown", 0x0200, "TLS 0x0200"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tlsVersionString(tt.version)
			if got != tt.want {
				t.Errorf("tlsVersionString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCipherBits(t *testing.T) {
	tests := []struct {
		name  string
		suite uint16
		want  int
	}{
		{"aes 256", tls.TLS_AES_256_GCM_SHA384, 256},
		{"chacha20", tls.TLS_CHACHA20_POLY1305_SHA256, 256},
		{"ecdhe aes 128 cbc sha", tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, 128},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cipherBits(tt.suite)
			if got != tt.want {
				t.Errorf("cipherBits() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		name   string
		s      string
		maxLen int
		want   string
	}{
		{"short", "hello", 10, "hello"},
		{"exact", "hello", 5, "hello"},
		{"truncated", "hello world", 5, "hello"},
		{"empty", "", 5, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncate(tt.s, tt.maxLen)
			if got != tt.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tt.s, tt.maxLen, got, tt.want)
			}
		})
	}
}

func TestUpdateSummary(t *testing.T) {
	s := &smtpSummary{}
	srv := map[string]any{
		"reachable":           true,
		"starttls":            true,
		"tls_version":         "TLSv1.3",
		"cert_valid":          true,
		"cert_days_remaining": 10,
	}
	updateSummary(s, srv)
	if s.Reachable != 1 {
		t.Errorf("Reachable = %d, want 1", s.Reachable)
	}
	if s.StartTLSSupport != 1 {
		t.Errorf("StartTLSSupport = %d, want 1", s.StartTLSSupport)
	}
	if s.TLS13 != 1 {
		t.Errorf("TLS13 = %d, want 1", s.TLS13)
	}
	if s.ValidCerts != 1 {
		t.Errorf("ValidCerts = %d, want 1", s.ValidCerts)
	}
	if s.ExpiringSoon != 1 {
		t.Errorf("ExpiringSoon = %d, want 1", s.ExpiringSoon)
	}
}

func TestUpdateSummaryTLS12(t *testing.T) {
	s := &smtpSummary{}
	srv := map[string]any{
		"reachable":   true,
		"starttls":    true,
		"tls_version": "TLSv1.2",
		"cert_valid":  false,
	}
	updateSummary(s, srv)
	if s.TLS12 != 1 {
		t.Errorf("TLS12 = %d, want 1", s.TLS12)
	}
	if s.ExpiringSoon != 0 {
		t.Errorf("ExpiringSoon = %d, want 0", s.ExpiringSoon)
	}
}

func TestSummaryToMap(t *testing.T) {
	s := &smtpSummary{
		TotalServers:    5,
		Reachable:       4,
		StartTLSSupport: 3,
		TLS13:           2,
		TLS12:           1,
		ValidCerts:      3,
		ExpiringSoon:    0,
	}
	m := summaryToMap(s)
	if m["total_servers"] != 5 {
		t.Errorf("total_servers = %v, want 5", m["total_servers"])
	}
	if m["reachable"] != 4 {
		t.Errorf("reachable = %v, want 4", m["reachable"])
	}
}

func TestEmptyLegacySummary(t *testing.T) {
	m := emptyLegacySummary()
	if m["total_servers"] != 0 {
		t.Errorf("total_servers = %v, want 0", m["total_servers"])
	}
	if m["reachable"] != 0 {
		t.Errorf("reachable = %v, want 0", m["reachable"])
	}
}

func TestMapGetStrSafe(t *testing.T) {
	tests := []struct {
		name string
		m    map[string]any
		key  string
		want string
	}{
		{"found", map[string]any{"k": "v"}, "k", "v"},
		{"missing", map[string]any{"k": "v"}, "other", ""},
		{"nil map", nil, "k", ""},
		{"non-string", map[string]any{"k": 42}, "k", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapGetStrSafe(tt.m, tt.key)
			if got != tt.want {
				t.Errorf("mapGetStrSafe() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestToFloat64Val(t *testing.T) {
	tests := []struct {
		name string
		v    any
		want float64
	}{
		{"float64", float64(3.14), 3.14},
		{"int", int(42), 42.0},
		{"int64", int64(100), 100.0},
		{"string", "nope", 0},
		{"nil", nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toFloat64Val(tt.v)
			if got != tt.want {
				t.Errorf("toFloat64Val() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSmtpResponseComplete(t *testing.T) {
	tests := []struct {
		name string
		data string
		want bool
	}{
		{"complete", "220 mail.example.com ESMTP\r\n", true},
		{"continuation", "220-mail.example.com\r\n", false},
		{"multi complete", "250-SIZE 35882577\r\n250 8BITMIME\r\n", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := smtpResponseComplete(tt.data)
			if got != tt.want {
				t.Errorf("smtpResponseComplete(%q) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
}

func TestComputeProbeConsensus(t *testing.T) {
	tests := []struct {
		name      string
		results   []map[string]any
		wantAgree string
	}{
		{"empty", []map[string]any{}, "unknown"},
		{"no observed", []map[string]any{{"status": "skipped"}}, "no_data"},
		{"unanimous tls", []map[string]any{
			{"status": "observed", "probe_verdict": "all_tls"},
			{"status": "observed", "probe_verdict": "all_tls"},
		}, "unanimous_tls"},
		{"unanimous no tls", []map[string]any{
			{"status": "observed", "probe_verdict": "no_tls"},
			{"status": "observed", "probe_verdict": "no_tls"},
		}, "unanimous_no_tls"},
		{"split", []map[string]any{
			{"status": "observed", "probe_verdict": "all_tls"},
			{"status": "observed", "probe_verdict": "no_tls"},
		}, "split"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeProbeConsensus(tt.results)
			if got["agreement"] != tt.wantAgree {
				t.Errorf("computeProbeConsensus() agreement = %v, want %v", got["agreement"], tt.wantAgree)
			}
		})
	}
}

func TestGetIssuesList(t *testing.T) {
	tests := []struct {
		name    string
		result  map[string]any
		wantLen int
	}{
		{"has issues", map[string]any{"issues": []string{"a", "b"}}, 2},
		{"no issues key", map[string]any{}, 0},
		{"wrong type", map[string]any{"issues": "not a slice"}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getIssuesList(tt.result)
			if len(got) != tt.wantLen {
				t.Errorf("getIssuesList() len = %d, want %d", len(got), tt.wantLen)
			}
		})
	}
}
