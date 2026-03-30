// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
	"context"
	"testing"
	"time"

	"dnstool/go-server/internal/telemetry"
)

func newMockAnalyzer() *Analyzer {
	return &Analyzer{
		DNS:           NewMockDNSClient(),
		HTTP:          NewMockHTTPClient(),
		SlowHTTP:      NewMockHTTPClient(),
		RDAPHTTP:      NewMockHTTPClient(),
		IANARDAPMap:   make(map[string][]string),
		Telemetry:     telemetry.NewRegistry(),
		RDAPCache:     telemetry.NewTTLCache[map[string]any]("rdap_test", 100, 1*time.Hour),
		ctCache:       make(map[string]ctCacheEntry),
		ctCacheTTL:    1 * time.Hour,
		maxConcurrent: 5,
		semaphore:     make(chan struct{}, 5),
		SMTPProbeMode: "skip",
	}
}

func TestAnalyzeSPF_WithMock_ValidRecord(t *testing.T) {
	a := newMockAnalyzer()
	mock := a.DNS.(*MockDNSClient)
	mock.AddResponse("TXT", "example.com", []string{
		"v=spf1 include:_spf.google.com ~all",
	})

	ctx := context.Background()
	result := a.AnalyzeSPF(ctx, "example.com")

	if result["status"] == "missing" {
		t.Error("expected SPF status to not be 'missing'")
	}
	validRecords := result["valid_records"].([]string)
	if len(validRecords) == 0 {
		t.Error("expected valid_records to contain at least one record")
	}
	includes := result["includes"].([]string)
	if len(includes) == 0 {
		t.Error("expected includes to contain _spf.google.com")
	}
	if result["all_mechanism"] != "~all" {
		t.Errorf("expected all_mechanism ~all, got %v", result["all_mechanism"])
	}
}

func TestAnalyzeSPF_WithMock_MissingRecord(t *testing.T) {
	a := newMockAnalyzer()

	ctx := context.Background()
	result := a.AnalyzeSPF(ctx, "nodomain.example")

	if result["status"] != "missing" {
		t.Errorf("expected status 'missing', got %v", result["status"])
	}
}

func TestAnalyzeSPF_WithMock_HardFail(t *testing.T) {
	a := newMockAnalyzer()
	mock := a.DNS.(*MockDNSClient)
	mock.AddResponse("TXT", "secure.example.com", []string{
		"v=spf1 ip4:192.0.2.0/24 -all",
	})

	ctx := context.Background()
	result := a.AnalyzeSPF(ctx, "secure.example.com")

	if result["all_mechanism"] != "-all" {
		t.Errorf("expected all_mechanism '-all', got %v", result["all_mechanism"])
	}
}

func TestAnalyzeSPF_WithMock_NoMailIntent(t *testing.T) {
	a := newMockAnalyzer()
	mock := a.DNS.(*MockDNSClient)
	mock.AddResponse("TXT", "nomail.example.com", []string{
		"v=spf1 -all",
	})

	ctx := context.Background()
	result := a.AnalyzeSPF(ctx, "nomail.example.com")

	if result["no_mail_intent"] != true {
		t.Errorf("expected no_mail_intent=true, got %v", result["no_mail_intent"])
	}
}

func TestAnalyzeDMARC_WithMock_ValidReject(t *testing.T) {
	a := newMockAnalyzer()
	mock := a.DNS.(*MockDNSClient)
	mock.AddResponse("TXT", "_dmarc.example.com", []string{
		"v=DMARC1; p=reject; rua=mailto:dmarc@example.com; ruf=mailto:dmarc-ruf@example.com; pct=100",
	})

	ctx := context.Background()
	result := a.AnalyzeDMARC(ctx, "example.com")

	if result["status"] == "missing" {
		t.Error("expected DMARC status to not be 'missing'")
	}
	if result["policy"] != "reject" {
		t.Errorf("expected policy 'reject', got %v", result["policy"])
	}
	if result["pct"] != 100 {
		t.Errorf("expected pct 100, got %v", result["pct"])
	}
	if result["rua"] == nil {
		t.Error("expected rua to be set")
	}
}

func TestAnalyzeDMARC_WithMock_MissingRecord(t *testing.T) {
	a := newMockAnalyzer()

	ctx := context.Background()
	result := a.AnalyzeDMARC(ctx, "nodmarc.example.com")

	if result["status"] != "missing" {
		t.Errorf("expected status 'missing', got %v", result["status"])
	}
}

func TestAnalyzeDMARC_WithMock_Quarantine(t *testing.T) {
	a := newMockAnalyzer()
	mock := a.DNS.(*MockDNSClient)
	mock.AddResponse("TXT", "_dmarc.example.com", []string{
		"v=DMARC1; p=quarantine; aspf=s; adkim=s",
	})

	ctx := context.Background()
	result := a.AnalyzeDMARC(ctx, "example.com")

	if result["policy"] != "quarantine" {
		t.Errorf("expected policy 'quarantine', got %v", result["policy"])
	}
	if result["aspf"] != "strict" {
		t.Errorf("expected aspf 'strict', got %v", result["aspf"])
	}
	if result["adkim"] != "strict" {
		t.Errorf("expected adkim 'strict', got %v", result["adkim"])
	}
}

func TestAnalyzeDKIM_WithMock_GoogleSelector(t *testing.T) {
	a := newMockAnalyzer()
	mock := a.DNS.(*MockDNSClient)

	mock.AddResponse("MX", "example.com", []string{
		"10 aspmx.l.google.com.",
	})
	mock.AddResponse("TXT", "example.com", []string{
		"v=spf1 include:_spf.google.com ~all",
	})
	mock.AddResponse("TXT", "google._domainkey.example.com", []string{
		"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890",
	})
	mock.AddResponse("NS", "_domainkey.example.com", []string{})

	ctx := context.Background()
	result := a.AnalyzeDKIM(ctx, "example.com", []string{"10 aspmx.l.google.com."}, nil)

	if result["status"] == nil {
		t.Error("expected DKIM result to have a status")
	}
	selectors, ok := result["selectors"].(map[string]any)
	if !ok {
		t.Fatalf("expected selectors to be map[string]any, got %T", result["selectors"])
	}
	if len(selectors) == 0 {
		t.Error("expected at least one DKIM selector to be found")
	}
	if result["primary_provider"] == nil {
		t.Error("expected primary_provider to be set")
	}
}

func TestAnalyzeDKIM_WithMock_NoSelectors(t *testing.T) {
	a := newMockAnalyzer()
	mock := a.DNS.(*MockDNSClient)

	mock.AddResponse("MX", "nodkim.example.com", []string{
		"10 mail.nodkim.example.com.",
	})
	mock.AddResponse("TXT", "nodkim.example.com", []string{})
	mock.AddResponse("NS", "_domainkey.nodkim.example.com", []string{})

	ctx := context.Background()
	result := a.AnalyzeDKIM(ctx, "nodkim.example.com", []string{"10 mail.nodkim.example.com."}, nil)

	selectors := result["selectors"].(map[string]any)
	if len(selectors) != 0 {
		t.Errorf("expected no selectors found, got %d", len(selectors))
	}
}

func TestAnalyzeCAA_WithMock_HasRecords(t *testing.T) {
	a := newMockAnalyzer()
	mock := a.DNS.(*MockDNSClient)
	mock.AddResponse("CAA", "example.com", []string{
		`0 issue "letsencrypt.org"`,
		`0 issuewild "letsencrypt.org"`,
		`0 iodef "mailto:security@example.com"`,
	})

	ctx := context.Background()
	result := a.AnalyzeCAA(ctx, "example.com")

	if result["status"] != "success" {
		t.Errorf("expected status 'success', got %v", result["status"])
	}
	if result["has_wildcard"] != true {
		t.Error("expected has_wildcard to be true")
	}
	if result["has_iodef"] != true {
		t.Error("expected has_iodef to be true")
	}
	issuers := result["issuers"].([]string)
	if len(issuers) == 0 {
		t.Error("expected at least one issuer")
	}
}

func TestAnalyzeCAA_WithMock_NoRecords(t *testing.T) {
	a := newMockAnalyzer()

	ctx := context.Background()
	result := a.AnalyzeCAA(ctx, "nocaa.example.com")

	if result["status"] != "warning" {
		t.Errorf("expected status 'warning', got %v", result["status"])
	}
	if result["has_wildcard"] != false {
		t.Error("expected has_wildcard false")
	}
}

func TestAnalyzeTLSRPT_WithMock_ValidRecord(t *testing.T) {
	a := newMockAnalyzer()
	mock := a.DNS.(*MockDNSClient)
	mock.AddResponse("TXT", "_smtp._tls.example.com", []string{
		"v=TLSRPTv1; rua=mailto:tlsrpt@example.com",
	})

	ctx := context.Background()
	result := a.AnalyzeTLSRPT(ctx, "example.com")

	if result["status"] != "success" {
		t.Errorf("expected status 'success', got %v", result["status"])
	}
	if result["rua"] == nil {
		t.Error("expected rua to be set")
	}
}

func TestAnalyzeTLSRPT_WithMock_MissingRecord(t *testing.T) {
	a := newMockAnalyzer()

	ctx := context.Background()
	result := a.AnalyzeTLSRPT(ctx, "notlsrpt.example.com")

	if result["status"] != "warning" {
		t.Errorf("expected status 'warning', got %v", result["status"])
	}
}

func TestAnalyzeBIMI_WithMock_MissingRecord(t *testing.T) {
	a := newMockAnalyzer()

	ctx := context.Background()
	result := a.AnalyzeBIMI(ctx, "nobimi.example.com")

	if result["status"] != "warning" {
		t.Errorf("expected status 'warning', got %v", result["status"])
	}
}

func TestAnalyzeSPF_WithMock_TableDriven(t *testing.T) {
	tests := []struct {
		name           string
		domain         string
		txtRecords     []string
		expectedStatus string
		expectNoMail   bool
	}{
		{
			name:           "soft fail with includes",
			domain:         "softfail.example.com",
			txtRecords:     []string{"v=spf1 include:sendgrid.net ~all"},
			expectedStatus: "success",
			expectNoMail:   false,
		},
		{
			name:           "hard fail strict",
			domain:         "hardfail.example.com",
			txtRecords:     []string{"v=spf1 mx ip4:10.0.0.0/24 -all"},
			expectedStatus: "success",
			expectNoMail:   false,
		},
		{
			name:           "no mail domain",
			domain:         "parked.example.com",
			txtRecords:     []string{"v=spf1 -all"},
			expectedStatus: "success",
			expectNoMail:   true,
		},
		{
			name:           "missing SPF",
			domain:         "missing.example.com",
			txtRecords:     nil,
			expectedStatus: "missing",
			expectNoMail:   false,
		},
		{
			name:           "permissive plus all",
			domain:         "permissive.example.com",
			txtRecords:     []string{"v=spf1 +all"},
			expectedStatus: "error",
			expectNoMail:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := newMockAnalyzer()
			mock := a.DNS.(*MockDNSClient)
			if tc.txtRecords != nil {
				mock.AddResponse("TXT", tc.domain, tc.txtRecords)
			}

			result := a.AnalyzeSPF(context.Background(), tc.domain)

			if result["status"] != tc.expectedStatus {
				t.Errorf("expected status %q, got %v", tc.expectedStatus, result["status"])
			}
			if result["no_mail_intent"] != tc.expectNoMail {
				t.Errorf("expected no_mail_intent=%v, got %v", tc.expectNoMail, result["no_mail_intent"])
			}
		})
	}
}

func TestAnalyzeDMARC_WithMock_TableDriven(t *testing.T) {
	tests := []struct {
		name           string
		domain         string
		dmarcRecord    string
		expectedStatus string
		expectedPolicy string
	}{
		{
			name:           "reject policy",
			domain:         "reject.example.com",
			dmarcRecord:    "v=DMARC1; p=reject; rua=mailto:dmarc@reject.example.com",
			expectedStatus: "success",
			expectedPolicy: "reject",
		},
		{
			name:           "quarantine policy",
			domain:         "quarantine.example.com",
			dmarcRecord:    "v=DMARC1; p=quarantine",
			expectedStatus: "success",
			expectedPolicy: "quarantine",
		},
		{
			name:           "none policy",
			domain:         "none.example.com",
			dmarcRecord:    "v=DMARC1; p=none; rua=mailto:dmarc@none.example.com",
			expectedStatus: "warning",
			expectedPolicy: "none",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := newMockAnalyzer()
			mock := a.DNS.(*MockDNSClient)
			mock.AddResponse("TXT", "_dmarc."+tc.domain, []string{tc.dmarcRecord})

			result := a.AnalyzeDMARC(context.Background(), tc.domain)

			if result["status"] != tc.expectedStatus {
				t.Errorf("expected status %q, got %v", tc.expectedStatus, result["status"])
			}
			if result["policy"] != tc.expectedPolicy {
				t.Errorf("expected policy %q, got %v", tc.expectedPolicy, result["policy"])
			}
		})
	}
}

func TestAnalyzeCAA_WithMock_TableDriven(t *testing.T) {
	tests := []struct {
		name           string
		domain         string
		caaRecords     []string
		expectedStatus string
		expectWildcard bool
		expectIodef    bool
	}{
		{
			name:   "single issuer with iodef",
			domain: "single.example.com",
			caaRecords: []string{
				`0 issue "digicert.com"`,
				`0 iodef "mailto:ca@single.example.com"`,
			},
			expectedStatus: "success",
			expectWildcard: false,
			expectIodef:    true,
		},
		{
			name:   "multiple issuers with wildcard",
			domain: "multi.example.com",
			caaRecords: []string{
				`0 issue "letsencrypt.org"`,
				`0 issue "digicert.com"`,
				`0 issuewild "letsencrypt.org"`,
			},
			expectedStatus: "success",
			expectWildcard: true,
			expectIodef:    false,
		},
		{
			name:           "no CAA records",
			domain:         "nocaa.example.com",
			caaRecords:     nil,
			expectedStatus: "warning",
			expectWildcard: false,
			expectIodef:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := newMockAnalyzer()
			mock := a.DNS.(*MockDNSClient)
			if tc.caaRecords != nil {
				mock.AddResponse("CAA", tc.domain, tc.caaRecords)
			}

			result := a.AnalyzeCAA(context.Background(), tc.domain)

			if result["status"] != tc.expectedStatus {
				t.Errorf("expected status %q, got %v", tc.expectedStatus, result["status"])
			}
			if result["has_wildcard"] != tc.expectWildcard {
				t.Errorf("expected has_wildcard=%v, got %v", tc.expectWildcard, result["has_wildcard"])
			}
			if result["has_iodef"] != tc.expectIodef {
				t.Errorf("expected has_iodef=%v, got %v", tc.expectIodef, result["has_iodef"])
			}
		})
	}
}

func TestGetBasicRecords_WithMock(t *testing.T) {
	a := newMockAnalyzer()
	mock := a.DNS.(*MockDNSClient)
	mock.AddResponse("A", "example.com", []string{"93.184.216.34"})
	mock.AddResponse("AAAA", "example.com", []string{"2606:2800:220:1:248:1893:25c8:1946"})
	mock.AddResponse("MX", "example.com", []string{"10 mail.example.com."})
	mock.AddResponse("NS", "example.com", []string{"ns1.example.com.", "ns2.example.com."})
	mock.AddResponse("TXT", "example.com", []string{"v=spf1 -all"})
	mock.AddResponse("CNAME", "example.com", []string{})
	mock.AddResponse("CAA", "example.com", []string{})
	mock.AddResponse("SOA", "example.com", []string{"ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400"})

	ctx := context.Background()
	result := a.GetBasicRecords(ctx, "example.com")

	aRecords := result["A"].([]string)
	if len(aRecords) == 0 {
		t.Error("expected A records")
	}
	mxRecords := result["MX"].([]string)
	if len(mxRecords) == 0 {
		t.Error("expected MX records")
	}
	nsRecords := result["NS"].([]string)
	if len(nsRecords) != 2 {
		t.Errorf("expected 2 NS records, got %d", len(nsRecords))
	}
}
