package analyzer

import (
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

func TestDnssecKeysToMaps_CB9(t *testing.T) {
	keys := []DNSSECKeyInfo{
		{
			Flags:     257,
			Protocol:  3,
			Algorithm: 13,
			KeyTag:    12345,
			KeyRole:   "KSK",
			AlgName:   "ECDSAP256SHA256",
			KeySize:   256,
		},
		{
			Flags:     256,
			Protocol:  3,
			Algorithm: 13,
			KeyTag:    54321,
			KeyRole:   "ZSK",
			AlgName:   "ECDSAP256SHA256",
			KeySize:   256,
		},
	}
	result := dnssecKeysToMaps(keys)
	if len(result) != 2 {
		t.Fatalf("dnssecKeysToMaps() len = %d, want 2", len(result))
	}
	if result[0]["key_role"] != "KSK" {
		t.Errorf("result[0] key_role = %v, want KSK", result[0]["key_role"])
	}
	if result[0]["key_tag"].(uint16) != 12345 {
		t.Errorf("result[0] key_tag = %v, want 12345", result[0]["key_tag"])
	}
	if result[1]["key_role"] != "ZSK" {
		t.Errorf("result[1] key_role = %v, want ZSK", result[1]["key_role"])
	}
}

func TestRrsigInfosToMaps_CB9(t *testing.T) {
	exp := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	inc := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	sigs := []RRSIGInfo{
		{
			TypeCovered:  "A",
			Algorithm:    13,
			Labels:       2,
			OriginalTTL:  3600,
			Expiration:   exp,
			Inception:    inc,
			KeyTag:       12345,
			SignerName:   "example.com.",
			TimeToExpiry: 24 * time.Hour,
			ExpiringSoon: false,
			Expired:      false,
		},
	}
	result := rrsigInfosToMaps(sigs)
	if len(result) != 1 {
		t.Fatalf("rrsigInfosToMaps() len = %d, want 1", len(result))
	}
	if result[0]["type_covered"] != "A" {
		t.Errorf("type_covered = %v", result[0]["type_covered"])
	}
	if result[0]["signer"] != "example.com." {
		t.Errorf("signer = %v", result[0]["signer"])
	}
	if result[0]["expired"] != false {
		t.Error("expired should be false")
	}
}

func TestDenialToMap_CB9(t *testing.T) {
	t.Run("NSEC", func(t *testing.T) {
		d := DenialOfExistence{Method: "NSEC"}
		m := denialToMap(d)
		if m["method"] != "NSEC" {
			t.Errorf("method = %v", m["method"])
		}
		if _, ok := m["nsec3_hash_algorithm"]; ok {
			t.Error("NSEC should not have nsec3 params")
		}
	})

	t.Run("NSEC3 with params", func(t *testing.T) {
		d := DenialOfExistence{
			Method: "NSEC3",
			NSEC3Params: &NSEC3Params{
				HashAlgorithm:  1,
				Flags:          0,
				Iterations:     10,
				SaltLength:     8,
				HighIterations: false,
			},
			Issues: []string{"High iteration count"},
		}
		m := denialToMap(d)
		if m["method"] != "NSEC3" {
			t.Errorf("method = %v", m["method"])
		}
		if m["nsec3_iterations"].(uint16) != 10 {
			t.Errorf("nsec3_iterations = %v", m["nsec3_iterations"])
		}
		if m["issues"] == nil {
			t.Error("issues should not be nil")
		}
	})
}

func TestRolloverToMap_CB9(t *testing.T) {
	r := RolloverReadiness{
		MultipleKSKs:    true,
		HasCDS:          true,
		HasCDNSKEY:      false,
		AutomationLevel: "full",
		ReadinessLevel:  "ready",
	}
	m := rolloverToMap(r)
	if m["multiple_ksks"] != true {
		t.Error("multiple_ksks should be true")
	}
	if m["has_cds"] != true {
		t.Error("has_cds should be true")
	}
	if m["has_cdnskey"] != false {
		t.Error("has_cdnskey should be false")
	}
	if m["automation"] != "full" {
		t.Errorf("automation = %v", m["automation"])
	}
	if m["readiness"] != "ready" {
		t.Errorf("readiness = %v", m["readiness"])
	}
}

func TestClassifyFindings_CB9(t *testing.T) {
	findings := []TestSSLFinding{
		{ID: "tls1_2", Severity: "OK", Finding: "offered"},
		{ID: "tls1_3", Severity: "OK", Finding: "offered"},
		{ID: "sslv3", Severity: "CRITICAL", Finding: "offered"},
		{ID: "cipher_order", Severity: "OK", Finding: "server"},
		{ID: "fs_strong", Severity: "OK", Finding: "yes"},
		{ID: "cert_expirationStatus", Severity: "OK", Finding: "valid"},
		{ID: "certificate_info", Severity: "INFO", Finding: "CN=example.com"},
		{ID: "hsts", Severity: "OK", Finding: "365 days"},
		{ID: "ocsp_stapling", Severity: "OK", Finding: "offered"},
		{ID: "heartbleed", Severity: "OK", Finding: "not vulnerable"},
		{ID: "poodle_ssl", Severity: "OK", Finding: "not vulnerable"},
		{ID: "cve-2021-3449", Severity: "OK", Finding: "not affected"},
		{ID: "unknown_high", Severity: "HIGH", Finding: "some issue"},
	}

	result := &TestSSLResult{}
	classifyFindings(result, findings)

	if len(result.Protocols) != 3 {
		t.Errorf("Protocols count = %d, want 3", len(result.Protocols))
	}
	if len(result.Ciphers) != 2 {
		t.Errorf("Ciphers count = %d, want 2", len(result.Ciphers))
	}
	if len(result.CertInfo) != 2 {
		t.Errorf("CertInfo count = %d, want 2", len(result.CertInfo))
	}
	if result.HSTS == nil {
		t.Error("HSTS should not be nil")
	}
	if result.OCSP == nil {
		t.Error("OCSP should not be nil")
	}
	if len(result.Vulnerabilities) < 3 {
		t.Errorf("Vulnerabilities count = %d, want >= 3", len(result.Vulnerabilities))
	}
}

func TestIsVulnerability_CB9(t *testing.T) {
	tests := []struct {
		id   string
		want bool
	}{
		{"heartbleed", true},
		{"poodle_ssl", true},
		{"cve-2021-3449", true},
		{"robot", true},
		{"sweet32", true},
		{"freak", true},
		{"drown", true},
		{"logjam", true},
		{"beast", true},
		{"lucky13", true},
		{"rc4", true},
		{"crime", true},
		{"breach", true},
		{"winshock", true},
		{"tls1_3", false},
		{"cipher_order", false},
		{"cert_info", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got := isVulnerability(tt.id)
			if got != tt.want {
				t.Errorf("isVulnerability(%q) = %v, want %v", tt.id, got, tt.want)
			}
		})
	}
}

func TestParseDSRecordTyped_CB9(t *testing.T) {
	rr := &dns.DS{DS: rdata.DS{KeyTag: 12345, Algorithm: 13, DigestType: 2, Digest: "abc123def456"}}

	result := parseDSRecordTyped(rr)
	if result.KeyTag != 12345 {
		t.Errorf("KeyTag = %d, want 12345", result.KeyTag)
	}
	if result.Algorithm != 13 {
		t.Errorf("Algorithm = %d, want 13", result.Algorithm)
	}
	if result.DigestType != 2 {
		t.Errorf("DigestType = %d, want 2", result.DigestType)
	}
	if result.Digest != "abc123def456" {
		t.Errorf("Digest = %q", result.Digest)
	}
}

func TestParseDNSKEYRecordTyped_CB9(t *testing.T) {
	rr := &dns.DNSKEY{DNSKEY: rdata.DNSKEY{Flags: 257, Protocol: 3, Algorithm: 13, PublicKey: "dGVzdA=="}}

	result := parseDNSKEYRecordTyped(rr)
	if result.Flags != 257 {
		t.Errorf("Flags = %d, want 257", result.Flags)
	}
	if result.Protocol != 3 {
		t.Errorf("Protocol = %d, want 3", result.Protocol)
	}
	if result.Algorithm != 13 {
		t.Errorf("Algorithm = %d, want 13", result.Algorithm)
	}
}

func TestIdentifyCAIssuer_CB9(t *testing.T) {
	tests := []struct {
		name   string
		record string
		want   string
	}{
		{"letsencrypt", "0 issue \"letsencrypt.org\"", "Let's Encrypt"},
		{"digicert", "0 issue \"digicert.com\"", "DigiCert"},
		{"sectigo", "0 issue \"sectigo.com\"", "Sectigo"},
		{"comodo", "0 issue \"comodo.com\"", "Sectigo"},
		{"globalsign", "0 issue \"globalsign.com\"", "GlobalSign"},
		{"amazon", "0 issue \"amazon.com\"", "Amazon"},
		{"google", "0 issue \"google.com\"", "Google Trust Services"},
		{"unknown with fields", "0 issue \"custom-ca.example.com\"", "custom-ca.example.com"},
		{"short record", "x", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := identifyCAIssuer(tt.record)
			if got != tt.want {
				t.Errorf("identifyCAIssuer(%q) = %q, want %q", tt.record, got, tt.want)
			}
		})
	}
}

func TestCollectMapKeys_CB9(t *testing.T) {
	m := map[string]bool{"a": true, "b": true, "c": true}
	keys := collectMapKeys(m)
	if len(keys) != 3 {
		t.Errorf("collectMapKeys() len = %d, want 3", len(keys))
	}
}

func TestBuildCAAMessage_CB9(t *testing.T) {
	msg := buildCAAMessage([]string{"Let's Encrypt"}, nil, false)
	if msg == "" {
		t.Error("buildCAAMessage() empty")
	}

	msg2 := buildCAAMessage([]string{"DigiCert"}, []string{"DigiCert"}, true)
	if msg2 == "" {
		t.Error("buildCAAMessage() with wildcard empty")
	}

	msg3 := buildCAAMessage(nil, nil, true)
	if msg3 == "" {
		t.Error("buildCAAMessage() empty issuers with wildcard")
	}
}

func TestParseCAARecords_CB9(t *testing.T) {
	records := []string{
		"0 issue \"letsencrypt.org\"",
		"0 issuewild \"digicert.com\"",
		"0 iodef \"mailto:admin@example.com\"",
	}
	parsed := parseCAARecords(records)
	if len(parsed.issueSet) != 1 {
		t.Errorf("issueSet len = %d, want 1", len(parsed.issueSet))
	}
	if !parsed.issueSet["Let's Encrypt"] {
		t.Error("issueSet should contain Let's Encrypt")
	}
	if len(parsed.issuewildSet) != 1 {
		t.Errorf("issuewildSet len = %d, want 1", len(parsed.issuewildSet))
	}
	if !parsed.hasWildcard {
		t.Error("hasWildcard should be true")
	}
	if !parsed.hasIodef {
		t.Error("hasIodef should be true")
	}
}

func TestMatchTakeoverService_CB9(t *testing.T) {
	tests := []struct {
		cname string
		want  bool
	}{
		{"myapp.herokuapp.com", true},
		{"mysite.github.io", true},
		{"cdn.cloudfront.net", true},
		{"safe.example.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.cname, func(t *testing.T) {
			got := matchTakeoverService(tt.cname)
			if (got != "") != tt.want {
				t.Errorf("matchTakeoverService(%q) = %q, want match=%v", tt.cname, got, tt.want)
			}
		})
	}
}

func TestBuildDanglingMessage_CB9(t *testing.T) {
	if buildDanglingMessage(1) != "1 potential subdomain takeover risk detected" {
		t.Errorf("single: %q", buildDanglingMessage(1))
	}
	if buildDanglingMessage(3) != "3 potential subdomain takeover risks detected" {
		t.Errorf("plural: %q", buildDanglingMessage(3))
	}
}

func TestBuildDanglingIssue_CB9(t *testing.T) {
	dr := map[string]any{
		"subdomain":    "sub.example.com",
		"cname_target": "myapp.herokuapp.com",
		"service":      "Heroku",
		"reason":       "CNAME points to unclaimed service",
	}
	got := buildDanglingIssue(dr)
	if got == "" {
		t.Error("buildDanglingIssue() empty")
	}
}

func TestCheckSubdomainDangling_CB9(t *testing.T) {
	t.Run("dangling with service", func(t *testing.T) {
		sd := map[string]any{
			"cname":     "myapp.herokuapp.com",
			"has_dns":   false,
			"subdomain": "app.example.com",
		}
		result := checkSubdomainDangling(sd)
		if result == nil {
			t.Fatal("expected dangling result")
		}
		if result["risk"] != "high" {
			t.Errorf("risk = %v, want high", result["risk"])
		}
	})

	t.Run("dangling unknown service", func(t *testing.T) {
		sd := map[string]any{
			"cname":     "unknown.random-service.com",
			"has_dns":   false,
			"subdomain": "x.example.com",
		}
		result := checkSubdomainDangling(sd)
		if result == nil {
			t.Fatal("expected dangling result")
		}
		if result["risk"] != "medium" {
			t.Errorf("risk = %v, want medium", result["risk"])
		}
	})

	t.Run("not dangling has dns", func(t *testing.T) {
		sd := map[string]any{
			"cname":     "target.example.com",
			"has_dns":   true,
			"subdomain": "sub.example.com",
		}
		result := checkSubdomainDangling(sd)
		if result != nil {
			t.Error("should not be dangling when has_dns is true")
		}
	})

	t.Run("no cname", func(t *testing.T) {
		sd := map[string]any{"subdomain": "sub.example.com"}
		result := checkSubdomainDangling(sd)
		if result != nil {
			t.Error("should return nil when no cname")
		}
	})
}

func TestItoa_CB9(t *testing.T) {
	tests := []struct {
		n    int
		want string
	}{
		{0, "0"},
		{1, "1"},
		{42, "42"},
		{100, "100"},
		{999, "999"},
	}
	for _, tt := range tests {
		got := itoa(tt.n)
		if got != tt.want {
			t.Errorf("itoa(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

func TestAppendBIMILogoIssue_CB9(t *testing.T) {
	logoURL := "https://example.com/logo.svg"
	status := "success"
	parts := []string{"BIMI configured"}

	result := appendBIMILogoIssue(&logoURL, map[string]any{"valid": false, "error": "Not SVG format"}, &status, parts)
	if status != "warning" {
		t.Errorf("status should be warning, got %q", status)
	}
	if len(result) != 2 {
		t.Errorf("parts len = %d, want 2", len(result))
	}
}

func TestFilterBIMIRecords_CB9(t *testing.T) {
	records := []string{
		"v=BIMI1; l=https://example.com/logo.svg",
		"v=spf1 ~all",
		"V=BIMI1; l=https://example.com/logo2.svg",
	}
	filtered := filterBIMIRecords(records)
	if len(filtered) != 2 {
		t.Errorf("filterBIMIRecords() len = %d, want 2", len(filtered))
	}
}

func TestExtractBIMIURLs_CB9(t *testing.T) {
	record := "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"
	logoURL, vmcURL := extractBIMIURLs(record)
	if logoURL == nil {
		t.Error("logoURL should not be nil")
	}
	if vmcURL == nil {
		t.Error("vmcURL should not be nil")
	}
}

func TestClassifyVMCCertificate_CB9(t *testing.T) {
	tests := []struct {
		name    string
		content string
		valid   bool
		issuer  string
	}{
		{"digicert", "-----BEGIN CERTIFICATE-----\nDigiCert stuff\n-----END CERTIFICATE-----", true, "DigiCert"},
		{"entrust", "-----BEGIN CERTIFICATE-----\nEntrust stuff\n-----END CERTIFICATE-----", true, "Entrust"},
		{"globalsign", "-----BEGIN CERTIFICATE-----\nGlobalSign stuff\n-----END CERTIFICATE-----", true, "GlobalSign"},
		{"generic", "-----BEGIN CERTIFICATE-----\nSome CA\n-----END CERTIFICATE-----", true, "Verified CA"},
		{"invalid", "not a certificate", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := map[string]any{}
			classifyVMCCertificate(tt.content, result)
			if tt.valid {
				if result["valid"] != true {
					t.Errorf("valid = %v, want true", result["valid"])
				}
				if result["issuer"] != tt.issuer {
					t.Errorf("issuer = %v, want %q", result["issuer"], tt.issuer)
				}
			} else {
				if errStr, ok := result["error"].(string); !ok || errStr == "" {
					t.Error("expected error string for invalid cert")
				}
			}
		})
	}
}

func TestClassifyBIMILogoFormat_CB9(t *testing.T) {
	t.Run("SVG content type", func(t *testing.T) {
		result := map[string]any{}
		classifyBIMILogoFormat("image/svg+xml", []byte("<svg></svg>"), result)
		if result["valid"] != true {
			t.Errorf("valid = %v, want true", result["valid"])
		}
		if result["format"] != "SVG" {
			t.Errorf("format = %v, want SVG", result["format"])
		}
	})

	t.Run("image/png", func(t *testing.T) {
		result := map[string]any{}
		classifyBIMILogoFormat("image/png", []byte{}, result)
		if result["valid"] != false {
			t.Errorf("valid = %v, want false (BIMI requires SVG)", result["valid"])
		}
		if result["format"] != "PNG" {
			t.Errorf("format = %v, want PNG", result["format"])
		}
	})

	t.Run("svg in body", func(t *testing.T) {
		result := map[string]any{}
		classifyBIMILogoFormat("text/html", []byte("<svg xmlns='...'>"), result)
		if result["valid"] != true {
			t.Errorf("valid = %v, want true", result["valid"])
		}
	})

	t.Run("not svg", func(t *testing.T) {
		result := map[string]any{}
		classifyBIMILogoFormat("text/html", []byte("not svg content"), result)
		if errStr, ok := result["error"].(string); !ok || errStr == "" {
			t.Error("expected error for non-SVG")
		}
	})
}

func TestParseSMIMEARecords_CB9(t *testing.T) {
	records := []*dns.SMIMEA{
		{SMIMEA: rdata.SMIMEA{Usage: 3, Selector: 1, MatchingType: 1, Certificate: "abcd1234"}},
		{SMIMEA: rdata.SMIMEA{Usage: 1, Selector: 0, MatchingType: 2, Certificate: "ef567890"}},
	}
	result := parseSMIMEARecords(records)
	if len(result) != 2 {
		t.Fatalf("parseSMIMEARecords() len = %d, want 2", len(result))
	}
	if result[0]["usage"].(uint8) != 3 {
		t.Errorf("usage = %v, want 3", result[0]["usage"])
	}
	if result[0]["selector"].(uint8) != 1 {
		t.Errorf("selector = %v, want 1", result[0]["selector"])
	}
	if result[0]["matching_type"].(uint8) != 1 {
		t.Errorf("matching_type = %v, want 1", result[0]["matching_type"])
	}

	empty := parseSMIMEARecords(nil)
	if len(empty) != 0 {
		t.Errorf("parseSMIMEARecords(nil) len = %d, want 0", len(empty))
	}
}

func TestParseOPENPGPKEYRecords_CB9(t *testing.T) {
	records := []*dns.OPENPGPKEY{
		{OPENPGPKEY: rdata.OPENPGPKEY{PublicKey: "dGVzdGtleQ=="}},
	}
	result := parseOPENPGPKEYRecords(records)
	if len(result) != 1 {
		t.Fatalf("parseOPENPGPKEYRecords() len = %d, want 1", len(result))
	}
	if result[0]["key_length"].(int) == 0 {
		t.Error("key_length should be > 0")
	}

	empty := parseOPENPGPKEYRecords(nil)
	if len(empty) != 0 {
		t.Errorf("parseOPENPGPKEYRecords(nil) len = %d, want 0", len(empty))
	}
}

func TestBuildNewSubdomainsFromSANs_CB9(t *testing.T) {
	sans := map[string]bool{
		"sub1.example.com": true,
		"sub2.example.com": true,
	}
	result := buildNewSubdomainsFromSANs(sans)
	if len(result) != 2 {
		t.Fatalf("buildNewSubdomainsFromSANs() len = %d, want 2", len(result))
	}
	for _, r := range result {
		if r["source"] != "nmap_san" {
			t.Errorf("source = %v, want nmap_san", r["source"])
		}
		if r["is_current"] != true {
			t.Error("is_current should be true")
		}
	}

	empty := buildNewSubdomainsFromSANs(map[string]bool{})
	if len(empty) != 0 {
		t.Errorf("empty SANs len = %d, want 0", len(empty))
	}
}

func TestSelectNmapTargets_CB9(t *testing.T) {
	subdomains := []map[string]any{
		{"name": "a.example.com", "is_current": true},
		{"name": "b.example.com", "is_current": false},
		{"name": "c.example.com", "is_current": true},
		{"name": "", "is_current": true},
	}

	targets := selectNmapTargets(subdomains, 5)
	if len(targets) != 2 {
		t.Errorf("selectNmapTargets() len = %d, want 2", len(targets))
	}

	limited := selectNmapTargets(subdomains, 1)
	if len(limited) != 1 {
		t.Errorf("selectNmapTargets(max=1) len = %d, want 1", len(limited))
	}
}

func TestSetCTCache_CB9(t *testing.T) {
	a := &Analyzer{
		ctCache:    make(map[string]ctCacheEntry),
		ctCacheTTL: 24 * time.Hour,
	}
	data := []map[string]any{{"test": true}}
	a.setCTCache("example.com", data)
	got, ok := a.GetCTCache("example.com")
	if !ok || got == nil {
		t.Error("setCTCache/GetCTCache should return cached value")
	}
	if len(got) != 1 {
		t.Errorf("cached data len = %d, want 1", len(got))
	}

	got2, ok2 := a.GetCTCache("missing.com")
	if ok2 || got2 != nil {
		t.Error("GetCTCache should return nil,false for missing key")
	}
}
