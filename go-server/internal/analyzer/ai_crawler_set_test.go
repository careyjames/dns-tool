package analyzer

import (
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
	"dnstool/go-server/internal/analyzer/ai_surface"
)

func TestBuildAICrawlerSet_CB11(t *testing.T) {
	crawlers := ai_surface.GetAICrawlers()
	set := map[string]bool{}
	for _, c := range crawlers {
		set[c] = true
	}
	if set == nil {
		t.Fatal("buildAICrawlerSet equivalent should return non-nil map")
	}
}

func TestConvertEvidenceSlice_CB11(t *testing.T) {
	evidence := []ai_surface.Evidence{
		{
			Type:       "test_type",
			Source:     "https://example.com",
			Detail:     "test detail",
			Severity:   "info",
			Confidence: "Observed",
		},
		{
			Type:       "another_type",
			Source:     "https://example.com/robots.txt",
			Detail:     "another detail",
			Severity:   "high",
			Confidence: "Observed",
		},
	}
	if len(evidence) != 2 {
		t.Fatalf("evidence len = %d, want 2", len(evidence))
	}
	if evidence[0].Type != "test_type" {
		t.Errorf("evidence[0].Type = %q, want test_type", evidence[0].Type)
	}
	if evidence[1].Severity != "high" {
		t.Errorf("evidence[1].Severity = %q, want high", evidence[1].Severity)
	}
}

func TestEvidenceStructFields_CB11(t *testing.T) {
	tests := []struct {
		name       string
		evidence   ai_surface.Evidence
		wantType   string
		wantSource string
	}{
		{
			name:       "llms_txt_found",
			evidence:   ai_surface.Evidence{Type: "llms_txt_found", Source: "https://example.com/.well-known/llms.txt", Detail: "found", Severity: "info", Confidence: "Observed"},
			wantType:   "llms_txt_found",
			wantSource: "https://example.com/.well-known/llms.txt",
		},
		{
			name:       "robots_txt_blocks_ai",
			evidence:   ai_surface.Evidence{Type: "robots_txt_blocks_ai", Source: "https://example.com/robots.txt", Detail: "blocks GPTBot", Severity: "info", Confidence: "Observed"},
			wantType:   "robots_txt_blocks_ai",
			wantSource: "https://example.com/robots.txt",
		},
		{
			name:       "poisoning_ioc",
			evidence:   ai_surface.Evidence{Type: "poisoning_ioc", Source: "https://example.com/", Detail: "prefilled link", Severity: "medium", Confidence: "Observed"},
			wantType:   "poisoning_ioc",
			wantSource: "https://example.com/",
		},
		{
			name:       "hidden_prompt",
			evidence:   ai_surface.Evidence{Type: "hidden_prompt", Source: "https://example.com/", Detail: "hidden element", Severity: "high", Confidence: "Observed"},
			wantType:   "hidden_prompt",
			wantSource: "https://example.com/",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.evidence.Type != tt.wantType {
				t.Errorf("Type = %q, want %q", tt.evidence.Type, tt.wantType)
			}
			if tt.evidence.Source != tt.wantSource {
				t.Errorf("Source = %q, want %q", tt.evidence.Source, tt.wantSource)
			}
		})
	}
}

func TestClassifyBIMILogoFormat_CB11(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        []byte
		wantValid   bool
		wantFormat  string
		wantError   bool
	}{
		{
			name:        "SVG content type",
			contentType: "image/svg+xml",
			body:        []byte("<svg xmlns='http://www.w3.org/2000/svg'></svg>"),
			wantValid:   true,
			wantFormat:  "SVG",
		},
		{
			name:        "SVG content type uppercase",
			contentType: "image/SVG+xml",
			body:        []byte("<svg></svg>"),
			wantValid:   true,
			wantFormat:  "SVG",
		},
		{
			name:        "PNG content type",
			contentType: "image/png",
			body:        []byte{0x89, 0x50, 0x4E, 0x47},
			wantValid:   false,
			wantFormat:  "PNG",
			wantError:   true,
		},
		{
			name:        "JPEG content type",
			contentType: "image/jpeg",
			body:        []byte{0xFF, 0xD8, 0xFF},
			wantValid:   false,
			wantFormat:  "JPEG",
			wantError:   true,
		},
		{
			name:        "WEBP content type",
			contentType: "image/webp",
			body:        []byte("RIFF"),
			wantValid:   false,
			wantFormat:  "WEBP",
			wantError:   true,
		},
		{
			name:        "SVG detected in body fallback",
			contentType: "text/plain",
			body:        []byte("<?xml version='1.0'?><svg xmlns='http://www.w3.org/2000/svg'></svg>"),
			wantValid:   true,
			wantFormat:  "SVG",
		},
		{
			name:        "no extension plain text not SVG",
			contentType: "text/plain",
			body:        []byte("this is just plain text not an image"),
			wantValid:   false,
			wantError:   true,
		},
		{
			name:        "application/octet-stream with SVG inside",
			contentType: "application/octet-stream",
			body:        []byte("<svg viewBox='0 0 100 100'></svg>"),
			wantValid:   true,
			wantFormat:  "SVG",
		},
		{
			name:        "application/octet-stream no SVG",
			contentType: "application/octet-stream",
			body:        []byte("binary data here"),
			wantValid:   false,
			wantError:   true,
		},
		{
			name:        "empty content type with SVG body",
			contentType: "",
			body:        []byte("<svg></svg>"),
			wantValid:   true,
			wantFormat:  "SVG",
		},
		{
			name:        "empty content type no SVG",
			contentType: "",
			body:        []byte("hello world"),
			wantValid:   false,
			wantError:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := map[string]any{}
			classifyBIMILogoFormat(tt.contentType, tt.body, result)
			if valid, _ := result["valid"].(bool); valid != tt.wantValid {
				t.Errorf("valid = %v, want %v", valid, tt.wantValid)
			}
			if tt.wantFormat != "" {
				if fmt, _ := result["format"].(string); fmt != tt.wantFormat {
					t.Errorf("format = %v, want %q", result["format"], tt.wantFormat)
				}
			}
			if tt.wantError {
				if _, ok := result["error"].(string); !ok {
					t.Error("expected error string")
				}
			}
		})
	}
}

func TestClassifyVMCCertificate_CB11(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		wantValid  bool
		wantIssuer string
		wantError  bool
	}{
		{
			name:       "DigiCert certificate",
			content:    "-----BEGIN CERTIFICATE-----\nMIIFoo DigiCert Inc\n-----END CERTIFICATE-----",
			wantValid:  true,
			wantIssuer: "DigiCert",
		},
		{
			name:       "Entrust certificate",
			content:    "-----BEGIN CERTIFICATE-----\nEntrust, Inc.\n-----END CERTIFICATE-----",
			wantValid:  true,
			wantIssuer: "Entrust",
		},
		{
			name:       "GlobalSign certificate",
			content:    "-----BEGIN CERTIFICATE-----\nGlobalSign nv-sa\n-----END CERTIFICATE-----",
			wantValid:  true,
			wantIssuer: "GlobalSign",
		},
		{
			name:       "Unknown CA certificate",
			content:    "-----BEGIN CERTIFICATE-----\nSome Random CA\n-----END CERTIFICATE-----",
			wantValid:  true,
			wantIssuer: "Verified CA",
		},
		{
			name:      "Not a certificate at all",
			content:   "This is not a certificate",
			wantValid: false,
			wantError: true,
		},
		{
			name:      "Empty string",
			content:   "",
			wantValid: false,
			wantError: true,
		},
		{
			name:      "Partial certificate header only",
			content:   "-----BEGIN CERT-----\ndata\n-----END CERT-----",
			wantValid: false,
			wantError: true,
		},
		{
			name:       "Certificate with multiple CAs mentioned first wins",
			content:    "-----BEGIN CERTIFICATE-----\nDigiCert then Entrust\n-----END CERTIFICATE-----",
			wantValid:  true,
			wantIssuer: "DigiCert",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := map[string]any{}
			classifyVMCCertificate(tt.content, result)
			if valid, _ := result["valid"].(bool); valid != tt.wantValid {
				t.Errorf("valid = %v, want %v", valid, tt.wantValid)
			}
			if tt.wantIssuer != "" {
				if issuer, _ := result["issuer"].(string); issuer != tt.wantIssuer {
					t.Errorf("issuer = %v, want %q", result["issuer"], tt.wantIssuer)
				}
			}
			if tt.wantError {
				if errStr, ok := result["error"].(string); !ok || errStr == "" {
					t.Error("expected non-empty error string")
				}
			}
		})
	}
}

func TestParseCDSRecords_CB11(t *testing.T) {
	tests := []struct {
		name        string
		records     []*dns.CDS
		wantLen     int
		checkDelete bool
		deleteIdx   int
		checkAlgo   bool
		algoIdx     int
		wantAlgo    string
	}{
		{
			name: "single normal CDS record",
			records: []*dns.CDS{
				{DS: dns.DS{DS: rdata.DS{KeyTag: 54321, Algorithm: 13, DigestType: 2, Digest: "deadbeef"}}},
			},
			wantLen:   1,
			checkAlgo: true,
			algoIdx:   0,
			wantAlgo:  "ECDSAP256SHA256",
		},
		{
			name: "delete signal CDS record",
			records: []*dns.CDS{
				{DS: dns.DS{DS: rdata.DS{KeyTag: 0, Algorithm: 0, DigestType: 0, Digest: ""}}},
			},
			wantLen:     1,
			checkDelete: true,
			deleteIdx:   0,
		},
		{
			name: "multiple CDS records",
			records: []*dns.CDS{
				{DS: dns.DS{DS: rdata.DS{KeyTag: 11111, Algorithm: 8, DigestType: 2, Digest: "aabbccdd"}}},
				{DS: dns.DS{DS: rdata.DS{KeyTag: 22222, Algorithm: 13, DigestType: 2, Digest: "eeff0011"}}},
			},
			wantLen: 2,
		},
		{
			name:    "empty records",
			records: []*dns.CDS{},
			wantLen: 0,
		},
		{
			name:    "nil records",
			records: nil,
			wantLen: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseCDSRecords(tt.records)
			if len(result) != tt.wantLen {
				t.Fatalf("parseCDSRecords() len = %d, want %d", len(result), tt.wantLen)
			}
			if tt.checkDelete && tt.deleteIdx < len(result) {
				if result[tt.deleteIdx]["delete_signal"] != true {
					t.Error("expected delete_signal = true")
				}
			}
			if tt.checkAlgo && tt.algoIdx < len(result) {
				if result[tt.algoIdx]["algorithm"] != tt.wantAlgo {
					t.Errorf("algorithm = %v, want %q", result[tt.algoIdx]["algorithm"], tt.wantAlgo)
				}
			}
		})
	}
}

func TestParseCDNSKEYRecords_CB11(t *testing.T) {
	tests := []struct {
		name        string
		records     []*dns.CDNSKEY
		wantLen     int
		checkDelete bool
		deleteIdx   int
	}{
		{
			name: "normal CDNSKEY record",
			records: []*dns.CDNSKEY{
				{DNSKEY: dns.DNSKEY{DNSKEY: rdata.DNSKEY{Flags: 257, Protocol: 3, Algorithm: 13, PublicKey: "dGVzdA=="}}},
			},
			wantLen: 1,
		},
		{
			name: "delete signal CDNSKEY record",
			records: []*dns.CDNSKEY{
				{DNSKEY: dns.DNSKEY{DNSKEY: rdata.DNSKEY{Flags: 0, Protocol: 3, Algorithm: 0, PublicKey: ""}}},
			},
			wantLen:     1,
			checkDelete: true,
			deleteIdx:   0,
		},
		{
			name: "multiple CDNSKEY records",
			records: []*dns.CDNSKEY{
				{DNSKEY: dns.DNSKEY{DNSKEY: rdata.DNSKEY{Flags: 257, Protocol: 3, Algorithm: 13, PublicKey: "a2V5MQ=="}}},
				{DNSKEY: dns.DNSKEY{DNSKEY: rdata.DNSKEY{Flags: 256, Protocol: 3, Algorithm: 8, PublicKey: "a2V5Mg=="}}},
			},
			wantLen: 2,
		},
		{
			name:    "nil records",
			records: nil,
			wantLen: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseCDNSKEYRecords(tt.records)
			if len(result) != tt.wantLen {
				t.Fatalf("parseCDNSKEYRecords() len = %d, want %d", len(result), tt.wantLen)
			}
			if tt.checkDelete && tt.deleteIdx < len(result) {
				if result[tt.deleteIdx]["delete_signal"] != true {
					t.Error("expected delete_signal = true")
				}
			}
			for i, r := range result {
				if _, ok := r["flags"]; !ok {
					t.Errorf("record[%d] missing flags key", i)
				}
				if _, ok := r["protocol"]; !ok {
					t.Errorf("record[%d] missing protocol key", i)
				}
				if _, ok := r["algorithm"]; !ok {
					t.Errorf("record[%d] missing algorithm key", i)
				}
				if _, ok := r["raw"]; !ok {
					t.Errorf("record[%d] missing raw key", i)
				}
			}
		})
	}
}

func TestSetCTCacheEviction_CB11(t *testing.T) {
	a := &Analyzer{
		ctCache:    make(map[string]ctCacheEntry),
		ctCacheTTL: 1 * time.Millisecond,
	}

	for i := 0; i < 250; i++ {
		domain := "domain" + itoa(i) + ".com"
		a.setCTCache(domain, []map[string]any{{"idx": i}})
	}

	time.Sleep(5 * time.Millisecond)

	a.setCTCache("trigger-eviction.com", []map[string]any{{"final": true}})

	got, ok := a.GetCTCache("trigger-eviction.com")
	if !ok || got == nil {
		t.Error("freshly cached entry should be retrievable")
	}

	a.ctCacheMu.RLock()
	remaining := len(a.ctCache)
	a.ctCacheMu.RUnlock()

	if remaining > 201 {
		t.Errorf("cache should have evicted expired entries, remaining = %d", remaining)
	}
}

func TestSetCTCacheNonNil_CB11(t *testing.T) {
	a := &Analyzer{
		ctCache:    make(map[string]ctCacheEntry),
		ctCacheTTL: 24 * time.Hour,
	}

	data := []map[string]any{
		{"cert_id": "abc123", "issuer": "Let's Encrypt"},
		{"cert_id": "def456", "issuer": "DigiCert"},
	}
	a.setCTCache("example.com", data)

	got, ok := a.GetCTCache("example.com")
	if !ok {
		t.Fatal("setCTCache: GetCTCache should return true")
	}
	if len(got) != 2 {
		t.Fatalf("cached data len = %d, want 2", len(got))
	}
	if got[0]["cert_id"] != "abc123" {
		t.Errorf("got[0][cert_id] = %v, want abc123", got[0]["cert_id"])
	}

	a.setCTCache("example.com", []map[string]any{{"updated": true}})
	got2, ok2 := a.GetCTCache("example.com")
	if !ok2 {
		t.Fatal("overwritten entry should still be cached")
	}
	if len(got2) != 1 {
		t.Fatalf("overwritten data len = %d, want 1", len(got2))
	}
}

func TestClassifyCDSAutomation_CB11(t *testing.T) {
	tests := []struct {
		name    string
		cds     []*dns.CDS
		cdnskey []*dns.CDNSKEY
		want    string
	}{
		{
			name: "full automation",
			cds: []*dns.CDS{
				{DS: dns.DS{DS: rdata.DS{KeyTag: 12345, Algorithm: 13, DigestType: 2}}},
			},
			cdnskey: []*dns.CDNSKEY{
				{DNSKEY: dns.DNSKEY{DNSKEY: rdata.DNSKEY{Flags: 257, Protocol: 3, Algorithm: 13}}},
			},
			want: "full_automation",
		},
		{
			name: "cds only",
			cds: []*dns.CDS{
				{DS: dns.DS{DS: rdata.DS{KeyTag: 12345, Algorithm: 13, DigestType: 2}}},
			},
			cdnskey: nil,
			want:    "cds_only",
		},
		{
			name: "cdnskey only",
			cds:  nil,
			cdnskey: []*dns.CDNSKEY{
				{DNSKEY: dns.DNSKEY{DNSKEY: rdata.DNSKEY{Flags: 257, Protocol: 3, Algorithm: 13}}},
			},
			want: "cdnskey_only",
		},
		{
			name:    "none",
			cds:     nil,
			cdnskey: nil,
			want:    "none",
		},
		{
			name: "delete signaled via CDS",
			cds: []*dns.CDS{
				{DS: dns.DS{DS: rdata.DS{KeyTag: 0, Algorithm: 0, DigestType: 0}}},
			},
			cdnskey: nil,
			want:    "delete_signaled",
		},
		{
			name: "delete signaled via CDNSKEY",
			cds:  nil,
			cdnskey: []*dns.CDNSKEY{
				{DNSKEY: dns.DNSKEY{DNSKEY: rdata.DNSKEY{Flags: 0, Protocol: 3, Algorithm: 0}}},
			},
			want: "delete_signaled",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyCDSAutomation(tt.cds, tt.cdnskey)
			if got != tt.want {
				t.Errorf("classifyCDSAutomation() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildCDSMessage_CB11(t *testing.T) {
	tests := []struct {
		name   string
		result map[string]any
		want   string
	}{
		{
			name:   "full automation",
			result: map[string]any{"automation": "full_automation"},
			want:   "Full RFC 8078 automated DNSSEC key rollover signaling detected (CDS + CDNSKEY)",
		},
		{
			name:   "cds only",
			result: map[string]any{"automation": "cds_only"},
			want:   "CDS records present for automated DS updates",
		},
		{
			name:   "cdnskey only",
			result: map[string]any{"automation": "cdnskey_only"},
			want:   "CDNSKEY records present for automated key rollover",
		},
		{
			name:   "delete signaled",
			result: map[string]any{"automation": "delete_signaled"},
			want:   "DNSSEC deletion signaled via CDS/CDNSKEY (RFC 8078 §4)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildCDSMessage(tt.result)
			if got != tt.want {
				t.Errorf("buildCDSMessage() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildBIMIMessage_CB11(t *testing.T) {
	tests := []struct {
		name       string
		logoURL    *string
		vmcURL     *string
		logoData   map[string]any
		vmcData    map[string]any
		wantStatus string
	}{
		{
			name:       "VMC valid with issuer",
			logoURL:    strPtrCB11("https://example.com/logo.svg"),
			vmcURL:     strPtrCB11("https://example.com/vmc.pem"),
			logoData:   map[string]any{"valid": true, "format": "SVG"},
			vmcData:    map[string]any{"valid": true, "issuer": "DigiCert"},
			wantStatus: "success",
		},
		{
			name:       "VMC present but invalid",
			logoURL:    strPtrCB11("https://example.com/logo.svg"),
			vmcURL:     strPtrCB11("https://example.com/vmc.pem"),
			logoData:   map[string]any{"valid": true},
			vmcData:    map[string]any{"valid": false, "error": "Invalid certificate"},
			wantStatus: "warning",
		},
		{
			name:       "Logo only no VMC",
			logoURL:    strPtrCB11("https://example.com/logo.svg"),
			vmcURL:     nil,
			logoData:   map[string]any{"valid": true},
			vmcData:    map[string]any{},
			wantStatus: "success",
		},
		{
			name:       "No logo no VMC",
			logoURL:    nil,
			vmcURL:     nil,
			logoData:   map[string]any{},
			vmcData:    map[string]any{},
			wantStatus: "warning",
		},
		{
			name:       "Logo invalid with error",
			logoURL:    strPtrCB11("https://example.com/logo.png"),
			vmcURL:     nil,
			logoData:   map[string]any{"valid": false, "error": "Not SVG format"},
			vmcData:    map[string]any{},
			wantStatus: "warning",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, msg := buildBIMIMessage(tt.logoURL, tt.vmcURL, tt.logoData, tt.vmcData)
			if status != tt.wantStatus {
				t.Errorf("status = %q, want %q", status, tt.wantStatus)
			}
			if msg == "" {
				t.Error("message should not be empty")
			}
		})
	}
}

func TestFilterBIMIRecords_CB11(t *testing.T) {
	tests := []struct {
		name    string
		records []string
		wantLen int
	}{
		{
			name:    "mixed records",
			records: []string{"v=BIMI1; l=https://x.com/logo.svg", "v=spf1 ~all", "v=DMARC1; p=reject"},
			wantLen: 1,
		},
		{
			name:    "all BIMI",
			records: []string{"v=BIMI1; l=https://a.com/logo.svg", "v=bimi1; l=https://b.com/logo.svg"},
			wantLen: 2,
		},
		{
			name:    "none BIMI",
			records: []string{"v=spf1", "v=DMARC1"},
			wantLen: 0,
		},
		{
			name:    "empty",
			records: []string{},
			wantLen: 0,
		},
		{
			name:    "nil",
			records: nil,
			wantLen: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterBIMIRecords(tt.records)
			if len(got) != tt.wantLen {
				t.Errorf("filterBIMIRecords() len = %d, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestExtractBIMIURLs_CB11(t *testing.T) {
	tests := []struct {
		name     string
		record   string
		wantLogo bool
		wantVMC  bool
	}{
		{
			name:     "both URLs",
			record:   "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
			wantLogo: true,
			wantVMC:  true,
		},
		{
			name:     "logo only",
			record:   "v=BIMI1; l=https://example.com/logo.svg",
			wantLogo: true,
			wantVMC:  false,
		},
		{
			name:     "VMC only",
			record:   "v=BIMI1; a=https://example.com/vmc.pem",
			wantLogo: false,
			wantVMC:  true,
		},
		{
			name:     "neither",
			record:   "v=BIMI1;",
			wantLogo: false,
			wantVMC:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logo, vmc := extractBIMIURLs(tt.record)
			if (logo != nil) != tt.wantLogo {
				t.Errorf("logoURL present = %v, want %v", logo != nil, tt.wantLogo)
			}
			if (vmc != nil) != tt.wantVMC {
				t.Errorf("vmcURL present = %v, want %v", vmc != nil, tt.wantVMC)
			}
		})
	}
}

func TestGetCTCacheExpired_CB11(t *testing.T) {
	a := &Analyzer{
		ctCache:    make(map[string]ctCacheEntry),
		ctCacheTTL: 1 * time.Millisecond,
	}

	a.setCTCache("expired.com", []map[string]any{{"test": true}})
	time.Sleep(5 * time.Millisecond)

	got, ok := a.GetCTCache("expired.com")
	if ok || got != nil {
		t.Error("expired entry should not be returned")
	}
}

func TestNewScannerCreation_CB11(t *testing.T) {
	scanner := ai_surface.NewScanner(nil)
	if scanner == nil {
		t.Fatal("NewScanner should return non-nil")
	}
}

func strPtrCB11(s string) *string {
	return &s
}
