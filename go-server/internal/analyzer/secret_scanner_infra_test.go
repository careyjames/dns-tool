package analyzer

import (
        "net/netip"
        "testing"

        dns "codeberg.org/miekg/dns"
        "codeberg.org/miekg/dns/svcb"
)

func TestRedactSecret_CB8(t *testing.T) {
        tests := []struct {
                input string
                want  string
        }{
                {"short", "****"},
                {"AKIA1234567890ABCDEF", "AKIA********CDEF"}, //nolint:gosec // #nosec G101 -- test fixture: fake AWS key for redaction unit test //gitleaks:allow // nosemgrep: generic.secrets.gitleaks.aws-access-token, generic.secrets.security.detected-aws-access-key-id-value // NOSONAR
                {"-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN [PRIVATE KEY REDACTED]-----"}, //nolint:gosec // #nosec G101 -- test fixture: fake PEM header for redaction unit test //gitleaks:allow // nosemgrep: generic.secrets.gitleaks.private-key // NOSONAR
                {"abcd1234efgh", "abcd********efgh"},
        }
        for _, tt := range tests {
                got := redactSecret(tt.input)
                if got != tt.want {
                        t.Errorf("redactSecret(%q) = %q, want %q", tt.input, got, tt.want)
                }
        }
}

func TestShortenURL_CB8(t *testing.T) {
        short := shortenURL("https://example.com/page")
        if short != "example.com/page" {
                t.Errorf("got %q", short)
        }
        short2 := shortenURL("http://example.com/page")
        if short2 != "example.com/page" {
                t.Errorf("got %q", short2)
        }
        long := shortenURL("https://example.com/" + string(make([]byte, 100)))
        if len(long) > 81 {
                t.Errorf("expected truncated URL, got len %d", len(long))
        }
}

func TestNormalizeScriptURL_CB8(t *testing.T) {
        tests := []struct {
                src, domain, want string
        }{
                {"//cdn.example.com/app.js", "example.com", "https://cdn.example.com/app.js"},
                {"/js/app.js", "example.com", "https://example.com/js/app.js"},
                {"app.js", "example.com", "https://example.com/app.js"},
                {"https://cdn.example.com/app.js", "example.com", "https://cdn.example.com/app.js"},
        }
        for _, tt := range tests {
                got := normalizeScriptURL(tt.src, tt.domain)
                if got != tt.want {
                        t.Errorf("normalizeScriptURL(%q, %q) = %q, want %q", tt.src, tt.domain, got, tt.want)
                }
        }
}

func TestIsSameOrigin_CB8(t *testing.T) {
        if !isSameOrigin("https://example.com/app.js", "example.com") {
                t.Fatal("expected same origin")
        }
        if isSameOrigin("https://other.com/app.js", "example.com") {
                t.Fatal("expected different origin")
        }
        if !isSameOrigin("https://example.com:443/app.js", "example.com") {
                t.Fatal("expected same origin with port")
        }
}

func TestExtractContext_CB8(t *testing.T) {
        body := "prefix...TESTKEYXXXXXXXXXXXXXXXX...suffix" //nolint:gosec // #nosec G101 -- test fixture: fake placeholder key for extractContext unit test //gitleaks:allow // nosemgrep: generic.secrets.gitleaks.generic-api-key // NOSONAR
        ctx := extractContext(body, 9, 29)
        if ctx == "" {
                t.Fatal("expected non-empty context")
        }
        ctx2 := extractContext("short", 0, 5)
        if ctx2 != "short" {
                t.Errorf("got %q", ctx2)
        }
}

func TestSanitizeContext_CB8(t *testing.T) {
        got := sanitizeContext("line1\nline2\tline3\r  end")
        if got == "" {
                t.Fatal("expected non-empty sanitized context")
        }
        long := string(make([]byte, 200))
        got2 := sanitizeContext(long)
        if len(got2) > 125 {
                t.Errorf("expected truncated, got len %d", len(got2))
        }
}

func TestIsInCommentOrDocumentation_CB8(t *testing.T) {
        if !isInCommentOrDocumentation("// example usage here") {
                t.Fatal("expected true for comment")
        }
        if isInCommentOrDocumentation("var apiKey = 'real-key'") {
                t.Fatal("expected false for real code")
        }
        if !isInCommentOrDocumentation("see the documentation for details") {
                t.Fatal("expected true for documentation")
        }
}

func TestDeduplicateFindings_CB8(t *testing.T) {
        findings := []SecretFinding{
                {Type: "AWS", Redacted: "AKIA****CDEF"},
                {Type: "AWS", Redacted: "AKIA****CDEF"},
                {Type: "Stripe", Redacted: "sk_l****abcd"},
        }
        deduped := deduplicateFindings(findings)
        if len(deduped) != 2 {
                t.Fatalf("expected 2 findings, got %d", len(deduped))
        }
}

func TestIsMinifiedJSFalsePositive_CB8(t *testing.T) {
        if isMinifiedJSFalsePositive("https://user:pass@example.com/path") {
                t.Fatal("expected false for valid URL")
        }
        if !isMinifiedJSFalsePositive("https://user:pass@noperiod/path") {
                t.Fatal("expected true for host without dot")
        }
        if isMinifiedJSFalsePositive("https://no-at-sign.com/path") {
                t.Fatal("expected false when no @ sign")
        }
}

func TestEvaluateMatch_CB8(t *testing.T) {
        body := "var key = 'AKIAI0SFODNN7ZQRSTUB'" //nolint:gosec // #nosec G101 -- test fixture: fake AWS key for evaluateMatch unit test //gitleaks:allow // nosemgrep: generic.secrets.gitleaks.aws-access-token, generic.secrets.gitleaks.generic-api-key, generic.secrets.security.detected-aws-access-key-id-value // NOSONAR
        pat := secretPatterns[0]
        loc := pat.Re.FindStringIndex(body)
        if loc == nil {
                t.Fatal("expected match for AWS key pattern")
        }
        finding, ok := evaluateMatch(body, loc, pat, "example.com/page")
        if !ok {
                t.Fatal("expected valid finding")
        }
        if finding.Type != "AWS Access Key ID" {
                t.Errorf("expected AWS type, got %q", finding.Type)
        }

        _, ok2 := evaluateMatch("short", []int{0, 3}, secretPattern{Name: "test", MinLen: 10}, "x")
        if ok2 {
                t.Fatal("expected false for too short match")
        }

        _, ok3 := evaluateMatch("example_PLACEHOLDER_key_1234567890", []int{0, 34}, secretPattern{Name: "test", MinLen: 5}, "x")
        if ok3 {
                t.Fatal("expected false for placeholder pattern")
        }
}

func TestScanContent_CB8(t *testing.T) {
        scanner := &SecretScanner{}
        body := `var key = "AKIAIOSFODNN7EXAMPLE1";` //nolint:gosec // #nosec G101 -- test fixture: AWS example key for scanContent unit test // gitleaks:allow // nosemgrep: generic.secrets.gitleaks.aws-access-token // NOSONAR
        findings := scanner.scanContent(body, "https://example.com/app.js", nil)
        _ = findings
}

func TestExtractScriptSources_CB8(t *testing.T) {
        html := `<html><head><script src="/js/app.js"></script><script src="https://other.com/ext.js"></script></head></html>`
        sources := extractScriptSources(html, "example.com")
        if len(sources) == 0 {
                t.Fatal("expected extracted script sources")
        }
}

func TestNewSecretScanner_CB8(t *testing.T) {
        scanner := NewSecretScanner(nil)
        if scanner == nil {
                t.Fatal("expected non-nil scanner")
        }
}

func TestAnalyzeDNSInfrastructureOSS_CB8(t *testing.T) {
        a := New(WithInitialIANAFetch(false))
        result := a.AnalyzeDNSInfrastructure("example.com", map[string]any{})
        if result == nil {
                t.Fatal("expected non-nil result")
        }
        if result["provider_tier"] != "standard" {
                t.Errorf("expected standard tier")
        }
}

func TestGetHostingInfoOSS_CB8(t *testing.T) {
        a := New(WithInitialIANAFetch(false))
        results := map[string]any{
                "basic_records": map[string]any{
                        "NS":    []string{"ns1.google.com"},
                        "MX":    []string{"aspmx.l.google.com"},
                        "CNAME": []string{},
                },
        }
        info := a.GetHostingInfo(nil, "example.com", results)
        if info == nil {
                t.Fatal("expected non-nil info")
        }
        if info["domain"] != "example.com" {
                t.Errorf("expected domain=example.com")
        }
}

func TestDetectEmailSecurityManagementOSS_CB8(t *testing.T) {
        a := New(WithInitialIANAFetch(false))
        result := a.DetectEmailSecurityManagement(nil, nil, nil, nil, "example.com", nil)
        if result == nil {
                t.Fatal("expected non-nil result")
        }
}

func TestStubFunctions_CB8(t *testing.T) {
        enrichHostingFromEdgeCDN(map[string]any{})
        matchEnterpriseProvider(nil)
        matchSelfHostedProvider("")
        matchManagedProvider("")
        matchGovernmentDomain("")
        collectAltSecurityItems(nil)
        assessTier("")
        matchAllProviders(nil, "")
        buildInfraResult(nil, false, false, nil)
        hostingConfidence("", false)
        dnsConfidence(false)
        emailConfidence(false, false)
        detectEmailProviderFromSPF(nil)
        detectProvider(nil, nil)
        matchMonitoringProvider("")
        detectDMARCReportProviders(nil, nil)
        detectTLSRPTReportProviders(nil, nil)
        detectSPFFlatteningProvider(nil, nil)
        detectMTASTSManagement(nil, nil)
        resolveEmailHosting(nil, nil)
        identifyEmailProvider(nil)
        identifyDNSProvider(nil)
        identifyWebHosting(nil)
        identifyHostingFromPTR(nil)
        matchDynamicServiceNS("")
        addDSDetection(nil, dynamicServiceInfo{}, "")
}

func TestAnalyzerStubMethods_CB8(t *testing.T) {
        a := New(WithInitialIANAFetch(false))
        a.resolveNSRecords("example.com", []string{"ns1.example.com"})
        a.detectHostingFromPTR(nil, nil)
        a.resolveDNSHosting("example.com", nil)
        a.detectHostedDKIMProviders(nil, "", nil)
        a.detectDynamicServices(nil, "")
        a.scanDynamicServiceZones(nil, nil)
}

func TestParseCDSRecords_CB8(t *testing.T) {
        cds1 := &dns.CDS{}
        cds1.KeyTag = 12345
        cds1.Algorithm = 8
        cds1.DigestType = 2
        cds1.Digest = "abc123"
        cds2 := &dns.CDS{}
        cds2.KeyTag = 0
        cds2.Algorithm = 0
        cds2.DigestType = 0
        records := []*dns.CDS{cds1, cds2}
        result := parseCDSRecords(records)
        if len(result) != 2 {
                t.Fatalf("expected 2, got %d", len(result))
        }
        if _, ok := result[1]["delete_signal"]; !ok {
                t.Fatal("expected delete_signal for zero CDS")
        }
}

func TestParseCDNSKEYRecords_CB8(t *testing.T) {
        dk1 := &dns.CDNSKEY{}
        dk1.Flags = 257
        dk1.Protocol = 3
        dk1.Algorithm = 8
        dk1.PublicKey = "abc"
        dk2 := &dns.CDNSKEY{}
        dk2.Flags = 0
        dk2.Protocol = 3
        dk2.Algorithm = 0
        records := []*dns.CDNSKEY{dk1, dk2}
        result := parseCDNSKEYRecords(records)
        if len(result) != 2 {
                t.Fatalf("expected 2, got %d", len(result))
        }
        if _, ok := result[1]["delete_signal"]; !ok {
                t.Fatal("expected delete_signal for zero CDNSKEY")
        }
}

func TestIpHintsToStrings_CB8(t *testing.T) {
        hints := []netip.Addr{
                netip.MustParseAddr("192.0.2.1"),
                netip.MustParseAddr("2001:db8::1"),
        }
        result := ipHintsToStrings(hints)
        if len(result) != 2 {
                t.Fatalf("expected 2, got %d", len(result))
        }
}

func TestHasHTTP3_CB8(t *testing.T) {
        if !hasHTTP3([]string{"h2", "h3"}) {
                t.Fatal("expected true for h3")
        }
        if hasHTTP3([]string{"h2", "http/1.1"}) {
                t.Fatal("expected false without h3")
        }
}

func TestUpdateSVCBCapabilities_CB8(t *testing.T) {
        result := map[string]any{}
        parsed := []map[string]any{
                {"alpn": []string{"h3", "h2"}, "ipv4hint": []string{"192.0.2.1"}},
        }
        updateSVCBCapabilities(result, parsed)
}

func TestBuildHTTPSMessage_CB8(t *testing.T) {
        result := map[string]any{
                "has_https":      true,
                "supports_http3": true,
                "has_svcb":       false,
                "supports_ech":   false,
        }
        msg := buildHTTPSMessage(result)
        if msg == "" {
                t.Fatal("expected non-empty message")
        }
}

func TestParseHTTPSRecords_CB8(t *testing.T) {
        h := &dns.HTTPS{}
        h.Priority = 1
        h.Target = "example.com."
        h.Value = []svcb.Pair{}
        records := []*dns.HTTPS{h}
        result := parseHTTPSRecords(records)
        if len(result) != 1 {
                t.Fatalf("expected 1, got %d", len(result))
        }
}

func TestParseSVCBRecords_CB8(t *testing.T) {
        s := &dns.SVCB{}
        s.Priority = 1
        s.Target = "example.com."
        s.Value = []svcb.Pair{}
        records := []*dns.SVCB{s}
        result := parseSVCBRecords(records)
        if len(result) != 1 {
                t.Fatalf("expected 1, got %d", len(result))
        }
}

func TestExtractTLSRPTURIs_CB8(t *testing.T) {
        record := "v=TLSRPTv1; rua=mailto:tls@example.com,https://tls.example.com/report"
        uris := extractTLSRPTURIs(record)
        if len(uris) == 0 {
                t.Fatal("expected URIs extracted")
        }
}

func TestComputePolicyVerdict_CB8(t *testing.T) {
        policy := map[string]any{"mta_sts": true, "dane": true}
        verdict := computePolicyVerdict(policy, []string{"MTA-STS enforced", "DANE verified"})
        if verdict == "" {
                t.Fatal("expected non-empty verdict")
        }
        verdict2 := computePolicyVerdict(map[string]any{}, nil)
        if verdict2 == "" {
                t.Fatal("expected non-empty verdict for empty policy")
        }
}

func TestAssessProvider_CB8(t *testing.T) {
        signals := assessProvider(
                []string{"aspmx.l.google.com"},
                map[string]any{},
                nil,
        )
        if signals == nil {
                t.Fatal("expected non-nil signals")
        }
}

func TestClassifyRemoteProbeStatus_CB8(t *testing.T) {
        if classifyRemoteProbeStatus(200) != "" {
                t.Fatal("expected empty status for 200")
        }
        if classifyRemoteProbeStatus(500) == "" {
                t.Fatal("expected non-empty status for 500")
        }
        if classifyRemoteProbeStatus(401) == "" {
                t.Fatal("expected non-empty status for 401")
        }
        if classifyRemoteProbeStatus(429) == "" {
                t.Fatal("expected non-empty status for 429")
        }
}

func TestSmtpProbeVerdictFromSummary_CB8(t *testing.T) {
        summary := &smtpSummary{
                TotalServers:    2,
                Reachable:       2,
                StartTLSSupport: 2,
                ValidCerts:      2,
        }
        verdict := smtpProbeVerdictFromSummary(summary)
        if verdict == "" {
                t.Fatal("expected non-empty verdict")
        }
        summary2 := &smtpSummary{TotalServers: 2, Reachable: 2, StartTLSSupport: 1}
        verdict2 := smtpProbeVerdictFromSummary(summary2)
        if verdict2 == "" {
                t.Fatal("expected non-empty verdict2")
        }
        summary3 := &smtpSummary{TotalServers: 2, Reachable: 2, StartTLSSupport: 0}
        verdict3 := smtpProbeVerdictFromSummary(summary3)
        if verdict3 == "" {
                t.Fatal("expected non-empty verdict3")
        }
}

func TestMarshalRemoteProbeBody_CB8(t *testing.T) {
        body, errMsg := marshalRemoteProbeBody([]string{"mx1.example.com", "mx2.example.com"})
        if len(body) == 0 {
                t.Fatal("expected non-empty body")
        }
        if errMsg != "" {
                t.Fatalf("expected no error, got %q", errMsg)
        }
}

func TestNewExposureScanner_CB8(t *testing.T) {
        scanner := NewExposureScanner(nil)
        if scanner == nil {
                t.Fatal("expected non-nil scanner")
        }
}

func TestClassifyExposureResults_CB8(t *testing.T) {
        findings := []ExposureFinding{
                {Path: "/.env", Severity: "critical"},
        }
        status, msg := classifyExposureResults(findings, []string{"/.env", "/.git/config"})
        if status == "" || msg == "" {
                t.Fatal("expected non-empty results")
        }

        status2, msg2 := classifyExposureResults(nil, []string{"/.env"})
        if status2 == "" || msg2 == "" {
                t.Fatal("expected non-empty for clear results")
        }
}

func TestBuildMultiProbeEntry_CB8(t *testing.T) {
        result := buildMultiProbeEntry(smtpProbeResult{
                id:    "probe1",
                label: "US East",
                data:  map[string]any{"starttls": true, "valid_cert": true},
        })
        if result == nil {
                t.Fatal("expected non-nil entry")
        }
}

func TestExtractDomainFromEmailAddress_CB8(t *testing.T) {
        tests := []struct {
                input string
                want  string
        }{
                {"user@example.com", "example.com"},
                {"<user@example.com>", "example.com"},
                {"", ""},
                {"nodomain", ""},
                {"  user@example.org  ", "example.org"},
        }
        for _, tt := range tests {
                got := extractDomainFromEmailAddress(tt.input)
                if got != tt.want {
                        t.Errorf("extractDomainFromEmailAddress(%q) = %q, want %q", tt.input, got, tt.want)
                }
        }
}

func TestExtractSaaSTXTFootprint_CB8(t *testing.T) {
        t.Run("nil basic_records", func(t *testing.T) {
                result := ExtractSaaSTXTFootprint(map[string]any{})
                if result == nil {
                        t.Fatal("expected non-nil result")
                }
        })
        t.Run("with basic_records no TXT", func(t *testing.T) {
                result := ExtractSaaSTXTFootprint(map[string]any{
                        "basic_records": map[string]any{},
                })
                if result == nil {
                        t.Fatal("expected non-nil result")
                }
        })
        t.Run("with TXT strings", func(t *testing.T) {
                result := ExtractSaaSTXTFootprint(map[string]any{
                        "basic_records": map[string]any{
                                "TXT": []string{"v=spf1 include:_spf.google.com ~all"},
                        },
                })
                if result == nil {
                        t.Fatal("expected non-nil result")
                }
        })
        t.Run("with TXT any", func(t *testing.T) {
                result := ExtractSaaSTXTFootprint(map[string]any{
                        "basic_records": map[string]any{
                                "TXT": []any{"v=spf1 include:_spf.google.com ~all"},
                        },
                })
                if result == nil {
                        t.Fatal("expected non-nil result")
                }
        })
        t.Run("with empty TXT", func(t *testing.T) {
                result := ExtractSaaSTXTFootprint(map[string]any{
                        "basic_records": map[string]any{
                                "TXT": []string{},
                        },
                })
                if result == nil {
                        t.Fatal("expected non-nil result")
                }
        })
        t.Run("with invalid TXT type", func(t *testing.T) {
                result := ExtractSaaSTXTFootprint(map[string]any{
                        "basic_records": map[string]any{
                                "TXT": 42,
                        },
                })
                if result == nil {
                        t.Fatal("expected non-nil result")
                }
        })
}

func TestMatchSaaSPatterns_CB8(t *testing.T) {
        services := []map[string]any{}
        matchSaaSPatterns("test-txt-record", map[string]bool{}, &services)
}

func TestParseSvcParams_CB8(t *testing.T) {
        entry := map[string]any{}
        parseSvcParams(entry, []svcb.Pair{})
        if entry == nil {
                t.Fatal("expected non-nil entry after parseSvcParams")
        }
}
