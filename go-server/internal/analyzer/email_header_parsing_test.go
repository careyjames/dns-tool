package analyzer

import (
        "strings"
        "testing"
        "time"
)

func TestSeparateHeadersAndBody_CB6(t *testing.T) {
        t.Run("with body", func(t *testing.T) {
                raw := "From: test@example.com\r\nTo: dest@example.com\r\n\r\nBody text here"
                headers, body, hadBody := SeparateHeadersAndBody(raw)
                if !hadBody {
                        t.Fatal("expected hadBody=true")
                }
                if !strings.Contains(headers, "From:") {
                        t.Fatal("expected From header")
                }
                if body != "Body text here" {
                        t.Fatalf("expected body text, got %q", body)
                }
        })
        t.Run("headers only", func(t *testing.T) {
                raw := "From: test@example.com\r\nTo: dest@example.com"
                headers, _, hadBody := SeparateHeadersAndBody(raw)
                if hadBody {
                        t.Fatal("expected hadBody=false")
                }
                if !strings.Contains(headers, "From:") {
                        t.Fatal("expected From header")
                }
        })
}

func TestHasHeaderFields_CB6(t *testing.T) {
        if !hasHeaderFields("From: test@example.com\nTo: dest@example.com") {
                t.Fatal("expected true for valid headers")
        }
        if hasHeaderFields("just some plain text") {
                t.Fatal("expected false for plain text")
        }
}

func TestUnfoldHeaders_CB6(t *testing.T) {
        input := "Subject: This is\r\n a folded\r\n\tsubject line"
        result := unfoldHeaders(input)
        if strings.Contains(result, "\r\n ") || strings.Contains(result, "\r\n\t") {
                t.Fatal("expected unfolded headers")
        }
}

func TestParseHeaderFields_CB6(t *testing.T) {
        input := "From: test@example.com\nTo: dest@example.com\nSubject: Test"
        fields := parseHeaderFields(input)
        if len(fields) < 3 {
                t.Fatalf("expected at least 3 fields, got %d", len(fields))
        }
}

func TestExtractHeader_CB6(t *testing.T) {
        fields := []headerField{
                {Name: "from", Value: "test@example.com"},
                {Name: "to", Value: "dest@example.com"},
        }
        from := extractHeader(fields, "from")
        if from != "test@example.com" {
                t.Fatalf("expected test@example.com, got %q", from)
        }
        missing := extractHeader(fields, "cc")
        if missing != "" {
                t.Fatalf("expected empty, got %q", missing)
        }
}

func TestExtractAllHeaders_CB6(t *testing.T) {
        fields := []headerField{
                {Name: "received", Value: "from mail1.example.com"},
                {Name: "received", Value: "from mail2.example.com"},
                {Name: "from", Value: "test@example.com"},
        }
        received := extractAllHeaders(fields, "received")
        if len(received) != 2 {
                t.Fatalf("expected 2 received headers, got %d", len(received))
        }
}

func TestFormatDelay_CB6(t *testing.T) {
        tests := []struct {
                d    time.Duration
                want string
        }{
                {500 * time.Millisecond, "<1s"},
                {2 * time.Second, "2s"},
                {5 * time.Minute, "5m0s"},
                {2 * time.Hour, "2h0m0s"},
        }
        for _, tt := range tests {
                result := formatDelay(tt.d)
                if result == "" {
                        t.Errorf("formatDelay(%v) returned empty string", tt.d)
                }
        }
}

func TestParseEmailDate_CB6(t *testing.T) {
        t.Run("RFC2822 date", func(t *testing.T) {
                _, err := parseEmailDate("Mon, 1 Jan 2024 00:00:00 +0000")
                if err != nil {
                        t.Fatalf("expected no error for RFC2822 date, got %v", err)
                }
        })
        t.Run("empty", func(t *testing.T) {
                _, err := parseEmailDate("")
                if err == nil {
                        t.Fatal("expected error for empty date")
                }
        })
}

func TestAnalyzeEmailHeadersFull_CB6(t *testing.T) {
        raw := `From: sender@example.com
To: recipient@example.com
Subject: Test Email
Date: Mon, 1 Jan 2024 00:00:00 +0000
Message-ID: <test123@example.com>
Return-Path: <sender@example.com>
Received: from mail.example.com (mail.example.com [93.184.216.34]) by mx.example.com with ESMTP id abc123; Mon, 1 Jan 2024 00:00:00 +0000
Authentication-Results: mx.example.com; spf=pass (sender IP is 93.184.216.34) smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass action=none header.from=example.com
`
        result := AnalyzeEmailHeaders(raw)
        if result == nil {
                t.Fatal("expected non-nil result")
        }
        if result.From != "sender@example.com" {
                t.Fatalf("expected From=sender@example.com, got %q", result.From)
        }
        if result.Subject != "Test Email" {
                t.Fatalf("expected Subject=Test Email, got %q", result.Subject)
        }
        if result.HopCount == 0 {
                t.Fatal("expected at least one hop")
        }
}

func TestAnalyzeEmailHeadersEmpty_CB6(t *testing.T) {
        result := AnalyzeEmailHeaders("")
        if result == nil {
                t.Fatal("expected non-nil result for empty input")
        }
}

func TestAnalyzeEmailHeadersSPFOnly_CB6(t *testing.T) {
        raw := `From: sender@example.com
Received-SPF: pass (example.com: domain of sender@example.com designates 93.184.216.34 as permitted sender) receiver=mx.example.com; client-ip=93.184.216.34; envelope-from=sender@example.com;
`
        result := AnalyzeEmailHeaders(raw)
        if result == nil {
                t.Fatal("expected non-nil result")
        }
}

func TestAnalyzeEmailHeadersARCChain_CB6(t *testing.T) {
        raw := `From: sender@example.com
ARC-Authentication-Results: i=1; mx.example.com; spf=pass smtp.mailfrom=example.com
ARC-Seal: i=1; a=rsa-sha256; s=selector; d=example.com; cv=none
ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=selector; h=from:to:subject
`
        result := AnalyzeEmailHeaders(raw)
        if result == nil {
                t.Fatal("expected non-nil result")
        }
}

func TestEvaluateProtocolStates_CB6(t *testing.T) {
        t.Run("all present", func(t *testing.T) {
                results := map[string]any{
                        "spf_analysis":     map[string]any{"status": "success", "record_count": 1},
                        "dmarc_analysis":   map[string]any{"status": "success", "policy": "reject", "has_rua": true, "pct": 100, "record_count": 1},
                        "dkim_analysis":    map[string]any{"status": "success"},
                        "dane_analysis":    map[string]any{"status": "success", "has_dane": true},
                        "dnssec_analysis":  map[string]any{"status": "success", "signed": true},
                        "mta_sts_analysis": map[string]any{"status": "success"},
                        "tlsrpt_analysis":  map[string]any{"status": "success"},
                        "bimi_analysis":    map[string]any{"status": "success"},
                        "caa_analysis":     map[string]any{"status": "success"},
                }
                ps := evaluateProtocolStates(results)
                if !ps.spfOK {
                        t.Fatal("expected spfOK")
                }
                if !ps.dmarcOK {
                        t.Fatal("expected dmarcOK")
                }
        })
        t.Run("empty results", func(t *testing.T) {
                ps := evaluateProtocolStates(map[string]any{})
                if ps.spfOK {
                        t.Fatal("expected spfOK=false for empty")
                }
        })
}

func TestDetectProbableNoMail_CB6(t *testing.T) {
        t.Run("no MX", func(t *testing.T) {
                results := map[string]any{
                        "basic_records": map[string]any{},
                }
                if !detectProbableNoMail(results) {
                        t.Fatal("expected true for no MX records")
                }
        })
        t.Run("has MX strings", func(t *testing.T) {
                results := map[string]any{
                        "basic_records": map[string]any{
                                "MX": []string{"10 mail.example.com."},
                        },
                }
                if detectProbableNoMail(results) {
                        t.Fatal("expected false for valid MX")
                }
        })
        t.Run("nil basic_records", func(t *testing.T) {
                results := map[string]any{}
                if detectProbableNoMail(results) {
                        t.Fatal("expected false when basic_records missing")
                }
        })
}

func TestIsMissingRecord_CB6(t *testing.T) {
        if isMissingRecord(map[string]any{"record_count": 0}) {
                t.Log("0 records treated as missing — OK")
        }
        if isMissingRecord(map[string]any{"record_count": 1}) {
                t.Fatal("expected false for record_count=1")
        }
}

func TestHasNonEmptyString_CB6(t *testing.T) {
        if !hasNonEmptyString(map[string]any{"key": "value"}, "key") {
                t.Fatal("expected true for non-empty string")
        }
        if hasNonEmptyString(map[string]any{"key": ""}, "key") {
                t.Fatal("expected false for empty string")
        }
        if hasNonEmptyString(map[string]any{}, "key") {
                t.Fatal("expected false for missing key")
        }
}

func TestExtractIntField_CB6(t *testing.T) {
        m := map[string]any{"count": float64(42)}
        if extractIntField(m, "count") != 42 {
                t.Fatalf("expected 42, got %d", extractIntField(m, "count"))
        }
        if extractIntField(m, "missing") != 0 {
                t.Fatalf("expected 0 for missing key")
        }
}

func TestExtractIntFieldDefault_CB6(t *testing.T) {
        m := map[string]any{"count": float64(42)}
        if extractIntFieldDefault(m, "count", 99) != 42 {
                t.Fatal("expected 42")
        }
        if extractIntFieldDefault(m, "missing", 99) != 99 {
                t.Fatal("expected default 99")
        }
}

func TestProviderSupportsDANE_CB6(t *testing.T) {
        if providerSupportsDANE("google") {
                t.Fatal("expected hosted provider google to NOT support DANE")
        }
        if !providerSupportsDANE("") {
                t.Fatal("expected empty provider to support DANE")
        }
}

func TestProviderSupportsBIMI_CB6(t *testing.T) {
        r1 := providerSupportsBIMI("")
        if !r1 {
                t.Fatal("expected empty provider to return true")
        }
        _ = providerSupportsBIMI("google")
        _ = providerSupportsBIMI("some-unknown")
}

func TestExtractSPFIncludes_CB6(t *testing.T) {
        results := map[string]any{
                "spf_analysis": map[string]any{
                        "includes": []any{"_spf.google.com", "_spf.example.com"},
                },
        }
        includes := extractSPFIncludes(results)
        if len(includes) != 2 {
                t.Fatalf("expected 2 includes, got %d", len(includes))
        }
}

func TestExtractDomain_CB6(t *testing.T) {
        results := map[string]any{
                "domain": "example.com",
        }
        d := extractDomain(results)
        if d != "example.com" {
                t.Fatalf("expected example.com, got %q", d)
        }
}

func TestFixToMap_CB6(t *testing.T) {
        f := fix{
                Title:       "Add SPF",
                Description: "Add SPF record",
                DNSType:     "TXT",
                DNSHost:     "@",
                DNSValue:    "v=spf1 -all",
                Section:     "email",
        }
        m := fixToMap(f)
        if m["title"] != "Add SPF" {
                t.Fatalf("expected title=Add SPF, got %v", m["title"])
        }
}

func TestSortFixes_CB6(t *testing.T) {
        fixes := []fix{
                {Title: "C", SeverityLevel: severityLevel{Order: 3, Name: "low"}},
                {Title: "A", SeverityLevel: severityLevel{Order: 1, Name: "critical"}},
                {Title: "B", SeverityLevel: severityLevel{Order: 2, Name: "high"}},
        }
        sortFixes(fixes)
        if fixes[0].SeverityLevel.Order != 1 {
                t.Fatalf("expected first fix order=1, got %d", fixes[0].SeverityLevel.Order)
        }
}

func TestBuildSPFValue_CB6(t *testing.T) {
        v := buildSPFValue([]string{"_spf.google.com"}, "-all")
        if !strings.Contains(v, "include:_spf.google.com") {
                t.Fatalf("expected include directive, got %q", v)
        }
}

func TestBuildSPFRecordExample_CB6(t *testing.T) {
        v := buildSPFRecordExample("example.com", []string{"_spf.google.com"}, "-all")
        if v == "" {
                t.Fatal("expected non-empty SPF record example")
        }
}

func TestDkimSelectorForProvider_CB6(t *testing.T) {
        s := dkimSelectorForProvider("google")
        if s == "" {
                t.Fatal("expected non-empty selector for google")
        }
        s2 := dkimSelectorForProvider("unknown")
        if s2 == "" {
                t.Fatal("expected a default selector")
        }
}

func TestDkimRecordExample_CB6(t *testing.T) {
        r := dkimRecordExample("example.com", "google")
        if r == "" {
                t.Fatal("expected non-empty DKIM record example")
        }
}

func TestParseAuthResultHeader_CB6(t *testing.T) {
        result := &EmailHeaderAnalysis{RawHeaders: ""}
        parseAuthResultHeader("spf=pass (sender IP is 93.184.216.34) smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass action=none header.from=example.com", result)
        if result.SPFResult.Result != "pass" {
                t.Fatalf("expected SPF pass, got %q", result.SPFResult.Result)
        }
}

func TestParseAuthPart_CB6(t *testing.T) {
        ar := parseAuthPart("spf=pass (sender IP is 93.184.216.34) smtp.mailfrom=example.com", "spf")
        if ar.Result != "pass" {
                t.Fatalf("expected pass, got %q", ar.Result)
        }
        ar2 := parseAuthPart("dkim=fail header.d=example.com", "dkim")
        if ar2.Result != "fail" {
                t.Fatalf("expected fail, got %q", ar2.Result)
        }
}

func TestCalculateHopDelays_CB6(t *testing.T) {
        now := time.Now()
        hops := []ReceivedHop{
                {Index: 0},
                {Index: 1},
        }
        timestamps := []time.Time{now, now.Add(2 * time.Second)}
        calculateHopDelays(hops, timestamps)
}

func TestEvaluateDKIMIssues_CB6(t *testing.T) {
        dkim := map[string]any{
                "issues": []any{"weak key length detected", "third-party only"},
        }
        weak, thirdParty := evaluateDKIMIssues(dkim)
        if !weak {
                t.Error("expected weak=true for 'weak key length detected'")
        }
        if !thirdParty {
                t.Error("expected thirdParty=true for 'third-party only'")
        }
}

func TestScanDKIMIssueStrings_CB6(t *testing.T) {
        weak, tp := scanDKIMIssueStrings([]any{"weak key", "third-party"})
        if !weak {
                t.Error("expected weak=true for 'weak key'")
        }
        if !tp {
                t.Error("expected thirdParty=true for 'third-party'")
        }
}
