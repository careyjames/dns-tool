// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
        "context"
        "fmt"
        "testing"
        "time"
)

func TestDetectDNSLink_IPFS_B14(t *testing.T) {
        txt := []string{"dnslink=/ipfs/QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"}
        result := AnalyzeWeb3Static(txt, nil)
        if !result["detected"].(bool) {
                t.Fatal("expected Web3 detected for IPFS dnslink")
        }
        indicators := result["indicators"].([]map[string]any)
        if len(indicators) == 0 {
                t.Fatal("expected at least one indicator")
        }
        if indicators[0]["type"] != indicatorTypeDNSLink {
                t.Errorf("expected type=%q, got %q", indicatorTypeDNSLink, indicators[0]["type"])
        }
        if result["dnslink_cid"] != "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG" {
                t.Errorf("unexpected CID: %v", result["dnslink_cid"])
        }
}

func TestDetectDNSLink_IPNS_B14(t *testing.T) {
        txt := []string{"dnslink=/ipns/example.com"}
        result := AnalyzeWeb3Static(txt, nil)
        if !result["detected"].(bool) {
                t.Fatal("expected Web3 detected for IPNS dnslink")
        }
        indicators := result["indicators"].([]map[string]any)
        if indicators[0]["type"] != indicatorTypeIPNSName {
                t.Errorf("expected type=%q, got %q", indicatorTypeIPNSName, indicators[0]["type"])
        }
        if result["dnslink_ipns"] != "example.com" {
                t.Errorf("unexpected IPNS name: %v", result["dnslink_ipns"])
        }
}

func TestDetectCryptoWallet_ETH_B14(t *testing.T) {
        txt := []string{"0x742d35Cc6634C0532925a3b844Bc9e7595f2bD12"}
        result := AnalyzeWeb3Static(txt, nil)
        if !result["detected"].(bool) {
                t.Fatal("expected Web3 detected for ETH wallet")
        }
        indicators := result["indicators"].([]map[string]any)
        if indicators[0]["type"] != indicatorTypeCryptoWallet {
                t.Errorf("expected type=%q, got %q", indicatorTypeCryptoWallet, indicators[0]["type"])
        }
        if indicators[0]["value"] == txt[0] {
                t.Error("wallet address should be redacted")
        }
}

func TestDetectCryptoWallet_BTC_B14(t *testing.T) {
        txt := []string{"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"}
        result := AnalyzeWeb3Static(txt, nil)
        if !result["detected"].(bool) {
                t.Fatal("expected Web3 detected for BTC wallet")
        }
}

func TestDetectENSRecord_B14(t *testing.T) {
        txt := []string{"contenthash=0xe301017012..."}
        result := AnalyzeWeb3Static(txt, nil)
        if !result["detected"].(bool) {
                t.Fatal("expected Web3 detected for ENS contenthash")
        }
        indicators := result["indicators"].([]map[string]any)
        if indicators[0]["type"] != indicatorTypeENSRecord {
                t.Errorf("expected type=%q, got %q", indicatorTypeENSRecord, indicators[0]["type"])
        }
}

func TestNoWeb3Detected_B14(t *testing.T) {
        txt := []string{"v=spf1 include:_spf.google.com ~all", "google-site-verification=abc123"}
        result := AnalyzeWeb3Static(txt, nil)
        if result["detected"].(bool) {
                t.Fatal("should not detect Web3 for standard TXT records")
        }
        if result["status"] != web3StatusNotDetected {
                t.Errorf("expected status=%q, got %q", web3StatusNotDetected, result["status"])
        }
}

func TestWeb3EmptyTXT_B14(t *testing.T) {
        result := AnalyzeWeb3Static(nil, nil)
        if result["detected"].(bool) {
                t.Fatal("should not detect Web3 for nil TXT records")
        }
        if result["indicator_count"].(int) != 0 {
                t.Errorf("expected indicator_count=0, got %v", result["indicator_count"])
        }
}

func TestDNSSECTrustNote_Success_B14(t *testing.T) {
        dnssec := map[string]any{"status": "success"}
        result := AnalyzeWeb3Static(nil, dnssec)
        note := result["dnssec_trust_note"].(string)
        if note == "" {
                t.Fatal("expected non-empty DNSSEC trust note")
        }
        if !containsB14(note, "validated") {
                t.Errorf("success DNSSEC should mention 'validated', got: %s", note)
        }
        trust := result["dnssec_trust"].(map[string]any)
        if !trust["dnssec_present"].(bool) {
                t.Error("expected dnssec_present=true")
        }
        if !trust["dnssec_valid"].(bool) {
                t.Error("expected dnssec_valid=true")
        }
}

func TestDNSSECTrustNote_Warning_B14(t *testing.T) {
        dnssec := map[string]any{"status": "warning"}
        result := AnalyzeWeb3Static(nil, dnssec)
        note := result["dnssec_trust_note"].(string)
        if !containsB14(note, "partially") {
                t.Errorf("warning DNSSEC should mention 'partially', got: %s", note)
        }
        trust := result["dnssec_trust"].(map[string]any)
        if !trust["dnssec_present"].(bool) {
                t.Error("expected dnssec_present=true for warning")
        }
        if trust["dnssec_valid"].(bool) {
                t.Error("expected dnssec_valid=false for warning")
        }
}

func TestDNSSECTrustNote_Missing_B14(t *testing.T) {
        dnssec := map[string]any{"status": "error"}
        result := AnalyzeWeb3Static(nil, dnssec)
        note := result["dnssec_trust_note"].(string)
        if !containsB14(note, "not configured") {
                t.Errorf("missing DNSSEC should mention 'not configured', got: %s", note)
        }
}

func TestDNSSECTrustNote_Nil_B14(t *testing.T) {
        result := AnalyzeWeb3Static(nil, nil)
        note := result["dnssec_trust_note"].(string)
        if !containsB14(note, "unknown") {
                t.Errorf("nil DNSSEC should mention 'unknown', got: %s", note)
        }
}

func TestIsValidCID_V0_B14(t *testing.T) {
        if !IsValidCID("QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG") {
                t.Error("expected valid CIDv0")
        }
}

func TestIsValidCID_V1_B14(t *testing.T) {
        cid := "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
        if !IsValidCID(cid) {
                t.Error("expected valid CIDv1")
        }
}

func TestIsValidCID_Invalid_B14(t *testing.T) {
        invalids := []string{"", "hello", "Qm123", "notacid"}
        for _, c := range invalids {
                if IsValidCID(c) {
                        t.Errorf("expected invalid CID for %q", c)
                }
        }
}

func TestTruncateCID_B14(t *testing.T) {
        short := "QmShort"
        if truncateCID(short) != short {
                t.Errorf("short CID should not be truncated")
        }
        long := "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
        truncated := truncateCID(long)
        if len(truncated) >= len(long) {
                t.Errorf("long CID should be truncated")
        }
}

func TestTruncateStr_B14(t *testing.T) {
        short := "hello"
        if truncateStr(short, 10) != short {
                t.Errorf("short string should not be truncated")
        }
        long := "this is a very long string that exceeds the limit"
        truncated := truncateStr(long, 20)
        if len(truncated) > 20 {
                t.Errorf("expected truncated to <= 20 chars, got %d", len(truncated))
        }
}

func TestRedactWalletAddress_B14(t *testing.T) {
        addr := "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD12"
        redacted := redactWalletAddress(addr)
        if redacted == addr {
                t.Error("address should be redacted")
        }
        if len(redacted) >= len(addr) {
                t.Errorf("redacted should be shorter than original")
        }

        short := "0xABCD"
        if redactWalletAddress(short) != short {
                t.Error("short address should not be redacted")
        }
}

func TestExtractTXTFromBasicRecords_B14(t *testing.T) {
        tests := []struct {
                name     string
                input    map[string]any
                expected int
        }{
                {"nil map", nil, 0},
                {"no TXT key", map[string]any{"A": []string{"1.2.3.4"}}, 0},
                {"string slice", map[string]any{"TXT": []string{"v=spf1", "dnslink=/ipfs/Qm123"}}, 2},
                {"any slice", map[string]any{"TXT": []any{"v=spf1", "dnslink=/ipfs/Qm123"}}, 2},
                {"any slice with non-string", map[string]any{"TXT": []any{"v=spf1", 42}}, 1},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        result := ExtractTXTFromBasicRecords(tt.input)
                        if len(result) != tt.expected {
                                t.Errorf("expected %d TXT records, got %d", tt.expected, len(result))
                        }
                })
        }
}

func TestDefaultWeb3Analysis_B14(t *testing.T) {
        d := DefaultWeb3Analysis()
        if d["detected"].(bool) {
                t.Error("default should not be detected")
        }
        if d["status"] != web3StatusNotDetected {
                t.Errorf("default status should be %q", web3StatusNotDetected)
        }
        if d["indicator_count"].(int) != 0 {
                t.Error("default indicator_count should be 0")
        }
        trust, ok := d["dnssec_trust"].(map[string]any)
        if !ok {
                t.Fatal("expected dnssec_trust map")
        }
        if trust["dnssec_present"].(bool) {
                t.Error("default should have dnssec_present=false")
        }
}

func TestMultipleIndicators_B14(t *testing.T) {
        txt := []string{
                "dnslink=/ipfs/QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",
                "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD12",
                "contenthash=0xe301017012abc",
        }
        result := AnalyzeWeb3Static(txt, map[string]any{"status": "success"})
        if !result["detected"].(bool) {
                t.Fatal("expected Web3 detected")
        }
        indicators := result["indicators"].([]map[string]any)
        if len(indicators) != 3 {
                t.Errorf("expected 3 indicators, got %d", len(indicators))
        }
        if result["indicator_count"].(int) != 3 {
                t.Errorf("expected indicator_count=3, got %v", result["indicator_count"])
        }
}

func TestAnalyzeWeb3WithAnalyzer_B14(t *testing.T) {
        a := &Analyzer{DNS: NewMockDNSClient()}
        ctx := context.Background()
        txt := []string{"dnslink=/ipns/example.com"}
        dnssec := map[string]any{"status": "success"}
        result := a.AnalyzeWeb3(ctx, "example.com", txt, dnssec)
        if !result["detected"].(bool) {
                t.Fatal("expected Web3 detected")
        }
        if result["dnslink_ipns"] != "example.com" {
                t.Errorf("expected IPNS name example.com")
        }
}

func TestClassifyWeb3HTTPError_B14(t *testing.T) {
        tests := []struct {
                errMsg   string
                expected string
        }{
                {"connection timeout", "timeout"},
                {"connection refused", "connection refused"},
                {"no such host", "DNS resolution failed"},
                {"other error", "connection error"},
        }
        for _, tt := range tests {
                t.Run(tt.errMsg, func(t *testing.T) {
                        result := classifyWeb3HTTPError(fmt.Errorf("%s", tt.errMsg))
                        if result != tt.expected {
                                t.Errorf("expected %q, got %q", tt.expected, result)
                        }
                })
        }
}

func TestWeb3ToMap_AllFields_B14(t *testing.T) {
        t1 := true
        w := &Web3Analysis{
                Detected:       true,
                Status:         web3StatusDetected,
                Indicators:     []Web3Indicator{{Type: indicatorTypeDNSLink, Value: "dnslink=/ipfs/QmTest", Description: "test", Link: "https://dweb.link/ipfs/QmTest", EvidenceClass: "protocol_binding"}},
                DNSLinkCID:     "QmTest",
                DNSLinkIPNS:    "example.com",
                DNSLinkSource:  "root_txt",
                IPFSReachable:  &t1,
                IPFSGatewayURL: "https://dweb.link/ipfs/QmTest",
                DNSSECTrust:    Web3DNSSECTrust{Present: true, Valid: true, Status: "validated"},
                IPFSProbe: &IPFSProbe{
                        Namespace:           "ipfs",
                        CIDOrName:           "QmTest",
                        ReachableViaAny:     true,
                        ReachableViaAll:     false,
                        GatewaysTested:      []string{"https://dweb.link"},
                        GatewaysReachable:   []string{"https://dweb.link"},
                        TrustMode:           trustModeGatewayTrusted,
                        PersistenceUnproven: true,
                },
                ResolutionInfo: map[string]any{"method": "eth.limo"},
                IndicatorCount: 1,
        }
        m := w.toMap()
        if !m["detected"].(bool) {
                t.Error("expected detected=true")
        }
        if m["dnslink_cid"] != "QmTest" {
                t.Error("expected dnslink_cid")
        }
        if m["dnslink_ipns"] != "example.com" {
                t.Error("expected dnslink_ipns")
        }
        if m["dnslink_source"] != "root_txt" {
                t.Error("expected dnslink_source=root_txt")
        }
        if !m["ipfs_reachable"].(bool) {
                t.Error("expected ipfs_reachable=true")
        }
        if m["ipfs_gateway_url"] != "https://dweb.link/ipfs/QmTest" {
                t.Error("expected ipfs_gateway_url")
        }
        if m["resolution_info"] == nil {
                t.Error("expected resolution_info")
        }

        probe, ok := m["ipfs_probe"].(map[string]any)
        if !ok {
                t.Fatal("expected ipfs_probe map")
        }
        if probe["namespace"] != "ipfs" {
                t.Error("expected namespace=ipfs")
        }
        if probe["trust_mode"] != trustModeGatewayTrusted {
                t.Error("expected trust_mode=gateway_trusted")
        }
        if !probe["persistence_unproven"].(bool) {
                t.Error("expected persistence_unproven=true")
        }
        if !probe["reachable_via_any"].(bool) {
                t.Error("expected reachable_via_any=true")
        }

        indicators := m["indicators"].([]map[string]any)
        if indicators[0]["evidence_class"] != "protocol_binding" {
                t.Error("expected evidence_class=protocol_binding")
        }
}

func TestVerifyIPFSReachability_InvalidCID_B14(t *testing.T) {
        w := &Web3Analysis{
                DNSLinkCID: "invalid-cid",
        }
        w.verifyIPFSReachability(context.Background())
        if w.IPFSReachable == nil || *w.IPFSReachable {
                t.Error("expected IPFSReachable=false for invalid CID")
        }
        if w.IPFSError != "Invalid IPFS CID format" {
                t.Errorf("unexpected error: %s", w.IPFSError)
        }
        if w.IPFSProbe == nil {
                t.Fatal("expected IPFSProbe set")
        }
        if w.IPFSProbe.TrustMode != trustModeGatewayTrusted {
                t.Error("expected trust_mode=gateway_trusted")
        }
}

func TestVerifyIPFSReachability_EmptyCID_B14(t *testing.T) {
        w := &Web3Analysis{}
        w.verifyIPFSReachability(context.Background())
        if w.IPFSReachable != nil {
                t.Error("expected IPFSReachable=nil for empty CID")
        }
}

func TestDNSLinkCaseInsensitive_B14(t *testing.T) {
        txt := []string{"DNSLINK=/IPFS/QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"}
        result := AnalyzeWeb3Static(txt, nil)
        if !result["detected"].(bool) {
                t.Fatal("expected case-insensitive dnslink detection")
        }
}

func TestIndicatorLink_B14(t *testing.T) {
        txt := []string{"dnslink=/ipfs/QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"}
        result := AnalyzeWeb3Static(txt, nil)
        indicators := result["indicators"].([]map[string]any)
        link, ok := indicators[0]["link"].(string)
        if !ok || link == "" {
                t.Error("expected non-empty link for IPFS dnslink indicator")
        }
}

func TestWalletPrefixedForms_B14(t *testing.T) {
        cases := []struct {
                name string
                txt  string
        }{
                {"ETH= prefix", "ETH=0x742d35Cc6634C0532925a3b844Bc9e7595f2bD12"},
                {"eth.addr= prefix", "eth.addr=0x742d35Cc6634C0532925a3b844Bc9e7595f2bD12"},
                {"addr: prefix ETH", "addr: 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD12"},
                {"bare ETH", "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD12"},
                {"BTC= prefix", "BTC=13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so"},
                {"btc.addr= prefix", "btc.addr=13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so"},
                {"bare BTC", "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so"},
        }
        for _, tc := range cases {
                t.Run(tc.name, func(t *testing.T) {
                        result := AnalyzeWeb3Static([]string{tc.txt}, nil)
                        if !result["detected"].(bool) {
                                t.Fatalf("expected Web3 detected for %q", tc.txt)
                        }
                })
        }
}

func TestDefaultWeb3Analysis_BackwardCompat_B14(t *testing.T) {
        d := DefaultWeb3Analysis()
        if d["detected"].(bool) {
                t.Error("default should not be detected")
        }
        if d["status"] != web3StatusNotDetected {
                t.Errorf("expected status=%q, got %q", web3StatusNotDetected, d["status"])
        }
        if d["indicator_count"].(int) != 0 {
                t.Error("expected 0 indicators")
        }
        indicators, ok := d["indicators"].([]Web3Indicator)
        if !ok {
                t.Fatal("indicators must be []Web3Indicator")
        }
        if indicators == nil {
                t.Error("indicators must be non-nil slice")
        }
}

func TestPhaseGroupMapping_B14(t *testing.T) {
        group := LookupPhaseGroup("web3_analysis")
        if group != "web3_analysis" {
                t.Errorf("expected web3_analysis phase group, got %q", group)
        }
}

func TestNoDetection_PlainTXT_B14(t *testing.T) {
        txt := []string{"v=spf1 include:_spf.google.com ~all", "google-site-verification=abc123"}
        result := AnalyzeWeb3Static(txt, nil)
        if result["detected"].(bool) {
                t.Error("plain DNS TXT records should not trigger Web3 detection")
        }
}

func TestEvidenceClass_B16(t *testing.T) {
        txt := []string{
                "dnslink=/ipfs/QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",
                "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD12",
                "contenthash=0xe301017012abc",
        }
        result := AnalyzeWeb3Static(txt, nil)
        indicators := result["indicators"].([]map[string]any)
        if indicators[0]["evidence_class"] != "protocol_binding" {
                t.Errorf("dnslink should be protocol_binding, got %v", indicators[0]["evidence_class"])
        }
        if indicators[1]["evidence_class"] != "identity_metadata" {
                t.Errorf("wallet should be identity_metadata, got %v", indicators[1]["evidence_class"])
        }
        if indicators[2]["evidence_class"] != "protocol_binding" {
                t.Errorf("ens record should be protocol_binding, got %v", indicators[2]["evidence_class"])
        }
}

func TestDNSSECTrustStruct_B16(t *testing.T) {
        dnssec := map[string]any{"status": "success"}
        result := AnalyzeWeb3Static(nil, dnssec)
        trust, ok := result["dnssec_trust"].(map[string]any)
        if !ok {
                t.Fatal("expected dnssec_trust to be a map")
        }
        if trust["status"] != "validated" {
                t.Errorf("expected status=validated, got %v", trust["status"])
        }
        if !trust["dnssec_present"].(bool) {
                t.Error("expected dnssec_present=true")
        }
        if !trust["dnssec_valid"].(bool) {
                t.Error("expected dnssec_valid=true")
        }
}

func TestDNSLinkSource_B16(t *testing.T) {
        txt := []string{"dnslink=/ipfs/QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"}
        result := AnalyzeWeb3Static(txt, nil)
        if result["dnslink_source"] != "root_txt" {
                t.Errorf("expected dnslink_source=root_txt, got %v", result["dnslink_source"])
        }
}

func TestInputClassification_B16(t *testing.T) {
        tests := []struct {
                domain   string
                expected InputKind
        }{
                {"vitalik.eth", InputKindENSName},
                {"example.hns", InputKindHNSName},
                {"example.forever", InputKindHNSName},
                {"example.com", InputKindDNSDomain},
                {"sub.example.com", InputKindDNSDomain},
        }
        for _, tt := range tests {
                t.Run(tt.domain, func(t *testing.T) {
                        kind := ClassifyInput(tt.domain)
                        if kind != tt.expected {
                                t.Errorf("ClassifyInput(%q) = %q, want %q", tt.domain, kind, tt.expected)
                        }
                })
        }
}

func TestIsGatewayDomain_B16(t *testing.T) {
        if !isGatewayDomain("vitalik.eth.limo", "eth.limo") {
                t.Error("vitalik.eth.limo should be a gateway domain for eth.limo")
        }
        if isGatewayDomain("example.com", "eth.limo") {
                t.Error("example.com should NOT be a gateway domain for eth.limo")
        }
}

func TestWeb3ResolutionToMap_B16(t *testing.T) {
        r := Web3ResolutionResult{
                IsWeb3Input:        true,
                InputDomain:        "test.eth",
                ResolvedDomain:     "test.eth.limo",
                ResolutionType:     "ens",
                Gateway:            "eth.limo",
                InputKind:          InputKindENSName,
                AnalysisScope:      ScopeGatewayDerived,
                IsGatewayDomain:    true,
                AttributionWarning: "test warning",
        }
        m := r.ToMap()
        if m["input_kind"] != "ens_name" {
                t.Errorf("expected input_kind=ens_name, got %v", m["input_kind"])
        }
        if m["analysis_scope"] != "gateway_derived" {
                t.Errorf("expected analysis_scope=gateway_derived, got %v", m["analysis_scope"])
        }
        if !m["is_gateway_domain"].(bool) {
                t.Error("expected is_gateway_domain=true")
        }
        if m["attribution_warning"] != "test warning" {
                t.Error("expected attribution_warning")
        }
}

func TestENSResolutionSetsGatewayFlag_B16(t *testing.T) {
        r := Web3ResolutionResult{
                IsWeb3Input:    true,
                InputDomain:    "vitalik.eth",
                ResolvedDomain: "vitalik.eth.limo",
                ResolutionType: "ens",
                Gateway:        "eth.limo",
                InputKind:      InputKindENSName,
        }
        r.IsGatewayDomain = isGatewayDomain(r.ResolvedDomain, r.Gateway)
        if !r.IsGatewayDomain {
                t.Error("ENS resolution to *.eth.limo should set IsGatewayDomain=true")
        }
}

func TestScopeGatewayDerived_SkipsEmailProtocols_B16(t *testing.T) {
        for key := range emailProtocolKeys {
                if key == "" {
                        t.Error("empty key in emailProtocolKeys")
                }
        }
        if !emailProtocolKeys["spf"] {
                t.Error("spf should be in emailProtocolKeys")
        }
        if !emailProtocolKeys["dmarc"] {
                t.Error("dmarc should be in emailProtocolKeys")
        }
        if !emailProtocolKeys["dkim"] {
                t.Error("dkim should be in emailProtocolKeys")
        }
}

func TestRenderDNSSECTrustNote_B16(t *testing.T) {
        tests := []struct {
                status   string
                contains string
        }{
                {"validated", "validated"},
                {"partial", "partially"},
                {"not_configured", "not configured"},
                {"unknown", "unknown"},
        }
        for _, tt := range tests {
                t.Run(tt.status, func(t *testing.T) {
                        note := renderDNSSECTrustNote(Web3DNSSECTrust{Status: tt.status})
                        if !containsB14(note, tt.contains) {
                                t.Errorf("expected note to contain %q, got: %s", tt.contains, note)
                        }
                })
        }
}

func TestDefaultWeb3Resolution_B16(t *testing.T) {
        d := DefaultWeb3Resolution()
        if d["input_kind"] != "dns_domain" {
                t.Errorf("expected input_kind=dns_domain, got %v", d["input_kind"])
        }
        if d["analysis_scope"] != "owned_dns" {
                t.Errorf("expected analysis_scope=owned_dns, got %v", d["analysis_scope"])
        }
        if d["is_gateway_domain"].(bool) {
                t.Error("expected is_gateway_domain=false")
        }
}

func TestScopeConstants_S007(t *testing.T) {
        if string(ScopeOwnedDNS) != "owned_dns" {
                t.Errorf("ScopeOwnedDNS = %q, want owned_dns", ScopeOwnedDNS)
        }
        if string(ScopeGatewayDerived) != "gateway_derived" {
                t.Errorf("ScopeGatewayDerived = %q, want gateway_derived", ScopeGatewayDerived)
        }
        if string(ScopeIdentityOnly) != "identity_only" {
                t.Errorf("ScopeIdentityOnly = %q, want identity_only", ScopeIdentityOnly)
        }
}

func TestInputKindConstants_S007(t *testing.T) {
        if string(InputKindDNSDomain) != "dns_domain" {
                t.Errorf("InputKindDNSDomain = %q", InputKindDNSDomain)
        }
        if string(InputKindENSName) != "ens_name" {
                t.Errorf("InputKindENSName = %q", InputKindENSName)
        }
        if string(InputKindHNSName) != "hns_name" {
                t.Errorf("InputKindHNSName = %q", InputKindHNSName)
        }
}

func TestBuildGatewayPosture_S007(t *testing.T) {
        results := map[string]any{"domain": "test.eth.limo"}
        posture := buildGatewayPosture(results)

        if posture["risk"] != "attribution_limited" {
                t.Errorf("risk = %q, want attribution_limited", posture["risk"])
        }
        if posture["risk_label"] != "Gateway Derived" {
                t.Errorf("risk_label = %q", posture["risk_label"])
        }
        if posture["score"] != 0 {
                t.Errorf("score = %v, want 0", posture["score"])
        }
        if posture["grade"] != "N/A" {
                t.Errorf("grade = %q", posture["grade"])
        }
        if posture["reason"] != "gateway_derived" {
                t.Errorf("reason = %q", posture["reason"])
        }
        if note, ok := posture["attribution_note"].(string); !ok || note == "" {
                t.Error("expected non-empty attribution_note")
        }
        for _, key := range []string{"issues", "recommendations", "monitoring", "configured", "absent", "provider_limited"} {
                arr, ok := posture[key].([]string)
                if !ok {
                        t.Errorf("%s should be []string", key)
                        continue
                }
                if len(arr) != 0 {
                        t.Errorf("%s should be empty, got %v", key, arr)
                }
        }
}

func TestBuildAnalysisProvenance_DNSDomain_S007(t *testing.T) {
        web3 := Web3ResolutionResult{}
        results := map[string]any{}
        p := buildAnalysisProvenance(InputKindDNSDomain, ScopeOwnedDNS, web3, results)

        if p["input_kind"] != "dns_domain" {
                t.Errorf("input_kind = %v", p["input_kind"])
        }
        if p["analysis_scope"] != "owned_dns" {
                t.Errorf("analysis_scope = %v", p["analysis_scope"])
        }
        if _, ok := p["resolution_type"]; ok {
                t.Error("non-web3 should not have resolution_type")
        }
}

func TestBuildAnalysisProvenance_ENS_S007(t *testing.T) {
        web3 := Web3ResolutionResult{
                IsWeb3Input:        true,
                ResolutionType:     "ens",
                IsGatewayDomain:    true,
                Gateway:            "eth.limo",
                AttributionWarning: "gateway attribution warning",
        }
        results := map[string]any{
                "web3_analysis": map[string]any{
                        "dnslink_source": "_dnslink",
                },
        }
        p := buildAnalysisProvenance(InputKindENSName, ScopeGatewayDerived, web3, results)

        if p["resolution_type"] != "ens" {
                t.Errorf("resolution_type = %v", p["resolution_type"])
        }
        if p["gateway_detected"] != true {
                t.Errorf("gateway_detected = %v", p["gateway_detected"])
        }
        if p["attribution_warning_emitted"] != true {
                t.Errorf("attribution_warning_emitted = %v", p["attribution_warning_emitted"])
        }
        if p["gateway"] != "eth.limo" {
                t.Errorf("gateway = %v", p["gateway"])
        }
        if p["dnslink_source"] != "_dnslink" {
                t.Errorf("dnslink_source = %v", p["dnslink_source"])
        }
}

func TestBuildAnalysisProvenance_SkipReason_S007(t *testing.T) {
        web3 := Web3ResolutionResult{}
        results := map[string]any{"skip_reason": "ssrf_blocked"}
        p := buildAnalysisProvenance(InputKindENSName, ScopeIdentityOnly, web3, results)
        if p["skip_reason"] != "ssrf_blocked" {
                t.Errorf("skip_reason = %v", p["skip_reason"])
        }
}

func TestDNSLinkPrimaryOrder_DNSLinkSubdomain_S007(t *testing.T) {
        dnslinkCID := "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
        rootCID := "QmOtherCID00000000000000000000000000000000000"

        mock := NewMockDNSClient()
        mock.AddResponse("TXT", "_dnslink.example.com", []string{"dnslink=/ipfs/" + dnslinkCID})
        a := &Analyzer{DNS: mock}

        ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
        defer cancel()
        result := a.AnalyzeWeb3(ctx, "example.com", []string{"dnslink=/ipfs/" + rootCID}, nil)
        if result["dnslink_source"] != "_dnslink" {
                t.Errorf("_dnslink subdomain should take priority, got source=%v", result["dnslink_source"])
        }
        if result["dnslink_cid"] != dnslinkCID {
                t.Errorf("expected CID from _dnslink (%s), got %v", dnslinkCID, result["dnslink_cid"])
        }
}

func TestDNSLinkPrimaryOrder_FallbackToRoot_S007(t *testing.T) {
        rootCID := "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"

        mock := NewMockDNSClient()
        a := &Analyzer{DNS: mock}

        ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
        defer cancel()
        result := a.AnalyzeWeb3(ctx, "example.com", []string{"dnslink=/ipfs/" + rootCID}, nil)
        if result["dnslink_source"] != "root_txt" {
                t.Errorf("fallback should set dnslink_source=root_txt, got %v", result["dnslink_source"])
        }
}

func TestDNSLinkStatic_AlwaysRootTXT_S007(t *testing.T) {
        txt := []string{"dnslink=/ipfs/QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"}
        result := AnalyzeWeb3Static(txt, nil)
        if result["dnslink_source"] != "root_txt" {
                t.Errorf("static analysis should always be root_txt, got %v", result["dnslink_source"])
        }
}

func TestHNSResolution_ScopeGatewayDerived_S007(t *testing.T) {
        mock := NewMockDNSClient()
        mock.AddSpecificResolverResponse("A", "mysite.hns", hnsResolverDomain+":53", []string{"1.2.3.4"})
        a := &Analyzer{DNS: mock}
        ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
        defer cancel()
        result := a.resolveHNS(ctx, "mysite.hns")
        if result.AnalysisScope != ScopeGatewayDerived {
                t.Errorf("HNS should get ScopeGatewayDerived, got %v", result.AnalysisScope)
        }
        if result.AttributionWarning == "" {
                t.Error("HNS via public resolver should emit attribution warning")
        }
}

func TestDefaultWeb3Resolution_OwnedDNS_S007(t *testing.T) {
        d := DefaultWeb3Resolution()
        if d["analysis_scope"] != "owned_dns" {
                t.Errorf("default scope should be owned_dns, got %v", d["analysis_scope"])
        }
        if d["input_kind"] != "dns_domain" {
                t.Errorf("default input_kind should be dns_domain, got %v", d["input_kind"])
        }
}

func TestLegacyScopeAliases_S007(t *testing.T) {
        if ScopeOwnedDNS == "full_dns" {
                t.Error("ScopeOwnedDNS should NOT be full_dns anymore")
        }
        if ScopeGatewayDerived == "core_dns_only" {
                t.Error("ScopeGatewayDerived should NOT be core_dns_only anymore")
        }
        if ScopeIdentityOnly == "web3_identity_only" {
                t.Error("ScopeIdentityOnly should NOT be web3_identity_only anymore")
        }
}

func TestHostileCID_Blocked_S007(t *testing.T) {
        hostileCIDs := []string{
                "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG/<script>alert(1)</script>",
                "../../../etc/passwd",
                "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG\x00evil",
        }
        for _, cid := range hostileCIDs {
                if IsValidCID(cid) {
                        t.Errorf("hostile CID should be rejected: %q", cid)
                }
        }
}

func containsB14(s, substr string) bool {
        for i := 0; i <= len(s)-len(substr); i++ {
                if s[i:i+len(substr)] == substr {
                        return true
                }
        }
        return false
}
