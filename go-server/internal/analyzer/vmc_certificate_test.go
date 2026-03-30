package analyzer

import (
        "testing"
)

func TestCoverageBoost13_ClassifyVMCCertificate_DigiCert(t *testing.T) {
        result := map[string]any{mapKeyValid: false, mapKeyIssuer: nil, "subject": nil, mapKeyError: nil}
        classifyVMCCertificate("-----BEGIN CERTIFICATE-----\nDigiCert Inc\n-----END CERTIFICATE-----", result)
        if result[mapKeyValid] != true {
                t.Error("expected valid=true for DigiCert cert")
        }
        if result[mapKeyIssuer] != "DigiCert" {
                t.Errorf("expected issuer=DigiCert, got %v", result[mapKeyIssuer])
        }
}

func TestCoverageBoost13_ClassifyVMCCertificate_Entrust(t *testing.T) {
        result := map[string]any{mapKeyValid: false, mapKeyIssuer: nil, "subject": nil, mapKeyError: nil}
        classifyVMCCertificate("-----BEGIN CERTIFICATE-----\nEntrust\n-----END CERTIFICATE-----", result)
        if result[mapKeyValid] != true {
                t.Error("expected valid=true for Entrust cert")
        }
        if result[mapKeyIssuer] != "Entrust" {
                t.Errorf("expected issuer=Entrust, got %v", result[mapKeyIssuer])
        }
}

func TestCoverageBoost13_ClassifyVMCCertificate_GlobalSign(t *testing.T) {
        result := map[string]any{mapKeyValid: false, mapKeyIssuer: nil, "subject": nil, mapKeyError: nil}
        classifyVMCCertificate("-----BEGIN CERTIFICATE-----\nGlobalSign\n-----END CERTIFICATE-----", result)
        if result[mapKeyValid] != true {
                t.Error("expected valid=true for GlobalSign cert")
        }
        if result[mapKeyIssuer] != "GlobalSign" {
                t.Errorf("expected issuer=GlobalSign, got %v", result[mapKeyIssuer])
        }
}

func TestCoverageBoost13_ClassifyVMCCertificate_UnknownCA(t *testing.T) {
        result := map[string]any{mapKeyValid: false, mapKeyIssuer: nil, "subject": nil, mapKeyError: nil}
        classifyVMCCertificate("-----BEGIN CERTIFICATE-----\nSomeOtherCA\n-----END CERTIFICATE-----", result)
        if result[mapKeyValid] != true {
                t.Error("expected valid=true for unknown CA cert")
        }
        if result[mapKeyIssuer] != "Verified CA" {
                t.Errorf("expected issuer=Verified CA, got %v", result[mapKeyIssuer])
        }
}

func TestCoverageBoost13_ClassifyVMCCertificate_InvalidFormat(t *testing.T) {
        result := map[string]any{mapKeyValid: false, mapKeyIssuer: nil, "subject": nil, mapKeyError: nil}
        classifyVMCCertificate("not a certificate", result)
        if result[mapKeyValid] != false {
                t.Error("expected valid=false for invalid cert")
        }
        if result[mapKeyError] != "Invalid certificate format" {
                t.Errorf("expected error=Invalid certificate format, got %v", result[mapKeyError])
        }
}

func TestCoverageBoost13_ParseSOASerial_Valid(t *testing.T) {
        serial, ok := parseSOASerial("ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400")
        if !ok {
                t.Fatal("expected ok=true")
        }
        if serial != 2024010101 {
                t.Errorf("expected serial=2024010101, got %d", serial)
        }
}

func TestCoverageBoost13_ParseSOASerial_TooFewParts(t *testing.T) {
        _, ok := parseSOASerial("ns1.example.com. admin.example.com.")
        if ok {
                t.Error("expected ok=false for too few parts")
        }
}

func TestCoverageBoost13_ParseSOASerial_NonNumeric(t *testing.T) {
        _, ok := parseSOASerial("ns1.example.com. admin.example.com. notanumber 3600 900")
        if ok {
                t.Error("expected ok=false for non-numeric serial")
        }
}

func TestCoverageBoost13_ParseSOASerial_Empty(t *testing.T) {
        _, ok := parseSOASerial("")
        if ok {
                t.Error("expected ok=false for empty string")
        }
}

func TestCoverageBoost13_IsInBailiwick_Subdomain(t *testing.T) {
        if !isInBailiwick("ns1.example.com", "example.com") {
                t.Error("expected ns1.example.com to be in bailiwick of example.com")
        }
}

func TestCoverageBoost13_IsInBailiwick_Exact(t *testing.T) {
        if !isInBailiwick("example.com", "example.com") {
                t.Error("expected example.com to be in bailiwick of example.com")
        }
}

func TestCoverageBoost13_IsInBailiwick_OutOfBailiwick(t *testing.T) {
        if isInBailiwick("ns1.otherdomain.com", "example.com") {
                t.Error("expected ns1.otherdomain.com to NOT be in bailiwick of example.com")
        }
}

func TestCoverageBoost13_IsInBailiwick_TrailingDots(t *testing.T) {
        if !isInBailiwick("ns1.example.com.", "example.com.") {
                t.Error("expected trailing dots to be handled")
        }
}

func TestCoverageBoost13_IsInBailiwick_CaseInsensitive(t *testing.T) {
        if !isInBailiwick("NS1.EXAMPLE.COM", "example.com") {
                t.Error("expected case insensitive matching")
        }
}

func TestCoverageBoost13_StructToMap_DSKeyAlignment(t *testing.T) {
        val := DSKeyAlignment{
                Aligned:      true,
                MatchedPairs: []DSKeyPair{{DSKeyTag: 12345, DSAlgorithm: 8, DNSKEYKeyTag: 12345, DNSKEYAlgorithm: 8}},
                UnmatchedDS:  []DSRecord{},
                UnmatchedKeys: []DNSKEYRecord{},
                Issues:       []string{},
        }
        m := structToMap(val)
        if m["aligned"] != true {
                t.Error("expected aligned=true")
        }
        pairs, ok := m["matched_pairs"].([]map[string]any)
        if !ok {
                t.Fatal("expected matched_pairs to be []map[string]any")
        }
        if len(pairs) != 1 {
                t.Errorf("expected 1 matched pair, got %d", len(pairs))
        }
}

func TestCoverageBoost13_StructToMap_GlueAnalysis(t *testing.T) {
        val := GlueAnalysis{
                Complete:         true,
                InBailiwickCount: 2,
                GluePresent:      2,
                GlueMissing:      0,
                Nameservers: []GlueStatus{
                        {NS: "ns1.example.com", InBailiwick: true, HasIPv4Glue: true, HasIPv6Glue: true, IPv4Addrs: []string{"1.2.3.4"}, IPv6Addrs: []string{"::1"}, Complete: true},
                },
                Issues: []string{},
        }
        m := structToMap(val)
        if m["complete"] != true {
                t.Error("expected complete=true")
        }
        if m["in_bailiwick_count"] != 2 {
                t.Errorf("expected in_bailiwick_count=2, got %v", m["in_bailiwick_count"])
        }
        nameservers, ok := m["nameservers"].([]map[string]any)
        if !ok {
                t.Fatal("expected nameservers to be []map[string]any")
        }
        if len(nameservers) != 1 {
                t.Errorf("expected 1 nameserver, got %d", len(nameservers))
        }
        ns := nameservers[0]
        if ns["ipv4_addrs"] == nil {
                t.Error("expected ipv4_addrs to be present")
        }
        if ns["ipv6_addrs"] == nil {
                t.Error("expected ipv6_addrs to be present")
        }
}

func TestCoverageBoost13_StructToMap_TTLComparison(t *testing.T) {
        p := uint32(3600)
        c := uint32(7200)
        val := TTLComparison{
                ParentTTL: &p,
                ChildTTL:  &c,
                Match:     false,
                DriftSecs: 3600,
                Issues:    []string{"mismatch"},
        }
        m := structToMap(val)
        if m["match"] != false {
                t.Error("expected match=false")
        }
        if m["drift_secs"] != int64(3600) {
                t.Errorf("expected drift_secs=3600, got %v", m["drift_secs"])
        }
        if m["parent_ttl"] != uint32(3600) {
                t.Errorf("expected parent_ttl=3600, got %v", m["parent_ttl"])
        }
        if m["child_ttl"] != uint32(7200) {
                t.Errorf("expected child_ttl=7200, got %v", m["child_ttl"])
        }
}

func TestCoverageBoost13_StructToMap_TTLComparison_NilTTLs(t *testing.T) {
        val := TTLComparison{
                ParentTTL: nil,
                ChildTTL:  nil,
                Match:     false,
                Issues:    []string{},
        }
        m := structToMap(val)
        if _, exists := m["parent_ttl"]; exists {
                t.Error("expected parent_ttl to be absent when nil")
        }
        if _, exists := m["child_ttl"]; exists {
                t.Error("expected child_ttl to be absent when nil")
        }
}

func TestCoverageBoost13_StructToMap_SOAConsistency(t *testing.T) {
        val := SOAConsistency{
                Consistent:  true,
                Serials:     map[string]uint32{"ns1": 2024010101, "ns2": 2024010101},
                UniqueCount: 1,
                Issues:      []string{},
        }
        m := structToMap(val)
        if m["consistent"] != true {
                t.Error("expected consistent=true")
        }
        if m["unique_count"] != 1 {
                t.Errorf("expected unique_count=1, got %v", m["unique_count"])
        }
        serials, ok := m["serials"].(map[string]any)
        if !ok {
                t.Fatal("expected serials to be map[string]any")
        }
        if len(serials) != 2 {
                t.Errorf("expected 2 serials, got %d", len(serials))
        }
}

func TestCoverageBoost13_StructToMap_UnknownType(t *testing.T) {
        m := structToMap("not a known struct")
        if len(m) != 0 {
                t.Errorf("expected empty map for unknown type, got %d entries", len(m))
        }
}

func TestCoverageBoost13_GlueStatusToMap_NoAddrs(t *testing.T) {
        status := GlueStatus{
                NS:          "ns1.external.com",
                InBailiwick: false,
                HasIPv4Glue: false,
                HasIPv6Glue: false,
                Complete:    true,
        }
        m := glueStatusToMap(status)
        if m["ns"] != "ns1.external.com" {
                t.Errorf("expected ns=ns1.external.com, got %v", m["ns"])
        }
        if _, exists := m["ipv4_addrs"]; exists {
                t.Error("expected ipv4_addrs to be absent when empty")
        }
        if _, exists := m["ipv6_addrs"]; exists {
                t.Error("expected ipv6_addrs to be absent when empty")
        }
}

func TestCoverageBoost13_DSKeyAlignmentToMap_WithUnmatched(t *testing.T) {
        val := DSKeyAlignment{
                Aligned:      false,
                MatchedPairs: []DSKeyPair{},
                UnmatchedDS:  []DSRecord{{KeyTag: 111, Algorithm: 8, DigestType: 2, Digest: "abc", Raw: "raw-ds"}},
                UnmatchedKeys: []DNSKEYRecord{{Flags: 257, Protocol: 3, Algorithm: 13, KeyTag: 222, IsKSK: true, Raw: "raw-key"}},
                Issues:       []string{"broken chain"},
        }
        m := dsKeyAlignmentToMap(val)
        unmatchedDS, ok := m["unmatched_ds"].([]map[string]any)
        if !ok || len(unmatchedDS) != 1 {
                t.Fatal("expected 1 unmatched DS")
        }
        unmatchedKeys, ok := m["unmatched_keys"].([]map[string]any)
        if !ok || len(unmatchedKeys) != 1 {
                t.Fatal("expected 1 unmatched key")
        }
}

func TestCoverageBoost13_BuildBIMICoreMessage_VMCValidNoIssuer(t *testing.T) {
        vmcURL := "https://example.com/vmc.pem"
        vmcData := map[string]any{mapKeyValid: true}
        status, parts := buildBIMICoreMessage(nil, &vmcURL, map[string]any{}, vmcData)
        if status != "success" {
                t.Errorf("expected status=success, got %s", status)
        }
        if len(parts) == 0 {
                t.Error("expected non-empty parts")
        }
}

func TestCoverageBoost13_BuildBIMICoreMessage_VMCInvalidNoError(t *testing.T) {
        vmcURL := "https://example.com/vmc.pem"
        vmcData := map[string]any{mapKeyValid: false}
        status, parts := buildBIMICoreMessage(nil, &vmcURL, map[string]any{}, vmcData)
        if status != "success" {
                t.Errorf("expected status=success (no error string), got %s", status)
        }
        if len(parts) == 0 {
                t.Error("expected non-empty parts")
        }
}

func TestCoverageBoost13_ClassifyBIMILogoFormat_SVGContentType(t *testing.T) {
        result := map[string]any{}
        classifyBIMILogoFormat("image/svg+xml", []byte("<svg></svg>"), result)
        if result[mapKeyValid] != true {
                t.Error("expected valid=true for SVG content type")
        }
        if result[mapKeyFormat] != "SVG" {
                t.Errorf("expected format=SVG, got %v", result[mapKeyFormat])
        }
}

func TestCoverageBoost13_ClassifyBIMILogoFormat_ImageWithSVGBody(t *testing.T) {
        result := map[string]any{}
        classifyBIMILogoFormat("image/png", []byte("<svg xmlns='http://www.w3.org/2000/svg'></svg>"), result)
        if result[mapKeyValid] != true {
                t.Error("expected valid=true for image with SVG body")
        }
}

func TestCoverageBoost13_ClassifyBIMILogoFormat_UnknownContentWithSVG(t *testing.T) {
        result := map[string]any{}
        classifyBIMILogoFormat("application/octet-stream", []byte("<svg></svg>"), result)
        if result[mapKeyValid] != true {
                t.Error("expected valid=true for unknown content type with SVG body")
        }
}

func TestCoverageBoost13_ClassifyBIMILogoFormat_UnknownContentNoSVG(t *testing.T) {
        result := map[string]any{}
        classifyBIMILogoFormat("application/octet-stream", []byte("not svg content"), result)
        if result[mapKeyValid] == true {
                t.Error("expected valid!=true for non-SVG content")
        }
        if result[mapKeyError] == nil {
                t.Error("expected error to be set")
        }
}

func TestCoverageBoost13_ClassifyBIMILogoFormat_ImageSinglePart(t *testing.T) {
        result := map[string]any{}
        classifyBIMILogoFormat("image", []byte("binary data"), result)
        if result[mapKeyValid] != false {
                t.Error("expected valid=false for non-SVG image")
        }
        if result[mapKeyFormat] != "unknown" {
                t.Errorf("expected format=unknown for single-part content type, got %v", result[mapKeyFormat])
        }
}
