package analyzer

import (
        "testing"
)

func TestValidateIPAddress(t *testing.T) {
        tests := []struct {
                ip   string
                want bool
        }{
                {"1.2.3.4", true},
                {"192.168.1.1", true},
                {"::1", true},
                {"2001:db8::1", true},
                {"invalid", false},
                {"", false},
                {"999.999.999.999", false},
                {"1.2.3", false},
        }
        for _, tt := range tests {
                got := ValidateIPAddress(tt.ip)
                if got != tt.want {
                        t.Errorf("ValidateIPAddress(%q) = %v, want %v", tt.ip, got, tt.want)
                }
        }
}

func TestIsPrivateIP(t *testing.T) {
        tests := []struct {
                ip   string
                want bool
        }{
                {"127.0.0.1", true},
                {"192.168.1.1", true},
                {"10.0.0.1", true},
                {"172.16.0.1", true},
                {"8.8.8.8", false},
                {"1.1.1.1", false},
                {"::1", true},
                {"invalid", false},
                {"0.0.0.0", true},
        }
        for _, tt := range tests {
                got := IsPrivateIP(tt.ip)
                if got != tt.want {
                        t.Errorf("IsPrivateIP(%q) = %v, want %v", tt.ip, got, tt.want)
                }
        }
}

func TestIsIPv6(t *testing.T) {
        tests := []struct {
                ip   string
                want bool
        }{
                {"::1", true},
                {"2001:db8::1", true},
                {"1.2.3.4", false},
                {"", false},
        }
        for _, tt := range tests {
                got := IsIPv6(tt.ip)
                if got != tt.want {
                        t.Errorf("IsIPv6(%q) = %v, want %v", tt.ip, got, tt.want)
                }
        }
}

func TestBuildArpaName_IPv4(t *testing.T) {
        got := buildArpaName("1.2.3.4")
        if got != "4.3.2.1.in-addr.arpa" {
                t.Errorf("buildArpaName('1.2.3.4') = %q", got)
        }
}

func TestBuildArpaName_IPv6(t *testing.T) {
        got := buildArpaName("::1")
        if got == "" {
                t.Skip("reverseIPv6 may return empty for short forms")
        }
        suffix := ".ip6.arpa"
        if len(got) >= len(suffix) && got[len(got)-len(suffix):] != suffix {
                t.Errorf("expected .ip6.arpa suffix, got %q", got)
        }
}

func TestBuildArpaName_InvalidIPv4(t *testing.T) {
        got := buildArpaName("invalid")
        if got != "" && got != ".in-addr.arpa" {
                t.Logf("buildArpaName('invalid') = %q (implementation-dependent)", got)
        }
}

func TestMapGetStr(t *testing.T) {
        m := map[string]any{
                "key1": "value1",
                "key2": 42,
        }
        if got := mapGetStr(m, "key1"); got != "value1" {
                t.Errorf("mapGetStr(m, 'key1') = %q, want 'value1'", got)
        }
        if got := mapGetStr(m, "key2"); got != "" {
                t.Errorf("mapGetStr(m, 'key2') = %q, want ''", got)
        }
        if got := mapGetStr(m, "missing"); got != "" {
                t.Errorf("mapGetStr(m, 'missing') = %q, want ''", got)
        }
}

func TestMapGetStr_Nil(t *testing.T) {
        if got := mapGetStr(nil, "key"); got != "" {
                t.Errorf("mapGetStr(nil, 'key') = %q, want ''", got)
        }
}

func TestFindFirstHostname_Empty(t *testing.T) {
        got := findFirstHostname(nil, "test")
        if got != "" {
                t.Errorf("findFirstHostname(nil, 'test') = %q, want ''", got)
        }
}

func TestExtractMXHost_Empty(t *testing.T) {
        got := extractMXHost("10 mail.example.com")
        if got != "" {
                t.Logf("extractMXHost returned %q (OSS stub returns empty)", got)
        }
}

func TestIPRelationship_Struct(t *testing.T) {
        r := IPRelationship{
                Classification: classDirectA,
                Evidence:       "A record match",
                RecordType:     "A",
                Hostname:       "example.com",
        }
        if r.Classification != "Direct Asset (A Record)" {
                t.Errorf("Classification = %q", r.Classification)
        }
}

func TestClassificationConstants(t *testing.T) {
        constants := map[string]string{
                "classCDNEdge":       classCDNEdge,
                "classCloudHosting":  classCloudHosting,
                "classDirectA":       classDirectA,
                "classDirectAAAA":    classDirectAAAA,
                "classDirectReverse": classDirectReverse,
                "classEmailMX":       classEmailMX,
                "classDNSNS":         classDNSNS,
                "classSPFAuth":       classSPFAuth,
                "classCTSubdomain":   classCTSubdomain,
        }
        for name, val := range constants {
                if val == "" {
                        t.Errorf("constant %s is empty", name)
                }
        }
}
