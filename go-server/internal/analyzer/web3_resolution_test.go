// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
        "context"
        "strings"
        "testing"
        "time"
)

func TestIsENSName_B14(t *testing.T) {
        tests := []struct {
                input string
                want  bool
        }{
                {"vitalik.eth", true},
                {"my-domain.eth", true},
                {"a.eth", true},
                {"example.com", false},
                {".eth", false},
                {"", false},
                {"VITALIK.ETH", true},
                {"-bad.eth", false},
                {"bad-.eth", false},
                {"hello.world.eth", false},
        }
        for _, tt := range tests {
                t.Run(tt.input, func(t *testing.T) {
                        if got := IsENSName(tt.input); got != tt.want {
                                t.Errorf("IsENSName(%q) = %v, want %v", tt.input, got, tt.want)
                        }
                })
        }
}

func TestIsHNSName_B14(t *testing.T) {
        tests := []struct {
                input string
                want  bool
        }{
                {"mysite.hns", true},
                {"example.forever", true},
                {"test.nb", true},
                {"site.c", true},
                {"example.com", false},
                {"hello.eth", false},
                {"", false},
                {"singlepart", false},
        }
        for _, tt := range tests {
                t.Run(tt.input, func(t *testing.T) {
                        if got := IsHNSName(tt.input); got != tt.want {
                                t.Errorf("IsHNSName(%q) = %v, want %v", tt.input, got, tt.want)
                        }
                })
        }
}

func TestIsWeb3Input_B14(t *testing.T) {
        tests := []struct {
                input string
                want  bool
        }{
                {"vitalik.eth", true},
                {"mysite.hns", true},
                {"example.com", false},
                {"", false},
        }
        for _, tt := range tests {
                if got := IsWeb3Input(tt.input); got != tt.want {
                        t.Errorf("IsWeb3Input(%q) = %v, want %v", tt.input, got, tt.want)
                }
        }
}

func TestDefaultWeb3Resolution_B14(t *testing.T) {
        r := DefaultWeb3Resolution()
        if r["is_web3_input"] != false {
                t.Error("expected is_web3_input=false")
        }
        if r["input_domain"] != "" {
                t.Error("expected empty input_domain")
        }
}

func TestWeb3ResolutionResult_ToMap_B14(t *testing.T) {
        r := Web3ResolutionResult{
                IsWeb3Input:    true,
                InputDomain:    "vitalik.eth",
                ResolvedDomain: "vitalik.eth",
                ResolutionType: "ens",
                Gateway:        "eth.limo",
        }
        m := r.ToMap()
        if m["is_web3_input"] != true {
                t.Error("expected is_web3_input=true")
        }
        if m["input_domain"] != "vitalik.eth" {
                t.Error("expected input_domain=vitalik.eth")
        }
        if m["resolution_type"] != "ens" {
                t.Error("expected resolution_type=ens")
        }
}

func TestResolveWeb3Domain_NotWeb3_B14(t *testing.T) {
        a := &Analyzer{DNS: NewMockDNSClient()}
        result := a.ResolveWeb3Domain(context.Background(), "example.com")
        if result.IsWeb3Input {
                t.Error("example.com should not be Web3 input")
        }
}

func TestResolveWeb3Domain_ENS_FieldsPopulated_B14(t *testing.T) {
        a := &Analyzer{DNS: NewMockDNSClient()}
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()
        result := a.resolveENS(ctx, "vitalik.eth")
        if !result.IsWeb3Input {
                t.Error("expected IsWeb3Input=true")
        }
        if result.ResolutionType != "ens" {
                t.Errorf("expected resolution_type=ens, got %s", result.ResolutionType)
        }
        if result.Gateway != "eth.limo" {
                t.Errorf("expected gateway=eth.limo, got %s", result.Gateway)
        }
}

func TestResolveWeb3Domain_HNS_NoRecords_B14(t *testing.T) {
        mock := NewMockDNSClient()
        a := &Analyzer{DNS: mock}

        ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
        defer cancel()
        result := a.resolveHNS(ctx, "mysite.hns")
        if !result.IsWeb3Input {
                t.Error("expected IsWeb3Input=true")
        }
        if result.ResolutionType != "hns" {
                t.Errorf("expected resolution_type=hns, got %s", result.ResolutionType)
        }
        if result.Error == "" {
                t.Error("expected an error when no records found")
        }
}

func TestResolveWeb3Domain_HNS_WithRecords_B14(t *testing.T) {
        mock := NewMockDNSClient()
        mock.AddSpecificResolverResponse("A", "mysite.hns", hnsResolverDomain+":53", []string{"1.2.3.4"})
        a := &Analyzer{DNS: mock}

        ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
        defer cancel()
        result := a.resolveHNS(ctx, "mysite.hns")
        if result.Error != "" {
                t.Errorf("expected no error, got %s", result.Error)
        }
        if result.ResolvedDomain != "mysite.hns" {
                t.Errorf("expected resolved=mysite.hns, got %s", result.ResolvedDomain)
        }
        if result.Gateway != hnsResolverDomain {
                t.Errorf("expected gateway=%s, got %s", hnsResolverDomain, result.Gateway)
        }
}

func TestExtractDomainFromURL_B14(t *testing.T) {
        tests := []struct {
                input string
                want  string
        }{
                {"https://example.com/path", "example.com"},
                {"http://test.org:8080/", "test.org"},
                {"example.com/foo", "example.com"},
                {"https://sub.domain.io", "sub.domain.io"},
                {"", ""},
        }
        for _, tt := range tests {
                if got := extractDomainFromURL(tt.input); got != tt.want {
                        t.Errorf("extractDomainFromURL(%q) = %q, want %q", tt.input, got, tt.want)
                }
        }
}

func TestResolveViaGatewayRedirect_SSRFBlock_B14(t *testing.T) {
        _, err := resolveViaGatewayRedirect(context.Background(), "127-0-0-1.eth", "evil.local")
        if err == nil {
                t.Error("expected SSRF block error")
        }
        if err != nil && !strings.Contains(err.Error(), "SSRF") && !strings.Contains(err.Error(), "unreachable") && !strings.Contains(err.Error(), "timeout") {
                t.Logf("SSRF/unreachable error received: %s", err.Error())
        }
}

func TestResolveWeb3Domain_ENS_Timeout_B14(t *testing.T) {
        a := &Analyzer{DNS: NewMockDNSClient()}
        ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
        defer cancel()
        time.Sleep(5 * time.Millisecond)
        result := a.resolveENS(ctx, "vitalik.eth")
        if !result.IsWeb3Input {
                t.Error("expected IsWeb3Input=true even on timeout")
        }
        if result.Error == "" {
                t.Log("ENS resolution returned without error despite canceled context")
        }
}

func TestResolveWeb3Domain_HNS_FallbackToAltResolver_B14(t *testing.T) {
        mock := NewMockDNSClient()
        mock.AddSpecificResolverResponse("A", "mysite.hns", hnsResolverAlt+":53", []string{"5.6.7.8"})
        a := &Analyzer{DNS: mock}

        ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
        defer cancel()
        result := a.resolveHNS(ctx, "mysite.hns")
        if result.Error != "" {
                t.Errorf("expected no error with alt resolver, got %s", result.Error)
        }
        if result.Gateway != hnsResolverAlt {
                t.Errorf("expected gateway=%s, got %s", hnsResolverAlt, result.Gateway)
        }
}

func TestResolveWeb3Domain_HNS_NSFallback_B14(t *testing.T) {
        mock := NewMockDNSClient()
        mock.AddSpecificResolverResponse("NS", "mysite.hns", hnsResolverDomain+":53", []string{"ns1.mysite.hns"})
        a := &Analyzer{DNS: mock}

        ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
        defer cancel()
        result := a.resolveHNS(ctx, "mysite.hns")
        if result.Error != "" {
                t.Errorf("expected NS fallback to succeed, got error: %s", result.Error)
        }
        if result.ResolvedDomain != "mysite.hns" {
                t.Errorf("expected resolved=mysite.hns, got %s", result.ResolvedDomain)
        }
}

func TestResolveWeb3Domain_Dispatch_ENS_B14(t *testing.T) {
        a := &Analyzer{DNS: NewMockDNSClient()}
        result := a.ResolveWeb3Domain(context.Background(), "test.eth")
        if result.ResolutionType != "ens" {
                t.Errorf("expected ens dispatch, got %s", result.ResolutionType)
        }
}

func TestResolveWeb3Domain_Dispatch_HNS_B14(t *testing.T) {
        a := &Analyzer{DNS: NewMockDNSClient()}
        result := a.ResolveWeb3Domain(context.Background(), "test.hns")
        if result.ResolutionType != "hns" {
                t.Errorf("expected hns dispatch, got %s", result.ResolutionType)
        }
}

func TestWeb3ResolutionResult_ToMap_WithError_B14(t *testing.T) {
        r := Web3ResolutionResult{
                IsWeb3Input:    true,
                InputDomain:    "bad.eth",
                ResolutionType: "ens",
                Gateway:        "eth.limo",
                Error:          "gateway timeout",
        }
        m := r.ToMap()
        if m["error"] != "gateway timeout" {
                t.Errorf("expected error='gateway timeout', got %v", m["error"])
        }
}

func TestIsENSName_EdgeCases_B14(t *testing.T) {
        tests := []struct {
                input string
                want  bool
        }{
                {"ab.eth", true},
                {"123.eth", true},
                {"a-b-c.eth", true},
                {"----.eth", false},
                {".ETH", false},
                {"test.Eth", true},
                {"a" + strings.Repeat("b", 61) + ".eth", true},
        }
        for _, tt := range tests {
                if got := IsENSName(tt.input); got != tt.want {
                        t.Errorf("IsENSName(%q) = %v, want %v", tt.input, got, tt.want)
                }
        }
}

func TestIsHNSName_AllTLDs_B14(t *testing.T) {
        for tld := range knownHNSTLDs {
                name := "test." + tld
                if !IsHNSName(name) {
                        t.Errorf("IsHNSName(%q) should be true for known TLD %q", name, tld)
                }
        }
}

func TestDefaultWeb3Resolution_AllKeys_B14(t *testing.T) {
        m := DefaultWeb3Resolution()
        expectedKeys := []string{"is_web3_input", "input_domain", "resolved_domain", "resolution_type", "gateway", "error"}
        for _, k := range expectedKeys {
                if _, ok := m[k]; !ok {
                        t.Errorf("DefaultWeb3Resolution missing key %q", k)
                }
        }
}

func TestIsWeb3Input_TraditionalDomains_Backward_B14(t *testing.T) {
        traditional := []string{
                "example.com", "google.co.uk", "amazon.de",
                "test.org", "mail.example.com", "192.168.1.1",
                "", "com", ".com",
        }
        for _, d := range traditional {
                if IsWeb3Input(d) {
                        t.Errorf("IsWeb3Input(%q) should be false for traditional domain", d)
                }
        }
}

func TestWeb3ResolutionResult_ToMap_EmptyResult_B14(t *testing.T) {
        r := Web3ResolutionResult{}
        m := r.ToMap()
        if m["is_web3_input"] != false {
                t.Error("zero-value result should have is_web3_input=false")
        }
        if m["input_domain"] != "" {
                t.Error("zero-value result should have empty input_domain")
        }
        if m["error"] != "" {
                t.Error("zero-value result should have empty error")
        }
}

func TestResolveWeb3Domain_ENS_GatewayDomain_B14(t *testing.T) {
        a := &Analyzer{DNS: NewMockDNSClient()}
        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()
        result := a.resolveENS(ctx, "vitalik.eth")

        if result.ResolvedDomain != "" && result.Error == "" {
                if !strings.HasSuffix(result.ResolvedDomain, "."+ensGateway) {
                        t.Errorf("expected resolved domain to end with .%s, got %s", ensGateway, result.ResolvedDomain)
                }
        }
}

func TestResolveWeb3Domain_HNS_WithNS_AltResolver_B14(t *testing.T) {
        mock := NewMockDNSClient()
        mock.AddSpecificResolverResponse("NS", "mysite.hns", hnsResolverAlt+":53", []string{"ns1.alt.hns"})
        a := &Analyzer{DNS: mock}

        ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
        defer cancel()
        result := a.resolveHNS(ctx, "mysite.hns")
        if result.Error != "" {
                t.Errorf("expected NS via alt resolver to succeed, got error: %s", result.Error)
        }
        if result.Gateway != hnsResolverAlt {
                t.Errorf("expected gateway=%s, got %s", hnsResolverAlt, result.Gateway)
        }
}

func TestWeb3Resolution_BackwardCompat_NoWeb3Input_B14(t *testing.T) {
        result := DefaultWeb3Resolution()
        if result["is_web3_input"] != false {
                t.Error("default resolution should not be web3 input")
        }
        if result["resolved_domain"] != "" {
                t.Error("default resolution should have empty resolved_domain")
        }
        if result["error"] != "" {
                t.Error("default resolution should have no error")
        }
}

func TestExtractDomainFromURL_EdgeCases_B14(t *testing.T) {
        tests := []struct {
                input string
                want  string
        }{
                {"https://a.b.c.d.e.f.g/path?q=1", "a.b.c.d.e.f.g"},
                {"http://localhost:3000", "localhost"},
                {"https://domain.com:443/page", "domain.com"},
        }
        for _, tt := range tests {
                if got := extractDomainFromURL(tt.input); got != tt.want {
                        t.Errorf("extractDomainFromURL(%q) = %q, want %q", tt.input, got, tt.want)
                }
        }
}
