package analyzer

import (
	"context"
	"testing"
)

func TestIsInBailiwick_CB5(t *testing.T) {
	tests := []struct {
		ns, domain string
		want       bool
	}{
		{"ns1.example.com.", "example.com", true},
		{"ns1.example.com", "example.com.", true},
		{"ns1.external.com", "example.com", false},
		{"example.com", "example.com", true},
		{"ns1.sub.example.com", "example.com", true},
	}
	for _, tt := range tests {
		if got := isInBailiwick(tt.ns, tt.domain); got != tt.want {
			t.Errorf("isInBailiwick(%q, %q) = %v, want %v", tt.ns, tt.domain, got, tt.want)
		}
	}
}

func TestCheckGlueCompleteness_CB5(t *testing.T) {
	t.Run("all out of bailiwick", func(t *testing.T) {
		result := CheckGlueCompleteness([]string{"ns1.external.com"}, "example.com", nil, nil)
		if !result.Complete {
			t.Error("out-of-bailiwick NS should be complete")
		}
		if result.InBailiwickCount != 0 {
			t.Error("expected 0 in-bailiwick")
		}
	})
	t.Run("in-bailiwick with glue", func(t *testing.T) {
		ipv4 := map[string][]string{"ns1.example.com": {"1.2.3.4"}}
		ipv6 := map[string][]string{"ns1.example.com": {"2001:db8::1"}}
		result := CheckGlueCompleteness([]string{"ns1.example.com."}, "example.com", ipv4, ipv6)
		if result.InBailiwickCount != 1 {
			t.Error("expected 1 in-bailiwick")
		}
		if result.GluePresent != 1 {
			t.Error("expected 1 glue present")
		}
	})
	t.Run("in-bailiwick missing glue", func(t *testing.T) {
		result := CheckGlueCompleteness([]string{"ns1.example.com."}, "example.com", nil, nil)
		if result.Complete {
			t.Error("missing glue should not be complete")
		}
		if result.GlueMissing != 1 {
			t.Error("expected 1 glue missing")
		}
	})
	t.Run("in-bailiwick partial glue", func(t *testing.T) {
		ipv4 := map[string][]string{"ns1.example.com": {"1.2.3.4"}}
		result := CheckGlueCompleteness([]string{"ns1.example.com."}, "example.com", ipv4, nil)
		if result.GluePresent != 1 {
			t.Error("expected 1 glue present")
		}
		if len(result.Issues) == 0 {
			t.Error("expected issues for missing IPv6")
		}
	})
}

func TestCompareTTLs_CB5(t *testing.T) {
	t.Run("both nil", func(t *testing.T) {
		result := CompareTTLs(nil, nil)
		if result.Match {
			t.Error("expected no match")
		}
		if len(result.Issues) == 0 {
			t.Error("expected issues")
		}
	})
	t.Run("parent nil", func(t *testing.T) {
		child := uint32(3600)
		result := CompareTTLs(nil, &child)
		if result.Match {
			t.Error("expected no match")
		}
	})
	t.Run("child nil", func(t *testing.T) {
		parent := uint32(3600)
		result := CompareTTLs(&parent, nil)
		if result.Match {
			t.Error("expected no match")
		}
	})
	t.Run("matching TTLs", func(t *testing.T) {
		parent := uint32(3600)
		child := uint32(3600)
		result := CompareTTLs(&parent, &child)
		if !result.Match {
			t.Error("expected match")
		}
		if result.DriftSecs != 0 {
			t.Error("expected 0 drift")
		}
	})
	t.Run("mismatched TTLs", func(t *testing.T) {
		parent := uint32(3600)
		child := uint32(7200)
		result := CompareTTLs(&parent, &child)
		if result.Match {
			t.Error("expected no match")
		}
		if result.DriftSecs != 3600 {
			t.Errorf("expected 3600 drift, got %d", result.DriftSecs)
		}
	})
}

func TestCheckSOAConsistency_CB5(t *testing.T) {
	t.Run("consistent", func(t *testing.T) {
		result := CheckSOAConsistency(map[string]uint32{
			"ns1.example.com": 2024010101,
			"ns2.example.com": 2024010101,
		})
		if !result.Consistent {
			t.Error("expected consistent")
		}
	})
	t.Run("inconsistent", func(t *testing.T) {
		result := CheckSOAConsistency(map[string]uint32{
			"ns1.example.com": 2024010101,
			"ns2.example.com": 2024010102,
		})
		if result.Consistent {
			t.Error("expected inconsistent")
		}
		if len(result.Issues) == 0 {
			t.Error("expected issues")
		}
	})
	t.Run("empty", func(t *testing.T) {
		result := CheckSOAConsistency(map[string]uint32{})
		if !result.Consistent {
			t.Error("empty should be consistent")
		}
	})
	t.Run("single server", func(t *testing.T) {
		result := CheckSOAConsistency(map[string]uint32{"ns1.example.com": 2024010101})
		if !result.Consistent {
			t.Error("single server should be consistent")
		}
	})
}

func TestCheckDSKeyAlignment_CB5(t *testing.T) {
	t.Run("no records", func(t *testing.T) {
		result := CheckDSKeyAlignment(nil, nil)
		if len(result.MatchedPairs) != 0 {
			t.Error("expected no matched pairs")
		}
	})
	t.Run("matching pair", func(t *testing.T) {
		ds := []DSRecord{{KeyTag: 12345, Algorithm: 13, DigestType: 2, Digest: "abcdef"}}
		dnskey := []DNSKEYRecord{{Flags: 257, Protocol: 3, Algorithm: 13, KeyTag: 12345, IsKSK: true}}
		result := CheckDSKeyAlignment(ds, dnskey)
		if len(result.MatchedPairs) == 0 {
			t.Error("expected matching pair")
		}
	})
	t.Run("unmatched DS", func(t *testing.T) {
		ds := []DSRecord{{KeyTag: 9999, Algorithm: 13, DigestType: 2, Digest: "abcdef"}}
		dnskey := []DNSKEYRecord{{Flags: 257, Protocol: 3, Algorithm: 13, KeyTag: 12345, IsKSK: true}}
		result := CheckDSKeyAlignment(ds, dnskey)
		if len(result.UnmatchedDS) == 0 {
			t.Error("expected unmatched DS")
		}
	})
}

func TestParseSOASerial_CB5(t *testing.T) {
	tests := []struct {
		input string
		want  uint32
		ok    bool
	}{
		{"ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400", 2024010101, true},
		{"ns1.example.com. admin.example.com.", 0, false},
		{"", 0, false},
	}
	for _, tt := range tests {
		serial, ok := parseSOASerial(tt.input)
		if ok != tt.ok {
			t.Errorf("parseSOASerial(%q) ok=%v, want %v", tt.input, ok, tt.ok)
		}
		if ok && serial != tt.want {
			t.Errorf("parseSOASerial(%q) = %d, want %d", tt.input, serial, tt.want)
		}
	}
}

func TestStructToMap_CB5(t *testing.T) {
	t.Run("DSKeyAlignment", func(t *testing.T) {
		alignment := DSKeyAlignment{Aligned: true, MatchedPairs: []DSKeyPair{{DSKeyTag: 1}}, Issues: []string{}}
		result := structToMap(alignment)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
	})
	t.Run("GlueAnalysis", func(t *testing.T) {
		glue := GlueAnalysis{Complete: true, Nameservers: []GlueStatus{}, Issues: []string{}}
		result := structToMap(glue)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
	})
	t.Run("TTLComparison", func(t *testing.T) {
		ttl := TTLComparison{Match: true, Issues: []string{}}
		result := structToMap(ttl)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
	})
	t.Run("SOAConsistency", func(t *testing.T) {
		soa := SOAConsistency{Consistent: true, Serials: map[string]uint32{}, Issues: []string{}}
		result := structToMap(soa)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
	})
	t.Run("unknown type", func(t *testing.T) {
		result := structToMap("unknown")
		if result == nil {
			t.Error("expected non-nil empty map for unknown type")
		}
		if len(result) != 0 {
			t.Errorf("expected empty map for unknown type, got %d keys", len(result))
		}
	})
}

func TestAnalyzeDelegationConsistency_CB5(t *testing.T) {
	a := newMockAnalyzer()
	mock := a.DNS.(*MockDNSClient)
	mock.AddResponse("NS", "example.com", []string{"ns1.example.com.", "ns2.example.com."})
	mock.AddResponse("SOA", "example.com", []string{"ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400"})

	result := a.AnalyzeDelegationConsistency(context.Background(), "example.com")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result[mapKeyStatus] == nil {
		t.Error("expected status in result")
	}
}

func TestCollectKSKKeys_CB5(t *testing.T) {
	keys := []DNSKEYRecord{
		{Flags: 257, KeyTag: 100, Algorithm: 13, IsKSK: true},
		{Flags: 256, KeyTag: 200, Algorithm: 13, IsZSK: true},
		{Flags: 257, KeyTag: 300, Algorithm: 13, IsKSK: true},
	}
	ksks := collectKSKKeys(keys)
	if len(ksks) != 2 {
		t.Errorf("expected 2 KSK keys, got %d", len(ksks))
	}
	if _, ok := ksks[100]; !ok {
		t.Error("expected KSK with tag 100")
	}
	if _, ok := ksks[200]; ok {
		t.Error("ZSK 200 should not be in KSK map")
	}
}

func TestEvaluateInBailiwickGlue_CB5(t *testing.T) {
	t.Run("both glue present", func(t *testing.T) {
		status := GlueStatus{NS: "ns1.example.com", InBailiwick: true}
		result := GlueAnalysis{Complete: true, Issues: []string{}}
		ipv4 := map[string][]string{"ns1.example.com": {"1.2.3.4"}}
		ipv6 := map[string][]string{"ns1.example.com": {"2001:db8::1"}}
		evaluateInBailiwickGlue("ns1.example.com", ipv4, ipv6, &status, &result)
		if !status.HasIPv4Glue || !status.HasIPv6Glue {
			t.Error("expected both glue types")
		}
		if !status.Complete {
			t.Error("expected complete with both glue types")
		}
	})
	t.Run("no glue at all", func(t *testing.T) {
		status := GlueStatus{NS: "ns1.example.com", InBailiwick: true}
		result := GlueAnalysis{Complete: true, Issues: []string{}}
		evaluateInBailiwickGlue("ns1.example.com", nil, nil, &status, &result)
		if result.Complete {
			t.Error("expected incomplete with no glue")
		}
		if result.GlueMissing != 1 {
			t.Error("expected 1 glue missing")
		}
	})
}
