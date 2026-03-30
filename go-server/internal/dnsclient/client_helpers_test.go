// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package dnsclient

import (
	"testing"
	"time"
)

func TestDnsTypeFromString(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"A", false},
		{"a", false},
		{"AAAA", false},
		{"aaaa", false},
		{"MX", false},
		{"TXT", false},
		{"NS", false},
		{"CNAME", false},
		{"CAA", false},
		{"SOA", false},
		{"SRV", false},
		{"TLSA", false},
		{"DNSKEY", false},
		{"DS", false},
		{"RRSIG", false},
		{"NSEC", false},
		{"NSEC3", false},
		{"PTR", false},
		{"INVALID", true},
		{"", true},
		{"HINFO", true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			_, err := dnsTypeFromString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("dnsTypeFromString(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestBoolToInt(t *testing.T) {
	if boolToInt(true) != 1 {
		t.Error("boolToInt(true) should be 1")
	}
	if boolToInt(false) != 0 {
		t.Error("boolToInt(false) should be 0")
	}
}

func TestIsNXDomain(t *testing.T) {
	if isNXDomain(nil) {
		t.Error("isNXDomain(nil) should be false")
	}
}

func TestFindConsensus(t *testing.T) {
	t.Run("all_agree", func(t *testing.T) {
		input := map[string][]string{
			"Cloudflare": {"1.2.3.4"},
			"Google":     {"1.2.3.4"},
			"Quad9":      {"1.2.3.4"},
		}
		records, allSame, discrepancies := findConsensus(input)
		if !allSame {
			t.Error("expected consensus")
		}
		if len(discrepancies) != 0 {
			t.Errorf("expected no discrepancies, got %v", discrepancies)
		}
		if len(records) != 1 || records[0] != "1.2.3.4" {
			t.Errorf("expected [1.2.3.4], got %v", records)
		}
	})

	t.Run("disagreement", func(t *testing.T) {
		input := map[string][]string{
			"Cloudflare": {"1.2.3.4"},
			"Google":     {"5.6.7.8"},
			"Quad9":      {"1.2.3.4"},
		}
		_, allSame, discrepancies := findConsensus(input)
		if allSame {
			t.Error("expected no consensus")
		}
		if len(discrepancies) == 0 {
			t.Error("expected discrepancies")
		}
	})

	t.Run("empty_results", func(t *testing.T) {
		input := map[string][]string{
			"Cloudflare": {},
			"Google":     {},
		}
		records, allSame, _ := findConsensus(input)
		if !allSame {
			t.Error("expected consensus for empty results")
		}
		if len(records) != 0 {
			t.Errorf("expected nil records, got %v", records)
		}
	})

	t.Run("single_resolver", func(t *testing.T) {
		input := map[string][]string{
			"Cloudflare": {"1.2.3.4", "5.6.7.8"},
		}
		records, allSame, _ := findConsensus(input)
		if !allSame {
			t.Error("expected consensus with single resolver")
		}
		if len(records) != 2 {
			t.Errorf("expected 2 records, got %v", records)
		}
	})
}

func TestParseDohResponse(t *testing.T) {
	t.Run("valid_A_record", func(t *testing.T) {
		body := []byte(`{"Status":0,"Answer":[{"data":"1.2.3.4","TTL":300}]}`)
		result := parseDohResponse(body, "A")
		if len(result.Records) != 1 || result.Records[0] != "1.2.3.4" {
			t.Errorf("expected [1.2.3.4], got %v", result.Records)
		}
		if result.TTL == nil || *result.TTL != 300 {
			t.Error("expected TTL 300")
		}
	})

	t.Run("valid_TXT_record", func(t *testing.T) {
		body := []byte(`{"Status":0,"Answer":[{"data":"\"v=spf1 include:_spf.google.com ~all\"","TTL":3600}]}`)
		result := parseDohResponse(body, "TXT")
		if len(result.Records) != 1 {
			t.Fatalf("expected 1 record, got %d", len(result.Records))
		}
	})

	t.Run("nxdomain", func(t *testing.T) {
		body := []byte(`{"Status":3,"Answer":[]}`)
		result := parseDohResponse(body, "A")
		if len(result.Records) != 0 {
			t.Errorf("expected empty for NXDOMAIN, got %v", result.Records)
		}
	})

	t.Run("empty_answer", func(t *testing.T) {
		body := []byte(`{"Status":0,"Answer":[]}`)
		result := parseDohResponse(body, "A")
		if len(result.Records) != 0 {
			t.Errorf("expected empty, got %v", result.Records)
		}
	})

	t.Run("invalid_json", func(t *testing.T) {
		body := []byte(`not json`)
		result := parseDohResponse(body, "A")
		if len(result.Records) != 0 {
			t.Error("expected empty for invalid JSON")
		}
	})

	t.Run("dedup_records", func(t *testing.T) {
		body := []byte(`{"Status":0,"Answer":[{"data":"1.2.3.4","TTL":300},{"data":"1.2.3.4","TTL":300}]}`)
		result := parseDohResponse(body, "A")
		if len(result.Records) != 1 {
			t.Errorf("expected dedup to 1 record, got %d", len(result.Records))
		}
	})

	t.Run("empty_data_skipped", func(t *testing.T) {
		body := []byte(`{"Status":0,"Answer":[{"data":"","TTL":300},{"data":"1.2.3.4","TTL":300}]}`)
		result := parseDohResponse(body, "A")
		if len(result.Records) != 1 {
			t.Errorf("expected 1 record, got %d", len(result.Records))
		}
	})

	t.Run("multiple_records", func(t *testing.T) {
		body := []byte(`{"Status":0,"Answer":[{"data":"1.2.3.4","TTL":300},{"data":"5.6.7.8","TTL":300}]}`)
		result := parseDohResponse(body, "A")
		if len(result.Records) != 2 {
			t.Errorf("expected 2 records, got %d", len(result.Records))
		}
	})
}

func TestNewClient(t *testing.T) {
	c := New()
	if c == nil {
		t.Fatal("New() returned nil")
	}
	if len(c.resolvers) != len(DefaultResolvers) {
		t.Errorf("expected %d resolvers, got %d", len(DefaultResolvers), len(c.resolvers))
	}
}

func TestNewClientWithOptions(t *testing.T) {
	customResolvers := []ResolverConfig{{Name: "Test", IP: "1.2.3.4"}}
	c := New(
		WithResolvers(customResolvers),
		WithTimeout(5*time.Second),
		WithCacheTTL(10*time.Minute),
	)
	if len(c.resolvers) != 1 {
		t.Errorf("expected 1 resolver, got %d", len(c.resolvers))
	}
	if c.timeout != 5*time.Second {
		t.Errorf("expected 5s timeout, got %v", c.timeout)
	}
	if c.cacheTTL != 10*time.Minute {
		t.Errorf("expected 10m cacheTTL, got %v", c.cacheTTL)
	}
}

func TestSetUserAgentVersion(t *testing.T) {
	original := UserAgent
	defer func() { UserAgent = original }()

	SetUserAgentVersion("2.0.0")
	expected := "DNSTool-DomainSecurityAudit/2.0.0 (+https://dnstool.it-help.tech)"
	if UserAgent != expected {
		t.Errorf("expected %q, got %q", expected, UserAgent)
	}
}

func TestCacheGetSet(t *testing.T) {
	c := New(WithCacheTTL(1 * time.Hour))
	c.cacheMax = 100

	_, ok := c.cacheGet("test:key")
	if ok {
		t.Error("expected cache miss")
	}

	c.cacheSet("test:key", []string{"val1", "val2"})
	data, ok := c.cacheGet("test:key")
	if !ok {
		t.Error("expected cache hit")
	}
	if len(data) != 2 || data[0] != "val1" {
		t.Errorf("unexpected cache data: %v", data)
	}
}

func TestCacheExpiry(t *testing.T) {
	c := New(WithCacheTTL(1 * time.Millisecond))
	c.cacheMax = 100

	c.cacheSet("test:key", []string{"val"})
	time.Sleep(5 * time.Millisecond)

	_, ok := c.cacheGet("test:key")
	if ok {
		t.Error("expected cache miss after expiry")
	}
}

func TestQueryDNS_EmptyInputs(t *testing.T) {
	c := New()
	ctx := t.Context()

	if result := c.QueryDNS(ctx, "", "example.com"); result != nil {
		t.Errorf("expected nil for empty recordType, got %v", result)
	}
	if result := c.QueryDNS(ctx, "A", ""); result != nil {
		t.Errorf("expected nil for empty domain, got %v", result)
	}
}

func TestQueryDNSWithTTL_EmptyInputs(t *testing.T) {
	c := New()
	ctx := t.Context()

	result := c.QueryDNSWithTTL(ctx, "", "example.com")
	if len(result.Records) != 0 {
		t.Error("expected empty for empty recordType")
	}
	result = c.QueryDNSWithTTL(ctx, "A", "")
	if len(result.Records) != 0 {
		t.Error("expected empty for empty domain")
	}
}

func TestQueryWithConsensus_EmptyInputs(t *testing.T) {
	c := New()
	ctx := t.Context()

	result := c.QueryWithConsensus(ctx, "", "example.com")
	if !result.Consensus {
		t.Error("expected consensus for empty recordType")
	}
	result = c.QueryWithConsensus(ctx, "A", "")
	if !result.Consensus {
		t.Error("expected consensus for empty domain")
	}
}

func TestDefaultResolvers(t *testing.T) {
	if len(DefaultResolvers) == 0 {
		t.Fatal("DefaultResolvers should not be empty")
	}
	for _, r := range DefaultResolvers {
		if r.Name == "" {
			t.Error("resolver name should not be empty")
		}
		if r.IP == "" {
			t.Error("resolver IP should not be empty")
		}
	}
}
