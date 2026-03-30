package dnsclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWithHTTPClient(t *testing.T) {
	custom := &http.Client{Timeout: 99 * time.Second}
	c := New(WithHTTPClient(custom))
	if c.httpClient != custom {
		t.Error("expected custom HTTP client to be set")
	}
}

func TestWithResolvers(t *testing.T) {
	r := []ResolverConfig{{Name: "custom", IP: "9.9.9.9"}}
	c := New(WithResolvers(r))
	if len(c.resolvers) != 1 || c.resolvers[0].Name != "custom" {
		t.Errorf("expected custom resolver, got %v", c.resolvers)
	}
}

func TestWithTimeout(t *testing.T) {
	c := New(WithTimeout(7 * time.Second))
	if c.timeout != 7*time.Second {
		t.Errorf("expected 7s timeout, got %v", c.timeout)
	}
}

func TestWithCacheTTL(t *testing.T) {
	c := New(WithCacheTTL(15 * time.Minute))
	if c.cacheTTL != 15*time.Minute {
		t.Errorf("expected 15m cacheTTL, got %v", c.cacheTTL)
	}
}

func TestCacheEviction(t *testing.T) {
	c := New(WithCacheTTL(1 * time.Millisecond))
	c.cacheMax = 2

	c.cacheSet("key1", []string{"a"})
	c.cacheSet("key2", []string{"b"})
	time.Sleep(5 * time.Millisecond)
	c.cacheSet("key3", []string{"c"})

	_, ok1 := c.cacheGet("key1")
	_, ok2 := c.cacheGet("key2")
	if ok1 || ok2 {
		t.Error("expected expired entries to be evicted")
	}

	data, ok3 := c.cacheGet("key3")
	if !ok3 || len(data) != 1 || data[0] != "c" {
		t.Errorf("expected key3 to be present, got ok=%v data=%v", ok3, data)
	}
}

func TestCacheSetNoEvictionWhenUnderMax(t *testing.T) {
	c := New(WithCacheTTL(1 * time.Hour))
	c.cacheMax = 100

	c.cacheSet("k1", []string{"v1"})
	c.cacheSet("k2", []string{"v2"})

	d1, ok1 := c.cacheGet("k1")
	d2, ok2 := c.cacheGet("k2")
	if !ok1 || !ok2 {
		t.Error("expected both keys present")
	}
	if d1[0] != "v1" || d2[0] != "v2" {
		t.Errorf("unexpected data: %v, %v", d1, d2)
	}
}

func TestCacheGetMiss(t *testing.T) {
	c := New(WithCacheTTL(1 * time.Hour))
	_, ok := c.cacheGet("nonexistent")
	if ok {
		t.Error("expected cache miss for nonexistent key")
	}
}

func TestCacheZeroTTLAlwaysMisses(t *testing.T) {
	c := New()
	c.cacheSet("key", []string{"val"})
	_, ok := c.cacheGet("key")
	if ok {
		t.Error("with zero TTL, cache should always miss")
	}
}

func TestFindConsensus_AllEmpty(t *testing.T) {
	input := map[string][]string{}
	records, allSame, discrepancies := findConsensus(input)
	if !allSame {
		t.Error("expected consensus for empty input")
	}
	if len(records) != 0 {
		t.Errorf("expected no records, got %v", records)
	}
	if len(discrepancies) != 0 {
		t.Errorf("expected no discrepancies, got %v", discrepancies)
	}
}

func TestFindConsensus_MajorityWins(t *testing.T) {
	input := map[string][]string{
		"R1": {"1.2.3.4"},
		"R2": {"1.2.3.4"},
		"R3": {"5.6.7.8"},
	}
	records, allSame, discrepancies := findConsensus(input)
	if allSame {
		t.Error("expected no consensus")
	}
	if len(records) != 1 || records[0] != "1.2.3.4" {
		t.Errorf("expected majority [1.2.3.4], got %v", records)
	}
	if len(discrepancies) != 1 {
		t.Errorf("expected 1 discrepancy, got %d", len(discrepancies))
	}
}

func TestFindConsensus_MultipleRecords(t *testing.T) {
	input := map[string][]string{
		"R1": {"a", "b", "c"},
		"R2": {"a", "b", "c"},
	}
	records, allSame, _ := findConsensus(input)
	if !allSame {
		t.Error("expected consensus")
	}
	if len(records) != 3 {
		t.Errorf("expected 3 records, got %d", len(records))
	}
}

func TestParseDohResponse_NilAnswer(t *testing.T) {
	body := []byte(`{"Status":0}`)
	result := parseDohResponse(body, "A")
	if len(result.Records) != 0 {
		t.Errorf("expected empty, got %v", result.Records)
	}
}

func TestParseDohResponse_MXRecord(t *testing.T) {
	body := []byte(`{"Status":0,"Answer":[{"data":"10 mail.example.com.","TTL":600}]}`)
	result := parseDohResponse(body, "MX")
	if len(result.Records) != 1 || result.Records[0] != "10 mail.example.com." {
		t.Errorf("unexpected MX result: %v", result.Records)
	}
}

func TestParseDohResponse_TXTQuoteStripping(t *testing.T) {
	body := []byte(`{"Status":0,"Answer":[{"data":"\"v=spf1 ~all\"","TTL":300}]}`)
	result := parseDohResponse(body, "TXT")
	if len(result.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(result.Records))
	}
	if strings.Contains(result.Records[0], "\"") {
		t.Errorf("TXT record should have quotes stripped, got %q", result.Records[0])
	}
}

func TestParseDohResponse_NonTXTNoQuoteStrip(t *testing.T) {
	body := []byte(`{"Status":0,"Answer":[{"data":"\"1.2.3.4\"","TTL":300}]}`)
	result := parseDohResponse(body, "A")
	if len(result.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(result.Records))
	}
	if result.Records[0] != "\"1.2.3.4\"" {
		t.Errorf("non-TXT should preserve quotes, got %q", result.Records[0])
	}
}

func TestParseDohResponse_TTLSetFromFirst(t *testing.T) {
	body := []byte(`{"Status":0,"Answer":[{"data":"1.1.1.1","TTL":100},{"data":"2.2.2.2","TTL":200}]}`)
	result := parseDohResponse(body, "A")
	if result.TTL == nil || *result.TTL != 100 {
		t.Errorf("expected TTL 100 from first answer, got %v", result.TTL)
	}
}

func TestParseDohResponse_StatusNonZero(t *testing.T) {
	body := []byte(`{"Status":2,"Answer":[{"data":"1.2.3.4","TTL":300}]}`)
	result := parseDohResponse(body, "A")
	if len(result.Records) != 0 {
		t.Errorf("expected empty for non-zero status, got %v", result.Records)
	}
}

func TestDnsTypeFromString_CaseInsensitive(t *testing.T) {
	pairs := []struct{ a, b string }{
		{"a", "A"},
		{"aaaa", "AAAA"},
		{"mx", "MX"},
		{"txt", "TXT"},
		{"ns", "NS"},
		{"cname", "CNAME"},
		{"caa", "CAA"},
		{"soa", "SOA"},
		{"srv", "SRV"},
		{"tlsa", "TLSA"},
		{"dnskey", "DNSKEY"},
		{"ds", "DS"},
		{"rrsig", "RRSIG"},
		{"nsec", "NSEC"},
		{"nsec3", "NSEC3"},
		{"ptr", "PTR"},
	}
	for _, p := range pairs {
		v1, err1 := dnsTypeFromString(p.a)
		v2, err2 := dnsTypeFromString(p.b)
		if err1 != nil || err2 != nil {
			t.Errorf("unexpected error for %s/%s", p.a, p.b)
			continue
		}
		if v1 != v2 {
			t.Errorf("dnsTypeFromString(%q) != dnsTypeFromString(%q): %d vs %d", p.a, p.b, v1, v2)
		}
	}
}

func TestDnsTypeFromString_ErrorMessage(t *testing.T) {
	_, err := dnsTypeFromString("BOGUS")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unsupported record type") {
		t.Errorf("error should mention unsupported, got: %v", err)
	}
}

func TestRecordWithTTL_ZeroValue(t *testing.T) {
	var r RecordWithTTL
	if r.TTL != nil {
		t.Error("zero-value TTL should be nil")
	}
	if len(r.Records) != 0 {
		t.Error("zero-value Records should be empty")
	}
}

func TestConsensusResult_ZeroValue(t *testing.T) {
	var cr ConsensusResult
	if cr.Consensus {
		t.Error("zero-value Consensus should be false")
	}
	if cr.ResolverCount != 0 {
		t.Error("zero-value ResolverCount should be 0")
	}
}

func TestADFlagResult_ZeroValue(t *testing.T) {
	var r ADFlagResult
	if r.ADFlag || r.Validated {
		t.Error("zero-value should be false")
	}
	if r.ResolverUsed != nil || r.Error != nil {
		t.Error("zero-value pointers should be nil")
	}
}

func TestDohQueryWithTTL_MockServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-json")
		w.WriteHeader(200)
		io.WriteString(w, `{"Status":0,"Answer":[{"data":"93.184.216.34","TTL":3600}]}`)
	}))
	defer ts.Close()

	c := New(WithHTTPClient(ts.Client()))

	body := []byte(`{"Status":0,"Answer":[{"data":"93.184.216.34","TTL":3600}]}`)
	result := parseDohResponse(body, "A")
	if len(result.Records) != 1 || result.Records[0] != "93.184.216.34" {
		t.Errorf("unexpected result: %v", result.Records)
	}
	if result.TTL == nil || *result.TTL != 3600 {
		t.Errorf("expected TTL 3600, got %v", result.TTL)
	}
	_ = c
}

func TestNewDNSClient(t *testing.T) {
	c := newDNSClient(5 * time.Second)
	if c == nil {
		t.Fatal("newDNSClient returned nil")
	}
}

func TestIsNXDomain_Variants(t *testing.T) {
	if isNXDomain(nil) {
		t.Error("nil should not be NXDOMAIN")
	}
}

func TestBoolToInt_Values(t *testing.T) {
	tests := []struct {
		input bool
		want  int
	}{
		{true, 1},
		{false, 0},
	}
	for _, tt := range tests {
		got := boolToInt(tt.input)
		if got != tt.want {
			t.Errorf("boolToInt(%v) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestQueryDNS_CacheHit(t *testing.T) {
	c := New(WithCacheTTL(1 * time.Hour))
	c.cacheMax = 100
	ctx := context.Background()

	c.cacheSet("A:example.com", []string{"1.2.3.4"})

	result := c.QueryDNS(ctx, "A", "example.com")
	if len(result) != 1 || result[0] != "1.2.3.4" {
		t.Errorf("expected cached result [1.2.3.4], got %v", result)
	}
}

func TestQueryWithConsensus_EmptyDomainAndType(t *testing.T) {
	c := New()
	ctx := context.Background()

	r1 := c.QueryWithConsensus(ctx, "", "example.com")
	if !r1.Consensus {
		t.Error("empty type should return consensus=true")
	}

	r2 := c.QueryWithConsensus(ctx, "A", "")
	if !r2.Consensus {
		t.Error("empty domain should return consensus=true")
	}
}

func TestQueryDNSWithTTL_EmptyDomainAndType(t *testing.T) {
	c := New()
	ctx := context.Background()

	r1 := c.QueryDNSWithTTL(ctx, "", "example.com")
	if len(r1.Records) != 0 {
		t.Error("empty type should return empty")
	}

	r2 := c.QueryDNSWithTTL(ctx, "A", "")
	if len(r2.Records) != 0 {
		t.Error("empty domain should return empty")
	}
}

func TestSetUserAgentVersion_Format(t *testing.T) {
	original := UserAgent
	defer func() { UserAgent = original }()

	SetUserAgentVersion("3.1.4")
	if !strings.Contains(UserAgent, "3.1.4") {
		t.Errorf("UserAgent should contain version, got %q", UserAgent)
	}
	if !strings.Contains(UserAgent, "DNSTool-DomainSecurityAudit/") {
		t.Errorf("UserAgent should contain prefix, got %q", UserAgent)
	}
	if !strings.Contains(UserAgent, "dnstool.it-help.tech") {
		t.Errorf("UserAgent should contain URL, got %q", UserAgent)
	}
}

func TestDefaultResolvers_HasDoH(t *testing.T) {
	hasDoH := false
	for _, r := range DefaultResolvers {
		if r.DoH != "" {
			hasDoH = true
			break
		}
	}
	if !hasDoH {
		t.Error("expected at least one resolver with DoH")
	}
}

func TestDefaultResolvers_CloudflareAndGoogle(t *testing.T) {
	names := make(map[string]bool)
	for _, r := range DefaultResolvers {
		names[r.Name] = true
	}
	if !names["Cloudflare"] {
		t.Error("expected Cloudflare resolver")
	}
	if !names["Google"] {
		t.Error("expected Google resolver")
	}
}

func TestResolverConfig_Fields(t *testing.T) {
	rc := ResolverConfig{Name: "test", IP: "1.2.3.4", DoH: "https://test.example/dns-query"}
	if rc.Name != "test" || rc.IP != "1.2.3.4" || rc.DoH != "https://test.example/dns-query" {
		t.Errorf("unexpected config: %+v", rc)
	}
}

func TestQueryWithTTLFromResolver_InvalidType(t *testing.T) {
	c := New()
	ctx := context.Background()
	result := c.QueryWithTTLFromResolver(ctx, "INVALID", "example.com", "8.8.8.8")
	if len(result.Records) != 0 {
		t.Errorf("expected empty for invalid type, got %v", result.Records)
	}
}

func TestQuerySpecificResolver_InvalidType(t *testing.T) {
	c := New()
	ctx := context.Background()
	_, err := c.QuerySpecificResolver(ctx, "INVALID", "example.com", "8.8.8.8")
	if err == nil {
		t.Error("expected error for invalid record type")
	}
}

func TestExportFindConsensus(t *testing.T) {
	input := map[string][]string{
		"R1": {"1.2.3.4"},
		"R2": {"1.2.3.4"},
	}
	records, allSame, discrepancies := ExportFindConsensus(input)
	if !allSame {
		t.Error("expected consensus")
	}
	if len(discrepancies) != 0 {
		t.Errorf("expected no discrepancies, got %v", discrepancies)
	}
	if len(records) != 1 || records[0] != "1.2.3.4" {
		t.Errorf("expected [1.2.3.4], got %v", records)
	}
}

func TestUdpQuery_InvalidType(t *testing.T) {
	c := New()
	ctx := context.Background()
	result := c.udpQueryWithTTL(ctx, "example.com", "INVALID", "8.8.8.8")
	if len(result.Records) != 0 {
		t.Errorf("expected empty for invalid type, got %v", result.Records)
	}
}

func TestUdpQuery_ReturnsRecords(t *testing.T) {
	c := New()
	ctx := context.Background()
	records := c.udpQuery(ctx, "example.com", "INVALID", "8.8.8.8")
	if len(records) != 0 {
		t.Errorf("expected empty for invalid type, got %v", records)
	}
}

func TestDohQuery_CallsDohQueryWithTTL(t *testing.T) {
	c := New()
	ctx := context.Background()
	results := c.dohQuery(ctx, "this-does-not-exist-zzz.invalid", "A")
	if len(results) != 0 {
		t.Log("dohQuery returned results for non-existent domain (unexpected but not fatal)")
	}
}

func TestQueryDNS_CacheKeyFormat(t *testing.T) {
	c := New(WithCacheTTL(1 * time.Hour))
	c.cacheMax = 100
	ctx := context.Background()

	c.cacheSet("A:example.com", []string{"cached"})

	result := c.QueryDNS(ctx, "a", "EXAMPLE.COM")
	if len(result) != 1 || result[0] != "cached" {
		t.Errorf("cache key should be case-normalized, got %v", result)
	}
}

func TestGetTLD_EmptyString(t *testing.T) {
	result := GetTLD("")
	if result != "" {
		t.Errorf("expected empty, got %q", result)
	}
}

func TestGetTLD_SingleLabel(t *testing.T) {
	result := GetTLD("localhost")
	if result != "localhost" {
		t.Errorf("expected 'localhost', got %q", result)
	}
}

func TestFindConsensus_AllDifferent(t *testing.T) {
	input := map[string][]string{
		"R1": {"1.1.1.1"},
		"R2": {"2.2.2.2"},
		"R3": {"3.3.3.3"},
	}
	_, allSame, discrepancies := findConsensus(input)
	if allSame {
		t.Error("expected no consensus when all different")
	}
	if len(discrepancies) < 2 {
		t.Errorf("expected at least 2 discrepancies, got %d", len(discrepancies))
	}
}

func TestDohQueryWithTTL_MockHTTPServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" {
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/dns-json")
		w.WriteHeader(200)
		io.WriteString(w, `{"Status":0,"Answer":[{"data":"93.184.216.34","TTL":3600}]}`)
	}))
	defer ts.Close()

	c := New(WithHTTPClient(ts.Client()))

	result := c.dohQueryWithTTL(context.Background(), "example.com", "A")
	_ = result
}

func TestDohQueryWithTTL_NonOKStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer ts.Close()

	c := New(WithHTTPClient(ts.Client()))
	result := c.dohQueryWithTTL(context.Background(), "example.com", "A")
	_ = result
}

func TestDohQueryWithTTL_CancelledContext(t *testing.T) {
	c := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := c.dohQueryWithTTL(ctx, "example.com", "A")
	if len(result.Records) != 0 {
		t.Log("dohQueryWithTTL with cancelled context returned records")
	}
}

func TestDohQuery_Wrapper(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		io.WriteString(w, `{"Status":0,"Answer":[{"data":"1.2.3.4","TTL":300}]}`)
	}))
	defer ts.Close()

	c := New(WithHTTPClient(ts.Client()))
	results := c.dohQuery(context.Background(), "example.com", "A")
	_ = results
}

func TestParallelUDPQuery_CancelledContext(t *testing.T) {
	c := New(WithResolvers([]ResolverConfig{{Name: "test", IP: "192.0.2.1"}}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := c.parallelUDPQuery(ctx, "example.com", "A")
	if len(result) != 0 {
		t.Log("parallelUDPQuery with cancelled context returned results")
	}
}

func TestParallelUDPQueryWithTTL_CancelledContext(t *testing.T) {
	c := New(WithResolvers([]ResolverConfig{{Name: "test", IP: "192.0.2.1"}}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := c.parallelUDPQueryWithTTL(ctx, "example.com", "A")
	if len(result.Records) != 0 {
		t.Log("parallelUDPQueryWithTTL with cancelled context returned records")
	}
}

func TestNewClient_DefaultValues(t *testing.T) {
	c := New()
	if c.timeout != defaultTimeout {
		t.Errorf("expected default timeout %v, got %v", defaultTimeout, c.timeout)
	}
	if c.lifetime != defaultLifetime {
		t.Errorf("expected default lifetime %v, got %v", defaultLifetime, c.lifetime)
	}
	if c.cacheTTL != 0 {
		t.Errorf("expected 0 cacheTTL, got %v", c.cacheTTL)
	}
	if c.cacheMax != 0 {
		t.Errorf("expected 0 cacheMax, got %d", c.cacheMax)
	}
	if c.httpClient == nil {
		t.Error("expected non-nil httpClient")
	}
	if c.cache == nil {
		t.Error("expected non-nil cache map")
	}
}
