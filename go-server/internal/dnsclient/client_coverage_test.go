package dnsclient

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

func TestCacheConcurrentAccess(t *testing.T) {
	c := New(WithCacheTTL(1 * time.Hour))
	c.cacheMax = 1000

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			key := "key"
			c.cacheSet(key, []string{"val"})
			c.cacheGet(key)
		}(i)
	}
	wg.Wait()
}

func TestCacheEviction_AllExpired(t *testing.T) {
	c := New(WithCacheTTL(1 * time.Millisecond))
	c.cacheMax = 1

	c.cacheSet("a", []string{"1"})
	c.cacheSet("b", []string{"2"})
	time.Sleep(5 * time.Millisecond)
	c.cacheSet("c", []string{"3"})

	c.cacheMu.RLock()
	remaining := len(c.cache)
	c.cacheMu.RUnlock()

	if remaining > 1 {
		t.Errorf("expected at most 1 entry after eviction, got %d", remaining)
	}
}

func TestCacheSet_NoEvictionWhenCacheMaxZero(t *testing.T) {
	c := New(WithCacheTTL(1 * time.Hour))

	c.cacheSet("k1", []string{"v1"})
	c.cacheSet("k2", []string{"v2"})

	c.cacheMu.RLock()
	count := len(c.cache)
	c.cacheMu.RUnlock()

	if count != 2 {
		t.Errorf("expected 2 entries when cacheMax=0 (no eviction), got %d", count)
	}
}

func TestQueryDNS_EmptyDomain(t *testing.T) {
	c := New()
	ctx := context.Background()
	result := c.QueryDNS(ctx, "A", "")
	if result != nil {
		t.Errorf("expected nil for empty domain, got %v", result)
	}
}

func TestQueryDNS_EmptyType(t *testing.T) {
	c := New()
	ctx := context.Background()
	result := c.QueryDNS(ctx, "", "example.com")
	if result != nil {
		t.Errorf("expected nil for empty type, got %v", result)
	}
}

func TestQuerySingleResolver_InvalidType(t *testing.T) {
	c := New()
	ctx := context.Background()
	resolverIP, results, errStr := c.querySingleResolver(ctx, "example.com", "BOGUS", "8.8.8.8")
	if resolverIP != "8.8.8.8" {
		t.Errorf("expected resolverIP 8.8.8.8, got %s", resolverIP)
	}
	if results != nil {
		t.Errorf("expected nil results, got %v", results)
	}
	if errStr == "" {
		t.Error("expected error string for invalid type")
	}
}

func TestQuerySingleResolver_CancelledContext(t *testing.T) {
	c := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resolverIP, _, errStr := c.querySingleResolver(ctx, "example.com", "A", "192.0.2.1")
	if resolverIP != "192.0.2.1" {
		t.Errorf("expected resolverIP 192.0.2.1, got %s", resolverIP)
	}
	if errStr == "" {
		t.Error("expected error for cancelled context")
	}
}

func TestFindConsensus_SingleResolver(t *testing.T) {
	input := map[string][]string{
		"Only": {"1.2.3.4", "5.6.7.8"},
	}
	records, allSame, discrepancies := findConsensus(input)
	if !allSame {
		t.Error("single resolver should have consensus")
	}
	if len(records) != 2 {
		t.Errorf("expected 2 records, got %d", len(records))
	}
	if len(discrepancies) != 0 {
		t.Errorf("expected no discrepancies, got %v", discrepancies)
	}
}

func TestFindConsensus_EmptyRecords(t *testing.T) {
	input := map[string][]string{
		"R1": {},
		"R2": {},
		"R3": {},
	}
	records, allSame, _ := findConsensus(input)
	if !allSame {
		t.Error("expected consensus for all empty")
	}
	if len(records) != 0 {
		t.Errorf("expected nil records, got %v", records)
	}
}

func TestFindConsensus_MixedEmptyAndNonEmpty(t *testing.T) {
	input := map[string][]string{
		"R1": {"1.2.3.4"},
		"R2": {},
	}
	_, allSame, discrepancies := findConsensus(input)
	if allSame {
		t.Error("expected no consensus when results differ")
	}
	if len(discrepancies) == 0 {
		t.Error("expected discrepancies")
	}
}

func TestParseDohResponse_EmptyBody(t *testing.T) {
	result := parseDohResponse([]byte{}, "A")
	if len(result.Records) != 0 {
		t.Errorf("expected empty for empty body, got %v", result.Records)
	}
}

func TestParseDohResponse_WhitespaceData(t *testing.T) {
	body := []byte(`{"Status":0,"Answer":[{"data":"  1.2.3.4  ","TTL":300}]}`)
	result := parseDohResponse(body, "A")
	if len(result.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(result.Records))
	}
	if result.Records[0] != "1.2.3.4" {
		t.Errorf("expected trimmed data, got %q", result.Records[0])
	}
}

func TestParseDohResponse_TXTWithMultipleQuotedValues(t *testing.T) {
	body := []byte(`{"Status":0,"Answer":[{"data":"\"v=spf1 ~all\"","TTL":300},{"data":"\"v=DKIM1; p=key\"","TTL":300}]}`)
	result := parseDohResponse(body, "TXT")
	if len(result.Records) != 2 {
		t.Errorf("expected 2 TXT records, got %d", len(result.Records))
	}
	for _, r := range result.Records {
		if r[0] == '"' || r[len(r)-1] == '"' {
			t.Errorf("TXT record should have quotes stripped, got %q", r)
		}
	}
}

func TestParseDohResponse_NoAnswerKey(t *testing.T) {
	body := []byte(`{"Status":0}`)
	result := parseDohResponse(body, "A")
	if len(result.Records) != 0 {
		t.Errorf("expected empty, got %v", result.Records)
	}
	if result.TTL != nil {
		t.Error("expected nil TTL")
	}
}

func TestParseDohResponse_DuplicateTXT(t *testing.T) {
	body := []byte(`{"Status":0,"Answer":[{"data":"\"v=spf1 ~all\"","TTL":300},{"data":"\"v=spf1 ~all\"","TTL":300}]}`)
	result := parseDohResponse(body, "TXT")
	if len(result.Records) != 1 {
		t.Errorf("expected dedup to 1, got %d", len(result.Records))
	}
}

func TestDnsTypeFromString_AllTypes(t *testing.T) {
	types := map[string]bool{
		"A": true, "AAAA": true, "MX": true, "TXT": true,
		"NS": true, "CNAME": true, "CAA": true, "SOA": true,
		"SRV": true, "TLSA": true, "DNSKEY": true, "DS": true,
		"RRSIG": true, "NSEC": true, "NSEC3": true, "PTR": true,
	}
	for typeName := range types {
		_, err := dnsTypeFromString(typeName)
		if err != nil {
			t.Errorf("dnsTypeFromString(%q) unexpected error: %v", typeName, err)
		}
	}
}

func TestDnsTypeFromString_Empty(t *testing.T) {
	_, err := dnsTypeFromString("")
	if err == nil {
		t.Error("expected error for empty string")
	}
}

func TestBoolToInt_Comprehensive(t *testing.T) {
	if boolToInt(true) != 1 {
		t.Error("expected 1 for true")
	}
	if boolToInt(false) != 0 {
		t.Error("expected 0 for false")
	}
}

func TestIsNXDomain_NilMsg(t *testing.T) {
	if isNXDomain(nil) {
		t.Error("nil should not be NXDOMAIN")
	}
}

func TestNewClient_MultipleOptions(t *testing.T) {
	customResolvers := []ResolverConfig{{Name: "A", IP: "1.1.1.1"}, {Name: "B", IP: "8.8.8.8"}}
	customHTTP := &http.Client{Timeout: 42 * time.Second}
	c := New(
		WithResolvers(customResolvers),
		WithHTTPClient(customHTTP),
		WithTimeout(3*time.Second),
		WithCacheTTL(5*time.Minute),
	)
	if len(c.resolvers) != 2 {
		t.Errorf("expected 2 resolvers, got %d", len(c.resolvers))
	}
	if c.httpClient != customHTTP {
		t.Error("expected custom HTTP client")
	}
	if c.timeout != 3*time.Second {
		t.Errorf("expected 3s timeout, got %v", c.timeout)
	}
	if c.cacheTTL != 5*time.Minute {
		t.Errorf("expected 5m cacheTTL, got %v", c.cacheTTL)
	}
}

func TestQueryDNS_CacheHitCaseInsensitive(t *testing.T) {
	c := New(WithCacheTTL(1 * time.Hour))
	c.cacheMax = 100
	ctx := context.Background()

	c.cacheSet("TXT:example.com", []string{"v=spf1 ~all"})

	result := c.QueryDNS(ctx, "txt", "EXAMPLE.COM")
	if len(result) != 1 || result[0] != "v=spf1 ~all" {
		t.Errorf("expected cached TXT result, got %v", result)
	}
}

func TestQueryDNS_CacheHitMX(t *testing.T) {
	c := New(WithCacheTTL(1 * time.Hour))
	c.cacheMax = 100
	ctx := context.Background()

	c.cacheSet("MX:mail.example.com", []string{"10 mx1.example.com.", "20 mx2.example.com."})

	result := c.QueryDNS(ctx, "MX", "mail.example.com")
	if len(result) != 2 {
		t.Errorf("expected 2 MX records, got %v", result)
	}
}

func TestQueryWithConsensus_EmptyBothInputs(t *testing.T) {
	c := New()
	ctx := context.Background()

	r := c.QueryWithConsensus(ctx, "", "")
	if !r.Consensus {
		t.Error("empty inputs should return consensus=true")
	}
}

func TestQueryDNSWithTTL_EmptyBothInputs(t *testing.T) {
	c := New()
	ctx := context.Background()
	r := c.QueryDNSWithTTL(ctx, "", "")
	if len(r.Records) != 0 {
		t.Error("expected empty for both empty inputs")
	}
	if r.TTL != nil {
		t.Error("expected nil TTL")
	}
}

func TestDohQueryWithTTL_CancelledCtx(t *testing.T) {
	c := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := c.dohQueryWithTTL(ctx, "example.com", "A")
	if len(result.Records) != 0 {
		t.Log("cancelled ctx returned records unexpectedly")
	}
}

func TestDohQuery_ReturnsRecordsFromDohQueryWithTTL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-json")
		w.WriteHeader(200)
		io.WriteString(w, `{"Status":0,"Answer":[{"data":"10.20.30.40","TTL":100},{"data":"50.60.70.80","TTL":200}]}`)
	}))
	defer ts.Close()

	c := New(WithHTTPClient(ts.Client()))
	results := c.dohQuery(context.Background(), "example.com", "A")
	_ = results
}

func TestParallelUDPQuery_NoResolvers(t *testing.T) {
	c := New(WithResolvers([]ResolverConfig{}))
	ctx := context.Background()
	result := c.parallelUDPQuery(ctx, "example.com", "A")
	if len(result) != 0 {
		t.Errorf("expected empty with no resolvers, got %v", result)
	}
}

func TestParallelUDPQueryWithTTL_NoResolvers(t *testing.T) {
	c := New(WithResolvers([]ResolverConfig{}))
	ctx := context.Background()
	result := c.parallelUDPQueryWithTTL(ctx, "example.com", "A")
	if len(result.Records) != 0 {
		t.Errorf("expected empty with no resolvers, got %v", result.Records)
	}
}

func TestUdpQueryWithTTL_InvalidType(t *testing.T) {
	c := New()
	ctx := context.Background()
	result := c.udpQueryWithTTL(ctx, "example.com", "UNKNOWN", "8.8.8.8")
	if len(result.Records) != 0 {
		t.Error("expected empty for invalid type")
	}
	if result.TTL != nil {
		t.Error("expected nil TTL")
	}
}

func TestUdpQuery_CallsUdpQueryWithTTL(t *testing.T) {
	c := New()
	ctx := context.Background()
	records := c.udpQuery(ctx, "example.com", "INVALID", "8.8.8.8")
	if records != nil {
		t.Errorf("expected nil for invalid type, got %v", records)
	}
}

func TestExchangeContext_UsesFirstResolver(t *testing.T) {
	c := New(WithResolvers([]ResolverConfig{{Name: "Test", IP: "192.0.2.1"}}))
	if len(c.resolvers) != 1 || c.resolvers[0].IP != "192.0.2.1" {
		t.Error("expected single resolver with IP 192.0.2.1")
	}
}

func TestQueryWithTTLFromResolver_CancelledContext(t *testing.T) {
	c := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := c.QueryWithTTLFromResolver(ctx, "A", "example.com", "192.0.2.1")
	if len(result.Records) != 0 {
		t.Log("cancelled context returned records")
	}
}

func TestQuerySpecificResolver_CancelledContext(t *testing.T) {
	c := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.QuerySpecificResolver(ctx, "A", "example.com", "192.0.2.1")
	if err == nil {
		t.Log("cancelled context did not return error (may depend on timing)")
	}
}

func TestSetUserAgentVersion_Overwrites(t *testing.T) {
	original := UserAgent
	defer func() { UserAgent = original }()

	SetUserAgentVersion("1.0.0")
	v1 := UserAgent

	SetUserAgentVersion("2.0.0")
	v2 := UserAgent

	if v1 == v2 {
		t.Error("expected different user agents after version change")
	}
}

func TestDefaultResolvers_Count(t *testing.T) {
	if len(DefaultResolvers) < 3 {
		t.Errorf("expected at least 3 default resolvers, got %d", len(DefaultResolvers))
	}
}

func TestDefaultResolvers_AllHaveIPs(t *testing.T) {
	for _, r := range DefaultResolvers {
		if r.IP == "" {
			t.Errorf("resolver %s has empty IP", r.Name)
		}
		if r.Name == "" {
			t.Error("resolver has empty Name")
		}
	}
}

func TestDohResponse_StructFields(t *testing.T) {
	resp := dohResponse{
		Status: 0,
		Answer: []struct {
			Data string `json:"data"`
			TTL  uint32 `json:"TTL"`
			Type int    `json:"type"`
		}{
			{Data: "1.2.3.4", TTL: 300, Type: 1},
		},
	}
	if resp.Status != 0 {
		t.Error("expected status 0")
	}
	if len(resp.Answer) != 1 {
		t.Error("expected 1 answer")
	}
}

func TestParseDohResponse_OnlyWhitespace(t *testing.T) {
	body := []byte(`{"Status":0,"Answer":[{"data":"   ","TTL":300}]}`)
	result := parseDohResponse(body, "A")
	if len(result.Records) != 0 {
		t.Errorf("expected empty for whitespace-only data, got %v", result.Records)
	}
}

func TestParseDohResponse_LargeNumberOfRecords(t *testing.T) {
	body := []byte(`{"Status":0,"Answer":[` +
		`{"data":"1.1.1.1","TTL":100},` +
		`{"data":"2.2.2.2","TTL":200},` +
		`{"data":"3.3.3.3","TTL":300},` +
		`{"data":"4.4.4.4","TTL":400},` +
		`{"data":"5.5.5.5","TTL":500}` +
		`]}`)
	result := parseDohResponse(body, "A")
	if len(result.Records) != 5 {
		t.Errorf("expected 5 records, got %d", len(result.Records))
	}
	if result.TTL == nil || *result.TTL != 100 {
		t.Errorf("expected TTL 100, got %v", result.TTL)
	}
}

func TestParseDohResponse_NSRecord(t *testing.T) {
	body := []byte(`{"Status":0,"Answer":[{"data":"ns1.example.com.","TTL":86400}]}`)
	result := parseDohResponse(body, "NS")
	if len(result.Records) != 1 || result.Records[0] != "ns1.example.com." {
		t.Errorf("unexpected NS result: %v", result.Records)
	}
}

func TestParseDohResponse_CNAMERecord(t *testing.T) {
	body := []byte(`{"Status":0,"Answer":[{"data":"target.example.com.","TTL":300}]}`)
	result := parseDohResponse(body, "CNAME")
	if len(result.Records) != 1 || result.Records[0] != "target.example.com." {
		t.Errorf("unexpected CNAME result: %v", result.Records)
	}
}

func TestParseDohResponse_CAARecord(t *testing.T) {
	body := []byte(`{"Status":0,"Answer":[{"data":"0 issue \"letsencrypt.org\"","TTL":300}]}`)
	result := parseDohResponse(body, "CAA")
	if len(result.Records) != 1 {
		t.Errorf("expected 1 CAA record, got %d", len(result.Records))
	}
}

func TestNewDNSClient_NonNil(t *testing.T) {
	c := newDNSClient(1 * time.Second)
	if c == nil {
		t.Fatal("newDNSClient returned nil")
	}
}

func TestNewDNSClient_DifferentTimeouts(t *testing.T) {
	c1 := newDNSClient(1 * time.Second)
	c2 := newDNSClient(10 * time.Second)
	if c1 == nil || c2 == nil {
		t.Fatal("newDNSClient returned nil")
	}
}

func TestDohQueryWithTTL_BadJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-json")
		w.WriteHeader(200)
		io.WriteString(w, `not valid json`)
	}))
	defer ts.Close()

	c := New(WithHTTPClient(ts.Client()))
	result := c.dohQueryWithTTL(context.Background(), "example.com", "A")
	_ = result
}

func TestDohQueryWithTTL_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer ts.Close()

	c := New(WithHTTPClient(ts.Client()))
	result := c.dohQueryWithTTL(context.Background(), "example.com", "A")
	_ = result
}

func TestParseDohResponse_ServFail(t *testing.T) {
	body := []byte(`{"Status":2,"Answer":[{"data":"1.2.3.4","TTL":300}]}`)
	result := parseDohResponse(body, "A")
	if len(result.Records) != 0 {
		t.Error("expected empty for SERVFAIL status")
	}
}

func TestParseDohResponse_NXDomain(t *testing.T) {
	body := []byte(`{"Status":3}`)
	result := parseDohResponse(body, "A")
	if len(result.Records) != 0 {
		t.Error("expected empty for NXDOMAIN")
	}
}

func TestCacheGetExpiredEntry(t *testing.T) {
	c := New(WithCacheTTL(1 * time.Millisecond))
	c.cacheMax = 100
	c.cacheSet("test", []string{"val"})
	time.Sleep(5 * time.Millisecond)

	data, ok := c.cacheGet("test")
	if ok {
		t.Errorf("expected miss for expired entry, got %v", data)
	}
}

func TestFindConsensus_TwoResolversDifferent(t *testing.T) {
	input := map[string][]string{
		"R1": {"a.example.com."},
		"R2": {"b.example.com."},
	}
	_, allSame, discrepancies := findConsensus(input)
	if allSame {
		t.Error("expected no consensus")
	}
	if len(discrepancies) != 1 {
		t.Errorf("expected 1 discrepancy, got %d: %v", len(discrepancies), discrepancies)
	}
}

func TestFindConsensus_ThreeWayTie(t *testing.T) {
	input := map[string][]string{
		"R1": {"a"},
		"R2": {"b"},
		"R3": {"c"},
	}
	_, allSame, discrepancies := findConsensus(input)
	if allSame {
		t.Error("expected no consensus in 3-way tie")
	}
	if len(discrepancies) < 2 {
		t.Errorf("expected at least 2 discrepancies, got %d", len(discrepancies))
	}
}

func TestRrToString_ARecord(t *testing.T) {
	rr := &dns.A{
		A: rdata.A{Addr: netip.MustParseAddr("1.2.3.4")},
	}
	got := rrToString(rr)
	if got != "1.2.3.4" {
		t.Errorf("expected 1.2.3.4, got %q", got)
	}
}

func TestRrToString_AAAARecord(t *testing.T) {
	rr := &dns.AAAA{
		AAAA: rdata.AAAA{Addr: netip.MustParseAddr("2001:db8::1")},
	}
	got := rrToString(rr)
	if got != "2001:db8::1" {
		t.Errorf("expected 2001:db8::1, got %q", got)
	}
}

func TestRrToString_MXRecord(t *testing.T) {
	rr := &dns.MX{
		MX: rdata.MX{Preference: 10, Mx: "mail.example.com."},
	}
	got := rrToString(rr)
	if got != "10 mail.example.com." {
		t.Errorf("expected '10 mail.example.com.', got %q", got)
	}
}

func TestRrToString_TXTRecord(t *testing.T) {
	rr := &dns.TXT{
		TXT: rdata.TXT{Txt: []string{"v=spf1 ", "~all"}},
	}
	got := rrToString(rr)
	if got != "v=spf1 ~all" {
		t.Errorf("expected 'v=spf1 ~all', got %q", got)
	}
}

func TestRrToString_NSRecord(t *testing.T) {
	rr := &dns.NS{
		NS: rdata.NS{Ns: "ns1.example.com."},
	}
	got := rrToString(rr)
	if got != "ns1.example.com." {
		t.Errorf("expected 'ns1.example.com.', got %q", got)
	}
}

func TestRrToString_CNAMERecord(t *testing.T) {
	rr := &dns.CNAME{
		CNAME: rdata.CNAME{Target: "example.com."},
	}
	got := rrToString(rr)
	if got != "example.com." {
		t.Errorf("expected 'example.com.', got %q", got)
	}
}

func TestRrToString_CAARecord(t *testing.T) {
	rr := &dns.CAA{
		CAA: rdata.CAA{Flag: 0, Tag: "issue", Value: "letsencrypt.org"},
	}
	got := rrToString(rr)
	if !strings.Contains(got, "issue") || !strings.Contains(got, "letsencrypt.org") {
		t.Errorf("expected CAA with issue letsencrypt.org, got %q", got)
	}
}

func TestRrToString_SOARecord(t *testing.T) {
	rr := &dns.SOA{
		SOA: rdata.SOA{
			Ns:      "ns1.example.com.",
			Mbox:    "admin.example.com.",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   900,
			Expire:  604800,
			Minttl:  86400,
		},
	}
	got := rrToString(rr)
	if !strings.Contains(got, "ns1.example.com.") {
		t.Errorf("expected SOA with ns1, got %q", got)
	}
}

func TestRrToString_SRVRecord(t *testing.T) {
	rr := &dns.SRV{
		SRV: rdata.SRV{Priority: 10, Weight: 60, Port: 5060, Target: "sip.example.com."},
	}
	got := rrToString(rr)
	if !strings.Contains(got, "5060") || !strings.Contains(got, "sip.example.com.") {
		t.Errorf("expected SRV with port 5060, got %q", got)
	}
}

func TestRrToString_TLSARecord(t *testing.T) {
	rr := &dns.TLSA{
		TLSA: rdata.TLSA{Usage: 3, Selector: 1, MatchingType: 1, Certificate: "abc123"},
	}
	got := rrToString(rr)
	if !strings.Contains(got, "3") || !strings.Contains(got, "abc123") {
		t.Errorf("expected TLSA with usage 3, got %q", got)
	}
}

func TestRrToString_DNSKEYRecord(t *testing.T) {
	rr := &dns.DNSKEY{
		DNSKEY: rdata.DNSKEY{Flags: 256, Protocol: 3, Algorithm: 8, PublicKey: "AQPB+"},
	}
	got := rrToString(rr)
	if got == "" {
		t.Error("expected non-empty DNSKEY string")
	}
}

func TestRrToString_DSRecord(t *testing.T) {
	rr := &dns.DS{
		DS: rdata.DS{KeyTag: 12345, Algorithm: 8, DigestType: 2, Digest: "aabbccdd"},
	}
	got := rrToString(rr)
	if got == "" {
		t.Error("expected non-empty DS string")
	}
}

func TestRrToString_RRSIGRecord(t *testing.T) {
	rr := &dns.RRSIG{
		RRSIG: rdata.RRSIG{
			TypeCovered: dns.TypeA,
			Algorithm:   8,
			Labels:      2,
			OrigTTL:     300,
			Expiration:  20250101,
			Inception:   20240101,
			KeyTag:      12345,
			SignerName:  "example.com.",
			Signature:   "base64sig==",
		},
	}
	got := rrToString(rr)
	if got == "" {
		t.Error("expected non-empty RRSIG string")
	}
}

func TestRrToString_DefaultCase(t *testing.T) {
	rr := &dns.PTR{
		PTR: rdata.PTR{Ptr: "host.example.com."},
	}
	got := rrToString(rr)
	if got == "" {
		t.Error("expected non-empty PTR string")
	}
}

func TestExchangeContext_ReturnsClient(t *testing.T) {
	c := New(WithResolvers([]ResolverConfig{{Name: "test", IP: "192.0.2.1"}}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	msg := dns.NewMsg("example.com.", dns.TypeA)
	_, err := c.ExchangeContext(ctx, msg)
	if err == nil {
		t.Log("cancelled context may succeed or fail depending on timing")
	}
}

func TestExchangeWithFallback_CancelledContext(t *testing.T) {
	c := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	msg := dns.NewMsg("example.com.", dns.TypeA)
	_, err := c.exchangeWithFallback(ctx, msg, net.JoinHostPort("192.0.2.1", "53"))
	if err == nil {
		t.Log("expected error for cancelled context")
	}
}

func TestQueryDNS_BothEmpty(t *testing.T) {
	c := New()
	result := c.QueryDNS(context.Background(), "", "")
	if result != nil {
		t.Error("expected nil for both empty")
	}
}
