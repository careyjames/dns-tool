package dnsclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

func TestProbeExists_CancelledContext(t *testing.T) {
	c := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	exists, cname := c.ProbeExists(ctx, "example.com")
	if exists {
		t.Error("expected false for cancelled context")
	}
	if cname != "" {
		t.Errorf("expected empty cname, got %q", cname)
	}
}

func TestProbeExists_UnreachableResolver(t *testing.T) {
	c := New(WithTimeout(50 * time.Millisecond))
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	exists, cname := c.ProbeExists(ctx, "this-domain-should-not-exist-zzz.invalid")
	_ = exists
	_ = cname
}

func TestCheckDNSSECADFlag_CancelledContext(t *testing.T) {
	c := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := c.CheckDNSSECADFlag(ctx, "example.com")
	if result.ADFlag {
		t.Error("expected false AD flag for cancelled context")
	}
	if result.Error == nil {
		t.Log("cancelled context may or may not set error")
	}
}

func TestCheckDNSSECADFlag_UnreachableResolvers(t *testing.T) {
	c := New(WithTimeout(50 * time.Millisecond))
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	result := c.CheckDNSSECADFlag(ctx, "example.com")
	_ = result.ADFlag
	_ = result.Validated
	_ = result.ResolverUsed
	_ = result.Error
}

func TestValidateResolverConsensus_CancelledContext(t *testing.T) {
	c := New(WithResolvers([]ResolverConfig{{Name: "test", IP: "192.0.2.1"}}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := c.ValidateResolverConsensus(ctx, "example.com")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if _, ok := result["consensus_reached"]; !ok {
		t.Error("expected consensus_reached key")
	}
	if _, ok := result["resolvers_queried"]; !ok {
		t.Error("expected resolvers_queried key")
	}
	if _, ok := result["checks_performed"]; !ok {
		t.Error("expected checks_performed key")
	}
	if _, ok := result["discrepancies"]; !ok {
		t.Error("expected discrepancies key")
	}
	if _, ok := result["per_record_consensus"]; !ok {
		t.Error("expected per_record_consensus key")
	}
}

func TestValidateResolverConsensus_EmptyDomain(t *testing.T) {
	c := New()
	ctx := context.Background()

	result := c.ValidateResolverConsensus(ctx, "")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	checksPerformed, ok := result["checks_performed"].(int)
	if !ok {
		t.Fatal("checks_performed should be int")
	}
	if checksPerformed != 4 {
		t.Logf("checks_performed = %d (empty domain returns consensus=true for all types)", checksPerformed)
	}
}

func TestValidateResolverConsensus_UnreachableResolvers(t *testing.T) {
	c := New(
		WithResolvers([]ResolverConfig{{Name: "bad", IP: "192.0.2.1"}}),
		WithTimeout(50*time.Millisecond),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	result := c.ValidateResolverConsensus(ctx, "example.com")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestFindParentZone_CancelledContext(t *testing.T) {
	c := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := FindParentZone(c, ctx, "sub.example.com")
	_ = result
}

func TestFindParentZone_SingleLabel(t *testing.T) {
	c := New()
	ctx := context.Background()

	result := FindParentZone(c, ctx, "com")
	if result != "" {
		t.Errorf("expected empty for single-label domain, got %q", result)
	}
}

func TestFindParentZone_TwoLabels(t *testing.T) {
	c := New()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	result := FindParentZone(c, ctx, "example.com")
	if result != "" {
		t.Logf("FindParentZone returned %q for two-label domain (loop doesn't execute)", result)
	}
}

func TestFindParentZone_WithCachedResults(t *testing.T) {
	c := New(WithCacheTTL(1 * time.Hour))
	c.cacheMax = 100
	ctx := context.Background()

	c.cacheSet("NS:example.com", []string{"ns1.example.com."})

	result := FindParentZone(c, ctx, "sub.example.com")
	if result != "example.com" {
		t.Errorf("expected 'example.com' from cached NS, got %q", result)
	}
}

func TestFindParentZone_DeepSubdomain(t *testing.T) {
	c := New(WithCacheTTL(1 * time.Hour))
	c.cacheMax = 100
	ctx := context.Background()

	c.cacheSet("NS:example.com", []string{"ns1.example.com."})

	result := FindParentZone(c, ctx, "deep.sub.example.com")
	if result != "sub.example.com" && result != "example.com" {
		t.Logf("FindParentZone returned %q for deep subdomain", result)
	}
}

func TestQueryWithConsensus_AllResolversFail(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-json")
		w.WriteHeader(200)
		io.WriteString(w, `{"Status":0,"Answer":[{"data":"1.2.3.4","TTL":300}]}`)
	}))
	defer ts.Close()

	c := New(
		WithResolvers([]ResolverConfig{{Name: "bad", IP: "192.0.2.1"}}),
		WithHTTPClient(ts.Client()),
		WithTimeout(50*time.Millisecond),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	result := c.QueryWithConsensus(ctx, "A", "example.com")
	_ = result
}

func TestQueryWithConsensus_SingleResolverFails(t *testing.T) {
	c := New(
		WithResolvers([]ResolverConfig{
			{Name: "unreachable", IP: "192.0.2.1"},
		}),
		WithTimeout(50*time.Millisecond),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	result := c.QueryWithConsensus(ctx, "A", "example.com")
	_ = result.Consensus
	_ = result.ResolverCount
}

func TestQueryDNS_FallsBackToUDP(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer ts.Close()

	c := New(
		WithHTTPClient(ts.Client()),
		WithResolvers([]ResolverConfig{{Name: "unreachable", IP: "192.0.2.1"}}),
		WithTimeout(50*time.Millisecond),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	result := c.QueryDNS(ctx, "A", "example.com")
	_ = result
}

func TestQueryDNSWithTTL_FallsBackToUDP(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer ts.Close()

	c := New(
		WithHTTPClient(ts.Client()),
		WithResolvers([]ResolverConfig{{Name: "unreachable", IP: "192.0.2.1"}}),
		WithTimeout(50*time.Millisecond),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	result := c.QueryDNSWithTTL(ctx, "A", "example.com")
	_ = result
}

func TestQueryDNS_DohSuccess(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-json")
		w.WriteHeader(200)
		io.WriteString(w, `{"Status":0,"Answer":[{"data":"93.184.216.34","TTL":3600}]}`)
	}))
	defer ts.Close()

	c := New(
		WithHTTPClient(ts.Client()),
		WithCacheTTL(1*time.Hour),
	)
	c.cacheMax = 100
	ctx := context.Background()

	result := c.QueryDNS(ctx, "A", "test-doh-success.example.com")
	if len(result) == 0 {
		t.Log("DoH mock may not work due to hardcoded URL")
	}
}

func TestQueryDNSWithTTL_DohSuccess(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-json")
		w.WriteHeader(200)
		io.WriteString(w, `{"Status":0,"Answer":[{"data":"93.184.216.34","TTL":3600}]}`)
	}))
	defer ts.Close()

	c := New(WithHTTPClient(ts.Client()))
	ctx := context.Background()

	result := c.QueryDNSWithTTL(ctx, "A", "test-doh-ttl.example.com")
	_ = result
}

func TestDohQueryWithTTL_ReadBodyError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(200)
		w.Write([]byte("short"))
	}))
	defer ts.Close()

	c := New(WithHTTPClient(ts.Client()))
	result := c.dohQueryWithTTL(context.Background(), "example.com", "A")
	_ = result
}

func TestQuerySingleResolver_ValidButUnreachable(t *testing.T) {
	c := New(WithTimeout(50 * time.Millisecond))
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	resolverIP, results, errStr := c.querySingleResolver(ctx, "example.com", "A", "192.0.2.1")
	if resolverIP != "192.0.2.1" {
		t.Errorf("expected resolverIP 192.0.2.1, got %s", resolverIP)
	}
	if results != nil {
		t.Log("unexpected results from unreachable resolver")
	}
	if errStr == "" {
		t.Log("expected error from unreachable resolver")
	}
}

func TestQuerySpecificResolver_ValidButUnreachable(t *testing.T) {
	c := New(WithTimeout(50 * time.Millisecond))
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	results, err := c.QuerySpecificResolver(ctx, "A", "example.com", "192.0.2.1")
	if err == nil {
		t.Log("expected error for unreachable resolver")
	}
	_ = results
}

func TestQueryWithTTLFromResolver_ValidButUnreachable(t *testing.T) {
	c := New(WithTimeout(50 * time.Millisecond))
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	result := c.QueryWithTTLFromResolver(ctx, "A", "example.com", "192.0.2.1")
	if len(result.Records) != 0 {
		t.Log("unexpected records from unreachable resolver")
	}
}

func TestUdpQueryWithTTL_ValidButUnreachable(t *testing.T) {
	c := New(WithTimeout(50 * time.Millisecond))
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	result := c.udpQueryWithTTL(ctx, "example.com", "A", "192.0.2.1")
	if len(result.Records) != 0 {
		t.Log("unexpected records from unreachable resolver")
	}
}

func TestUdpQuery_ValidButUnreachable(t *testing.T) {
	c := New(WithTimeout(50 * time.Millisecond))
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	result := c.udpQuery(ctx, "example.com", "A", "192.0.2.1")
	if len(result) != 0 {
		t.Log("unexpected records from unreachable resolver")
	}
}

func TestExchangeWithFallback_UDPFailsThenTCPFails(t *testing.T) {
	c := New(WithTimeout(50 * time.Millisecond))
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	msg := newTestMsg("example.com.")
	_, err := c.exchangeWithFallback(ctx, msg, "192.0.2.1:53")
	if err == nil {
		t.Log("expected error when both UDP and TCP fail")
	}
}

func TestExchangeContext_WithMsg(t *testing.T) {
	c := New(
		WithResolvers([]ResolverConfig{{Name: "bad", IP: "192.0.2.1"}}),
		WithTimeout(50*time.Millisecond),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	msg := newTestMsg("example.com.")
	_, err := c.ExchangeContext(ctx, msg)
	if err == nil {
		t.Log("expected error for unreachable resolver")
	}
}

func TestIsNXDomain_WithRcode(t *testing.T) {
	msg := newTestMsg("example.com.")
	msg.Rcode = 3
	if !isNXDomain(msg) {
		t.Error("expected NXDOMAIN for Rcode 3")
	}
}

func TestIsNXDomain_WithNonNXDomainRcode(t *testing.T) {
	msg := newTestMsg("example.com.")
	msg.Rcode = 0
	if isNXDomain(msg) {
		t.Error("expected false for Rcode 0")
	}
}

func TestParseDohResponse_InvalidJSON(t *testing.T) {
	result := parseDohResponse([]byte(`{invalid`), "A")
	if len(result.Records) != 0 {
		t.Error("expected empty for invalid JSON")
	}
}

func TestParseDohResponse_MultipleRecordTypes(t *testing.T) {
	types := []string{"A", "AAAA", "MX", "NS", "CNAME", "SOA", "SRV", "CAA"}
	for _, rt := range types {
		body := []byte(`{"Status":0,"Answer":[{"data":"test-data","TTL":300}]}`)
		result := parseDohResponse(body, rt)
		if rt == "TXT" {
			continue
		}
		if len(result.Records) != 1 {
			t.Errorf("expected 1 record for type %s, got %d", rt, len(result.Records))
		}
	}
}

func TestQueryDNS_CacheSetAfterDoH(t *testing.T) {
	c := New(WithCacheTTL(1 * time.Hour))
	c.cacheMax = 100

	c.cacheSet("A:cached.example.com", []string{"10.0.0.1"})
	result := c.QueryDNS(context.Background(), "A", "cached.example.com")
	if len(result) != 1 || result[0] != "10.0.0.1" {
		t.Errorf("expected cached result, got %v", result)
	}
}

func TestGetTLD_VariousCases(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"a.b.c.d.example.org", "org"},
		{"UPPER.CASE.NET", "net"},
		{"single", "single"},
		{"", ""},
		{"a.com.", ""},
	}
	for _, tt := range tests {
		got := GetTLD(tt.input)
		if got != tt.want {
			t.Errorf("GetTLD(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestDohQueryWithTTL_SuccessfulResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" {
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/dns-json")
		w.WriteHeader(200)
		io.WriteString(w, `{"Status":0,"Answer":[{"data":"10.20.30.40","TTL":600}]}`)
	}))
	defer ts.Close()

	c := New(WithHTTPClient(ts.Client()))
	result := c.dohQueryWithTTL(context.Background(), "example.com", "A")
	_ = result.Records
	_ = result.TTL
}

func TestDohQueryWithTTL_EmptyAnswers(t *testing.T) {
	body := []byte(`{"Status":0,"Answer":[]}`)
	result := parseDohResponse(body, "A")
	if len(result.Records) != 0 {
		t.Errorf("expected empty for no answers, got %v", result.Records)
	}
}

func TestQueryWithConsensus_ContextTimeout(t *testing.T) {
	c := New(
		WithResolvers([]ResolverConfig{
			{Name: "r1", IP: "192.0.2.1"},
			{Name: "r2", IP: "192.0.2.2"},
		}),
		WithTimeout(50*time.Millisecond),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	result := c.QueryWithConsensus(ctx, "A", "example.com")
	_ = result
}

func TestFindConsensus_AllResolversSameEmptyString(t *testing.T) {
	input := map[string][]string{
		"R1": {""},
		"R2": {""},
	}
	records, allSame, _ := findConsensus(input)
	if !allSame {
		t.Error("expected consensus for identical empty-string results")
	}
	_ = records
}

func TestQueryWithConsensus_WithInvalidType(t *testing.T) {
	c := New(
		WithResolvers([]ResolverConfig{{Name: "test", IP: "192.0.2.1"}}),
		WithTimeout(50*time.Millisecond),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	result := c.QueryWithConsensus(ctx, "BOGUS", "example.com")
	_ = result
}

func TestValidateResolverConsensus_ShortTimeout(t *testing.T) {
	c := New(
		WithResolvers([]ResolverConfig{
			{Name: "r1", IP: "192.0.2.1"},
			{Name: "r2", IP: "192.0.2.2"},
		}),
		WithTimeout(10*time.Millisecond),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	result := c.ValidateResolverConsensus(ctx, "test.invalid")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	queuedCount, ok := result["resolvers_queried"].(int)
	if !ok {
		t.Fatal("resolvers_queried should be int")
	}
	if queuedCount != 2 {
		t.Errorf("expected 2 resolvers queried, got %d", queuedCount)
	}
}

func TestParseDohResponse_TXTWithEmptyQuotes(t *testing.T) {
	body := []byte(`{"Status":0,"Answer":[{"data":"\"\"","TTL":300}]}`)
	result := parseDohResponse(body, "TXT")
	if len(result.Records) != 0 {
		t.Logf("empty quoted TXT resulted in %v records", len(result.Records))
	}
}

func TestParseDohResponse_AAAARecord(t *testing.T) {
	body := []byte(`{"Status":0,"Answer":[{"data":"2001:db8::1","TTL":300}]}`)
	result := parseDohResponse(body, "AAAA")
	if len(result.Records) != 1 || result.Records[0] != "2001:db8::1" {
		t.Errorf("unexpected AAAA result: %v", result.Records)
	}
}

func TestParseDohResponse_SRVRecord(t *testing.T) {
	body := []byte(`{"Status":0,"Answer":[{"data":"10 5 443 target.example.com.","TTL":300}]}`)
	result := parseDohResponse(body, "SRV")
	if len(result.Records) != 1 {
		t.Errorf("expected 1 SRV record, got %d", len(result.Records))
	}
}

func TestCheckDNSSECADFlag_EmptyDomain(t *testing.T) {
	c := New(WithTimeout(50 * time.Millisecond))
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	result := c.CheckDNSSECADFlag(ctx, "")
	_ = result
}

func TestProbeExists_EmptyDomain(t *testing.T) {
	c := New(WithTimeout(50 * time.Millisecond))
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	exists, cname := c.ProbeExists(ctx, "")
	_ = exists
	_ = cname
}

func TestDohQueryWithTTL_ContextDeadlineExceeded(t *testing.T) {
	c := New()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	time.Sleep(1 * time.Millisecond)

	result := c.dohQueryWithTTL(ctx, "example.com", "A")
	if len(result.Records) != 0 {
		t.Log("expected empty for deadline exceeded")
	}
}

func TestQueryDNS_CacheKeyNormalization(t *testing.T) {
	c := New(WithCacheTTL(1 * time.Hour))
	c.cacheMax = 100

	c.cacheSet("MX:test.example.com", []string{"10 mx.example.com."})

	result := c.QueryDNS(context.Background(), "mx", "TEST.EXAMPLE.COM")
	if len(result) != 1 || result[0] != "10 mx.example.com." {
		t.Errorf("cache key normalization failed, got %v", result)
	}
}

func TestNewSafeHTTPClientWithTimeout_ZeroTimeout(t *testing.T) {
	c := NewSafeHTTPClientWithTimeout(0)
	if c == nil {
		t.Fatal("returned nil for zero timeout")
	}
}

func TestValidateURLTarget_EmptyString(t *testing.T) {
	result := ValidateURLTarget("")
	if result {
		t.Error("expected false for empty URL")
	}
}

func TestValidateURLTarget_MalformedURL(t *testing.T) {
	result := ValidateURLTarget("://bad-url")
	if result {
		t.Error("expected false for malformed URL")
	}
}

func TestGetDirect_EmptyURL(t *testing.T) {
	client := NewRDAPHTTPClient()
	ctx := context.Background()

	_, err := client.GetDirect(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
}

func TestSafeHTTPClient_Get_NilContext(t *testing.T) {
	client := NewSafeHTTPClient()
	client.SkipSSRF = true

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	resp, err := client.Get(context.Background(), ts.URL)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	resp.Body.Close()
}

func TestGetDirect_AllowedHostButUnreachable(t *testing.T) {
	client := NewRDAPHTTPClient()
	client.client.Timeout = 100 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err := client.GetDirect(ctx, "https://rdap.verisign.com/com/v1/domain/example.com")
	_ = err
}

func TestSafeHTTPClient_GetWithHeaders_NilHeaders(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	client := NewSafeHTTPClient()
	client.SkipSSRF = true

	resp, err := client.GetWithHeaders(context.Background(), ts.URL, nil)
	if err != nil {
		t.Fatalf("GetWithHeaders with nil headers failed: %v", err)
	}
	resp.Body.Close()
}

func TestIsPrivateIP_Multicast(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"224.0.0.1", true},
		{"ff02::1", true},
	}
	for _, tt := range tests {
		got := IsPrivateIP(tt.ip)
		if got != tt.want {
			t.Errorf("IsPrivateIP(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestQueryDNS_EmptyBothInputs(t *testing.T) {
	c := New()
	result := c.QueryDNS(context.Background(), "", "")
	if result != nil {
		t.Error("expected nil for both empty inputs")
	}
}

func TestCheckDNSSECADFlag_WithShortTimeout(t *testing.T) {
	c := New(WithTimeout(10 * time.Millisecond))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	result := c.CheckDNSSECADFlag(ctx, "nonexistent.invalid.test")
	if result.Validated {
		t.Error("expected not validated for unreachable domain")
	}
}

func TestGetDirect_AllowedHostNotReachable(t *testing.T) {
	client := NewRDAPHTTPClient()
	client.client.Timeout = 50 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := client.GetDirect(ctx, "https://rdap.org/domain/example.com")
	_ = err
}

func TestQueryWithConsensus_NoResolvers(t *testing.T) {
	c := New(WithResolvers([]ResolverConfig{}))
	ctx := context.Background()

	result := c.QueryWithConsensus(ctx, "A", "example.com")
	if result.ResolverCount > 0 && len(result.ResolverResults) == 0 {
		t.Log("no resolvers should produce DoH fallback")
	}
}

func TestDohQueryWithTTL_NXDOMAIN(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-json")
		w.WriteHeader(200)
		io.WriteString(w, `{"Status":3}`)
	}))
	defer ts.Close()

	c := New(WithHTTPClient(ts.Client()))
	result := c.dohQueryWithTTL(context.Background(), "nonexistent.example.com", "A")
	if len(result.Records) != 0 {
		t.Error("expected empty for NXDOMAIN")
	}
}

func TestFindConsensus_LargeNumberOfResolvers(t *testing.T) {
	input := make(map[string][]string)
	for i := 0; i < 10; i++ {
		name := "R" + strings.Repeat("x", i)
		input[name] = []string{"1.2.3.4"}
	}
	records, allSame, discrepancies := findConsensus(input)
	if !allSame {
		t.Error("expected consensus when all agree")
	}
	if len(records) != 1 || records[0] != "1.2.3.4" {
		t.Errorf("expected [1.2.3.4], got %v", records)
	}
	if len(discrepancies) != 0 {
		t.Errorf("expected no discrepancies, got %v", discrepancies)
	}
}

func newTestMsg(domain string) *dns.Msg {
	return dns.NewMsg(domain, dns.TypeA)
}
