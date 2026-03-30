package analyzer

import (
	"context"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"

	"dnstool/go-server/internal/dnsclient"
)

type testDNSQuerier struct {
	nsResults map[string][]string
}

func (q *testDNSQuerier) QueryDNS(_ context.Context, recordType, domain string) []string {
	if recordType == "NS" {
		return q.nsResults[domain]
	}
	return nil
}
func (q *testDNSQuerier) QueryDNSWithTTL(context.Context, string, string) dnsclient.RecordWithTTL {
	return dnsclient.RecordWithTTL{}
}
func (q *testDNSQuerier) QueryWithConsensus(context.Context, string, string) dnsclient.ConsensusResult {
	return dnsclient.ConsensusResult{}
}
func (q *testDNSQuerier) QuerySpecificResolver(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}
func (q *testDNSQuerier) QueryWithTTLFromResolver(context.Context, string, string, string) dnsclient.RecordWithTTL {
	return dnsclient.RecordWithTTL{}
}
func (q *testDNSQuerier) CheckDNSSECADFlag(context.Context, string) dnsclient.ADFlagResult {
	return dnsclient.ADFlagResult{}
}
func (q *testDNSQuerier) ExchangeContext(context.Context, *dns.Msg) (*dns.Msg, error) {
	return nil, nil
}
func (q *testDNSQuerier) ValidateResolverConsensus(context.Context, string) map[string]any {
	return nil
}
func (q *testDNSQuerier) ProbeExists(context.Context, string) (bool, string) {
	return false, ""
}

var _ DNSQuerier = (*testDNSQuerier)(nil)

func TestFindParentZone_Found(t *testing.T) {
	q := &testDNSQuerier{
		nsResults: map[string][]string{
			"example.com": {"ns1.example.com"},
		},
	}
	got := findParentZone(q, context.Background(), "sub.example.com")
	if got != "example.com" {
		t.Errorf("findParentZone = %q, want 'example.com'", got)
	}
}

func TestFindParentZone_NotFound(t *testing.T) {
	q := &testDNSQuerier{nsResults: map[string][]string{}}
	got := findParentZone(q, context.Background(), "sub.example.com")
	if got != "" {
		t.Errorf("findParentZone = %q, want ''", got)
	}
}

func TestFindParentZone_DeepSubdomain(t *testing.T) {
	q := &testDNSQuerier{
		nsResults: map[string][]string{
			"example.com": {"ns1.dns.com"},
		},
	}
	got := findParentZone(q, context.Background(), "a.b.c.example.com")
	if !strings.HasSuffix(got, "example.com") {
		t.Errorf("findParentZone = %q", got)
	}
}

func TestFindParentZone_SingleLabel(t *testing.T) {
	q := &testDNSQuerier{nsResults: map[string][]string{}}
	got := findParentZone(q, context.Background(), "com")
	if got != "" {
		t.Errorf("findParentZone('com') = %q, want ''", got)
	}
}

func TestDNSQuerierInterfaceCompiles(t *testing.T) {
	var _ DNSQuerier = (*testDNSQuerier)(nil)
}
