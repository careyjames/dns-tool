// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"context"
	"net/http"
	"strings"

	"codeberg.org/miekg/dns"

	"dnstool/go-server/internal/dnsclient"
)

type DNSQuerier interface {
	QueryDNS(ctx context.Context, recordType, domain string) []string
	QueryDNSWithTTL(ctx context.Context, recordType, domain string) dnsclient.RecordWithTTL
	QueryWithConsensus(ctx context.Context, recordType, domain string) dnsclient.ConsensusResult
	QuerySpecificResolver(ctx context.Context, recordType, domain, resolverIP string) ([]string, error)
	QueryWithTTLFromResolver(ctx context.Context, recordType, domain, resolverIP string) dnsclient.RecordWithTTL
	CheckDNSSECADFlag(ctx context.Context, domain string) dnsclient.ADFlagResult
	ExchangeContext(ctx context.Context, msg *dns.Msg) (*dns.Msg, error)
	ValidateResolverConsensus(ctx context.Context, domain string) map[string]any
	ProbeExists(ctx context.Context, domain string) (exists bool, cname string)
}

type HTTPClient interface {
	Get(ctx context.Context, rawURL string) (*http.Response, error)
	GetDirect(ctx context.Context, rawURL string) (*http.Response, error)
	ReadBody(resp *http.Response, maxBytes int64) ([]byte, error)
}

func findParentZone(c DNSQuerier, ctx context.Context, domain string) string {
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts)-1; i++ {
		candidate := strings.Join(parts[i:], ".")
		results := c.QueryDNS(ctx, "NS", candidate)
		if len(results) > 0 {
			return candidate
		}
	}
	return ""
}
