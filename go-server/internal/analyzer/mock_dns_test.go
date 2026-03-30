// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"codeberg.org/miekg/dns"

	"dnstool/go-server/internal/dnsclient"
)

type MockDNSClient struct {
	mu            sync.Mutex
	responses     map[string][]string
	consensusResp map[string]dnsclient.ConsensusResult
	ttlResponses  map[string]dnsclient.RecordWithTTL
	adFlagResults map[string]dnsclient.ADFlagResult
	exchangeFunc  func(ctx context.Context, msg *dns.Msg) (*dns.Msg, error)
	probeResults  map[string]struct {
		exists bool
		cname  string
	}
	validationResp map[string]map[string]any
	specificResp   map[string][]string
}

func NewMockDNSClient() *MockDNSClient {
	return &MockDNSClient{
		responses:     make(map[string][]string),
		consensusResp: make(map[string]dnsclient.ConsensusResult),
		ttlResponses:  make(map[string]dnsclient.RecordWithTTL),
		adFlagResults: make(map[string]dnsclient.ADFlagResult),
		probeResults: make(map[string]struct {
			exists bool
			cname  string
		}),
		validationResp: make(map[string]map[string]any),
		specificResp:   make(map[string][]string),
	}
}

func mockKey(recordType, domain string) string {
	return fmt.Sprintf("%s:%s", strings.ToUpper(recordType), strings.ToLower(domain))
}

func (m *MockDNSClient) AddResponse(recordType, domain string, records []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.responses[mockKey(recordType, domain)] = records
}

func (m *MockDNSClient) AddConsensusResponse(recordType, domain string, cr dnsclient.ConsensusResult) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.consensusResp[mockKey(recordType, domain)] = cr
}

func (m *MockDNSClient) AddTTLResponse(recordType, domain string, r dnsclient.RecordWithTTL) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ttlResponses[mockKey(recordType, domain)] = r
}

func (m *MockDNSClient) AddADFlagResult(domain string, r dnsclient.ADFlagResult) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.adFlagResults[strings.ToLower(domain)] = r
}

func (m *MockDNSClient) AddProbeResult(domain string, exists bool, cname string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.probeResults[strings.ToLower(domain)] = struct {
		exists bool
		cname  string
	}{exists, cname}
}

func (m *MockDNSClient) AddSpecificResolverResponse(recordType, domain, resolverIP string, records []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := fmt.Sprintf("%s:%s:%s", strings.ToUpper(recordType), strings.ToLower(domain), resolverIP)
	m.specificResp[key] = records
}

func (m *MockDNSClient) SetExchangeFunc(f func(ctx context.Context, msg *dns.Msg) (*dns.Msg, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.exchangeFunc = f
}

func (m *MockDNSClient) QueryDNS(_ context.Context, recordType, domain string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.responses[mockKey(recordType, domain)]
}

func (m *MockDNSClient) QueryDNSWithTTL(_ context.Context, recordType, domain string) dnsclient.RecordWithTTL {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.ttlResponses[mockKey(recordType, domain)]; ok {
		return r
	}
	if recs, ok := m.responses[mockKey(recordType, domain)]; ok {
		return dnsclient.RecordWithTTL{Records: recs}
	}
	return dnsclient.RecordWithTTL{}
}

func (m *MockDNSClient) QueryWithConsensus(_ context.Context, recordType, domain string) dnsclient.ConsensusResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cr, ok := m.consensusResp[mockKey(recordType, domain)]; ok {
		return cr
	}
	recs := m.responses[mockKey(recordType, domain)]
	return dnsclient.ConsensusResult{
		Records:       recs,
		Consensus:     true,
		ResolverCount: 5,
	}
}

func (m *MockDNSClient) QuerySpecificResolver(_ context.Context, recordType, domain, resolverIP string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := fmt.Sprintf("%s:%s:%s", strings.ToUpper(recordType), strings.ToLower(domain), resolverIP)
	if recs, ok := m.specificResp[key]; ok {
		return recs, nil
	}
	return m.responses[mockKey(recordType, domain)], nil
}

func (m *MockDNSClient) QueryWithTTLFromResolver(_ context.Context, recordType, domain, _ string) dnsclient.RecordWithTTL {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.ttlResponses[mockKey(recordType, domain)]; ok {
		return r
	}
	if recs, ok := m.responses[mockKey(recordType, domain)]; ok {
		return dnsclient.RecordWithTTL{Records: recs}
	}
	return dnsclient.RecordWithTTL{}
}

func (m *MockDNSClient) CheckDNSSECADFlag(_ context.Context, domain string) dnsclient.ADFlagResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.adFlagResults[strings.ToLower(domain)]; ok {
		return r
	}
	return dnsclient.ADFlagResult{}
}

func (m *MockDNSClient) ExchangeContext(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	m.mu.Lock()
	f := m.exchangeFunc
	m.mu.Unlock()
	if f != nil {
		return f(ctx, msg)
	}
	resp := new(dns.Msg)
	resp.ID = msg.ID
	resp.Response = true
	resp.Question = msg.Question
	return resp, nil
}

func (m *MockDNSClient) ValidateResolverConsensus(_ context.Context, domain string) map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.validationResp[strings.ToLower(domain)]; ok {
		return r
	}
	return map[string]any{
		"consensus_reached":    true,
		"resolvers_queried":    5,
		"checks_performed":     4,
		"discrepancies":        []string{},
		"per_record_consensus": map[string]any{},
	}
}

func (m *MockDNSClient) ProbeExists(_ context.Context, domain string) (bool, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.probeResults[strings.ToLower(domain)]; ok {
		return r.exists, r.cname
	}
	return false, ""
}

type MockHTTPClient struct {
	mu        sync.Mutex
	responses map[string]*http.Response
	errors    map[string]error
}

func NewMockHTTPClient() *MockHTTPClient {
	return &MockHTTPClient{
		responses: make(map[string]*http.Response),
		errors:    make(map[string]error),
	}
}

func (m *MockHTTPClient) AddResponse(url string, statusCode int, body string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.responses[url] = &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

func (m *MockHTTPClient) AddError(url string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errors[url] = err
}

func (m *MockHTTPClient) Get(_ context.Context, rawURL string) (*http.Response, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err, ok := m.errors[rawURL]; ok {
		return nil, err
	}
	if resp, ok := m.responses[rawURL]; ok {
		return resp, nil
	}
	return nil, fmt.Errorf("mock: no response configured for %s", rawURL)
}

func (m *MockHTTPClient) GetDirect(_ context.Context, rawURL string) (*http.Response, error) {
	return m.Get(context.Background(), rawURL)
}

func (m *MockHTTPClient) ReadBody(resp *http.Response, maxBytes int64) ([]byte, error) {
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, maxBytes))
}
