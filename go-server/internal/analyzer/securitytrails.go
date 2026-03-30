// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const contentTypeJSON = "application/json"

const (
	stMonthlyBudget     = 50
	stBudgetReserve     = 5
	stSubdomainCacheTTL = 24 * time.Hour
	stMaxSubdomainCache = 500
	stRateLimitCooldown = 6 * time.Hour

	mapKeyCount = "count"
	mapKeyMonth = "month"
	strAccept   = "Accept"
	strApikey   = "APIKEY"
)

var (
	securityTrailsEnabled bool
	securityTrailsAPIKey  string
	securityTrailsOnce    sync.Once

	stBudget = &stAPIBudget{}
)

type stAPIBudget struct {
	mu            sync.Mutex
	callCount     int
	monthKey      string
	rateLimitedAt time.Time
}

func (b *stAPIBudget) canSpend(n int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	currentMonth := time.Now().UTC().Format("2006-01")
	if b.monthKey != currentMonth {
		b.callCount = 0
		b.monthKey = currentMonth
		b.rateLimitedAt = time.Time{}
		slog.Info("SecurityTrails budget: new month reset", mapKeyMonth, currentMonth)
	}

	if !b.rateLimitedAt.IsZero() && time.Since(b.rateLimitedAt) < stRateLimitCooldown {
		return false
	}

	return b.callCount+n <= stMonthlyBudget-stBudgetReserve
}

func (b *stAPIBudget) spend(n int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.callCount += n
	slog.Info("SecurityTrails budget: spent", "calls", n, "total_this_month", b.callCount, "remaining", stMonthlyBudget-b.callCount)
}

func (b *stAPIBudget) markRateLimited() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.rateLimitedAt = time.Now()
	slog.Warn("SecurityTrails budget: rate limited, cooling down", "cooldown", stRateLimitCooldown)
}

func (b *stAPIBudget) stats() map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	currentMonth := time.Now().UTC().Format("2006-01")
	if b.monthKey != currentMonth {
		return map[string]any{mapKeyMonth: currentMonth, "used": 0, "budget": stMonthlyBudget, "available": true}
	}
	cooldownActive := !b.rateLimitedAt.IsZero() && time.Since(b.rateLimitedAt) < stRateLimitCooldown
	return map[string]any{
		mapKeyMonth:       b.monthKey,
		"used":            b.callCount,
		"budget":          stMonthlyBudget,
		"available":       b.callCount < stMonthlyBudget-stBudgetReserve && !cooldownActive,
		"cooldown_active": cooldownActive,
	}
}

func STBudgetAvailable(n int) bool {
	initSecurityTrails()
	if !securityTrailsEnabled {
		return false
	}
	return stBudget.canSpend(n)
}

func STBudgetStats() map[string]any {
	return stBudget.stats()
}

func initSecurityTrails() {
	securityTrailsOnce.Do(func() {
		securityTrailsAPIKey = os.Getenv("SECURITYTRAILS_API_KEY")
		securityTrailsEnabled = securityTrailsAPIKey != ""
		if securityTrailsEnabled {
			slog.Info("SecurityTrails API enabled")
		}
	})
}

var securityTrailsHTTPClient = &http.Client{
	Timeout: 10 * time.Second,
}

type stSubdomainCacheEntry struct {
	subdomains []string
	cachedAt   time.Time
}

var (
	stSubdomainCache   = make(map[string]*stSubdomainCacheEntry)
	stSubdomainCacheMu sync.RWMutex
)

func getSubdomainCache(domain string) ([]string, bool) {
	stSubdomainCacheMu.RLock()
	defer stSubdomainCacheMu.RUnlock()
	entry, ok := stSubdomainCache[domain]
	if !ok || time.Since(entry.cachedAt) > stSubdomainCacheTTL {
		return nil, false
	}
	result := make([]string, len(entry.subdomains))
	copy(result, entry.subdomains)
	return result, true
}

func setSubdomainCache(domain string, subs []string) {
	stSubdomainCacheMu.Lock()
	defer stSubdomainCacheMu.Unlock()
	if len(stSubdomainCache) >= stMaxSubdomainCache {
		var oldestKey string
		var oldestTime time.Time
		first := true
		for k, e := range stSubdomainCache {
			if time.Since(e.cachedAt) > stSubdomainCacheTTL {
				delete(stSubdomainCache, k)
				continue
			}
			if first || e.cachedAt.Before(oldestTime) {
				oldestKey = k
				oldestTime = e.cachedAt
				first = false
			}
		}
		if len(stSubdomainCache) >= stMaxSubdomainCache && oldestKey != "" {
			delete(stSubdomainCache, oldestKey)
		}
	}
	cached := make([]string, len(subs))
	copy(cached, subs)
	stSubdomainCache[domain] = &stSubdomainCacheEntry{subdomains: cached, cachedAt: time.Now()}
}

type stSubdomainsResponse struct {
	Subdomains []string `json:"subdomains"`
}

type stSearchResponse struct {
	Records []struct {
		Hostname string `json:"hostname"`
	} `json:"records"`
}

type STFetchStatus struct {
	RateLimited bool
	Errored     bool
}

func FetchSubdomains(ctx context.Context, domain string) ([]string, *STFetchStatus, error) {
	initSecurityTrails()
	if !securityTrailsEnabled {
		return nil, nil, nil
	}

	if cached, ok := getSubdomainCache(domain); ok {
		slog.Info("SecurityTrails subdomains: cache hit", mapKeyDomain, domain, mapKeyCount, len(cached))
		return cached, nil, nil
	}

	if !stBudget.canSpend(1) {
		slog.Info("SecurityTrails subdomains: budget exhausted, skipping", mapKeyDomain, domain)
		return []string{}, nil, nil
	}

	url := fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains?children_only=false&include_inactive=false", domain)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		slog.Warn("SecurityTrails: failed to create request", mapKeyDomain, domain, mapKeyError, err)
		return []string{}, &STFetchStatus{Errored: true}, nil
	}
	req.Header.Set(strApikey, securityTrailsAPIKey)
	req.Header.Set(strAccept, contentTypeJSON)

	stBudget.spend(1)
	resp, err := securityTrailsHTTPClient.Do(req)
	if err != nil {
		slog.Warn("SecurityTrails: request failed", mapKeyDomain, domain, mapKeyError, err)
		return []string{}, &STFetchStatus{Errored: true}, nil
	}
	defer safeClose(resp.Body, "securitytrails-subdomains")

	if resp.StatusCode == http.StatusTooManyRequests {
		slog.Warn("SecurityTrails: rate limited (429)", mapKeyDomain, domain)
		stBudget.markRateLimited()
		return []string{}, &STFetchStatus{RateLimited: true}, nil
	}

	if resp.StatusCode != http.StatusOK {
		slog.Warn("SecurityTrails: unexpected status", mapKeyDomain, domain, mapKeyStatus, resp.StatusCode)
		return []string{}, &STFetchStatus{Errored: true}, nil
	}

	var stResp stSubdomainsResponse
	if err := json.NewDecoder(resp.Body).Decode(&stResp); err != nil {
		slog.Warn("SecurityTrails: failed to parse response", mapKeyDomain, domain, mapKeyError, err)
		return []string{}, &STFetchStatus{Errored: true}, nil
	}

	fqdns := make([]string, 0, len(stResp.Subdomains))
	for _, label := range stResp.Subdomains {
		if label == "" {
			continue
		}
		fqdns = append(fqdns, label+"."+domain)
	}

	setSubdomainCache(domain, fqdns)
	slog.Info("SecurityTrails: discovered subdomains", mapKeyDomain, domain, mapKeyCount, len(fqdns))
	return fqdns, nil, nil
}

func FetchDomainsByIP(ctx context.Context, ip string) ([]string, error) {
	initSecurityTrails()
	if !securityTrailsEnabled {
		return nil, nil
	}
	return fetchDomainsByIPInternal(ctx, ip, securityTrailsAPIKey)
}

func FetchDomainsByIPWithKey(ctx context.Context, ip, userAPIKey string) ([]string, error) {
	if userAPIKey == "" {
		return nil, nil
	}
	return fetchDomainsByIPInternal(ctx, ip, userAPIKey)
}

func fetchDomainsByIPInternal(ctx context.Context, ip, apiKey string) ([]string, error) {
	ipField := "ipv4"
	if strings.Contains(ip, ":") {
		ipField = "ipv6"
	}

	payload := map[string]any{
		"filter": map[string]string{
			ipField: ip,
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		slog.Warn("SecurityTrails: failed to marshal search payload", "ip", ip, mapKeyError, err)
		return []string{}, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.securitytrails.com/v1/search/list", bytes.NewReader(body))
	if err != nil {
		slog.Warn("SecurityTrails: failed to create search request", "ip", ip, mapKeyError, err)
		return []string{}, nil
	}
	req.Header.Set(strApikey, apiKey)
	req.Header.Set(strAccept, contentTypeJSON)
	req.Header.Set("Content-Type", contentTypeJSON)

	resp, err := securityTrailsHTTPClient.Do(req)
	if err != nil {
		slog.Warn("SecurityTrails: search request failed", "ip", ip, mapKeyError, err)
		return nil, fmt.Errorf("connection_error")
	}
	defer safeClose(resp.Body, "securitytrails-search")

	if resp.StatusCode == http.StatusTooManyRequests {
		slog.Warn("SecurityTrails: rate limited (429)", "ip", ip)
		return nil, fmt.Errorf("rate_limited")
	}

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		slog.Warn("SecurityTrails: auth failed", "ip", ip, mapKeyStatus, resp.StatusCode)
		return nil, fmt.Errorf("auth_failed")
	}

	if resp.StatusCode != http.StatusOK {
		slog.Warn("SecurityTrails: search unexpected status", "ip", ip, mapKeyStatus, resp.StatusCode)
		return nil, fmt.Errorf("api_error_%d", resp.StatusCode)
	}

	var stResp stSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&stResp); err != nil {
		slog.Warn("SecurityTrails: failed to parse search response", "ip", ip, mapKeyError, err)
		return []string{}, nil
	}

	domains := make([]string, 0, len(stResp.Records))
	for _, rec := range stResp.Records {
		if rec.Hostname != "" {
			domains = append(domains, rec.Hostname)
		}
	}

	slog.Info("SecurityTrails: discovered domains by IP", "ip", ip, mapKeyCount, len(domains))
	return domains, nil
}

func FetchSubdomainsWithKey(ctx context.Context, domain, userAPIKey string) ([]string, error) {
	if userAPIKey == "" {
		return nil, nil
	}

	url := fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains?children_only=false&include_inactive=false", domain)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(strApikey, userAPIKey)
	req.Header.Set(strAccept, contentTypeJSON)

	resp, err := securityTrailsHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer safeClose(resp.Body, "securitytrails-subdomains-userkey")

	if resp.StatusCode != http.StatusOK {
		return []string{}, nil
	}

	var stResp stSubdomainsResponse
	if err := json.NewDecoder(resp.Body).Decode(&stResp); err != nil {
		return nil, err
	}

	fqdns := make([]string, 0, len(stResp.Subdomains))
	for _, label := range stResp.Subdomains {
		if label != "" {
			fqdns = append(fqdns, label+"."+domain)
		}
	}

	slog.Info("SecurityTrails: discovered subdomains (user key)", mapKeyDomain, domain, mapKeyCount, len(fqdns))
	return fqdns, nil
}
