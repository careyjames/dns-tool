// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

type IPInfoResult struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	City     string `json:"city"`
	Region   string `json:"region"`
	Country  string `json:"country"`
	Loc      string `json:"loc"`
	Org      string `json:"org"`
	Postal   string `json:"postal"`
	Timezone string `json:"timezone"`
	Anycast  bool   `json:"anycast"`
	Bogon    bool   `json:"bogon"`
}

var (
	ipInfoCache   = make(map[string]*ipInfoCacheEntry)
	ipInfoCacheMu sync.RWMutex
)

type ipInfoCacheEntry struct {
	result    *IPInfoResult
	fetchedAt time.Time
}

const ipInfoCacheTTL = 24 * time.Hour

var ipInfoHTTPClient = &http.Client{
	Timeout: 10 * time.Second,
}

func FetchIPInfo(ctx context.Context, ip, token string) (*IPInfoResult, error) {
	if token == "" {
		return nil, nil
	}

	ipInfoCacheMu.RLock()
	if entry, ok := ipInfoCache[ip]; ok && time.Since(entry.fetchedAt) < ipInfoCacheTTL {
		ipInfoCacheMu.RUnlock()
		slog.Info("IPInfo: cache hit", "ip", ip)
		return entry.result, nil
	}
	ipInfoCacheMu.RUnlock()

	url := fmt.Sprintf("https://ipinfo.io/%s/json?token=%s", ip, token)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		slog.Warn("IPInfo: failed to create request", "ip", ip, mapKeyError, err)
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := ipInfoHTTPClient.Do(req)
	if err != nil {
		slog.Warn("IPInfo: request failed", "ip", ip, mapKeyError, err)
		return nil, err
	}
	defer safeClose(resp.Body, "ipinfo")

	if resp.StatusCode == http.StatusTooManyRequests {
		slog.Warn("IPInfo: rate limited (429)", "ip", ip)
		return nil, fmt.Errorf("IPInfo rate limit exceeded")
	}

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		slog.Warn("IPInfo: invalid token", "ip", ip, "status", resp.StatusCode)
		return nil, fmt.Errorf("IPInfo: invalid or expired token")
	}

	if resp.StatusCode != http.StatusOK {
		slog.Warn("IPInfo: unexpected status", "ip", ip, "status", resp.StatusCode)
		return nil, fmt.Errorf("IPInfo: unexpected status %d", resp.StatusCode)
	}

	var result IPInfoResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		slog.Warn("IPInfo: failed to parse response", "ip", ip, mapKeyError, err)
		return nil, err
	}

	ipInfoCacheMu.Lock()
	ipInfoCache[ip] = &ipInfoCacheEntry{result: &result, fetchedAt: time.Now()}
	ipInfoCacheMu.Unlock()

	slog.Info("IPInfo: fetched data", "ip", ip, "city", result.City, "org", result.Org)
	return &result, nil
}
