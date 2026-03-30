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
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	mapKeyAdded   = "added"
	mapKeyDomain  = "domain"
	mapKeyRemoved = "removed"
	mapKeyType    = "type"
)

const dateFormatISO = "2006-01-02"

const maxHistoryCacheEntries = 500

type DNSHistoryCache struct {
	mu      sync.RWMutex
	entries map[string]*dnsHistoryCacheEntry
	ttl     time.Duration
}

type dnsHistoryCacheEntry struct {
	result   map[string]any
	cachedAt time.Time
}

func NewDNSHistoryCache(ttl time.Duration) *DNSHistoryCache {
	return &DNSHistoryCache{
		entries: make(map[string]*dnsHistoryCacheEntry),
		ttl:     ttl,
	}
}

func (c *DNSHistoryCache) Get(domain string) (map[string]any, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[domain]
	if !ok {
		return nil, false
	}
	if time.Since(entry.cachedAt) > c.ttl {
		return nil, false
	}

	cached := make(map[string]any, len(entry.result))
	for k, v := range entry.result {
		cached[k] = v
	}
	cached["cache_hit"] = true
	cached["cached_at"] = entry.cachedAt.UTC().Format(time.RFC3339)
	return cached, true
}

func (c *DNSHistoryCache) Set(domain string, result map[string]any) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= maxHistoryCacheEntries {
		c.evictOldest()
	}
	c.entries[domain] = &dnsHistoryCacheEntry{
		result:   result,
		cachedAt: time.Now(),
	}
}

func (c *DNSHistoryCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, e := range c.entries {
		if time.Since(e.cachedAt) > c.ttl {
			delete(c.entries, k)
			continue
		}
		if first || e.cachedAt.Before(oldestTime) {
			oldestKey = k
			oldestTime = e.cachedAt
			first = false
		}
	}
	if len(c.entries) >= maxHistoryCacheEntries && oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}

func (c *DNSHistoryCache) Stats() map[string]any {
	c.mu.RLock()
	defer c.mu.RUnlock()
	active := 0
	for _, e := range c.entries {
		if time.Since(e.cachedAt) <= c.ttl {
			active++
		}
	}
	return map[string]any{
		"total_entries":  len(c.entries),
		"active_entries": active,
		"ttl_hours":      int(c.ttl.Hours()),
		"max_entries":    maxHistoryCacheEntries,
	}
}

type stHistoryResponse struct {
	Records []stHistoryRecord `json:"records"`
	Pages   int               `json:"pages"`
	Type    string            `json:"type"`
}

type stHistoryRecord struct {
	FirstSeen     string           `json:"first_seen"`
	LastSeen      *string          `json:"last_seen"`
	Organizations []string         `json:"organizations"`
	Values        []stHistoryValue `json:"values"`
}

type stHistoryValue struct {
	IP      string `json:"ip"`
	IPCount int    `json:"ip_count"`
	Host    string `json:"host,omitempty"`
}

type dnsChangeEvent struct {
	RecordType  string
	Value       string
	Action      string
	Date        string
	Org         string
	Description string
	DaysAgo     int
}

type historyFetchResult struct {
	changes     []dnsChangeEvent
	rateLimited bool
	errored     bool
}

type historyAggregation struct {
	changes          []dnsChangeEvent
	rateLimitedCount int
	errorCount       int
	totalTypes       int
}

func fetchAllHistoryTypes(ctx context.Context, domain, userAPIKey string) historyAggregation {
	recordTypes := []string{"a", "aaaa", "mx", "ns"}
	type indexedResult struct {
		idx    int
		result historyFetchResult
	}
	resultsCh := make(chan indexedResult, len(recordTypes))
	for i, rtype := range recordTypes {
		go func(idx int, rt string) {
			resultsCh <- indexedResult{idx, fetchHistoryForTypeWithKey(ctx, domain, rt, userAPIKey)}
		}(i, rtype)
	}

	agg := historyAggregation{totalTypes: len(recordTypes)}
	for range recordTypes {
		ir := <-resultsCh
		agg.changes = append(agg.changes, ir.result.changes...)
		if ir.result.rateLimited {
			agg.rateLimitedCount++
		}
		if ir.result.errored {
			agg.errorCount++
		}
	}

	sort.Slice(agg.changes, func(i, j int) bool {
		return agg.changes[i].Date > agg.changes[j].Date
	})
	maxChanges := 15
	if len(agg.changes) > maxChanges {
		agg.changes = agg.changes[:maxChanges]
	}
	return agg
}

func buildHistoryResult(agg historyAggregation) map[string]any {
	changesMaps := make([]map[string]any, len(agg.changes))
	for i, ch := range agg.changes {
		changesMaps[i] = map[string]any{
			"record_type": ch.RecordType,
			"value":       ch.Value,
			"action":      ch.Action,
			"date":        ch.Date,
			"org":         ch.Org,
			"description": ch.Description,
			"days_ago":    float64(ch.DaysAgo),
		}
	}

	failedCount := agg.rateLimitedCount + agg.errorCount
	allFailed := failedCount == agg.totalTypes
	allRateLimited := agg.rateLimitedCount == agg.totalTypes
	anyFailed := failedCount > 0
	status := determineHistoryStatus(allRateLimited, allFailed, anyFailed)

	return map[string]any{
		"available":     !allFailed,
		"api_enabled":   true,
		"has_changes":   len(agg.changes) > 0,
		"changes":       changesMaps,
		"total_events":  float64(len(agg.changes)),
		"source":        "SecurityTrails",
		mapKeyStatus:    status,
		"rate_limited":  agg.rateLimitedCount > 0,
		"fully_checked": failedCount == 0,
	}
}

func FetchDNSHistoryWithKey(ctx context.Context, domain, userAPIKey string, cache *DNSHistoryCache) map[string]any {
	if userAPIKey == "" {
		return map[string]any{
			"available":   false,
			"api_enabled": false,
			mapKeyStatus:  "no_key",
		}
	}

	if cache != nil {
		if cached, ok := cache.Get(domain); ok {
			slog.Info("DNS history cache hit", mapKeyDomain, domain)
			return cached
		}
	}

	agg := fetchAllHistoryTypes(ctx, domain, userAPIKey)
	result := buildHistoryResult(agg)

	status, _ := result[mapKeyStatus].(string)
	if cache != nil && (status == "success" || status == "partial") {
		cache.Set(domain, result)
		slog.Info("DNS history cached", mapKeyDomain, domain, mapKeyStatus, status, "ttl", cache.ttl)
	}

	return result
}

func determineHistoryStatus(allRateLimited, allFailed, anyFailed bool) string {
	if allRateLimited {
		return "rate_limited"
	}
	if allFailed {
		return mapKeyError
	}
	if anyFailed {
		return "partial"
	}
	return "success"
}

func fetchHistoryForTypeWithKey(ctx context.Context, domain, rtype, apiKey string) historyFetchResult {
	url := fmt.Sprintf("https://api.securitytrails.com/v1/history/%s/dns/%s", domain, rtype)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		slog.Warn("SecurityTrails history: failed to create request", mapKeyDomain, domain, mapKeyType, rtype, mapKeyError, err)
		return historyFetchResult{errored: true}
	}
	req.Header.Set("APIKEY", apiKey)
	req.Header.Set("Accept", contentTypeJSON)

	resp, err := securityTrailsHTTPClient.Do(req)
	if err != nil {
		slog.Warn("SecurityTrails history: request failed", mapKeyDomain, domain, mapKeyType, rtype, mapKeyError, err)
		return historyFetchResult{errored: true}
	}
	defer safeClose(resp.Body, "securitytrails-history")

	if resp.StatusCode == http.StatusTooManyRequests {
		slog.Warn("SecurityTrails history: rate limited", mapKeyDomain, domain, mapKeyType, rtype)
		stBudget.markRateLimited()
		return historyFetchResult{rateLimited: true}
	}

	if resp.StatusCode != http.StatusOK {
		slog.Warn("SecurityTrails history: unexpected status", mapKeyDomain, domain, mapKeyType, rtype, mapKeyStatus, resp.StatusCode)
		return historyFetchResult{errored: true}
	}

	var histResp stHistoryResponse
	if err := json.NewDecoder(resp.Body).Decode(&histResp); err != nil {
		slog.Warn("SecurityTrails history: parse failed", mapKeyDomain, domain, mapKeyType, rtype, mapKeyError, err)
		return historyFetchResult{errored: true}
	}

	now := time.Now()
	upperType := strings.ToUpper(rtype)
	var changes []dnsChangeEvent

	for _, rec := range histResp.Records {
		value := extractHistoryValue(rec, rtype)
		if value == "" {
			continue
		}

		firstSeen, _ := time.Parse(dateFormatISO, rec.FirstSeen)

		var daysActive int
		var daysSinceGone int

		if rec.LastSeen != nil {
			lastSeen, _ := time.Parse(dateFormatISO, *rec.LastSeen)
			daysActive = int(lastSeen.Sub(firstSeen).Hours() / 24)
			daysSinceGone = int(now.Sub(lastSeen).Hours() / 24)
		} else {
			daysActive = int(now.Sub(firstSeen).Hours() / 24)
		}

		orgLabel := ""
		if len(rec.Organizations) > 0 {
			orgLabel = rec.Organizations[0]
		}

		changes = append(changes, dnsChangeEvent{
			RecordType:  upperType,
			Value:       value,
			Action:      mapKeyAdded,
			Date:        rec.FirstSeen,
			Org:         orgLabel,
			Description: buildChangeDescription(upperType, value, mapKeyAdded, orgLabel, daysActive),
			DaysAgo:     int(now.Sub(firstSeen).Hours() / 24),
		})

		if rec.LastSeen != nil {
			lastSeen, _ := time.Parse(dateFormatISO, *rec.LastSeen)
			changes = append(changes, dnsChangeEvent{
				RecordType:  upperType,
				Value:       value,
				Action:      mapKeyRemoved,
				Date:        *rec.LastSeen,
				Org:         orgLabel,
				Description: buildChangeDescription(upperType, value, mapKeyRemoved, orgLabel, daysSinceGone),
				DaysAgo:     int(now.Sub(lastSeen).Hours() / 24),
			})
		}
	}

	slog.Info("SecurityTrails history: fetched", mapKeyDomain, domain, mapKeyType, rtype, "events", len(changes))
	return historyFetchResult{changes: changes}
}

func extractHistoryValue(rec stHistoryRecord, rtype string) string {
	if len(rec.Values) == 0 {
		return ""
	}
	v := rec.Values[0]
	switch rtype {
	case "a", "aaaa":
		return v.IP
	case "mx", "ns":
		if v.Host != "" {
			return v.Host
		}
		return v.IP
	default:
		if v.IP != "" {
			return v.IP
		}
		return v.Host
	}
}

func buildChangeDescription(rtype, value, action, org string, daysMetric int) string {
	timeLabel := formatDaysAgo(daysMetric)

	switch action {
	case mapKeyAdded:
		if org != "" {
			return fmt.Sprintf("%s record %s (%s) appeared %s", rtype, value, org, timeLabel)
		}
		return fmt.Sprintf("%s record %s appeared %s", rtype, value, timeLabel)
	case mapKeyRemoved:
		if org != "" {
			return fmt.Sprintf("%s record %s (%s) was removed %s", rtype, value, org, timeLabel)
		}
		return fmt.Sprintf("%s record %s was removed %s", rtype, value, timeLabel)
	default:
		return fmt.Sprintf("%s record %s changed %s", rtype, value, timeLabel)
	}
}

func formatDaysAgo(days int) string {
	if days == 0 {
		return "today"
	}
	if days == 1 {
		return "yesterday"
	}
	if days < 7 {
		return fmt.Sprintf("%d days ago", days)
	}
	if days < 30 {
		weeks := days / 7
		if weeks == 1 {
			return "1 week ago"
		}
		return fmt.Sprintf("%d weeks ago", weeks)
	}
	if days < 365 {
		months := days / 30
		if months == 1 {
			return "1 month ago"
		}
		return fmt.Sprintf("%d months ago", months)
	}
	years := days / 365
	if years == 1 {
		return "1 year ago"
	}
	return fmt.Sprintf("%d years ago", years)
}
