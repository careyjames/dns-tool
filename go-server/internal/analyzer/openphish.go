// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"bufio"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	openPhishFeedURL  = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
	openPhishCacheTTL = 12 * time.Hour
)

var (
	openPhishCache     map[string]bool
	openPhishCacheTime time.Time
	openPhishMu        sync.RWMutex
)

func fetchOpenPhishFeed() map[string]bool {
	openPhishMu.RLock()
	if openPhishCache != nil && time.Since(openPhishCacheTime) < openPhishCacheTTL {
		defer openPhishMu.RUnlock()
		return openPhishCache
	}
	openPhishMu.RUnlock()

	openPhishMu.Lock()
	defer openPhishMu.Unlock()

	if openPhishCache != nil && time.Since(openPhishCacheTime) < openPhishCacheTTL {
		return openPhishCache
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(openPhishFeedURL)
	if err != nil {
		return openPhishCache
	}
	defer safeClose(resp.Body, "openphish")

	if resp.StatusCode != http.StatusOK {
		return openPhishCache
	}

	feed := make(map[string]bool)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parsed, err := url.Parse(line)
		if err == nil && parsed.Host != "" {
			feed[strings.ToLower(parsed.Host)] = true
			feed[strings.ToLower(line)] = true
		}
	}

	if len(feed) > 0 {
		openPhishCache = feed
		openPhishCacheTime = time.Now()
	}

	return openPhishCache
}

func CheckURLsAgainstOpenPhish(urls []string) []PhishingIndicator {
	feed := fetchOpenPhishFeed()
	if feed == nil || len(feed) == 0 {
		return nil
	}

	var indicators []PhishingIndicator
	var matchedDomains []string

	seen := make(map[string]bool)
	for _, rawURL := range urls {
		parsed, err := url.Parse(rawURL)
		if err != nil || parsed.Host == "" {
			continue
		}
		host := strings.ToLower(parsed.Host)
		if seen[host] {
			continue
		}
		seen[host] = true

		if feed[host] || feed[strings.ToLower(rawURL)] {
			matchedDomains = append(matchedDomains, host)
		}
	}

	if len(matchedDomains) > 0 {
		indicators = append(indicators, PhishingIndicator{
			Category:    "Known Phishing URLs",
			Severity:    "danger",
			Description: "One or more URLs in this email match domains from the OpenPhish public feed — a community-maintained list of confirmed phishing URLs.",
			Evidence:    "Matched domains: " + strings.Join(matchedDomains, ", "),
		})
	}

	return indicators
}
