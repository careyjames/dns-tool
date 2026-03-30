package analyzer

import (
        "strings"
        "sync"
        "testing"
        "time"
)

func TestCheckURLsAgainstOpenPhish_EmptyInput(t *testing.T) {
        indicators := CheckURLsAgainstOpenPhish(nil)
        if len(indicators) != 0 {
                t.Errorf("expected 0 indicators for nil input, got %d", len(indicators))
        }
}

func TestCheckURLsAgainstOpenPhish_EmptySlice(t *testing.T) {
        indicators := CheckURLsAgainstOpenPhish([]string{})
        if len(indicators) != 0 {
                t.Errorf("expected 0 indicators for empty slice, got %d", len(indicators))
        }
}

func TestCheckURLsAgainstOpenPhish_InvalidURLs(t *testing.T) {
        indicators := CheckURLsAgainstOpenPhish([]string{"not-a-url", "", ":::bad"})
        if len(indicators) != 0 {
                t.Errorf("invalid URLs should produce 0 indicators, got %d", len(indicators))
        }
}

func TestCheckURLsAgainstOpenPhish_WithPrepopulatedFeed(t *testing.T) {
        openPhishMu.Lock()
        origCache := openPhishCache
        origTime := openPhishCacheTime
        openPhishCache = map[string]bool{
                "phish.example.com": true,
        }
        openPhishCacheTime = time.Now()
        openPhishMu.Unlock()

        defer func() {
                openPhishMu.Lock()
                openPhishCache = origCache
                openPhishCacheTime = origTime
                openPhishMu.Unlock()
        }()

        indicators := CheckURLsAgainstOpenPhish([]string{"https://phish.example.com/login"})
        if len(indicators) != 1 {
                t.Fatalf("expected 1 indicator for known phishing domain, got %d", len(indicators))
        }
        if indicators[0].Category != "Known Phishing URLs" {
                t.Errorf("Category = %q", indicators[0].Category)
        }
        if indicators[0].Severity != "danger" {
                t.Errorf("Severity = %q", indicators[0].Severity)
        }
        if !strings.Contains(indicators[0].Evidence, "phish.example.com") {
                t.Errorf("Evidence = %q, should contain domain", indicators[0].Evidence)
        }
}

func TestCheckURLsAgainstOpenPhish_NoMatchInFeed(t *testing.T) {
        openPhishMu.Lock()
        origCache := openPhishCache
        origTime := openPhishCacheTime
        openPhishCache = map[string]bool{
                "phish.example.com": true,
        }
        openPhishCacheTime = time.Now()
        openPhishMu.Unlock()

        defer func() {
                openPhishMu.Lock()
                openPhishCache = origCache
                openPhishCacheTime = origTime
                openPhishMu.Unlock()
        }()

        indicators := CheckURLsAgainstOpenPhish([]string{"https://safe.example.com/page"})
        if len(indicators) != 0 {
                t.Errorf("safe domain should produce 0 indicators, got %d", len(indicators))
        }
}

func TestCheckURLsAgainstOpenPhish_DeduplicatesHosts(t *testing.T) {
        openPhishMu.Lock()
        origCache := openPhishCache
        origTime := openPhishCacheTime
        openPhishCache = map[string]bool{
                "phish.example.com": true,
        }
        openPhishCacheTime = time.Now()
        openPhishMu.Unlock()

        defer func() {
                openPhishMu.Lock()
                openPhishCache = origCache
                openPhishCacheTime = origTime
                openPhishMu.Unlock()
        }()

        indicators := CheckURLsAgainstOpenPhish([]string{
                "https://phish.example.com/page1",
                "https://phish.example.com/page2",
        })
        if len(indicators) != 1 {
                t.Errorf("expected 1 indicator (deduplicated), got %d", len(indicators))
        }
}

func TestCheckURLsAgainstOpenPhish_EmptyFeed(t *testing.T) {
        openPhishMu.Lock()
        origCache := openPhishCache
        origTime := openPhishCacheTime
        openPhishCache = map[string]bool{}
        openPhishCacheTime = time.Now()
        openPhishMu.Unlock()

        defer func() {
                openPhishMu.Lock()
                openPhishCache = origCache
                openPhishCacheTime = origTime
                openPhishMu.Unlock()
        }()

        indicators := CheckURLsAgainstOpenPhish([]string{"https://example.com"})
        if indicators != nil {
                t.Errorf("empty feed should return nil indicators, got %v", indicators)
        }
}

func TestOpenPhishConcurrentAccess(t *testing.T) {
        openPhishMu.Lock()
        origCache := openPhishCache
        origTime := openPhishCacheTime
        openPhishCache = map[string]bool{"test.com": true}
        openPhishCacheTime = time.Now()
        openPhishMu.Unlock()

        defer func() {
                openPhishMu.Lock()
                openPhishCache = origCache
                openPhishCacheTime = origTime
                openPhishMu.Unlock()
        }()

        var wg sync.WaitGroup
        for i := 0; i < 10; i++ {
                wg.Add(1)
                go func() {
                        defer wg.Done()
                        CheckURLsAgainstOpenPhish([]string{"https://test.com/path"})
                }()
        }
        wg.Wait()
}

func TestOpenPhishConstants(t *testing.T) {
        if openPhishFeedURL == "" {
                t.Error("openPhishFeedURL is empty")
        }
        if openPhishCacheTTL <= 0 {
                t.Error("openPhishCacheTTL should be positive")
        }
}
