package analyzer

import (
	"testing"
	"time"
)

func TestDNSHistoryCache_GetSet(t *testing.T) {
	cache := NewDNSHistoryCache(1 * time.Hour)

	_, ok := cache.Get("example.com")
	if ok {
		t.Error("expected cache miss for empty cache")
	}

	cache.Set("example.com", map[string]any{"status": "success", "changes": []any{}})

	result, ok := cache.Get("example.com")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if result["status"] != "success" {
		t.Errorf("expected status=success, got %v", result["status"])
	}
	if result["cache_hit"] != true {
		t.Error("expected cache_hit=true")
	}
}

func TestDNSHistoryCache_Expiry(t *testing.T) {
	cache := NewDNSHistoryCache(1 * time.Millisecond)
	cache.Set("example.com", map[string]any{"status": "success"})

	time.Sleep(5 * time.Millisecond)

	_, ok := cache.Get("example.com")
	if ok {
		t.Error("expected cache miss after TTL expiry")
	}
}

func TestDNSHistoryCache_Stats(t *testing.T) {
	cache := NewDNSHistoryCache(1 * time.Hour)
	cache.Set("a.com", map[string]any{})
	cache.Set("b.com", map[string]any{})

	stats := cache.Stats()
	if stats["total_entries"] != 2 {
		t.Errorf("expected 2 total entries, got %v", stats["total_entries"])
	}
	if stats["active_entries"] != 2 {
		t.Errorf("expected 2 active entries, got %v", stats["active_entries"])
	}
	if stats["max_entries"] != maxHistoryCacheEntries {
		t.Errorf("expected max_entries=%d, got %v", maxHistoryCacheEntries, stats["max_entries"])
	}
}

func TestDNSHistoryCache_EvictsOldest(t *testing.T) {
	cache := &DNSHistoryCache{
		entries: make(map[string]*dnsHistoryCacheEntry),
		ttl:     1 * time.Hour,
	}

	for i := 0; i < maxHistoryCacheEntries; i++ {
		cache.entries[string(rune('a'+i%26))+string(rune('0'+i/26))] = &dnsHistoryCacheEntry{
			result:   map[string]any{},
			cachedAt: time.Now(),
		}
	}

	cache.Set("new-domain.com", map[string]any{})

	if len(cache.entries) > maxHistoryCacheEntries {
		t.Errorf("cache should not exceed max entries, got %d", len(cache.entries))
	}
}

func TestExtractHistoryValue(t *testing.T) {
	tests := []struct {
		name  string
		rec   stHistoryRecord
		rtype string
		want  string
	}{
		{
			name:  "empty values",
			rec:   stHistoryRecord{},
			rtype: "a",
			want:  "",
		},
		{
			name:  "a record returns ip",
			rec:   stHistoryRecord{Values: []stHistoryValue{{IP: "1.2.3.4"}}},
			rtype: "a",
			want:  "1.2.3.4",
		},
		{
			name:  "aaaa record returns ip",
			rec:   stHistoryRecord{Values: []stHistoryValue{{IP: "::1"}}},
			rtype: "aaaa",
			want:  "::1",
		},
		{
			name:  "mx record returns host",
			rec:   stHistoryRecord{Values: []stHistoryValue{{Host: "mail.example.com", IP: "1.2.3.4"}}},
			rtype: "mx",
			want:  "mail.example.com",
		},
		{
			name:  "mx record falls back to ip",
			rec:   stHistoryRecord{Values: []stHistoryValue{{IP: "5.6.7.8"}}},
			rtype: "mx",
			want:  "5.6.7.8",
		},
		{
			name:  "ns record returns host",
			rec:   stHistoryRecord{Values: []stHistoryValue{{Host: "ns1.example.com"}}},
			rtype: "ns",
			want:  "ns1.example.com",
		},
		{
			name:  "unknown type prefers ip",
			rec:   stHistoryRecord{Values: []stHistoryValue{{IP: "9.9.9.9", Host: "host.example.com"}}},
			rtype: "txt",
			want:  "9.9.9.9",
		},
		{
			name:  "unknown type falls back to host",
			rec:   stHistoryRecord{Values: []stHistoryValue{{Host: "host.example.com"}}},
			rtype: "txt",
			want:  "host.example.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractHistoryValue(tt.rec, tt.rtype)
			if got != tt.want {
				t.Errorf("extractHistoryValue() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatDaysAgo(t *testing.T) {
	tests := []struct {
		days int
		want string
	}{
		{0, "today"},
		{1, "yesterday"},
		{3, "3 days ago"},
		{6, "6 days ago"},
		{7, "1 week ago"},
		{14, "2 weeks ago"},
		{21, "3 weeks ago"},
		{30, "1 month ago"},
		{60, "2 months ago"},
		{365, "1 year ago"},
		{730, "2 years ago"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := formatDaysAgo(tt.days)
			if got != tt.want {
				t.Errorf("formatDaysAgo(%d) = %q, want %q", tt.days, got, tt.want)
			}
		})
	}
}

func TestBuildChangeDescription(t *testing.T) {
	tests := []struct {
		name       string
		rtype      string
		value      string
		action     string
		org        string
		daysMetric int
		wantSub    string
	}{
		{"added with org", "A", "1.2.3.4", "added", "CloudFlare", 0, "A record 1.2.3.4 (CloudFlare) appeared today"},
		{"added no org", "MX", "mail.example.com", "added", "", 1, "MX record mail.example.com appeared yesterday"},
		{"removed with org", "NS", "ns1.example.com", "removed", "AWS", 30, "NS record ns1.example.com (AWS) was removed 1 month ago"},
		{"removed no org", "AAAA", "::1", "removed", "", 7, "AAAA record ::1 was removed 1 week ago"},
		{"default action", "A", "9.9.9.9", "changed", "", 365, "A record 9.9.9.9 changed 1 year ago"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildChangeDescription(tt.rtype, tt.value, tt.action, tt.org, tt.daysMetric)
			if got != tt.wantSub {
				t.Errorf("buildChangeDescription() = %q, want %q", got, tt.wantSub)
			}
		})
	}
}

func TestDetermineHistoryStatus(t *testing.T) {
	tests := []struct {
		name           string
		allRateLimited bool
		allFailed      bool
		anyFailed      bool
		want           string
	}{
		{"all rate limited", true, true, true, "rate_limited"},
		{"all failed", false, true, true, "error"},
		{"partial failure", false, false, true, "partial"},
		{"all success", false, false, false, "success"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := determineHistoryStatus(tt.allRateLimited, tt.allFailed, tt.anyFailed)
			if got != tt.want {
				t.Errorf("determineHistoryStatus() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildHistoryResult(t *testing.T) {
	t.Run("empty changes", func(t *testing.T) {
		agg := historyAggregation{totalTypes: 4}
		result := buildHistoryResult(agg)
		if result["has_changes"] != false {
			t.Error("expected has_changes=false")
		}
		if result["total_events"] != float64(0) {
			t.Errorf("expected total_events=0, got %v", result["total_events"])
		}
		if result["source"] != "SecurityTrails" {
			t.Error("expected source=SecurityTrails")
		}
	})

	t.Run("with changes", func(t *testing.T) {
		agg := historyAggregation{
			changes: []dnsChangeEvent{
				{RecordType: "A", Value: "1.2.3.4", Action: "added", Date: "2024-01-01"},
			},
			totalTypes: 4,
		}
		result := buildHistoryResult(agg)
		if result["has_changes"] != true {
			t.Error("expected has_changes=true")
		}
		if result["available"] != true {
			t.Error("expected available=true")
		}
		changes := result["changes"].([]map[string]any)
		if len(changes) != 1 {
			t.Errorf("expected 1 change, got %d", len(changes))
		}
	})

	t.Run("all failed", func(t *testing.T) {
		agg := historyAggregation{
			errorCount: 4,
			totalTypes: 4,
		}
		result := buildHistoryResult(agg)
		if result["available"] != false {
			t.Error("expected available=false when all failed")
		}
		if result["status"] != "error" {
			t.Errorf("expected status=error, got %v", result["status"])
		}
	})
}
