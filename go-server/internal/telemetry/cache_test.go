// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package telemetry_test

import (
	"dnstool/go-server/internal/telemetry"
	"sync"
	"testing"
	"time"
)

const msgExpectedValue1 = "expected 'value1', got '%s'"

func TestSetAndGet(t *testing.T) {
	cache := telemetry.NewTTLCache[string]("test", 10, 1*time.Second)

	cache.Set("key1", "value1")
	value, ok := cache.Get("key1")

	if !ok {
		t.Fatal("expected to find key1")
	}
	if value != "value1" {
		t.Errorf(msgExpectedValue1, value)
	}
}

func TestSetAndGetMultipleEntries(t *testing.T) {
	cache := telemetry.NewTTLCache[int]("test", 10, 1*time.Second)

	cache.Set("key1", 1)
	cache.Set("key2", 2)
	cache.Set("key3", 3)

	v1, ok1 := cache.Get("key1")
	v2, ok2 := cache.Get("key2")
	v3, ok3 := cache.Get("key3")

	if !ok1 || v1 != 1 {
		t.Error("key1 not found or wrong value")
	}
	if !ok2 || v2 != 2 {
		t.Error("key2 not found or wrong value")
	}
	if !ok3 || v3 != 3 {
		t.Error("key3 not found or wrong value")
	}
}

func TestGetMissReturnsZeroValue(t *testing.T) {
	cache := telemetry.NewTTLCache[string]("test", 10, 1*time.Second)

	value, ok := cache.Get("nonexistent")

	if ok {
		t.Error("expected ok to be false for missing key")
	}
	if value != "" {
		t.Errorf("expected zero value (empty string), got '%s'", value)
	}
}

func TestGetMissReturnsZeroValueInt(t *testing.T) {
	cache := telemetry.NewTTLCache[int]("test", 10, 1*time.Second)

	value, ok := cache.Get("nonexistent")

	if ok {
		t.Error("expected ok to be false for missing key")
	}
	if value != 0 {
		t.Errorf("expected zero value (0), got %d", value)
	}
}

func TestTTLExpiration(t *testing.T) {
	cache := telemetry.NewTTLCache[string]("test", 10, 100*time.Millisecond)

	cache.Set("key1", "value1")
	value, ok := cache.Get("key1")
	if !ok {
		t.Fatal("key1 should exist immediately after set")
	}
	if value != "value1" {
		t.Errorf(msgExpectedValue1, value)
	}

	time.Sleep(150 * time.Millisecond)

	value, ok = cache.Get("key1")
	if ok {
		t.Fatal("key1 should be expired after TTL")
	}
	if value != "" {
		t.Errorf("expected zero value for expired key, got '%s'", value)
	}
}

func TestMaxEntriesEviction(t *testing.T) {
	cache := telemetry.NewTTLCache[int]("test", 3, 10*time.Second)

	cache.Set("key1", 1)
	time.Sleep(10 * time.Millisecond)
	cache.Set("key2", 2)
	time.Sleep(10 * time.Millisecond)
	cache.Set("key3", 3)

	stats := cache.Stats()
	if stats.Size != 3 {
		t.Errorf("expected size 3, got %d", stats.Size)
	}

	time.Sleep(10 * time.Millisecond)
	cache.Set("key4", 4)

	_, ok1 := cache.Get("key1")
	_, ok2 := cache.Get("key2")
	_, ok3 := cache.Get("key3")
	_, ok4 := cache.Get("key4")

	if ok1 {
		t.Error("key1 should be evicted (oldest)")
	}
	if !ok2 {
		t.Error("key2 should still exist")
	}
	if !ok3 {
		t.Error("key3 should still exist")
	}
	if !ok4 {
		t.Error("key4 should exist")
	}
}

func TestMaxEntriesEvictionByExpiry(t *testing.T) {
	cache := telemetry.NewTTLCache[int]("test", 2, 10*time.Second)

	cache.Set("key1", 1)
	time.Sleep(20 * time.Millisecond)
	cache.Set("key2", 2)
	time.Sleep(20 * time.Millisecond)
	cache.Set("key3", 3)

	_, ok1 := cache.Get("key1")
	_, ok2 := cache.Get("key2")
	_, ok3 := cache.Get("key3")

	if ok1 {
		t.Error("key1 should be evicted (expires first)")
	}
	if !ok2 {
		t.Error("key2 should still exist")
	}
	if !ok3 {
		t.Error("key3 should exist")
	}
}

func TestStatsHitsAndMisses(t *testing.T) {
	cache := telemetry.NewTTLCache[string]("mycache", 10, 1*time.Second)

	cache.Set("key1", "value1")

	cache.Get("key1")
	cache.Get("key1")
	cache.Get("nonexistent")
	cache.Get("nonexistent")

	stats := cache.Stats()

	if stats.Hits != 2 {
		t.Errorf("expected 2 hits, got %d", stats.Hits)
	}
	if stats.Misses != 2 {
		t.Errorf("expected 2 misses, got %d", stats.Misses)
	}
}

func TestStatsSize(t *testing.T) {
	cache := telemetry.NewTTLCache[string]("test", 10, 1*time.Second)

	cache.Set("key1", "value1")
	cache.Set("key2", "value2")
	cache.Set("key3", "value3")

	stats := cache.Stats()

	if stats.Size != 3 {
		t.Errorf("expected size 3, got %d", stats.Size)
	}
	if stats.MaxSize != 10 {
		t.Errorf("expected max size 10, got %d", stats.MaxSize)
	}
}

func TestStatsName(t *testing.T) {
	cache := telemetry.NewTTLCache[string]("myname", 10, 1*time.Second)

	stats := cache.Stats()

	if stats.Name != "myname" {
		t.Errorf("expected name 'myname', got '%s'", stats.Name)
	}
}

func TestStatsHitRate(t *testing.T) {
	cache := telemetry.NewTTLCache[string]("test", 10, 1*time.Second)

	cache.Set("key1", "value1")

	cache.Get("key1")
	cache.Get("key1")
	cache.Get("nonexistent")
	cache.Get("nonexistent")

	stats := cache.Stats()

	if stats.HitRate != "50.0%" {
		t.Errorf("expected hit rate '50.0%%', got '%s'", stats.HitRate)
	}
}

func TestStatsHitRateZero(t *testing.T) {
	cache := telemetry.NewTTLCache[string]("test", 10, 1*time.Second)

	stats := cache.Stats()

	if stats.HitRate != "0%" {
		t.Errorf("expected hit rate '0%%', got '%s'", stats.HitRate)
	}
}

func TestStatsHitRate100Percent(t *testing.T) {
	cache := telemetry.NewTTLCache[string]("test", 10, 1*time.Second)

	cache.Set("key1", "value1")

	cache.Get("key1")
	cache.Get("key1")
	cache.Get("key1")

	stats := cache.Stats()

	if stats.HitRate != "100.0%" {
		t.Errorf("expected hit rate '100.0%%', got '%s'", stats.HitRate)
	}
}

func TestConcurrentReads(t *testing.T) {
	cache := telemetry.NewTTLCache[string]("test", 10, 10*time.Second)

	cache.Set("key1", "value1")

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			value, ok := cache.Get("key1")
			if !ok || value != "value1" {
				t.Error("concurrent read failed")
			}
		}()
	}

	wg.Wait()
}

func TestConcurrentWrites(t *testing.T) {
	cache := telemetry.NewTTLCache[int]("test", 100, 10*time.Second)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(num int) {
			defer wg.Done()
			key := "key" + string(rune(num))
			cache.Set(key, num)
		}(i)
	}

	wg.Wait()

	stats := cache.Stats()
	if stats.Size > 100 {
		t.Errorf("expected size <= 100, got %d", stats.Size)
	}
}

func TestConcurrentReadAndWrite(t *testing.T) {
	cache := telemetry.NewTTLCache[string]("test", 50, 10*time.Second)

	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(num int) {
			defer wg.Done()
			key := "key1"
			cache.Set(key, "value1")
		}(i)
	}

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(num int) {
			defer wg.Done()
			cache.Get("key1")
		}(i)
	}

	wg.Wait()

	value, ok := cache.Get("key1")
	if !ok {
		t.Fatal("key1 should exist after concurrent operations")
	}
	if value != "value1" {
		t.Errorf(msgExpectedValue1, value)
	}
}

func TestConcurrentMixedOperations(t *testing.T) {
	cache := telemetry.NewTTLCache[int]("test", 100, 10*time.Second)

	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(num int) {
			defer wg.Done()
			cache.Set("key"+string(rune(num%10)), num)
		}(i)
	}

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(num int) {
			defer wg.Done()
			cache.Get("key" + string(rune(num%10)))
		}(i)
	}

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(num int) {
			defer wg.Done()
			cache.Stats()
		}(i)
	}

	wg.Wait()

	stats := cache.Stats()
	if stats.Size > 100 {
		t.Errorf("expected size <= 100, got %d", stats.Size)
	}
	if stats.Hits == 0 && stats.Misses == 0 {
		t.Error("expected some hits or misses recorded")
	}
}

func TestConcurrentGetDoesNotRaceWithExpiry(t *testing.T) {
	cache := telemetry.NewTTLCache[string]("test", 10, 100*time.Millisecond)

	cache.Set("key1", "value1")

	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cache.Get("key1")
		}()
	}

	time.Sleep(150 * time.Millisecond)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cache.Get("key1")
		}()
	}

	wg.Wait()
}

func TestUpdateExistingKey(t *testing.T) {
	cache := telemetry.NewTTLCache[string]("test", 10, 1*time.Second)

	cache.Set("key1", "value1")
	value1, ok1 := cache.Get("key1")

	cache.Set("key1", "value2")
	value2, ok2 := cache.Get("key1")

	if !ok1 || value1 != "value1" {
		t.Error("initial value not correct")
	}
	if !ok2 || value2 != "value2" {
		t.Error("updated value not correct")
	}
}

func TestMultipleKeysWithDifferentExpiryTimes(t *testing.T) {
	cache := telemetry.NewTTLCache[int]("test", 10, 1*time.Second)

	cache.Set("key1", 1)
	time.Sleep(500 * time.Millisecond)
	cache.Set("key2", 2)
	time.Sleep(600 * time.Millisecond)

	_, ok1 := cache.Get("key1")
	_, ok2 := cache.Get("key2")

	if ok1 {
		t.Error("key1 should be expired")
	}
	if !ok2 {
		t.Error("key2 should not be expired")
	}
}

func TestEmptyCacheStats(t *testing.T) {
	cache := telemetry.NewTTLCache[string]("emptycache", 10, 1*time.Second)

	stats := cache.Stats()

	if stats.Name != "emptycache" {
		t.Errorf("expected name 'emptycache', got '%s'", stats.Name)
	}
	if stats.Size != 0 {
		t.Errorf("expected size 0, got %d", stats.Size)
	}
	if stats.MaxSize != 10 {
		t.Errorf("expected max size 10, got %d", stats.MaxSize)
	}
	if stats.Hits != 0 {
		t.Errorf("expected 0 hits, got %d", stats.Hits)
	}
	if stats.Misses != 0 {
		t.Errorf("expected 0 misses, got %d", stats.Misses)
	}
}

func TestGetAfterExpiry(t *testing.T) {
	cache := telemetry.NewTTLCache[string]("test", 10, 50*time.Millisecond)

	cache.Set("key1", "value1")
	time.Sleep(100 * time.Millisecond)
	_, ok := cache.Get("key1")

	if ok {
		t.Error("should return false for expired key")
	}

	stats := cache.Stats()
	if stats.Misses != 1 {
		t.Errorf("expected 1 miss, got %d", stats.Misses)
	}
}

func TestMaxEntriesExactCapacity(t *testing.T) {
	cache := telemetry.NewTTLCache[string]("test", 5, 10*time.Second)

	for i := 0; i < 5; i++ {
		key := "key" + string(rune(48+i))
		cache.Set(key, "value"+string(rune(48+i)))
	}

	stats := cache.Stats()
	if stats.Size != 5 {
		t.Errorf("expected size 5, got %d", stats.Size)
	}
}

func TestCacheWithSmallMaxSize(t *testing.T) {
	cache := telemetry.NewTTLCache[int]("test", 1, 10*time.Second)

	cache.Set("key1", 1)
	cache.Set("key2", 2)

	_, ok1 := cache.Get("key1")
	_, ok2 := cache.Get("key2")

	if ok1 {
		t.Error("key1 should be evicted")
	}
	if !ok2 {
		t.Error("key2 should exist")
	}

	stats := cache.Stats()
	if stats.Size != 1 {
		t.Errorf("expected size 1, got %d", stats.Size)
	}
}

func TestHitRatePercision(t *testing.T) {
	cache := telemetry.NewTTLCache[string]("test", 10, 1*time.Second)

	cache.Set("key1", "value1")

	for i := 0; i < 3; i++ {
		cache.Get("key1")
	}
	for i := 0; i < 7; i++ {
		cache.Get("nonexistent" + string(rune(48+i)))
	}

	stats := cache.Stats()

	if stats.Hits != 3 {
		t.Errorf("expected 3 hits, got %d", stats.Hits)
	}
	if stats.Misses != 7 {
		t.Errorf("expected 7 misses, got %d", stats.Misses)
	}

	expectedHitRate := "30.0%"
	if stats.HitRate != expectedHitRate {
		t.Errorf("expected hit rate '%s', got '%s'", expectedHitRate, stats.HitRate)
	}
}

func TestSetOverwritesExistingValue(t *testing.T) {
	cache := telemetry.NewTTLCache[string]("test", 10, 10*time.Second)

	cache.Set("key1", "original")
	cache.Set("key1", "updated")

	stats := cache.Stats()
	if stats.Size != 1 {
		t.Errorf("expected size 1, got %d", stats.Size)
	}

	value, ok := cache.Get("key1")
	if !ok || value != "updated" {
		t.Error("expected updated value")
	}
}
