// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny plumbing
package telemetry

import (
	"sync"
	"time"
)

type CacheStats struct {
	Name    string `json:"name"`
	Size    int    `json:"size"`
	MaxSize int    `json:"max_size"`
	Hits    int64  `json:"hits"`
	Misses  int64  `json:"misses"`
	HitRate string `json:"hit_rate"`
}

type cacheEntry[V any] struct {
	value     V
	expiresAt time.Time
}

type TTLCache[V any] struct {
	mu      sync.RWMutex
	name    string
	items   map[string]cacheEntry[V]
	maxSize int
	ttl     time.Duration
	hits    int64
	misses  int64
}

func NewTTLCache[V any](name string, maxSize int, ttl time.Duration) *TTLCache[V] {
	c := &TTLCache[V]{
		name:    name,
		items:   make(map[string]cacheEntry[V]),
		maxSize: maxSize,
		ttl:     ttl,
	}

	go c.cleanupLoop()

	return c
}

func (c *TTLCache[V]) Get(key string) (V, bool) {
	c.mu.RLock()
	entry, ok := c.items[key]
	c.mu.RUnlock()

	if !ok {
		c.mu.Lock()
		c.misses++
		c.mu.Unlock()
		var zero V
		return zero, false
	}

	if time.Now().After(entry.expiresAt) {
		c.mu.Lock()
		delete(c.items, key)
		c.misses++
		c.mu.Unlock()
		var zero V
		return zero, false
	}

	c.mu.Lock()
	c.hits++
	c.mu.Unlock()

	return entry.value, true
}

func (c *TTLCache[V]) Set(key string, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.items) >= c.maxSize {
		c.evictOldest()
	}

	c.items[key] = cacheEntry[V]{
		value:     value,
		expiresAt: time.Now().Add(c.ttl),
	}
}

func (c *TTLCache[V]) Stats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	total := c.hits + c.misses
	hitRate := "0%"
	if total > 0 {
		hitRate = formatPercent(float64(c.hits) / float64(total) * 100)
	}

	return CacheStats{
		Name:    c.name,
		Size:    len(c.items),
		MaxSize: c.maxSize,
		Hits:    c.hits,
		Misses:  c.misses,
		HitRate: hitRate,
	}
}

func (c *TTLCache[V]) evictOldest() {
	var oldestKey string
	var oldestTime time.Time
	first := true

	for key, entry := range c.items {
		if first || entry.expiresAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.expiresAt
			first = false
		}
	}

	if !first {
		delete(c.items, oldestKey)
	}
}

func (c *TTLCache[V]) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, entry := range c.items {
			if now.After(entry.expiresAt) {
				delete(c.items, key)
			}
		}
		c.mu.Unlock()
	}
}

func formatPercent(v float64) string {
	if v == 0 {
		return "0%"
	}
	return fmtFloat(v, 1) + "%"
}

func fmtFloat(f float64, prec int) string {
	const digits = "0123456789"
	if f < 0 {
		return "-" + fmtFloat(-f, prec)
	}

	mult := 1.0
	for i := 0; i < prec; i++ {
		mult *= 10
	}
	rounded := int(f*mult + 0.5)

	intPart := rounded / int(mult)
	fracPart := rounded % int(mult)

	s := ""
	if intPart == 0 {
		s = "0"
	} else {
		for intPart > 0 {
			s = string(digits[intPart%10]) + s
			intPart /= 10
		}
	}

	if prec > 0 {
		s += "."
		fs := ""
		for i := 0; i < prec; i++ {
			fs = string(digits[fracPart%10]) + fs
			fracPart /= 10
		}
		s += fs
	}

	return s
}
