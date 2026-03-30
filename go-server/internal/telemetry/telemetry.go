// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny plumbing
package telemetry

import (
        "math"
        "slices"
        "sync"
        "time"
)

type HealthState string

const (
        Healthy   HealthState = "healthy"
        Degraded  HealthState = "degraded"
        Unhealthy HealthState = "unhealthy"

        degradedThreshold  = 6
        unhealthyThreshold = 10
        cooldownBase       = 5 * time.Second
        cooldownMax        = 2 * time.Minute
        latencyWindowSize  = 100
)

type ProviderStats struct {
        Name            string      `json:"name"`
        State           HealthState `json:"state"`
        TotalRequests   int64       `json:"total_requests"`
        SuccessCount    int64       `json:"success_count"`
        FailureCount    int64       `json:"failure_count"`
        ConsecFailures  int         `json:"consecutive_failures"`
        LastError       string      `json:"last_error,omitempty"`
        LastErrorTime   *time.Time  `json:"last_error_time,omitempty"`
        LastSuccessTime *time.Time  `json:"last_success_time,omitempty"`
        AvgLatencyMs    float64     `json:"avg_latency_ms"`
        P95LatencyMs    float64     `json:"p95_latency_ms"`
        InCooldown      bool        `json:"in_cooldown"`
        CooldownUntil   *time.Time  `json:"cooldown_until,omitempty"`
}

type provider struct {
        mu             sync.RWMutex
        name           string
        totalRequests  int64
        successCount   int64
        failureCount   int64
        consecFailures int
        lastError      string
        lastErrorTime  time.Time
        lastSuccess    time.Time
        latencies      []float64
        latencyIdx     int
        latencyFull    bool
        cooldownUntil  time.Time
}

type Registry struct {
        mu        sync.RWMutex
        providers map[string]*provider
}

func NewRegistry() *Registry {
        return &Registry{
                providers: make(map[string]*provider),
        }
}

func (r *Registry) getOrCreate(name string) *provider {
        r.mu.RLock()
        p, ok := r.providers[name]
        r.mu.RUnlock()
        if ok {
                return p
        }

        r.mu.Lock()
        defer r.mu.Unlock()
        if p, ok = r.providers[name]; ok {
                return p
        }
        p = &provider{
                name:      name,
                latencies: make([]float64, latencyWindowSize),
        }
        r.providers[name] = p
        return p
}

func (r *Registry) RecordSuccess(name string, latency time.Duration) {
        p := r.getOrCreate(name)
        p.mu.Lock()
        defer p.mu.Unlock()

        now := time.Now()
        p.totalRequests++
        p.successCount++
        p.consecFailures = 0
        p.lastSuccess = now
        p.cooldownUntil = time.Time{}

        ms := float64(latency.Microseconds()) / 1000.0
        p.latencies[p.latencyIdx] = ms
        p.latencyIdx++
        if p.latencyIdx >= latencyWindowSize {
                p.latencyIdx = 0
                p.latencyFull = true
        }
}

func (r *Registry) RecordFailure(name, errMsg string) {
        p := r.getOrCreate(name)
        p.mu.Lock()
        defer p.mu.Unlock()

        now := time.Now()
        p.totalRequests++
        p.failureCount++
        p.consecFailures++
        p.lastError = errMsg
        p.lastErrorTime = now

        if p.consecFailures >= degradedThreshold {
                backoff := time.Duration(math.Min(
                        float64(cooldownBase)*math.Pow(2, float64(p.consecFailures-degradedThreshold)),
                        float64(cooldownMax),
                ))
                p.cooldownUntil = now.Add(backoff)
        }
}

func (r *Registry) InCooldown(name string) bool {
        r.mu.RLock()
        p, ok := r.providers[name]
        r.mu.RUnlock()
        if !ok {
                return false
        }

        p.mu.RLock()
        defer p.mu.RUnlock()
        if p.cooldownUntil.IsZero() {
                return false
        }
        return time.Now().Before(p.cooldownUntil)
}

func (r *Registry) GetStats(name string) ProviderStats {
        p := r.getOrCreate(name)
        p.mu.RLock()
        defer p.mu.RUnlock()
        return p.stats()
}

func (r *Registry) AllStats() []ProviderStats {
        r.mu.RLock()
        names := make([]string, 0, len(r.providers))
        for name := range r.providers {
                names = append(names, name)
        }
        r.mu.RUnlock()

        stats := make([]ProviderStats, 0, len(names))
        for _, name := range names {
                stats = append(stats, r.GetStats(name))
        }
        return stats
}

func (p *provider) stats() ProviderStats {
        s := ProviderStats{
                Name:           p.name,
                TotalRequests:  p.totalRequests,
                SuccessCount:   p.successCount,
                FailureCount:   p.failureCount,
                ConsecFailures: p.consecFailures,
                LastError:      p.lastError,
        }

        if !p.lastErrorTime.IsZero() {
                t := p.lastErrorTime
                s.LastErrorTime = &t
        }
        if !p.lastSuccess.IsZero() {
                t := p.lastSuccess
                s.LastSuccessTime = &t
        }

        switch {
        case p.consecFailures >= unhealthyThreshold:
                s.State = Unhealthy
        case p.consecFailures >= degradedThreshold:
                s.State = Degraded
        default:
                s.State = Healthy
        }

        now := time.Now()
        if !p.cooldownUntil.IsZero() && now.Before(p.cooldownUntil) {
                s.InCooldown = true
                t := p.cooldownUntil
                s.CooldownUntil = &t
        }

        count := p.latencyIdx
        if p.latencyFull {
                count = latencyWindowSize
        }
        if count > 0 {
                sorted := make([]float64, count)
                copy(sorted, p.latencies[:count])
                slices.Sort(sorted)
                s.AvgLatencyMs = avgFloats(sorted)
                s.P95LatencyMs = sorted[int(float64(len(sorted)-1)*0.95)]
        }

        return s
}

func avgFloats(data []float64) float64 {
        if len(data) == 0 {
                return 0
        }
        sum := 0.0
        for _, v := range data {
                sum += v
        }
        return sum / float64(len(data))
}
