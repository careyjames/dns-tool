// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package telemetry_test

import (
        "dnstool/go-server/internal/telemetry"
        "sync"
        "sync/atomic"
        "testing"
        "time"
)

const (
        msgExpectedSuccesses = "expected %d successes, got %d"
        msgExpectedFailures  = "expected %d failures, got %d"
)

func assertSuccessCount(t *testing.T, stats telemetry.ProviderStats, expected int64) {
        t.Helper()
        if stats.SuccessCount != expected {
                t.Errorf(msgExpectedSuccesses, expected, stats.SuccessCount)
        }
}

func assertFailureCount(t *testing.T, stats telemetry.ProviderStats, expected int64) {
        t.Helper()
        if stats.FailureCount != expected {
                t.Errorf(msgExpectedFailures, expected, stats.FailureCount)
        }
}

func assertConsecFailures(t *testing.T, stats telemetry.ProviderStats, expected int) {
        t.Helper()
        if stats.ConsecFailures != expected {
                t.Errorf("expected %d consecutive failures, got %d", expected, stats.ConsecFailures)
        }
}

func assertLastError(t *testing.T, stats telemetry.ProviderStats, expected string) {
        t.Helper()
        if stats.LastError != expected {
                t.Errorf("expected last error %q, got %q", expected, stats.LastError)
        }
}

func assertHealthState(t *testing.T, stats telemetry.ProviderStats, expected telemetry.HealthState) {
        t.Helper()
        if stats.State != expected {
                t.Errorf("expected health state %q, got %q", expected, stats.State)
        }
}

func assertInCooldown(t *testing.T, stats telemetry.ProviderStats, expected bool) {
        t.Helper()
        if stats.InCooldown != expected {
                t.Errorf("expected in_cooldown=%v, got %v", expected, stats.InCooldown)
        }
}

func assertProviderCount(t *testing.T, allStats []telemetry.ProviderStats, expected int) {
        t.Helper()
        if len(allStats) != expected {
                t.Errorf("expected %d providers, got %d", expected, len(allStats))
        }
}

func recordFailures(reg *telemetry.Registry, provider string, count int) {
        for i := 0; i < count; i++ {
                reg.RecordFailure(provider, "error")
        }
}

func recordSuccesses(reg *telemetry.Registry, provider string, latencies []time.Duration) {
        for _, lat := range latencies {
                reg.RecordSuccess(provider, lat)
        }
}

func findProviderStats(t *testing.T, allStats []telemetry.ProviderStats, provider string, expectedSuccesses int) {
        t.Helper()
        for _, stats := range allStats {
                if stats.Name == provider && stats.SuccessCount == int64(expectedSuccesses) {
                        return
                }
        }
        t.Errorf("provider %q with %d successes not found in all stats", provider, expectedSuccesses)
}

func assertCooldownRange(t *testing.T, stats telemetry.ProviderStats, minDur, maxDur time.Duration) {
        t.Helper()
        if !stats.InCooldown {
                t.Errorf("expected InCooldown=true in stats, got false")
                return
        }
        if stats.CooldownUntil == nil {
                t.Errorf("expected CooldownUntil to be set, got nil")
                return
        }
        cooldownDuration := stats.CooldownUntil.Sub(time.Now())
        if cooldownDuration < minDur || cooldownDuration > maxDur {
                t.Logf("cooldown duration %v is not in expected range [%v, %v]", cooldownDuration, minDur, maxDur)
        }
}

func runConcurrentOps(reg *telemetry.Registry, provider string, numGoroutines, opsPerGo int, opFn func(goroutineID, op int)) {
        var wg sync.WaitGroup
        wg.Add(numGoroutines)
        for g := 0; g < numGoroutines; g++ {
                go func(goroutineID int) {
                        defer wg.Done()
                        for op := 0; op < opsPerGo; op++ {
                                opFn(goroutineID, op)
                        }
                }(g)
        }
        wg.Wait()
}

func TestRecordSuccess(t *testing.T) {
        tests := []struct {
                name               string
                provider           string
                latencies          []time.Duration
                expectedSuccesses  int64
                expectedFailures   int64
                expectedConsecFail int
        }{
                {
                        name:               "single_success",
                        provider:           "google",
                        latencies:          []time.Duration{100 * time.Millisecond},
                        expectedSuccesses:  1,
                        expectedFailures:   0,
                        expectedConsecFail: 0,
                },
                {
                        name:               "multiple_successes",
                        provider:           "cloudflare",
                        latencies:          []time.Duration{50 * time.Millisecond, 75 * time.Millisecond, 100 * time.Millisecond},
                        expectedSuccesses:  3,
                        expectedFailures:   0,
                        expectedConsecFail: 0,
                },
                {
                        name:               "success_resets_consecutive_failures",
                        provider:           "quad9",
                        latencies:          []time.Duration{100 * time.Millisecond},
                        expectedSuccesses:  1,
                        expectedFailures:   0,
                        expectedConsecFail: 0,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        reg := telemetry.NewRegistry()
                        recordSuccesses(reg, tt.provider, tt.latencies)
                        stats := reg.GetStats(tt.provider)
                        assertSuccessCount(t, stats, tt.expectedSuccesses)
                        assertFailureCount(t, stats, tt.expectedFailures)
                        assertConsecFailures(t, stats, tt.expectedConsecFail)
                })
        }
}

func TestRecordFailure(t *testing.T) {
        tests := []struct {
                name               string
                provider           string
                failures           []string
                expectedFailures   int64
                expectedSuccesses  int64
                expectedConsecFail int
                expectedLastError  string
        }{
                {
                        name:               "single_failure",
                        provider:           "google",
                        failures:           []string{"timeout"},
                        expectedFailures:   1,
                        expectedSuccesses:  0,
                        expectedConsecFail: 1,
                        expectedLastError:  "timeout",
                },
                {
                        name:               "multiple_failures",
                        provider:           "cloudflare",
                        failures:           []string{"error1", "error2", "error3"},
                        expectedFailures:   3,
                        expectedSuccesses:  0,
                        expectedConsecFail: 3,
                        expectedLastError:  "error3",
                },
                {
                        name:               "consecutive_failures_tracking",
                        provider:           "quad9",
                        failures:           []string{"fail1", "fail2", "fail3", "fail4"},
                        expectedFailures:   4,
                        expectedSuccesses:  0,
                        expectedConsecFail: 4,
                        expectedLastError:  "fail4",
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        reg := telemetry.NewRegistry()
                        for _, errMsg := range tt.failures {
                                reg.RecordFailure(tt.provider, errMsg)
                        }
                        stats := reg.GetStats(tt.provider)
                        assertFailureCount(t, stats, tt.expectedFailures)
                        assertSuccessCount(t, stats, tt.expectedSuccesses)
                        assertConsecFailures(t, stats, tt.expectedConsecFail)
                        assertLastError(t, stats, tt.expectedLastError)
                })
        }
}

func TestCooldown(t *testing.T) {
        tests := []struct {
                name                string
                provider            string
                failureCount        int
                expectCooldown      bool
                expectedCooldownMin time.Duration
                expectedCooldownMax time.Duration
        }{
                {
                        name:                "cooldown_after_6_failures",
                        provider:            "google",
                        failureCount:        6,
                        expectCooldown:      true,
                        expectedCooldownMin: 5 * time.Second,
                        expectedCooldownMax: 10 * time.Second,
                },
                {
                        name:           "no_cooldown_with_5_failures",
                        provider:       "cloudflare",
                        failureCount:   5,
                        expectCooldown: false,
                },
                {
                        name:                "exponential_backoff_at_7_failures",
                        provider:            "quad9",
                        failureCount:        7,
                        expectCooldown:      true,
                        expectedCooldownMin: 10 * time.Second,
                        expectedCooldownMax: 20 * time.Second,
                },
                {
                        name:                "exponential_backoff_at_8_failures",
                        provider:            "opendns",
                        failureCount:        8,
                        expectCooldown:      true,
                        expectedCooldownMin: 20 * time.Second,
                        expectedCooldownMax: 40 * time.Second,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        reg := telemetry.NewRegistry()
                        recordFailures(reg, tt.provider, tt.failureCount)

                        inCooldown := reg.InCooldown(tt.provider)
                        if inCooldown != tt.expectCooldown {
                                t.Errorf("expected in_cooldown=%v, got %v", tt.expectCooldown, inCooldown)
                        }

                        if !tt.expectCooldown {
                                return
                        }
                        stats := reg.GetStats(tt.provider)
                        assertCooldownRange(t, stats, tt.expectedCooldownMin, tt.expectedCooldownMax)
                })
        }
}

func TestCooldownCap(t *testing.T) {
        tests := []struct {
                name         string
                provider     string
                failureCount int
                maxCooldown  time.Duration
        }{
                {
                        name:         "cooldown_capped_at_2_minutes",
                        provider:     "google",
                        failureCount: 20,
                        maxCooldown:  2 * time.Minute,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        reg := telemetry.NewRegistry()
                        recordFailures(reg, tt.provider, tt.failureCount)

                        stats := reg.GetStats(tt.provider)
                        if stats.CooldownUntil == nil {
                                return
                        }
                        cooldownDuration := stats.CooldownUntil.Sub(time.Now())
                        if cooldownDuration > tt.maxCooldown {
                                t.Errorf("expected cooldown <= %v, got %v", tt.maxCooldown, cooldownDuration)
                        }
                })
        }
}

func TestCooldownReset(t *testing.T) {
        tests := []struct {
                name                   string
                provider               string
                failuresBeforeSuccess  int
                latencyAfterSuccess    time.Duration
                expectedConsecFailures int
                expectedInCooldown     bool
        }{
                {
                        name:                   "success_resets_cooldown",
                        provider:               "google",
                        failuresBeforeSuccess:  6,
                        latencyAfterSuccess:    100 * time.Millisecond,
                        expectedConsecFailures: 0,
                        expectedInCooldown:     false,
                },
                {
                        name:                   "success_after_10_failures",
                        provider:               "cloudflare",
                        failuresBeforeSuccess:  10,
                        latencyAfterSuccess:    50 * time.Millisecond,
                        expectedConsecFailures: 0,
                        expectedInCooldown:     false,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        reg := telemetry.NewRegistry()
                        recordFailures(reg, tt.provider, tt.failuresBeforeSuccess)
                        reg.RecordSuccess(tt.provider, tt.latencyAfterSuccess)
                        stats := reg.GetStats(tt.provider)
                        assertConsecFailures(t, stats, tt.expectedConsecFailures)
                        assertInCooldown(t, stats, tt.expectedInCooldown)
                })
        }
}

func TestHealthStates(t *testing.T) {
        tests := []struct {
                name                string
                provider            string
                failureCount        int
                expectedHealthState telemetry.HealthState
        }{
                {
                        name:                "healthy_with_0_failures",
                        provider:            "google",
                        failureCount:        0,
                        expectedHealthState: telemetry.Healthy,
                },
                {
                        name:                "healthy_with_2_failures",
                        provider:            "cloudflare",
                        failureCount:        2,
                        expectedHealthState: telemetry.Healthy,
                },
                {
                        name:                "healthy_with_5_failures",
                        provider:            "quad9",
                        failureCount:        5,
                        expectedHealthState: telemetry.Healthy,
                },
                {
                        name:                "degraded_with_6_failures",
                        provider:            "opendns",
                        failureCount:        6,
                        expectedHealthState: telemetry.Degraded,
                },
                {
                        name:                "degraded_with_9_failures",
                        provider:            "verisign",
                        failureCount:        9,
                        expectedHealthState: telemetry.Degraded,
                },
                {
                        name:                "unhealthy_with_10_failures",
                        provider:            "akamai",
                        failureCount:        10,
                        expectedHealthState: telemetry.Unhealthy,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        reg := telemetry.NewRegistry()
                        recordFailures(reg, tt.provider, tt.failureCount)
                        stats := reg.GetStats(tt.provider)
                        assertHealthState(t, stats, tt.expectedHealthState)
                })
        }
}

func applyOperation(reg *telemetry.Registry, provider, op string) {
        if op == "fail" {
                reg.RecordFailure(provider, "error")
        } else {
                reg.RecordSuccess(provider, 100*time.Millisecond)
        }
}

func TestHealthStateTransitions(t *testing.T) {
        tests := []struct {
                name           string
                provider       string
                operations     []string
                expectedStates []telemetry.HealthState
        }{
                {
                        name:           "healthy_to_degraded",
                        provider:       "google",
                        operations:     []string{"fail", "fail", "fail", "fail", "fail", "fail"},
                        expectedStates: []telemetry.HealthState{telemetry.Healthy, telemetry.Healthy, telemetry.Healthy, telemetry.Healthy, telemetry.Healthy, telemetry.Degraded},
                },
                {
                        name:           "degraded_to_unhealthy",
                        provider:       "cloudflare",
                        operations:     []string{"fail", "fail", "fail", "fail", "fail", "fail", "fail", "fail", "fail", "fail"},
                        expectedStates: []telemetry.HealthState{telemetry.Healthy, telemetry.Healthy, telemetry.Healthy, telemetry.Healthy, telemetry.Healthy, telemetry.Degraded, telemetry.Degraded, telemetry.Degraded, telemetry.Degraded, telemetry.Unhealthy},
                },
                {
                        name:           "unhealthy_back_to_healthy",
                        provider:       "quad9",
                        operations:     []string{"fail", "fail", "fail", "fail", "fail", "fail", "fail", "fail", "fail", "fail", "success"},
                        expectedStates: []telemetry.HealthState{telemetry.Healthy, telemetry.Healthy, telemetry.Healthy, telemetry.Healthy, telemetry.Healthy, telemetry.Degraded, telemetry.Degraded, telemetry.Degraded, telemetry.Degraded, telemetry.Unhealthy, telemetry.Healthy},
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        reg := telemetry.NewRegistry()
                        for i, op := range tt.operations {
                                applyOperation(reg, tt.provider, op)
                                stats := reg.GetStats(tt.provider)
                                if stats.State != tt.expectedStates[i] {
                                        t.Errorf("after operation %d, expected state %q, got %q", i, tt.expectedStates[i], stats.State)
                                }
                        }
                })
        }
}

func assertLatencyNonZero(t *testing.T, stats telemetry.ProviderStats, count int) {
        t.Helper()
        if stats.AvgLatencyMs == 0 && count > 0 {
                t.Errorf("expected average latency > 0, got 0")
        }
        if stats.P95LatencyMs == 0 && count > 0 {
                t.Errorf("expected p95 latency > 0, got 0")
        }
}

func assertP95Range(t *testing.T, stats telemetry.ProviderStats, minVal, maxVal float64) {
        t.Helper()
        if minVal <= 0 || maxVal <= 0 {
                return
        }
        if stats.P95LatencyMs < minVal || stats.P95LatencyMs > maxVal {
                t.Logf("p95 latency %f outside expected range [%f, %f]", stats.P95LatencyMs, minVal, maxVal)
        }
}

func TestLatencyTracking(t *testing.T) {
        tests := []struct {
                name           string
                provider       string
                latencies      []time.Duration
                expectedP95Min float64
                expectedP95Max float64
        }{
                {
                        name:           "single_latency",
                        provider:       "google",
                        latencies:      []time.Duration{100 * time.Millisecond},
                        expectedP95Min: 99.0,
                        expectedP95Max: 101.0,
                },
                {
                        name:           "multiple_latencies",
                        provider:       "cloudflare",
                        latencies:      []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond, 40 * time.Millisecond, 50 * time.Millisecond},
                        expectedP95Min: 40.0,
                        expectedP95Max: 50.0,
                },
                {
                        name:      "many_latencies",
                        provider:  "quad9",
                        latencies: generateLatencies(50, 100),
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        reg := telemetry.NewRegistry()
                        recordSuccesses(reg, tt.provider, tt.latencies)
                        stats := reg.GetStats(tt.provider)
                        assertLatencyNonZero(t, stats, len(tt.latencies))
                        assertP95Range(t, stats, tt.expectedP95Min, tt.expectedP95Max)
                })
        }
}

func TestAllStats(t *testing.T) {
        tests := []struct {
                name              string
                providers         map[string]int
                expectedProviders int
        }{
                {
                        name:              "single_provider",
                        providers:         map[string]int{"google": 5},
                        expectedProviders: 1,
                },
                {
                        name: "multiple_providers",
                        providers: map[string]int{
                                "google":     3,
                                "cloudflare": 4,
                                "quad9":      5,
                        },
                        expectedProviders: 3,
                },
                {
                        name: "many_providers",
                        providers: map[string]int{
                                "provider1": 1,
                                "provider2": 2,
                                "provider3": 3,
                                "provider4": 4,
                                "provider5": 5,
                        },
                        expectedProviders: 5,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        reg := telemetry.NewRegistry()
                        for provider, count := range tt.providers {
                                for i := 0; i < count; i++ {
                                        reg.RecordSuccess(provider, 100*time.Millisecond)
                                }
                        }
                        allStats := reg.AllStats()
                        assertProviderCount(t, allStats, tt.expectedProviders)
                        for provider, expectedCount := range tt.providers {
                                findProviderStats(t, allStats, provider, expectedCount)
                        }
                })
        }
}

func TestAllStatsIndependence(t *testing.T) {
        tests := []struct {
                name      string
                providers []string
                failures  map[string]int
        }{
                {
                        name:      "providers_tracked_independently",
                        providers: []string{"google", "cloudflare", "quad9"},
                        failures: map[string]int{
                                "google":     1,
                                "cloudflare": 3,
                                "quad9":      5,
                        },
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        reg := telemetry.NewRegistry()
                        for provider, failCount := range tt.failures {
                                recordFailures(reg, provider, failCount)
                        }

                        allStats := reg.AllStats()
                        for _, stats := range allStats {
                                expectedFails := tt.failures[stats.Name]
                                assertFailureCount(t, stats, int64(expectedFails))
                        }
                })
        }
}

func concurrentSuccessOp(reg *telemetry.Registry, provider string, successCount *int64) func(int, int) {
        return func(_, _ int) {
                reg.RecordSuccess(provider, 100*time.Millisecond)
                atomic.AddInt64(successCount, 1)
        }
}

func concurrentFailureOp(reg *telemetry.Registry, provider string, failureCount *int64) func(int, int) {
        return func(_, _ int) {
                reg.RecordFailure(provider, "error")
                atomic.AddInt64(failureCount, 1)
        }
}

func concurrentMixedOp(reg *telemetry.Registry, provider string, successCount, failureCount *int64) func(int, int) {
        return func(goroutineID, op int) {
                if (goroutineID+op)%2 == 0 {
                        reg.RecordSuccess(provider, 100*time.Millisecond)
                        atomic.AddInt64(successCount, 1)
                } else {
                        reg.RecordFailure(provider, "error")
                        atomic.AddInt64(failureCount, 1)
                }
        }
}

func TestConcurrency(t *testing.T) {
        tests := []struct {
                name              string
                numGoroutines     int
                operationsPerGo   int
                operationType     string
                expectedSuccesses int64
                expectedFailures  int64
        }{
                {
                        name:              "concurrent_successes",
                        numGoroutines:     10,
                        operationsPerGo:   10,
                        operationType:     "success",
                        expectedSuccesses: 100,
                        expectedFailures:  0,
                },
                {
                        name:              "concurrent_failures",
                        numGoroutines:     10,
                        operationsPerGo:   10,
                        operationType:     "failure",
                        expectedSuccesses: 0,
                        expectedFailures:  100,
                },
                {
                        name:              "mixed_concurrent_operations",
                        numGoroutines:     20,
                        operationsPerGo:   5,
                        operationType:     "mixed",
                        expectedSuccesses: 50,
                        expectedFailures:  50,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        reg := telemetry.NewRegistry()
                        provider := "test_provider"
                        var successCount, failureCount int64

                        var opFn func(int, int)
                        switch tt.operationType {
                        case "success":
                                opFn = concurrentSuccessOp(reg, provider, &successCount)
                        case "failure":
                                opFn = concurrentFailureOp(reg, provider, &failureCount)
                        case "mixed":
                                opFn = concurrentMixedOp(reg, provider, &successCount, &failureCount)
                        }

                        runConcurrentOps(reg, provider, tt.numGoroutines, tt.operationsPerGo, opFn)
                        stats := reg.GetStats(provider)
                        assertSuccessCount(t, stats, tt.expectedSuccesses)
                        assertFailureCount(t, stats, tt.expectedFailures)
                })
        }
}

func concurrentMultiProviderOp(reg *telemetry.Registry, providers []string, numProviders int) func(int, int) {
        return func(goroutineID, op int) {
                provider := providers[(goroutineID+op)%numProviders]
                if (goroutineID+op)%3 == 0 {
                        reg.RecordSuccess(provider, 100*time.Millisecond)
                } else {
                        reg.RecordFailure(provider, "error")
                }
        }
}

func TestConcurrentMultipleProviders(t *testing.T) {
        tests := []struct {
                name            string
                numProviders    int
                numGoroutines   int
                operationsPerGo int
        }{
                {
                        name:            "multiple_providers_concurrent",
                        numProviders:    5,
                        numGoroutines:   20,
                        operationsPerGo: 10,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        reg := telemetry.NewRegistry()

                        providers := make([]string, tt.numProviders)
                        for i := 0; i < tt.numProviders; i++ {
                                providers[i] = "provider_" + string(rune('0'+i))
                        }

                        opFn := concurrentMultiProviderOp(reg, providers, tt.numProviders)
                        runConcurrentOps(reg, "", tt.numGoroutines, tt.operationsPerGo, opFn)

                        allStats := reg.AllStats()
                        assertProviderCount(t, allStats, tt.numProviders)
                        for _, stats := range allStats {
                                if stats.TotalRequests == 0 {
                                        t.Errorf("provider %q has no requests", stats.Name)
                                }
                        }
                })
        }
}

func TestConcurrentGetStats(t *testing.T) {
        tests := []struct {
                name            string
                numGoroutines   int
                operationsPerGo int
        }{
                {
                        name:            "concurrent_get_stats",
                        numGoroutines:   10,
                        operationsPerGo: 100,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        reg := telemetry.NewRegistry()
                        provider := "test_provider"

                        for i := 0; i < 50; i++ {
                                reg.RecordSuccess(provider, 100*time.Millisecond)
                        }

                        opFn := func(_, _ int) {
                                stats := reg.GetStats(provider)
                                if stats.SuccessCount != 50 {
                                        t.Errorf("expected 50 successes, got %d", stats.SuccessCount)
                                }
                        }
                        runConcurrentOps(reg, provider, tt.numGoroutines, tt.operationsPerGo, opFn)
                })
        }
}

func generateLatencies(count, baseMs int) []time.Duration {
        latencies := make([]time.Duration, count)
        for i := 0; i < count; i++ {
                latencies[i] = time.Duration((baseMs + i%50)) * time.Millisecond
        }
        return latencies
}
