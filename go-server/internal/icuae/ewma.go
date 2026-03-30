// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.

// dns-tool:scrutiny science
package icuae

import (
        "math"
        "sync"

        "gonum.org/v1/gonum/stat"
)

type EWMAControlChart struct {
        mu                     sync.Mutex
        lambda                 float64
        target                 float64
        sigma                  float64
        initialSigma           float64
        controlLimitMultiplier float64
        ewmaValue              float64
        period                 int
        points                 []float64
        sigmaFrozen            bool
}

const ewmaSigmaFreezeThreshold = 25

func NewEWMAControlChart(lambda, target, sigma, controlLimitMultiplier float64) *EWMAControlChart {
        return &EWMAControlChart{
                lambda:                 lambda,
                target:                 target,
                sigma:                  sigma,
                initialSigma:           sigma,
                controlLimitMultiplier: controlLimitMultiplier,
                ewmaValue:              target,
                period:                 0,
                points:                 make([]float64, 0),
                sigmaFrozen:            false,
        }
}

func (c *EWMAControlChart) Add(value float64) {
        c.mu.Lock()
        defer c.mu.Unlock()
        c.points = append(c.points, value)
        c.period++
        c.ewmaValue = c.lambda*value + (1-c.lambda)*c.ewmaValue
        if !c.sigmaFrozen && len(c.points) >= 10 {
                c.sigma = stat.StdDev(c.points, nil)
                if len(c.points) >= ewmaSigmaFreezeThreshold {
                        c.sigmaFrozen = true
                }
        }
}

func (c *EWMAControlChart) Value() float64 {
        c.mu.Lock()
        defer c.mu.Unlock()
        return c.ewmaValue
}

func (c *EWMAControlChart) ControlLimits() (ucl, lcl float64) {
        c.mu.Lock()
        defer c.mu.Unlock()
        return c.controlLimits()
}

func (c *EWMAControlChart) controlLimits() (ucl, lcl float64) {
        if c.period == 0 {
                return c.target + c.controlLimitMultiplier*c.sigma, c.target - c.controlLimitMultiplier*c.sigma
        }
        factor := c.lambda / (2 - c.lambda) * (1 - math.Pow(1-c.lambda, 2*float64(c.period)))
        spread := c.controlLimitMultiplier * c.sigma * math.Sqrt(factor)
        ucl = c.target + spread
        lcl = c.target - spread
        return
}

func (c *EWMAControlChart) IsOutOfControl() bool {
        c.mu.Lock()
        defer c.mu.Unlock()
        if c.period == 0 {
                return false
        }
        v := c.ewmaValue
        ucl, lcl := c.controlLimits()
        return v > ucl || v < lcl
}

func (c *EWMAControlChart) Trend() string {
        c.mu.Lock()
        defer c.mu.Unlock()
        return c.trend()
}

func (c *EWMAControlChart) trend() string {
        n := len(c.points)
        if n < 4 {
                return "stable"
        }
        half := n / 2
        recentAvg := sliceMean(c.points[half:])
        olderAvg := sliceMean(c.points[:half])
        delta := recentAvg - olderAvg
        if math.Abs(delta) < 1.0 {
                return "stable"
        }
        if delta > 0 {
                return "improving"
        }
        return "declining"
}

func (c *EWMAControlChart) Period() int {
        c.mu.Lock()
        defer c.mu.Unlock()
        return c.period
}

type ChartSnapshot struct {
        Value        float64
        UCL          float64
        LCL          float64
        OutOfControl bool
        Trend        string
        Period       int
}

func (c *EWMAControlChart) Snapshot() ChartSnapshot {
        c.mu.Lock()
        defer c.mu.Unlock()
        ucl, lcl := c.controlLimits()
        ooc := false
        if c.period > 0 {
                ooc = c.ewmaValue > ucl || c.ewmaValue < lcl
        }
        return ChartSnapshot{
                Value:        c.ewmaValue,
                UCL:          ucl,
                LCL:          lcl,
                OutOfControl: ooc,
                Trend:        c.trend(),
                Period:       c.period,
        }
}

func sliceMean(vals []float64) float64 {
        if len(vals) == 0 {
                return 0
        }
        sum := 0.0
        for _, v := range vals {
                sum += v
        }
        return sum / float64(len(vals))
}

type DimensionCharts struct {
        mu     sync.Mutex
        Charts map[string]*EWMAControlChart
}

var dimensionKeys = []string{
        "SourceCredibility",
        "TemporalValidity",
        "ResolverConsensus",
        "TTLCompliance",
        "ChainCompleteness",
}

func NewDimensionCharts() *DimensionCharts {
        charts := make(map[string]*EWMAControlChart, len(dimensionKeys))
        for _, k := range dimensionKeys {
                // Heuristic bootstrap parameters: λ=0.2 (smoothing), μ₀=50 (center), σ=10 (initial spread), L=3.0 (control multiplier).
                // σ is refined adaptively from observed data after 10+ observations (see Add method).
                // These are not fitted from historical in-control DNS data; they are operational defaults
                // that allow the chart to begin monitoring immediately. See NIST/SEMATECH §6.3.2.4.
                charts[k] = NewEWMAControlChart(0.2, 50.0, 10.0, 3.0)
        }
        return &DimensionCharts{Charts: charts}
}

func (dc *DimensionCharts) RecordDimensionScores(scores map[string]float64) {
        dc.mu.Lock()
        defer dc.mu.Unlock()
        for dim, score := range scores {
                if chart, ok := dc.Charts[dim]; ok {
                        chart.Add(score)
                }
        }
}

func (dc *DimensionCharts) Summary() map[string]ChartSnapshot {
        dc.mu.Lock()
        defer dc.mu.Unlock()
        result := make(map[string]ChartSnapshot, len(dc.Charts))
        for dim, chart := range dc.Charts {
                result[dim] = chart.Snapshot()
        }
        return result
}
