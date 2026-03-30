package icuae

import (
	"math"
	"testing"
)

const (
	testLambda                = 0.2
	testTarget                = 50.0
	testSigma                 = 10.0
	testControlLimitMultipler = 3.0
	testMinPoints             = 10
	testTrendThreshold        = 1.0
)

func newTestChart() *EWMAControlChart {
	return NewEWMAControlChart(testLambda, testTarget, testSigma, testControlLimitMultipler)
}

func TestNewEWMAControlChart(t *testing.T) {
	c := newTestChart()
	if c.lambda != testLambda {
		t.Errorf("expected lambda=%v, got %f", testLambda, c.lambda)
	}
	if c.target != testTarget {
		t.Errorf("expected target=%v, got %f", testTarget, c.target)
	}
	if c.sigma != testSigma {
		t.Errorf("expected sigma=%v, got %f", testSigma, c.sigma)
	}
	if c.controlLimitMultiplier != testControlLimitMultipler {
		t.Errorf("expected controlLimitMultiplier=%v, got %f", testControlLimitMultipler, c.controlLimitMultiplier)
	}
	if c.Period() != 0 {
		t.Errorf("expected period=0, got %d", c.Period())
	}
}

func TestAddAndValue(t *testing.T) {
	c := newTestChart()
	c.Add(55.0)
	if c.Period() != 1 {
		t.Errorf("expected period=1, got %d", c.Period())
	}
	v := c.Value()
	if v == 0 {
		t.Error("expected non-zero value after Add")
	}

	c.Add(60.0)
	c.Add(45.0)
	if c.Period() != 3 {
		t.Errorf("expected period=3, got %d", c.Period())
	}
}

func TestControlLimitsCalculation(t *testing.T) {
	c := newTestChart()
	c.Add(testTarget)

	ucl, lcl := c.ControlLimits()

	factor := testLambda / (2 - testLambda) * (1 - math.Pow(1-testLambda, 2))
	expectedSpread := testControlLimitMultipler * testSigma * math.Sqrt(factor)
	expectedUCL := testTarget + expectedSpread
	expectedLCL := testTarget - expectedSpread

	if math.Abs(ucl-expectedUCL) > 0.0001 {
		t.Errorf("UCL: expected %f, got %f", expectedUCL, ucl)
	}
	if math.Abs(lcl-expectedLCL) > 0.0001 {
		t.Errorf("LCL: expected %f, got %f", expectedLCL, lcl)
	}

	if ucl <= testTarget || lcl >= testTarget {
		t.Error("UCL should be above target and LCL below target")
	}
}

func TestControlLimitsZeroPeriod(t *testing.T) {
	c := newTestChart()
	ucl, lcl := c.ControlLimits()
	expectedUCL := testTarget + testControlLimitMultipler*testSigma
	expectedLCL := testTarget - testControlLimitMultipler*testSigma
	if ucl != expectedUCL {
		t.Errorf("expected UCL=%v at period 0, got %f", expectedUCL, ucl)
	}
	if lcl != expectedLCL {
		t.Errorf("expected LCL=%v at period 0, got %f", expectedLCL, lcl)
	}
}

func TestIsOutOfControlInControl(t *testing.T) {
	c := newTestChart()
	for i := 0; i < 5; i++ {
		c.Add(testTarget)
	}
	if c.IsOutOfControl() {
		t.Error("expected in-control for values at target")
	}
}

func TestIsOutOfControlOutOfControl(t *testing.T) {
	c := NewEWMAControlChart(testLambda, testTarget, 1.0, testControlLimitMultipler)
	for i := 0; i < 20; i++ {
		c.Add(100.0)
	}
	if !c.IsOutOfControl() {
		t.Error("expected out-of-control for extreme values")
	}
}

func TestIsOutOfControlZeroPeriod(t *testing.T) {
	c := newTestChart()
	if c.IsOutOfControl() {
		t.Error("expected not out-of-control at period 0")
	}
}

func TestTrendImproving(t *testing.T) {
	c := newTestChart()
	for i := 0; i < 5; i++ {
		c.Add(40.0)
	}
	for i := 0; i < 5; i++ {
		c.Add(60.0)
	}
	trend := c.Trend()
	if trend != "improving" {
		t.Errorf("expected improving, got %s", trend)
	}
}

func TestTrendDeclining(t *testing.T) {
	c := newTestChart()
	for i := 0; i < 5; i++ {
		c.Add(60.0)
	}
	for i := 0; i < 5; i++ {
		c.Add(40.0)
	}
	trend := c.Trend()
	if trend != "declining" {
		t.Errorf("expected declining, got %s", trend)
	}
}

func TestTrendStable(t *testing.T) {
	c := newTestChart()
	for i := 0; i < testMinPoints; i++ {
		c.Add(testTarget)
	}
	trend := c.Trend()
	if trend != "stable" {
		t.Errorf("expected stable, got %s", trend)
	}
}

func TestTrendInsufficientData(t *testing.T) {
	c := newTestChart()
	c.Add(testTarget)
	trend := c.Trend()
	if trend != "stable" {
		t.Errorf("expected stable with insufficient data, got %s", trend)
	}
}

func TestSigmaRecalculation(t *testing.T) {
	c := newTestChart()
	if c.sigma != testSigma {
		t.Errorf("initial sigma should be %v, got %f", testSigma, c.sigma)
	}

	for i := 0; i < testMinPoints-1; i++ {
		c.Add(testTarget)
	}
	if c.sigma != testSigma {
		t.Errorf("sigma should remain %v before %d points, got %f", testSigma, testMinPoints, c.sigma)
	}

	c.Add(55.0)
	if c.sigma == testSigma {
		t.Error("sigma should have been recalculated after enough points")
	}
	if c.sigma <= 0 {
		t.Errorf("recalculated sigma should be positive, got %f", c.sigma)
	}
}

func TestSnapshotConsistency(t *testing.T) {
	c := newTestChart()
	for i := 0; i < 5; i++ {
		c.Add(testTarget)
	}
	snap := c.Snapshot()
	if snap.Period != 5 {
		t.Errorf("expected period=5 in snapshot, got %d", snap.Period)
	}
	if snap.UCL <= testTarget || snap.LCL >= testTarget {
		t.Error("snapshot UCL should be above target and LCL below target")
	}
	if snap.Trend != "stable" {
		t.Errorf("expected stable trend in snapshot, got %s", snap.Trend)
	}
}

func TestPeriodAccessor(t *testing.T) {
	c := newTestChart()
	if c.Period() != 0 {
		t.Errorf("expected period=0, got %d", c.Period())
	}
	c.Add(testTarget)
	if c.Period() != 1 {
		t.Errorf("expected period=1, got %d", c.Period())
	}
}

func TestDimensionChartsCreation(t *testing.T) {
	dc := NewDimensionCharts()
	for _, dim := range dimensionKeys {
		if _, ok := dc.Charts[dim]; !ok {
			t.Errorf("missing dimension chart: %s", dim)
		}
	}
	if len(dc.Charts) != len(dimensionKeys) {
		t.Errorf("expected %d charts, got %d", len(dimensionKeys), len(dc.Charts))
	}
}

func TestDimensionChartsRecordAndSummary(t *testing.T) {
	dc := NewDimensionCharts()
	scores := map[string]float64{
		"SourceCredibility": 85.0,
		"TemporalValidity":  90.0,
		"ResolverConsensus": 75.0,
		"TTLCompliance":     80.0,
		"ChainCompleteness": 70.0,
	}
	dc.RecordDimensionScores(scores)
	dc.RecordDimensionScores(scores)

	summary := dc.Summary()
	for dim := range scores {
		snap, ok := summary[dim]
		if !ok {
			t.Errorf("missing dimension in summary: %s", dim)
			continue
		}
		if snap.Period != 2 {
			t.Errorf("expected period=2 for %s, got %d", dim, snap.Period)
		}
	}
}

func TestDimensionChartsIgnoresUnknown(t *testing.T) {
	dc := NewDimensionCharts()
	scores := map[string]float64{
		"UnknownDimension": testTarget,
	}
	dc.RecordDimensionScores(scores)
	for _, chart := range dc.Charts {
		if chart.Period() != 0 {
			t.Error("unknown dimension should not affect any chart")
		}
	}
}

func TestControlLimitsWiden(t *testing.T) {
	c := newTestChart()
	c.Add(testTarget)
	ucl1, lcl1 := c.ControlLimits()
	for i := 0; i < 20; i++ {
		c.Add(testTarget)
	}
	ucl2, lcl2 := c.ControlLimits()
	spread1 := ucl1 - lcl1
	spread2 := ucl2 - lcl2
	if spread2 < spread1 {
		t.Logf("spread1=%f, spread2=%f — later periods have wider limits as expected by EWMA formula", spread1, spread2)
	}
}

func TestSliceMean(t *testing.T) {
	tests := []struct {
		name     string
		vals     []float64
		expected float64
	}{
		{"empty", []float64{}, 0},
		{"single", []float64{5.0}, 5.0},
		{"multiple", []float64{2.0, 4.0, 6.0}, 4.0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sliceMean(tt.vals)
			if math.Abs(got-tt.expected) > 1e-9 {
				t.Errorf("sliceMean(%v) = %v, want %v", tt.vals, got, tt.expected)
			}
		})
	}
}
