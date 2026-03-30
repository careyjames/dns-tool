package icae

import (
	"math"
	"sync"
	"testing"
)

func TestNewCalibrationEngineHasAllProtocols(t *testing.T) {
	ce := NewCalibrationEngine()
	expected := []string{"SPF", "DKIM", "DMARC", "DANE", "DNSSEC", "BIMI", "MTA_STS", "TLS_RPT", "CAA"}
	priors := ce.AllPriors()
	if len(priors) != len(expected) {
		t.Fatalf("expected %d protocols, got %d", len(expected), len(priors))
	}
	for _, name := range expected {
		if _, ok := priors[name]; !ok {
			t.Errorf("missing protocol %s", name)
		}
	}
}

func TestPriorForCategoryValid(t *testing.T) {
	ce := NewCalibrationEngine()
	alpha, beta, ok := ce.PriorForCategory("SPF")
	if !ok {
		t.Fatal("expected ok=true for SPF")
	}
	if alpha != 95 || beta != 5 {
		t.Errorf("SPF: expected alpha=95, beta=5, got alpha=%v, beta=%v", alpha, beta)
	}
}

func TestPriorForCategoryInvalid(t *testing.T) {
	ce := NewCalibrationEngine()
	_, _, ok := ce.PriorForCategory("NONEXISTENT")
	if ok {
		t.Error("expected ok=false for nonexistent category")
	}
}

func TestPriorMean(t *testing.T) {
	ce := NewCalibrationEngine()
	tests := []struct {
		category string
		expected float64
	}{
		{"SPF", 95.0 / 100.0},
		{"DKIM", 90.0 / 100.0},
		{"DMARC", 97.0 / 100.0},
		{"DANE", 85.0 / 100.0},
		{"DNSSEC", 92.0 / 100.0},
		{"BIMI", 88.0 / 100.0},
		{"MTA_STS", 90.0 / 100.0},
		{"TLS_RPT", 93.0 / 100.0},
		{"CAA", 95.0 / 100.0},
	}
	for _, tt := range tests {
		got := ce.PriorMean(tt.category)
		if math.Abs(got-tt.expected) > 1e-9 {
			t.Errorf("PriorMean(%s) = %v, want %v", tt.category, got, tt.expected)
		}
	}
}

func TestPriorMeanInvalid(t *testing.T) {
	ce := NewCalibrationEngine()
	got := ce.PriorMean("NONEXISTENT")
	if got != 0 {
		t.Errorf("PriorMean(NONEXISTENT) = %v, want 0", got)
	}
}

func TestCalibratedConfidenceFullAgreement(t *testing.T) {
	ce := NewCalibrationEngine()
	result := ce.CalibratedConfidence("SPF", 0.8, 3, 3)
	if math.Abs(result-0.8) > 1e-9 {
		t.Errorf("full agreement: expected 0.8, got %v", result)
	}
}

func TestCalibratedConfidencePartialAgreement(t *testing.T) {
	ce := NewCalibrationEngine()
	result := ce.CalibratedConfidence("SPF", 0.8, 2, 4)
	w := 0.5
	priorMean := 0.95
	expected := w*0.8 + (1-w)*priorMean
	if math.Abs(result-expected) > 1e-9 {
		t.Errorf("partial agreement: expected %v, got %v", expected, result)
	}
}

func TestCalibratedConfidenceNoAgreement(t *testing.T) {
	ce := NewCalibrationEngine()
	result := ce.CalibratedConfidence("SPF", 0.8, 0, 3)
	priorMean := 0.95
	if math.Abs(result-priorMean) > 1e-9 {
		t.Errorf("no agreement: expected %v, got %v", priorMean, result)
	}
}

func TestCalibratedConfidenceZeroResolvers(t *testing.T) {
	ce := NewCalibrationEngine()
	result := ce.CalibratedConfidence("SPF", 0.8, 0, 0)
	priorMean := 0.95
	if math.Abs(result-priorMean) > 1e-9 {
		t.Errorf("zero resolvers: expected %v, got %v", priorMean, result)
	}
}

func TestCalibratedConfidenceClampsToZeroOne(t *testing.T) {
	ce := NewCalibrationEngine()
	result := ce.CalibratedConfidence("SPF", 1.5, 3, 3)
	if result > 1.0 {
		t.Errorf("expected clamped to 1.0, got %v", result)
	}
	result2 := ce.CalibratedConfidence("SPF", -0.5, 3, 3)
	if result2 < 0.0 {
		t.Errorf("expected clamped to 0.0, got %v", result2)
	}
}

func TestUpdatePriorCorrect(t *testing.T) {
	ce := NewCalibrationEngine()
	alpha0, beta0, _ := ce.PriorForCategory("SPF")
	ce.UpdatePrior("SPF", true)
	alpha1, beta1, _ := ce.PriorForCategory("SPF")
	if alpha1 != alpha0+1 {
		t.Errorf("expected alpha=%v, got %v", alpha0+1, alpha1)
	}
	if beta1 != beta0 {
		t.Errorf("expected beta=%v, got %v", beta0, beta1)
	}
}

func TestUpdatePriorIncorrect(t *testing.T) {
	ce := NewCalibrationEngine()
	alpha0, beta0, _ := ce.PriorForCategory("DKIM")
	ce.UpdatePrior("DKIM", false)
	alpha1, beta1, _ := ce.PriorForCategory("DKIM")
	if alpha1 != alpha0 {
		t.Errorf("expected alpha=%v, got %v", alpha0, alpha1)
	}
	if beta1 != beta0+1 {
		t.Errorf("expected beta=%v, got %v", beta0+1, beta1)
	}
}

func TestUpdatePriorNonexistent(t *testing.T) {
	ce := NewCalibrationEngine()
	ce.UpdatePrior("NONEXISTENT", true)
}

func TestAllPriorsReturnsCopy(t *testing.T) {
	ce := NewCalibrationEngine()
	priors := ce.AllPriors()
	priors["SPF"] = CategoryPrior{Alpha: 999, Beta: 999}
	alpha, _, _ := ce.PriorForCategory("SPF")
	if alpha == 999 {
		t.Error("AllPriors did not return a copy")
	}
}

func TestConcurrentUpdatePrior(t *testing.T) {
	ce := NewCalibrationEngine()
	alpha0, beta0, _ := ce.PriorForCategory("DMARC")
	n := 100
	var wg sync.WaitGroup
	wg.Add(2 * n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			ce.UpdatePrior("DMARC", true)
		}()
		go func() {
			defer wg.Done()
			ce.UpdatePrior("DMARC", false)
		}()
	}
	wg.Wait()
	alpha1, beta1, _ := ce.PriorForCategory("DMARC")
	if alpha1 != alpha0+float64(n) {
		t.Errorf("concurrent alpha: expected %v, got %v", alpha0+float64(n), alpha1)
	}
	if beta1 != beta0+float64(n) {
		t.Errorf("concurrent beta: expected %v, got %v", beta0+float64(n), beta1)
	}
}
