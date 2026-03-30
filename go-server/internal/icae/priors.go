// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.

// dns-tool:scrutiny science
package icae

import (
	"math"
	"sync"

	"gonum.org/v1/gonum/stat/distuv"
)

type CategoryPrior struct {
	Alpha       float64
	Beta        float64
	Description string
}

type CalibrationEngine struct {
	mu     sync.RWMutex
	priors map[string]CategoryPrior
}

func NewCalibrationEngine() *CalibrationEngine {
	return &CalibrationEngine{
		priors: map[string]CategoryPrior{
			"SPF":     {Alpha: 95, Beta: 5, Description: "very reliable detection"},
			"DKIM":    {Alpha: 90, Beta: 10, Description: "reliable but selector discovery varies"},
			"DMARC":   {Alpha: 97, Beta: 3, Description: "deterministic record parsing"},
			"DANE":    {Alpha: 85, Beta: 15, Description: "TLSA can be tricky"},
			"DNSSEC":  {Alpha: 92, Beta: 8, Description: "chain validation well understood"},
			"BIMI":    {Alpha: 88, Beta: 12, Description: "newer standard, less field data"},
			"MTA_STS": {Alpha: 90, Beta: 10, Description: "straightforward policy check"},
			"TLS_RPT": {Alpha: 93, Beta: 7, Description: "simple record presence"},
			"CAA":     {Alpha: 95, Beta: 5, Description: "deterministic DNS record"},
		},
	}
}

func (ce *CalibrationEngine) PriorForCategory(category string) (alpha, beta float64, ok bool) {
	ce.mu.RLock()
	defer ce.mu.RUnlock()
	p, ok := ce.priors[category]
	if !ok {
		return 0, 0, false
	}
	return p.Alpha, p.Beta, true
}

func (ce *CalibrationEngine) PriorMean(category string) float64 {
	ce.mu.RLock()
	defer ce.mu.RUnlock()
	p, ok := ce.priors[category]
	if !ok {
		return 0
	}
	d := distuv.Beta{Alpha: p.Alpha, Beta: p.Beta}
	return d.Mean()
}

func (ce *CalibrationEngine) CalibratedConfidence(category string, rawConfidence float64, resolverAgreement, totalResolvers int) float64 {
	if totalResolvers == 0 {
		return ce.PriorMean(category)
	}
	measurementQuality := float64(resolverAgreement) / float64(totalResolvers)
	priorMean := ce.PriorMean(category)
	w := measurementQuality
	calibrated := w*rawConfidence + (1-w)*priorMean
	return math.Max(0.0, math.Min(1.0, calibrated))
}

func (ce *CalibrationEngine) UpdatePrior(category string, wasCorrect bool) {
	ce.mu.Lock()
	defer ce.mu.Unlock()
	p, ok := ce.priors[category]
	if !ok {
		return
	}
	if wasCorrect {
		p.Alpha += 1
	} else {
		p.Beta += 1
	}
	ce.priors[category] = p
}

func (ce *CalibrationEngine) AllPriors() map[string]CategoryPrior {
	ce.mu.RLock()
	defer ce.mu.RUnlock()
	result := make(map[string]CategoryPrior, len(ce.priors))
	for k, v := range ce.priors {
		result[k] = v
	}
	return result
}
