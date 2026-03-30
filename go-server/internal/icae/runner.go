// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package icae

import (
	"time"
)

type Runner struct {
	AppVersion string
	GitCommit  string
	RunType    string
	cases      []TestCase
}

func NewRunner(appVersion, gitCommit, runType string) *Runner {
	return &Runner{
		AppVersion: appVersion,
		GitCommit:  gitCommit,
		RunType:    runType,
	}
}

func (r *Runner) Register(cases ...TestCase) {
	r.cases = append(r.cases, cases...)
}

func (r *Runner) Run() RunSummary {
	start := time.Now()
	var results []TestResult
	passed := 0
	failed := 0

	for _, tc := range r.cases {
		actual, ok := tc.RunFn()
		result := TestResult{
			CaseID:     tc.CaseID,
			CaseName:   tc.CaseName,
			Protocol:   tc.Protocol,
			Layer:      tc.Layer,
			RFCSection: tc.RFCSection,
			Expected:   tc.Expected,
			Actual:     actual,
			Passed:     ok,
		}
		if !ok {
			failed++
		} else {
			passed++
		}
		results = append(results, result)
	}

	duration := time.Since(start)

	return RunSummary{
		AppVersion:  r.AppVersion,
		GitCommit:   r.GitCommit,
		RunType:     r.RunType,
		TotalCases:  len(r.cases),
		TotalPassed: passed,
		TotalFailed: failed,
		DurationMs:  int(duration.Milliseconds()),
		Results:     results,
		CreatedAt:   time.Now(),
	}
}

func (r *Runner) CaseCount() int {
	return len(r.cases)
}

func SummarizeByProtocol(results []TestResult) map[string]map[string]struct {
	Total  int
	Passed int
	Failed int
} {
	summary := make(map[string]map[string]struct {
		Total  int
		Passed int
		Failed int
	})

	for _, r := range results {
		if summary[r.Protocol] == nil {
			summary[r.Protocol] = make(map[string]struct {
				Total  int
				Passed int
				Failed int
			})
		}
		s := summary[r.Protocol][r.Layer]
		s.Total++
		if r.Passed {
			s.Passed++
		} else {
			s.Failed++
		}
		summary[r.Protocol][r.Layer] = s
	}

	return summary
}
