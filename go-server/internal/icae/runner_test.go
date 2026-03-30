package icae

import (
        "testing"
)

func TestNewRunner(t *testing.T) {
        r := NewRunner("1.0.0", "abc123", "full")
        if r.AppVersion != "1.0.0" {
                t.Errorf("AppVersion = %q", r.AppVersion)
        }
        if r.GitCommit != "abc123" {
                t.Errorf("GitCommit = %q", r.GitCommit)
        }
        if r.RunType != "full" {
                t.Errorf("RunType = %q", r.RunType)
        }
}

func TestRunner_Register(t *testing.T) {
        r := NewRunner("1.0.0", "", "test")
        r.Register(TestCase{
                CaseID:   "TC-001",
                CaseName: "Test Case 1",
                RunFn:    func() (string, bool) { return "ok", true },
        })
        if r.CaseCount() != 1 {
                t.Errorf("CaseCount = %d, want 1", r.CaseCount())
        }
}

func TestRunner_RegisterMultiple(t *testing.T) {
        r := NewRunner("1.0.0", "", "test")
        cases := []TestCase{
                {CaseID: "TC-001", CaseName: "Case 1", RunFn: func() (string, bool) { return "", true }},
                {CaseID: "TC-002", CaseName: "Case 2", RunFn: func() (string, bool) { return "", true }},
        }
        r.Register(cases...)
        if r.CaseCount() != 2 {
                t.Errorf("CaseCount = %d, want 2", r.CaseCount())
        }
}

func TestRunner_Run_AllPass(t *testing.T) {
        r := NewRunner("1.0.0", "commit1", "full")
        r.Register(
                TestCase{CaseID: "TC-001", CaseName: "Passing 1", Protocol: "SPF", Layer: "analysis", RunFn: func() (string, bool) { return "pass", true }},
                TestCase{CaseID: "TC-002", CaseName: "Passing 2", Protocol: "DMARC", Layer: "analysis", RunFn: func() (string, bool) { return "pass", true }},
        )

        summary := r.Run()
        if summary.TotalCases != 2 {
                t.Errorf("TotalCases = %d, want 2", summary.TotalCases)
        }
        if summary.TotalPassed != 2 {
                t.Errorf("TotalPassed = %d, want 2", summary.TotalPassed)
        }
        if summary.TotalFailed != 0 {
                t.Errorf("TotalFailed = %d, want 0", summary.TotalFailed)
        }
        if summary.AppVersion != "1.0.0" {
                t.Errorf("AppVersion = %q", summary.AppVersion)
        }
        if len(summary.Results) != 2 {
                t.Errorf("Results len = %d, want 2", len(summary.Results))
        }
}

func TestRunner_Run_Mixed(t *testing.T) {
        r := NewRunner("1.0.0", "", "test")
        r.Register(
                TestCase{CaseID: "TC-001", CaseName: "Passing", RunFn: func() (string, bool) { return "ok", true }},
                TestCase{CaseID: "TC-002", CaseName: "Failing", RunFn: func() (string, bool) { return "fail reason", false }},
        )

        summary := r.Run()
        if summary.TotalPassed != 1 {
                t.Errorf("TotalPassed = %d, want 1", summary.TotalPassed)
        }
        if summary.TotalFailed != 1 {
                t.Errorf("TotalFailed = %d, want 1", summary.TotalFailed)
        }

        if summary.Results[1].Actual != "fail reason" {
                t.Errorf("Results[1].Actual = %q, want 'fail reason'", summary.Results[1].Actual)
        }
}

func TestRunner_Run_Empty(t *testing.T) {
        r := NewRunner("1.0.0", "", "test")
        summary := r.Run()
        if summary.TotalCases != 0 {
                t.Errorf("TotalCases = %d, want 0", summary.TotalCases)
        }
        if summary.DurationMs < 0 {
                t.Error("DurationMs should be >= 0")
        }
}

func TestRunner_Run_ResultFields(t *testing.T) {
        r := NewRunner("1.0.0", "", "test")
        r.Register(TestCase{
                CaseID:     "TC-001",
                CaseName:   "Test",
                Protocol:   "SPF",
                Layer:      "collection",
                RFCSection: "RFC7208§5",
                Expected:   "expected val",
                RunFn:      func() (string, bool) { return "actual val", true },
        })

        summary := r.Run()
        result := summary.Results[0]
        if result.CaseID != "TC-001" {
                t.Errorf("CaseID = %q", result.CaseID)
        }
        if result.Protocol != "SPF" {
                t.Errorf("Protocol = %q", result.Protocol)
        }
        if result.Layer != "collection" {
                t.Errorf("Layer = %q", result.Layer)
        }
        if result.RFCSection != "RFC7208§5" {
                t.Errorf("RFCSection = %q", result.RFCSection)
        }
        if result.Expected != "expected val" {
                t.Errorf("Expected = %q", result.Expected)
        }
        if result.Actual != "actual val" {
                t.Errorf("Actual = %q", result.Actual)
        }
        if !result.Passed {
                t.Error("expected Passed = true")
        }
}

func TestSummarizeByProtocol_GroupsByProtocolAndLayer(t *testing.T) {
        results := []TestResult{
                {Protocol: "SPF", Layer: "analysis", Passed: true},
                {Protocol: "SPF", Layer: "analysis", Passed: false},
                {Protocol: "SPF", Layer: "collection", Passed: true},
                {Protocol: "DMARC", Layer: "analysis", Passed: true},
        }

        summary := SummarizeByProtocol(results)

        spfAnalysis := summary["SPF"]["analysis"]
        if spfAnalysis.Total != 2 {
                t.Errorf("SPF/analysis Total = %d, want 2", spfAnalysis.Total)
        }
        if spfAnalysis.Passed != 1 {
                t.Errorf("SPF/analysis Passed = %d, want 1", spfAnalysis.Passed)
        }
        if spfAnalysis.Failed != 1 {
                t.Errorf("SPF/analysis Failed = %d, want 1", spfAnalysis.Failed)
        }

        spfCollection := summary["SPF"]["collection"]
        if spfCollection.Total != 1 {
                t.Errorf("SPF/collection Total = %d, want 1", spfCollection.Total)
        }

        dmarcAnalysis := summary["DMARC"]["analysis"]
        if dmarcAnalysis.Total != 1 {
                t.Errorf("DMARC/analysis Total = %d, want 1", dmarcAnalysis.Total)
        }
}

func TestCaseCount_Empty(t *testing.T) {
        r := NewRunner("1.0", "", "test")
        if r.CaseCount() != 0 {
                t.Errorf("CaseCount = %d, want 0", r.CaseCount())
        }
}
