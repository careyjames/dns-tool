// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import "strings"

const (
	mapKeyDaneAnalysis  = "dane_analysis"
	mapKeyDmarcAnalysis = "dmarc_analysis"
)

type PostureDiffField struct {
	Label    string
	Previous string
	Current  string
	Severity string
}

func ComputePostureDiff(prev, curr map[string]any) []PostureDiffField {
	type fieldSpec struct {
		label   string
		section string
		key     string
	}

	fields := []fieldSpec{
		{"SPF Status", "spf_analysis", mapKeyStatus},
		{"DMARC Status", mapKeyDmarcAnalysis, mapKeyStatus},
		{"DMARC Policy", mapKeyDmarcAnalysis, "policy"},
		{"DKIM Status", "dkim_analysis", mapKeyStatus},
		{"MTA-STS Status", "mta_sts_analysis", mapKeyStatus},
		{"MTA-STS Mode", "mta_sts_analysis", "mode"},
		{"TLS-RPT Status", "tlsrpt_analysis", mapKeyStatus},
		{"BIMI Status", "bimi_analysis", mapKeyStatus},
		{"DANE Status", mapKeyDaneAnalysis, mapKeyStatus},
		{"CAA Status", "caa_analysis", mapKeyStatus},
		{"DNSSEC Status", "dnssec_analysis", mapKeyStatus},
		{"Mail Posture", "mail_posture", "label"},
	}

	var diffs []PostureDiffField

	for _, f := range fields {
		prevVal := extractPostureField(prev, f.section, f.key)
		currVal := extractPostureField(curr, f.section, f.key)
		if prevVal != currVal {
			diffs = append(diffs, PostureDiffField{
				Label:    f.label,
				Previous: displayVal(prevVal),
				Current:  displayVal(currVal),
				Severity: classifyDriftSeverity(f.label, prevVal, currVal),
			})
		}
	}

	type sortedSpec struct {
		label string
		fn    func(map[string]any) string
	}
	sortedFields := []sortedSpec{
		{"DKIM Selectors", extractSortedSelectors},
		{"CAA Tags", extractSortedCAATags},
		{"SPF Records", func(r map[string]any) string { return extractSortedRecords(r, "spf_analysis", "records") }},
		{"DMARC Records", func(r map[string]any) string { return extractSortedRecords(r, mapKeyDmarcAnalysis, "records") }},
		{"MX Records", extractSortedMX},
		{"NS Records", extractSortedNS},
	}
	for _, sf := range sortedFields {
		prevVal := sf.fn(prev)
		currVal := sf.fn(curr)
		if prevVal != currVal {
			diffs = append(diffs, PostureDiffField{
				Label:    sf.label,
				Previous: displayVal(prevVal),
				Current:  displayVal(currVal),
				Severity: classifyDriftSeverity(sf.label, prevVal, currVal),
			})
		}
	}

	prevDANE := extractPostureBool(prev, mapKeyDaneAnalysis, "has_dane")
	currDANE := extractPostureBool(curr, mapKeyDaneAnalysis, "has_dane")
	if prevDANE != currDANE {
		diffs = append(diffs, PostureDiffField{
			Label:    "DANE Present",
			Previous: displayVal(prevDANE),
			Current:  displayVal(currDANE),
			Severity: classifyDriftSeverity("DANE Present", prevDANE, currDANE),
		})
	}

	return diffs
}

func displayVal(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "(none)"
	}
	return v
}
