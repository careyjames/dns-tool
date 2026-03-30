//go:build !intel

// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.

// dns-tool:scrutiny science
package analyzer

import "strings"

func classifyDriftSeverity(fieldLabel, prevVal, currVal string) string {
	lbl := strings.ToLower(fieldLabel)
	prev := normalizeStatusVal(prevVal)
	curr := normalizeStatusVal(currVal)

	switch {
	case lbl == "dmarc policy":
		return classifyPolicyChange(prev, curr)
	case strings.HasSuffix(lbl, "status") || lbl == "dane present":
		return classifyStatusChange(prev, curr)
	case strings.HasSuffix(lbl, "records") || strings.HasSuffix(lbl, "selectors") || strings.HasSuffix(lbl, "tags"):
		return "warning"
	default:
		return "info"
	}
}

func normalizeStatusVal(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if idx := strings.Index(v, " ("); idx > 0 {
		v = v[:idx]
	}
	return v
}

func classifyPolicyChange(prev, curr string) string {
	rank := map[string]int{"reject": 3, "quarantine": 2, "none": 1, "": 0, "(none)": 0}
	prevR := rank[prev]
	currR := rank[curr]
	if currR < prevR {
		return "danger"
	}
	if currR > prevR {
		return "success"
	}
	return "info"
}

func classifyStatusChange(prev, curr string) string {
	good := map[string]bool{"pass": true, "valid": true, "configured": true, "found": true, "active": true, "enabled": true, "secure": true}
	bad := map[string]bool{"fail": true, "missing": true, "none": true, "not found": true, "not configured": true, "": true, "(none)": true, "insecure": true}

	prevGood := good[prev]
	currGood := good[curr]
	prevBad := bad[prev]
	currBad := bad[curr]

	if prevGood && currBad {
		return "danger"
	}
	if prevBad && currGood {
		return "success"
	}
	return "warning"
}
