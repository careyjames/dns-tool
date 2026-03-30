// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// This file contains stub implementations. See the corresponding _intel.go file (requires -tags intel build).
package analyzer

import "regexp"

type saasPattern struct {
        Name    string
        Pattern *regexp.Regexp
}

var saasPatterns = []saasPattern{}

func ExtractSaaSTXTFootprint(results map[string]any) map[string]any {
        return map[string]any{
                "status":        "success",
                "services":      []map[string]any{},
                "service_count": 0,
                "issues":        []string{},
                "message":       "No SaaS verification records detected",
        }
}

func matchSaaSPatterns(txt string, seen map[string]bool, services *[]map[string]any) {
        // intentionally empty — OSS stub
}

func truncateRecord(s string, maxLen int) string {
        if len(s) <= maxLen {
                return s
        }
        return s[:maxLen] + "..."
}
