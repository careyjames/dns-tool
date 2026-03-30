// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.

// poisoning.go — Framework only (types, utilities). Always compiled.
// Detection stubs live in poisoning_oss.go / poisoning_intel.go.
package ai_surface

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
