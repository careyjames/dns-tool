// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.

// robots_txt.go — Framework only (types, constants). Always compiled.
// Detection and parsing stubs live in robots_txt_oss.go / robots_txt_intel.go.
package ai_surface

type robotsDirective struct {
	UserAgent string `json:"user_agent"`
	Action    string `json:"action"`
	Path      string `json:"path"`
}
