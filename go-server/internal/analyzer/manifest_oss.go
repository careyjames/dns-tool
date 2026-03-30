//go:build !intel

// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// Stub implementations. See the corresponding _intel.go file (requires -tags intel build).
// dns-tool:scrutiny science
package analyzer

var FeatureParityManifest = []ManifestEntry{}

var RequiredSchemaKeys []string

func init() {
        // OSS stub: manifest initialization handled in _intel.go counterpart
}
