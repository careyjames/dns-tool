// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

type ManifestEntry struct {
	Feature          string
	Category         string
	Description      string
	SchemaKey        string
	DetectionMethods []string
	RFC              string
}

func GetManifestByCategory(category string) []ManifestEntry {
	var result []ManifestEntry
	for _, entry := range FeatureParityManifest {
		if entry.Category == category {
			result = append(result, entry)
		}
	}
	return result
}
