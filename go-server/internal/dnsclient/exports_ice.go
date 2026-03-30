// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package dnsclient

func ExportFindConsensus(resolverResults map[string][]string) (records []string, allSame bool, discrepancies []string) {
	return findConsensus(resolverResults)
}
