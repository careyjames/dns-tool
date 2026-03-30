//go:build !intel

// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// Stub implementations. See the corresponding _intel.go file (requires -tags intel build).
// dns-tool:scrutiny science
package analyzer

var cdnASNs = map[string]string{}

var cloudASNs = map[string]string{}

var cloudCDNPTRPatterns = map[string]string{}

var cdnCNAMEPatterns = map[string]string{}

func DetectEdgeCDN(results map[string]any) map[string]any {
        return map[string]any{
                "status":         "success",
                "is_behind_cdn":  false,
                "cdn_provider":   "",
                "cdn_indicators": []string{},
                "origin_visible": true,
                "issues":         []string{},
                "message":        "Domain appears to use direct origin hosting",
        }
}

func checkASNForCDN(results map[string]any, indicators []string) (string, []string) {
        return "", indicators
}

func matchASNEntries(asnData map[string]any, key string, indicators []string) (string, []string) {
        return "", indicators
}

func checkCNAMEForCDN(results map[string]any, indicators []string) (string, []string) {
        return "", indicators
}

func checkPTRForCDN(results map[string]any, indicators []string) (string, []string) {
        return "", indicators
}

func classifyCloudIP(asn string, ptrRecords []string) (provider string, isCDN bool) {
        return "", false
}

func isOriginVisible(provider string) bool {
        return false
}
