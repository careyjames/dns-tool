//go:build !intel

// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// Stub implementations. See the corresponding _intel.go file (requires -tags intel build).
// dns-tool:scrutiny science
package analyzer

const noSaaSDetectedMsg = "No SaaS services detected"

var saasPatterns = []saasPattern{}

func ExtractSaaSTXTFootprint(results map[string]any) map[string]any {
        basicRecords, ok := results["basic_records"].(map[string]any)

        const (
                mapKeyServiceCount = "service_count"
                mapKeyServices     = "services"
        )
        if !ok {
                return map[string]any{
                        mapKeyStatus:       mapKeySuccess,
                        mapKeyServices:     []map[string]any{},
                        mapKeyServiceCount: 0,
                        mapKeyIssues:       []string{},
                        mapKeyMessage:      noSaaSDetectedMsg,
                }
        }

        txtRaw, ok := basicRecords["TXT"]
        if !ok {
                return map[string]any{
                        mapKeyStatus:       mapKeySuccess,
                        mapKeyServices:     []map[string]any{},
                        mapKeyServiceCount: 0,
                        mapKeyIssues:       []string{},
                        mapKeyMessage:      noSaaSDetectedMsg,
                }
        }

        var txtAsAny []any
        switch v := txtRaw.(type) {
        case []string:
                for _, s := range v {
                        txtAsAny = append(txtAsAny, s)
                }
        case []any:
                txtAsAny = v
        default:
                return map[string]any{
                        mapKeyStatus:       mapKeySuccess,
                        mapKeyServices:     []map[string]any{},
                        mapKeyServiceCount: 0,
                        mapKeyIssues:       []string{},
                        mapKeyMessage:      noSaaSDetectedMsg,
                }
        }

        if len(txtAsAny) == 0 {
                return map[string]any{
                        mapKeyStatus:       mapKeySuccess,
                        mapKeyServices:     []map[string]any{},
                        mapKeyServiceCount: 0,
                        mapKeyIssues:       []string{},
                        mapKeyMessage:      noSaaSDetectedMsg,
                }
        }

        return extractSaaSTXTFromRecords(txtAsAny, commoditySaaSPatterns)
}

func matchSaaSPatterns(txt string, seen map[string]bool, services *[]map[string]any) {
        // OSS stub: full SaaS pattern matching in _intel.go counterpart
}
