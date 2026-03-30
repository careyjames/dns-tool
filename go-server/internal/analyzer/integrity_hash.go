// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
        "encoding/hex"
        "encoding/json"
        "fmt"
        "sort"
        "strings"

        "golang.org/x/crypto/sha3"
)

func ReportIntegrityHash(domain string, analysisID int32, timestamp, toolVersion string, results map[string]any) string {
        var parts []string

        parts = append(parts, "domain:"+strings.ToLower(strings.TrimSpace(domain)))
        parts = append(parts, fmt.Sprintf("id:%d", analysisID))
        parts = append(parts, "ts:"+strings.TrimSpace(timestamp))
        parts = append(parts, "ver:"+strings.TrimSpace(toolVersion))

        canonicalResults := canonicalizeMap(results)
        parts = append(parts, "data:"+canonicalResults)

        payload := strings.Join(parts, "|")
        hash := sha3.Sum512([]byte(payload))
        return hex.EncodeToString(hash[:])
}

func canonicalizeMap(m map[string]any) string {
        keys := make([]string, 0, len(m))
        for k := range m {
                if strings.HasPrefix(k, "_") {
                        continue
                }
                keys = append(keys, k)
        }
        sort.Strings(keys)

        var parts []string
        for _, k := range keys {
                v := m[k]
                parts = append(parts, k+"="+canonicalizeValue(v))
        }
        return strings.Join(parts, ";")
}

func canonicalizeValue(v any) string {
        switch val := v.(type) {
        case nil:
                return "null"
        case string:
                return val
        case bool:
                if val {
                        return "true"
                }
                return "false"
        case float64:
                return fmt.Sprintf("%g", val)
        case int:
                return fmt.Sprintf("%d", val)
        case int32:
                return fmt.Sprintf("%d", val)
        case int64:
                return fmt.Sprintf("%d", val)
        case map[string]any:
                return "{" + canonicalizeMap(val) + "}"
        case []any:
                var items []string
                for _, item := range val {
                        items = append(items, canonicalizeValue(item))
                }
                sort.Strings(items)
                return "[" + strings.Join(items, ",") + "]"
        case []map[string]any:
                var items []string
                for _, item := range val {
                        items = append(items, "{"+canonicalizeMap(item)+"}")
                }
                return "[" + strings.Join(items, ",") + "]"
        case []string:
                sorted := make([]string, len(val))
                copy(sorted, val)
                sort.Strings(sorted)
                return "[" + strings.Join(sorted, ",") + "]"
        default:
                b, err := json.Marshal(val)
                if err != nil {
                        return fmt.Sprintf("%v", val)
                }
                return string(b)
        }
}

func CountVerifiedStandards(results map[string]any) int {
        standardsSections := map[string][]string{
                "spf_analysis":     {"RFC 7208"},
                "dmarc_analysis":   {"RFC 7489"},
                "dkim_analysis":    {"RFC 6376"},
                "mta_sts_analysis": {"RFC 8461"},
                "tlsrpt_analysis":  {"RFC 8460"},
                "bimi_analysis":    {"draft-brand-indicators-for-message-identification"},
                "dane_analysis":    {"RFC 6698", "RFC 7671"},
                "caa_analysis":     {"RFC 8659"},
                "dnssec_analysis":  {"RFC 4033", "RFC 4034", "RFC 4035"},
        }

        count := 0
        for section := range standardsSections {
                if data, ok := results[section].(map[string]any); ok {
                        if status, ok := data["status"].(string); ok && status != "" {
                                count += len(standardsSections[section])
                        }
                }
        }
        return count
}
