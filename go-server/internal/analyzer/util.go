// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"encoding/json"
	"strings"
)

func jsonUnmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

func strContainsAny(s string, substrs ...string) bool {
	lower := strings.ToLower(s)
	for _, sub := range substrs {
		if strings.Contains(lower, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

func strHasSuffix(s string, suffixes ...string) bool {
	lower := strings.ToLower(s)
	for _, suffix := range suffixes {
		if strings.HasSuffix(lower, strings.ToLower(suffix)) {
			return true
		}
	}
	return false
}

func uniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range input {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func getStr(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getSlice(m map[string]any, key string) []string {
	if v, ok := m[key]; ok {
		switch s := v.(type) {
		case []string:
			return s
		case []any:
			var result []string
			for _, item := range s {
				if str, ok := item.(string); ok {
					result = append(result, str)
				}
			}
			return result
		}
	}
	return nil
}

func getBool(m map[string]any, key string) bool {
	if v, ok := m[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

func getMap(m map[string]any, key string) map[string]any {
	if v, ok := m[key]; ok {
		if sub, ok := v.(map[string]any); ok {
			return sub
		}
	}
	return nil
}

func derefStr(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

func derefInt(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

func classifyHTTPError(err error, truncateLen int) string {
	errStr := err.Error()
	if strings.Contains(errStr, "tls") || strings.Contains(errStr, "certificate") {
		return "SSL error"
	}
	if strings.Contains(errStr, "connection") || strings.Contains(errStr, "dial") {
		return "Connection failed"
	}
	if strings.Contains(errStr, "timeout") {
		return "Timeout"
	}
	if truncateLen > 0 && len(errStr) > truncateLen {
		errStr = errStr[:truncateLen]
	}
	return errStr
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
