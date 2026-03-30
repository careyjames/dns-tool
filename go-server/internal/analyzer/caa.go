// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"context"
	"fmt"
	"strings"
)

func identifyCAIssuer(record string) string {
	lower := strings.ToLower(record)
	switch {
	case strings.Contains(lower, "letsencrypt"):
		return "Let's Encrypt"
	case strings.Contains(lower, "digicert"):
		return "DigiCert"
	case strings.Contains(lower, "sectigo") || strings.Contains(lower, "comodo"):
		return "Sectigo"
	case strings.Contains(lower, "globalsign"):
		return "GlobalSign"
	case strings.Contains(lower, "amazon"):
		return "Amazon"
	case strings.Contains(lower, "google"):
		return "Google Trust Services"
	default:
		parts := strings.Fields(record)
		if len(parts) >= 3 {
			return strings.Trim(parts[len(parts)-1], "\"")
		}
		return ""
	}
}

type caaParsedRecords struct {
	issueSet     map[string]bool
	issuewildSet map[string]bool
	hasWildcard  bool
	hasIodef     bool
}

func parseCAARecords(records []string) caaParsedRecords {
	parsed := caaParsedRecords{
		issueSet:     make(map[string]bool),
		issuewildSet: make(map[string]bool),
	}
	for _, record := range records {
		parseSingleCAARecord(record, &parsed)
	}
	return parsed
}

func parseSingleCAARecord(record string, parsed *caaParsedRecords) {
	lower := strings.ToLower(record)

	if strings.Contains(lower, "issuewild") {
		parsed.hasWildcard = true
		if issuer := identifyCAIssuer(record); issuer != "" {
			parsed.issuewildSet[issuer] = true
		}
	} else if strings.Contains(lower, "issue ") || strings.Contains(lower, "issue\"") {
		if issuer := identifyCAIssuer(record); issuer != "" {
			parsed.issueSet[issuer] = true
		}
	}

	if strings.Contains(lower, "iodef") {
		parsed.hasIodef = true
	}
}

func collectMapKeys(m map[string]bool) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func buildCAAMessage(issuers, wildcardIssuers []string, hasWildcard bool) string {
	messageParts := []string{"CAA configured"}
	if len(issuers) > 0 {
		messageParts = append(messageParts, "- only "+strings.Join(issuers, ", ")+" can issue certificates")
	} else {
		messageParts = append(messageParts, "- specific CAs authorized")
	}

	if hasWildcard {
		if len(wildcardIssuers) > 0 {
			messageParts = append(messageParts, fmt.Sprintf("(wildcard issuance: %s per RFC 8659 §4.3)", strings.Join(wildcardIssuers, ", ")))
		} else {
			messageParts = append(messageParts, "(wildcard issuance restricted)")
		}
	}

	return strings.Join(messageParts, " ")
}

func (a *Analyzer) AnalyzeCAA(ctx context.Context, domain string) map[string]any {
	records := a.DNS.QueryDNS(ctx, "CAA", domain)

	if len(records) == 0 {
		return map[string]any{
			"status":       "warning",
			"message":      "No CAA records found - any CA can issue certificates",
			"records":      []string{},
			"issuers":      []string{},
			"has_wildcard": false,
			"has_iodef":    false,
		}
	}

	parsed := parseCAARecords(records)
	issuers := collectMapKeys(parsed.issueSet)
	wildcardIssuers := collectMapKeys(parsed.issuewildSet)
	message := buildCAAMessage(issuers, wildcardIssuers, parsed.hasWildcard)

	return map[string]any{
		"status":           "success",
		"message":          message,
		"records":          records,
		"issuers":          issuers,
		"wildcard_issuers": wildcardIssuers,
		"has_wildcard":     parsed.hasWildcard,
		"has_iodef":        parsed.hasIodef,
		"mpic_note":        "Since September 2025, all public CAs must verify domain control from multiple geographic locations (Multi-Perspective Issuance Corroboration, CA/B Forum Ballot SC-067). CAA records are now checked from multiple network perspectives before certificate issuance.",
	}
}
