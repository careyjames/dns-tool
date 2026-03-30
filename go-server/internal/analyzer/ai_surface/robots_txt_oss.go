//go:build !intel

// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// Stub implementations. See the corresponding _intel.go file (requires -tags intel build).
// dns-tool:scrutiny science
package ai_surface

import "context"

var knownAICrawlers = []string{}

func (s *Scanner) CheckRobotsTxtAI(ctx context.Context, domain string) map[string]any {
        return map[string]any{
                "found":              false,
                "url":                nil,
                "blocks_ai_crawlers": false,
                "allows_ai_crawlers": false,
                "blocked_crawlers":   []string{},
                "allowed_crawlers":   []string{},
                "directives":         []robotsDirective{},
                "evidence":           []Evidence{},
        }
}

func parseRobotsForAI(body string) (blocked, allowed []string, directives []robotsDirective) {
        return nil, nil, nil
}

func processRobotsLine(lower, line, currentUA string, seenBlocked, seenAllowed map[string]bool, directives *[]robotsDirective) {
        // OSS stub: full implementation in _intel.go counterpart
}

func matchAICrawler(userAgent string) string {
        return ""
}
