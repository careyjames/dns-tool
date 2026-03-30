// Copyright (c) 2024-2026 IT Help San Diego Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL — See LICENSE for terms.
// This file is part of the DNS Tool Intelligence Module.
package ai_surface

import (
	"context"
	"fmt"
	"strings"
)

const directiveDisallow = directiveDisallow

var knownAICrawlers = []string{
	"GPTBot",
	"ChatGPT-User",
	"Google-Extended",
	"CCBot",
	"anthropic-ai",
	"ClaudeBot",
	"Claude-Web",
	"Bytespider",
	"PerplexityBot",
	"Amazonbot",
	"FacebookBot",
	"Meta-ExternalAgent",
	"Applebot-Extended",
	"Cohere-ai",
	"Diffbot",
	"ImagesiftBot",
	"Omgilibot",
	"YouBot",
}

type robotsDirective struct {
	UserAgent string `json:"user_agent"`
	Action    string `json:"action"`
	Path      string `json:"path"`
}

func (s *Scanner) CheckRobotsTxtAI(ctx context.Context, domain string) map[string]any {
	result := map[string]any{
		"found":             false,
		"url":               nil,
		"blocks_ai_crawlers": false,
		"allows_ai_crawlers": false,
		"blocked_crawlers":  []string{},
		"allowed_crawlers":  []string{},
		"directives":        []robotsDirective{},
		"evidence":          []Evidence{},
	}

	robotsURL := fmt.Sprintf("https://%s/robots.txt", domain)
	body, err := s.fetchTextFile(ctx, robotsURL)
	if err != nil || body == "" {
		return result
	}

	if strings.Contains(strings.ToLower(body), "<html") {
		return result
	}

	result["found"] = true
	result["url"] = robotsURL

	blocked, allowed, directives := parseRobotsForAI(body)

	result["blocked_crawlers"] = blocked
	result["allowed_crawlers"] = allowed
	result["directives"] = directives
	result["blocks_ai_crawlers"] = len(blocked) > 0
	result["allows_ai_crawlers"] = len(allowed) > 0 && len(blocked) == 0

	var evidence []Evidence
	if len(blocked) > 0 {
		evidence = append(evidence, Evidence{
			Type:       "robots_ai_block",
			Source:     robotsURL,
			Detail:     fmt.Sprintf("robots.txt blocks %d AI crawler(s): %s", len(blocked), strings.Join(blocked, ", ")),
			Severity:   "informational",
			Confidence: "observed",
		})
	}
	if len(allowed) > 0 && len(blocked) == 0 {
		evidence = append(evidence, Evidence{
			Type:       "robots_ai_allow",
			Source:     robotsURL,
			Detail:     fmt.Sprintf("robots.txt explicitly allows %d AI crawler(s) with no blocks", len(allowed)),
			Severity:   "low",
			Confidence: "observed",
		})
	}
	result["evidence"] = evidence

	return result
}

func parseRobotsForAI(body string) (blocked []string, allowed []string, directives []robotsDirective) {
	var currentUA string
	seenBlocked := make(map[string]bool)
	seenAllowed := make(map[string]bool)

	wildcardDisallowAll := false

	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "user-agent:") {
			currentUA = strings.TrimSpace(line[len("user-agent:"):])
			continue
		}

		if currentUA == "*" && strings.HasPrefix(lower, directiveDisallow) {
			path := strings.TrimSpace(line[len(directiveDisallow):])
			if path == "/" {
				wildcardDisallowAll = true
			}
		}

		processRobotsLine(lower, line, currentUA, seenBlocked, seenAllowed, &directives)
	}

	for name := range seenBlocked {
		blocked = append(blocked, name)
	}

	if wildcardDisallowAll {
		for _, crawler := range knownAICrawlers {
			if !seenBlocked[crawler] && !seenAllowed[crawler] {
				seenBlocked[crawler] = true
				blocked = append(blocked, crawler)
			}
		}
	}

	for name := range seenAllowed {
		if !seenBlocked[name] {
			allowed = append(allowed, name)
		}
	}

	return blocked, allowed, directives
}

func processRobotsLine(lower, _ string, currentUA string, seenBlocked, seenAllowed map[string]bool, directives *[]robotsDirective) {
	matchedCrawler := matchAICrawler(currentUA)
	if matchedCrawler == "" {
		return
	}

	if strings.HasPrefix(lower, directiveDisallow) {
		path := strings.TrimSpace(lower[len(directiveDisallow):])
		if path == "/" || path == "" {
			seenBlocked[matchedCrawler] = true
			*directives = append(*directives, robotsDirective{
				UserAgent: matchedCrawler,
				Action:    "disallow",
				Path:      path,
			})
		}
	} else if strings.HasPrefix(lower, "allow:") {
		path := strings.TrimSpace(lower[len("allow:"):])
		seenAllowed[matchedCrawler] = true
		*directives = append(*directives, robotsDirective{
			UserAgent: matchedCrawler,
			Action:    "allow",
			Path:      path,
		})
	}
}

func matchAICrawler(userAgent string) string {
	lower := strings.ToLower(userAgent)
	for _, crawler := range knownAICrawlers {
		if strings.EqualFold(userAgent, crawler) || strings.Contains(lower, strings.ToLower(crawler)) {
			return crawler
		}
	}
	return ""
}

