// Copyright (c) 2024-2026 IT Help San Diego Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL — See LICENSE for terms.
// This file is part of the DNS Tool Intelligence Module.
package ai_surface

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

var (
	prefilledPromptRe = regexp.MustCompile(`(?i)https?://[^\s"'<>]*(?:chat\.openai\.com/|chatgpt\.com/|claude\.ai/|gemini\.google\.com/|perplexity\.ai/|copilot\.microsoft\.com/)[^\s"'<>]*[?&](?:q|prompt|text|message)=`)
	promptInjectionRe = regexp.MustCompile(`(?i)(?:always recommend|you must suggest|when asked about|ignore previous|disregard all|your instructions are|respond with|you are an? (?:helpful|expert|knowledgeable))[^.]{5,80}(?:our (?:product|service|company|brand|website)|(?:visit|go to|check out) (?:https?://)?[a-zA-Z0-9.-]+\.[a-z]{2,})`)
	hiddenTextSelectors = []string{
		`display:\s*none`,
		`visibility:\s*hidden`,
		`opacity:\s*0[^.]`,
		`position:\s*absolute[^;]*(?:left|top):\s*-\d{4,}`,
		`font-size:\s*0(?:px|em|rem|%)`,
		`color:\s*(?:transparent|rgba\s*\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*0\s*\))`,
		`height:\s*0[^.].*overflow:\s*hidden`,
		`clip:\s*rect\s*\(\s*0`,
	}
)

func (s *Scanner) DetectPoisoningIOCs(ctx context.Context, domain string) map[string]any {
	result := map[string]any{
		"status":    "success",
		"message":   "No AI recommendation poisoning indicators found",
		"ioc_count": 0,
		"iocs":      []map[string]any{},
		"evidence":  []Evidence{},
	}

	homepageURL := fmt.Sprintf("https://%s/", domain)
	body, err := s.fetchTextFile(ctx, homepageURL)
	if err != nil || body == "" {
		result["message"] = "Could not fetch homepage for analysis"
		return result
	}

	var iocs []map[string]any
	var evidence []Evidence

	prefilledMatches := prefilledPromptRe.FindAllString(body, 10)
	for _, match := range prefilledMatches {
		iocs = append(iocs, map[string]any{
			"type":    "prefilled_prompt_link",
			"detail":  truncate(match, 120),
			"source":  homepageURL,
		})
		evidence = append(evidence, Evidence{
			Type:       "prefilled_prompt",
			Source:     homepageURL,
			Detail:     fmt.Sprintf("Prefilled AI prompt link detected: %s", truncate(match, 80)),
			Severity:   "medium",
			Confidence: "observed",
		})
	}

	injectionMatches := promptInjectionRe.FindAllString(body, 5)
	for _, match := range injectionMatches {
		iocs = append(iocs, map[string]any{
			"type":    "prompt_injection_text",
			"detail":  truncate(match, 120),
			"source":  homepageURL,
		})
		evidence = append(evidence, Evidence{
			Type:       "prompt_injection",
			Source:     homepageURL,
			Detail:     fmt.Sprintf("Possible prompt injection text: %s", truncate(match, 80)),
			Severity:   "medium",
			Confidence: "inferred",
		})
	}

	if len(iocs) > 0 {
		result["status"] = "warning"
		result["message"] = fmt.Sprintf("%d AI recommendation poisoning indicator(s) detected", len(iocs))
	}
	result["ioc_count"] = len(iocs)
	result["iocs"] = iocs
	result["evidence"] = evidence

	return result
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func (s *Scanner) DetectHiddenPrompts(ctx context.Context, domain string) map[string]any {
	result := map[string]any{
		"status":         "success",
		"message":        "No hidden prompt-like artifacts found",
		"artifact_count": 0,
		"artifacts":      []map[string]any{},
		"evidence":       []Evidence{},
	}

	homepageURL := fmt.Sprintf("https://%s/", domain)
	body, err := s.fetchTextFile(ctx, homepageURL)
	if err != nil || body == "" {
		result["message"] = "Could not fetch homepage for analysis"
		return result
	}

	var artifacts []map[string]any
	var evidence []Evidence

	artifacts, evidence = detectHiddenTextArtifacts(body, homepageURL, artifacts, evidence)

	if len(artifacts) > 0 {
		result["status"] = "warning"
		result["message"] = fmt.Sprintf("%d hidden prompt-like artifact(s) found", len(artifacts))
	}
	result["artifact_count"] = len(artifacts)
	result["artifacts"] = artifacts
	result["evidence"] = evidence

	return result
}

func detectHiddenTextArtifacts(body, sourceURL string, artifacts []map[string]any, evidence []Evidence) ([]map[string]any, []Evidence) {
	hiddenBlockRe := buildHiddenBlockRegex()
	if hiddenBlockRe == nil {
		return artifacts, evidence
	}

	matches := hiddenBlockRe.FindAllString(body, 20)
	for _, match := range matches {
		text := extractTextContent(match)
		if text == "" || len(text) < 30 {
			continue
		}
		if looksLikePromptInstruction(text) {
			artifacts = append(artifacts, map[string]any{
				"type":    "hidden_prompt_text",
				"detail":  truncate(text, 200),
				"source":  sourceURL,
				"method":  "css_hidden",
			})
			evidence = append(evidence, Evidence{
				Type:       "hidden_prompt",
				Source:     sourceURL,
				Detail:     fmt.Sprintf("CSS-hidden text with prompt-like content: %s", truncate(text, 80)),
				Severity:   "high",
				Confidence: "inferred",
			})
		}
	}
	return artifacts, evidence
}

func buildHiddenBlockRegex() *regexp.Regexp {
	patterns := make([]string, len(hiddenTextSelectors))
	for i, sel := range hiddenTextSelectors {
		patterns[i] = fmt.Sprintf(`<[^>]+style="[^"]*%s[^"]*"[^>]*>[^<]{30,500}<`, sel)
	}
	combined := strings.Join(patterns, "|")
	re, err := regexp.Compile("(?i)(?:" + combined + ")")
	if err != nil {
		return nil
	}
	return re
}

func extractTextContent(html string) string {
	tagRe := regexp.MustCompile(`<[^>]*>`)
	text := tagRe.ReplaceAllString(html, " ")
	text = strings.Join(strings.Fields(text), " ")
	return strings.TrimSpace(text)
}

func looksLikePromptInstruction(text string) bool {
	lower := strings.ToLower(text)
	promptMarkers := []string{
		"always recommend",
		"you must suggest",
		"when asked about",
		"ignore previous",
		"you are a",
		"respond with",
		"your instructions",
		"as an ai",
		"preferred provider",
		"best choice for",
	}
	for _, marker := range promptMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

