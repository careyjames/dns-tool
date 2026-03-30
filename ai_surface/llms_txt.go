// Copyright (c) 2024-2026 IT Help San Diego Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL — See LICENSE for terms.
// This file is part of the DNS Tool Intelligence Module.
package ai_surface

import (
	"context"
	"fmt"
	"strings"
)

func (s *Scanner) CheckLLMSTxt(ctx context.Context, domain string) map[string]any {
	result := map[string]any{
		"found":      false,
		"full_found": false,
		"url":        nil,
		"full_url":   nil,
		"fields":     map[string]any{},
		"evidence":   []Evidence{},
	}

	llmsURL := fmt.Sprintf("https://%s/llms.txt", domain)
	llmsFullURL := fmt.Sprintf("https://%s/llms-full.txt", domain)

	body, err := s.fetchTextFile(ctx, llmsURL)
	if err == nil && body != "" && looksLikeLLMSTxt(body) {
		result["found"] = true
		result["url"] = llmsURL
		result["fields"] = parseLLMSTxt(body)
		result["evidence"] = []Evidence{{
			Type:       "llms_txt",
			Source:     llmsURL,
			Detail:     "llms.txt file found — domain provides structured LLM context",
			Severity:   "informational",
			Confidence: "observed",
		}}
	}

	fullBody, err := s.fetchTextFile(ctx, llmsFullURL)
	if err == nil && fullBody != "" {
		result["full_found"] = true
		result["full_url"] = llmsFullURL
		size := len(fullBody)
		result["full_size"] = size
		if !result["found"].(bool) {
			result["evidence"] = []Evidence{{
				Type:       "llms_full_txt",
				Source:     llmsFullURL,
				Detail:     fmt.Sprintf("llms-full.txt found (%d bytes)", size),
				Severity:   "informational",
				Confidence: "observed",
			}}
		} else {
			ev := result["evidence"].([]Evidence)
			ev = append(ev, Evidence{
				Type:       "llms_full_txt",
				Source:     llmsFullURL,
				Detail:     fmt.Sprintf("llms-full.txt also found (%d bytes) — extended LLM context available", size),
				Severity:   "informational",
				Confidence: "observed",
			})
			result["evidence"] = ev
		}
	}

	return result
}

func looksLikeLLMSTxt(body string) bool {
	lower := strings.ToLower(body)
	if strings.Contains(lower, "<html") || strings.Contains(lower, "<!doctype") {
		return false
	}
	markers := []string{"#", "url:", "description:", "docs:", "api:"}
	for _, m := range markers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return len(body) > 10 && len(body) < 100000
}

func parseLLMSTxt(body string) map[string]any {
	fields := map[string]any{}
	var currentSection string
	var docs []string

	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "# ") {
			currentSection = strings.TrimPrefix(line, "# ")
			if _, ok := fields["title"]; !ok {
				fields["title"] = currentSection
			}
			continue
		}
		if strings.HasPrefix(line, "> ") {
			fields["description"] = strings.TrimPrefix(line, "> ")
			continue
		}
		parseLLMSTxtFieldLine(line, currentSection, fields, &docs)
	}

	if len(docs) > 0 {
		fields["docs"] = docs
	}

	return fields
}

func parseLLMSTxtFieldLine(line, _ string, fields map[string]any, docs *[]string) {
	lower := strings.ToLower(line)
	if strings.HasPrefix(lower, "- [") || strings.HasPrefix(lower, "- http") {
		*docs = append(*docs, line)
		return
	}
	for _, prefix := range []string{"url:", "docs:", "api:", "contact:", "license:"} {
		if strings.HasPrefix(lower, prefix) {
			key := strings.TrimSuffix(prefix, ":")
			val := strings.TrimSpace(line[len(prefix):])
			fields[key] = val
			return
		}
	}
}

