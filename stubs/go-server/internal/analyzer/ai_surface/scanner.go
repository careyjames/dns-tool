// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// This file contains stub implementations. See the corresponding _intel.go file (requires -tags intel build).
package ai_surface

import (
        "context"

        "dnstool/go-server/internal/dnsclient"
)

type Scanner struct {
        HTTP *dnsclient.SafeHTTPClient
}

func NewScanner(httpClient *dnsclient.SafeHTTPClient) *Scanner {
        return &Scanner{HTTP: httpClient}
}

type Evidence struct {
        Type       string `json:"type"`
        Source     string `json:"source"`
        Detail     string `json:"detail"`
        Severity   string `json:"severity"`
        Confidence string `json:"confidence"`
}

type ScanResult struct {
        Status    string         `json:"status"`
        Message   string         `json:"message"`
        LLMSTxt   map[string]any `json:"llms_txt"`
        RobotsTxt map[string]any `json:"robots_txt"`
        Poisoning map[string]any `json:"poisoning"`
        Hidden    map[string]any `json:"hidden_prompts"`
        Evidence  []Evidence     `json:"evidence"`
        Summary   map[string]any `json:"summary"`
}

func (s *Scanner) Scan(ctx context.Context, domain string) map[string]any {
        return map[string]any{
                "status":         "info",
                "message":        "AI surface scanning not available in stub version",
                "llms_txt":       map[string]any{"found": false, "full_found": false, "url": nil, "full_url": nil, "fields": map[string]any{}, "content": "", "full_content": "", "evidence": []map[string]any{}},
                "robots_txt":     map[string]any{"found": false, "url": nil, "blocks_ai_crawlers": false, "allows_ai_crawlers": false, "blocked_crawlers": []string{}, "allowed_crawlers": []string{}, "directives": []map[string]any{}, "evidence": []map[string]any{}},
                "poisoning":      map[string]any{"status": "success", "message": "No AI recommendation poisoning indicators found", "ioc_count": 0, "iocs": []map[string]any{}, "evidence": []map[string]any{}},
                "hidden_prompts": map[string]any{"status": "success", "message": "No hidden prompt-like artifacts found", "artifact_count": 0, "artifacts": []map[string]any{}, "evidence": []map[string]any{}},
                "evidence":       []map[string]any{},
                "summary": map[string]any{
                        "status":          "info",
                        "message":         "No significant AI surface findings",
                        "has_llms_txt":    false,
                        "blocks_ai":      false,
                        "allows_ai":      false,
                        "poisoning_count": 0,
                        "hidden_count":    0,
                        "total_evidence":  0,
                },
        }
}

func convertEvidenceToMaps(result map[string]any) {
        // intentionally empty — OSS stub
}

func buildSummary(results map[string]any, evidence []Evidence) map[string]any {
        return map[string]any{
                "status":          "info",
                "message":         "No significant AI surface findings",
                "has_llms_txt":    false,
                "blocks_ai":      false,
                "allows_ai":      false,
                "poisoning_count": 0,
                "hidden_count":    0,
                "total_evidence":  0,
        }
}
