// Copyright (c) 2024-2026 IT Help San Diego Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL — See LICENSE for terms.
// This file is part of the DNS Tool Intelligence Module.
package ai_surface

import (
        "context"
        "sync"

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
        Status    string                 `json:"status"`
        Message   string                 `json:"message"`
        LLMSTxt   map[string]any         `json:"llms_txt"`
        RobotsTxt map[string]any         `json:"robots_txt"`
        Poisoning map[string]any         `json:"poisoning"`
        Hidden    map[string]any         `json:"hidden_prompts"`
        Evidence  []Evidence             `json:"evidence"`
        Summary   map[string]any         `json:"summary"`
}

func (s *Scanner) Scan(ctx context.Context, domain string) map[string]any {
        var wg sync.WaitGroup
        type namedResult struct {
                key    string
                result map[string]any
        }
        ch := make(chan namedResult, 4)

        tasks := map[string]func(){
                "llms_txt":       func() { ch <- namedResult{"llms_txt", s.CheckLLMSTxt(ctx, domain)} },
                "robots_txt":     func() { ch <- namedResult{"robots_txt", s.CheckRobotsTxtAI(ctx, domain)} },
                "poisoning":      func() { ch <- namedResult{"poisoning", s.DetectPoisoningIOCs(ctx, domain)} },
                "hidden_prompts": func() { ch <- namedResult{"hidden_prompts", s.DetectHiddenPrompts(ctx, domain)} },
        }

        for _, fn := range tasks {
                wg.Add(1)
                go func(f func()) {
                        defer wg.Done()
                        f()
                }(fn)
        }

        go func() {
                wg.Wait()
                close(ch)
        }()

        results := make(map[string]any)
        var allEvidence []Evidence
        for nr := range ch {
                if ev, ok := nr.result["evidence"].([]Evidence); ok {
                        allEvidence = append(allEvidence, ev...)
                }
                convertEvidenceToMaps(nr.result)
                results[nr.key] = nr.result
        }

        summary := buildSummary(results, allEvidence)

        evidenceMaps := make([]map[string]any, len(allEvidence))
        for i, e := range allEvidence {
                evidenceMaps[i] = map[string]any{
                        "type":       e.Type,
                        "source":     e.Source,
                        "detail":     e.Detail,
                        "severity":   e.Severity,
                        "confidence": e.Confidence,
                }
        }

        return map[string]any{
                "status":         summary["status"],
                "message":        summary["message"],
                "llms_txt":       results["llms_txt"],
                "robots_txt":     results["robots_txt"],
                "poisoning":      results["poisoning"],
                "hidden_prompts": results["hidden_prompts"],
                "evidence":       evidenceMaps,
                "summary":        summary,
        }
}

func convertEvidenceToMaps(result map[string]any) {
        if ev, ok := result["evidence"].([]Evidence); ok {
                maps := make([]map[string]any, len(ev))
                for i, e := range ev {
                        maps[i] = map[string]any{
                                "type":       e.Type,
                                "source":     e.Source,
                                "detail":     e.Detail,
                                "severity":   e.Severity,
                                "confidence": e.Confidence,
                        }
                }
                result["evidence"] = maps
        }
}

func buildSummary(results map[string]any, evidence []Evidence) map[string]any {
        hasLLMSTxt := false
        if lt, ok := results["llms_txt"].(map[string]any); ok {
                hasLLMSTxt, _ = lt["found"].(bool)
        }

        robotsBlocksAI := false
        robotsAllowsAI := false
        if rt, ok := results["robots_txt"].(map[string]any); ok {
                robotsBlocksAI, _ = rt["blocks_ai_crawlers"].(bool)
                robotsAllowsAI, _ = rt["allows_ai_crawlers"].(bool)
        }

        poisoningCount := 0
        if p, ok := results["poisoning"].(map[string]any); ok {
                if iocs, ok := p["ioc_count"].(int); ok {
                        poisoningCount = iocs
                }
        }

        hiddenCount := 0
        if h, ok := results["hidden_prompts"].(map[string]any); ok {
                if cnt, ok := h["artifact_count"].(int); ok {
                        hiddenCount = cnt
                }
        }

        status := "info"
        message := "No significant AI surface findings"

        if poisoningCount > 0 || hiddenCount > 0 {
                status = "warning"
                message = "AI surface risks detected"
        } else if hasLLMSTxt || robotsBlocksAI {
                status = "success"
                message = "Active AI governance detected"
        } else if robotsAllowsAI {
                status = "info"
                message = "AI crawlers permitted (no explicit governance)"
        }

        return map[string]any{
                "status":           status,
                "message":          message,
                "has_llms_txt":     hasLLMSTxt,
                "blocks_ai":       robotsBlocksAI,
                "allows_ai":       robotsAllowsAI,
                "poisoning_count":  poisoningCount,
                "hidden_count":     hiddenCount,
                "total_evidence":   len(evidence),
        }
}

