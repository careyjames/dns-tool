// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.

// dns-tool:scrutiny science
package ai_surface

import (
        "bufio"
        "context"
        "fmt"
        "io"
        "log/slog"
        "net/http"
        "regexp"
        "strings"
)

func safeClose(c io.Closer, label string) {
        if err := c.Close(); err != nil {
                slog.Debug("close error", "resource", label, "error", err)
        }
}

type HTTPClient interface {
        Get(ctx context.Context, rawURL string) (*http.Response, error)
        ReadBody(resp *http.Response, maxBytes int64) ([]byte, error)
}

const (
        mapKeyAllowsAiCrawlers = "allows_ai_crawlers"
        mapKeyArtifactCount    = "artifact_count"
        mapKeyBlocksAiCrawlers = "blocks_ai_crawlers"
        mapKeyContentUsage     = "content_usage"
        mapKeyDetail           = "detail"
        mapKeyEvidence         = "evidence"
        mapKeyFound            = "found"
        mapKeyHttps            = "https"
        mapKeyIocCount         = "ioc_count"
        mapKeyMessage          = "message"
        mapKeyStatus           = "status"
        mapKeySuccess          = "success"
        mapKeyWarning          = "warning"
        strObserved            = "Observed"
        mapKeyUrl              = "url"
        mapKeyRaw              = "raw"
        mapKeyLLMSTxt          = "llms_txt"
        mapKeyRobotsTxt        = "robots_txt"
        mapKeyPoisoning        = "poisoning"
        mapKeyHiddenPrompts    = "hidden_prompts"
        mapKeyHttp             = "http"
        mapKeyType             = "type"
        mapKeyInfo             = "info"
)

var hiddenPatternRegexes = []struct {
        re     *regexp.Regexp
        method string
}{
        {regexp.MustCompile(`display\s*:\s*none`), "CSS display:none"},
        {regexp.MustCompile(`visibility\s*:\s*hidden`), "CSS visibility:hidden"},
        {regexp.MustCompile(`position\s*:\s*(absolute|fixed)[^}]{0,100}(left|top)\s*:\s*-\d{4,}`), "Off-screen positioning"},
        {regexp.MustCompile(`aria-hidden\s*=\s*"true"`), "ARIA hidden attribute"},
        {regexp.MustCompile(`opacity\s*:\s*0[^.0-9]`), "CSS zero opacity"},
        {regexp.MustCompile(`font-size\s*:\s*0[^.0-9]`), "CSS zero font-size"},
        {regexp.MustCompile(`color\s*:\s*transparent`), "CSS transparent color"},
        {regexp.MustCompile(`text-indent\s*:\s*-\d{4,}`), "Off-screen text-indent"},
}

type Scanner struct {
        HTTP HTTPClient
}

func NewScanner(httpClient HTTPClient) *Scanner {
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
        evidence := []Evidence{}

        llmsResult := s.checkLLMSTxt(ctx, domain, &evidence)
        robotsResult := s.checkRobotsTxt(ctx, domain, &evidence)
        poisoningResult := s.checkPoisoning(ctx, domain, &evidence)
        hiddenResult := s.checkHiddenPrompts(ctx, domain, &evidence)

        results := map[string]any{
                mapKeyLLMSTxt:       llmsResult,
                mapKeyRobotsTxt:     robotsResult,
                mapKeyPoisoning:     poisoningResult,
                mapKeyHiddenPrompts: hiddenResult,
                mapKeyEvidence:      convertEvidenceSlice(evidence),
        }

        summary := buildSummary(results, evidence)
        results[mapKeyStatus] = summary[mapKeyStatus]
        results[mapKeyMessage] = summary[mapKeyMessage]
        results["summary"] = summary

        return results
}

func llmsTxtURLCandidates(domain string) []string {
        var urls []string
        for _, scheme := range []string{mapKeyHttps, mapKeyHttp} {
                for _, path := range []string{"/.well-known/llms.txt", "/llms.txt"} {
                        urls = append(urls, fmt.Sprintf("%s://%s%s", scheme, domain, path))
                }
        }
        return urls
}

func (s *Scanner) tryFetchLLMSTxt(ctx context.Context, u string) (string, bool) {
        resp, err := s.HTTP.Get(ctx, u)
        if err != nil {
                return "", false
        }
        defer safeClose(resp.Body, "tryFetchLLMSTxt")

        if resp.StatusCode != http.StatusOK {
                return "", false
        }

        body, err := s.HTTP.ReadBody(resp, 64*1024)
        if err != nil {
                return "", false
        }
        if len(string(body)) <= 10 {
                return "", false
        }
        return string(body), true
}

func (s *Scanner) fetchLLMSTxt(ctx context.Context, domain string, evidence *[]Evidence) (found bool, url string, fields map[string]any, rawContent string) {
        for _, u := range llmsTxtURLCandidates(domain) {
                content, ok := s.tryFetchLLMSTxt(ctx, u)
                if !ok {
                        continue
                }
                *evidence = append(*evidence, Evidence{
                        Type:       "llms_txt_found",
                        Source:     u,
                        Detail:     "llms.txt file found providing structured LLM context",
                        Severity:   mapKeyInfo,
                        Confidence: strObserved,
                })
                slog.Info("AI Surface: llms.txt found", "domain", domain, mapKeyUrl, u)
                return true, u, parseLLMSTxtFields(content), content
        }
        return false, "", nil, ""
}

func llmsFullTxtURLCandidates(domain string) []string {
        var urls []string
        for _, scheme := range []string{mapKeyHttps, mapKeyHttp} {
                for _, path := range []string{"/.well-known/llms-full.txt", "/llms-full.txt"} {
                        urls = append(urls, fmt.Sprintf("%s://%s%s", scheme, domain, path))
                }
        }
        return urls
}

func (s *Scanner) tryFetchLLMSFullTxt(ctx context.Context, u string) (string, bool) {
        resp, err := s.HTTP.Get(ctx, u)
        if err != nil {
                return "", false
        }
        defer safeClose(resp.Body, "tryFetchLLMSFullTxt")

        if resp.StatusCode != http.StatusOK {
                return "", false
        }

        body, err := s.HTTP.ReadBody(resp, 256*1024)
        if err != nil {
                return "", false
        }
        if len(body) <= 10 {
                return "", false
        }
        return string(body), true
}

func (s *Scanner) fetchLLMSFullTxt(ctx context.Context, domain string, evidence *[]Evidence) (found bool, fullURL string, rawContent string) {
        for _, u := range llmsFullTxtURLCandidates(domain) {
                content, ok := s.tryFetchLLMSFullTxt(ctx, u)
                if !ok {
                        continue
                }
                *evidence = append(*evidence, Evidence{
                        Type:       "llms_full_txt_found",
                        Source:     u,
                        Detail:     "llms-full.txt also found (extended LLM context)",
                        Severity:   mapKeyInfo,
                        Confidence: strObserved,
                })
                return true, u, content
        }
        return false, "", ""
}

func (s *Scanner) checkLLMSTxt(ctx context.Context, domain string, evidence *[]Evidence) map[string]any {
        result := map[string]any{
                mapKeyFound:    false,
                "full_found":   false,
                mapKeyUrl:      nil,
                "full_url":     nil,
                "fields":       map[string]any{},
                "content":      "",
                "full_content": "",
                mapKeyEvidence: []map[string]any{},
        }

        if found, url, fields, rawContent := s.fetchLLMSTxt(ctx, domain, evidence); found {
                result[mapKeyFound] = true
                result[mapKeyUrl] = url
                result["fields"] = fields
                result["content"] = rawContent
        }

        if found, fullURL, rawContent := s.fetchLLMSFullTxt(ctx, domain, evidence); found {
                result["full_found"] = true
                result["full_url"] = fullURL
                result["full_content"] = rawContent
        }

        return result
}

func parseLLMSTxtFields(content string) map[string]any {
        fields := map[string]any{}
        scanner := bufio.NewScanner(strings.NewReader(content))
        for scanner.Scan() {
                line := strings.TrimSpace(scanner.Text())
                if strings.HasPrefix(line, "#") || line == "" {
                        continue
                }
                if idx := strings.Index(line, ":"); idx > 0 {
                        key := strings.TrimSpace(line[:idx])
                        val := strings.TrimSpace(line[idx+1:])
                        if val != "" {
                                fields[strings.ToLower(key)] = val
                        }
                }
        }
        return fields
}

func (s *Scanner) fetchRobotsTxtContent(ctx context.Context, domain string) (content, url string, ok bool) {
        for _, scheme := range []string{mapKeyHttps, mapKeyHttp} {
                u := fmt.Sprintf("%s://%s/robots.txt", scheme, domain)
                resp, err := s.HTTP.Get(ctx, u)
                if err != nil {
                        continue
                }
                defer safeClose(resp.Body, "fetchRobotsTxtContent")

                if resp.StatusCode != http.StatusOK {
                        continue
                }

                body, err := s.HTTP.ReadBody(resp, 128*1024)
                if err != nil {
                        continue
                }
                if len(string(body)) < 5 {
                        continue
                }
                return string(body), u, true
        }
        return "", "", false
}

func addCrawlerEvidence(evidence *[]Evidence, url string, blocked []string) {
        if len(blocked) > 0 {
                *evidence = append(*evidence, Evidence{
                        Type:       "robots_txt_blocks_ai",
                        Source:     url,
                        Detail:     fmt.Sprintf("robots.txt blocks %d AI crawler(s): %s", len(blocked), strings.Join(blocked, ", ")),
                        Severity:   mapKeyInfo,
                        Confidence: strObserved,
                })
                return
        }
        *evidence = append(*evidence, Evidence{
                Type:       "robots_txt_no_ai_blocks",
                Source:     url,
                Detail:     "robots.txt found but no AI-specific blocking directives",
                Severity:   "low",
                Confidence: strObserved,
        })
}

func addContentUsageEvidence(evidence *[]Evidence, url string, contentUsage map[string]any) {
        found, ok := contentUsage[mapKeyFound].(bool)
        if !ok || !found {
                return
        }
        detail := "Content-Usage directive present in robots.txt"
        if raw, ok := contentUsage[mapKeyRaw].(string); ok {
                detail = fmt.Sprintf("Content-Usage directive observed: %s", raw)
        }
        *evidence = append(*evidence, Evidence{
                Type:       "content_usage_directive",
                Source:     url,
                Detail:     detail,
                Severity:   mapKeyInfo,
                Confidence: strObserved,
        })
}

func (s *Scanner) checkRobotsTxt(ctx context.Context, domain string, evidence *[]Evidence) map[string]any {
        result := map[string]any{
                mapKeyFound:            false,
                mapKeyUrl:              nil,
                mapKeyBlocksAiCrawlers: false,
                mapKeyAllowsAiCrawlers: false,
                "blocked_crawlers":     []string{},
                "allowed_crawlers":     []string{},
                "directives":           []map[string]any{},
                mapKeyContentUsage:     map[string]any{},
                mapKeyEvidence:         []map[string]any{},
        }

        content, url, ok := s.fetchRobotsTxtContent(ctx, domain)
        if !ok {
                return result
        }

        result[mapKeyFound] = true
        result[mapKeyUrl] = url

        blocked, allowed, directives := parseRobotsTxtForAI(content)
        result["blocked_crawlers"] = blocked
        result["allowed_crawlers"] = allowed
        result["directives"] = directives
        result[mapKeyBlocksAiCrawlers] = len(blocked) > 0
        result[mapKeyAllowsAiCrawlers] = len(blocked) == 0

        contentUsage := parseContentUsageDirectives(content)
        result[mapKeyContentUsage] = contentUsage

        addCrawlerEvidence(evidence, url, blocked)
        addContentUsageEvidence(evidence, url, contentUsage)

        slog.Info("AI Surface: robots.txt analyzed", "domain", domain, "blocked", len(blocked), mapKeyContentUsage, contentUsage[mapKeyFound])
        return result
}

func parseContentUsageDirectives(content string) map[string]any {
        result := map[string]any{
                mapKeyFound:  false,
                mapKeyRaw:    "",
                "ai_denied":  false,
                "parameters": map[string]string{},
        }

        rawLines, params := extractContentUsageLines(content)

        if len(rawLines) > 0 {
                result[mapKeyFound] = true
                result[mapKeyRaw] = strings.Join(rawLines, "; ")
        }
        result["parameters"] = params
        result["ai_denied"] = isAIDenied(params)

        return result
}

func extractContentUsageLines(content string) ([]string, map[string]string) {
        var rawLines []string
        params := map[string]string{}

        sc := bufio.NewScanner(strings.NewReader(content))
        for sc.Scan() {
                line := strings.TrimSpace(sc.Text())
                if strings.HasPrefix(line, "#") || line == "" {
                        continue
                }
                lower := strings.ToLower(line)
                if !strings.HasPrefix(lower, "content-usage:") {
                        continue
                }

                value := strings.TrimSpace(line[len("content-usage:"):])
                if value == "" {
                        continue
                }

                rawLines = append(rawLines, value)
                parseContentUsageTokens(value, params)
        }

        return rawLines, params
}

func parseContentUsageTokens(value string, params map[string]string) {
        tokens := strings.Fields(value)
        for _, tok := range tokens {
                if strings.HasPrefix(tok, "/") {
                        continue
                }
                if idx := strings.Index(tok, "="); idx > 0 {
                        key := strings.ToLower(tok[:idx])
                        val := strings.ToLower(tok[idx+1:])
                        params[key] = val
                }
        }
}

func isAIDenied(params map[string]string) bool {
        denyValues := map[string]bool{"n": true, "no": true, "none": true, "disallow": true}
        for _, key := range []string{"ai", "train-ai", "ai-training", "ai-inference"} {
                if val, ok := params[key]; ok && denyValues[val] {
                        return true
                }
        }
        return false
}

type robotsParseState struct {
        currentAgents []string
        blockedSet    map[string]bool
        allowedSet    map[string]bool
        blocked       []string
        allowed       []string
        directives    []map[string]any
}

func processRobotsDirective(line, lower string, state *robotsParseState) {
        for _, agent := range state.currentAgents {
                if strings.HasPrefix(lower, "disallow:") {
                        disallowPath := strings.TrimSpace(line[len("disallow:"):])
                        if disallowPath != "" && !state.blockedSet[agent] {
                                state.blockedSet[agent] = true
                                state.blocked = append(state.blocked, agent)
                                state.directives = append(state.directives, map[string]any{
                                        "agent":     agent,
                                        "directive": "Disallow",
                                        "path":      disallowPath,
                                })
                        }
                } else if strings.HasPrefix(lower, "allow:") {
                        allowPath := strings.TrimSpace(line[len("allow:"):])
                        if allowPath != "" && !state.allowedSet[agent] {
                                state.allowedSet[agent] = true
                                state.allowed = append(state.allowed, agent)
                        }
                }
        }
}

func buildAICrawlerSet() map[string]bool {
        set := map[string]bool{}
        for _, c := range GetAICrawlers() {
                set[strings.ToLower(c)] = true
        }
        return set
}

func handleUserAgentLine(line string, currentAgents []string, aiCrawlerSet map[string]bool) []string {
        agent := strings.TrimSpace(line[len("user-agent:"):])
        agentLower := strings.ToLower(agent)
        if len(currentAgents) > 0 && !strings.HasPrefix(strings.ToLower(currentAgents[0]), agentLower) {
                currentAgents = nil
        }
        if aiCrawlerSet[agentLower] {
                currentAgents = append(currentAgents, agent)
        }
        return currentAgents
}

func parseRobotsTxtForAI(content string) (blocked, allowed []string, directives []map[string]any) {
        sc := bufio.NewScanner(strings.NewReader(content))
        state := &robotsParseState{
                blockedSet: map[string]bool{},
                allowedSet: map[string]bool{},
        }
        aiCrawlerSet := buildAICrawlerSet()

        for sc.Scan() {
                line := strings.TrimSpace(sc.Text())
                if strings.HasPrefix(line, "#") || line == "" {
                        continue
                }

                lower := strings.ToLower(line)

                if strings.HasPrefix(lower, "user-agent:") {
                        state.currentAgents = handleUserAgentLine(line, state.currentAgents, aiCrawlerSet)
                        continue
                }

                if len(state.currentAgents) == 0 {
                        continue
                }

                processRobotsDirective(line, lower, state)
        }

        return state.blocked, state.allowed, state.directives
}

func scanForPrefillLinks(content string) []map[string]any {
        iocs := []map[string]any{}
        prefillPatterns := []string{
                "chat.openai.com/chat?prompt=",
                "chatgpt.com/?prompt=",
                "claude.ai/chat?q=",
                "bard.google.com/?q=",
                "copilot.microsoft.com/?q=",
        }
        for _, pattern := range prefillPatterns {
                if strings.Contains(strings.ToLower(content), strings.ToLower(pattern)) {
                        iocs = append(iocs, map[string]any{
                                mapKeyType:   "prefilled_prompt_link",
                                mapKeyDetail: fmt.Sprintf("Found prefilled AI prompt link pattern: %s", pattern),
                        })
                }
        }
        return iocs
}

func (s *Scanner) fetchHomepageBody(ctx context.Context, domain string) (body, url string, ok bool) {
        for _, scheme := range []string{mapKeyHttps, mapKeyHttp} {
                u := fmt.Sprintf("%s://%s/", scheme, domain)
                resp, err := s.HTTP.Get(ctx, u)
                if err != nil {
                        continue
                }
                defer safeClose(resp.Body, "fetchHomepageBody")

                if resp.StatusCode != http.StatusOK {
                        continue
                }

                b, err := s.HTTP.ReadBody(resp, 512*1024)
                if err != nil {
                        continue
                }
                return string(b), u, true
        }
        return "", "", false
}

func addPoisoningEvidence(evidence *[]Evidence, url string, iocs []map[string]any) {
        for _, ioc := range iocs {
                *evidence = append(*evidence, Evidence{
                        Type:       "poisoning_ioc",
                        Source:     url,
                        Detail:     ioc[mapKeyDetail].(string),
                        Severity:   "medium",
                        Confidence: strObserved,
                })
        }
}

func (s *Scanner) checkPoisoning(ctx context.Context, domain string, evidence *[]Evidence) map[string]any {
        result := map[string]any{
                mapKeyStatus:   mapKeySuccess,
                mapKeyMessage:  "No AI recommendation poisoning indicators found",
                mapKeyIocCount: 0,
                "iocs":         []map[string]any{},
                mapKeyEvidence: []map[string]any{},
        }

        body, url, ok := s.fetchHomepageBody(ctx, domain)
        if !ok {
                return result
        }

        iocs := scanForPrefillLinks(body)
        if len(iocs) == 0 {
                return result
        }

        result[mapKeyIocCount] = len(iocs)
        result["iocs"] = iocs
        result[mapKeyStatus] = mapKeyWarning
        result[mapKeyMessage] = fmt.Sprintf("%d AI recommendation poisoning indicator(s) found", len(iocs))
        addPoisoningEvidence(evidence, url, iocs)

        return result
}

var promptKeywords = []string{
        "you are a", "ignore previous", "system prompt",
        "act as", "pretend you", "respond as if",
        "disregard", "forget your", "new instructions",
        "do not reveal", "override", "jailbreak",
}

func extractNearbyText(lower string, loc []int) string {
        start := loc[0]
        end := start + 500
        if end > len(lower) {
                end = len(lower)
        }
        return lower[start:end]
}

func findKeywordsInRegion(nearby, method string, seen map[string]bool) []map[string]any {
        var artifacts []map[string]any
        for _, kw := range promptKeywords {
                if !strings.Contains(nearby, kw) {
                        continue
                }
                key := method + "|" + kw
                if seen[key] {
                        continue
                }
                seen[key] = true
                artifacts = append(artifacts, map[string]any{
                        "method":     method,
                        mapKeyDetail: fmt.Sprintf("Hidden element with prompt keyword '%s' detected near %s pattern", kw, method),
                })
        }
        return artifacts
}

func scanForHiddenPrompts(content string) []map[string]any {
        var artifacts []map[string]any
        seen := map[string]bool{}

        lower := strings.ToLower(content)
        for _, hp := range hiddenPatternRegexes {
                locs := hp.re.FindAllStringIndex(lower, -1)
                for _, loc := range locs {
                        nearby := extractNearbyText(lower, loc)
                        artifacts = append(artifacts, findKeywordsInRegion(nearby, hp.method, seen)...)
                }
        }

        return artifacts
}

func (s *Scanner) fetchHomepageBodyRaw(ctx context.Context, domain string) (body, url string, ok bool) {
        for _, scheme := range []string{mapKeyHttps, mapKeyHttp} {
                u := fmt.Sprintf("%s://%s/", scheme, domain)
                resp, err := s.HTTP.Get(ctx, u)
                if err != nil {
                        continue
                }
                defer safeClose(resp.Body, "fetchHomepageBodyRaw")

                if resp.StatusCode != http.StatusOK {
                        continue
                }

                b, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
                if err != nil {
                        continue
                }
                return string(b), u, true
        }
        return "", "", false
}

func addHiddenPromptEvidence(evidence *[]Evidence, url string, artifacts []map[string]any) {
        for _, a := range artifacts {
                *evidence = append(*evidence, Evidence{
                        Type:       "hidden_prompt",
                        Source:     url,
                        Detail:     a[mapKeyDetail].(string),
                        Severity:   "high",
                        Confidence: strObserved,
                })
        }
}

func (s *Scanner) checkHiddenPrompts(ctx context.Context, domain string, evidence *[]Evidence) map[string]any {
        result := map[string]any{
                mapKeyStatus:        mapKeySuccess,
                mapKeyMessage:       "No hidden prompt-like artifacts detected",
                mapKeyArtifactCount: 0,
                "artifacts":         []map[string]any{},
                mapKeyEvidence:      []map[string]any{},
        }

        body, url, ok := s.fetchHomepageBodyRaw(ctx, domain)
        if !ok {
                return result
        }

        artifacts := scanForHiddenPrompts(body)
        if len(artifacts) == 0 {
                return result
        }

        result[mapKeyArtifactCount] = len(artifacts)
        result["artifacts"] = artifacts
        result[mapKeyStatus] = mapKeyWarning
        result[mapKeyMessage] = fmt.Sprintf("%d hidden prompt artifact(s) found", len(artifacts))
        addHiddenPromptEvidence(evidence, url, artifacts)

        return result
}

func convertEvidenceSlice(evidence []Evidence) []map[string]any {
        result := make([]map[string]any, 0, len(evidence))
        for _, e := range evidence {
                result = append(result, map[string]any{
                        mapKeyType:   e.Type,
                        "source":     e.Source,
                        mapKeyDetail: e.Detail,
                        "severity":   e.Severity,
                        "confidence": e.Confidence,
                })
        }
        return result
}

func convertEvidenceToMaps(result map[string]any) {
        // Intentionally empty: evidence is already in map form from OSS scan path
}

func buildSummary(results map[string]any, evidence []Evidence) map[string]any {
        llms := results[mapKeyLLMSTxt].(map[string]any)
        robots := results[mapKeyRobotsTxt].(map[string]any)
        poisoning := results[mapKeyPoisoning].(map[string]any)
        hidden := results[mapKeyHiddenPrompts].(map[string]any)

        hasLLMS, _ := llms[mapKeyFound].(bool)
        blocksAI, _ := robots[mapKeyBlocksAiCrawlers].(bool)
        allowsAI, _ := robots[mapKeyAllowsAiCrawlers].(bool)
        hasContentUsage := false
        if cu, ok := robots[mapKeyContentUsage].(map[string]any); ok {
                hasContentUsage, _ = cu[mapKeyFound].(bool)
        }
        iocCount := 0
        if v, ok := poisoning[mapKeyIocCount].(int); ok {
                iocCount = v
        }
        hiddenCount := 0
        if v, ok := hidden[mapKeyArtifactCount].(int); ok {
                hiddenCount = v
        }

        status := mapKeyInfo
        message := "No significant AI surface findings"

        if iocCount > 0 || hiddenCount > 0 {
                status = mapKeyWarning
                message = "AI-related risks detected — review recommended"
        } else if hasLLMS || blocksAI || hasContentUsage {
                status = mapKeySuccess
                message = "AI governance signals observed"
        } else if allowsAI {
                status = mapKeyInfo
                message = "No AI governance measures detected"
        }

        return map[string]any{
                mapKeyStatus:        status,
                mapKeyMessage:       message,
                "has_llms_txt":      hasLLMS,
                "blocks_ai":         blocksAI,
                "allows_ai":         allowsAI,
                "has_content_usage": hasContentUsage,
                "poisoning_count":   iocCount,
                "hidden_count":      hiddenCount,
                "total_evidence":    len(evidence),
        }
}
