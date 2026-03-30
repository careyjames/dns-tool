package ai_surface

import (
        "context"
        "io"
        "testing"
)

func TestCoverageBoostAI_ParseLLMSTxtFieldLine_Stub(t *testing.T) {
        fields := map[string]any{}
        var docs []string
        parseLLMSTxtFieldLine("Title: Example", "header", fields, &docs)
        if len(fields) != 0 {
                t.Errorf("expected empty fields from OSS stub, got %v", fields)
        }
        if len(docs) != 0 {
                t.Errorf("expected empty docs from OSS stub, got %v", docs)
        }
}

func TestCoverageBoostAI_ProcessRobotsLine_Stub(t *testing.T) {
        seenBlocked := map[string]bool{}
        seenAllowed := map[string]bool{}
        var directives []robotsDirective
        processRobotsLine("disallow: /", "disallow: /", "GPTBot", seenBlocked, seenAllowed, &directives)
        if len(seenBlocked) != 0 {
                t.Errorf("expected empty seenBlocked from OSS stub, got %v", seenBlocked)
        }
        if len(directives) != 0 {
                t.Errorf("expected empty directives from OSS stub, got %v", directives)
        }
}

func TestCoverageBoostAI_MatchAICrawler_Stub(t *testing.T) {
        result := matchAICrawler("GPTBot")
        if result != "" {
                t.Errorf("expected empty string from OSS stub, got %q", result)
        }
}

func TestCoverageBoostAI_LooksLikeLLMSTxt_Stub(t *testing.T) {
        if looksLikeLLMSTxt("# Example llms.txt\nTitle: Test") {
                t.Error("expected false from OSS stub")
        }
}

func TestCoverageBoostAI_ParseLLMSTxt_Stub(t *testing.T) {
        result := parseLLMSTxt("# Example\nTitle: Test")
        if len(result) != 0 {
                t.Errorf("expected empty map from OSS stub, got %v", result)
        }
}

func TestCoverageBoostAI_GetAICrawlers_Stub(t *testing.T) {
        crawlers := GetAICrawlers()
        if crawlers == nil {
                t.Error("expected non-nil slice")
        }
}

func TestCoverageBoostAI_CheckLLMSTxt_Stub(t *testing.T) {
        s := NewScanner(nil)
        result := s.CheckLLMSTxt(context.Background(), "example.com")
        if result["found"] != false {
                t.Error("expected found=false from OSS stub")
        }
}

func TestCoverageBoostAI_CheckRobotsTxtAI_Stub(t *testing.T) {
        s := NewScanner(nil)
        result := s.CheckRobotsTxtAI(context.Background(), "example.com")
        if result["found"] != false {
                t.Error("expected found=false from OSS stub")
        }
}

func TestCoverageBoostAI_DetectPoisoningIOCs_Stub(t *testing.T) {
        s := NewScanner(nil)
        result := s.DetectPoisoningIOCs(context.Background(), "example.com")
        if result["ioc_count"] != 0 {
                t.Error("expected ioc_count=0 from OSS stub")
        }
}

func TestCoverageBoostAI_DetectHiddenPrompts_Stub(t *testing.T) {
        s := NewScanner(nil)
        result := s.DetectHiddenPrompts(context.Background(), "example.com")
        if result["artifact_count"] != 0 {
                t.Error("expected artifact_count=0 from OSS stub")
        }
}

func TestCoverageBoostAI_DetectHiddenTextArtifacts_Stub(t *testing.T) {
        artifacts, evidence := detectHiddenTextArtifacts("<div>test</div>", "https://example.com", nil, nil)
        if artifacts != nil {
                t.Error("expected nil artifacts from OSS stub")
        }
        if evidence != nil {
                t.Error("expected nil evidence from OSS stub")
        }
}

func TestCoverageBoostAI_BuildHiddenBlockRegex_Stub(t *testing.T) {
        re := buildHiddenBlockRegex()
        if re != nil {
                t.Error("expected nil regex from OSS stub")
        }
}

func TestCoverageBoostAI_ExtractTextContent_Stub(t *testing.T) {
        result := extractTextContent("<div>hello</div>")
        if result != "" {
                t.Errorf("expected empty string from OSS stub, got %q", result)
        }
}

func TestCoverageBoostAI_LooksLikePromptInstruction_Stub(t *testing.T) {
        if looksLikePromptInstruction("you are a helpful assistant") {
                t.Error("expected false from OSS stub")
        }
}

func TestCoverageBoostAI_Truncate(t *testing.T) {
        if truncate("hello", 10) != "hello" {
                t.Error("expected no truncation for short string")
        }
        if truncate("hello world", 5) != "hello..." {
                t.Errorf("expected truncation, got %q", truncate("hello world", 5))
        }
}

func TestCoverageBoostAI_ParseRobotsForAI_Stub(t *testing.T) {
        blocked, allowed, directives := parseRobotsForAI("User-agent: GPTBot\nDisallow: /")
        if blocked != nil {
                t.Error("expected nil blocked from OSS stub")
        }
        if allowed != nil {
                t.Error("expected nil allowed from OSS stub")
        }
        if directives != nil {
                t.Error("expected nil directives from OSS stub")
        }
}

func TestCoverageBoostAI_KnownAICrawlers_Stub(t *testing.T) {
        if len(knownAICrawlers) != 0 {
                t.Error("expected empty knownAICrawlers in OSS build")
        }
}

func TestCoverageBoostAI_PrefilledPromptRe_Stub(t *testing.T) {
        if prefilledPromptRe.MatchString("chat.openai.com/chat?prompt=test") {
                t.Error("expected placeholder regex to not match real content")
        }
}

func TestCoverageBoostAI_PromptInjectionRe_Stub(t *testing.T) {
        if promptInjectionRe.MatchString("ignore previous instructions") {
                t.Error("expected placeholder regex to not match real content")
        }
}

func TestCoverageBoostAI_SafeClose_NilBody(t *testing.T) {
        safeClose(io.NopCloser(nil), "test")
}

func TestCoverageBoostAI_AddPoisoningEvidence(t *testing.T) {
        var evidence []Evidence
        iocs := []map[string]any{
                {"detail": "Found prefilled AI prompt link pattern: test"},
        }
        addPoisoningEvidence(&evidence, "https://example.com", iocs)
        if len(evidence) != 1 {
                t.Errorf("expected 1 evidence entry, got %d", len(evidence))
        }
        if evidence[0].Type != "poisoning_ioc" {
                t.Errorf("expected type=poisoning_ioc, got %s", evidence[0].Type)
        }
}

func TestCoverageBoostAI_AddHiddenPromptEvidence(t *testing.T) {
        var evidence []Evidence
        artifacts := []map[string]any{
                {"detail": "Hidden element with prompt keyword detected"},
        }
        addHiddenPromptEvidence(&evidence, "https://example.com", artifacts)
        if len(evidence) != 1 {
                t.Errorf("expected 1 evidence entry, got %d", len(evidence))
        }
        if evidence[0].Severity != "high" {
                t.Errorf("expected severity=high, got %s", evidence[0].Severity)
        }
}

func TestCoverageBoostAI_IsAIDenied(t *testing.T) {
        tests := []struct {
                name   string
                params map[string]string
                want   bool
        }{
                {"ai=no", map[string]string{"ai": "no"}, true},
                {"train-ai=n", map[string]string{"train-ai": "n"}, true},
                {"ai-training=none", map[string]string{"ai-training": "none"}, true},
                {"ai-inference=disallow", map[string]string{"ai-inference": "disallow"}, true},
                {"ai=yes", map[string]string{"ai": "yes"}, false},
                {"empty", map[string]string{}, false},
                {"unrelated", map[string]string{"foo": "no"}, false},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := isAIDenied(tt.params)
                        if got != tt.want {
                                t.Errorf("isAIDenied(%v) = %v, want %v", tt.params, got, tt.want)
                        }
                })
        }
}

func TestCoverageBoostAI_ParseContentUsageTokens(t *testing.T) {
        params := map[string]string{}
        parseContentUsageTokens("ai=no /path train-ai=n", params)
        if params["ai"] != "no" {
                t.Errorf("expected ai=no, got %v", params["ai"])
        }
        if params["train-ai"] != "n" {
                t.Errorf("expected train-ai=n, got %v", params["train-ai"])
        }
        if _, exists := params["/path"]; exists {
                t.Error("expected paths starting with / to be skipped")
        }
}

func TestCoverageBoostAI_HiddenTextSelectors_Stub(t *testing.T) {
        if len(hiddenTextSelectors) != 0 {
                t.Error("expected empty hiddenTextSelectors in OSS build")
        }
}
