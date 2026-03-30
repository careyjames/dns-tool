package ai_surface

import (
	"context"
	"strings"
	"testing"
)

func TestParseLLMSTxtFields_EmptyValue(t *testing.T) {
	content := "Title:\nDescription: hello\n"
	fields := parseLLMSTxtFields(content)
	if _, ok := fields["title"]; ok {
		t.Error("parseLLMSTxtFields should skip keys with empty values")
	}
	if fields["description"] != "hello" {
		t.Errorf("description = %v, want hello", fields["description"])
	}
}

func TestParseLLMSTxtFields_CaseInsensitiveKeys(t *testing.T) {
	content := "TITLE: Upper\nDescription: Mixed\nauthor: lower\n"
	fields := parseLLMSTxtFields(content)
	if fields["title"] != "Upper" {
		t.Errorf("title = %v, want Upper", fields["title"])
	}
	if fields["description"] != "Mixed" {
		t.Errorf("description = %v, want Mixed", fields["description"])
	}
	if fields["author"] != "lower" {
		t.Errorf("author = %v, want lower", fields["author"])
	}
}

func TestParseLLMSTxtFields_ColonInValue(t *testing.T) {
	content := "URL: https://example.com\n"
	fields := parseLLMSTxtFields(content)
	if fields["url"] != "https://example.com" {
		t.Errorf("url = %v, want https://example.com", fields["url"])
	}
}

func TestParseLLMSTxtFields_NoColon(t *testing.T) {
	content := "No colon here\nTitle: Valid\n"
	fields := parseLLMSTxtFields(content)
	if len(fields) != 1 {
		t.Errorf("got %d fields, want 1", len(fields))
	}
}

func TestParseLLMSTxtFields_WhitespaceHandling(t *testing.T) {
	content := "  Title  :  My Site  \n  # comment  \n  \n  Author  :  Test  \n"
	fields := parseLLMSTxtFields(content)
	if fields["title"] != "My Site" {
		t.Errorf("title = %q, want %q", fields["title"], "My Site")
	}
	if fields["author"] != "Test" {
		t.Errorf("author = %q, want %q", fields["author"], "Test")
	}
}

func TestParseLLMSTxtFields_MultipleFields(t *testing.T) {
	content := `# llms.txt
Title: Example Site
Description: An example
Author: John Doe
URL: https://example.com
Version: 1.0
License: MIT
Contact: john@example.com
`
	fields := parseLLMSTxtFields(content)
	if len(fields) != 7 {
		t.Errorf("got %d fields, want 7", len(fields))
	}
}

func TestParseContentUsageDirectives_CaseInsensitive(t *testing.T) {
	content := "CONTENT-USAGE: AI=No\n"
	result := parseContentUsageDirectives(content)
	if result["found"] != true {
		t.Error("should find Content-Usage regardless of case")
	}
	if result["ai_denied"] != true {
		t.Error("should detect AI denial from AI=No")
	}
}

func TestParseContentUsageDirectives_MultipleDirectives(t *testing.T) {
	content := "Content-Usage: ai=no\nContent-Usage: train-ai=disallow\n"
	result := parseContentUsageDirectives(content)
	if result["found"] != true {
		t.Error("should find Content-Usage directives")
	}
	raw, ok := result["raw"].(string)
	if !ok {
		t.Fatal("raw should be a string")
	}
	if !strings.Contains(raw, "ai=no") || !strings.Contains(raw, "train-ai=disallow") {
		t.Errorf("raw = %q, should contain both directives", raw)
	}
}

func TestParseContentUsageDirectives_AllDenyValues(t *testing.T) {
	denyValues := []string{"n", "no", "none", "disallow"}
	denyKeys := []string{"ai", "train-ai", "ai-training", "ai-inference"}

	for _, key := range denyKeys {
		for _, val := range denyValues {
			t.Run(key+"_"+val, func(t *testing.T) {
				content := "Content-Usage: " + key + "=" + val + "\n"
				result := parseContentUsageDirectives(content)
				if result["ai_denied"] != true {
					t.Errorf("expected ai_denied=true for %s=%s", key, val)
				}
			})
		}
	}
}

func TestParseContentUsageDirectives_AllowedValues(t *testing.T) {
	tests := []string{"ai=yes", "ai=allow", "train-ai=yes", "ai-training=permit"}
	for _, directive := range tests {
		t.Run(directive, func(t *testing.T) {
			content := "Content-Usage: " + directive + "\n"
			result := parseContentUsageDirectives(content)
			if result["ai_denied"] != false {
				t.Errorf("expected ai_denied=false for %s", directive)
			}
		})
	}
}

func TestParseContentUsageDirectives_PathSkipped(t *testing.T) {
	content := "Content-Usage: /images ai=no\n"
	result := parseContentUsageDirectives(content)
	params, _ := result["parameters"].(map[string]string)
	if _, ok := params["/images"]; ok {
		t.Error("path tokens starting with / should be skipped")
	}
	if params["ai"] != "no" {
		t.Errorf("ai param = %q, want no", params["ai"])
	}
}

func TestParseContentUsageDirectives_EmptyDirectiveValue(t *testing.T) {
	content := "Content-Usage:\n"
	result := parseContentUsageDirectives(content)
	if result["found"] != false {
		t.Error("empty Content-Usage value should not count as found")
	}
}

func TestParseContentUsageDirectives_OnlyComments(t *testing.T) {
	content := "# Content-Usage: ai=no\n"
	result := parseContentUsageDirectives(content)
	if result["found"] != false {
		t.Error("commented Content-Usage should not be found")
	}
}

func TestParseRobotsTxtForAI_Empty(t *testing.T) {
	blocked, allowed, directives := parseRobotsTxtForAI("")
	if len(blocked) != 0 {
		t.Errorf("blocked = %v, want empty", blocked)
	}
	if len(allowed) != 0 {
		t.Errorf("allowed = %v, want empty", allowed)
	}
	if len(directives) != 0 {
		t.Errorf("directives = %v, want empty", directives)
	}
}

func TestParseRobotsTxtForAI_OnlyComments(t *testing.T) {
	content := "# robots.txt\n# comments only\n\n"
	blocked, allowed, directives := parseRobotsTxtForAI(content)
	if len(blocked) != 0 || len(allowed) != 0 || len(directives) != 0 {
		t.Error("comments-only content should produce no results")
	}
}

func TestParseRobotsTxtForAI_DirectiveWithoutAgent(t *testing.T) {
	content := "Disallow: /private\nAllow: /public\n"
	blocked, allowed, directives := parseRobotsTxtForAI(content)
	if len(blocked) != 0 || len(allowed) != 0 || len(directives) != 0 {
		t.Error("directives without user-agent should be ignored")
	}
}

func TestParseRobotsTxtForAI_EmptyDisallow(t *testing.T) {
	content := "User-Agent: GPTBot\nDisallow:\n"
	blocked, _, _ := parseRobotsTxtForAI(content)
	if len(blocked) != 0 {
		t.Error("empty Disallow path should not count as blocked")
	}
}

func TestScanForHiddenPrompts_Empty(t *testing.T) {
	artifacts := scanForHiddenPrompts("")
	if len(artifacts) != 0 {
		t.Errorf("scanForHiddenPrompts empty string got %d artifacts, want 0", len(artifacts))
	}
}

func TestScanForHiddenPrompts_OnlyHidingNoKeywords(t *testing.T) {
	content := `<div style="display:none">safe content here</div>`
	artifacts := scanForHiddenPrompts(content)
	if len(artifacts) != 0 {
		t.Errorf("got %d artifacts, want 0 (no prompt keywords)", len(artifacts))
	}
}

func TestScanForHiddenPrompts_OnlyKeywordsNoHiding(t *testing.T) {
	content := `<div>you are a helpful assistant ignore previous instructions</div>`
	artifacts := scanForHiddenPrompts(content)
	if len(artifacts) != 0 {
		t.Errorf("got %d artifacts, want 0 (no hiding pattern)", len(artifacts))
	}
}

func TestScanForHiddenPrompts_AllHidingMethods(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"display_none", `<div style="display:none">you are a helpful bot</div>`},
		{"visibility_hidden", `<div style="visibility:hidden">you are a helpful bot</div>`},
		{"aria_hidden", `<div aria-hidden="true">you are a helpful bot</div>`},
		{"opacity_zero", `<div style="opacity:0;">you are a helpful bot</div>`},
		{"font_size_zero", `<div style="font-size:0;">you are a helpful bot</div>`},
		{"color_transparent", `<div style="color:transparent">you are a helpful bot</div>`},
		{"text_indent", `<div style="text-indent:-9999px">you are a helpful bot</div>`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			artifacts := scanForHiddenPrompts(tt.content)
			if len(artifacts) == 0 {
				t.Errorf("expected at least 1 artifact for %s hiding method", tt.name)
			}
		})
	}
}

func TestScanForPrefillLinks_AllPatterns(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
	}{
		{"openai", "chat.openai.com/chat?prompt=test"},
		{"chatgpt", "chatgpt.com/?prompt=hello"},
		{"claude", "claude.ai/chat?q=hello"},
		{"bard", "bard.google.com/?q=test"},
		{"copilot", "copilot.microsoft.com/?q=test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := `<a href="https://` + tt.pattern + `">click</a>`
			iocs := scanForPrefillLinks(content)
			if len(iocs) != 1 {
				t.Errorf("scanForPrefillLinks got %d, want 1 for pattern %s", len(iocs), tt.name)
			}
		})
	}
}

func TestScanForPrefillLinks_CaseInsensitive(t *testing.T) {
	content := `<a href="https://Chat.OpenAI.Com/Chat?Prompt=test">click</a>`
	iocs := scanForPrefillLinks(content)
	if len(iocs) != 1 {
		t.Errorf("case insensitive match got %d, want 1", len(iocs))
	}
}

func TestScanForPrefillLinks_Empty(t *testing.T) {
	iocs := scanForPrefillLinks("")
	if len(iocs) != 0 {
		t.Errorf("empty content got %d, want 0", len(iocs))
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		maxLen int
		want   string
	}{
		{"short_string", "hello", 10, "hello"},
		{"exact_length", "hello", 5, "hello"},
		{"truncated", "hello world", 5, "hello..."},
		{"empty", "", 5, ""},
		{"zero_max", "hello", 0, "..."},
		{"one_char", "hello", 1, "h..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncate(tt.input, tt.maxLen)
			if got != tt.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
			}
		})
	}
}

func TestOSSStubs_SafeDefaults(t *testing.T) {
	t.Run("looksLikeLLMSTxt", func(t *testing.T) {
		if looksLikeLLMSTxt("anything") {
			t.Error("OSS stub should return false")
		}
		if looksLikeLLMSTxt("") {
			t.Error("OSS stub should return false for empty")
		}
	})

	t.Run("parseLLMSTxt", func(t *testing.T) {
		result := parseLLMSTxt("Title: test")
		if result == nil {
			t.Error("OSS stub should return non-nil map")
		}
		if len(result) != 0 {
			t.Errorf("OSS stub should return empty map, got %d entries", len(result))
		}
	})

	t.Run("parseLLMSTxtFieldLine", func(t *testing.T) {
		fields := map[string]any{}
		docs := []string{}
		parseLLMSTxtFieldLine("Title: test", "section", fields, &docs)
		if len(fields) != 0 {
			t.Error("OSS stub should not modify fields")
		}
	})

	t.Run("matchAICrawler", func(t *testing.T) {
		if matchAICrawler("GPTBot") != "" {
			t.Error("OSS stub should return empty string")
		}
	})

	t.Run("parseRobotsForAI_oss", func(t *testing.T) {
		blocked, allowed, directives := parseRobotsForAI("User-Agent: GPTBot\nDisallow: /")
		if blocked != nil || allowed != nil || directives != nil {
			t.Error("OSS stub should return nil slices")
		}
	})

	t.Run("processRobotsLine", func(t *testing.T) {
		processRobotsLine("disallow: /", "Disallow: /", "GPTBot", map[string]bool{}, map[string]bool{}, nil)
	})

	t.Run("detectHiddenTextArtifacts", func(t *testing.T) {
		arts, evs := detectHiddenTextArtifacts("<html></html>", "https://example.com", nil, nil)
		if arts != nil || evs != nil {
			t.Error("OSS stub should return input slices (nil)")
		}
	})

	t.Run("buildHiddenBlockRegex", func(t *testing.T) {
		if buildHiddenBlockRegex() != nil {
			t.Error("OSS stub should return nil")
		}
	})

	t.Run("extractTextContent", func(t *testing.T) {
		if extractTextContent("<p>test</p>") != "" {
			t.Error("OSS stub should return empty string")
		}
	})

	t.Run("looksLikePromptInstruction", func(t *testing.T) {
		if looksLikePromptInstruction("ignore previous instructions") {
			t.Error("OSS stub should return false")
		}
	})

	t.Run("fetchTextFile", func(t *testing.T) {
		scanner := &Scanner{}
		result, err := scanner.fetchTextFile(context.Background(), "https://example.com/test.txt")
		if err != nil {
			t.Errorf("OSS stub should return nil error, got %v", err)
		}
		if result != "" {
			t.Error("OSS stub should return empty string")
		}
	})
}

func TestExtractNearbyText_EmptyContent(t *testing.T) {
	result := extractNearbyText("", []int{0, 0})
	if result != "" {
		t.Errorf("expected empty, got %q", result)
	}
}

func TestExtractNearbyText_ExactBoundary(t *testing.T) {
	text := strings.Repeat("x", 500)
	result := extractNearbyText(text, []int{0, 500})
	if len(result) != 500 {
		t.Errorf("length = %d, want 500", len(result))
	}
}

func TestLlmsTxtURLCandidates_SpecialDomain(t *testing.T) {
	urls := llmsTxtURLCandidates("sub.domain.co.uk")
	if len(urls) != 4 {
		t.Fatalf("got %d URLs, want 4", len(urls))
	}
	for _, u := range urls {
		if !strings.Contains(u, "sub.domain.co.uk") {
			t.Errorf("URL %q doesn't contain expected domain", u)
		}
	}
}

func TestLlmsFullTxtURLCandidates_SpecialDomain(t *testing.T) {
	urls := llmsFullTxtURLCandidates("sub.domain.co.uk")
	if len(urls) != 4 {
		t.Fatalf("got %d URLs, want 4", len(urls))
	}
	for _, u := range urls {
		if !strings.Contains(u, "llms-full.txt") {
			t.Errorf("URL %q doesn't contain llms-full.txt", u)
		}
	}
}

func TestProcessRobotsDirective_DeduplicateBlocked(t *testing.T) {
	state := &robotsParseState{
		currentAgents: []string{"GPTBot"},
		blockedSet:    map[string]bool{"GPTBot": true},
		allowedSet:    map[string]bool{},
		blocked:       []string{"GPTBot"},
	}
	processRobotsDirective("Disallow: /", "disallow: /", state)
	if len(state.blocked) != 1 {
		t.Errorf("blocked = %v, should not duplicate already-blocked agent", state.blocked)
	}
	if len(state.directives) != 0 {
		t.Errorf("directives = %v, should not add duplicate directive", state.directives)
	}
}

func TestProcessRobotsDirective_DeduplicateAllowed(t *testing.T) {
	state := &robotsParseState{
		currentAgents: []string{"CCBot"},
		blockedSet:    map[string]bool{},
		allowedSet:    map[string]bool{"CCBot": true},
		allowed:       []string{"CCBot"},
	}
	processRobotsDirective("Allow: /public", "allow: /public", state)
	if len(state.allowed) != 1 {
		t.Errorf("allowed = %v, should not duplicate already-allowed agent", state.allowed)
	}
}

func TestProcessRobotsDirective_EmptyDisallowPath(t *testing.T) {
	state := &robotsParseState{
		currentAgents: []string{"GPTBot"},
		blockedSet:    map[string]bool{},
		allowedSet:    map[string]bool{},
	}
	processRobotsDirective("Disallow:", "disallow:", state)
	if len(state.blocked) != 0 {
		t.Errorf("empty disallow path should not block, got %v", state.blocked)
	}
}

func TestProcessRobotsDirective_EmptyAllowPath(t *testing.T) {
	state := &robotsParseState{
		currentAgents: []string{"CCBot"},
		blockedSet:    map[string]bool{},
		allowedSet:    map[string]bool{},
	}
	processRobotsDirective("Allow:", "allow:", state)
	if len(state.allowed) != 0 {
		t.Errorf("empty allow path should not add agent, got %v", state.allowed)
	}
}

func TestProcessRobotsDirective_UnrelatedDirective(t *testing.T) {
	state := &robotsParseState{
		currentAgents: []string{"GPTBot"},
		blockedSet:    map[string]bool{},
		allowedSet:    map[string]bool{},
	}
	processRobotsDirective(
		"Sitemap: https://example.com/sitemap.xml", "sitemap: https://example.com/sitemap.xml", state,
	)
	if len(state.blocked) != 0 || len(state.allowed) != 0 || len(state.directives) != 0 {
		t.Error("unrelated directive should produce no results")
	}
}

func TestProcessRobotsDirective_MultipleAgents(t *testing.T) {
	state := &robotsParseState{
		currentAgents: []string{"GPTBot", "CCBot"},
		blockedSet:    map[string]bool{},
		allowedSet:    map[string]bool{},
	}
	processRobotsDirective("Disallow: /", "disallow: /", state)
	if len(state.blocked) != 2 {
		t.Errorf("blocked = %v, want 2 agents", state.blocked)
	}
	if len(state.directives) != 2 {
		t.Errorf("directives = %v, want 2 entries", state.directives)
	}
}

func TestBuildSummary_AllFieldsPresent(t *testing.T) {
	results := map[string]any{
		"llms_txt":       map[string]any{"found": false},
		"robots_txt":     map[string]any{"blocks_ai_crawlers": false, "allows_ai_crawlers": false, "content_usage": map[string]any{"found": false}},
		"poisoning":      map[string]any{"ioc_count": 0},
		"hidden_prompts": map[string]any{"artifact_count": 0},
	}
	summary := buildSummary(results, []Evidence{})

	requiredKeys := []string{"status", "message", "has_llms_txt", "blocks_ai", "allows_ai", "has_content_usage", "poisoning_count", "hidden_count", "total_evidence"}
	for _, key := range requiredKeys {
		if _, ok := summary[key]; !ok {
			t.Errorf("summary missing key %q", key)
		}
	}
}

func TestBuildSummary_WarningTakesPriorityOverSuccess(t *testing.T) {
	results := map[string]any{
		"llms_txt":       map[string]any{"found": true},
		"robots_txt":     map[string]any{"blocks_ai_crawlers": true, "allows_ai_crawlers": false, "content_usage": map[string]any{"found": true}},
		"poisoning":      map[string]any{"ioc_count": 1},
		"hidden_prompts": map[string]any{"artifact_count": 0},
	}
	summary := buildSummary(results, []Evidence{})
	if summary["status"] != "warning" {
		t.Errorf("status = %v, want warning (should take priority over success)", summary["status"])
	}
}

func TestBuildSummary_ContentUsageNoType(t *testing.T) {
	results := map[string]any{
		"llms_txt":       map[string]any{"found": false},
		"robots_txt":     map[string]any{"blocks_ai_crawlers": false, "allows_ai_crawlers": false, "content_usage": "not a map"},
		"poisoning":      map[string]any{"ioc_count": 0},
		"hidden_prompts": map[string]any{"artifact_count": 0},
	}
	summary := buildSummary(results, []Evidence{})
	if summary["has_content_usage"] != false {
		t.Error("should handle non-map content_usage gracefully")
	}
}

func TestConvertEvidenceSlice_PreservesOrder(t *testing.T) {
	evidence := []Evidence{
		{Type: "a", Source: "s1", Detail: "d1", Severity: "info", Confidence: "Observed"},
		{Type: "b", Source: "s2", Detail: "d2", Severity: "high", Confidence: "Inferred"},
		{Type: "c", Source: "s3", Detail: "d3", Severity: "low", Confidence: "Derived"},
	}
	result := convertEvidenceSlice(evidence)
	if len(result) != 3 {
		t.Fatalf("got %d items, want 3", len(result))
	}
	for i, e := range evidence {
		if result[i]["type"] != e.Type {
			t.Errorf("result[%d][type] = %v, want %v", i, result[i]["type"], e.Type)
		}
	}
}

func TestNewScanner_WithNilHTTP(t *testing.T) {
	s := NewScanner(nil)
	if s == nil {
		t.Fatal("NewScanner returned nil")
	}
	if s.HTTP != nil {
		t.Error("HTTP should be nil")
	}
}

func TestAddCrawlerEvidence_MultipleBlocked(t *testing.T) {
	var evidence []Evidence
	addCrawlerEvidence(&evidence, "https://example.com/robots.txt", []string{"GPTBot", "CCBot", "ClaudeBot"})
	if len(evidence) != 1 {
		t.Fatalf("got %d evidence items, want 1", len(evidence))
	}
	if !strings.Contains(evidence[0].Detail, "3") {
		t.Errorf("detail should mention 3 crawlers, got %q", evidence[0].Detail)
	}
	if !strings.Contains(evidence[0].Detail, "GPTBot") {
		t.Errorf("detail should list crawler names, got %q", evidence[0].Detail)
	}
}

func TestAddContentUsageEvidence_InvalidFoundType(t *testing.T) {
	var evidence []Evidence
	contentUsage := map[string]any{"found": "not a bool"}
	addContentUsageEvidence(&evidence, "https://example.com/robots.txt", contentUsage)
	if len(evidence) != 0 {
		t.Error("invalid found type should not add evidence")
	}
}

func TestConvertEvidenceToMaps_NoOp(t *testing.T) {
	result := map[string]any{"key": "value"}
	convertEvidenceToMaps(result)
	if result["key"] != "value" {
		t.Error("convertEvidenceToMaps should not modify the map")
	}
}

func TestOSSStub_ProcessRobotsLine(t *testing.T) {
	seenBlocked := map[string]bool{}
	seenAllowed := map[string]bool{}
	processRobotsLine("disallow: /", "Disallow: /", "GPTBot", seenBlocked, seenAllowed, nil)
	if len(seenBlocked) != 0 {
		t.Error("OSS stub processRobotsLine should not modify seenBlocked")
	}
	if len(seenAllowed) != 0 {
		t.Error("OSS stub processRobotsLine should not modify seenAllowed")
	}
}

func TestOSSStub_ParseLLMSTxtFieldLine(t *testing.T) {
	fields := map[string]any{}
	docs := []string{}
	parseLLMSTxtFieldLine("Title: test", "section", fields, &docs)
	if len(fields) != 0 {
		t.Error("OSS stub should not modify fields")
	}
	if len(docs) != 0 {
		t.Error("OSS stub should not modify docs")
	}
}
