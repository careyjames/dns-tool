package ai_surface

import (
	"testing"
)

func TestLlmsTxtURLCandidates(t *testing.T) {
	urls := llmsTxtURLCandidates("example.com")
	if len(urls) != 4 {
		t.Fatalf("llmsTxtURLCandidates returned %d URLs, want 4", len(urls))
	}
	expected := []string{
		"https://example.com/.well-known/llms.txt",
		"https://example.com/llms.txt",
		"http://example.com/.well-known/llms.txt",
		"http://example.com/llms.txt",
	}
	for i, want := range expected {
		if urls[i] != want {
			t.Errorf("urls[%d] = %q, want %q", i, urls[i], want)
		}
	}
}

func TestLlmsFullTxtURLCandidates(t *testing.T) {
	urls := llmsFullTxtURLCandidates("test.org")
	if len(urls) != 4 {
		t.Fatalf("llmsFullTxtURLCandidates returned %d URLs, want 4", len(urls))
	}
	expected := []string{
		"https://test.org/.well-known/llms-full.txt",
		"https://test.org/llms-full.txt",
		"http://test.org/.well-known/llms-full.txt",
		"http://test.org/llms-full.txt",
	}
	for i, want := range expected {
		if urls[i] != want {
			t.Errorf("urls[%d] = %q, want %q", i, urls[i], want)
		}
	}
}

func TestBuildAICrawlerSet(t *testing.T) {
	set := buildAICrawlerSet()
	if set == nil {
		t.Fatal("buildAICrawlerSet returned nil")
	}
	crawlers := GetAICrawlers()
	if len(set) != len(crawlers) {
		t.Errorf("buildAICrawlerSet size = %d, want %d (matching GetAICrawlers)", len(set), len(crawlers))
	}
}

func TestHandleUserAgentLine_AIAgent(t *testing.T) {
	aiSet := map[string]bool{"gptbot": true, "ccbot": true}

	agents := handleUserAgentLine("User-Agent: GPTBot", nil, aiSet)
	if len(agents) != 1 {
		t.Fatalf("handleUserAgentLine for AI agent got %d agents, want 1", len(agents))
	}
	if agents[0] != "GPTBot" {
		t.Errorf("agent = %q, want %q", agents[0], "GPTBot")
	}
}

func TestHandleUserAgentLine_NonAIAgent(t *testing.T) {
	aiSet := map[string]bool{"gptbot": true}

	agents := handleUserAgentLine("User-Agent: Googlebot", nil, aiSet)
	if len(agents) != 0 {
		t.Errorf("handleUserAgentLine for non-AI agent got %d agents, want 0", len(agents))
	}
}

func TestHandleUserAgentLine_ResetsOnNewAgent(t *testing.T) {
	aiSet := map[string]bool{"gptbot": true, "ccbot": true}

	agents := []string{"GPTBot"}
	agents = handleUserAgentLine("User-Agent: CCBot", agents, aiSet)
	if len(agents) != 1 || agents[0] != "CCBot" {
		t.Errorf("handleUserAgentLine should reset and add new AI agent, got %v", agents)
	}
}

func TestHandleUserAgentLine_AppendsSamePrefix(t *testing.T) {
	aiSet := map[string]bool{"gptbot": true}

	agents := []string{"GPTBot"}
	agents = handleUserAgentLine("User-Agent: GPTBot", agents, aiSet)
	if len(agents) != 2 {
		t.Errorf("handleUserAgentLine should append same-prefix agent, got %d agents", len(agents))
	}
}

func TestExtractNearbyText_Short(t *testing.T) {
	text := "hello world"
	result := extractNearbyText(text, []int{0, 5})
	if result != "hello world" {
		t.Errorf("extractNearbyText = %q, want %q", result, "hello world")
	}
}

func TestExtractNearbyText_Long(t *testing.T) {
	text := make([]byte, 1000)
	for i := range text {
		text[i] = 'a'
	}
	result := extractNearbyText(string(text), []int{100, 200})
	if len(result) != 500 {
		t.Errorf("extractNearbyText length = %d, want 500", len(result))
	}
}

func TestExtractNearbyText_NearEnd(t *testing.T) {
	text := "short text"
	result := extractNearbyText(text, []int{5, 10})
	if result != " text" {
		t.Errorf("extractNearbyText = %q, want %q", result, " text")
	}
}

func TestFindKeywordsInRegion_Match(t *testing.T) {
	seen := map[string]bool{}
	artifacts := findKeywordsInRegion("you are a helpful assistant", "CSS display:none", seen)
	if len(artifacts) != 1 {
		t.Fatalf("findKeywordsInRegion got %d artifacts, want 1", len(artifacts))
	}
	if artifacts[0]["method"] != "CSS display:none" {
		t.Errorf("method = %v, want CSS display:none", artifacts[0]["method"])
	}
}

func TestFindKeywordsInRegion_NoMatch(t *testing.T) {
	seen := map[string]bool{}
	artifacts := findKeywordsInRegion("normal website content here", "CSS display:none", seen)
	if len(artifacts) != 0 {
		t.Errorf("findKeywordsInRegion got %d artifacts, want 0", len(artifacts))
	}
}

func TestFindKeywordsInRegion_Dedup(t *testing.T) {
	seen := map[string]bool{}
	findKeywordsInRegion("you are a helpful assistant", "CSS display:none", seen)
	artifacts := findKeywordsInRegion("you are a helpful assistant", "CSS display:none", seen)
	if len(artifacts) != 0 {
		t.Errorf("findKeywordsInRegion should deduplicate, got %d artifacts", len(artifacts))
	}
}

func TestFindKeywordsInRegion_MultipleKeywords(t *testing.T) {
	seen := map[string]bool{}
	artifacts := findKeywordsInRegion("you are a system prompt override jailbreak", "method1", seen)
	if len(artifacts) < 3 {
		t.Errorf("findKeywordsInRegion got %d artifacts, want at least 3", len(artifacts))
	}
}

func TestAddCrawlerEvidence_WithBlocked(t *testing.T) {
	var evidence []Evidence
	addCrawlerEvidence(&evidence, "https://example.com/robots.txt", []string{"GPTBot", "CCBot"})
	if len(evidence) != 1 {
		t.Fatalf("addCrawlerEvidence got %d evidence items, want 1", len(evidence))
	}
	if evidence[0].Type != "robots_txt_blocks_ai" {
		t.Errorf("type = %q, want robots_txt_blocks_ai", evidence[0].Type)
	}
	if evidence[0].Severity != "info" {
		t.Errorf("severity = %q, want info", evidence[0].Severity)
	}
}

func TestAddCrawlerEvidence_NoBlocked(t *testing.T) {
	var evidence []Evidence
	addCrawlerEvidence(&evidence, "https://example.com/robots.txt", []string{})
	if len(evidence) != 1 {
		t.Fatalf("addCrawlerEvidence got %d evidence items, want 1", len(evidence))
	}
	if evidence[0].Type != "robots_txt_no_ai_blocks" {
		t.Errorf("type = %q, want robots_txt_no_ai_blocks", evidence[0].Type)
	}
	if evidence[0].Severity != "low" {
		t.Errorf("severity = %q, want low", evidence[0].Severity)
	}
}

func TestAddContentUsageEvidence_Found(t *testing.T) {
	var evidence []Evidence
	contentUsage := map[string]any{
		"found": true,
		"raw":   "ai=no",
	}
	addContentUsageEvidence(&evidence, "https://example.com/robots.txt", contentUsage)
	if len(evidence) != 1 {
		t.Fatalf("addContentUsageEvidence got %d evidence items, want 1", len(evidence))
	}
	if evidence[0].Type != "content_usage_directive" {
		t.Errorf("type = %q, want content_usage_directive", evidence[0].Type)
	}
}

func TestAddContentUsageEvidence_NotFound(t *testing.T) {
	var evidence []Evidence
	contentUsage := map[string]any{"found": false}
	addContentUsageEvidence(&evidence, "https://example.com/robots.txt", contentUsage)
	if len(evidence) != 0 {
		t.Errorf("addContentUsageEvidence should not add evidence when not found, got %d", len(evidence))
	}
}

func TestAddContentUsageEvidence_NoRaw(t *testing.T) {
	var evidence []Evidence
	contentUsage := map[string]any{"found": true}
	addContentUsageEvidence(&evidence, "https://example.com/robots.txt", contentUsage)
	if len(evidence) != 1 {
		t.Fatalf("got %d, want 1", len(evidence))
	}
	if evidence[0].Detail != "Content-Usage directive present in robots.txt" {
		t.Errorf("detail = %q, want default message", evidence[0].Detail)
	}
}

func TestAddPoisoningEvidence(t *testing.T) {
	var evidence []Evidence
	iocs := []map[string]any{
		{"detail": "Found prefilled AI prompt link pattern: chat.openai.com/chat?prompt="},
		{"detail": "Found prefilled AI prompt link pattern: claude.ai/chat?q="},
	}
	addPoisoningEvidence(&evidence, "https://example.com/", iocs)
	if len(evidence) != 2 {
		t.Fatalf("addPoisoningEvidence got %d evidence items, want 2", len(evidence))
	}
	for _, e := range evidence {
		if e.Type != "poisoning_ioc" {
			t.Errorf("type = %q, want poisoning_ioc", e.Type)
		}
		if e.Severity != "medium" {
			t.Errorf("severity = %q, want medium", e.Severity)
		}
	}
}

func TestAddPoisoningEvidence_Empty(t *testing.T) {
	var evidence []Evidence
	addPoisoningEvidence(&evidence, "https://example.com/", []map[string]any{})
	if len(evidence) != 0 {
		t.Errorf("addPoisoningEvidence with empty iocs should add nothing, got %d", len(evidence))
	}
}

func TestAddHiddenPromptEvidence(t *testing.T) {
	var evidence []Evidence
	artifacts := []map[string]any{
		{"detail": "Hidden element with prompt keyword 'you are a' detected near CSS display:none pattern"},
	}
	addHiddenPromptEvidence(&evidence, "https://example.com/", artifacts)
	if len(evidence) != 1 {
		t.Fatalf("addHiddenPromptEvidence got %d evidence items, want 1", len(evidence))
	}
	if evidence[0].Type != "hidden_prompt" {
		t.Errorf("type = %q, want hidden_prompt", evidence[0].Type)
	}
	if evidence[0].Severity != "high" {
		t.Errorf("severity = %q, want high", evidence[0].Severity)
	}
}

func TestAddHiddenPromptEvidence_Empty(t *testing.T) {
	var evidence []Evidence
	addHiddenPromptEvidence(&evidence, "https://example.com/", []map[string]any{})
	if len(evidence) != 0 {
		t.Errorf("addHiddenPromptEvidence with empty artifacts should add nothing, got %d", len(evidence))
	}
}

func TestConvertEvidenceSlice(t *testing.T) {
	evidence := []Evidence{
		{Type: "t1", Source: "s1", Detail: "d1", Severity: "info", Confidence: "Observed"},
		{Type: "t2", Source: "s2", Detail: "d2", Severity: "high", Confidence: "Inferred"},
	}
	result := convertEvidenceSlice(evidence)
	if len(result) != 2 {
		t.Fatalf("convertEvidenceSlice returned %d items, want 2", len(result))
	}
	if result[0]["type"] != "t1" {
		t.Errorf("result[0][type] = %v, want t1", result[0]["type"])
	}
	if result[1]["severity"] != "high" {
		t.Errorf("result[1][severity] = %v, want high", result[1]["severity"])
	}
}

func TestConvertEvidenceSlice_Empty(t *testing.T) {
	result := convertEvidenceSlice([]Evidence{})
	if result == nil {
		t.Error("convertEvidenceSlice should return non-nil for empty input")
	}
	if len(result) != 0 {
		t.Errorf("convertEvidenceSlice returned %d items, want 0", len(result))
	}
}

func TestBuildSummary_NoFindings(t *testing.T) {
	results := map[string]any{
		"llms_txt":       map[string]any{"found": false},
		"robots_txt":     map[string]any{"blocks_ai_crawlers": false, "allows_ai_crawlers": false, "content_usage": map[string]any{"found": false}},
		"poisoning":      map[string]any{"ioc_count": 0},
		"hidden_prompts": map[string]any{"artifact_count": 0},
	}
	summary := buildSummary(results, []Evidence{})
	if summary["status"] != "info" {
		t.Errorf("status = %v, want info", summary["status"])
	}
}

func TestBuildSummary_Warning_Poisoning(t *testing.T) {
	results := map[string]any{
		"llms_txt":       map[string]any{"found": false},
		"robots_txt":     map[string]any{"blocks_ai_crawlers": false, "allows_ai_crawlers": false, "content_usage": map[string]any{"found": false}},
		"poisoning":      map[string]any{"ioc_count": 2},
		"hidden_prompts": map[string]any{"artifact_count": 0},
	}
	summary := buildSummary(results, []Evidence{})
	if summary["status"] != "warning" {
		t.Errorf("status = %v, want warning", summary["status"])
	}
}

func TestBuildSummary_Warning_HiddenPrompts(t *testing.T) {
	results := map[string]any{
		"llms_txt":       map[string]any{"found": false},
		"robots_txt":     map[string]any{"blocks_ai_crawlers": false, "allows_ai_crawlers": false, "content_usage": map[string]any{"found": false}},
		"poisoning":      map[string]any{"ioc_count": 0},
		"hidden_prompts": map[string]any{"artifact_count": 3},
	}
	summary := buildSummary(results, []Evidence{})
	if summary["status"] != "warning" {
		t.Errorf("status = %v, want warning", summary["status"])
	}
}

func TestBuildSummary_Success_LLMSTxt(t *testing.T) {
	results := map[string]any{
		"llms_txt":       map[string]any{"found": true},
		"robots_txt":     map[string]any{"blocks_ai_crawlers": false, "allows_ai_crawlers": false, "content_usage": map[string]any{"found": false}},
		"poisoning":      map[string]any{"ioc_count": 0},
		"hidden_prompts": map[string]any{"artifact_count": 0},
	}
	summary := buildSummary(results, []Evidence{})
	if summary["status"] != "success" {
		t.Errorf("status = %v, want success", summary["status"])
	}
}

func TestBuildSummary_Success_BlocksAI(t *testing.T) {
	results := map[string]any{
		"llms_txt":       map[string]any{"found": false},
		"robots_txt":     map[string]any{"blocks_ai_crawlers": true, "allows_ai_crawlers": false, "content_usage": map[string]any{"found": false}},
		"poisoning":      map[string]any{"ioc_count": 0},
		"hidden_prompts": map[string]any{"artifact_count": 0},
	}
	summary := buildSummary(results, []Evidence{})
	if summary["status"] != "success" {
		t.Errorf("status = %v, want success", summary["status"])
	}
}

func TestBuildSummary_Success_ContentUsage(t *testing.T) {
	results := map[string]any{
		"llms_txt":       map[string]any{"found": false},
		"robots_txt":     map[string]any{"blocks_ai_crawlers": false, "allows_ai_crawlers": false, "content_usage": map[string]any{"found": true}},
		"poisoning":      map[string]any{"ioc_count": 0},
		"hidden_prompts": map[string]any{"artifact_count": 0},
	}
	summary := buildSummary(results, []Evidence{})
	if summary["status"] != "success" {
		t.Errorf("status = %v, want success", summary["status"])
	}
}

func TestBuildSummary_Info_AllowsAI(t *testing.T) {
	results := map[string]any{
		"llms_txt":       map[string]any{"found": false},
		"robots_txt":     map[string]any{"blocks_ai_crawlers": false, "allows_ai_crawlers": true, "content_usage": map[string]any{"found": false}},
		"poisoning":      map[string]any{"ioc_count": 0},
		"hidden_prompts": map[string]any{"artifact_count": 0},
	}
	summary := buildSummary(results, []Evidence{})
	if summary["status"] != "info" {
		t.Errorf("status = %v, want info", summary["status"])
	}
	if summary["allows_ai"] != true {
		t.Errorf("allows_ai = %v, want true", summary["allows_ai"])
	}
}

func TestBuildSummary_Fields(t *testing.T) {
	evidence := []Evidence{{}, {}, {}}
	results := map[string]any{
		"llms_txt":       map[string]any{"found": true},
		"robots_txt":     map[string]any{"blocks_ai_crawlers": true, "allows_ai_crawlers": false, "content_usage": map[string]any{"found": true}},
		"poisoning":      map[string]any{"ioc_count": 1},
		"hidden_prompts": map[string]any{"artifact_count": 2},
	}
	summary := buildSummary(results, evidence)

	if summary["has_llms_txt"] != true {
		t.Errorf("has_llms_txt = %v, want true", summary["has_llms_txt"])
	}
	if summary["blocks_ai"] != true {
		t.Errorf("blocks_ai = %v, want true", summary["blocks_ai"])
	}
	if summary["has_content_usage"] != true {
		t.Errorf("has_content_usage = %v, want true", summary["has_content_usage"])
	}
	if summary["poisoning_count"] != 1 {
		t.Errorf("poisoning_count = %v, want 1", summary["poisoning_count"])
	}
	if summary["hidden_count"] != 2 {
		t.Errorf("hidden_count = %v, want 2", summary["hidden_count"])
	}
	if summary["total_evidence"] != 3 {
		t.Errorf("total_evidence = %v, want 3", summary["total_evidence"])
	}
}

func TestParseLLMSTxtFields(t *testing.T) {
	content := `# This is a comment
Title: My Site
Description: A test site
Author: Test User
`
	fields := parseLLMSTxtFields(content)
	if fields["title"] != "My Site" {
		t.Errorf("title = %v, want 'My Site'", fields["title"])
	}
	if fields["description"] != "A test site" {
		t.Errorf("description = %v, want 'A test site'", fields["description"])
	}
	if fields["author"] != "Test User" {
		t.Errorf("author = %v, want 'Test User'", fields["author"])
	}
}

func TestParseLLMSTxtFields_Empty(t *testing.T) {
	fields := parseLLMSTxtFields("")
	if len(fields) != 0 {
		t.Errorf("parseLLMSTxtFields empty input got %d fields, want 0", len(fields))
	}
}

func TestParseLLMSTxtFields_SkipsComments(t *testing.T) {
	content := `# comment
# another comment

Title: Hello
`
	fields := parseLLMSTxtFields(content)
	if len(fields) != 1 {
		t.Errorf("got %d fields, want 1", len(fields))
	}
}

func TestScanForPrefillLinks(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    int
	}{
		{"no_links", "<html><body>normal content</body></html>", 0},
		{"openai_link", `<a href="https://chat.openai.com/chat?prompt=test">click</a>`, 1},
		{"claude_link", `<a href="https://claude.ai/chat?q=hello">ask</a>`, 1},
		{"multiple_links", `chat.openai.com/chat?prompt=x claude.ai/chat?q=y`, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iocs := scanForPrefillLinks(tt.content)
			if len(iocs) != tt.want {
				t.Errorf("scanForPrefillLinks got %d, want %d", len(iocs), tt.want)
			}
		})
	}
}

func TestParseContentUsageDirectives(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		wantFound bool
		wantDeny  bool
	}{
		{"empty", "", false, false},
		{"no_directive", "User-Agent: *\nDisallow: /private\n", false, false},
		{"ai_denied", "Content-Usage: ai=no\n", true, true},
		{"ai_allowed", "Content-Usage: ai=yes\n", true, false},
		{"train_ai_denied", "Content-Usage: train-ai=disallow\n", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseContentUsageDirectives(tt.content)
			if result["found"] != tt.wantFound {
				t.Errorf("found = %v, want %v", result["found"], tt.wantFound)
			}
			if result["ai_denied"] != tt.wantDeny {
				t.Errorf("ai_denied = %v, want %v", result["ai_denied"], tt.wantDeny)
			}
		})
	}
}

func TestParseRobotsTxtForAI(t *testing.T) {
	content := `User-Agent: Googlebot
Disallow: /private

User-Agent: *
Allow: /
`
	blocked, allowed, directives := parseRobotsTxtForAI(content)
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

func TestProcessRobotsDirective_Disallow(t *testing.T) {
	state := &robotsParseState{
		currentAgents: []string{"GPTBot"},
		blockedSet:    map[string]bool{},
		allowedSet:    map[string]bool{},
	}
	processRobotsDirective("Disallow: /", "disallow: /", state)
	if len(state.blocked) != 1 || state.blocked[0] != "GPTBot" {
		t.Errorf("blocked = %v, want [GPTBot]", state.blocked)
	}
	if len(state.allowed) != 0 {
		t.Errorf("allowed = %v, want empty", state.allowed)
	}
	if len(state.directives) != 1 {
		t.Errorf("directives = %v, want 1 entry", state.directives)
	}
}

func TestProcessRobotsDirective_Allow(t *testing.T) {
	state := &robotsParseState{
		currentAgents: []string{"CCBot"},
		blockedSet:    map[string]bool{},
		allowedSet:    map[string]bool{},
	}
	processRobotsDirective("Allow: /public", "allow: /public", state)
	if len(state.blocked) != 0 {
		t.Errorf("blocked = %v, want empty", state.blocked)
	}
	if len(state.allowed) != 1 || state.allowed[0] != "CCBot" {
		t.Errorf("allowed = %v, want [CCBot]", state.allowed)
	}
	if len(state.directives) != 0 {
		t.Errorf("directives = %v, want empty", state.directives)
	}
}

func TestNewScanner(t *testing.T) {
	scanner := NewScanner(nil)
	if scanner == nil {
		t.Fatal("NewScanner returned nil")
	}
	if scanner.HTTP != nil {
		t.Error("scanner.HTTP should be nil when passed nil")
	}
}

func TestConvertEvidenceToMaps(t *testing.T) {
	result := map[string]any{}
	convertEvidenceToMaps(result)
}

func TestPromptKeywords(t *testing.T) {
	if len(promptKeywords) < 10 {
		t.Errorf("promptKeywords has %d entries, expected at least 10", len(promptKeywords))
	}
}
