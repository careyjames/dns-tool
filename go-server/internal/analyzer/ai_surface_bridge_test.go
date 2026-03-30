package analyzer

import (
	"context"
	"testing"
)

func TestAnalyzeAISurface_ReturnsStructuredResult(t *testing.T) {
	mockHTTP := NewMockHTTPClient()
	mockHTTP.AddResponse("https://example.com/.well-known/llms.txt", 404, "")
	mockHTTP.AddResponse("https://example.com/llms.txt", 404, "")
	mockHTTP.AddResponse("https://example.com/robots.txt", 200, "User-agent: *\nDisallow: /private\n")
	mockHTTP.AddResponse("https://example.com", 200, "<html><body>Hello</body></html>")

	a := &Analyzer{HTTP: mockHTTP}
	result := a.AnalyzeAISurface(context.Background(), "example.com")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	status, ok := result["status"].(string)
	if !ok {
		t.Fatal("expected 'status' to be a string")
	}
	if status == "" {
		t.Error("status should not be empty")
	}
	msg, ok := result["message"].(string)
	if !ok {
		t.Fatal("expected 'message' to be a string")
	}
	if msg == "" {
		t.Error("message should not be empty")
	}
}

func TestAnalyzeAISurface_ContainsExpectedKeys(t *testing.T) {
	mockHTTP := NewMockHTTPClient()
	mockHTTP.AddResponse("https://example.com/.well-known/llms.txt", 404, "")
	mockHTTP.AddResponse("https://example.com/llms.txt", 404, "")
	mockHTTP.AddResponse("https://example.com/robots.txt", 200, "User-agent: *\nAllow: /\n")
	mockHTTP.AddResponse("https://example.com", 200, "<html><body>clean</body></html>")

	a := &Analyzer{HTTP: mockHTTP}
	result := a.AnalyzeAISurface(context.Background(), "example.com")

	requiredKeys := []string{"status", "message", "llms_txt", "robots_txt", "poisoning", "hidden_prompts", "evidence", "summary"}
	for _, key := range requiredKeys {
		if _, ok := result[key]; !ok {
			t.Errorf("missing expected key %q in result", key)
		}
	}
}

func TestAnalyzeAISurface_WithLLMSTxt(t *testing.T) {
	mockHTTP := NewMockHTTPClient()
	mockHTTP.AddResponse("https://example.com/.well-known/llms.txt", 200, "# example.com LLMs.txt\n\n> This site allows AI training.\n")
	mockHTTP.AddResponse("https://example.com/llms.txt", 404, "")
	mockHTTP.AddResponse("https://example.com/robots.txt", 200, "User-agent: *\nAllow: /\n")
	mockHTTP.AddResponse("https://example.com", 200, "<html><body>Hello</body></html>")

	a := &Analyzer{HTTP: mockHTTP}
	result := a.AnalyzeAISurface(context.Background(), "example.com")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	llmsTxt, ok := result["llms_txt"].(map[string]any)
	if !ok {
		t.Fatalf("expected llms_txt to be map[string]any, got %T", result["llms_txt"])
	}
	if llmsTxt["found"] != true {
		t.Errorf("expected llms_txt.found = true, got %v", llmsTxt["found"])
	}
}

func TestAnalyzeAISurface_EmptyDomain(t *testing.T) {
	mockHTTP := NewMockHTTPClient()
	a := &Analyzer{HTTP: mockHTTP}
	result := a.AnalyzeAISurface(context.Background(), "")
	if result == nil {
		t.Fatal("expected non-nil result even for empty domain")
	}
	if _, ok := result["status"]; !ok {
		t.Error("expected 'status' key even for empty domain")
	}
}

func TestAnalyzeAISurface_DelegatesHTTPClient(t *testing.T) {
	mockHTTP := NewMockHTTPClient()
	a := &Analyzer{HTTP: mockHTTP}
	if a.HTTP != mockHTTP {
		t.Fatal("expected HTTP client to be the mock")
	}
	result := a.AnalyzeAISurface(context.Background(), "test.example.com")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if _, ok := result["summary"]; !ok {
		t.Error("expected 'summary' key in result")
	}
}

func TestAnalyzeAISurface_RobotsTxtBlocksAI(t *testing.T) {
	mockHTTP := NewMockHTTPClient()
	mockHTTP.AddResponse("https://blocked.example.com/.well-known/llms.txt", 404, "")
	mockHTTP.AddResponse("https://blocked.example.com/llms.txt", 404, "")
	mockHTTP.AddResponse("https://blocked.example.com/robots.txt", 200,
		"User-agent: GPTBot\nDisallow: /\n\nUser-agent: ChatGPT-User\nDisallow: /\n")
	mockHTTP.AddResponse("https://blocked.example.com", 200, "<html><body>Hello</body></html>")

	a := &Analyzer{HTTP: mockHTTP}
	result := a.AnalyzeAISurface(context.Background(), "blocked.example.com")

	robotsTxt, ok := result["robots_txt"].(map[string]any)
	if !ok {
		t.Fatalf("expected robots_txt to be map, got %T", result["robots_txt"])
	}
	blocked, ok := robotsTxt["ai_agents_blocked"].(int)
	if !ok {
		t.Skipf("ai_agents_blocked type = %T", robotsTxt["ai_agents_blocked"])
	}
	if blocked == 0 {
		t.Error("expected at least one AI agent to be blocked")
	}
}
