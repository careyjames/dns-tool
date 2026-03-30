package logging

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewDiscordSink(t *testing.T) {
	sink := NewDiscordSink("https://discord.com/api/webhooks/test")
	if sink == nil {
		t.Fatal("expected non-nil sink")
	}
	if sink.webhookURL != "https://discord.com/api/webhooks/test" {
		t.Errorf("webhookURL = %q", sink.webhookURL)
	}
	if sink.minLevel != slog.LevelError {
		t.Errorf("minLevel = %v, want Error", sink.minLevel)
	}
}

func TestDiscordSink_ShouldSend_EmptyWebhook(t *testing.T) {
	sink := &DiscordSink{
		webhookURL: "",
		lastSent:   make(map[string]time.Time),
	}
	if sink.ShouldSend(slog.LevelError, "test", "system") {
		t.Error("should not send with empty webhook URL")
	}
}

func TestDiscordSink_ShouldSend_SecurityCategory(t *testing.T) {
	sink := NewDiscordSink("https://discord.com/api/webhooks/test")
	result := sink.ShouldSend(slog.LevelWarn, "csrf_reject", CategorySecurity)
	if !result {
		t.Error("should send for security category events")
	}
}

func TestDiscordSink_ShouldSend_ErrorLevel(t *testing.T) {
	sink := NewDiscordSink("https://discord.com/api/webhooks/test")
	result := sink.ShouldSend(slog.LevelError, "db_error", CategorySystem)
	if !result {
		t.Error("should send for error level events")
	}
}

func TestDiscordSink_ShouldSend_InfoLevel_NotSecurity(t *testing.T) {
	sink := NewDiscordSink("https://discord.com/api/webhooks/test")
	result := sink.ShouldSend(slog.LevelInfo, "scan_started", CategoryScan)
	if result {
		t.Error("should not send for info level non-security events")
	}
}

func TestDiscordSink_ShouldSend_RateWindowed(t *testing.T) {
	sink := NewDiscordSink("https://discord.com/api/webhooks/test")

	first := sink.ShouldSend(slog.LevelError, "db_error", CategorySystem)
	if !first {
		t.Fatal("first call should return true")
	}

	second := sink.ShouldSend(slog.LevelError, "db_error", CategorySystem)
	if second {
		t.Error("second call within rate window should return false")
	}
}

func TestDiscordSink_ShouldSend_DifferentEvents(t *testing.T) {
	sink := NewDiscordSink("https://discord.com/api/webhooks/test")

	sink.ShouldSend(slog.LevelError, "event1", CategorySystem)
	result := sink.ShouldSend(slog.LevelError, "event2", CategorySystem)
	if !result {
		t.Error("different events should not be rate-limited against each other")
	}
}

func TestDiscordSink_Send_PostsToWebhook(t *testing.T) {
	var receivedBody []byte
	var receivedContentType string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	sink := &DiscordSink{
		webhookURL: ts.URL,
		client:     ts.Client(),
		lastSent:   make(map[string]time.Time),
		minLevel:   slog.LevelError,
	}

	sink.Send(context.Background(), slog.LevelError, "test error message", map[string]string{
		AttrDomain:   "example.com",
		AttrCategory: CategorySecurity,
		AttrTraceID:  "trace-abc",
	})

	if receivedContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", receivedContentType)
	}
	if len(receivedBody) == 0 {
		t.Fatal("expected non-empty body")
	}

	var payload discordPayload
	if err := json.Unmarshal(receivedBody, &payload); err != nil {
		t.Fatalf("failed to parse payload: %v", err)
	}
	if payload.Username != "DNS Tool Logger" {
		t.Errorf("Username = %q", payload.Username)
	}
	if len(payload.Embeds) != 1 {
		t.Fatalf("expected 1 embed, got %d", len(payload.Embeds))
	}
	embed := payload.Embeds[0]
	if !strings.Contains(embed.Title, "CRITICAL") {
		t.Errorf("Title = %q, expected CRITICAL label", embed.Title)
	}
	if !strings.Contains(embed.Title, "test error message") {
		t.Errorf("Title = %q, expected message", embed.Title)
	}
	if embed.Color != 0xDC3545 {
		t.Errorf("Color = %x, want 0xDC3545 for error", embed.Color)
	}
	if !strings.Contains(embed.Description, "example.com") {
		t.Errorf("Description = %q, expected domain", embed.Description)
	}
}

func TestDiscordSink_Send_SkipsRedactedAttrs(t *testing.T) {
	var receivedBody []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	sink := &DiscordSink{
		webhookURL: ts.URL,
		client:     ts.Client(),
		lastSent:   make(map[string]time.Time),
		minLevel:   slog.LevelError,
	}

	sink.Send(context.Background(), slog.LevelError, "msg", map[string]string{
		"secret":    "[REDACTED]",
		"empty":     "",
		"real_attr": "visible",
	})

	body := string(receivedBody)
	if strings.Contains(body, "[REDACTED]") {
		t.Error("redacted values should be filtered out")
	}
	if !strings.Contains(body, "visible") {
		t.Error("real attributes should be included")
	}
}

func TestDiscordSink_Send_WarnLevel(t *testing.T) {
	var receivedBody []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	sink := &DiscordSink{
		webhookURL: ts.URL,
		client:     ts.Client(),
		lastSent:   make(map[string]time.Time),
	}

	sink.Send(context.Background(), slog.LevelWarn, "warning msg", nil)

	var payload discordPayload
	json.Unmarshal(receivedBody, &payload)
	if len(payload.Embeds) != 1 {
		t.Fatal("expected 1 embed")
	}
	if payload.Embeds[0].Color != 0xFFC107 {
		t.Errorf("warn color = %x, want 0xFFC107", payload.Embeds[0].Color)
	}
	if !strings.Contains(payload.Embeds[0].Title, "WARNING") {
		t.Errorf("Title = %q, expected WARNING", payload.Embeds[0].Title)
	}
}

func TestLevelColor(t *testing.T) {
	if levelColor(slog.LevelError) != 0xDC3545 {
		t.Errorf("error color = %x, want 0xDC3545", levelColor(slog.LevelError))
	}
	if levelColor(slog.LevelWarn) != 0xFFC107 {
		t.Errorf("warn color = %x, want 0xFFC107", levelColor(slog.LevelWarn))
	}
	if levelColor(slog.LevelInfo) != 0x6C757D {
		t.Errorf("info color = %x, want 0x6C757D", levelColor(slog.LevelInfo))
	}
}

func TestLevelLabel(t *testing.T) {
	if levelLabel(slog.LevelError) != "CRITICAL" {
		t.Errorf("error label = %q", levelLabel(slog.LevelError))
	}
	if levelLabel(slog.LevelWarn) != "WARNING" {
		t.Errorf("warn label = %q", levelLabel(slog.LevelWarn))
	}
	if levelLabel(slog.LevelInfo) != "INFO" {
		t.Errorf("info label = %q", levelLabel(slog.LevelInfo))
	}
}

func TestTruncate_Short(t *testing.T) {
	result := truncate("hello", 10)
	if result != "hello" {
		t.Errorf("truncate = %q, want 'hello'", result)
	}
}

func TestTruncate_Long(t *testing.T) {
	result := truncate("hello world foo bar baz", 10)
	if len(result) > 15 {
		t.Errorf("truncated string too long: %q", result)
	}
	if !strings.HasSuffix(result, "…") {
		t.Errorf("truncated string should end with ellipsis: %q", result)
	}
}

func TestTruncate_Exact(t *testing.T) {
	result := truncate("exactly10!", 10)
	if result != "exactly10!" {
		t.Errorf("truncate = %q, want 'exactly10!'", result)
	}
}

func TestBuildDescription_Empty(t *testing.T) {
	result := buildDescription(map[string]string{})
	if result != "" {
		t.Errorf("expected empty description, got %q", result)
	}
}

func TestBuildDescription_WithDomain(t *testing.T) {
	result := buildDescription(map[string]string{
		AttrDomain: "example.com",
	})
	if !strings.Contains(result, "example.com") {
		t.Errorf("expected domain in description: %q", result)
	}
	if !strings.Contains(result, "**") {
		t.Error("domain should be bold in description")
	}
}

func TestBuildDescription_WithCategory(t *testing.T) {
	result := buildDescription(map[string]string{
		AttrCategory: "security",
	})
	if !strings.Contains(result, "security") {
		t.Errorf("expected category in description: %q", result)
	}
}

func TestBuildDescription_WithErrorChain(t *testing.T) {
	result := buildDescription(map[string]string{
		AttrErrorChain: "resolver timeout > dns lookup failed",
	})
	if !strings.Contains(result, "resolver timeout") {
		t.Errorf("expected error chain in description: %q", result)
	}
	if !strings.Contains(result, "```") {
		t.Error("error chain should be in code block")
	}
}

func TestBuildDescription_SkipsEmpty(t *testing.T) {
	result := buildDescription(map[string]string{
		AttrDomain:   "",
		AttrCategory: "",
	})
	if result != "" {
		t.Errorf("expected empty for all-empty attrs, got %q", result)
	}
}

func TestBuildDescription_AllFields(t *testing.T) {
	result := buildDescription(map[string]string{
		AttrDomain:     "test.com",
		AttrCategory:   "security",
		AttrErrorChain: "some error",
	})
	if !strings.Contains(result, "test.com") {
		t.Error("missing domain")
	}
	if !strings.Contains(result, "security") {
		t.Error("missing category")
	}
	if !strings.Contains(result, "some error") {
		t.Error("missing error chain")
	}
}
