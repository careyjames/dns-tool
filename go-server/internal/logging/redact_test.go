package logging

import (
        "errors"
        "log/slog"
        "strings"
        "testing"
)

func TestRedactMessage_Email(t *testing.T) {
        msg := "User user@example.com logged in"
        result := RedactMessage(msg)
        if strings.Contains(result, "user@example.com") {
                t.Errorf("expected email to be redacted: %q", result)
        }
        if !strings.Contains(result, "[REDACTED_EMAIL]") {
                t.Errorf("expected [REDACTED_EMAIL] placeholder: %q", result)
        }
}

func TestRedactMessage_Webhook(t *testing.T) {
        msg := "Sending to https://discord.com/api/webhooks/123/abc"
        result := RedactMessage(msg)
        if strings.Contains(result, "discord.com/api/webhooks") {
                t.Errorf("expected webhook to be redacted: %q", result)
        }
        if !strings.Contains(result, "[REDACTED_WEBHOOK]") {
                t.Errorf("expected [REDACTED_WEBHOOK] placeholder: %q", result)
        }
}

func TestRedactMessage_Token(t *testing.T) {
        msg := "token=abc123xyz"
        result := RedactMessage(msg)
        if strings.Contains(result, "abc123xyz") {
                t.Errorf("expected token to be redacted: %q", result)
        }
        if !strings.Contains(result, "[REDACTED_CREDENTIAL]") {
                t.Errorf("expected [REDACTED_CREDENTIAL] placeholder: %q", result)
        }
}

func TestRedactMessage_Authorization(t *testing.T) {
        msg := "authorization=BearerToken123"
        result := RedactMessage(msg)
        if strings.Contains(result, "BearerToken123") {
                t.Errorf("expected auth value to be redacted: %q", result)
        }
}

func TestRedactMessage_SecretKey(t *testing.T) {
        msg := "secret=mysecretvalue"
        result := RedactMessage(msg)
        if strings.Contains(result, "mysecretvalue") {
                t.Errorf("expected secret to be redacted: %q", result)
        }
}

func TestRedactMessage_NoSensitive(t *testing.T) {
        msg := "Application started on port 8080"
        result := RedactMessage(msg)
        if result != msg {
                t.Errorf("result = %q, want %q", result, msg)
        }
}

func TestRedactMessage_MultiplePatterns(t *testing.T) {
        msg := "user@test.com sent token=secret123 to https://discordapp.com/api/webhooks/1/2"
        result := RedactMessage(msg)
        if strings.Contains(result, "user@test.com") {
                t.Error("email should be redacted")
        }
        if strings.Contains(result, "discordapp.com/api/webhooks") {
                t.Error("webhook should be redacted")
        }
}

func TestRedactAttr_SensitiveKey(t *testing.T) {
        tests := []string{
                "password", "secret", "token", "authorization",
                "cookie", "session_id", "api_key", "webhook_url",
                "scan_token", "csrf_token", "probe_key",
        }
        for _, key := range tests {
                t.Run(key, func(t *testing.T) {
                        a := slog.String(key, "sensitive-value")
                        result := redactAttr(a)
                        if result.Value.String() != "[REDACTED]" {
                                t.Errorf("key %q: value = %q, want [REDACTED]", key, result.Value.String())
                        }
                })
        }
}

func TestRedactAttr_NonSensitiveKey(t *testing.T) {
        a := slog.String("domain", "example.com")
        result := redactAttr(a)
        if result.Value.String() != "example.com" {
                t.Errorf("non-sensitive key should preserve value: %q", result.Value.String())
        }
}

func TestRedactAttr_StringWithEmail(t *testing.T) {
        a := slog.String("message", "login by admin@corp.com")
        result := redactAttr(a)
        if strings.Contains(result.Value.String(), "admin@corp.com") {
                t.Error("email in string attr should be redacted")
        }
}

func TestRedactAttr_ErrorType(t *testing.T) {
        err := errors.New("failed for user@example.com")
        a := slog.Any("error", err)
        result := redactAttr(a)
        if strings.Contains(result.Value.String(), "user@example.com") {
                t.Error("email in error should be redacted")
        }
}

func TestRedactAttr_GroupType(t *testing.T) {
        group := slog.Group("auth",
                slog.String("password", "secret123"),
                slog.String("username", "admin"),
        )
        result := redactAttr(group)
        attrs := result.Value.Group()
        for _, a := range attrs {
                if a.Key == "password" && a.Value.String() != "[REDACTED]" {
                        t.Error("password in group should be redacted")
                }
                if a.Key == "username" && a.Value.String() != "admin" {
                        t.Error("username should be preserved")
                }
        }
}

func TestRedactAttr_CaseInsensitiveKeys(t *testing.T) {
        a := slog.String("Password", "secret")
        result := redactAttr(a)
        if result.Value.String() != "[REDACTED]" {
                t.Error("case-insensitive key should still be redacted")
        }
}

func TestSensitiveKeys_Complete(t *testing.T) {
        expected := []string{
                "password", "secret", "token", "authorization",
                "cookie", "session_id", "api_key", "webhook_url",
                "scan_token", "csrf_token", "probe_key",
        }
        for _, key := range expected {
                if !sensitiveKeys[key] {
                        t.Errorf("missing sensitive key: %q", key)
                }
        }
}

func TestRedactMessage_DiscordAppWebhook(t *testing.T) {
        msg := "hook: https://discordapp.com/api/webhooks/999/token"
        result := RedactMessage(msg)
        if !strings.Contains(result, "[REDACTED_WEBHOOK]") {
                t.Errorf("discordapp.com webhook should be redacted: %q", result)
        }
}

func TestRedactMessage_SecretWithColon(t *testing.T) {
        msg := "secret: mysecretvalue"
        result := RedactMessage(msg)
        if !strings.Contains(result, "[REDACTED_CREDENTIAL]") {
                t.Errorf("secret: pattern should be redacted: %q", result)
        }
}

func TestRedactMessage_EmptyString(t *testing.T) {
        result := RedactMessage("")
        if result != "" {
                t.Errorf("empty string should stay empty: %q", result)
        }
}
